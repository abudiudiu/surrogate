#!/usr/bin/env python3
"""
proxy.py v7 — Production‑tuned HTTP/HTTPS multiplexer for anyip.io

Performance enhancements over v6:
  • SO_REUSEPORT + backlog=65535 for higher accept rate
  • TCP_NODELAY on all client sockets (lower latency)
  • Per‑client error tracking → auto‑rotate after 3 consecutive failures
  • Enhanced Prometheus metrics (active connections, pool size, DNS cache)
  • Stricter backpressure (conditional drain everywhere)
  • Per‑session idle connection limit bumped to 20 (configurable)
  • Linux kernel tuning recommendations (see docs)

All existing anyip.io session features, management endpoints, and configuration
variables remain identical.
"""

from __future__ import annotations

import asyncio
import base64
import collections
import fcntl
import hashlib
import json
import logging
import multiprocessing
import os
import resource
import socket
import sys
import time
import urllib.request
from pathlib import Path
from typing import Optional

# ── uvloop (optional, ~2× throughput) ────────────────────────────────────────

try:
    import uvloop
    uvloop.install()
except ImportError:
    pass

# ── Configuration ─────────────────────────────────────────────────────────────

ANYIP_HOST             = os.environ.get("ANYIP_HOST",             "portal.anyip.io")
ANYIP_PORT             = int(os.environ.get("ANYIP_PORT",         "1080"))
ANYIP_USERNAME         = os.environ.get("ANYIP_USERNAME",         "user_XXXX")
ANYIP_PASSWORD         = os.environ.get("ANYIP_PASSWORD",         "changeme")
ANYIP_PROXY_TYPE       = os.environ.get("ANYIP_PROXY_TYPE",       "mobile")
ANYIP_SESSION_MINUTES  = int(os.environ.get("ANYIP_SESSION_MINUTES", "4320"))
ANYIP_COUNTRY          = os.environ.get("ANYIP_COUNTRY",          "")
ANYIP_CITY             = os.environ.get("ANYIP_CITY",             "")
SESSION_SALT           = os.environ.get("ANYIP_SESSION_SALT",     "changeme")
SESSION_STORE_PATH     = os.environ.get("SESSION_STORE_PATH",     "/var/lib/proxy/sessions.json")

ANYIP_SESSION_MODE    = os.environ.get("ANYIP_SESSION_MODE",    "sticky").lower()
ANYIP_STRICT_COLLISION = os.environ.get("ANYIP_STRICT_COLLISION", "false").lower() == "true"
ANYIP_SESSION_REPLACE  = os.environ.get("ANYIP_SESSION_REPLACE",  "true").lower() == "true"
ANYIP_SESSION_ASN_STRICT = os.environ.get("ANYIP_SESSION_ASN_STRICT", "false").lower() == "true"
ANYIP_PROXY_ID         = os.environ.get("ANYIP_PROXY_ID",         "")
ANYIP_INVALIDATE_HASH  = os.environ.get("ANYIP_INVALIDATE_HASH",  "")

LISTEN_HOST      = "0.0.0.0"
LISTEN_PORT      = int(os.environ.get("PROXY_PORT",        "3128"))
LOG_LEVEL        = os.environ.get("LOG_LEVEL",              "info").upper()
PROXY_WORKERS    = int(os.environ.get("PROXY_WORKERS",      str(max(1, (os.cpu_count() or 1)))))
MAX_CONNS_PER_IP = int(os.environ.get("MAX_CONNS_PER_IP",   "50"))

CONNECT_TIMEOUT      = 30
RESPONSE_TIMEOUT     = 120
IDLE_TIMEOUT         = 300
POOL_IDLE_TIMEOUT    = 90
MAX_IDLE_PER_SESSION = int(os.environ.get("MAX_IDLE_PER_SESSION", "20"))   # bumped from 8
FLUSH_INTERVAL       = 30
GC_INTERVAL          = 300
TARGET_NOFILE        = 65536
WRITE_BUFFER_HIGH    = 256 * 1024

# Feature flags
DNS_TTL = int(os.environ.get("DNS_TTL", "300"))
AUTO_ROTATE_ON_ERROR = os.environ.get("AUTO_ROTATE_ON_ERROR", "true").lower() == "true"
SESSION_ID_HEADER = os.environ.get("SESSION_ID_HEADER", "X-Session-ID").lower().encode()
_NO_BODY_STATUS = frozenset({100, 101, 102, 103, 204, 304})

# Front proxy / LB
TRUST_PROXY_HEADERS = os.environ.get("TRUST_PROXY_HEADERS", "true").lower() == "true"
ENABLE_PROXY_PROTOCOL = os.environ.get("ENABLE_PROXY_PROTOCOL", "true").lower() == "true"
TRUSTED_PROXY_RANGES = ("127.", "10.", "172.16.", "192.168.", "::1")

# Performance
ENABLE_ZERO_COPY = os.environ.get("ENABLE_ZERO_COPY", "true").lower() == "true"
PROMETHEUS_METRICS = os.environ.get("PROMETHEUS_METRICS", "true").lower() == "true"
TCP_NODELAY = os.environ.get("TCP_NODELAY", "true").lower() == "true"

# ── Logging ───────────────────────────────────────────────────────────────────

logging.basicConfig(
    level=getattr(logging, LOG_LEVEL, logging.INFO),
    format="%(asctime)s [%(levelname)s] %(message)s",
    stream=sys.stderr,
)
log = logging.getLogger("proxy")

# ── Helper functions (real IP, PROXY protocol, etc.) ─────────────────────────

def _is_trusted_proxy(ip: str) -> bool:
    return any(ip.startswith(prefix) for prefix in TRUSTED_PROXY_RANGES)

async def _read_proxy_protocol(reader: asyncio.StreamReader) -> Optional[str]:
    if not ENABLE_PROXY_PROTOCOL:
        return None
    try:
        line = await reader.readuntil(b"\r\n")
        if line.startswith(b"PROXY "):
            parts = line.strip().split()
            if len(parts) >= 3:
                return parts[2].decode()
        else:
            reader._buffer = line + reader._buffer
    except Exception:
        pass
    return None

def _extract_real_ip(peer_ip: str, headers: list[bytes]) -> str:
    if not TRUST_PROXY_HEADERS or not _is_trusted_proxy(peer_ip):
        return peer_ip
    xff = xri = None
    for h in headers:
        hl = h.lower()
        if hl.startswith(b"x-forwarded-for:"):
            xff = h.split(b":", 1)[1].strip()
        elif hl.startswith(b"x-real-ip:"):
            xri = h.split(b":", 1)[1].strip()
    if xff:
        try:
            return xff.split(b",")[0].strip().decode()
        except Exception:
            pass
    if xri:
        try:
            return xri.decode()
        except Exception:
            pass
    return peer_ip

def _build_client_id(client_ip: str, session_id_val: Optional[str]) -> str:
    if session_id_val:
        return f"{client_ip}:{session_id_val}"
    return client_ip

# ── Live counters (per‑worker) ────────────────────────────────────────────────

_counters: dict[str, int] = collections.defaultdict(int)

def _inc(key: str, n: int = 1):
    _counters[key] += n

# ── DNS cache ─────────────────────────────────────────────────────────────────

_dns_cache: dict[str, tuple[str, float]] = {}

async def _resolve_host(host: str) -> str:
    now = time.time()
    entry = _dns_cache.get(host)
    if entry and now < entry[1]:
        return entry[0]
    try:
        loop = asyncio.get_running_loop()
        infos = await loop.getaddrinfo(
            host, None, type=socket.SOCK_STREAM, family=socket.AF_UNSPEC
        )
        # Prefer IPv4
        infos.sort(key=lambda x: 0 if x[0] == socket.AF_INET else 1)
        ip = infos[0][4][0]
        _dns_cache[host] = (ip, now + DNS_TTL)
        log.debug(f"DNS resolved: {host} → {ip} (TTL={DNS_TTL}s)")
        return ip
    except Exception as exc:
        log.warning(f"DNS resolve failed for {host}: {exc} — using hostname")
        return host

# ── OS file‑descriptor limit ─────────────────────────────────────────────────

def _raise_fd_limit():
    try:
        soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
        cap = hard if hard != resource.RLIM_INFINITY else TARGET_NOFILE
        target = min(TARGET_NOFILE, cap)
        if soft < target:
            resource.setrlimit(resource.RLIMIT_NOFILE, (target, hard))
            log.info(f"FD limit: {soft} → {target}")
    except Exception as e:
        log.warning(f"Could not raise FD limit: {e}")

# ── Session store (persistent) ───────────────────────────────────────────────

class SessionStore:
    def __init__(self, path: str):
        self._path = Path(path)
        self._lock = asyncio.Lock()
        self._sessions: dict[str, dict] = {}
        self._dirty = False

    def load_sync(self):
        try:
            if self._path.exists():
                self._sessions = json.loads(self._path.read_text())
                log.info(f"Loaded {len(self._sessions)} sessions from {self._path}")
        except Exception as e:
            log.warning(f"Could not load sessions: {e}")

    async def get_or_create(self, client_id: str) -> dict:
        ttl_ms = ANYIP_SESSION_MINUTES * 60 * 1000
        now = int(time.time() * 1000)
        async with self._lock:
            s = self._sessions.get(client_id)
            if s and (now - s["created_at"]) < ttl_ms:
                s["last_used"] = now
                s["request_count"] = s.get("request_count", 0) + 1
                return dict(s)
            # Double‑check (safe)
            s = self._sessions.get(client_id)
            if s and (now - s["created_at"]) < ttl_ms:
                s["last_used"] = now
                s["request_count"] = s.get("request_count", 0) + 1
                return dict(s)
            rotation = s.get("rotation_count", 0) if s else 0
            name = _make_session_name(client_id, rotation)
            s = {
                "client_id":      client_id,
                "session_name":   name,
                "rotation_count": rotation,
                "created_at":     now,
                "last_used":      now,
                "request_count":  1,
            }
            self._sessions[client_id] = s
            self._dirty = True
            log.info(f"New session: client={client_id} session={name}")
            return dict(s)

    async def flush(self):
        async with self._lock:
            if not self._dirty:
                return
            snapshot = dict(self._sessions)
            self._dirty = False
        await asyncio.get_running_loop().run_in_executor(None, self._write_sync, snapshot)

    def _write_sync(self, data: dict):
        try:
            self._path.parent.mkdir(parents=True, exist_ok=True)
            lock_path = self._path.with_suffix(".lock")
            with open(lock_path, "w") as lf:
                fcntl.flock(lf, fcntl.LOCK_EX)
                tmp = self._path.with_suffix(".tmp")
                tmp.write_text(json.dumps(data, indent=2))
                tmp.replace(self._path)
        except Exception as e:
            log.warning(f"Persist error: {e}")

    async def gc(self):
        cutoff = ANYIP_SESSION_MINUTES * 60 * 1000 * 1.1
        now = int(time.time() * 1000)
        async with self._lock:
            expired = [k for k, v in self._sessions.items() if (now - v["created_at"]) > cutoff]
            for k in expired:
                log.debug(f"GC: {k}")
                del self._sessions[k]
            if expired:
                self._dirty = True

    async def rotate(self, client_id: str) -> Optional[dict]:
        now = int(time.time() * 1000)
        async with self._lock:
            s = self._sessions.get(client_id)
            if not s:
                return None
            rotation = s.get("rotation_count", 0) + 1
            new_name = _make_session_name(client_id, rotation)
            s.update({
                "session_name":   new_name,
                "rotation_count": rotation,
                "created_at":     now,
                "request_count":  0,
            })
            self._dirty = True
            log.info(f"Rotated: client={client_id} → session={new_name}")
            return dict(s)

    async def rotate_all(self) -> int:
        now = int(time.time() * 1000)
        async with self._lock:
            for client_id, s in self._sessions.items():
                rotation = s.get("rotation_count", 0) + 1
                s.update({
                    "session_name":   _make_session_name(client_id, rotation),
                    "rotation_count": rotation,
                    "created_at":     now,
                    "request_count":  0,
                })
            count = len(self._sessions)
            self._dirty = True
        log.info(f"Rotated all {count} sessions")
        return count

    async def snapshot(self) -> list[dict]:
        now = int(time.time() * 1000)
        ttl_ms = ANYIP_SESSION_MINUTES * 60 * 1000
        async with self._lock:
            return [
                {**s, "remaining_ms": max(0, ttl_ms - (now - s["created_at"]))}
                for s in self._sessions.values()
            ]

_store: SessionStore
_pool_lock: asyncio.Lock
_ip_limiter: "PerIpLimiter"
_error_counts: dict[str, int] = {}   # per‑client consecutive error count (in‑memory)

def _make_session_name(client_id: str, rotation: int = 0) -> str:
    key = ":".join([
        client_id, SESSION_SALT, ANYIP_PROXY_TYPE,
        ANYIP_COUNTRY or "", ANYIP_CITY or "", str(rotation)
    ])
    return "gw" + hashlib.sha256(key.encode()).hexdigest()[:16]

def _build_auth(session_name: Optional[str]) -> str:
    parts = [ANYIP_USERNAME]
    if ANYIP_COUNTRY:
        parts.append(f"country_{ANYIP_COUNTRY}")
    if ANYIP_CITY:
        parts.append(f"city_{ANYIP_CITY}")
    parts.append(f"type_{ANYIP_PROXY_TYPE}")
    if session_name:
        parts.append(f"session_{session_name}")
        parts.append(f"sesstime_{ANYIP_SESSION_MINUTES}")
        if not ANYIP_SESSION_REPLACE:
            parts.append("sessreplace_false")
        if ANYIP_STRICT_COLLISION:
            parts.append("sessipcollision_strict")
        if ANYIP_SESSION_ASN_STRICT:
            parts.append("sessasn_strict")
    return base64.b64encode(f"{','.join(parts)}:{ANYIP_PASSWORD}".encode()).decode()

async def _get_auth(client_id: str) -> str:
    if ANYIP_SESSION_MODE == "rotating":
        return _build_auth(None)
    session = await _store.get_or_create(client_id)
    return _build_auth(session["session_name"])

# ── Per‑IP connection limiter ─────────────────────────────────────────────────

class PerIpLimiter:
    def __init__(self, max_conns: int):
        self._max = max_conns
        self._active: dict[str, int] = collections.defaultdict(int)
        self._lock = asyncio.Lock()

    async def try_acquire(self, ip: str) -> bool:
        async with self._lock:
            if self._active[ip] >= self._max:
                return False
            self._active[ip] += 1
            return True

    async def release(self, ip: str):
        async with self._lock:
            self._active[ip] = max(0, self._active[ip] - 1)

    def active_counts(self) -> dict[str, int]:
        return {ip: n for ip, n in self._active.items() if n > 0}

# ── HTTP upstream connection pool (per‑session) ──────────────────────────────

_pool: dict[str, collections.deque]

def _pool_key(auth: str) -> str:
    return hashlib.md5(auth.encode()).hexdigest()

async def _pool_acquire(auth: str) -> Optional[tuple[asyncio.StreamReader, asyncio.StreamWriter]]:
    key = _pool_key(auth)
    async with _pool_lock:
        dq = _pool.get(key)
        if not dq:
            return None
        while dq:
            reader, writer, ts = dq.pop()
            if writer.is_closing() or (time.time() - ts) > POOL_IDLE_TIMEOUT:
                try:
                    writer.close()
                except Exception:
                    pass
                continue
            _inc("pool_hits")
            return reader, writer
    return None

async def _pool_release(auth: str, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
    if writer.is_closing():
        return
    key = _pool_key(auth)
    async with _pool_lock:
        dq = _pool.setdefault(key, collections.deque())
        if len(dq) >= MAX_IDLE_PER_SESSION:
            try:
                writer.close()
            except Exception:
                pass
            return
        dq.append((reader, writer, time.time()))

async def _open_upstream(auth: str) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
    conn = await _pool_acquire(auth)
    if conn:
        return conn
    _inc("upstream_connections_opened")
    host_ip = await _resolve_host(ANYIP_HOST)
    return await asyncio.wait_for(
        asyncio.open_connection(host_ip, ANYIP_PORT),
        timeout=CONNECT_TIMEOUT,
    )

# ── Pipe (bidirectional copy) with backpressure ──────────────────────────────

async def _pipe(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
    try:
        while True:
            data = await asyncio.wait_for(reader.read(65536), timeout=IDLE_TIMEOUT)
            if not data:
                break
            if ENABLE_ZERO_COPY:
                writer.write(memoryview(data))
            else:
                writer.write(data)
            if writer.transport.get_write_buffer_size() > WRITE_BUFFER_HIGH:
                await writer.drain()
            else:
                await asyncio.sleep(0)
    except (asyncio.TimeoutError, asyncio.CancelledError, ConnectionResetError, BrokenPipeError, OSError):
        pass
    finally:
        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass

# ── HTTP response forwarder (with 407 handling) ──────────────────────────────

async def _forward_response(
    up_r: asyncio.StreamReader,
    cl_w: asyncio.StreamWriter,
    method: str,
) -> tuple[bool, int]:
    buf = b""
    while b"\r\n\r\n" not in buf:
        chunk = await asyncio.wait_for(up_r.read(8192), timeout=RESPONSE_TIMEOUT)
        if not chunk:
            return False, 0
        buf += chunk

    sep = buf.index(b"\r\n\r\n")
    header_block = buf[:sep + 4]
    leftover = buf[sep + 4:]

    lines = header_block.split(b"\r\n")
    try:
        status_code = int(lines[0].split(b" ", 2)[1])
    except (IndexError, ValueError):
        status_code = 200

    content_length: Optional[int] = None
    chunked = False
    upstream_keep_alive = True

    for line in lines[1:]:
        if not line:
            continue
        name_b, _, val_b = line.partition(b":")
        key = name_b.strip().lower()
        val = val_b.strip()
        if key == b"content-length":
            try:
                content_length = int(val)
            except ValueError:
                pass
        elif key == b"transfer-encoding" and b"chunked" in val.lower():
            chunked = True
        elif key == b"connection" and val.lower() == b"close":
            upstream_keep_alive = False

    if status_code == 407:
        # drain silently
        try:
            if content_length:
                await asyncio.wait_for(up_r.read(content_length), timeout=5)
            elif chunked:
                tmp = leftover
                while not tmp.endswith(b"0\r\n\r\n"):
                    more = await asyncio.wait_for(up_r.read(4096), timeout=5)
                    if not more:
                        break
                    tmp += more
        except Exception:
            pass
        return False, 407

    if ENABLE_ZERO_COPY:
        cl_w.write(memoryview(header_block))
    else:
        cl_w.write(header_block)

    if status_code in _NO_BODY_STATUS or method.upper() == "HEAD":
        await cl_w.drain()
        return upstream_keep_alive, status_code

    if chunked:
        ok = await _forward_chunked(up_r, cl_w, leftover)
        await cl_w.drain()
        return upstream_keep_alive and ok, status_code

    if content_length is not None:
        remaining = content_length - len(leftover)
        if leftover:
            if ENABLE_ZERO_COPY:
                cl_w.write(memoryview(leftover))
            else:
                cl_w.write(leftover)
        while remaining > 0:
            chunk = await asyncio.wait_for(up_r.read(min(remaining, 65536)), timeout=IDLE_TIMEOUT)
            if not chunk:
                break
            if ENABLE_ZERO_COPY:
                cl_w.write(memoryview(chunk))
            else:
                cl_w.write(chunk)
            remaining -= len(chunk)
            if cl_w.transport.get_write_buffer_size() > WRITE_BUFFER_HIGH:
                await cl_w.drain()
        await cl_w.drain()
        return upstream_keep_alive and (remaining <= 0), status_code

    # No length — read until EOF
    if leftover:
        if ENABLE_ZERO_COPY:
            cl_w.write(memoryview(leftover))
        else:
            cl_w.write(leftover)
    while True:
        try:
            chunk = await asyncio.wait_for(up_r.read(65536), timeout=IDLE_TIMEOUT)
            if not chunk:
                break
            if ENABLE_ZERO_COPY:
                cl_w.write(memoryview(chunk))
            else:
                cl_w.write(chunk)
            if cl_w.transport.get_write_buffer_size() > WRITE_BUFFER_HIGH:
                await cl_w.drain()
        except asyncio.TimeoutError:
            break
    await cl_w.drain()
    return False, status_code

async def _forward_chunked(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    initial: bytes = b"",
) -> bool:
    buf = initial
    try:
        while True:
            while b"\r\n" not in buf:
                data = await asyncio.wait_for(reader.read(4096), timeout=IDLE_TIMEOUT)
                if not data:
                    return False
                buf += data

            size_line, _, buf = buf.partition(b"\r\n")
            try:
                chunk_size = int(size_line.split(b";")[0].strip(), 16)
            except ValueError:
                return False

            if ENABLE_ZERO_COPY:
                writer.write(memoryview(size_line + b"\r\n"))
            else:
                writer.write(size_line + b"\r\n")

            if chunk_size == 0:
                while b"\r\n\r\n" not in buf:
                    try:
                        more = await asyncio.wait_for(reader.read(1024), timeout=10)
                        if not more:
                            break
                        buf += more
                    except asyncio.TimeoutError:
                        break
                if ENABLE_ZERO_COPY:
                    writer.write(memoryview(buf or b"\r\n"))
                else:
                    writer.write(buf or b"\r\n")
                return True

            need = chunk_size + 2
            while len(buf) < need:
                more = await asyncio.wait_for(reader.read(65536), timeout=IDLE_TIMEOUT)
                if not more:
                    return False
                buf += more

            if ENABLE_ZERO_COPY:
                writer.write(memoryview(buf[:chunk_size]))
                writer.write(memoryview(b"\r\n"))
            else:
                writer.write(buf[:chunk_size])
                writer.write(b"\r\n")
            buf = buf[need:]

            if writer.transport.get_write_buffer_size() > WRITE_BUFFER_HIGH:
                await writer.drain()
    except Exception:
        return False

# ── CONNECT handler (with auto‑rotation on 407) ──────────────────────────────

async def handle_connect(
    cl_r: asyncio.StreamReader,
    cl_w: asyncio.StreamWriter,
    host: str,
    port: int,
    client_ip: str,
    client_id: str,
):
    _inc("requests_connect")
    host_ip = await _resolve_host(ANYIP_HOST)
    max_attempts = 2 if AUTO_ROTATE_ON_ERROR else 1

    for attempt in range(max_attempts):
        auth = await _get_auth(client_id)
        try:
            up_r, up_w = await asyncio.wait_for(
                asyncio.open_connection(host_ip, ANYIP_PORT),
                timeout=CONNECT_TIMEOUT,
            )
        except asyncio.TimeoutError:
            cl_w.write(b"HTTP/1.1 504 Gateway Timeout\r\n\r\n")
            await cl_w.drain()
            _inc("errors")
            return
        except Exception as e:
            log.warning(f"CONNECT upstream error ({client_ip} → {host}:{port}): {e}")
            cl_w.write(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
            await cl_w.drain()
            _inc("errors")
            return

        up_w.write(
            f"CONNECT {host}:{port} HTTP/1.1\r\n"
            f"Host: {host}:{port}\r\n"
            f"Proxy-Authorization: Basic {auth}\r\n"
            f"\r\n".encode()
        )
        await up_w.drain()

        resp = b""
        try:
            while b"\r\n\r\n" not in resp:
                chunk = await asyncio.wait_for(up_r.read(4096), timeout=CONNECT_TIMEOUT)
                if not chunk:
                    break
                resp += chunk
        except asyncio.TimeoutError:
            pass

        status_line = resp.split(b"\r\n", 1)[0]

        if b" 407 " in status_line and attempt == 0:
            log.warning(f"CONNECT 407 — auto‑rotating session for {client_id}")
            _inc("auto_rotations")
            try:
                up_w.close()
            except Exception:
                pass
            await _store.rotate(client_id)
            continue

        if b" 200 " not in status_line:
            status = status_line.decode(errors="replace")
            log.warning(f"CONNECT refused ({client_ip} → {host}:{port}): {status}")
            cl_w.write(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
            await cl_w.drain()
            try:
                up_w.close()
            except Exception:
                pass
            _inc("errors")
            return

        cl_w.write(b"HTTP/1.1 200 Connection established\r\n\r\n")
        await cl_w.drain()
        log.debug(f"TUNNEL {client_ip} [{client_id}] → {host}:{port}")

        await asyncio.gather(
            _pipe(cl_r, up_w),
            _pipe(up_r, cl_w),
            return_exceptions=True,
        )
        return

# ── HTTP handler (with error tracking & adaptive rotation) ───────────────────

async def handle_http(
    cl_r: asyncio.StreamReader,
    cl_w: asyncio.StreamWriter,
    method: str,
    url: str,
    version: str,
    raw_headers: list[bytes],
    client_ip: str,
    client_id: str,
) -> bool:
    _inc("requests_http")

    content_length = 0
    client_keep_alive = "1.1" in version
    filtered: list[bytes] = []

    for line in raw_headers:
        lower = line.lower()
        if lower.startswith(b"proxy-authorization:") or lower.startswith(b"proxy-connection:"):
            continue
        if lower.startswith(b"content-length:"):
            try:
                content_length = int(line.split(b":", 1)[1].strip())
            except ValueError:
                pass
        if lower.startswith(b"connection:"):
            if line.split(b":", 1)[1].strip().lower() == b"close":
                client_keep_alive = False
        filtered.append(line)

    body = b""
    if content_length > 0:
        try:
            body = await asyncio.wait_for(cl_r.read(content_length), timeout=30)
        except Exception:
            pass

    max_attempts = 2 if AUTO_ROTATE_ON_ERROR else 1
    for attempt in range(max_attempts):
        auth = await _get_auth(client_id)
        req_headers = filtered + [
            f"Proxy-Authorization: Basic {auth}".encode(),
            b"Connection: keep-alive",
        ]

        try:
            up_r, up_w = await _open_upstream(auth)
        except asyncio.TimeoutError:
            cl_w.write(b"HTTP/1.1 504 Gateway Timeout\r\nContent-Length: 0\r\n\r\n")
            await cl_w.drain()
            _inc("errors")
            return client_keep_alive
        except Exception as e:
            log.warning(f"HTTP upstream error ({client_ip} → {url}): {e}")
            cl_w.write(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
            await cl_w.drain()
            _inc("errors")
            return client_keep_alive

        try:
            up_w.write(f"{method} {url} HTTP/1.1\r\n".encode())
            up_w.write(b"\r\n".join(req_headers) + b"\r\n\r\n")
            if body:
                up_w.write(body)
            await up_w.drain()
            log.debug(f"HTTP {method} {url} ({client_ip}) [{client_id}]")
            upstream_keep_alive, status_code = await _forward_response(up_r, cl_w, method)
        except Exception as e:
            log.debug(f"HTTP error ({client_ip}): {e}")
            try:
                up_w.close()
            except Exception:
                pass
            _inc("errors")
            return False

        # Adaptive rotation: on 407 or repeated 5xx errors
        if status_code == 407 and attempt == 0:
            log.warning(f"HTTP 407 — auto‑rotating session for {client_id}")
            _inc("auto_rotations")
            try:
                up_w.close()
            except Exception:
                pass
            await _store.rotate(client_id)
            continue

        # Track consecutive errors (5xx or connection errors)
        if status_code >= 500 or status_code == 0:
            _error_counts[client_id] = _error_counts.get(client_id, 0) + 1
            if _error_counts[client_id] >= 3:
                log.warning(f"HTTP {status_code} repeated errors — rotating session for {client_id}")
                _inc("adaptive_rotations")
                await _store.rotate(client_id)
                _error_counts[client_id] = 0
                try:
                    up_w.close()
                except Exception:
                    pass
                continue   # retry with new session
        else:
            _error_counts[client_id] = 0   # reset on success

        if upstream_keep_alive:
            await _pool_release(auth, up_r, up_w)
        else:
            try:
                up_w.close()
            except Exception:
                pass

        return client_keep_alive and upstream_keep_alive

    # All attempts exhausted
    cl_w.write(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
    await cl_w.drain()
    _inc("errors")
    return False

# ── anyip.io rotation API call ───────────────────────────────────────────────

async def _anyip_rotate_api(session_name: str):
    if not ANYIP_PROXY_ID or not ANYIP_INVALIDATE_HASH:
        return
    url = (
        f"https://dashboard.anyip.io/api/proxy_accounts/"
        f"{ANYIP_PROXY_ID}/invalidate/{ANYIP_INVALIDATE_HASH}/session/{session_name}"
    )
    try:
        loop = asyncio.get_running_loop()
        await loop.run_in_executor(None, lambda: urllib.request.urlopen(url, timeout=10).read())
        log.info(f"anyip.io API: invalidated session {session_name}")
    except Exception as e:
        log.warning(f"anyip.io rotation API failed for {session_name}: {e}")

# ── Management endpoints ─────────────────────────────────────────────────────

def _json_response(cl_w: asyncio.StreamWriter, data: dict, status: str = "200 OK") -> None:
    payload = json.dumps(data, indent=2).encode()
    cl_w.write(
        f"HTTP/1.1 {status}\r\nContent-Type: application/json\r\n"
        f"Content-Length: {len(payload)}\r\nConnection: close\r\n\r\n".encode()
        + payload
    )

async def handle_stats(cl_w: asyncio.StreamWriter):
    sessions = await _store.snapshot()
    pool_total = sum(len(dq) for dq in _pool.values())
    _json_response(cl_w, {
        "worker_pid":            os.getpid(),
        "sessions_active":       len(sessions),
        "pool_idle_connections": pool_total,
        "active_conns_per_ip":   _ip_limiter.active_counts(),
        "counters":              dict(_counters),
        "config": {
            "session_mode":          ANYIP_SESSION_MODE,
            "proxy_type":            ANYIP_PROXY_TYPE,
            "session_minutes":       ANYIP_SESSION_MINUTES,
            "country":               ANYIP_COUNTRY or None,
            "city":                  ANYIP_CITY or None,
            "session_replace":       ANYIP_SESSION_REPLACE,
            "strict_collision":      ANYIP_STRICT_COLLISION,
            "session_asn_strict":    ANYIP_SESSION_ASN_STRICT,
            "rotation_api_enabled":  bool(ANYIP_PROXY_ID and ANYIP_INVALIDATE_HASH),
            "auto_rotate_on_error":  AUTO_ROTATE_ON_ERROR,
            "session_id_header":     SESSION_ID_HEADER.decode(),
            "dns_ttl_seconds":       DNS_TTL,
            "dns_cache":             {h: ip for h, (ip, _) in _dns_cache.items()},
            "max_conns_per_ip":      f"{MAX_CONNS_PER_IP} (per-worker)",
            "proxy_workers":         PROXY_WORKERS,
            "max_idle_per_session":  MAX_IDLE_PER_SESSION,
            "tcp_nodelay":           TCP_NODELAY,
        },
    })
    await cl_w.drain()

async def handle_sessions_list(cl_w: asyncio.StreamWriter):
    sessions = await _store.snapshot()
    _json_response(cl_w, {"worker_pid": os.getpid(), "sessions": sessions})
    await cl_w.drain()

async def handle_rotate(cl_w: asyncio.StreamWriter, client_id: str):
    if not client_id:
        _json_response(cl_w, {"error": "missing client_id"}, "400 Bad Request")
        await cl_w.drain()
        return
    old_session = (await _store.snapshot())
    old_session = next((s for s in old_session if s["client_id"] == client_id), None)
    old_name = old_session["session_name"] if old_session else None
    result = await _store.rotate(client_id)
    if not result:
        _json_response(cl_w, {"error": f"session not found for {client_id}"}, "404 Not Found")
        await cl_w.drain()
        return
    if old_name:
        asyncio.create_task(_anyip_rotate_api(old_name))
    _inc("rotations")
    _json_response(cl_w, {
        "ok": True,
        "client_id":       client_id,
        "old_session":     old_name,
        "new_session":     result["session_name"],
        "rotation_count":  result["rotation_count"],
    })
    await cl_w.drain()

async def handle_rotate_all(cl_w: asyncio.StreamWriter):
    old_sessions = await _store.snapshot()
    count = await _store.rotate_all()
    if ANYIP_PROXY_ID and ANYIP_INVALIDATE_HASH:
        for s in old_sessions:
            asyncio.create_task(_anyip_rotate_api(s["session_name"]))
    _inc("rotations", count)
    _json_response(cl_w, {"ok": True, "sessions_rotated": count})
    await cl_w.drain()

def _prometheus_metrics() -> bytes:
    lines = []
    for k, v in _counters.items():
        lines.append(f"proxy_{k} {v}")
    lines.append(f"proxy_sessions {len(_store._sessions)}")
    lines.append(f"proxy_active_connections {sum(_ip_limiter._active.values())}")
    lines.append(f"proxy_pool_size {sum(len(dq) for dq in _pool.values())}")
    lines.append(f"proxy_dns_cache_entries {len(_dns_cache)}")
    return ("\n".join(lines) + "\n").encode()

async def handle_metrics(cl_w: asyncio.StreamWriter):
    payload = _prometheus_metrics()
    cl_w.write(
        b"HTTP/1.1 200 OK\r\n"
        b"Content-Type: text/plain\r\n"
        b"Content-Length: " + str(len(payload)).encode() + b"\r\n\r\n" + payload
    )
    await cl_w.drain()

def _parse_management_url(url: str) -> tuple[str, dict[str, str]]:
    if "://" in url:
        rest = url.split("://", 1)[1]
        url = "/" + rest.split("/", 1)[1] if "/" in rest else "/"
    path, _, qs = url.partition("?")
    params: dict[str, str] = {}
    for part in qs.split("&"):
        if "=" in part:
            k, _, v = part.partition("=")
            params[k.strip()] = v.strip()
    return path.rstrip("/"), params

async def dispatch_management(method: str, url: str, cl_w: asyncio.StreamWriter) -> bool:
    path, params = _parse_management_url(url)
    if path == "/_stats":
        await handle_stats(cl_w)
        return True
    if path == "/_sessions":
        await handle_sessions_list(cl_w)
        return True
    if path == "/_rotate_all":
        await handle_rotate_all(cl_w)
        return True
    if path == "/_rotate":
        client_id = params.get("ip") or params.get("client_id", "")
        await handle_rotate(cl_w, client_id)
        return True
    if path == "/_metrics" and PROMETHEUS_METRICS:
        await handle_metrics(cl_w)
        return True
    return False

# ── Client connection handler (with TCP_NODELAY) ─────────────────────────────

async def handle_client(cl_r: asyncio.StreamReader, cl_w: asyncio.StreamWriter):
    # Enable TCP_NODELAY on the client socket for lower latency
    if TCP_NODELAY:
        sock = cl_w.get_extra_info("socket")
        if sock:
            try:
                sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            except Exception:
                pass

    peername = cl_w.get_extra_info("peername")
    peer_ip = peername[0] if peername else "unknown"
    proxy_ip = await _read_proxy_protocol(cl_r)
    client_ip = proxy_ip or peer_ip
    log.debug(
        f"Connection accepted: peer_ip={peer_ip} proxy_ip={proxy_ip or '-'} client_ip={client_ip}"
    )
    if not await _ip_limiter.try_acquire(client_ip):
        cl_w.write(b"HTTP/1.1 429 Too Many Requests\r\nContent-Length: 0\r\n\r\n")
        try:
            await cl_w.drain()
            cl_w.close()
            await cl_w.wait_closed()
        except Exception:
            pass
        _inc("rejected_rate_limit")
        return

    try:
        keep_alive = True
        while keep_alive:
            try:
                req_line = await asyncio.wait_for(cl_r.readline(), timeout=30)
                if not req_line or not req_line.strip():
                    break
                parts = req_line.decode(errors="replace").strip().split()
                if len(parts) < 3:
                    break
                method, url, version = parts[0].upper(), parts[1], parts[2]

                raw_headers: list[bytes] = []
                while True:
                    line = await asyncio.wait_for(cl_r.readline(), timeout=30)
                    stripped = line.rstrip(b"\r\n")
                    if not stripped:
                        break
                    raw_headers.append(stripped)

                extracted_client_ip = _extract_real_ip(client_ip, raw_headers)
                if extracted_client_ip != client_ip:
                    log.debug(
                        f"Client IP updated from headers: peer_ip={peer_ip} previous_client_ip={client_ip} client_ip={extracted_client_ip}"
                    )
                client_ip = extracted_client_ip

                session_id_val: Optional[str] = None
                clean_headers: list[bytes] = []
                log.warning(f"RAW HEADERS from {peer_ip}: {[h.decode(errors='ignore') for h in raw_headers]}")
                for h in raw_headers:
                    if h.lower().startswith(SESSION_ID_HEADER + b":"):
                        session_id_val = h.split(b":", 1)[1].strip().decode(errors="replace")
                    else:
                        clean_headers.append(h)
                raw_headers = clean_headers
                client_id = _build_client_id(client_ip, session_id_val)

                path_check = url if url.startswith("/") else ("/" + url.split("://", 1)[-1].split("/", 1)[-1] if "://" in url else url)
                if path_check.startswith("/_"):
                    await dispatch_management(method, url, cl_w)
                    break

                if method == "CONNECT":
                    host, _, port_str = url.rpartition(":")
                    await handle_connect(cl_r, cl_w, host, int(port_str or 443), client_ip, client_id)
                    break
                else:
                    keep_alive = await handle_http(
                        cl_r, cl_w, method, url, version, raw_headers, client_ip, client_id
                    )
            except asyncio.TimeoutError:
                break
            except (ConnectionResetError, BrokenPipeError):
                break
            except Exception as e:
                log.debug(f"Client error ({client_ip}): {e}")
                break
    finally:
        await _ip_limiter.release(client_ip)

    try:
        cl_w.close()
        await cl_w.wait_closed()
    except Exception:
        pass
# ── Background tasks ─────────────────────────────────────────────────────────

async def _periodic_flush():
    while True:
        await asyncio.sleep(FLUSH_INTERVAL)
        await _store.flush()

async def _periodic_gc():
    while True:
        await asyncio.sleep(GC_INTERVAL)
        await _store.gc()

# ── Worker bootstrap ─────────────────────────────────────────────────────────

async def _async_main(sock: Optional[socket.socket] = None):
    global _store, _pool, _pool_lock, _ip_limiter
    _store = SessionStore(SESSION_STORE_PATH)
    _store.load_sync()
    _pool = collections.defaultdict(collections.deque)
    _pool_lock = asyncio.Lock()
    _ip_limiter = PerIpLimiter(MAX_CONNS_PER_IP)

    asyncio.create_task(_periodic_flush())
    asyncio.create_task(_periodic_gc())

    if sock:
        server = await asyncio.start_server(
            handle_client, sock=sock, limit=2**20, backlog=65535
        )
    else:
        server = await asyncio.start_server(
            handle_client, LISTEN_HOST, LISTEN_PORT,
            limit=2**20, backlog=65535, reuse_port=True
        )

    pid = os.getpid()
    log.info(f"[pid={pid}] Listening on {LISTEN_HOST}:{LISTEN_PORT} | "
             f"upstream={ANYIP_HOST}:{ANYIP_PORT} | type={ANYIP_PROXY_TYPE}")

    async with server:
        await server.serve_forever()

def _worker_main(sock: socket.socket):
    try:
        asyncio.run(_async_main(sock))
    except KeyboardInterrupt:
        pass

# ── Main ─────────────────────────────────────────────────────────────────────

def main():
    _raise_fd_limit()

    if PROXY_WORKERS <= 1:
        log.info("Starting single‑worker mode")
        try:
            asyncio.run(_async_main())
        except KeyboardInterrupt:
            log.info("Shutting down.")
        return

    # Multi‑worker: shared socket with SO_REUSEPORT
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
    except (AttributeError, OSError):
        log.warning("SO_REUSEPORT not available – workers will share a single accept queue")
    sock.bind((LISTEN_HOST, LISTEN_PORT))
    sock.listen(65535)
    sock.setblocking(False)

    log.info(f"Starting {PROXY_WORKERS} worker processes on {LISTEN_HOST}:{LISTEN_PORT}")
    processes: list[multiprocessing.Process] = []
    for _ in range(PROXY_WORKERS):
        p = multiprocessing.Process(target=_worker_main, args=(sock,), daemon=True)
        p.start()
        processes.append(p)

    try:
        for p in processes:
            p.join()
    except KeyboardInterrupt:
        log.info("Shutting down workers.")
        for p in processes:
            p.terminate()
        for p in processes:
            p.join(timeout=5)

if __name__ == "__main__":
    main()
