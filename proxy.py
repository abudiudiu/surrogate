#!/usr/bin/env python3
"""
proxy.py v6 — High-performance transparent HTTP/HTTPS multiplexer for anyip.io

Each client gets its own deterministic anyip.io session. No client auth needed.

anyip.io session features (https://anyip.io/docs/guides/sessions-and-rotation):
  • Rotating mode      — ANYIP_SESSION_MODE=rotating → fresh IP per request
  • Sticky sessions    — ANYIP_SESSION_MODE=sticky (default) → persistent per-client session
  • Custom duration    — ANYIP_SESSION_MINUTES (1–10 080 min) → sesstime_N
  • Auto-replace       — ANYIP_SESSION_REPLACE=false → sessreplace_false
  • IP collision guard — ANYIP_STRICT_COLLISION=true → sessipcollision_strict
  • ASN/ISP strict     — ANYIP_SESSION_ASN_STRICT=true → sessasn_strict
  • Force rotation     — GET /_rotate?ip=X — increment counter → new exit IP;
                         also calls anyip.io Change IP URL if ANYIP_PROXY_ID/ANYIP_INVALIDATE_HASH set

New in v6 vs v5:
  1. DNS caching      — ANYIP_HOST resolved once per DNS_TTL seconds (default 5 min);
                        eliminates per-connection DNS round-trips on slow free-tier resolvers
  2. Auto-rotate      — AUTO_ROTATE_ON_ERROR=true (default): on 407 from anyip.io the session
                        is silently rotated and the request retried; client never sees the error
  3. X-Session-ID     — SESSION_ID_HEADER (default: X-Session-ID): clients can send this header
                        to override the IP-based session key — essential for NATted environments
                        where all clients share one public IP; header is stripped before forwarding

Management endpoints:
  GET  /_stats            live counters, config, DNS cache state
  GET  /_sessions         all active sessions + remaining TTL
  GET  /_rotate?ip=X      rotate a single session (also accepts client_id=X)
  GET  /_rotate_all       rotate every session
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
    uvloop.install()          # preferred API on Python ≥ 3.11; also works on 3.10
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

# ── anyip.io session flags (see https://anyip.io/docs/guides/sessions-and-rotation)
# sticky  = same IP per client (default)
# rotating = fresh IP per request (no session flag sent)
ANYIP_SESSION_MODE    = os.environ.get("ANYIP_SESSION_MODE",    "sticky").lower()

# sessipcollision_strict — no two sessions ever share the same exit IP
ANYIP_STRICT_COLLISION = os.environ.get("ANYIP_STRICT_COLLISION", "false").lower() == "true"

# sessreplace_false — when a sticky IP goes offline, return peer_not_found
# instead of silently rotating to a new IP (default: True = allow auto-replace)
ANYIP_SESSION_REPLACE  = os.environ.get("ANYIP_SESSION_REPLACE",  "true").lower() == "true"

# sessasn_strict — when an IP is replaced, enforce same ISP/ASN
ANYIP_SESSION_ASN_STRICT = os.environ.get("ANYIP_SESSION_ASN_STRICT", "false").lower() == "true"

# anyip.io "Change IP URL" credentials — found in Dashboard > Proxies > Get Proxy Details
# If set, /_rotate will also call anyip.io's API to invalidate the session there immediately
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
MAX_IDLE_PER_SESSION = 8
FLUSH_INTERVAL       = 30
GC_INTERVAL          = 300
TARGET_NOFILE        = 65536
WRITE_BUFFER_HIGH    = 256 * 1024   # drain / yield when write-buffer exceeds this

# ── Feature flags ─────────────────────────────────────────────────────────────

# DNS cache TTL — how long to reuse the resolved IP of ANYIP_HOST (seconds)
DNS_TTL = int(os.environ.get("DNS_TTL", "300"))

# Auto-rotate session + retry on 407 from anyip.io (bad/expired session)
AUTO_ROTATE_ON_ERROR = os.environ.get("AUTO_ROTATE_ON_ERROR", "true").lower() == "true"

# Header clients can send to override the session key (default: their IP)
# Useful for NATted clients (office, shared WiFi) who all appear as the same IP
SESSION_ID_HEADER = os.environ.get("SESSION_ID_HEADER", "X-Session-ID").lower().encode()

_NO_BODY_STATUS = frozenset({100, 101, 102, 103, 204, 304})

# ── Logging ───────────────────────────────────────────────────────────────────

logging.basicConfig(
    level=getattr(logging, LOG_LEVEL, logging.INFO),
    format="%(asctime)s [%(levelname)s] %(message)s",
    stream=sys.stderr,
)
log = logging.getLogger("proxy")

# ── Live counters (per-worker; shown in /_stats) ──────────────────────────────

_counters: dict[str, int] = collections.defaultdict(int)


def _inc(key: str, n: int = 1):
    _counters[key] += n

# ── DNS cache ─────────────────────────────────────────────────────────────────

_dns_cache: dict[str, tuple[str, float]] = {}   # host → (resolved_ip, expiry_ts)


async def _resolve_host(host: str) -> str:
    """Resolve hostname to IP with a local TTL cache.

    Avoids a DNS round-trip on every new upstream connection — especially
    important on free-tier hosts whose resolvers are slow (5–50 ms each).
    Falls back to the original hostname on any resolver error.
    """
    now = time.time()
    entry = _dns_cache.get(host)
    if entry and now < entry[1]:
        return entry[0]
    try:
        loop = asyncio.get_running_loop()
        infos = await loop.getaddrinfo(host, None, type=socket.SOCK_STREAM)
        ip = infos[0][4][0]
        _dns_cache[host] = (ip, now + DNS_TTL)
        log.debug(f"DNS resolved: {host} → {ip} (TTL={DNS_TTL}s)")
        return ip
    except Exception as exc:
        log.warning(f"DNS resolve failed for {host}: {exc} — using hostname")
        return host

# ── OS file-descriptor limit ──────────────────────────────────────────────────

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

# ── Session store ─────────────────────────────────────────────────────────────

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
                return dict(s)     # shallow-copy; all values are immutable
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
        # Acquire an exclusive flock on a sidecar .lock file before writing so
        # concurrent worker processes don't clobber each other's output.
        # The tmp→rename is still atomic; the lock just serialises the write.
        try:
            self._path.parent.mkdir(parents=True, exist_ok=True)
            lock_path = self._path.with_suffix(".lock")
            with open(lock_path, "w") as lf:
                fcntl.flock(lf, fcntl.LOCK_EX)      # blocks until lock acquired
                tmp = self._path.with_suffix(".tmp")
                tmp.write_text(json.dumps(data, indent=2))
                tmp.replace(self._path)
                # lock released automatically when `lf` is closed
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
        """Force a new anyip.io session for client_id by incrementing the
        rotation counter → new SHA-256 → new session name → new exit IP."""
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
        """Rotate every session. Returns number of sessions rotated."""
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


def _make_session_name(client_id: str, rotation: int = 0) -> str:
    """Deterministic session name from client identity + config + rotation counter.
    Changing country/type/rotation produces a new name → anyip.io creates a
    fresh session with the correct filters."""
    key = ":".join([
        client_id,
        SESSION_SALT,
        ANYIP_PROXY_TYPE,
        ANYIP_COUNTRY or "",
        ANYIP_CITY or "",
        str(rotation),
    ])
    return "gw" + hashlib.sha256(key.encode()).hexdigest()[:16]


def _build_auth(session_name: Optional[str]) -> str:
    """
    Build the Base64-encoded Proxy-Authorization value for anyip.io.

    Username flag order follows anyip.io docs:
      user_XXXX [,country_XX] [,city_XX] ,type_XX
      [,session_NAME ,sesstime_N] [,sessreplace_false]
      [,sessipcollision_strict] [,sessasn_strict]

    If session_name is None (ANYIP_SESSION_MODE=rotating), session flags are
    omitted → anyip.io uses a fresh IP for every request.
    """
    parts = [ANYIP_USERNAME]
    if ANYIP_COUNTRY:
        parts.append(f"country_{ANYIP_COUNTRY}")
    if ANYIP_CITY:
        parts.append(f"city_{ANYIP_CITY}")
    parts.append(f"type_{ANYIP_PROXY_TYPE}")

    if session_name:                             # sticky mode
        parts.append(f"session_{session_name}")
        parts.append(f"sesstime_{ANYIP_SESSION_MINUTES}")
        if not ANYIP_SESSION_REPLACE:
            parts.append("sessreplace_false")    # keep same IP or error, never auto-rotate
        if ANYIP_STRICT_COLLISION:
            parts.append("sessipcollision_strict")
        if ANYIP_SESSION_ASN_STRICT:
            parts.append("sessasn_strict")       # replacement must use same ISP/ASN

    return base64.b64encode(f"{','.join(parts)}:{ANYIP_PASSWORD}".encode()).decode()


async def _get_auth(client_ip: str) -> str:
    if ANYIP_SESSION_MODE == "rotating":
        return _build_auth(None)   # no session flag → fresh IP per request
    session = await _store.get_or_create(client_ip)
    return _build_auth(session["session_name"])

# ── Per-IP connection limiter ─────────────────────────────────────────────────

class PerIpLimiter:
    """
    Tracks active connection counts per client IP.

    Uses an asyncio.Lock for atomic check-and-increment, eliminating the
    private-attribute (_value) access that BoundedSemaphore required and the
    race window between the check and the subsequent acquire().

    Note: limits are per-worker-process. Global maximum is
    MAX_CONNS_PER_IP × PROXY_WORKERS. For strict global limits, a shared
    store (Redis) would be needed; for 1000 clients, per-worker is sufficient.
    """

    def __init__(self, max_conns: int):
        self._max = max_conns
        self._active: dict[str, int] = collections.defaultdict(int)
        self._lock = asyncio.Lock()

    async def try_acquire(self, ip: str) -> bool:
        """Atomically check and increment. Returns False if at limit."""
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

# ── HTTP upstream connection pool ─────────────────────────────────────────────

_pool: dict[str, collections.deque]   # set in _async_main


async def _pool_acquire(auth: str) -> Optional[tuple[asyncio.StreamReader, asyncio.StreamWriter]]:
    async with _pool_lock:
        dq = _pool.get(auth)
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
    async with _pool_lock:
        dq = _pool[auth]
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

# ── Pipe (CONNECT tunnels) — with cooperative yield on read side ──────────────

async def _pipe(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
    try:
        while True:
            data = await asyncio.wait_for(reader.read(65536), timeout=IDLE_TIMEOUT)
            if not data:
                break
            writer.write(data)
            buf = writer.transport.get_write_buffer_size()
            if buf > WRITE_BUFFER_HIGH:
                await writer.drain()   # block until consumer catches up (backpressure)
            else:
                await asyncio.sleep(0) # cooperative yield — let slow reader catch up
    except (asyncio.TimeoutError, asyncio.CancelledError,
            ConnectionResetError, BrokenPipeError, OSError):
        pass
    finally:
        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass

# ── HTTP response forwarder ───────────────────────────────────────────────────

async def _forward_response(
    up_r: asyncio.StreamReader,
    cl_w: asyncio.StreamWriter,
    method: str,
) -> tuple[bool, int]:
    """Read one HTTP response from up_r and write to cl_w.

    Returns (upstream_keep_alive, status_code).
    On 407 the response is silently drained — nothing is written to cl_w so
    the caller can rotate the session and retry transparently.
    """
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

    # 407 from anyip.io means our session credentials were rejected.
    # Drain the body silently so the caller can rotate and retry without
    # the client ever seeing the error.
    if status_code == 407:
        try:
            if content_length:
                await asyncio.wait_for(up_r.read(content_length), timeout=5)
            elif chunked:
                # Read until terminal chunk — best effort
                tmp = leftover
                while not tmp.endswith(b"0\r\n\r\n"):
                    more = await asyncio.wait_for(up_r.read(4096), timeout=5)
                    if not more:
                        break
                    tmp += more
        except Exception:
            pass
        return False, 407

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
            cl_w.write(leftover)
        while remaining > 0:
            chunk = await asyncio.wait_for(
                up_r.read(min(remaining, 65536)), timeout=IDLE_TIMEOUT
            )
            if not chunk:
                break
            cl_w.write(chunk)
            remaining -= len(chunk)
            if cl_w.transport.get_write_buffer_size() > WRITE_BUFFER_HIGH:
                await cl_w.drain()
        await cl_w.drain()
        return upstream_keep_alive and (remaining <= 0), status_code

    # No content-length — read until upstream closes
    if leftover:
        cl_w.write(leftover)
    while True:
        try:
            chunk = await asyncio.wait_for(up_r.read(65536), timeout=IDLE_TIMEOUT)
            if not chunk:
                break
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
                writer.write(buf or b"\r\n")
                return True

            need = chunk_size + 2
            while len(buf) < need:
                more = await asyncio.wait_for(reader.read(65536), timeout=IDLE_TIMEOUT)
                if not more:
                    return False
                buf += more

            writer.write(buf[:chunk_size])
            writer.write(b"\r\n")
            buf = buf[need:]

            if writer.transport.get_write_buffer_size() > WRITE_BUFFER_HIGH:
                await writer.drain()

    except Exception:
        return False

# ── CONNECT handler ───────────────────────────────────────────────────────────

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
            log.warning(f"CONNECT 407 — auto-rotating session for {client_id}")
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

# ── HTTP handler (keep-alive + connection pool) ───────────────────────────────

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
    """Returns True if the client connection should be kept alive."""
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

    # Read body once (before any retry loop — client can't re-send it)
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

        if status_code == 407 and attempt == 0:
            log.warning(f"HTTP 407 — auto-rotating session for {client_id}")
            _inc("auto_rotations")
            try:
                up_w.close()
            except Exception:
                pass
            await _store.rotate(client_id)
            continue   # retry with new session

        if upstream_keep_alive:
            await _pool_release(auth, up_r, up_w)
        else:
            try:
                up_w.close()
            except Exception:
                pass

        return client_keep_alive and upstream_keep_alive

    # Both attempts exhausted (shouldn't normally reach here)
    cl_w.write(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
    await cl_w.drain()
    _inc("errors")
    return False

# ── anyip.io rotation API ─────────────────────────────────────────────────────

async def _anyip_rotate_api(session_name: str):
    """Call anyip.io's Change IP URL to immediately invalidate a session there.
    Only fires if ANYIP_PROXY_ID and ANYIP_INVALIDATE_HASH are configured.
    See: https://anyip.io/docs/guides/sessions-and-rotation"""
    if not ANYIP_PROXY_ID or not ANYIP_INVALIDATE_HASH:
        return
    url = (
        f"https://dashboard.anyip.io/api/proxy_accounts/"
        f"{ANYIP_PROXY_ID}/invalidate/{ANYIP_INVALIDATE_HASH}/session/{session_name}"
    )
    try:
        loop = asyncio.get_running_loop()
        await loop.run_in_executor(
            None,
            lambda: urllib.request.urlopen(url, timeout=10).read(),
        )
        log.info(f"anyip.io API: invalidated session {session_name}")
    except Exception as e:
        log.warning(f"anyip.io rotation API failed for {session_name}: {e}")

# ── Management HTTP endpoint helpers ──────────────────────────────────────────

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

    # Also call anyip.io's API to invalidate the old session immediately
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
    # Snapshot old names for API invalidation
    old_sessions = await _store.snapshot()
    count = await _store.rotate_all()

    # Invalidate each old session via anyip.io API concurrently
    if ANYIP_PROXY_ID and ANYIP_INVALIDATE_HASH:
        for s in old_sessions:
            asyncio.create_task(_anyip_rotate_api(s["session_name"]))

    _inc("rotations", count)
    _json_response(cl_w, {"ok": True, "sessions_rotated": count})
    await cl_w.drain()


def _parse_management_url(url: str) -> tuple[str, dict[str, str]]:
    """Extract path and query params from an absolute or relative proxy URL."""
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


async def dispatch_management(
    method: str,
    url: str,
    cl_w: asyncio.StreamWriter,
) -> bool:
    """Route management endpoints. Returns True if the request was handled."""
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

    return False

# ── Client connection entry point ─────────────────────────────────────────────

async def handle_client(
    cl_r: asyncio.StreamReader,
    cl_w: asyncio.StreamWriter,
):
    peername = cl_w.get_extra_info("peername")
    client_ip = peername[0] if peername else "unknown"

    # Per-IP concurrency limit — atomic check-and-increment (no private attrs)
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

                # ── Derive session key ────────────────────────────────────────
                # Clients behind NAT all share one IP; they can send
                # X-Session-ID (or whatever SESSION_ID_HEADER is set to) to
                # get their own independent sticky session.
                session_id_val: Optional[str] = None
                clean_headers: list[bytes] = []
                for h in raw_headers:
                    if h.lower().startswith(SESSION_ID_HEADER + b":"):
                        session_id_val = h.split(b":", 1)[1].strip().decode(errors="replace")
                    else:
                        clean_headers.append(h)
                raw_headers = clean_headers            # strip header before forwarding
                client_id = session_id_val or client_ip

                # Management endpoints — intercept before forwarding upstream
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

# ── Background tasks ──────────────────────────────────────────────────────────

async def _periodic_flush():
    while True:
        await asyncio.sleep(FLUSH_INTERVAL)
        await _store.flush()


async def _periodic_gc():
    while True:
        await asyncio.sleep(GC_INTERVAL)
        await _store.gc()

# ── Worker bootstrap ──────────────────────────────────────────────────────────

async def _async_main(sock: Optional[socket.socket] = None):
    """Initialise per-worker globals then start serving."""
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
            handle_client, sock=sock, limit=2 ** 20, backlog=1024
        )
    else:
        server = await asyncio.start_server(
            handle_client, LISTEN_HOST, LISTEN_PORT, limit=2 ** 20, backlog=1024
        )

    pid = os.getpid()
    log.info(f"[pid={pid}] Listening on {LISTEN_HOST}:{LISTEN_PORT} | "
             f"upstream={ANYIP_HOST}:{ANYIP_PORT} | type={ANYIP_PROXY_TYPE}")

    async with server:
        await server.serve_forever()


def _worker_main(sock: socket.socket):
    """Entry point for each child worker process."""
    try:
        asyncio.run(_async_main(sock))
    except KeyboardInterrupt:
        pass

# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    _raise_fd_limit()

    if PROXY_WORKERS <= 1:
        log.info("Starting single-worker mode")
        try:
            asyncio.run(_async_main())
        except KeyboardInterrupt:
            log.info("Shutting down.")
        return

    # Multi-worker: create a shared socket with SO_REUSEPORT, then fork.
    # Each worker gets its own event loop and session store.
    # Session names are deterministic (SHA-256), so all workers produce the
    # same anyip.io session name for a given client IP — no coordination needed.
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
    except (AttributeError, OSError):
        log.warning("SO_REUSEPORT not available — workers will share a single accept queue")
    sock.bind((LISTEN_HOST, LISTEN_PORT))
    sock.listen(1024)
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
