# AnyIP.io Multiplexer Proxy

Transparent HTTP/HTTPS proxy that routes each client through its own sticky
anyip.io mobile session — **no client credentials required**.

```
Client A ──────────────────────► session_gwAAA ──► anyip.io ──► mobile IP #1
Client B ──► proxy :3128 ──────► session_gwBBB ──► anyip.io ──► mobile IP #2
Client C ──────────────────────► session_gwCCC ──► anyip.io ──► mobile IP #3
NAT clients (X-Session-ID) ────► session_gwDDD ──► anyip.io ──► mobile IP #4
```

---

## How it works

`proxy.py` is a pure-Python asyncio HTTP/HTTPS forward proxy. For every
incoming connection it:

1. Identifies the client by **source IP** (or `X-Session-ID` header for NATted clients)
2. Derives a **deterministic anyip.io session name** via `SHA-256(client_id + salt + config + rotation)`
3. Builds the upstream username with the correct anyip.io flags
4. Injects `Proxy-Authorization` automatically when forwarding to `portal.anyip.io:1080`
5. On `407` from anyip.io — silently rotates the session and retries; **client never sees the error**

Same client → same hash → same anyip.io session → **same exit IP** (within TTL).  
Different clients → different hashes → **different exit IPs**.  
Sessions persist to disk and survive container restarts.

---

## Quick start

```bash
cp .env.example .env
# Edit .env — fill in ANYIP_USERNAME, ANYIP_PASSWORD, ANYIP_SESSION_SALT

docker compose up -d
docker compose logs -f
```

---

## Testing

```bash
# Verify proxy works — no client credentials needed
curl -x http://localhost:3128 https://ipinfo.io

# Two clients with different session IDs → different exit IPs
curl -x http://localhost:3128 -H "X-Session-ID: alice" https://ipinfo.io
curl -x http://localhost:3128 -H "X-Session-ID: bob"   https://ipinfo.io

# HTTPS tunnel (CONNECT method)
curl -x http://localhost:3128 https://ip-api.com/json/
```

---

## Management endpoints

All endpoints are reachable through the proxy itself:

```bash
BASE=http://localhost:3128

# Live stats, counters, config and DNS cache
curl $BASE/_stats

# All active sessions with remaining TTL
curl $BASE/_sessions

# Force a new exit IP for one client
curl "$BASE/_rotate?ip=192.168.1.50"

# Rotate every session at once
curl $BASE/_rotate_all
```

---

## Configuration

All settings via environment variables (`.env`). Copy `.env.example` to start.

### Credentials

| Variable | Default | Description |
|---|---|---|
| `ANYIP_USERNAME` | *(required)* | Your anyip.io username (`user_XXXX`) |
| `ANYIP_PASSWORD` | *(required)* | Your anyip.io password |
| `ANYIP_SESSION_SALT` | `changeme` | Secret for session hashing — **change this** |

### Proxy type & geo-targeting

| Variable | Default | Description |
|---|---|---|
| `ANYIP_PROXY_TYPE` | `mobile` | `mobile` \| `residential` \| `both` |
| `ANYIP_COUNTRY` | `` | ISO country code e.g. `MY`, `US` |
| `ANYIP_CITY` | `` | City name e.g. `KualaLumpur` |

### Session behaviour

| Variable | Default | Description |
|---|---|---|
| `ANYIP_SESSION_MODE` | `sticky` | `sticky` = same IP per client · `rotating` = fresh IP per request |
| `ANYIP_SESSION_MINUTES` | `4320` | Session TTL in minutes (max `10080` = 7 days) |
| `ANYIP_STRICT_COLLISION` | `false` | `sessipcollision_strict` — unique exit IP across all sessions |
| `ANYIP_SESSION_REPLACE` | `true` | `false` → `sessreplace_false` — error on peer drop instead of auto-replace |
| `ANYIP_SESSION_ASN_STRICT` | `false` | `sessasn_strict` — replacement peer must share same ISP/ASN |

### Session rotation API (optional)

Found in anyip.io Dashboard → Proxies → Get Proxy Details.  
When set, `/_rotate` also calls anyip.io's [Change IP URL](https://anyip.io/docs/guides/sessions-and-rotation) to invalidate the old session immediately.

| Variable | Default | Description |
|---|---|---|
| `ANYIP_PROXY_ID` | `` | Proxy account ID from anyip.io dashboard |
| `ANYIP_INVALIDATE_HASH` | `` | Invalidation hash from anyip.io dashboard |

### Performance & reliability

| Variable | Default | Description |
|---|---|---|
| `AUTO_ROTATE_ON_ERROR` | `true` | On `407` from anyip.io: rotate session + retry transparently |
| `SESSION_ID_HEADER` | `X-Session-ID` | Header clients send to override IP-based session key |
| `DNS_TTL` | `300` | Seconds to cache the resolved IP of `ANYIP_HOST` |
| `PROXY_WORKERS` | CPU count | Worker processes (use `1` on free-tier hosts) |
| `MAX_CONNS_PER_IP` | `50` | Max concurrent connections per client IP (per worker) |
| `LOG_LEVEL` | `info` | `debug` \| `info` \| `warning` \| `error` |

### Advanced

| Variable | Default | Description |
|---|---|---|
| `ANYIP_HOST` | `portal.anyip.io` | anyip.io proxy hostname |
| `ANYIP_PORT` | `1080` | anyip.io proxy port |
| `PROXY_PORT` | `3128` | Port this proxy listens on |
| `SESSION_STORE_PATH` | `/var/lib/proxy/sessions.json` | Session persistence file |

---

## NATted clients (shared public IP)

If multiple clients sit behind the same router they all appear as one IP and
would share a single anyip.io session. Send `X-Session-ID` to get independent sessions:

```bash
# alice and bob get different exit IPs even from the same network
curl -x http://proxy:3128 -H "X-Session-ID: alice" https://ipinfo.io
curl -x http://proxy:3128 -H "X-Session-ID: bob"   https://ipinfo.io
```

The header is stripped before the request reaches the target site.

---

## Session rotation

### Manual (force a new exit IP)

```bash
# Rotate one client
curl "http://localhost:3128/_rotate?ip=192.168.1.50"

# Rotate by session ID header value
curl "http://localhost:3128/_rotate?client_id=alice"

# Rotate all
curl http://localhost:3128/_rotate_all
```

### Automatic

- **On 407**: `AUTO_ROTATE_ON_ERROR=true` (default) silently rotates and retries
- **On TTL expiry**: sessions expire after `ANYIP_SESSION_MINUTES` and are recreated on the next request

---

## Deployment on Fly.io (free tier)

```bash
fly launch                                          # detects Dockerfile
fly volumes create proxy_sessions --size 1          # persistent sessions
fly secrets set \
  ANYIP_USERNAME=user_XXX \
  ANYIP_PASSWORD=xxx \
  ANYIP_SESSION_SALT=$(openssl rand -hex 16) \
  ANYIP_COUNTRY=MY
fly deploy
```

Set `PROXY_WORKERS=1` — free VMs have one shared vCPU.
