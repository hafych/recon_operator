"""Rate limiting — memory + optional Redis.

Source of truth for rate-limit state and checks. ``recon_operator.server``
re-exports the same objects so ``import autonmap`` patches (``autonmap.rate_limits``,
``autonmap.MAX_RATE_LIMIT_CLIENTS``, ...) keep working: live lookups prefer the
server module binding when present, falling back to ``recon_operator.config``.
"""

from __future__ import annotations

import ipaddress
import secrets
import sys
import threading
import time
from collections import defaultdict
from typing import Any

from quart import g
from quart import request as _quart_request

import recon_operator.config as _config
from recon_operator.metrics import METRICS

# Re-export config constants for server compat (snapshots at import; live
# lookups below prefer server overrides set by tests at runtime).


def _server_module():
    return sys.modules.get("recon_operator.server")


def _active_request():
    """Return patched server.request when tests override it, else Quart request.

    Tests monkeypatch ``autonmap.request`` with a stub; since this module
    imported ``request`` directly from Quart, honor the server override.
    """
    server = _server_module()
    if server is not None and "request" in getattr(server, "__dict__", {}):
        return server.__dict__["request"]
    return _quart_request


def _active_client_key_fn():
    """Return server._client_key override when tests patch it."""
    server = _server_module()
    if server is not None and "_client_key" in getattr(server, "__dict__", {}):
        candidate = server.__dict__["_client_key"]
        if candidate is not None and candidate is not _client_key and callable(candidate):
            return candidate
    return None


def _live_value(name: str) -> Any:
    """Return server override when present, else config value.

    Tests patch ``autonmap.MAX_RATE_LIMIT_CLIENTS`` etc. Since ``autonmap``
    is an alias of ``recon_operator.server``, prefer that binding at call
    time so patches take effect without reimport.
    """
    server = _server_module()
    if server is not None and hasattr(server, name):
        try:
            return getattr(server, name)
        except Exception:  # noqa: S110 - missing/broken override falls back to config
            pass
    return getattr(_config, name)


def _sync_redis_state_from_server() -> None:
    """Honor server-patched _redis_* globals set by tests."""
    global _redis_client, _redis_init_attempted, _redis_available
    server = _server_module()
    if server is None:
        return
    for name in ("_redis_client", "_redis_init_attempted", "_redis_available"):
        if name in getattr(server, "__dict__", {}):
            try:
                globals()[name] = server.__dict__[name]
            except Exception:  # noqa: S110 - best effort test sync
                pass


TRUSTED_PROXIES = _config.TRUSTED_PROXIES
TRUSTED_PROXY_MODE = _config.TRUSTED_PROXY_MODE
RATE_LIMIT_INCLUDE_OWNER = _config.RATE_LIMIT_INCLUDE_OWNER
MAX_RATE_LIMIT_CLIENTS = _config.MAX_RATE_LIMIT_CLIENTS
RATE_LIMIT_WINDOW_SECONDS = _config.RATE_LIMIT_WINDOW_SECONDS
MAX_REQUESTS_PER_WINDOW = _config.MAX_REQUESTS_PER_WINDOW
REDIS_URL = _config.REDIS_URL
REDIS_RATE_LIMIT_PREFIX = _config.REDIS_RATE_LIMIT_PREFIX

rate_limits = defaultdict(list)
_rate_limit_lock = threading.Lock()

_redis_client: Any = None
_redis_init_attempted = False
_redis_available = False


def _get_redis_client() -> Any:
    global _redis_client, _redis_init_attempted, _redis_available
    _sync_redis_state_from_server()
    redis_url = _live_value("REDIS_URL")
    if not redis_url:
        return None
    if _redis_init_attempted:
        return _redis_client if _redis_available else None
    _redis_init_attempted = True
    try:
        import redis  # type: ignore
    except ImportError:
        _redis_available = False
        return None
    try:
        client = redis.Redis.from_url(
            redis_url,
            decode_responses=True,
            socket_connect_timeout=1.0,
            socket_timeout=1.0,
            health_check_interval=30,
        )
        client.ping()
        _redis_client = client
        _redis_available = True
        return client
    except Exception:
        _redis_client = None
        _redis_available = False
        return None


def reset_rate_limit_state() -> None:
    """Clear in-memory buckets and Redis client cache (tests only)."""
    global _redis_client, _redis_init_attempted, _redis_available
    rate_limits.clear()
    _redis_client = None
    _redis_init_attempted = False
    _redis_available = False


def rate_limit_backend() -> str:
    redis_url = _live_value("REDIS_URL")
    if redis_url and _get_redis_client() is not None:
        return "redis"
    if redis_url:
        return "memory_fallback"
    return "memory"


def _peer_is_trusted_proxy(peer: str) -> bool:
    if not peer or peer == "unknown":
        return False
    try:
        peer_ip = ipaddress.ip_address(peer)
    except ValueError:
        return False
    for entry in _live_value("TRUSTED_PROXIES"):
        try:
            if "/" in entry:
                if peer_ip in ipaddress.ip_network(entry, strict=False):
                    return True
            elif peer_ip == ipaddress.ip_address(entry):
                return True
        except ValueError:
            continue
    return False


def _first_valid_ip(candidates: str) -> str | None:
    for part in candidates.split(","):
        candidate = part.strip()
        if not candidate:
            continue
        if candidate.count(":") == 1 and not candidate.startswith("["):
            candidate = candidate.split(":", 1)[0].strip()
        try:
            return str(ipaddress.ip_address(candidate))
        except ValueError:
            continue
    return None


def _client_key() -> str:
    req = _active_request()
    peer = req.remote_addr or "unknown"
    trusted_mode = _live_value("TRUSTED_PROXY_MODE")
    if not trusted_mode or not _peer_is_trusted_proxy(peer):
        return peer
    xff = (req.headers.get("X-Forwarded-For") or "").strip()
    if xff:
        forwarded = _first_valid_ip(xff)
        if forwarded:
            return forwarded
    xreal = (req.headers.get("X-Real-IP") or "").strip()
    if xreal:
        real_ip = _first_valid_ip(xreal)
        if real_ip:
            return real_ip
    return peer


def _rate_limit_bucket_key() -> str:
    override = _active_client_key_fn()
    client_ip = override() if override is not None else _client_key()
    if not _live_value("RATE_LIMIT_INCLUDE_OWNER"):
        return client_ip
    try:
        owner = getattr(g, "owner_id", None)
    except RuntimeError:
        owner = None
    if not owner or owner == "local":
        return client_ip
    return f"{client_ip}:o{owner[:12]}"


def _check_rate_limit_memory(bucket: str) -> bool:
    now = time.time()
    max_clients = _live_value("MAX_RATE_LIMIT_CLIENTS")
    window = _live_value("RATE_LIMIT_WINDOW_SECONDS")
    limit = _live_value("MAX_REQUESTS_PER_WINDOW")
    with _rate_limit_lock:
        if bucket not in rate_limits and len(rate_limits) >= max_clients:
            stale_before = now - window
            stale_clients = [
                key
                for key, timestamps in rate_limits.items()
                if not timestamps or timestamps[-1] <= stale_before
            ]
            for key in stale_clients:
                rate_limits.pop(key, None)
            if len(rate_limits) >= max_clients:
                oldest_client = min(
                    rate_limits,
                    key=lambda key: rate_limits[key][-1] if rate_limits[key] else 0,
                )
                rate_limits.pop(oldest_client, None)
        request_window = rate_limits[bucket]
        rate_limits[bucket] = [req_time for req_time in request_window if now - req_time < window]
        if len(rate_limits[bucket]) >= limit:
            return False
        rate_limits[bucket].append(now)
        return True


_REDIS_RATE_LIMIT_LUA = """
local key = KEYS[1]
local now = tonumber(ARGV[1])
local window = tonumber(ARGV[2])
local limit = tonumber(ARGV[3])
local member = ARGV[4]
redis.call('ZREMRANGEBYSCORE', key, 0, now - window)
local count = redis.call('ZCARD', key)
if count >= limit then
  return 0
end
redis.call('ZADD', key, now, member)
redis.call('EXPIRE', key, window + 1)
return 1
"""


def _check_rate_limit_redis(client: Any, bucket: str) -> bool:
    now = time.time()
    prefix = _live_value("REDIS_RATE_LIMIT_PREFIX")
    window = _live_value("RATE_LIMIT_WINDOW_SECONDS")
    limit = _live_value("MAX_REQUESTS_PER_WINDOW")
    key = f"{prefix}{bucket}"
    member = f"{now:.6f}:{secrets.token_hex(4)}"
    try:
        allowed = client.eval(
            _REDIS_RATE_LIMIT_LUA,
            1,
            key,
            str(now),
            str(window),
            str(limit),
            member,
        )
        return bool(int(allowed))
    except Exception:
        return _check_rate_limit_memory(bucket)


def check_rate_limit() -> bool:
    bucket = _rate_limit_bucket_key()
    client = _get_redis_client()
    if client is not None:
        allowed = _check_rate_limit_redis(client, bucket)
    else:
        allowed = _check_rate_limit_memory(bucket)
    if not allowed:
        METRICS.inc("recon_operator_rate_limit_exceeded_total")
    return allowed
