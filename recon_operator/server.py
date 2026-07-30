"""Recon Operator server implementation (package entry for routes, jobs, auth)."""

import asyncio
import fcntl
import hashlib
import ipaddress
import json
import logging
import math
import os
import re
import secrets
import shutil
import signal
import subprocess
import tempfile
import threading
import time
import uuid
from collections import defaultdict
from datetime import datetime, timezone
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from cryptography.fernet import InvalidToken
from dotenv import load_dotenv
from quart import Quart, g, jsonify, request
from telegram import Bot
from telegram.error import TelegramError

import recon_operator.auth as _auth
import recon_operator.config as _config
from recon_operator.ai_pack import build_ai_pack, normalize_budget
from recon_operator.crypto import build_fernet_cipher, load_fernet_key_material
from recon_operator.metrics import METRICS
from recon_operator.playbook import (
    build_engagement_record,
    list_playbooks,
    public_engagement_view,
    resolve_phases,
)
from recon_operator.posture import evaluate_posture, load_expected_posture
from recon_operator.presets import (
    PHASE_ORDER,
    apply_preset_to_payload,
    list_presets,
    next_phase,
)
from recon_planner import build_recon_plan, recon_plan_to_jsonl, recon_plan_to_markdown
from scan_engine import (
    PRODUCT_NAME,
    DiscoveryError,
    NmapNotFoundError,
    NmapScanError,
    NmapTimeoutError,
    ScanCancelledError,
    available_discovery_engines,
    clear_process_token,
    diff_scan_results,
    import_nmap_xml,
    kill_active_process,
    mark_process_cancelled,
    prepare_process_token,
    run_nmap_scan,
    supported_scan_types,
    validate_discovery,
    validate_ports_expression,
    validate_scripts_expression,
)
from state_store import StateStore
from tool_inventory import build_tool_inventory, inventory_to_jsonl, inventory_to_markdown
from ui import UI_HTML

load_dotenv()

"""
Recon Operator — multi-tool recon control plane (Nmap engine, Kali inventory, planner).

Immediate scan (async job):
curl -X POST http://127.0.0.1:5000/scan \\
  -H "X-API-KEY: $API_TOKEN" \\
  -H "Content-Type: application/json" \\
  -d '{"target":"127.0.0.1","scan_type":"Ping"}'

Poll job:
curl -H "X-API-KEY: $API_TOKEN" http://127.0.0.1:5000/jobs/<job_id>
"""


start_time = datetime.now(timezone.utc)


class JobCancelledError(RuntimeError):
    """A scan job reached the cancelled domain state."""


# --- Config surface (source of truth: recon_operator.config) ---
VERSION = _config.VERSION
SCAN_LOG_PATH = _config.SCAN_LOG_PATH
RESULTS_DIR = _config.RESULTS_DIR
APP_HOST = _config.APP_HOST
APP_PORT = _config.APP_PORT
_parse_bool_env = _config._parse_bool_env
_parse_int_env = _config._parse_int_env
API_AUTH_REQUIRED = _config.API_AUTH_REQUIRED
API_AUTH_HEADER = _config.API_AUTH_HEADER
RATE_LIMIT_WINDOW_SECONDS = _config.RATE_LIMIT_WINDOW_SECONDS
MAX_REQUESTS_PER_WINDOW = _config.MAX_REQUESTS_PER_WINDOW
MAX_RATE_LIMIT_CLIENTS = _config.MAX_RATE_LIMIT_CLIENTS
REDIS_URL = _config.REDIS_URL
REDIS_RATE_LIMIT_PREFIX = _config.REDIS_RATE_LIMIT_PREFIX
RATE_LIMIT_INCLUDE_OWNER = _config.RATE_LIMIT_INCLUDE_OWNER
TRUSTED_PROXY_MODE = _config.TRUSTED_PROXY_MODE
TRUSTED_PROXIES = _config.TRUSTED_PROXIES
_load_trusted_proxies = _config._load_trusted_proxies
WORKER_ID = _config.WORKER_ID
JOB_LEASE_SECONDS = _config.JOB_LEASE_SECONDS
JOB_CLAIM_POLL_SECONDS = _config.JOB_CLAIM_POLL_SECONDS
REDIS_JOB_LEASE_PREFIX = _config.REDIS_JOB_LEASE_PREFIX
SCHEDULER_LOCK_NAME = _config.SCHEDULER_LOCK_NAME
SCHEDULER_LEADER_SECONDS = _config.SCHEDULER_LEADER_SECONDS
SCHEDULER_LEADER_POLL_SECONDS = _config.SCHEDULER_LEADER_POLL_SECONDS
REDIS_LEADER_PREFIX = _config.REDIS_LEADER_PREFIX
MAX_CONCURRENT_SCANS = _config.MAX_CONCURRENT_SCANS
MAX_SCHEDULED_TASKS = _config.MAX_SCHEDULED_TASKS
MAX_SCAN_JOBS = _config.MAX_SCAN_JOBS
SCAN_TIMEOUT_SECONDS = _config.SCAN_TIMEOUT_SECONDS
TOOL_INVENTORY_CACHE_SECONDS = _config.TOOL_INVENTORY_CACHE_SECONDS
MAX_TARGET_ADDRESSES = _config.MAX_TARGET_ADDRESSES
MAX_REQUEST_BODY_BYTES = _config.MAX_REQUEST_BODY_BYTES
MIN_SCHEDULE_INTERVAL_MINUTES = _config.MIN_SCHEDULE_INTERVAL_MINUTES
MAX_SCHEDULE_INTERVAL_MINUTES = _config.MAX_SCHEDULE_INTERVAL_MINUTES
RESULTS_MAX_FILES = _config.RESULTS_MAX_FILES
RESULTS_MAX_AGE_DAYS = _config.RESULTS_MAX_AGE_DAYS
LEGACY_RESULTS_SHARED = _config.LEGACY_RESULTS_SHARED
MAX_IMPORT_XML_BYTES = _config.MAX_IMPORT_XML_BYTES
STATE_DB_PATH = _config.STATE_DB_PATH
_load_target_allowlist = _config._load_target_allowlist
TARGET_ALLOWLIST = _config.TARGET_ALLOWLIST
HOST_TIMEOUT_SEC = _config.HOST_TIMEOUT_SEC
NMAP_MAX_RETRIES = _config.NMAP_MAX_RETRIES
FERNET_KEY = _config.FERNET_KEY
FERNET_PREVIOUS_KEYS_RAW = _config.FERNET_PREVIOUS_KEYS_RAW
AUDIT_LOG_PATH = _config.AUDIT_LOG_PATH
AUDIT_LOG_MAX_EVENTS = _config.AUDIT_LOG_MAX_EVENTS
METRICS_AUTH_REQUIRED = _config.METRICS_AUTH_REQUIRED
STRUCTURED_LOGS = _config.STRUCTURED_LOGS

# --- Auth surface (source of truth: recon_operator.auth) ---
API_KEY_SCOPES = _auth.API_KEY_SCOPES
API_KEY_ID_RE = _auth.API_KEY_ID_RE
_normalize_key_scopes = _auth._normalize_key_scopes
_expand_scopes = _auth._expand_scopes
_public_api_key_view = _auth._public_api_key_view
_load_api_auth_keys = _auth._load_api_auth_keys
_load_api_auth_tokens = _auth._load_api_auth_tokens
API_AUTH_KEYS = _auth.reload_api_auth_registry()
API_AUTH_TOKENS = _auth.API_AUTH_TOKENS
API_AUTH_TOKEN = _auth.API_AUTH_TOKEN
_resolve_api_key = _auth._resolve_api_key
_token_is_authorized = _auth._token_is_authorized
scopes_allow = _auth.scopes_allow
owner_id_from_token = _auth.owner_id_from_token
current_owner_id = _auth.current_owner_id
current_api_key_id = _auth.current_api_key_id
current_scopes = _auth.current_scopes
require_api_auth = _auth.require_api_auth


def _create_log_handler():
    for path in [SCAN_LOG_PATH, "scan_log.txt"]:
        try:
            log_dir = os.path.dirname(path)
            if log_dir:
                os.makedirs(log_dir, exist_ok=True)
            return RotatingFileHandler(
                path,
                maxBytes=10 * 1024 * 1024,
                backupCount=5,
            )
        except (OSError, ValueError):
            continue
    return logging.StreamHandler()


logging.basicConfig(
    handlers=[_create_log_handler()],
    level=logging.INFO,
    format="[%(asctime)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)

TELEGRAM_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN")
CHAT_ID = os.getenv("TELEGRAM_CHAT_ID")
bot = Bot(token=TELEGRAM_TOKEN) if TELEGRAM_TOKEN and CHAT_ID else None

_redis_client: Any = None
_redis_init_attempted = False
_redis_available = False
_job_worker_task: Optional[asyncio.Task] = None
_scheduler_leader_task: Optional[asyncio.Task] = None
_is_scheduler_leader = False

if API_AUTH_REQUIRED and not API_AUTH_TOKENS:
    raise RuntimeError(
        "API_AUTH_REQUIRED=true, but no API tokens are configured. "
        "Set API_AUTH_TOKEN, API_AUTH_TOKENS, and/or API_AUTH_KEYS."
    )

try:
    FERNET_KEYS = load_fernet_key_material()
    cipher = build_fernet_cipher(FERNET_KEYS)
except RuntimeError:
    raise
FERNET_KEY_COUNT = len(FERNET_KEYS)


# Static UI assets live at the repo-root ``static/`` directory (not under this package).
_STATIC_DIR = Path(__file__).resolve().parent.parent / "static"
app = Quart(
    __name__,
    static_folder=str(_STATIC_DIR),
    static_url_path="/static",
)
# Quart applies this ceiling before route dispatch. Use the largest supported
# body here; a route-aware hook below keeps ordinary JSON at the lower limit.
app.config["MAX_CONTENT_LENGTH"] = max(MAX_REQUEST_BODY_BYTES, MAX_IMPORT_XML_BYTES)
scan_tasks: Dict[str, asyncio.Task] = {}
scan_jobs: Dict[str, Dict[str, Any]] = {}
engagements: Dict[str, Dict[str, Any]] = {}
_engagement_tasks: Dict[str, asyncio.Task] = {}
rate_limits = defaultdict(list)
tool_inventory_cache = {}
tool_inventory_locks = defaultdict(threading.Lock)
_scan_semaphore: Optional[asyncio.Semaphore] = None
_jobs_lock = asyncio.Lock()
_engagements_lock = asyncio.Lock()
state_store = StateStore(STATE_DB_PATH)


@app.before_request
async def _enforce_route_body_limit():
    if request.method not in {"POST", "PUT", "PATCH"}:
        return None
    if request.path == "/results/import":
        return None
    content_length = request.content_length
    if content_length is not None and content_length > MAX_REQUEST_BODY_BYTES:
        return jsonify({"error": "Request body too large"}), 413
    if content_length is None:
        body = await request.get_data(cache=True)
        if len(body) > MAX_REQUEST_BODY_BYTES:
            return jsonify({"error": "Request body too large"}), 413
    return None


@app.errorhandler(413)
async def _request_too_large(_error):
    return jsonify({"error": "Request body too large"}), 413


SUPPORTED_SCAN_TYPES = {name: name for name in supported_scan_types()}
RESULT_FILENAME_RE = re.compile(
    r"^(?:o[a-f0-9]{12}_)?[A-Za-z0-9._-]{1,200}_\w+_\d{8}_\d{6}_\d+\.json$"
)
OWNER_RESULT_PREFIX_RE = re.compile(r"^o([a-f0-9]{12})_")


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _utc_now_iso() -> str:
    return _utc_now().isoformat()


def _normalize_scan_type(scan_type: str) -> Optional[str]:
    normalized = scan_type.strip()
    if not normalized:
        return None

    for key in SUPPORTED_SCAN_TYPES:
        if key.lower() == normalized.lower():
            return key

    return None


def _get_scan_semaphore() -> asyncio.Semaphore:
    global _scan_semaphore
    if _scan_semaphore is None:
        _scan_semaphore = asyncio.Semaphore(MAX_CONCURRENT_SCANS)
    return _scan_semaphore


def get_scan_type_choices() -> str:
    return ", ".join(f"'{k}'" for k in SUPPORTED_SCAN_TYPES.keys())


def log_event(event: str, **fields: Any):
    """Emit an operator log line; optional JSON when STRUCTURED_LOGS=true."""
    if STRUCTURED_LOGS:
        payload = {
            "ts": _utc_now_iso(),
            "level": "info",
            "message": str(event),
            "product": PRODUCT_NAME,
            "version": VERSION,
            "worker_id": WORKER_ID,
        }
        for key, value in fields.items():
            if value is None:
                continue
            # Never log secrets.
            if key.lower() in {"token", "api_token", "fernet_key", "password", "secret"}:
                continue
            payload[key] = value
        line = json.dumps(payload, ensure_ascii=False, separators=(",", ":"))
        logging.info(line)
        print(line)
        return
    logging.info(event)
    print(event)


def record_audit_event(
    action: str,
    *,
    target: Optional[str] = None,
    scan_type: Optional[str] = None,
    job_id: Optional[str] = None,
    task_id: Optional[str] = None,
    result_file: Optional[str] = None,
    status: Optional[str] = None,
    detail: Optional[str] = None,
    actor_key_id: Optional[str] = None,
    actor_owner_prefix: Optional[str] = None,
) -> None:
    """Append a security-relevant event without secrets (tokens/keys).

    Stored in SQLite via state_store; optionally mirrored to AUDIT_LOG_PATH as JSONL.
    """
    try:
        key_id = actor_key_id if actor_key_id is not None else current_api_key_id()
        if actor_owner_prefix is not None:
            owner_prefix = actor_owner_prefix
        else:
            owner = current_owner_id()
            owner_prefix = owner[:12] if owner else None
        # Bound free-text fields; never accept raw tokens.
        safe_detail = (detail or "")[:500] or None
        ts = _utc_now_iso()
        state_store.append_audit_event(
            ts=ts,
            action=action,
            actor_key_id=(str(key_id)[:64] if key_id else None),
            actor_owner_prefix=(str(owner_prefix)[:16] if owner_prefix else None),
            target=(str(target)[:256] if target else None),
            scan_type=(str(scan_type)[:64] if scan_type else None),
            job_id=(str(job_id)[:64] if job_id else None),
            task_id=(str(task_id)[:200] if task_id else None),
            result_file=(str(result_file)[:260] if result_file else None),
            status=(str(status)[:64] if status else None),
            detail=safe_detail,
            max_events=AUDIT_LOG_MAX_EVENTS,
        )
        if AUDIT_LOG_PATH:
            line = json.dumps(
                {
                    "ts": ts,
                    "action": action,
                    "actor_key_id": key_id,
                    "actor_owner_prefix": owner_prefix,
                    "target": target,
                    "scan_type": scan_type,
                    "job_id": job_id,
                    "task_id": task_id,
                    "result_file": result_file,
                    "status": status,
                    "detail": safe_detail,
                },
                ensure_ascii=False,
                separators=(",", ":"),
            )
            path = Path(AUDIT_LOG_PATH)
            path.parent.mkdir(parents=True, exist_ok=True)
            with path.open("a", encoding="utf-8") as handle:
                handle.write(line + "\n")
    except Exception as exc:
        log_event(f"Audit log write failed: {exc}")


def _validate_scan_payload(
    payload: Optional[Dict],
    *,
    validate_interval: bool = True,
) -> Tuple[
    Optional[str],
    Optional[str],
    Optional[float],
    Optional[str],
    Optional[str],
    Optional[str],
    Optional[str],
]:
    """Return target, scan_type, interval, ports, scripts, discovery, error."""
    if not isinstance(payload, dict):
        return None, None, None, None, None, None, "Missing or invalid request body"

    target = payload.get("target")
    if isinstance(target, str):
        target = target.strip()

    if not target:
        return None, None, None, None, None, None, "target is required"

    scan_type = payload.get("scan_type", "TCP")
    if not isinstance(scan_type, str):
        return None, None, None, None, None, None, "scan_type must be a string"

    normalized_scan_type = _normalize_scan_type(scan_type)
    if normalized_scan_type is None:
        return (
            None,
            None,
            None,
            None,
            None,
            None,
            f"Invalid scan_type. Allowed: {get_scan_type_choices()}",
        )
    scan_type = normalized_scan_type

    ports, ports_error = validate_ports_expression(payload.get("ports"))
    if ports_error:
        return target, scan_type, None, None, None, None, ports_error
    scripts, scripts_error = validate_scripts_expression(payload.get("scripts"))
    if scripts_error:
        return target, scan_type, None, None, None, None, scripts_error
    discovery, discovery_error = validate_discovery(payload.get("discovery"))
    if discovery_error:
        return target, scan_type, None, None, None, None, discovery_error
    if discovery not in (None, "none") and scan_type in {"UDP", "Ping"}:
        return (
            target,
            scan_type,
            None,
            ports,
            scripts,
            discovery,
            f"discovery is TCP-only and cannot be combined with {scan_type}",
        )

    interval = payload.get("interval", 30) if validate_interval else None
    interval_value = None
    if interval is not None:
        if isinstance(interval, bool) or not isinstance(interval, (int, float)):
            return target, scan_type, None, ports, scripts, discovery, "interval must be a number"
        try:
            interval_value = float(interval)
        except (OverflowError, ValueError):
            return (
                target,
                scan_type,
                None,
                ports,
                scripts,
                discovery,
                "interval must be a finite number",
            )
        if not math.isfinite(interval_value):
            return (
                target,
                scan_type,
                None,
                ports,
                scripts,
                discovery,
                "interval must be a finite number",
            )
        if interval_value <= 0:
            return (
                target,
                scan_type,
                None,
                ports,
                scripts,
                discovery,
                "interval must be a positive number",
            )
        if interval_value < MIN_SCHEDULE_INTERVAL_MINUTES:
            return (
                target,
                scan_type,
                None,
                ports,
                scripts,
                discovery,
                f"interval must be at least {MIN_SCHEDULE_INTERVAL_MINUTES} minutes",
            )
        if interval_value > MAX_SCHEDULE_INTERVAL_MINUTES:
            return (
                target,
                scan_type,
                None,
                ports,
                scripts,
                discovery,
                f"interval must be at most {MAX_SCHEDULE_INTERVAL_MINUTES} minutes",
            )

    if not validate_ip_or_host(target):
        return (
            target,
            scan_type,
            interval_value,
            ports,
            scripts,
            discovery,
            "Invalid IP, CIDR, or hostname",
        )

    allowlist_error = target_allowlist_error(target)
    if allowlist_error:
        return (
            target,
            scan_type,
            interval_value,
            ports,
            scripts,
            discovery,
            allowlist_error,
        )

    return (
        _canonicalize_valid_target(target),
        scan_type,
        interval_value,
        ports,
        scripts,
        discovery,
        None,
    )


def owner_result_prefix(owner_id: Optional[str] = None) -> str:
    value = owner_id or current_owner_id()
    normalized = (
        value.lower()
        if re.fullmatch(r"[a-fA-F0-9]{12,64}", value)
        else hashlib.sha256(value.encode("utf-8")).hexdigest()
    )
    return f"o{normalized[:12]}_"


def result_visible_to_owner(filename: str, owner_id: Optional[str] = None) -> bool:
    """Decide whether a stored result file is visible to the given owner.

    Owned files (``o{12hex}_…``) are only visible to that owner. Legacy files
    without a prefix are shared only when ``LEGACY_RESULTS_SHARED`` is true
    (default for single-operator compatibility).
    """
    owner = owner_id or current_owner_id()
    match = OWNER_RESULT_PREFIX_RE.match(filename)
    if not match:
        return LEGACY_RESULTS_SHARED
    return match.group(1) == owner_result_prefix(owner)[1:13]


def job_visible_to_owner(job: Dict[str, Any], owner_id: Optional[str] = None) -> bool:
    owner = owner_id or current_owner_id()
    job_owner = job.get("owner_id")
    return job_owner is None or job_owner == owner


def make_task_id(target: str, scan_type: str, owner_id: Optional[str] = None) -> str:
    owner = owner_id or current_owner_id()
    owner_prefix = owner_result_prefix(owner)[1:13]
    return f"o{owner_prefix}-{target}-{scan_type}"


def _peer_is_trusted_proxy(peer: str) -> bool:
    """Return True when the direct TCP peer is listed in TRUSTED_PROXIES."""
    if not peer or peer == "unknown":
        return False
    try:
        peer_ip = ipaddress.ip_address(peer)
    except ValueError:
        return False
    for entry in TRUSTED_PROXIES:
        try:
            if "/" in entry:
                if peer_ip in ipaddress.ip_network(entry, strict=False):
                    return True
            elif peer_ip == ipaddress.ip_address(entry):
                return True
        except ValueError:
            continue
    return False


def _first_valid_ip(candidates: str) -> Optional[str]:
    """Return the first parseable IP from a comma-separated header value."""
    for part in candidates.split(","):
        candidate = part.strip()
        if not candidate:
            continue
        # Strip optional port for IPv4 host:port (not bracketed IPv6).
        if candidate.count(":") == 1 and not candidate.startswith("["):
            candidate = candidate.split(":", 1)[0].strip()
        try:
            return str(ipaddress.ip_address(candidate))
        except ValueError:
            continue
    return None


def _client_key() -> str:
    """Client identifier for rate limiting.

    By default uses the direct peer address. When ``TRUSTED_PROXY_MODE`` is on
    and the peer is in ``TRUSTED_PROXIES``, prefer ``X-Forwarded-For`` (leftmost
    valid IP) or ``X-Real-IP``. Spoofed headers from untrusted peers are ignored.
    """
    peer = request.remote_addr or "unknown"
    if not TRUSTED_PROXY_MODE or not _peer_is_trusted_proxy(peer):
        return peer

    xff = (request.headers.get("X-Forwarded-For") or "").strip()
    if xff:
        forwarded = _first_valid_ip(xff)
        if forwarded:
            return forwarded

    xreal = (request.headers.get("X-Real-IP") or "").strip()
    if xreal:
        real_ip = _first_valid_ip(xreal)
        if real_ip:
            return real_ip
    return peer


def _cleanup_finished_tasks() -> list:
    finished_task_ids = [task_id for task_id, task in scan_tasks.items() if task.done()]
    if not finished_task_ids:
        return []

    for task_id in finished_task_ids:
        try:
            task = scan_tasks.pop(task_id)
            if task.cancelled():
                log_event(f"Task {task_id} removed from registry after cancellation")
            else:
                exception = task.exception()
                if exception is not None:
                    log_event(f"Task {task_id} finished with error: {exception}")
        except Exception as e:
            log_event(f"Error removing task {task_id}: {e}")

    return finished_task_ids


def _rate_limit_bucket_key() -> str:
    """Build a stable rate-limit bucket from client IP and optional owner id."""
    client_ip = _client_key()
    if not RATE_LIMIT_INCLUDE_OWNER:
        return client_ip
    try:
        owner = getattr(g, "owner_id", None)
    except RuntimeError:
        owner = None
    if not owner or owner == "local":
        return client_ip
    return f"{client_ip}:o{owner[:12]}"


def _get_redis_client() -> Any:
    """Lazy-connect Redis when REDIS_URL is configured. Returns None on failure/disabled."""
    global _redis_client, _redis_init_attempted, _redis_available
    if not REDIS_URL:
        return None
    if _redis_init_attempted:
        return _redis_client if _redis_available else None
    _redis_init_attempted = True
    try:
        import redis  # type: ignore
    except ImportError:
        log_event("REDIS_URL is set but redis package is not installed; using memory rate limits")
        _redis_available = False
        return None
    try:
        client = redis.Redis.from_url(
            REDIS_URL,
            decode_responses=True,
            socket_connect_timeout=1.0,
            socket_timeout=1.0,
            health_check_interval=30,
        )
        client.ping()
        _redis_client = client
        _redis_available = True
        log_event("Redis rate-limit backend connected")
        return client
    except Exception as exc:
        log_event(f"Redis rate-limit backend unavailable ({exc}); using memory fallback")
        _redis_client = None
        _redis_available = False
        return None


def rate_limit_backend() -> str:
    """Return active rate-limit backend name for health/docs."""
    if REDIS_URL and _get_redis_client() is not None:
        return "redis"
    if REDIS_URL:
        return "memory_fallback"
    return "memory"


def _check_rate_limit_memory(bucket: str) -> bool:
    now = time.time()

    if bucket not in rate_limits and len(rate_limits) >= MAX_RATE_LIMIT_CLIENTS:
        stale_before = now - RATE_LIMIT_WINDOW_SECONDS
        stale_clients = [
            key
            for key, timestamps in rate_limits.items()
            if not timestamps or timestamps[-1] <= stale_before
        ]
        for key in stale_clients:
            rate_limits.pop(key, None)

        if len(rate_limits) >= MAX_RATE_LIMIT_CLIENTS:
            oldest_client = min(
                rate_limits,
                key=lambda key: rate_limits[key][-1] if rate_limits[key] else 0,
            )
            rate_limits.pop(oldest_client, None)

    request_window = rate_limits[bucket]
    rate_limits[bucket] = [
        req_time for req_time in request_window if now - req_time < RATE_LIMIT_WINDOW_SECONDS
    ]

    if len(rate_limits[bucket]) >= MAX_REQUESTS_PER_WINDOW:
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
    """Sliding-window limit via Redis sorted set (atomic Lua, shared across workers)."""
    now = time.time()
    key = f"{REDIS_RATE_LIMIT_PREFIX}{bucket}"
    member = f"{now:.6f}:{secrets.token_hex(4)}"
    try:
        # Prefer EVAL for atomicity under concurrent workers.
        allowed = client.eval(
            _REDIS_RATE_LIMIT_LUA,
            1,
            key,
            str(now),
            str(RATE_LIMIT_WINDOW_SECONDS),
            str(MAX_REQUESTS_PER_WINDOW),
            member,
        )
        return bool(int(allowed))
    except Exception as exc:
        log_event(f"Redis rate limit error for {bucket}: {exc}; falling back to memory")
        return _check_rate_limit_memory(bucket)


def check_rate_limit() -> bool:
    """Enforce per-window request budget (memory or shared Redis)."""
    bucket = _rate_limit_bucket_key()
    client = _get_redis_client()
    if client is not None:
        allowed = _check_rate_limit_redis(client, bucket)
    else:
        allowed = _check_rate_limit_memory(bucket)
    if not allowed:
        METRICS.inc("recon_operator_rate_limit_exceeded_total")
    return allowed


def _bool_query_param(name: str, default: bool = False) -> bool:
    value = request.args.get(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on", "y"}


def get_cached_tool_inventory(expand: bool = False) -> Dict:
    cache_key = "expanded" if expand else "summary"
    with tool_inventory_locks[cache_key]:
        cached = tool_inventory_cache.get(cache_key)
        now = time.time()
        if (
            cached
            and TOOL_INVENTORY_CACHE_SECONDS > 0
            and now - cached["created_at"] < TOOL_INVENTORY_CACHE_SECONDS
        ):
            return cached["inventory"]

        inventory = build_tool_inventory(expand=expand)
        tool_inventory_cache[cache_key] = {
            "created_at": time.time(),
            "inventory": inventory,
        }
        return inventory


async def send_telegram_message(message: str):
    if not bot:
        log_event("Telegram is not configured. Message not sent.")
        return
    try:
        await bot.send_message(chat_id=CHAT_ID, text=message)
    except TelegramError as e:
        log_event(f"Telegram send error: {e}")
    except Exception as e:
        log_event(f"Unexpected Telegram error: {e}")


def validate_ip_or_host(target: str) -> bool:
    """Validate IP, network, or domain syntax."""
    if not isinstance(target, str) or not target:
        return False

    target = target.strip()
    if len(target) > 253:
        return False

    dangerous_chars = [";", "&", "|", "`", "$", "(", ")", "<", ">", "\\", "\n", "\r", "\t"]
    if any(char in target for char in dangerous_chars):
        log_event(f"Potential injection-like input detected in target: {target}")
        return False

    try:
        network = ipaddress.ip_network(target, strict=False)
        if network.num_addresses > MAX_TARGET_ADDRESSES:
            log_event(
                f"Target range is too large: {target} contains {network.num_addresses} addresses"
            )
            return False
        return True
    except ValueError:
        auth_domain_re = re.compile(
            r"^(?:(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}|localhost)$",
            re.IGNORECASE,
        )
        return auth_domain_re.fullmatch(target) is not None


def _allowlist_entry_matches_ip(entry: str, addr: Any) -> bool:
    try:
        return addr == ipaddress.ip_address(entry)
    except ValueError:
        pass
    try:
        return addr in ipaddress.ip_network(entry, strict=False)
    except ValueError:
        return False


def _allowlist_entry_covers_network(entry: str, network: Any) -> bool:
    try:
        allowed = ipaddress.ip_network(entry, strict=False)
    except ValueError:
        return False
    if allowed.version != network.version:
        return False
    return bool(network.subnet_of(allowed))


def _allowlist_entry_matches_host(entry: str, host: str) -> bool:
    entry_lower = entry.strip().lower()
    host_lower = host.strip().lower()
    if not entry_lower or not host_lower:
        return False
    # Reject IP/CIDR-shaped entries for hostname targets.
    try:
        ipaddress.ip_network(entry_lower, strict=False)
        return False
    except ValueError:
        pass
    if entry_lower.startswith("*."):
        suffix = entry_lower[1:]  # ".example.com"
        return host_lower.endswith(suffix) and host_lower != suffix.lstrip(".")
    return entry_lower == host_lower


def target_in_allowlist(target: str, allowlist: Optional[List[str]] = None) -> bool:
    """Return True when target is permitted by the engagement allowlist."""
    return target_allowlist_error(target, allowlist) is None


def target_allowlist_error(target: str, allowlist: Optional[List[str]] = None) -> Optional[str]:
    """Return an error string if target is outside the configured allowlist.

    Empty allowlist means unrestricted (default single-operator behavior).
    """
    rules = TARGET_ALLOWLIST if allowlist is None else allowlist
    if not rules:
        return None
    if not isinstance(target, str) or not target.strip():
        return "Target is outside the configured allowlist"

    candidate = target.strip()
    try:
        addr = ipaddress.ip_address(candidate)
        if any(_allowlist_entry_matches_ip(entry, addr) for entry in rules):
            return None
        return "Target is outside the configured allowlist"
    except ValueError:
        pass

    try:
        network = ipaddress.ip_network(candidate, strict=False)
        # Single-host network is already covered by the address path above for bare IPs.
        if any(_allowlist_entry_covers_network(entry, network) for entry in rules):
            return None
        return "Target is outside the configured allowlist"
    except ValueError:
        pass

    if any(_allowlist_entry_matches_host(entry, candidate) for entry in rules):
        return None
    return "Target is outside the configured allowlist"


def _canonicalize_valid_target(target: str) -> str:
    """Return a stable task/scan target after validation has succeeded."""
    try:
        return str(ipaddress.ip_address(target))
    except ValueError:
        try:
            return str(ipaddress.ip_network(target, strict=False))
        except ValueError:
            return target.lower()


def build_scan_args(scan_type: str) -> str:
    """Legacy helper retained for tests and docs; engine builds argv lists."""
    if scan_type not in SUPPORTED_SCAN_TYPES:
        raise ValueError(f"Invalid scan_type: {scan_type}")
    return f"{scan_type} --host-timeout {HOST_TIMEOUT_SEC}s --max-retries {NMAP_MAX_RETRIES}"


def scan_network(
    target: str,
    scan_type: str,
    ports: Optional[str] = None,
    scripts: Optional[str] = None,
    discovery: Optional[str] = None,
    process_token: Optional[str] = None,
) -> dict:
    """
    Synchronous scan entry point used by the async executor.
    Exceptions propagate to the async layer.
    """
    log_event(
        f"Starting scan {target} type={scan_type} ports={ports} "
        f"scripts={scripts} discovery={discovery}",
        job_id=process_token,
    )
    try:
        return run_nmap_scan(
            target,
            scan_type,
            host_timeout_sec=HOST_TIMEOUT_SEC,
            max_retries=NMAP_MAX_RETRIES,
            scan_timeout_sec=SCAN_TIMEOUT_SECONDS,
            ports=ports,
            scripts=scripts,
            discovery=discovery,
            process_token=process_token,
        )
    except ScanCancelledError:
        raise
    except NmapTimeoutError as exc:
        raise TimeoutError(str(exc)) from exc
    except DiscoveryError as exc:
        raise RuntimeError(str(exc)) from exc


def _result_files() -> List[Path]:
    directory = Path(RESULTS_DIR)
    if not directory.is_dir():
        return []
    existing: List[Tuple[float, Path]] = []
    try:
        candidates = list(directory.iterdir())
    except OSError:
        return []
    for path in candidates:
        try:
            if path.is_file() and path.suffix == ".json":
                existing.append((path.stat().st_mtime, path))
        except OSError:
            # Retention may remove a file between enumeration and stat.
            continue
    existing.sort(key=lambda item: item[0], reverse=True)
    return [path for _, path in existing]


def apply_results_retention(directory: Optional[str] = None) -> Dict[str, int]:
    """Delete old encrypted results by count and optional age."""
    root = Path(directory or RESULTS_DIR)
    if not root.is_dir():
        return {"deleted": 0, "remaining": 0}

    lock_path = root / ".retention.lock"
    with lock_path.open("a+", encoding="utf-8") as lock:
        os.chmod(lock_path, 0o600)
        fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
        files = [path for path in root.iterdir() if path.is_file() and path.suffix == ".json"]
        deleted = 0
        now = time.time()

        if RESULTS_MAX_AGE_DAYS > 0:
            max_age_seconds = RESULTS_MAX_AGE_DAYS * 86400
            for path in list(files):
                try:
                    if now - path.stat().st_mtime > max_age_seconds:
                        path.unlink()
                        deleted += 1
                        files.remove(path)
                except OSError as exc:
                    log_event(f"Retention age cleanup failed for {path}: {exc}")

        existing = []
        for path in files:
            try:
                existing.append((path.stat().st_mtime, path))
            except OSError:
                continue
        existing.sort(key=lambda item: item[0])
        files = [path for _, path in existing]
        while len(files) > RESULTS_MAX_FILES:
            path = files.pop(0)
            try:
                path.unlink()
                deleted += 1
            except OSError as exc:
                log_event(f"Retention count cleanup failed for {path}: {exc}")

        return {"deleted": deleted, "remaining": len(files)}


def _write_encrypted_result(path: str, encrypted_data: bytes) -> None:
    """Atomically persist encrypted output with owner-only permissions."""
    directory = os.path.dirname(path) or "."
    os.makedirs(directory, mode=0o700, exist_ok=True)
    temporary_path = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="wb", dir=directory, prefix=".scan-", delete=False
        ) as handle:
            temporary_path = handle.name
            os.chmod(temporary_path, 0o600)
            handle.write(encrypted_data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary_path, path)
    finally:
        if temporary_path and os.path.exists(temporary_path):
            os.unlink(temporary_path)


async def save_scan_results_async(
    results: dict,
    target: str,
    scan_type: str,
    owner_id: Optional[str] = None,
) -> Optional[str]:
    if not results:
        return None

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S_%f")
    safe_target = (
        "".join(c if c.isalnum() or c in [".", "_", "-"] else "_" for c in str(target))[:120]
        or "target"
    )
    safe_scan_type = (
        "".join(c if c.isalnum() or c in ["_", "-"] else "_" for c in str(scan_type))[:40] or "Scan"
    )
    owner = owner_id or "local"
    filename = f"{owner_result_prefix(owner)}{safe_target}_{safe_scan_type}_{timestamp}.json"
    results_root = Path(RESULTS_DIR).resolve()
    path = (results_root / filename).resolve()
    try:
        path.relative_to(results_root)
    except ValueError as exc:
        raise ValueError("Result filename escaped RESULTS_DIR") from exc

    try:
        encrypted_data = cipher.encrypt(json.dumps(results, indent=2).encode())
        await asyncio.to_thread(_write_encrypted_result, str(path), encrypted_data)
        try:
            await asyncio.to_thread(apply_results_retention, RESULTS_DIR)
        except Exception as exc:
            # The encrypted result is already durable; maintenance failure
            # must not turn a successful scan into a failed job.
            log_event(f"Result retention failed after saving {filename}: {exc}")
        log_event(f"Results saved to {path}")
        await send_telegram_message(f"Scan {target} finished. Results: {filename}")
        return filename
    except Exception as e:
        err = f"Error saving results: {e}"
        log_event(err)
        await send_telegram_message(f"Error saving results for {target}: {e}")
        raise


async def _load_job_result_payload(job: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """Load a completed job result from memory or its encrypted result file."""
    result = job.get("result")
    if isinstance(result, dict):
        return result
    result_file = job.get("result_file")
    if not isinstance(result_file, str) or os.path.basename(result_file) != result_file:
        return None
    root = Path(RESULTS_DIR).resolve()
    path = (root / result_file).resolve()
    try:
        path.relative_to(root)
        encrypted = await asyncio.to_thread(path.read_bytes)
        plaintext = cipher.decrypt(encrypted)
        payload = json.loads(plaintext.decode("utf-8"))
    except (InvalidToken, OSError, UnicodeDecodeError, json.JSONDecodeError, ValueError):
        return None
    return payload if isinstance(payload, dict) else None


def _job_public_view(job: Dict[str, Any], *, include_result: bool = True) -> Dict[str, Any]:
    view = {
        "job_id": job["job_id"],
        "target": job["target"],
        "scan_type": job["scan_type"],
        "ports": job.get("ports"),
        "scripts": job.get("scripts"),
        "discovery": job.get("discovery"),
        "status": job["status"],
        "created_at": job["created_at"],
        "started_at": job.get("started_at"),
        "finished_at": job.get("finished_at"),
        "error": job.get("error"),
        "result_file": job.get("result_file"),
        "kind": job.get("kind", "immediate"),
        "lease_owner": job.get("lease_owner"),
    }
    if include_result and job.get("status") == "completed":
        view["result"] = job.get("result")
    return view


def _persist_job(job: Dict[str, Any]) -> None:
    """Persist compatibility state and propagate failures to the caller."""
    state_store.upsert_job(job)
    state_store.prune_jobs(MAX_SCAN_JOBS)


def _try_redis_job_lease(job_id: str, *, renew: bool = False) -> bool:
    """Optional Redis fence so only one process holds a job lease."""
    client = _get_redis_client()
    if client is None:
        return True
    key = f"{REDIS_JOB_LEASE_PREFIX}{job_id}"
    try:
        if renew:
            current = client.get(key)
            if current not in (None, WORKER_ID):
                return False
            client.set(key, WORKER_ID, ex=JOB_LEASE_SECONDS)
            return True
        # SET NX — first claimant wins; allow same worker to refresh.
        ok = client.set(key, WORKER_ID, nx=True, ex=JOB_LEASE_SECONDS)
        if ok:
            return True
        return client.get(key) == WORKER_ID
    except Exception as exc:
        log_event(f"Redis job lease error for {job_id}: {exc}")
        # Fail open to SQLite-only claim when Redis blips.
        return True


def _release_redis_job_lease(job_id: str) -> None:
    client = _get_redis_client()
    if client is None:
        return
    key = f"{REDIS_JOB_LEASE_PREFIX}{job_id}"
    try:
        current = client.get(key)
        if current == WORKER_ID:
            client.delete(key)
    except Exception as exc:
        log_event(f"Redis job lease release error for {job_id}: {exc}")


def _claim_job_for_worker(job_id: str) -> Optional[Dict[str, Any]]:
    """SQLite atomic claim + optional Redis fence."""
    if not _try_redis_job_lease(job_id):
        return None
    claimed = state_store.try_claim_job(
        job_id,
        WORKER_ID,
        now=time.time(),
        lease_seconds=JOB_LEASE_SECONDS,
        started_at=_utc_now_iso(),
    )
    if claimed is None:
        _release_redis_job_lease(job_id)
        return None
    return claimed


def _renew_job_lease(job_id: str) -> bool:
    if not _try_redis_job_lease(job_id, renew=True):
        return False
    return state_store.renew_job_lease(
        job_id,
        WORKER_ID,
        now=time.time(),
        lease_seconds=JOB_LEASE_SECONDS,
    )


async def _prune_jobs_locked() -> None:
    """Keep completed/failed jobs within MAX_SCAN_JOBS."""
    if len(scan_jobs) <= MAX_SCAN_JOBS:
        return
    terminal = [
        job
        for job in scan_jobs.values()
        if job["status"] in {"completed", "failed", "cancelled", "timeout"}
    ]
    terminal.sort(key=lambda item: item.get("finished_at") or item.get("created_at") or "")
    overflow = len(scan_jobs) - MAX_SCAN_JOBS
    for job in terminal[:overflow]:
        removed = scan_jobs.pop(job["job_id"], None)
        if removed:
            try:
                state_store.delete_job(job["job_id"])
            except Exception as exc:
                log_event(f"Failed to delete persisted job {job['job_id']}: {exc}")


_TERMINAL_JOB_STATUSES = frozenset({"completed", "failed", "cancelled", "timeout"})


def _note_job_terminal_metrics(job: Dict[str, Any], *, previous_status: Any, status: str) -> None:
    """Record finish counter + duration once when a job first becomes terminal."""
    if status not in _TERMINAL_JOB_STATUSES:
        return
    if previous_status in _TERMINAL_JOB_STATUSES:
        return
    scan_type = str(job.get("scan_type") or "unknown")
    METRICS.inc(
        "recon_operator_jobs_finished_total",
        status=str(status),
        scan_type=scan_type,
    )
    started_mono = job.get("_metrics_started_mono")
    if isinstance(started_mono, (int, float)):
        METRICS.observe(
            "recon_operator_scan_duration_seconds",
            max(0.0, time.monotonic() - float(started_mono)),
            scan_type=scan_type,
            status=str(status),
        )
        return
    # Monotonic timestamps are process-local. A reclaimed job or a terminal
    # update observed by another worker still has durable UTC timestamps.
    try:
        started_at = datetime.fromisoformat(str(job.get("started_at")))
        finished_at = datetime.fromisoformat(str(job.get("finished_at")))
        duration = (finished_at - started_at).total_seconds()
    except (TypeError, ValueError):
        return
    METRICS.observe(
        "recon_operator_scan_duration_seconds",
        max(0.0, duration),
        scan_type=scan_type,
        status=str(status),
    )


async def _set_job_fields(job_id: str, **fields: Any) -> None:
    """Compatibility helper for non-runner callers and test doubles.

    The real runner uses the fenced start/finalize helpers below.
    """
    async with _jobs_lock:
        job = scan_jobs.get(job_id)
        if not job:
            return
        previous_status = job.get("status")
        job.update(fields)
        # Clear lease markers on terminal states.
        if fields.get("status") in _TERMINAL_JOB_STATUSES:
            job["lease_owner"] = None
            job["lease_until"] = None
            _note_job_terminal_metrics(
                job,
                previous_status=previous_status,
                status=str(fields.get("status") or "unknown"),
            )
        _persist_job(job)


async def _refresh_job_from_store(job_id: str) -> Optional[Dict[str, Any]]:
    """Refresh durable fields while preserving only process-local state."""
    stored = await asyncio.to_thread(state_store.get_job, job_id)
    async with _jobs_lock:
        current = scan_jobs.get(job_id)
        if stored is None:
            return current
        task = (current or {}).get("task")
        result = None
        if (
            current
            and stored.get("status") == "completed"
            and current.get("status") == "completed"
            and current.get("result_file") == stored.get("result_file")
        ):
            result = current.get("result")
        merged = {**stored, "task": task, "result": result}
        scan_jobs[job_id] = merged
        return merged


async def _mark_job_running(job_id: str) -> bool:
    started_at = _utc_now_iso()
    stored = await asyncio.to_thread(
        state_store.mark_job_running,
        job_id,
        WORKER_ID,
        started_at=started_at,
    )
    if stored is None:
        await _refresh_job_from_store(job_id)
        return False
    async with _jobs_lock:
        current = scan_jobs.get(job_id)
        task = (current or {}).get("task")
        stored["task"] = task
        stored["_metrics_started_mono"] = time.monotonic()
        scan_jobs[job_id] = stored
    return True


async def _finalize_job(
    job_id: str,
    *,
    status: str,
    error: Optional[str],
    result_file: Optional[str] = None,
    result: Optional[Dict[str, Any]] = None,
) -> bool:
    finished_at = _utc_now_iso()
    stored = await asyncio.to_thread(
        state_store.finalize_job,
        job_id,
        WORKER_ID,
        status=status,
        finished_at=finished_at,
        error=error,
        result_file=result_file,
    )
    if stored is None:
        await _refresh_job_from_store(job_id)
        return False
    async with _jobs_lock:
        current = scan_jobs.get(job_id)
        previous_status = (current or {}).get("status")
        task = (current or {}).get("task")
        started_mono = (current or {}).get("_metrics_started_mono")
        stored["task"] = task
        stored["result"] = result if status == "completed" else None
        if started_mono is not None:
            stored["_metrics_started_mono"] = started_mono
        scan_jobs[job_id] = stored
        _note_job_terminal_metrics(stored, previous_status=previous_status, status=status)
    return True


def _delete_saved_result(result_file: Optional[str]) -> None:
    """Remove an uncommitted result created after a lost terminal-state race."""
    if not result_file or os.path.basename(result_file) != result_file:
        return
    root = Path(RESULTS_DIR).resolve()
    candidate = (root / result_file).resolve()
    try:
        candidate.relative_to(root)
        candidate.unlink(missing_ok=True)
    except (OSError, ValueError):
        pass


def _request_job_process_cancel(job_id: str) -> bool:
    mark_process_cancelled(job_id)
    return kill_active_process(job_id)


async def _run_scan_job(job_id: str, *, already_claimed: bool = False) -> None:
    if not already_claimed:
        claimed = await asyncio.to_thread(_claim_job_for_worker, job_id)
        if claimed is None:
            # Another worker owns this job (or it disappeared).
            stored = await asyncio.to_thread(state_store.get_job, job_id)
            async with _jobs_lock:
                if stored is not None:
                    existing_task = (scan_jobs.get(job_id) or {}).get("task")
                    scan_jobs[job_id] = {**stored, "task": existing_task}
                job = scan_jobs.get(job_id)
                if job:
                    job["task"] = None
            return
        async with _jobs_lock:
            existing_task = (scan_jobs.get(job_id) or {}).get("task")
            scan_jobs[job_id] = {**claimed, "task": existing_task}
            job = scan_jobs[job_id]
            if job.get("status") == "cancelled":
                return
            target = job["target"]
            scan_type = job["scan_type"]
            ports = job.get("ports")
            scripts = job.get("scripts")
            discovery = job.get("discovery")
            owner_id = job.get("owner_id") or "local"
    else:
        async with _jobs_lock:
            job = scan_jobs.get(job_id)
            if not job or job["status"] == "cancelled":
                return
            target = job["target"]
            scan_type = job["scan_type"]
            ports = job.get("ports")
            scripts = job.get("scripts")
            discovery = job.get("discovery")
            owner_id = job.get("owner_id") or "local"

    loop = asyncio.get_running_loop()
    runner_task = asyncio.current_task()
    heartbeat: Optional[asyncio.Task] = None
    lease_lost = False
    executor_submitted = False
    prepare_process_token(job_id)

    def _execute_scan() -> Dict[str, Any]:
        try:
            return scan_network(
                target,
                scan_type,
                ports=ports,
                scripts=scripts,
                discovery=discovery,
                process_token=job_id,
            )
        finally:
            clear_process_token(job_id)

    async def _lease_heartbeat() -> None:
        nonlocal lease_lost
        interval = min(5.0, max(0.05, JOB_LEASE_SECONDS / 3))
        while True:
            await asyncio.sleep(interval)
            ok = await asyncio.to_thread(_renew_job_lease, job_id)
            if not ok:
                lease_lost = True
                log_event(f"Lost job lease for {job_id}; stopping scan")
                _request_job_process_cancel(job_id)
                if runner_task is not None and not runner_task.done():
                    runner_task.cancel()
                return

    try:
        heartbeat = asyncio.create_task(_lease_heartbeat())
        async with _get_scan_semaphore():
            if not await _mark_job_running(job_id):
                return
            executor_future = loop.run_in_executor(None, _execute_scan)
            executor_submitted = True
            results = await asyncio.wait_for(
                executor_future,
                timeout=SCAN_TIMEOUT_SECONDS + 5,
            )
        # Recheck the durable fence before writing results: another worker may
        # have cancelled the job or taken ownership since the last heartbeat.
        stored = await asyncio.to_thread(state_store.get_job, job_id)
        async with _jobs_lock:
            current = scan_jobs.get(job_id)
            durable_conflict = bool(
                stored
                and (
                    stored.get("status") in _TERMINAL_JOB_STATUSES
                    or stored.get("lease_owner") not in (None, WORKER_ID)
                )
            )
            if durable_conflict:
                current_task = (current or {}).get("task")
                scan_jobs[job_id] = {**stored, "task": current_task}
                return
            if current and current.get("status") == "cancelled":
                return
        result_file = await save_scan_results_async(results, target, scan_type, owner_id=owner_id)
        committed = await _finalize_job(
            job_id,
            status="completed",
            error=None,
            result_file=result_file,
            result=results,
        )
        if not committed:
            await asyncio.to_thread(_delete_saved_result, result_file)
            return
        record_audit_event(
            "scan.finish",
            target=target,
            scan_type=scan_type,
            job_id=job_id,
            result_file=result_file,
            status="completed",
            actor_owner_prefix=(owner_id[:12] if owner_id else None),
        )
    except asyncio.CancelledError:
        _request_job_process_cancel(job_id)
        if lease_lost:
            # The durable row is authoritative: another worker may now own it,
            # or a different worker may already have recorded user cancellation.
            stored = await asyncio.to_thread(state_store.get_job, job_id)
            async with _jobs_lock:
                current_task = (scan_jobs.get(job_id) or {}).get("task")
                if stored is not None:
                    scan_jobs[job_id] = {**stored, "task": current_task}
        else:
            committed = await _finalize_job(
                job_id,
                status="cancelled",
                error="Scan cancelled",
            )
            if committed:
                record_audit_event(
                    "scan.finish",
                    target=target,
                    scan_type=scan_type,
                    job_id=job_id,
                    status="cancelled",
                    actor_owner_prefix=(owner_id[:12] if owner_id else None),
                )
        raise
    except ScanCancelledError:
        committed = await _finalize_job(
            job_id,
            status="cancelled",
            error="Scan cancelled",
        )
        if committed:
            record_audit_event(
                "scan.finish",
                target=target,
                scan_type=scan_type,
                job_id=job_id,
                status="cancelled",
                actor_owner_prefix=(owner_id[:12] if owner_id else None),
            )
    except asyncio.TimeoutError:
        _request_job_process_cancel(job_id)
        err = f"Scan timeout for {target} ({scan_type})"
        log_event(err, job_id=job_id)
        committed = await _finalize_job(
            job_id,
            status="timeout",
            error=err,
        )
        if committed:
            await send_telegram_message(err)
            record_audit_event(
                "scan.finish",
                target=target,
                scan_type=scan_type,
                job_id=job_id,
                status="timeout",
                actor_owner_prefix=(owner_id[:12] if owner_id else None),
            )
    except TimeoutError as exc:
        _request_job_process_cancel(job_id)
        err = str(exc)
        log_event(err, job_id=job_id)
        committed = await _finalize_job(
            job_id,
            status="timeout",
            error=err,
        )
        if committed:
            await send_telegram_message(err)
            record_audit_event(
                "scan.finish",
                target=target,
                scan_type=scan_type,
                job_id=job_id,
                status="timeout",
                actor_owner_prefix=(owner_id[:12] if owner_id else None),
            )
    except (NmapNotFoundError, NmapScanError, Exception) as exc:
        err = f"Scan error for {target} ({scan_type}): {exc}"
        log_event(err, job_id=job_id)
        committed = await _finalize_job(
            job_id,
            status="failed",
            error=str(exc),
        )
        if committed:
            await send_telegram_message(err)
            record_audit_event(
                "scan.finish",
                target=target,
                scan_type=scan_type,
                job_id=job_id,
                status="failed",
                detail=str(exc)[:200],
                actor_owner_prefix=(owner_id[:12] if owner_id else None),
            )
    finally:
        kill_active_process(job_id)
        if not executor_submitted:
            clear_process_token(job_id)
        if heartbeat is not None:
            heartbeat.cancel()
            try:
                await heartbeat
            except asyncio.CancelledError:
                pass
        await asyncio.to_thread(state_store.release_job_lease, job_id, WORKER_ID)
        _release_redis_job_lease(job_id)
        await _refresh_job_from_store(job_id)
        async with _jobs_lock:
            job = scan_jobs.get(job_id)
            if job:
                job["task"] = None
            await _prune_jobs_locked()


async def _adopt_claimed_job(claimed: Dict[str, Any]) -> None:
    """Register a job claimed by the poller and run it locally."""
    job_id = claimed["job_id"]
    async with _jobs_lock:
        existing = scan_jobs.get(job_id)
        if existing and existing.get("task") is not None and not existing["task"].done():
            # The already-registered local runner can consume this worker's
            # queued lease through try_claim_job; do not create a second task.
            return
        active = sum(1 for job in scan_jobs.values() if job["status"] in {"queued", "running"})
        if active >= MAX_SCAN_JOBS and job_id not in scan_jobs:
            # Capacity full — release so another worker can take it later.
            try:
                state_store.requeue_owned_job(job_id, WORKER_ID)
            except Exception as exc:
                log_event(f"Failed to requeue capacity-limited job {job_id}: {exc}")
            _release_redis_job_lease(job_id)
            return
        job = {**claimed, "task": None}
        scan_jobs[job_id] = job
        task = asyncio.create_task(_run_scan_job(job_id, already_claimed=True))
        job["task"] = task


async def job_claim_loop(stop_event: Optional[asyncio.Event] = None) -> None:
    """Poll SQLite for queued / expired-lease jobs (multi-worker recovery)."""
    log_event(f"Job claim loop started (worker={WORKER_ID}, lease={JOB_LEASE_SECONDS}s)")
    while True:
        if stop_event is not None and stop_event.is_set():
            break
        try:
            claimed = await asyncio.to_thread(
                state_store.claim_next_job,
                WORKER_ID,
                now=time.time(),
                lease_seconds=JOB_LEASE_SECONDS,
                started_at=_utc_now_iso(),
            )
            if claimed is not None:
                # Align Redis fence with SQLite claim.
                if not _try_redis_job_lease(claimed["job_id"]):
                    try:
                        await asyncio.to_thread(
                            state_store.requeue_owned_job,
                            claimed["job_id"],
                            WORKER_ID,
                        )
                    except Exception as exc:
                        log_event(f"Failed to release Redis-rejected job claim: {exc}")
                else:
                    await _adopt_claimed_job(claimed)
                    continue
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            log_event(f"Job claim loop error: {exc}")
        await asyncio.sleep(JOB_CLAIM_POLL_SECONDS)


async def create_scan_job(
    target: str,
    scan_type: str,
    *,
    kind: str = "immediate",
    ports: Optional[str] = None,
    scripts: Optional[str] = None,
    discovery: Optional[str] = None,
    owner_id: Optional[str] = None,
) -> Dict[str, Any]:
    owner = owner_id or current_owner_id()
    async with _jobs_lock:
        await _prune_jobs_locked()
        job_id = str(uuid.uuid4())
        job = {
            "job_id": job_id,
            "target": target,
            "scan_type": scan_type,
            "ports": ports,
            "scripts": scripts,
            "discovery": discovery,
            "owner_id": owner,
            "status": "queued",
            "created_at": _utc_now_iso(),
            "started_at": None,
            "finished_at": None,
            "error": None,
            "result": None,
            "result_file": None,
            "kind": kind,
            "lease_owner": None,
            "lease_until": None,
            "task": None,
        }
        # Capacity and scheduled-occurrence deduplication must be shared across
        # workers; a per-process dictionary check admits races.
        accepted, inserted = await asyncio.to_thread(
            state_store.insert_job_with_capacity,
            job,
            max_active=MAX_SCAN_JOBS,
            dedupe_active=kind == "scheduled",
        )
        if accepted is None:
            raise RuntimeError("Scan job capacity reached")
        if not inserted:
            existing_task = (scan_jobs.get(accepted["job_id"]) or {}).get("task")
            accepted["task"] = existing_task
            scan_jobs[accepted["job_id"]] = accepted
            return _job_public_view(accepted, include_result=False)
        try:
            await asyncio.to_thread(state_store.prune_jobs, MAX_SCAN_JOBS)
        except Exception as exc:
            # Retention maintenance must not invalidate an accepted durable job.
            log_event(f"Failed to prune jobs after inserting {job_id}: {exc}")
        scan_jobs[job_id] = job
        # Low-latency local attempt; claim ensures only one worker executes.
        task = asyncio.create_task(_run_scan_job(job_id))
        job["task"] = task
        METRICS.inc("recon_operator_jobs_created_total", kind=str(kind or "immediate"))
        log_event(
            f"Scan job queued {job_id}",
            job_id=job_id,
            target=target,
            scan_type=scan_type,
            kind=kind,
            owner_prefix=(owner[:12] if owner else None),
        )
        record_audit_event(
            "scan.create",
            target=target,
            scan_type=scan_type,
            job_id=job_id,
            status="queued",
            detail=kind,
            actor_owner_prefix=owner[:12] if owner else None,
        )
        return _job_public_view(job, include_result=False)


async def async_scan(
    target: str,
    scan_type: str,
    ports: Optional[str] = None,
    scripts: Optional[str] = None,
    discovery: Optional[str] = None,
    owner_id: Optional[str] = None,
    kind: str = "immediate",
) -> dict:
    """Run a scan and wait for completion (used by scheduled scans)."""
    job = await create_scan_job(
        target,
        scan_type,
        kind=kind,
        ports=ports,
        scripts=scripts,
        discovery=discovery,
        owner_id=owner_id,
    )
    job_id = job["job_id"]
    while True:
        current = await _refresh_job_from_store(job_id)
        if not current:
            raise RuntimeError("Scan job disappeared")
        status = current["status"]
        if status in {"completed", "failed", "cancelled", "timeout"}:
            if status == "completed":
                return await _load_job_result_payload(current) or {}
            if status == "timeout":
                raise TimeoutError(current.get("error") or "Scan timed out")
            if status == "cancelled":
                raise JobCancelledError(current.get("error") or "Scan cancelled")
            raise RuntimeError(current.get("error") or "Scan failed")
        task = current.get("task")
        if task is not None:
            try:
                await asyncio.wait_for(asyncio.shield(task), timeout=0.5)
            except asyncio.TimeoutError:
                pass
            except asyncio.CancelledError:
                raise
            except Exception:
                # Job state is the source of truth; continue loop.
                pass
        else:
            await asyncio.sleep(0.05)


@app.route("/presets", methods=["GET"])
async def presets_list():
    """List named recon presets / ordered engagement phases."""
    auth_error = require_api_auth("read")
    if auth_error:
        return auth_error
    return (
        jsonify(
            {
                "phases": PHASE_ORDER,
                "presets": list_presets(),
                "playbooks": list_playbooks(),
                "usage": 'POST /scan with {"target":"...","preset":"map"}',
                "playbook_usage": 'POST /playbook/run with {"target":"...","playbook":"standard"}',
            }
        ),
        200,
    )


async def _wait_job_terminal(job_id: str) -> Dict[str, Any]:
    """Poll until a job reaches a terminal status; return the job dict."""
    terminal = _TERMINAL_JOB_STATUSES
    while True:
        stored = await asyncio.to_thread(state_store.get_job, job_id)
        if stored is None:
            return {
                "job_id": job_id,
                "status": "failed",
                "error": "Scan job disappeared from durable state",
                "result_file": None,
            }
        current = await _refresh_job_from_store(job_id)
        if current and current.get("status") in terminal:
            return current
        await asyncio.sleep(0.1)


def _skip_engagement_tail(
    steps: List[Dict[str, Any]],
    *,
    after_index: int,
    reason: str,
) -> None:
    """Make terminal playbook state explicit for phases that will never run."""
    for later in steps[after_index + 1 :]:
        if isinstance(later, dict) and later.get("status") == "pending":
            later["status"] = "skipped"
            later["error"] = reason


async def _run_engagement(engagement_id: str) -> None:
    """Sequentially queue playbook phases as scan jobs (no planner auto-exec)."""
    async with _engagements_lock:
        eng = engagements.get(engagement_id)
        if not eng:
            return
        eng["status"] = "running"
        steps = eng.get("steps") or []
        owner = eng.get("owner_id") or "local"
        target = eng.get("target")

    active_job_id: Optional[str] = None
    active_step_index = -1
    try:
        for index, step in enumerate(steps):
            if not isinstance(step, dict):
                continue
            async with _engagements_lock:
                eng = engagements.get(engagement_id)
                if not eng or eng.get("status") == "cancelled":
                    return
                eng["current_index"] = index
                step["status"] = "running"
                active_step_index = index
            payload = {
                "target": target,
                "preset": step.get("phase"),
            }
            merged, err = apply_preset_to_payload(payload)
            if err or not merged:
                async with _engagements_lock:
                    step["status"] = "failed"
                    step["error"] = err or "preset failed"
                    eng["status"] = "failed"
                    _skip_engagement_tail(
                        steps,
                        after_index=index,
                        reason="Skipped after an earlier phase failed",
                    )
                return
            try:
                job = await create_scan_job(
                    str(merged["target"]),
                    str(merged["scan_type"]),
                    kind="playbook",
                    ports=merged.get("ports"),
                    scripts=merged.get("scripts"),
                    discovery=merged.get("discovery"),
                    owner_id=owner,
                )
            except Exception as exc:
                async with _engagements_lock:
                    step["status"] = "failed"
                    step["error"] = str(exc)
                    eng["status"] = "failed"
                    _skip_engagement_tail(
                        steps,
                        after_index=index,
                        reason="Skipped after an earlier phase failed",
                    )
                log_event(
                    f"Playbook step failed to queue: {exc}",
                    engagement_id=engagement_id,
                    phase=step.get("phase"),
                )
                return
            job_id = job.get("job_id")
            active_job_id = str(job_id) if job_id else None
            async with _engagements_lock:
                step["job_id"] = job_id
            finished = await _wait_job_terminal(str(job_id))
            active_job_id = None
            async with _engagements_lock:
                step["status"] = finished.get("status") or "failed"
                step["result_file"] = finished.get("result_file")
                step["error"] = finished.get("error")
                if finished.get("status") != "completed":
                    eng["status"] = (
                        "cancelled" if finished.get("status") == "cancelled" else "failed"
                    )
                    _skip_engagement_tail(
                        steps,
                        after_index=index,
                        reason=(
                            "Skipped because the playbook was cancelled"
                            if eng["status"] == "cancelled"
                            else "Skipped after an earlier phase failed"
                        ),
                    )
                    log_event(
                        f"Playbook stopped after phase {step.get('phase')}",
                        engagement_id=engagement_id,
                        job_id=job_id,
                        status=finished.get("status"),
                    )
                    return
            log_event(
                f"Playbook phase completed: {step.get('phase')}",
                engagement_id=engagement_id,
                job_id=job_id,
                phase=step.get("phase"),
            )
        async with _engagements_lock:
            eng = engagements.get(engagement_id)
            if eng and eng.get("status") == "running":
                eng["status"] = "completed"
                eng["current_index"] = len(steps)
        log_event(f"Playbook completed {engagement_id}", engagement_id=engagement_id)
    except asyncio.CancelledError:
        if active_job_id:
            await _cancel_scan_job(active_job_id, owner_id=str(owner))
        async with _engagements_lock:
            eng = engagements.get(engagement_id)
            if eng:
                eng["status"] = "cancelled"
                if 0 <= active_step_index < len(steps):
                    active_step = steps[active_step_index]
                    if active_step.get("status") == "running":
                        active_step["status"] = "cancelled"
                        active_step["error"] = "Playbook cancelled"
                _skip_engagement_tail(
                    steps,
                    after_index=active_step_index,
                    reason="Skipped because the playbook was cancelled",
                )
        raise
    except Exception as exc:
        async with _engagements_lock:
            eng = engagements.get(engagement_id)
            if eng:
                eng["status"] = "failed"
                if 0 <= active_step_index < len(steps):
                    active_step = steps[active_step_index]
                    if active_step.get("status") == "running":
                        active_step["status"] = "failed"
                        active_step["error"] = str(exc)
                _skip_engagement_tail(
                    steps,
                    after_index=active_step_index,
                    reason="Skipped after an earlier phase failed",
                )
        log_event(f"Playbook error {engagement_id}: {exc}", engagement_id=engagement_id)


@app.route("/playbook/run", methods=["POST"])
async def playbook_run():
    """Start an ordered engagement playbook (queues sequential scan jobs)."""
    auth_error = require_api_auth("scan")
    if auth_error:
        return auth_error
    if not check_rate_limit():
        return jsonify({"error": "Rate limit exceeded"}), 429

    data = await request.get_json(silent=True)
    if not isinstance(data, dict):
        return jsonify({"error": "Expected JSON body with target"}), 400
    target = data.get("target")
    if not isinstance(target, str) or not target.strip():
        return jsonify({"error": "target is required"}), 400
    target = target.strip()
    # Validate target using the same payload rules as a Ping scan.
    probe = {"target": target, "scan_type": "Ping"}
    _t, _st, _i, _p, _s, _d, error = _validate_scan_payload(
        probe,
        validate_interval=False,
    )
    if error:
        return jsonify({"error": error}), 400
    target = _t or target

    phases, playbook_id, phase_error = resolve_phases(
        playbook=data.get("playbook") or data.get("playbook_id"),
        phases=data.get("phases"),
    )
    if phase_error or not phases or not playbook_id:
        return jsonify({"error": phase_error or "Unable to resolve playbook phases"}), 400

    owner = current_owner_id()
    record = build_engagement_record(
        target=target,
        phase_ids=phases,
        playbook_id=playbook_id,
        owner_id=owner,
    )
    engagement_id = record["engagement_id"]
    async with _engagements_lock:
        engagements[engagement_id] = record
        # Prune old completed engagements if map grows large.
        if len(engagements) > 200:
            finished = [
                eid
                for eid, row in engagements.items()
                if row.get("status") in {"completed", "failed", "cancelled"}
            ]
            for eid in finished[: max(0, len(engagements) - 150)]:
                engagements.pop(eid, None)
                task = _engagement_tasks.pop(eid, None)
                if task and not task.done():
                    task.cancel()

    task = asyncio.create_task(_run_engagement(engagement_id))
    _engagement_tasks[engagement_id] = task
    record_audit_event(
        "playbook.start",
        target=target,
        status="queued",
        detail=f"playbook={playbook_id};phases={','.join(phases)}",
    )
    log_event(
        f"Playbook started {engagement_id}",
        engagement_id=engagement_id,
        playbook=playbook_id,
        target=target,
    )
    return jsonify(public_engagement_view(record)), 202


@app.route("/playbook/<engagement_id>", methods=["GET"])
async def playbook_status(engagement_id: str):
    """Return status of a playbook engagement."""
    auth_error = require_api_auth("read")
    if auth_error:
        return auth_error
    async with _engagements_lock:
        eng = engagements.get(engagement_id)
    if not eng:
        return jsonify({"error": "Engagement not found"}), 404
    owner = current_owner_id()
    if eng.get("owner_id") not in (None, owner) and owner != "local":
        # Hide other operators' engagements.
        if eng.get("owner_id") != owner:
            return jsonify({"error": "Engagement not found"}), 404
    return jsonify(public_engagement_view(eng)), 200


@app.route("/playbook/<engagement_id>", methods=["DELETE"])
async def playbook_cancel(engagement_id: str):
    """Cancel a running playbook and its in-flight scan job."""
    auth_error = require_api_auth("scan")
    if auth_error:
        return auth_error
    async with _engagements_lock:
        eng = engagements.get(engagement_id)
        if not eng:
            return jsonify({"error": "Engagement not found"}), 404
        owner = current_owner_id()
        if eng.get("owner_id") not in (None, owner) and owner != "local":
            if eng.get("owner_id") != owner:
                return jsonify({"error": "Engagement not found"}), 404
        eng["status"] = "cancelled"
        task = _engagement_tasks.get(engagement_id)
        active_steps = []
        for index, step in enumerate(eng.get("steps") or []):
            if not isinstance(step, dict):
                continue
            if step.get("status") == "pending":
                step["status"] = "skipped"
                step["error"] = "Skipped because the playbook was cancelled"
                continue
            if step.get("status") != "running":
                continue
            job_id = step.get("job_id")
            if job_id:
                active_steps.append((index, str(job_id)))
            else:
                step["status"] = "cancelled"
                step["error"] = "Playbook cancelled"
    if task and not task.done():
        task.cancel()

    cancelled_job_ids = []
    killed_processes = 0
    for index, job_id in active_steps:
        job, changed, killed = await _cancel_scan_job(job_id, owner_id=owner)
        if changed:
            cancelled_job_ids.append(job_id)
        if killed:
            killed_processes += 1
        async with _engagements_lock:
            current = engagements.get(engagement_id)
            steps = current.get("steps") if current else None
            if not isinstance(steps, list) or not 0 <= index < len(steps):
                continue
            step = steps[index]
            if not isinstance(step, dict):
                continue
            if job is None:
                step["status"] = "cancelled"
                step["error"] = "Playbook cancelled"
            else:
                step["status"] = job.get("status") or "cancelled"
                step["result_file"] = job.get("result_file")
                step["error"] = job.get("error")

    record_audit_event(
        "playbook.cancel",
        status="cancelled",
        detail=(
            f"{engagement_id};jobs={','.join(cancelled_job_ids)};"
            f"processes_killed={killed_processes}"
        ),
    )
    return jsonify(public_engagement_view(eng)), 200


@app.route("/posture/evaluate", methods=["POST"])
async def posture_evaluate():
    """Evaluate a scan (or stored result) against expected service posture."""
    auth_error = require_api_auth("read")
    if auth_error:
        return auth_error
    if not check_rate_limit():
        return jsonify({"error": "Rate limit exceeded"}), 429

    body = await request.get_json(silent=True)
    if not isinstance(body, dict):
        return jsonify({"error": "Expected JSON body"}), 400
    scan, error, _, _ = await _resolve_scan_for_pack(body=body)
    if error:
        return jsonify({"error": error}), 400 if "not found" not in error.lower() else 404
    try:
        if "posture" in body:
            expected = body["posture"]
        elif "expected" in body:
            expected = body["expected"]
        else:
            expected = load_expected_posture()
        if expected is None:
            pass
        elif isinstance(expected, str):
            expected = load_expected_posture(expected)
        elif not isinstance(expected, dict):
            return jsonify({"error": "posture must be an object or JSON string"}), 400
        else:
            # Normalize list form under services if caller posted raw list.
            if "services" not in expected and isinstance(expected.get("ports"), list):
                expected = {
                    "services": expected["ports"],
                    "deny_unexpected": expected.get("deny_unexpected", True),
                }
            expected = load_expected_posture(json.dumps(expected))
    except RuntimeError as exc:
        return jsonify({"error": str(exc)}), 400
    report = evaluate_posture(scan, expected)
    return jsonify(report), 200


@app.route("/scan", methods=["POST"])
async def start_scan():
    try:
        auth_error = require_api_auth("scan")
        if auth_error:
            return auth_error

        if not check_rate_limit():
            return jsonify({"error": "Rate limit exceeded"}), 429

        data = await request.get_json(silent=True)
        data, preset_error = apply_preset_to_payload(data if isinstance(data, dict) else None)
        if preset_error:
            return jsonify({"error": preset_error}), 400
        target, scan_type, _, ports, scripts, discovery, error = _validate_scan_payload(
            data,
            validate_interval=False,
        )
        if error:
            return jsonify({"error": error}), 400

        wait = _bool_query_param("wait", False)
        preset_id = (data or {}).get("preset")
        log_event(
            f"Scan requested: {target}, type={scan_type}, wait={wait}"
            + (f", preset={preset_id}" if preset_id else "")
        )

        if wait:
            try:
                results = await async_scan(
                    target,
                    scan_type,
                    ports=ports,
                    scripts=scripts,
                    discovery=discovery,
                    owner_id=current_owner_id(),
                )
            except JobCancelledError as e:
                return jsonify({"error": str(e), "status": "cancelled"}), 409
            except TimeoutError as e:
                return jsonify({"error": str(e)}), 504
            except Exception as e:
                log_event(f"API error in /scan wait mode: {e}")
                return jsonify({"error": "Internal scan error"}), 500
            payload = results or {"message": "Scan completed with no results"}
            if isinstance(payload, dict) and preset_id:
                payload = dict(payload)
                payload["preset"] = preset_id
                payload["preset_phase"] = (data or {}).get("preset_phase")
                nxt = next_phase(str(preset_id))
                if nxt:
                    payload["next_preset"] = nxt
            return jsonify(payload), 200

        job = await create_scan_job(
            target,
            scan_type,
            kind="immediate",
            ports=ports,
            scripts=scripts,
            discovery=discovery,
            owner_id=current_owner_id(),
        )
        if preset_id and isinstance(job, dict):
            job = dict(job)
            job["preset"] = preset_id
            job["preset_phase"] = (data or {}).get("preset_phase")
            job["scan_type"] = scan_type
            job["ports"] = ports
            job["scripts"] = scripts
            job["discovery"] = discovery
            nxt = next_phase(str(preset_id))
            if nxt:
                job["next_preset"] = nxt
        return jsonify(job), 202
    except Exception as e:
        err = f"API error in /scan: {e}"
        log_event(err)
        await send_telegram_message(f"API error: {e}")
        return jsonify({"error": "Internal scan error"}), 500


@app.route("/jobs", methods=["GET"])
async def list_jobs():
    auth_error = require_api_auth("read")
    if auth_error:
        return auth_error

    owner = current_owner_id()
    try:
        persisted = await asyncio.to_thread(state_store.list_jobs, MAX_SCAN_JOBS, owner)
    except Exception as exc:
        log_event(f"Failed to list persisted jobs: {exc}")
        persisted = []
    async with _jobs_lock:
        merged = {
            job["job_id"]: job
            for job in persisted
            if job.get("job_id") and job_visible_to_owner(job, owner)
        }
        for job in scan_jobs.values():
            if job_visible_to_owner(job, owner) and job["job_id"] not in merged:
                # Durable state wins. Memory-only rows are retained only for
                # compatibility with tests/startup edge cases.
                merged[job["job_id"]] = job
        jobs = [
            _job_public_view(job, include_result=False)
            for job in sorted(
                merged.values(),
                key=lambda item: item.get("created_at") or "",
                reverse=True,
            )[:MAX_SCAN_JOBS]
        ]
    return jsonify(jobs), 200


@app.route("/jobs/<job_id>", methods=["GET"])
async def get_job(job_id: str):
    auth_error = require_api_auth("read")
    if auth_error:
        return auth_error

    job = await _refresh_job_from_store(job_id)
    if not job:
        return jsonify({"error": "Job not found"}), 404
    if not job_visible_to_owner(job):
        return jsonify({"error": "Job not found"}), 404
    if job.get("status") == "completed" and not isinstance(job.get("result"), dict):
        loaded = await _load_job_result_payload(job)
        if loaded is not None:
            job = {**job, "result": loaded}
    return jsonify(_job_public_view(job, include_result=True)), 200


async def _cancel_scan_job(
    job_id: str,
    *,
    owner_id: str,
) -> Tuple[Optional[Dict[str, Any]], bool, bool]:
    """Cancel an owned queued/running job and return (job, changed, process_killed)."""
    finished_at = _utc_now_iso()
    durable, changed = await asyncio.to_thread(
        state_store.cancel_job_if_active,
        job_id,
        owner_id,
        finished_at=finished_at,
        error="Scan cancelled",
    )
    if durable is None:
        # Compatibility for process-local jobs created by older integrations.
        # New jobs are inserted durably before they can be launched.
        async with _jobs_lock:
            existing = scan_jobs.get(job_id)
            if existing is None or not job_visible_to_owner(existing, owner_id):
                return None, False, False
            previous_status = existing.get("status")
            changed = previous_status in {"queued", "running"}
            if changed:
                existing.update(
                    {
                        "status": "cancelled",
                        "finished_at": finished_at,
                        "error": "Scan cancelled",
                        "lease_owner": None,
                        "lease_until": None,
                    }
                )
                _note_job_terminal_metrics(
                    existing,
                    previous_status=previous_status,
                    status="cancelled",
                )
            job = existing
            task = existing.get("task")
            should_stop = changed or existing.get("status") == "cancelled"
            if should_stop and task is not None and not task.done():
                task.cancel()
        killed = _request_job_process_cancel(job_id) if should_stop else False
        return job, changed, killed

    async with _jobs_lock:
        existing = scan_jobs.get(job_id)
        task = (existing or {}).get("task")
        previous_status = (existing or {}).get("status")
        result = None
        if (
            existing
            and durable.get("status") == "completed"
            and existing.get("status") == "completed"
            and existing.get("result_file") == durable.get("result_file")
        ):
            result = existing.get("result")
        job = {**durable, "task": task, "result": result}
        scan_jobs[job_id] = job
        if changed:
            _note_job_terminal_metrics(job, previous_status=previous_status, status="cancelled")
        should_stop = changed or durable.get("status") == "cancelled"
        if should_stop and task is not None and not task.done():
            task.cancel()

    # Hard-cancel Nmap/discovery process group (task.cancel alone does not stop executor).
    killed = _request_job_process_cancel(job_id) if should_stop else False
    if changed:
        _release_redis_job_lease(job_id)
    return job, changed, killed


@app.route("/jobs/<job_id>", methods=["DELETE"])
async def cancel_job(job_id: str):
    auth_error = require_api_auth("scan")
    if auth_error:
        return auth_error

    job, changed, killed = await _cancel_scan_job(job_id, owner_id=current_owner_id())
    if job is None:
        return jsonify({"error": "Job not found"}), 404
    if not changed:
        return jsonify(
            {
                "message": f"Job already {job['status']}",
                "job_id": job_id,
                "process_killed": killed,
            }
        ), 200
    log_event(
        f"Job {job_id} cancelled",
        job_id=job_id,
        process_killed=killed,
    )
    record_audit_event(
        "scan.cancel",
        target=job.get("target"),
        scan_type=job.get("scan_type"),
        job_id=job_id,
        status="cancelled",
        detail=f"process_killed={killed}",
    )
    return jsonify(
        {
            "message": f"Job {job_id} cancelled",
            "job_id": job_id,
            "process_killed": killed,
        }
    ), 200


def _try_redis_leadership(lock_name: str, *, renew: bool = False) -> bool:
    client = _get_redis_client()
    if client is None:
        return True
    key = f"{REDIS_LEADER_PREFIX}{lock_name}"
    try:
        if renew:
            current = client.get(key)
            if current not in (None, WORKER_ID):
                return False
            client.set(key, WORKER_ID, ex=SCHEDULER_LEADER_SECONDS)
            return True
        ok = client.set(key, WORKER_ID, nx=True, ex=SCHEDULER_LEADER_SECONDS)
        if ok:
            return True
        return client.get(key) == WORKER_ID
    except Exception as exc:
        log_event(f"Redis leadership error for {lock_name}: {exc}")
        return True


def _release_redis_leadership(lock_name: str) -> None:
    client = _get_redis_client()
    if client is None:
        return
    key = f"{REDIS_LEADER_PREFIX}{lock_name}"
    try:
        if client.get(key) == WORKER_ID:
            client.delete(key)
    except Exception as exc:
        log_event(f"Redis leadership release error for {lock_name}: {exc}")


def try_become_scheduler_leader() -> bool:
    """Acquire or renew the scheduler leadership lease."""
    if not _try_redis_leadership(SCHEDULER_LOCK_NAME, renew=_is_scheduler_leader):
        return False
    acquired = state_store.try_acquire_leadership(
        SCHEDULER_LOCK_NAME,
        WORKER_ID,
        now=time.time(),
        lease_seconds=SCHEDULER_LEADER_SECONDS,
    )
    if not acquired:
        _release_redis_leadership(SCHEDULER_LOCK_NAME)
    return acquired


def is_scheduler_leader() -> bool:
    return _is_scheduler_leader


def _start_local_scheduled_task(row: Dict[str, Any]) -> bool:
    """Start a local periodic_scan for a DB row if not already running."""
    task_id = row["task_id"]
    if task_id in scan_tasks and not scan_tasks[task_id].done():
        return False
    if len(scan_tasks) >= MAX_SCHEDULED_TASKS:
        return False
    task = asyncio.create_task(
        periodic_scan(
            row["target"],
            row["scan_type"],
            float(row["interval_minutes"]),
            ports=row.get("ports"),
            scripts=row.get("scripts"),
            discovery=row.get("discovery"),
            owner_id=row.get("owner_id") or "local",
        )
    )
    scan_tasks[task_id] = task
    return True


async def stop_all_local_schedules() -> None:
    """Cancel every local periodic task (used when leadership is lost)."""
    tasks = list(scan_tasks.items())
    for _task_id, task in tasks:
        task.cancel()
    if tasks:
        await asyncio.gather(*(task for _, task in tasks), return_exceptions=True)
    scan_tasks.clear()
    log_event("Stopped local scheduled tasks after leadership loss")


async def sync_scheduled_tasks_from_store() -> None:
    """Ensure leader local loops match durable schedule rows."""
    if not _is_scheduler_leader:
        return
    try:
        rows = await asyncio.to_thread(state_store.list_scheduled_tasks)
    except Exception as exc:
        log_event(f"Failed to list scheduled tasks for sync: {exc}")
        return
    desired = {row["task_id"] for row in rows}
    # Stop local tasks removed from DB.
    for task_id in list(scan_tasks.keys()):
        if task_id not in desired:
            scan_tasks[task_id].cancel()
            del scan_tasks[task_id]
    for row in rows:
        if _start_local_scheduled_task(row):
            log_event(
                f"Scheduler leader started task {row['task_id']} "
                f"every {row['interval_minutes']} minutes"
            )


async def scheduler_leader_loop(stop_event: Optional[asyncio.Event] = None) -> None:
    """Elect a single scheduler leader so recurring scans do not duplicate."""
    global _is_scheduler_leader
    log_event(
        f"Scheduler leader loop started (worker={WORKER_ID}, lease={SCHEDULER_LEADER_SECONDS}s)"
    )
    while True:
        if stop_event is not None and stop_event.is_set():
            break
        try:
            acquired = await asyncio.to_thread(try_become_scheduler_leader)
            if acquired:
                if not _is_scheduler_leader:
                    _is_scheduler_leader = True
                    log_event(f"Became scheduler leader ({WORKER_ID})")
                await sync_scheduled_tasks_from_store()
            else:
                if _is_scheduler_leader:
                    _is_scheduler_leader = False
                    log_event(f"Lost scheduler leadership ({WORKER_ID})")
                    await stop_all_local_schedules()
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            log_event(f"Scheduler leader loop error: {exc}")
        await asyncio.sleep(SCHEDULER_LEADER_POLL_SECONDS)


async def periodic_scan(
    target: str,
    scan_type: str,
    interval_minutes: float,
    ports: Optional[str] = None,
    scripts: Optional[str] = None,
    discovery: Optional[str] = None,
    owner_id: Optional[str] = None,
):
    """Async recurring scan loop (leader only)."""
    try:
        interval = float(interval_minutes)
    except (TypeError, ValueError):
        raise ValueError("interval must be a number")

    if interval <= 0:
        raise ValueError("interval must be a positive number")

    owner = owner_id or "local"
    log_event(f"Started periodic scan {target} every {interval} minutes")
    await send_telegram_message(
        f"{PRODUCT_NAME}: started periodic scan {target} every {interval} minutes"
    )

    while True:
        if not _is_scheduler_leader:
            log_event(f"Periodic scan {target} stopping (not scheduler leader)")
            break
        _cleanup_finished_tasks()
        try:
            log_event(f"Running periodic scan: {target}")
            await async_scan(
                target,
                scan_type,
                ports=ports,
                scripts=scripts,
                discovery=discovery,
                owner_id=owner,
                kind="scheduled",
            )
        except JobCancelledError:
            log_event(f"Periodic scan occurrence cancelled: {target}")
        except asyncio.CancelledError:
            log_event(f"Periodic scan {target} cancelled")
            break
        except Exception as e:
            err = f"Periodic scan error for {target}: {e}"
            log_event(err)
            await send_telegram_message(err)

        try:
            await asyncio.sleep(interval * 60)
        except asyncio.CancelledError:
            break


@app.route("/schedule", methods=["POST"])
async def add_scheduled_scan():
    try:
        auth_error = require_api_auth("scan")
        if auth_error:
            return auth_error

        if not check_rate_limit():
            return jsonify({"error": "Rate limit exceeded"}), 429

        data = await request.get_json(silent=True)
        data, preset_error = apply_preset_to_payload(data if isinstance(data, dict) else None)
        if preset_error:
            return jsonify({"error": preset_error}), 400
        target, scan_type, interval, ports, scripts, discovery, error = _validate_scan_payload(data)
        if error:
            return jsonify({"error": error}), 400

        if interval is None:
            interval = 30.0

        owner = current_owner_id()
        task_id = make_task_id(target, scan_type, owner)
        _cleanup_finished_tasks()

        try:
            existing = await asyncio.to_thread(state_store.list_scheduled_tasks)
        except Exception as exc:
            log_event(f"Failed to list schedules: {exc}")
            existing = []
        if any(row.get("task_id") == task_id for row in existing):
            return jsonify({"error": "Scan already scheduled"}), 400
        if len(existing) >= MAX_SCHEDULED_TASKS:
            return jsonify({"error": "Scheduled task limit reached"}), 429

        try:
            state_store.upsert_scheduled_task(
                task_id,
                target,
                scan_type,
                interval,
                ports=ports,
                scripts=scripts,
                discovery=discovery,
                owner_id=owner,
                created_at=_utc_now_iso(),
            )
        except Exception as exc:
            log_event(f"Failed to persist scheduled task {task_id}: {exc}")
            return jsonify({"error": "Failed to persist scheduled task"}), 500

        # Leader starts the loop immediately; non-leaders rely on leader sync.
        if _is_scheduler_leader:
            _start_local_scheduled_task(
                {
                    "task_id": task_id,
                    "target": target,
                    "scan_type": scan_type,
                    "interval_minutes": interval,
                    "ports": ports,
                    "scripts": scripts,
                    "discovery": discovery,
                    "owner_id": owner,
                }
            )
        log_event(f"Scan {target} scheduled every {interval} minutes")
        record_audit_event(
            "schedule.create",
            target=target,
            scan_type=scan_type,
            task_id=task_id,
            status="scheduled",
            detail=f"interval={interval}",
        )

        return jsonify(
            {
                "message": f"Scan {target} scheduled every {interval} minutes",
                "task_id": task_id,
                "scheduler_leader": _is_scheduler_leader,
            }
        ), 200
    except Exception as e:
        err = f"Error in /schedule: {e}"
        log_event(err)
        return jsonify({"error": "Internal scheduler error"}), 500


@app.route("/tasks", methods=["GET"])
async def list_tasks():
    auth_error = require_api_auth("read")
    if auth_error:
        return auth_error

    owner = current_owner_id()
    owner_prefix = f"o{owner_result_prefix(owner)[1:13]}-"
    _cleanup_finished_tasks()
    try:
        rows = await asyncio.to_thread(state_store.list_scheduled_tasks)
    except Exception as exc:
        log_event(f"Failed to list scheduled tasks: {exc}")
        rows = []

    tasks_info = []
    for row in rows:
        task_id = row["task_id"]
        row_owner = row.get("owner_id")
        if row_owner and row_owner != owner:
            continue
        if not row_owner and task_id.startswith("o") and not task_id.startswith(owner_prefix):
            continue
        local = scan_tasks.get(task_id)
        tasks_info.append(
            {
                "id": task_id,
                "target": row.get("target"),
                "scan_type": row.get("scan_type"),
                "interval_minutes": row.get("interval_minutes"),
                "running": bool(local is not None and not local.done()),
                "cancelled": bool(local is not None and local.cancelled()),
                "scheduler_leader": _is_scheduler_leader,
            }
        )
    # Include any local-only legacy tasks not yet in DB.
    for task_id, task in scan_tasks.items():
        if any(item["id"] == task_id for item in tasks_info):
            continue
        if task_id.startswith("o") and not task_id.startswith(owner_prefix):
            continue
        tasks_info.append(
            {
                "id": task_id,
                "running": not task.done(),
                "cancelled": task.cancelled(),
                "scheduler_leader": _is_scheduler_leader,
            }
        )
    return jsonify(tasks_info), 200


@app.route("/tasks/<path:task_id>", methods=["DELETE"])
async def cancel_task(task_id):
    auth_error = require_api_auth("scan")
    if auth_error:
        return auth_error

    owner = current_owner_id()
    owner_prefix = f"o{owner_result_prefix(owner)[1:13]}-"
    if task_id.startswith("o") and not task_id.startswith(owner_prefix):
        return jsonify({"error": "Task not found"}), 404

    _cleanup_finished_tasks()
    local_exists = task_id in scan_tasks
    durable_exists = False
    try:
        # Delete durable state first so a successful response cannot be
        # reversed by leader synchronization.
        existing = await asyncio.to_thread(state_store.list_scheduled_tasks)
        durable_exists = any(row.get("task_id") == task_id for row in existing)
        if durable_exists:
            deleted_durable = await asyncio.to_thread(
                state_store.delete_scheduled_task,
                task_id,
            )
            if not deleted_durable:
                return jsonify({"error": "Failed to delete persisted task"}), 503
    except Exception as exc:
        log_event(f"Failed to delete persisted task {task_id}: {exc}")
        return jsonify({"error": "Failed to delete persisted task"}), 503
    if local_exists:
        scan_tasks[task_id].cancel()
        del scan_tasks[task_id]
    deleted = durable_exists or local_exists
    if deleted:
        log_event(f"Task {task_id} cancelled")
        record_audit_event("schedule.cancel", task_id=task_id, status="cancelled")
        await send_telegram_message(f"Task {task_id} cancelled")
        return jsonify({"message": f"Task {task_id} cancelled"}), 200
    return jsonify({"error": "Task not found"}), 404


def _safe_result_path(result_id: str) -> Optional[Path]:
    name = os.path.basename(result_id.strip())
    if name != result_id.strip() or ".." in name:
        return None
    if not RESULT_FILENAME_RE.fullmatch(name) and not re.fullmatch(
        r"^[A-Za-z0-9._-]{1,220}\.json$", name
    ):
        return None
    path = Path(RESULTS_DIR).resolve() / name
    try:
        path.resolve().relative_to(Path(RESULTS_DIR).resolve())
    except ValueError:
        return None
    return path if path.is_file() else None


@app.route("/results", methods=["GET"])
async def list_results():
    auth_error = require_api_auth("read")
    if auth_error:
        return auth_error

    limit = _parse_optional_limit(request.args.get("limit"), default=50, max_value=500)
    owner = current_owner_id()
    files = await asyncio.to_thread(_result_files)
    items = []
    for path in files:
        if not result_visible_to_owner(path.name, owner):
            continue
        try:
            stat = path.stat()
            items.append(
                {
                    "id": path.name,
                    "filename": path.name,
                    "size_bytes": stat.st_size,
                    "modified_at": datetime.fromtimestamp(
                        stat.st_mtime, tz=timezone.utc
                    ).isoformat(),
                }
            )
        except OSError:
            continue
        if len(items) >= limit:
            break
    return jsonify({"count": len(items), "results": items}), 200


def _parse_optional_limit(raw: Optional[str], default: int, max_value: int) -> int:
    if raw is None or raw == "":
        return default
    try:
        value = int(raw)
    except (TypeError, ValueError):
        return default
    if value < 1:
        return default
    return min(value, max_value)


@app.route("/results/<path:result_id>", methods=["GET"])
async def get_result(result_id: str):
    auth_error = require_api_auth("read")
    if auth_error:
        return auth_error

    path = _safe_result_path(result_id)
    if path is None or not result_visible_to_owner(path.name):
        return jsonify({"error": "Result not found"}), 404

    try:
        encrypted = await asyncio.to_thread(path.read_bytes)
        plaintext = cipher.decrypt(encrypted)
        payload = json.loads(plaintext.decode("utf-8"))
    except InvalidToken:
        return jsonify({"error": "Unable to decrypt result with configured FERNET_KEY"}), 500
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        log_event(f"Result read error for {result_id}: {exc}")
        return jsonify({"error": "Result file is unreadable"}), 500

    return jsonify({"id": path.name, "filename": path.name, "result": payload}), 200


async def _load_result_reference(ref: Any) -> Tuple[Optional[dict], Optional[str]]:
    """Resolve a result object or {id: filename} reference."""
    if isinstance(ref, dict) and isinstance(ref.get("hosts"), list):
        return ref, None
    if isinstance(ref, dict) and ref.get("result") and isinstance(ref["result"], dict):
        return ref["result"], None
    result_id = None
    if isinstance(ref, str):
        result_id = ref
    elif isinstance(ref, dict):
        result_id = ref.get("id") or ref.get("filename") or ref.get("result_id")
    if not result_id or not isinstance(result_id, str):
        return None, "Expected a scan result object or result id"
    path = _safe_result_path(result_id)
    if path is None or not result_visible_to_owner(path.name):
        return None, f"Result not found: {result_id}"
    try:
        encrypted = await asyncio.to_thread(path.read_bytes)
        plaintext = cipher.decrypt(encrypted)
        return json.loads(plaintext.decode("utf-8")), None
    except InvalidToken:
        return None, "Unable to decrypt result with configured FERNET_KEY"
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        log_event(f"Result load error for {result_id}: {exc}")
        return None, "Result file is unreadable"


@app.route("/results/import", methods=["POST"])
async def import_result_xml():
    auth_error = require_api_auth("scan")
    if auth_error:
        return auth_error
    if not check_rate_limit():
        return jsonify({"error": "Rate limit exceeded"}), 429

    content_type = (request.content_type or "").lower()
    target_label = ""
    scan_type = "Import"
    xml_bytes: Optional[bytes] = None

    if "application/json" in content_type:
        data = await request.get_json(silent=True)
        if not isinstance(data, dict) or not isinstance(data.get("xml"), str):
            return jsonify({"error": "Expected JSON body with xml string"}), 400
        xml_bytes = data["xml"].encode("utf-8")
        if isinstance(data.get("target"), str):
            target_label = data["target"].strip()
        if isinstance(data.get("scan_type"), str) and data["scan_type"].strip():
            scan_type = data["scan_type"].strip()[:40]
    else:
        xml_bytes = await request.get_data(cache=False)
        target_label = (request.args.get("target") or "").strip()

    if not xml_bytes:
        return jsonify({"error": "Empty XML payload"}), 400
    if len(xml_bytes) > MAX_IMPORT_XML_BYTES:
        return jsonify(
            {"error": f"XML exceeds {MAX_IMPORT_XML_BYTES // (1024 * 1024)} MiB limit"}
        ), 413

    try:
        result = await asyncio.to_thread(
            import_nmap_xml,
            xml_bytes,
            target=target_label or "xml-import",
            scan_type=scan_type,
        )
    except Exception as exc:
        log_event(f"XML import failed: {exc}")
        return jsonify({"error": f"XML import failed: {exc}"}), 400

    filename = await save_scan_results_async(
        result,
        result.get("target") or "xml-import",
        scan_type,
        owner_id=current_owner_id(),
    )
    record_audit_event(
        "result.import",
        target=result.get("target") or "xml-import",
        scan_type=scan_type,
        result_file=filename,
        status="imported",
    )
    return jsonify({"id": filename, "filename": filename, "result": result}), 201


@app.route("/results/diff", methods=["POST"])
async def diff_results():
    auth_error = require_api_auth("read")
    if auth_error:
        return auth_error
    if not check_rate_limit():
        return jsonify({"error": "Rate limit exceeded"}), 429

    data = await request.get_json(silent=True)
    if not isinstance(data, dict):
        return jsonify({"error": "Expected JSON with baseline and current"}), 400

    baseline, baseline_error = await _load_result_reference(
        data.get("baseline") or data.get("old") or data.get("a")
    )
    if baseline_error:
        return jsonify({"error": f"baseline: {baseline_error}"}), 400
    current, current_error = await _load_result_reference(
        data.get("current") or data.get("new") or data.get("b")
    )
    if current_error:
        return jsonify({"error": f"current: {current_error}"}), 400

    diff = await asyncio.to_thread(diff_scan_results, baseline, current)
    return jsonify(diff), 200


@app.route("/tools", methods=["GET"])
async def tools_inventory():
    auth_error = require_api_auth("read")
    if auth_error:
        return auth_error
    if not check_rate_limit():
        return jsonify({"error": "Rate limit exceeded"}), 429

    expand = _bool_query_param("expand", False)
    inventory = await asyncio.to_thread(get_cached_tool_inventory, expand=expand)
    return jsonify(inventory), 200


@app.route("/tools/ai-context", methods=["GET"])
async def tools_ai_context():
    auth_error = require_api_auth("read")
    if auth_error:
        return auth_error
    if not check_rate_limit():
        return jsonify({"error": "Rate limit exceeded"}), 429

    expand = _bool_query_param("expand", False)
    output_format = request.args.get("format", "jsonl").strip().lower()
    inventory = await asyncio.to_thread(get_cached_tool_inventory, expand=expand)
    if output_format in {"md", "markdown"}:
        return (
            inventory_to_markdown(inventory),
            200,
            {"Content-Type": "text/markdown; charset=utf-8"},
        )
    return (
        inventory_to_jsonl(inventory),
        200,
        {"Content-Type": "application/x-ndjson; charset=utf-8"},
    )


@app.route("/recon/plan", methods=["POST"])
async def recon_plan():
    auth_error = require_api_auth("read")
    if auth_error:
        return auth_error
    if not check_rate_limit():
        return jsonify({"error": "Rate limit exceeded"}), 429

    data = await request.get_json(silent=True)
    if not isinstance(data, dict):
        return jsonify({"error": "Expected scan result JSON"}), 400

    scan = data.get("scan") or data.get("result") or data
    if not isinstance(scan, dict) or not isinstance(scan.get("hosts"), list):
        return jsonify({"error": "Expected parsed Nmap result with hosts[]"}), 400

    inventory = await asyncio.to_thread(
        get_cached_tool_inventory, expand=_bool_query_param("expand", False)
    )
    plan = await asyncio.to_thread(build_recon_plan, scan, inventory=inventory)
    output_format = request.args.get("format", "json").strip().lower()
    if output_format == "jsonl":
        return (
            recon_plan_to_jsonl(plan),
            200,
            {"Content-Type": "application/x-ndjson; charset=utf-8"},
        )
    if output_format in {"md", "markdown"}:
        return recon_plan_to_markdown(plan), 200, {"Content-Type": "text/markdown; charset=utf-8"}
    return jsonify(plan), 200


async def _resolve_scan_for_pack(
    *,
    body: Optional[Dict[str, Any]] = None,
    result_id: Optional[str] = None,
    job_id: Optional[str] = None,
) -> Tuple[Optional[Dict[str, Any]], Optional[str], Optional[str], Optional[str]]:
    """Return (scan, error, resolved_result_id, resolved_job_id)."""
    body = body or {}
    result_id = (result_id or body.get("result_id") or body.get("id") or "").strip() or None
    job_id = (job_id or body.get("job_id") or "").strip() or None

    # Explicit scan payload wins when it looks like a parsed result.
    scan = body.get("scan") or body.get("result")
    if isinstance(scan, dict) and isinstance(scan.get("hosts"), list):
        return scan, None, result_id, job_id
    if (
        not result_id
        and not job_id
        and isinstance(body, dict)
        and isinstance(body.get("hosts"), list)
    ):
        return body, None, None, None

    if job_id:
        job = await _refresh_job_from_store(job_id)
        if not job or not job_visible_to_owner(job):
            return None, "Job not found", None, job_id
        if job.get("status") != "completed":
            return (
                None,
                f"Job is not completed (status={job.get('status')})",
                None,
                job_id,
            )
        result = job.get("result")
        if isinstance(result, dict) and isinstance(result.get("hosts"), list):
            return result, None, job.get("result_file"), job_id
        file_name = job.get("result_file")
        if file_name:
            result_id = str(file_name)
        else:
            return None, "Job completed without a loadable result", None, job_id

    if result_id:
        path = _safe_result_path(result_id)
        if path is None or not result_visible_to_owner(path.name):
            return None, "Result not found", result_id, job_id
        try:
            encrypted = await asyncio.to_thread(path.read_bytes)
            plaintext = cipher.decrypt(encrypted)
            payload = json.loads(plaintext.decode("utf-8"))
        except InvalidToken:
            return None, "Unable to decrypt result with configured FERNET_KEY", result_id, job_id
        except (OSError, UnicodeDecodeError, json.JSONDecodeError):
            return None, "Result file is unreadable", result_id, job_id
        if not isinstance(payload, dict) or not isinstance(payload.get("hosts"), list):
            return None, "Stored result is not a parsed scan with hosts[]", result_id, job_id
        return payload, None, path.name, job_id

    return None, "Provide scan JSON body, result_id, or job_id", None, None


@app.route("/ai/pack", methods=["GET", "POST"])
async def ai_pack():
    """Budgeted AI recon pack (default small/compact NDJSON, not full archive)."""
    auth_error = require_api_auth("read")
    if auth_error:
        return auth_error
    if not check_rate_limit():
        return jsonify({"error": "Rate limit exceeded"}), 429

    body: Dict[str, Any] = {}
    if request.method == "POST":
        payload = await request.get_json(silent=True)
        if isinstance(payload, dict):
            body = payload

    budget_raw = request.args.get("budget") or body.get("budget") or "s"
    try:
        budget = normalize_budget(budget_raw)
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400

    output_format = (request.args.get("format") or body.get("format") or "jsonl").strip().lower()
    include_closed = _bool_query_param("include_closed", False) or bool(body.get("include_closed"))
    # Full archive still available via detail=full|l budget or /results/<id>.
    if str(request.args.get("detail") or body.get("detail") or "").lower() in {
        "full",
        "l",
        "large",
        "archive",
    }:
        budget = "l"

    result_id = (request.args.get("result_id") or request.args.get("id") or "").strip() or None
    job_id = (request.args.get("job_id") or "").strip() or None
    mode = (request.args.get("mode") or body.get("mode") or "").strip().lower() or None
    scan, error, resolved_result_id, resolved_job_id = await _resolve_scan_for_pack(
        body=body, result_id=result_id, job_id=job_id
    )
    if error:
        status = 404 if "not found" in error.lower() else 400
        return jsonify({"error": error}), status

    baseline = None
    if mode in {"retest", "diff"} or body.get("baseline") is not None:
        base_ref = body.get("baseline")
        if isinstance(base_ref, dict) and isinstance(base_ref.get("hosts"), list):
            baseline = base_ref
        elif isinstance(base_ref, dict) and (
            base_ref.get("result_id") or base_ref.get("id") or base_ref.get("job_id")
        ):
            baseline, base_err, _, _ = await _resolve_scan_for_pack(
                body=base_ref,
                result_id=(base_ref.get("result_id") or base_ref.get("id")),
                job_id=base_ref.get("job_id"),
            )
            if base_err:
                return jsonify({"error": f"baseline: {base_err}"}), 400
        elif isinstance(base_ref, str) and base_ref.strip():
            baseline, base_err, _, _ = await _resolve_scan_for_pack(
                body={}, result_id=base_ref.strip()
            )
            if base_err:
                return jsonify({"error": f"baseline: {base_err}"}), 400
        elif request.args.get("baseline_id"):
            baseline, base_err, _, _ = await _resolve_scan_for_pack(
                body={}, result_id=request.args.get("baseline_id")
            )
            if base_err:
                return jsonify({"error": f"baseline: {base_err}"}), 400
        if baseline is None:
            return jsonify({"error": "retest mode requires baseline scan or baseline_id"}), 400
        mode = mode or "retest"

    inventory = await asyncio.to_thread(
        get_cached_tool_inventory, expand=_bool_query_param("expand", False)
    )
    try:
        pack_body, content_type, rows = await asyncio.to_thread(
            build_ai_pack,
            scan,
            budget=budget,
            inventory=inventory,
            format=output_format,
            job_id=resolved_job_id,
            result_id=resolved_result_id,
            include_closed=include_closed and budget == "l",
            baseline=baseline,
            mode=mode,
        )
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400
    except Exception as exc:
        log_event(f"AI pack build failed: {exc}")
        return jsonify({"error": "Failed to build AI pack"}), 500

    record_audit_event(
        "ai.pack",
        target=str(scan.get("target") or "")[:256] or None,
        scan_type=str(scan.get("scan_type") or "")[:64] or None,
        job_id=resolved_job_id,
        result_file=resolved_result_id,
        status=budget,
        detail=f"lines={len(rows)};format={output_format};mode={mode or 'pack'}",
    )
    return pack_body, 200, {"Content-Type": content_type, "Cache-Control": "no-store"}


def _render_dashboard_html() -> tuple:
    nonce = secrets.token_urlsafe(18)
    html = UI_HTML.replace("__CSP_NONCE__", nonce)
    # 'self' covers /static/* assets; nonces still bind the dashboard link/script tags.
    csp = (
        f"default-src 'self'; "
        f"style-src 'self' 'nonce-{nonce}'; "
        f"script-src 'self' 'nonce-{nonce}'; "
        f"connect-src 'self'; img-src 'self' data:; frame-ancestors 'none'; "
        f"base-uri 'self'; form-action 'self'"
    )
    return (
        html,
        200,
        {
            "Content-Type": "text/html; charset=utf-8",
            "Content-Security-Policy": csp,
            "Cache-Control": "no-store",
        },
    )


@app.route("/", methods=["GET"])
@app.route("/ui", methods=["GET"])
async def dashboard():
    return _render_dashboard_html()


@app.route("/favicon.ico", methods=["GET"])
async def favicon():
    """Browsers probe /favicon.ico; serve the SVG asset with cacheable headers."""
    path = _STATIC_DIR / "favicon.svg"
    if not path.is_file():
        return "", 404
    return await app.send_static_file("favicon.svg")


@app.after_request
async def add_security_headers(response):
    path = request.path or ""
    is_static = path.startswith("/static/") or path == "/favicon.ico"
    if is_static:
        # Fingerprint-free static assets: short public cache (override no-store default).
        response.headers["Cache-Control"] = "public, max-age=3600"
    else:
        response.headers.setdefault("Cache-Control", "no-store")
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Referrer-Policy", "no-referrer")
    response.headers.setdefault("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
    # HTML dashboard sets a nonce-based CSP; API responses get a tight default.
    if "Content-Security-Policy" not in response.headers:
        content_type = (response.content_type or "").lower()
        if is_static:
            response.headers["Content-Security-Policy"] = (
                "default-src 'none'; frame-ancestors 'none'; base-uri 'none'"
            )
        elif "text/html" in content_type:
            response.headers["Content-Security-Policy"] = (
                "default-src 'self'; frame-ancestors 'none'; base-uri 'self'"
            )
        else:
            response.headers["Content-Security-Policy"] = (
                "default-src 'none'; frame-ancestors 'none'; base-uri 'none'"
            )
    rule = getattr(request, "url_rule", None)
    route = getattr(rule, "rule", None) or "unmatched"
    METRICS.inc(
        "recon_operator_http_requests_total",
        method=request.method,
        route=route,
        status=str(response.status_code),
    )
    return response


def _check_nmap_available() -> bool:
    executable = shutil.which("nmap")
    if not executable:
        return False
    try:
        result = subprocess.run(
            [executable, "--version"],
            capture_output=True,
            check=False,
            timeout=3,
        )
        return result.returncode == 0
    except (FileNotFoundError, OSError, subprocess.TimeoutExpired):
        return False


def _job_status_gauges() -> Dict[Tuple[str, Tuple[Tuple[str, str], ...]], float]:
    """Live gauges derived from durable state shared by every worker."""
    try:
        jobs = state_store.list_jobs(MAX_SCAN_JOBS)
        scheduled_count = len(state_store.list_scheduled_tasks())
    except Exception as exc:
        log_event(f"Metrics durable-state read failed: {exc}")
        jobs = list(scan_jobs.values())
        scheduled_count = len(scan_tasks)
    queued = 0
    running = 0
    known = 0
    for job in jobs:
        known += 1
        status = job.get("status")
        if status == "queued":
            queued += 1
        elif status == "running":
            running += 1
    return {
        ("recon_operator_jobs_queued", ()): float(queued),
        ("recon_operator_jobs_running", ()): float(running),
        ("recon_operator_jobs_known", ()): float(known),
        ("recon_operator_scheduled_tasks", ()): float(scheduled_count),
    }


def render_metrics_text() -> str:
    """Prometheus text body for the scrape endpoint."""
    return METRICS.render_prometheus(
        extra_gauges=_job_status_gauges(),
        info_labels={"version": VERSION, "product": PRODUCT_NAME},
    )


def _health_payload(*, nmap_available: bool) -> dict:
    gauges = _job_status_gauges()
    return {
        "status": "healthy" if nmap_available else "unhealthy",
        "product": PRODUCT_NAME,
        "version": VERSION,
        "ready": nmap_available,
        "live": True,
        "tasks_count": len(scan_tasks),
        "jobs_queued": int(gauges[("recon_operator_jobs_queued", ())]),
        "jobs_running": int(gauges[("recon_operator_jobs_running", ())]),
        "metrics_path": "/metrics",
        "metrics_auth_required": METRICS_AUTH_REQUIRED,
        "telegram_configured": bot is not None,
        "uptime": str(_utc_now() - start_time),
        "fernet_key_configured": bool(FERNET_KEY),
        "fernet_key_count": FERNET_KEY_COUNT,
        "nmap_available": nmap_available,
        "max_requests_per_window": MAX_REQUESTS_PER_WINDOW,
        "rate_limit_window_seconds": RATE_LIMIT_WINDOW_SECONDS,
        "rate_limit_backend": rate_limit_backend(),
        "rate_limit_include_owner": RATE_LIMIT_INCLUDE_OWNER,
        "trusted_proxy_mode": TRUSTED_PROXY_MODE,
        "trusted_proxies_count": len(TRUSTED_PROXIES),
        "max_concurrent_scans": MAX_CONCURRENT_SCANS,
        "max_scheduled_tasks": MAX_SCHEDULED_TASKS,
        "max_scan_jobs": MAX_SCAN_JOBS,
        "max_target_addresses": MAX_TARGET_ADDRESSES,
        "target_allowlist_enabled": bool(TARGET_ALLOWLIST),
        "target_allowlist_count": len(TARGET_ALLOWLIST),
        "results_max_files": RESULTS_MAX_FILES,
        "results_max_age_days": RESULTS_MAX_AGE_DAYS,
        "legacy_results_shared": LEGACY_RESULTS_SHARED,
        "api_auth_required": API_AUTH_REQUIRED,
        "api_auth_header": API_AUTH_HEADER,
        "api_key_count": len([key for key in API_AUTH_KEYS if not key.get("revoked")]),
        "named_api_keys": len(API_AUTH_KEYS) > 0,
        "worker_id": WORKER_ID,
        "job_lease_seconds": JOB_LEASE_SECONDS,
        "scheduler_leader": _is_scheduler_leader,
        "scheduler_leader_seconds": SCHEDULER_LEADER_SECONDS,
        "state_db": STATE_DB_PATH,
        "discovery_engines": {
            name: bool(path) for name, path in available_discovery_engines().items()
        },
    }


@app.route("/live", methods=["GET"])
async def liveness():
    """Process liveness: event loop is responsive."""
    return jsonify(
        {
            "status": "live",
            "product": PRODUCT_NAME,
            "version": VERSION,
            "uptime": str(_utc_now() - start_time),
        }
    ), 200


@app.route("/ready", methods=["GET"])
async def readiness():
    """Readiness: dependencies required to accept scan work."""
    nmap_available = _check_nmap_available()
    payload = {
        "status": "ready" if nmap_available else "not_ready",
        "product": PRODUCT_NAME,
        "version": VERSION,
        "nmap_available": nmap_available,
        "fernet_key_configured": bool(FERNET_KEY),
        "state_db": STATE_DB_PATH,
    }
    return jsonify(payload), 200 if nmap_available else 503


@app.route("/metrics", methods=["GET"])
async def metrics_endpoint():
    """Prometheus text exposition (no secrets).

    Default is unauthenticated for local scrapers on loopback. Set
    ``METRICS_AUTH_REQUIRED=true`` to require a read-scoped API key (recommended
    when the port is reachable beyond localhost).
    """
    if METRICS_AUTH_REQUIRED:
        auth_error = require_api_auth("read")
        if auth_error:
            return auth_error
    body = render_metrics_text()
    return (
        body,
        200,
        {
            "Content-Type": "text/plain; version=0.0.4; charset=utf-8",
            "Cache-Control": "no-store",
        },
    )


@app.route("/health", methods=["GET"])
async def health_check():
    """Detailed health snapshot (readiness semantics for HTTP status)."""
    _cleanup_finished_tasks()
    nmap_available = _check_nmap_available()
    async with _jobs_lock:
        jobs_count = len(scan_jobs)
        active_jobs = sum(1 for job in scan_jobs.values() if job["status"] in {"queued", "running"})

    payload = _health_payload(nmap_available=nmap_available)
    payload["jobs_count"] = jobs_count
    payload["active_jobs"] = active_jobs
    return jsonify(payload), 200 if nmap_available else 503


def build_openapi_spec() -> dict:
    scan_types = list(SUPPORTED_SCAN_TYPES.keys())
    error_schema = {
        "type": "object",
        "properties": {"error": {"type": "string"}},
        "required": ["error"],
    }
    scan_request = {
        "type": "object",
        "required": ["target"],
        "properties": {
            "target": {"type": "string", "example": "127.0.0.1"},
            "scan_type": {"type": "string", "enum": scan_types, "example": "TCP"},
            "interval": {"type": "number", "example": 30},
            "ports": {"type": "string", "example": "22,80,443"},
            "scripts": {"type": "string", "example": "banner"},
            "discovery": {
                "type": "string",
                "enum": ["auto", "naabu", "rustscan", "none"],
            },
        },
    }
    security = [{"ApiKeyAuth": []}] if API_AUTH_REQUIRED else []
    return {
        "openapi": "3.0.3",
        "info": {
            "title": f"{PRODUCT_NAME} API",
            "version": VERSION,
            "description": (
                "Multi-tool recon control plane: Nmap engine, hybrid discovery, "
                "Kali inventory, review-only recon plans, encrypted results."
            ),
        },
        "servers": [{"url": f"http://{APP_HOST}:{APP_PORT}", "description": "Configured bind"}],
        "components": {
            "securitySchemes": {
                "ApiKeyAuth": {
                    "type": "apiKey",
                    "in": "header",
                    "name": API_AUTH_HEADER,
                }
            },
            "schemas": {
                "Error": error_schema,
                "ScanRequest": scan_request,
                "Job": {
                    "type": "object",
                    "properties": {
                        "job_id": {"type": "string"},
                        "status": {
                            "type": "string",
                            "enum": [
                                "queued",
                                "running",
                                "completed",
                                "failed",
                                "cancelled",
                                "timeout",
                            ],
                        },
                        "target": {"type": "string"},
                        "scan_type": {"type": "string"},
                        "result": {"type": "object"},
                        "result_file": {"type": "string", "nullable": True},
                        "error": {"type": "string", "nullable": True},
                    },
                },
            },
        },
        "security": security,
        "paths": {
            "/auth/whoami": {
                "get": {
                    "summary": "Authenticated API key metadata",
                    "responses": {
                        "200": {"description": "Key id, label, scopes, owner prefix"},
                        "401": {"description": "Missing API token"},
                        "403": {"description": "Invalid or revoked key"},
                    },
                }
            },
            "/audit": {
                "get": {
                    "summary": "List recent audit events (admin)",
                    "parameters": [
                        {
                            "name": "limit",
                            "in": "query",
                            "schema": {"type": "integer", "default": 100, "maximum": 1000},
                        },
                        {
                            "name": "action",
                            "in": "query",
                            "schema": {"type": "string"},
                            "description": "Filter by action (e.g. scan.create)",
                        },
                        {
                            "name": "actor",
                            "in": "query",
                            "schema": {"type": "string"},
                            "description": "Filter by API key id",
                        },
                    ],
                    "responses": {
                        "200": {"description": "Audit event list"},
                        "403": {"description": "Admin scope required"},
                    },
                }
            },
            "/live": {
                "get": {
                    "summary": "Liveness probe",
                    "security": [],
                    "responses": {"200": {"description": "Process is live"}},
                }
            },
            "/ready": {
                "get": {
                    "summary": "Readiness probe",
                    "security": [],
                    "responses": {
                        "200": {"description": "Ready to accept scans"},
                        "503": {"description": "Not ready (for example Nmap missing)"},
                    },
                }
            },
            "/health": {
                "get": {
                    "summary": "Detailed health",
                    "security": [],
                    "responses": {
                        "200": {"description": "Healthy / ready"},
                        "503": {"description": "Unhealthy / not ready"},
                    },
                }
            },
            "/metrics": {
                "get": {
                    "summary": "Prometheus metrics scrape",
                    "security": (
                        [{"ApiKeyAuth": []}] if METRICS_AUTH_REQUIRED and API_AUTH_REQUIRED else []
                    ),
                    "responses": {
                        "200": {"description": "Prometheus text exposition (jobs, scans, rates)"}
                    },
                }
            },
            "/api/docs": {
                "get": {
                    "summary": "Human-readable runtime API docs",
                    "security": [],
                    "responses": {"200": {"description": "JSON docs"}},
                }
            },
            "/openapi.json": {
                "get": {
                    "summary": "OpenAPI 3 document",
                    "security": [],
                    "responses": {"200": {"description": "OpenAPI schema"}},
                }
            },
            "/scan": {
                "post": {
                    "summary": "Queue or run a scan",
                    "parameters": [
                        {
                            "name": "wait",
                            "in": "query",
                            "schema": {"type": "boolean"},
                            "description": "Block until the scan finishes",
                        }
                    ],
                    "requestBody": {
                        "required": True,
                        "content": {
                            "application/json": {
                                "schema": {"$ref": "#/components/schemas/ScanRequest"}
                            }
                        },
                    },
                    "responses": {
                        "200": {"description": "Completed result when wait=1"},
                        "202": {
                            "description": "Job accepted",
                            "content": {
                                "application/json": {"schema": {"$ref": "#/components/schemas/Job"}}
                            },
                        },
                        "400": {
                            "description": "Validation error",
                            "content": {
                                "application/json": {
                                    "schema": {"$ref": "#/components/schemas/Error"}
                                }
                            },
                        },
                        "401": {"description": "Missing API token"},
                        "403": {"description": "Invalid API token"},
                        "429": {"description": "Rate limited"},
                        "504": {"description": "Scan timeout"},
                    },
                }
            },
            "/jobs": {
                "get": {
                    "summary": "List scan jobs",
                    "responses": {"200": {"description": "Job list"}},
                }
            },
            "/jobs/{job_id}": {
                "get": {
                    "summary": "Get job status/result",
                    "parameters": [
                        {
                            "name": "job_id",
                            "in": "path",
                            "required": True,
                            "schema": {"type": "string"},
                        }
                    ],
                    "responses": {
                        "200": {"description": "Job"},
                        "404": {"description": "Not found"},
                    },
                },
                "delete": {
                    "summary": "Cancel a job",
                    "parameters": [
                        {
                            "name": "job_id",
                            "in": "path",
                            "required": True,
                            "schema": {"type": "string"},
                        }
                    ],
                    "responses": {
                        "200": {"description": "Cancelled"},
                        "404": {"description": "Not found"},
                    },
                },
            },
            "/schedule": {
                "post": {
                    "summary": "Schedule a recurring scan",
                    "requestBody": {
                        "required": True,
                        "content": {
                            "application/json": {
                                "schema": {"$ref": "#/components/schemas/ScanRequest"}
                            }
                        },
                    },
                    "responses": {
                        "200": {"description": "Scheduled"},
                        "400": {"description": "Validation error"},
                        "429": {"description": "Limit reached"},
                    },
                }
            },
            "/tasks": {
                "get": {
                    "summary": "List scheduled tasks",
                    "responses": {"200": {"description": "Tasks"}},
                }
            },
            "/tasks/{task_id}": {
                "delete": {
                    "summary": "Cancel scheduled task",
                    "parameters": [
                        {
                            "name": "task_id",
                            "in": "path",
                            "required": True,
                            "schema": {"type": "string"},
                        }
                    ],
                    "responses": {
                        "200": {"description": "Cancelled"},
                        "404": {"description": "Not found"},
                    },
                }
            },
            "/results": {
                "get": {
                    "summary": "List encrypted results",
                    "responses": {"200": {"description": "Result index"}},
                }
            },
            "/results/{result_id}": {
                "get": {
                    "summary": "Decrypt and return a stored result",
                    "parameters": [
                        {
                            "name": "result_id",
                            "in": "path",
                            "required": True,
                            "schema": {"type": "string"},
                        }
                    ],
                    "responses": {
                        "200": {"description": "Decrypted result"},
                        "404": {"description": "Not found"},
                    },
                }
            },
            "/results/import": {
                "post": {
                    "summary": "Import Nmap XML",
                    "responses": {
                        "201": {"description": "Imported"},
                        "400": {"description": "Parse error"},
                        "413": {"description": "Payload too large"},
                    },
                }
            },
            "/results/diff": {
                "post": {
                    "summary": "Diff two scan results",
                    "responses": {"200": {"description": "Diff summary"}},
                }
            },
            "/tools": {
                "get": {
                    "summary": "Kali/pentest tool inventory",
                    "responses": {"200": {"description": "Inventory JSON"}},
                }
            },
            "/tools/ai-context": {
                "get": {
                    "summary": "AI-readable inventory context",
                    "parameters": [
                        {
                            "name": "format",
                            "in": "query",
                            "schema": {"type": "string", "enum": ["jsonl", "markdown", "md"]},
                        }
                    ],
                    "responses": {"200": {"description": "JSONL or Markdown"}},
                }
            },
            "/recon/plan": {
                "post": {
                    "summary": "Build review-only multi-tool recon plan",
                    "responses": {"200": {"description": "Plan JSON/Markdown/JSONL"}},
                }
            },
            "/ai/pack": {
                "get": {
                    "summary": "Budgeted AI recon pack (result_id or job_id)",
                    "parameters": [
                        {
                            "name": "budget",
                            "in": "query",
                            "schema": {
                                "type": "string",
                                "enum": ["s", "m", "l"],
                                "default": "s",
                            },
                            "description": "s=brief (default), m=session, l=fuller pack",
                        },
                        {"name": "result_id", "in": "query", "schema": {"type": "string"}},
                        {"name": "job_id", "in": "query", "schema": {"type": "string"}},
                        {
                            "name": "format",
                            "in": "query",
                            "schema": {
                                "type": "string",
                                "enum": ["jsonl", "json"],
                                "default": "jsonl",
                            },
                        },
                    ],
                    "responses": {
                        "200": {"description": "Compact NDJSON/JSON pack"},
                        "400": {"description": "Missing reference or bad budget"},
                        "404": {"description": "Job/result not found"},
                    },
                },
                "post": {
                    "summary": "Budgeted AI recon pack from posted scan JSON",
                    "requestBody": {
                        "required": True,
                        "content": {
                            "application/json": {
                                "schema": {
                                    "type": "object",
                                    "description": "scan/result with hosts[], or result_id/job_id",
                                }
                            }
                        },
                    },
                    "responses": {"200": {"description": "Compact NDJSON/JSON pack"}},
                },
            },
            "/": {
                "get": {
                    "summary": "Operator dashboard",
                    "security": [],
                    "responses": {"200": {"description": "HTML dashboard"}},
                }
            },
            "/ui": {
                "get": {
                    "summary": "Operator dashboard (alias)",
                    "security": [],
                    "responses": {"200": {"description": "HTML dashboard"}},
                }
            },
        },
    }


@app.route("/openapi.json", methods=["GET"])
async def openapi_json():
    return jsonify(build_openapi_spec()), 200


@app.route("/auth/whoami", methods=["GET"])
async def auth_whoami():
    """Return the authenticated key metadata (never the secret token)."""
    auth_error = require_api_auth()
    if auth_error:
        # Auth-only: any valid non-revoked key may call whoami.
        return auth_error
    return (
        jsonify(
            {
                "key_id": current_api_key_id(),
                "label": getattr(g, "api_key_label", current_api_key_id()),
                "scopes": sorted(current_scopes()),
                "owner_id_prefix": current_owner_id()[:12],
                "product": PRODUCT_NAME,
                "version": VERSION,
            }
        ),
        200,
    )


@app.route("/audit", methods=["GET"])
async def list_audit_events():
    """List recent audit events (admin). Never includes API tokens or Fernet keys."""
    auth_error = require_api_auth("admin")
    if auth_error:
        return auth_error
    if not check_rate_limit():
        return jsonify({"error": "Rate limit exceeded"}), 429

    limit = _parse_optional_limit(request.args.get("limit"), default=100, max_value=1000)
    action = (request.args.get("action") or "").strip() or None
    actor = (request.args.get("actor") or request.args.get("key_id") or "").strip() or None
    try:
        events = await asyncio.to_thread(
            state_store.list_audit_events,
            limit=limit,
            action=action,
            actor_key_id=actor,
        )
    except Exception as exc:
        log_event(f"Failed to list audit events: {exc}")
        return jsonify({"error": "Failed to list audit events"}), 500
    return jsonify({"events": events, "count": len(events)}), 200


@app.route("/api/docs", methods=["GET"])
async def api_docs():
    return jsonify(
        {
            "name": f"{PRODUCT_NAME} API",
            "product": PRODUCT_NAME,
            "version": VERSION,
            "openapi": "/openapi.json",
            "probes": {
                "live": "/live",
                "ready": "/ready",
                "health": "/health",
                "metrics": "/metrics",
            },
            "security": {
                "api_auth_required": API_AUTH_REQUIRED,
                "api_auth_header": API_AUTH_HEADER,
                "api_token_count": len(API_AUTH_TOKENS),
                "api_key_count": len([key for key in API_AUTH_KEYS if not key.get("revoked")]),
                "scopes": sorted(API_KEY_SCOPES),
                "scope_hierarchy": "admin > scan > read (scan includes read)",
                "rate_limit": f"{MAX_REQUESTS_PER_WINDOW} requests per {RATE_LIMIT_WINDOW_SECONDS} seconds",
                "max_concurrent_scans": MAX_CONCURRENT_SCANS,
            },
            "scan_types": list(SUPPORTED_SCAN_TYPES.keys()),
            "endpoints": {
                "GET /auth/whoami": {
                    "description": "Authenticated key id, label, scopes, owner prefix (no secret)",
                    "scope": "any valid key",
                },
                "GET /audit": {
                    "description": "Recent audit events (who scanned what when; no secrets)",
                    "scope": "admin",
                    "query": {
                        "limit": "Max events (default 100, max 1000)",
                        "action": "Optional action filter (scan.create, scan.finish, …)",
                        "actor": "Optional API key id filter",
                    },
                },
                "POST /scan": {
                    "description": "Queue an immediate scan (202 job) or wait with ?wait=1",
                    "scope": "scan",
                    "request": {
                        "target": "IP address, CIDR, or hostname",
                        "scan_type": "TCP|SYN|UDP|OS|Aggressive|Ping|Version|Safe|Vuln|Full|Hybrid|HybridNaabu|HybridRustScan",
                        "ports": "Optional Nmap port expression",
                        "scripts": "Optional extra NSE script names",
                        "discovery": "Optional auto|naabu|rustscan|none",
                    },
                    "query": {"wait": "If true, block until the scan finishes"},
                    "example": {
                        "target": "192.168.1.1",
                        "scan_type": "Version",
                        "ports": "22,80,443",
                    },
                },
                "GET /jobs": {"description": "List recent scan jobs", "scope": "read"},
                "GET /jobs/<job_id>": {
                    "description": "Get scan job status and result",
                    "scope": "read",
                },
                "DELETE /jobs/<job_id>": {
                    "description": "Cancel a queued or running job",
                    "scope": "scan",
                },
                "POST /schedule": {
                    "description": "Schedule a recurring scan",
                    "scope": "scan",
                    "request": {
                        "target": "IP address, range, or hostname",
                        "scan_type": "Scan type",
                        "interval": "Interval in minutes",
                        "ports": "Optional ports",
                        "scripts": "Optional NSE scripts",
                    },
                    "example": {
                        "target": "192.168.1.0/24",
                        "scan_type": "SYN",
                        "interval": 30,
                    },
                },
                "GET /tasks": {"description": "List scheduled tasks", "scope": "read"},
                "DELETE /tasks/<task_id>": {
                    "description": "Cancel a scheduled task",
                    "scope": "scan",
                },
                "GET /results": {"description": "List encrypted result files", "scope": "read"},
                "GET /results/<id>": {
                    "description": "Decrypt and return a stored result",
                    "scope": "read",
                },
                "POST /results/import": {
                    "description": "Import Nmap XML, encrypt, and return parsed result",
                    "scope": "scan",
                    "request": {"xml": "Nmap XML string", "target": "optional label"},
                },
                "POST /results/diff": {
                    "description": "Diff two scan results (objects or stored result ids)",
                    "scope": "read",
                    "request": {"baseline": "result or {id}", "current": "result or {id}"},
                },
                "GET /live": {"description": "Liveness probe (always 200 when process is up)"},
                "GET /ready": {"description": "Readiness probe (503 when Nmap missing)"},
                "GET /health": {"description": "Detailed health snapshot"},
                "GET /metrics": {
                    "description": "Prometheus text metrics (jobs queued/running, finish totals, durations)",
                    "auth": (
                        "read scope"
                        if METRICS_AUTH_REQUIRED and API_AUTH_REQUIRED
                        else "none (scrape; bind loopback or firewall in production)"
                    ),
                },
                "GET /openapi.json": {"description": "OpenAPI 3 schema"},
                "GET /tools": {
                    "description": "Inventory of Kali/pentest tools across recon categories",
                    "scope": "read",
                },
                "GET /tools/ai-context": {
                    "description": "JSONL/Markdown tool context for GPT/Claude",
                    "scope": "read",
                },
                "POST /recon/plan": {
                    "description": "Review-only multi-tool recon plan from parsed scan results",
                    "scope": "read",
                    "request": {"scan": "Parsed scan response or object with hosts[]"},
                    "formats": "json|jsonl|markdown",
                },
                "GET|POST /ai/pack": {
                    "description": (
                        "Token-efficient AI recon pack (default budget=s NDJSON). "
                        "Prefer this over pasting full /results JSON into an LLM."
                    ),
                    "scope": "read",
                    "query": {
                        "budget": "s|m|l (default s; s ≤4KiB/100 lines)",
                        "result_id": "stored encrypted result filename",
                        "job_id": "completed job id",
                        "format": "jsonl|json",
                        "detail": "full|l upgrades to large pack",
                    },
                    "request": {
                        "scan": "parsed scan with hosts[]",
                        "budget": "optional s|m|l",
                        "result_id": "optional",
                        "job_id": "optional",
                    },
                },
            },
        }
    ), 200


async def load_initial_tasks():
    """Persist startup schedules from INITIAL_TASKS (leader loop starts them)."""
    initial_tasks_raw = os.getenv("INITIAL_TASKS", "[]")
    if not initial_tasks_raw.strip():
        return

    try:
        initial_tasks = json.loads(initial_tasks_raw)
        if not isinstance(initial_tasks, list):
            log_event("INITIAL_TASKS must be an array")
            return

        try:
            existing = {row["task_id"] for row in state_store.list_scheduled_tasks()}
        except Exception:
            existing = set()

        for task_config in initial_tasks:
            if len(existing) >= MAX_SCHEDULED_TASKS:
                log_event(
                    f"INITIAL_TASKS: reached limit {MAX_SCHEDULED_TASKS}; remaining tasks skipped"
                )
                break
            if not isinstance(task_config, dict):
                log_event("INITIAL_TASKS contains an invalid element")
                continue

            merged_config, preset_error = apply_preset_to_payload(task_config)
            if preset_error or merged_config is None:
                log_event(f"INITIAL_TASKS: skipped task ({preset_error}). Payload: {task_config}")
                continue
            target, scan_type, interval, ports, scripts, discovery, error = _validate_scan_payload(
                merged_config
            )
            if error:
                log_event(f"INITIAL_TASKS: skipped task ({error}). Payload: {task_config}")
                continue

            if interval is None:
                interval = 30.0

            owner = "local"
            if API_AUTH_REQUIRED:
                eligible_keys = [
                    key
                    for key in API_AUTH_KEYS
                    if not key.get("revoked")
                    and scopes_allow(key.get("effective_scopes") or key.get("scopes"), {"scan"})
                ]
                requested_key_id = str(task_config.get("owner_key_id") or "").strip()
                if requested_key_id:
                    key = next(
                        (row for row in eligible_keys if row.get("id") == requested_key_id),
                        None,
                    )
                elif len(eligible_keys) == 1:
                    key = eligible_keys[0]
                else:
                    key = None
                if key is None:
                    log_event(
                        "INITIAL_TASKS: skipped task because owner_key_id is missing, "
                        "unknown, revoked, or lacks scan scope"
                    )
                    continue
                owner = owner_id_from_token(str(key["token"]))
            task_id = make_task_id(target, scan_type, owner)
            if task_id in existing:
                continue
            try:
                state_store.upsert_scheduled_task(
                    task_id,
                    target,
                    scan_type,
                    interval,
                    ports=ports,
                    scripts=scripts,
                    discovery=discovery,
                    owner_id=owner,
                    created_at=_utc_now_iso(),
                )
                existing.add(task_id)
            except Exception as exc:
                log_event(f"Failed to persist INITIAL_TASKS entry {task_id}: {exc}")
                continue
            log_event(
                f"Registered initial task: {target} ({scan_type}) every {interval} minutes "
                "(awaiting scheduler leader)"
            )
    except json.JSONDecodeError as e:
        log_event(f"INITIAL_TASKS JSON parse error: {e}")
    except (KeyError, TypeError) as e:
        log_event(f"INITIAL_TASKS structure error: {e}")
    except Exception as e:
        log_event(f"INITIAL_TASKS load error: {e}")


async def load_persisted_state():
    """Restore job history from SQLite after restart (schedules start via leader loop)."""
    try:
        jobs = await asyncio.to_thread(state_store.list_jobs, MAX_SCAN_JOBS)
    except Exception as exc:
        log_event(f"Failed to load persisted jobs: {exc}")
        jobs = []

    async with _jobs_lock:
        for job in jobs:
            # Do not rewrite a startup snapshot: another worker may have
            # acquired or renewed the lease after list_jobs returned. The
            # atomic claim loop reclaims expired queued/running work.
            scan_jobs[job["job_id"]] = job
        log_event(f"Loaded {len(scan_jobs)} persisted scan jobs from {STATE_DB_PATH}")

    try:
        schedules = await asyncio.to_thread(state_store.list_scheduled_tasks)
        log_event(
            f"Found {len(schedules)} durable schedules "
            f"(leader loop will start them on this or another worker)"
        )
    except Exception as exc:
        log_event(f"Failed to load persisted scheduled tasks: {exc}")


async def main():
    global _job_worker_task, _scheduler_leader_task
    log_event(f"{PRODUCT_NAME} started (version {VERSION}, worker={WORKER_ID})")
    await send_telegram_message(f"{PRODUCT_NAME} v{VERSION} started")

    await load_persisted_state()
    await load_initial_tasks()

    loop = asyncio.get_running_loop()
    stop_event = asyncio.Event()
    registered_signals = []
    for signame in {"SIGINT", "SIGTERM"}:
        try:
            sig = getattr(signal, signame)
            loop.add_signal_handler(sig, stop_event.set)
            registered_signals.append(sig)
        except (NotImplementedError, AttributeError, ValueError):
            pass

    _job_worker_task = asyncio.create_task(job_claim_loop(stop_event))
    _scheduler_leader_task = asyncio.create_task(scheduler_leader_loop(stop_event))
    shutdown_trigger = stop_event.wait if registered_signals else None
    server_task = asyncio.create_task(
        app.run_task(
            host=APP_HOST,
            port=APP_PORT,
            shutdown_trigger=shutdown_trigger,
        )
    )
    stop_waiter = asyncio.create_task(stop_event.wait()) if registered_signals else None
    try:
        if stop_waiter is None:
            await server_task
        else:
            done, _ = await asyncio.wait(
                {stop_waiter, server_task},
                return_when=asyncio.FIRST_COMPLETED,
            )
            if server_task in done:
                await server_task
    finally:
        for sig in registered_signals:
            loop.remove_signal_handler(sig)
        if stop_waiter is not None and not stop_waiter.done():
            stop_waiter.cancel()

        if stop_event.is_set():
            log_event("Stop signal received")
        stop_event.set()
        await send_telegram_message(f"{PRODUCT_NAME} is shutting down")

        if _job_worker_task is not None:
            _job_worker_task.cancel()
        if _scheduler_leader_task is not None:
            _scheduler_leader_task.cancel()
        try:
            state_store.release_leadership(SCHEDULER_LOCK_NAME, WORKER_ID)
        except Exception:
            pass
        _release_redis_leadership(SCHEDULER_LOCK_NAME)

        _cleanup_finished_tasks()
        scheduled_tasks = list(scan_tasks.values())
        for task in scheduled_tasks:
            task.cancel()

        async with _jobs_lock:
            job_tasks = [
                job["task"]
                for job in scan_jobs.values()
                if job.get("task") is not None and not job["task"].done()
            ]
            for task in job_tasks:
                task.cancel()

        bg_tasks = [task for task in (_job_worker_task, _scheduler_leader_task) if task is not None]
        shutdown_tasks = [*scheduled_tasks, *job_tasks, *bg_tasks, server_task]
        try:
            await asyncio.wait_for(
                asyncio.gather(*shutdown_tasks, return_exceptions=True),
                timeout=30.0,
            )
        except asyncio.TimeoutError:
            log_event("Forced task shutdown after timeout")
            for task in shutdown_tasks:
                if task is not None:
                    task.cancel()
            await asyncio.gather(*shutdown_tasks, return_exceptions=True)

        log_event("Service stopped")
        await send_telegram_message(f"{PRODUCT_NAME} stopped")


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        log_event("KeyboardInterrupt received")
        raise SystemExit(130)
    except Exception as e:
        log_event(f"Critical error: {e}")
        raise SystemExit(1)
