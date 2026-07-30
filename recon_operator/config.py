"""Application configuration loaded from the environment.

This module is the source of truth for settings. ``recon_operator.server``
imports and re-exports the same names so ``import autonmap`` patches remain
stable. Runtime objects (``app``, job maps) stay on the server module and are
only exposed here via lazy re-export for package-surface convenience.
"""

from __future__ import annotations

import ipaddress
import json
import os
import uuid
from importlib import import_module
from pathlib import Path
from typing import Any, List, Optional

from dotenv import load_dotenv

load_dotenv()

VERSION = "1.11.2"
SCAN_LOG_PATH = os.getenv("SCAN_LOG_PATH", "/app/logs/scan_log.txt")
RESULTS_DIR = os.getenv("RESULTS_DIR", "encrypted_results")
APP_HOST = os.getenv("APP_HOST", "127.0.0.1")


def _parse_bool_env(name: str, default: bool = False) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    normalized = value.strip().lower()
    if normalized in {"1", "true", "yes", "on", "y"}:
        return True
    if normalized in {"0", "false", "no", "off", "n"}:
        return False
    raise RuntimeError(
        f"{name} must be an explicit boolean "
        f"(true/false, yes/no, on/off, 1/0), got: {value!r}"
    )


# When true, GET /metrics requires a valid API key with read scope (safer non-loopback).
METRICS_AUTH_REQUIRED = _parse_bool_env("METRICS_AUTH_REQUIRED", False)
# When true, log_event emits a JSON line with timestamp/level/message (correlation-friendly).
STRUCTURED_LOGS = _parse_bool_env("STRUCTURED_LOGS", False)


def _parse_int_env(
    name: str,
    default: int,
    min_value: Optional[int] = None,
    max_value: Optional[int] = None,
) -> int:
    value = os.getenv(name)
    if value is None:
        return default
    try:
        parsed = int(value)
    except (ValueError, TypeError):
        raise RuntimeError(f"{name} must be integer, got: {value!r}")

    if min_value is not None and parsed < min_value:
        raise RuntimeError(f"{name} must be >= {min_value}, got: {parsed}")
    if max_value is not None and parsed > max_value:
        raise RuntimeError(f"{name} must be <= {max_value}, got: {parsed}")

    return parsed


API_AUTH_REQUIRED = _parse_bool_env("API_AUTH_REQUIRED", True)
API_AUTH_HEADER = os.getenv("API_AUTH_HEADER", "X-API-KEY").strip() or "X-API-KEY"

RATE_LIMIT_WINDOW_SECONDS = _parse_int_env(
    "RATE_LIMIT_WINDOW_SECONDS", default=60, min_value=1, max_value=3600
)
MAX_REQUESTS_PER_WINDOW = _parse_int_env(
    "MAX_REQUESTS_PER_WINDOW", default=10, min_value=1, max_value=200
)
MAX_RATE_LIMIT_CLIENTS = _parse_int_env(
    "MAX_RATE_LIMIT_CLIENTS", default=10_000, min_value=100, max_value=100_000
)
# Optional shared rate-limit backend for multi-worker deploys (empty = in-process memory).
REDIS_URL = os.getenv("REDIS_URL", "").strip()
REDIS_RATE_LIMIT_PREFIX = (
    os.getenv("REDIS_RATE_LIMIT_PREFIX", "recon_operator:rl:").strip() or "recon_operator:rl:"
)
# Include authenticated owner hash in the bucket so tokens are limited independently of IP.
RATE_LIMIT_INCLUDE_OWNER = _parse_bool_env("RATE_LIMIT_INCLUDE_OWNER", True)

# Trusted reverse-proxy mode (opt-in). When enabled, client IP for rate limits may come
# from X-Forwarded-For / X-Real-IP — but only when the direct peer is in TRUSTED_PROXIES.
TRUSTED_PROXY_MODE = _parse_bool_env("TRUSTED_PROXY_MODE", False)


def _load_trusted_proxies() -> List[str]:
    """Load proxy peer allowlist (IPs or CIDRs). Empty when proxy mode is off."""
    entries: List[str] = []
    raw = os.getenv("TRUSTED_PROXIES", "").strip()
    if raw:
        if raw.startswith("["):
            try:
                parsed = json.loads(raw)
            except json.JSONDecodeError as exc:
                raise RuntimeError(
                    "TRUSTED_PROXIES must be a JSON array or comma-separated list"
                ) from exc
            if not isinstance(parsed, list):
                raise RuntimeError("TRUSTED_PROXIES JSON value must be an array of strings")
            if any(not isinstance(item, str) or not item.strip() for item in parsed):
                raise RuntimeError(
                    "TRUSTED_PROXIES JSON value must contain non-empty strings only"
                )
            entries.extend(item.strip() for item in parsed)
        else:
            entries.extend(part.strip() for part in raw.split(",") if part.strip())

    unique: List[str] = []
    seen = set()
    for entry in entries:
        try:
            if "/" in entry:
                key = str(ipaddress.ip_network(entry, strict=False))
            else:
                key = str(ipaddress.ip_address(entry))
        except ValueError as exc:
            raise RuntimeError(f"Invalid TRUSTED_PROXIES entry: {entry!r}") from exc
        if key in seen:
            continue
        seen.add(key)
        unique.append(key)
        if len(unique) > 1000:
            raise RuntimeError("TRUSTED_PROXIES exceeds 1000 entries")
    return unique


TRUSTED_PROXIES = _load_trusted_proxies()
if TRUSTED_PROXY_MODE and not TRUSTED_PROXIES:
    raise RuntimeError(
        "TRUSTED_PROXY_MODE=true requires a non-empty TRUSTED_PROXIES allowlist "
        "(IPs/CIDRs of reverse proxies that may set X-Forwarded-For / X-Real-IP)."
    )

# Multi-worker job leases (SQLite claim + optional Redis fence).
_configured_worker_id = os.getenv("WORKER_ID", "").strip()
if len(_configured_worker_id) > 64:
    raise RuntimeError("WORKER_ID must be at most 64 characters")
WORKER_ID = _configured_worker_id or f"worker-{uuid.uuid4().hex[:12]}"
JOB_LEASE_SECONDS = _parse_int_env("JOB_LEASE_SECONDS", default=90, min_value=15, max_value=3600)
JOB_CLAIM_POLL_SECONDS = _parse_int_env(
    "JOB_CLAIM_POLL_SECONDS", default=2, min_value=1, max_value=60
)
REDIS_JOB_LEASE_PREFIX = (
    os.getenv("REDIS_JOB_LEASE_PREFIX", "recon_operator:job_lease:").strip()
    or "recon_operator:job_lease:"
)
SCHEDULER_LOCK_NAME = "scheduler"
SCHEDULER_LEADER_SECONDS = _parse_int_env(
    "SCHEDULER_LEADER_SECONDS", default=30, min_value=10, max_value=600
)
SCHEDULER_LEADER_POLL_SECONDS = _parse_int_env(
    "SCHEDULER_LEADER_POLL_SECONDS", default=5, min_value=1, max_value=60
)
REDIS_LEADER_PREFIX = (
    os.getenv("REDIS_LEADER_PREFIX", "recon_operator:leader:").strip() or "recon_operator:leader:"
)

MAX_CONCURRENT_SCANS = _parse_int_env("MAX_CONCURRENT_SCANS", default=2, min_value=1, max_value=20)
MAX_SCHEDULED_TASKS = _parse_int_env(
    "MAX_SCHEDULED_TASKS", default=100, min_value=1, max_value=10_000
)
MAX_SCAN_JOBS = _parse_int_env("MAX_SCAN_JOBS", default=200, min_value=10, max_value=10_000)
SCAN_TIMEOUT_SECONDS = _parse_int_env(
    "SCAN_TIMEOUT_SECONDS", default=1800, min_value=60, max_value=7200
)
APP_PORT = _parse_int_env("APP_PORT", default=5000, min_value=1, max_value=65535)
TOOL_INVENTORY_CACHE_SECONDS = _parse_int_env(
    "TOOL_INVENTORY_CACHE_SECONDS", default=300, min_value=0, max_value=3600
)
MAX_TARGET_ADDRESSES = _parse_int_env(
    "MAX_TARGET_ADDRESSES", default=4096, min_value=1, max_value=1_048_576
)
MAX_REQUEST_BODY_BYTES = _parse_int_env(
    "MAX_REQUEST_BODY_BYTES", default=1_048_576, min_value=1024, max_value=16_777_216
)
MIN_SCHEDULE_INTERVAL_MINUTES = _parse_int_env(
    "MIN_SCHEDULE_INTERVAL_MINUTES", default=1, min_value=1, max_value=1440
)
MAX_SCHEDULE_INTERVAL_MINUTES = _parse_int_env(
    "MAX_SCHEDULE_INTERVAL_MINUTES", default=10_080, min_value=1, max_value=525_600
)
RESULTS_MAX_FILES = _parse_int_env("RESULTS_MAX_FILES", default=500, min_value=1, max_value=100_000)
RESULTS_MAX_AGE_DAYS = _parse_int_env(
    "RESULTS_MAX_AGE_DAYS", default=0, min_value=0, max_value=3650
)
# When false, result files without an owner prefix (pre-1.7 legacy) are hidden
# from all operators. Prefer false for multi-token / semi-public deploys.
LEGACY_RESULTS_SHARED = _parse_bool_env("LEGACY_RESULTS_SHARED", True)
MAX_IMPORT_XML_BYTES = _parse_int_env(
    "MAX_IMPORT_XML_BYTES", default=64 * 1024 * 1024, min_value=1024, max_value=64 * 1024 * 1024
)
STATE_DB_PATH = (
    os.getenv("STATE_DB_PATH", "data/recon_operator.db").strip() or "data/recon_operator.db"
)


def _load_target_allowlist() -> List[str]:
    """Load engagement-scope allowlist from env and optional file.

    Empty list means unrestricted (backward compatible). Entries may be IPs,
    CIDRs, exact hostnames, or ``*.example.com`` wildcard suffixes.
    """
    entries: List[str] = []
    raw = os.getenv("TARGET_ALLOWLIST", "").strip()
    if raw:
        if raw.startswith("["):
            try:
                parsed = json.loads(raw)
            except json.JSONDecodeError as exc:
                raise RuntimeError(
                    "TARGET_ALLOWLIST must be a JSON array or comma-separated list"
                ) from exc
            if not isinstance(parsed, list):
                raise RuntimeError("TARGET_ALLOWLIST JSON value must be an array of strings")
            entries.extend(str(item).strip() for item in parsed if str(item).strip())
        else:
            entries.extend(part.strip() for part in raw.split(",") if part.strip())

    file_path = os.getenv("TARGET_ALLOWLIST_FILE", "").strip()
    if file_path:
        path = Path(file_path)
        if not path.is_file():
            raise RuntimeError(f"TARGET_ALLOWLIST_FILE not found: {file_path}")
        try:
            text = path.read_text(encoding="utf-8")
        except OSError as exc:
            raise RuntimeError(f"Unable to read TARGET_ALLOWLIST_FILE: {exc}") from exc
        for line in text.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            entries.append(line)

    unique: List[str] = []
    seen = set()
    for entry in entries:
        key = entry.lower()
        if key in seen:
            continue
        seen.add(key)
        unique.append(entry)
        if len(unique) > 10_000:
            raise RuntimeError("TARGET_ALLOWLIST exceeds 10000 entries")
    return unique


TARGET_ALLOWLIST = _load_target_allowlist()

if MIN_SCHEDULE_INTERVAL_MINUTES > MAX_SCHEDULE_INTERVAL_MINUTES:
    raise RuntimeError(
        "MIN_SCHEDULE_INTERVAL_MINUTES must not exceed MAX_SCHEDULE_INTERVAL_MINUTES"
    )

HOST_TIMEOUT_SEC = _parse_int_env("NMAP_HOST_TIMEOUT_SEC", default=300, min_value=1, max_value=3600)
NMAP_MAX_RETRIES = _parse_int_env("NMAP_MAX_RETRIES", default=2, min_value=0, max_value=10)

FERNET_KEY = os.getenv("FERNET_KEY", "").strip()
# Comma-separated or JSON array of retired Fernet keys (decrypt-only rotation).
FERNET_PREVIOUS_KEYS_RAW = os.getenv("FERNET_PREVIOUS_KEYS", "").strip()

# Optional append-only audit log path (JSON lines). Empty = SQLite-only via state store.
AUDIT_LOG_PATH = os.getenv("AUDIT_LOG_PATH", "").strip()
AUDIT_LOG_MAX_EVENTS = _parse_int_env(
    "AUDIT_LOG_MAX_EVENTS", default=10_000, min_value=100, max_value=1_000_000
)

# Runtime symbols still owned by server; keep package surface stable.
_SERVER_RUNTIME_EXPORTS = frozenset({"app", "state_store", "scan_jobs", "scan_tasks"})


def __getattr__(name: str) -> Any:
    if name in _SERVER_RUNTIME_EXPORTS:
        _server = import_module("recon_operator.server")

        return getattr(_server, name)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
