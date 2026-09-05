"""Authentication, named API keys, and scope checks.

Source of truth for key loading and request authentication. Mutable key
registries are re-exported on ``recon_operator.server`` / ``autonmap`` so
existing tests that rebind ``autonmap.API_AUTH_KEYS`` keep working: live
lookups prefer the server module binding when present.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import secrets
import sys
from importlib import import_module
from typing import Any

from quart import g, jsonify, request

# Scopes are defined here (auth domain). config does not own them.
API_KEY_SCOPES = frozenset({"read", "scan", "admin"})
API_KEY_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")


def _normalize_key_scopes(raw: Any) -> list[str]:
    if raw is None:
        return ["admin"]
    if isinstance(raw, str):
        values = [part.strip().lower() for part in raw.split(",") if part.strip()]
    elif isinstance(raw, (list, tuple, set)):
        values = [str(part).strip().lower() for part in raw if str(part).strip()]
    else:
        raise RuntimeError("API key scopes must be a list or comma-separated string")
    if not values:
        raise RuntimeError("API key scopes must not be empty")
    unknown = sorted(set(values) - API_KEY_SCOPES)
    if unknown:
        raise RuntimeError(
            f"Unknown API key scopes: {', '.join(unknown)}. "
            f"Allowed: {', '.join(sorted(API_KEY_SCOPES))}"
        )
    # Preserve declared order without duplicates.
    ordered: list[str] = []
    seen = set()
    for scope in values:
        if scope in seen:
            continue
        seen.add(scope)
        ordered.append(scope)
    return ordered


def _expand_scopes(scopes: list[str]) -> frozenset:
    """admin ⊃ scan ⊃ read."""
    have = set(scopes)
    if "admin" in have:
        return frozenset(API_KEY_SCOPES)
    if "scan" in have:
        have.add("read")
    return frozenset(have)


def _public_api_key_view(key: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": key["id"],
        "label": key.get("label") or key["id"],
        "scopes": list(key.get("scopes") or []),
        "created_at": key.get("created_at"),
        "revoked": bool(key.get("revoked")),
    }


def _load_api_auth_keys() -> list[dict[str, Any]]:
    """Load named API keys and legacy raw tokens.

    Supports:
    - API_AUTH_KEYS JSON array of objects:
      ``{"id","label","token","scopes","created_at","revoked"}``
    - API_AUTH_TOKEN / API_AUTH_TOKENS (legacy full-access tokens)
    """
    keys: list[dict[str, Any]] = []
    seen_tokens: set = set()
    seen_ids: set = set()

    def add_key(
        *,
        key_id: str,
        label: str,
        token: str,
        scopes: Any,
        created_at: str | None = None,
        revoked: bool = False,
    ) -> None:
        token = (token or "").strip()
        key_id = (key_id or "").strip()
        if not token:
            raise RuntimeError("API key token must not be empty")
        if token in seen_tokens:
            return
        if not key_id or not API_KEY_ID_RE.fullmatch(key_id):
            raise RuntimeError(
                f"Invalid API key id {key_id!r}. Use 1-64 chars: letters, digits, ._- "
                "(must start alphanumeric)."
            )
        if key_id in seen_ids:
            raise RuntimeError(f"Duplicate API key id: {key_id}")
        normalized_scopes = _normalize_key_scopes(scopes)
        seen_tokens.add(token)
        seen_ids.add(key_id)
        keys.append(
            {
                "id": key_id,
                "label": (label or key_id).strip()[:120] or key_id,
                "token": token,
                "scopes": normalized_scopes,
                "effective_scopes": sorted(_expand_scopes(normalized_scopes)),
                "created_at": created_at,
                "revoked": bool(revoked),
            }
        )

    structured = os.getenv("API_AUTH_KEYS", "").strip()
    if structured:
        try:
            parsed = json.loads(structured)
        except json.JSONDecodeError as exc:
            raise RuntimeError("API_AUTH_KEYS must be a JSON array of key objects") from exc
        if not isinstance(parsed, list):
            raise RuntimeError("API_AUTH_KEYS must be a JSON array of key objects")
        for index, item in enumerate(parsed):
            if not isinstance(item, dict):
                raise RuntimeError(f"API_AUTH_KEYS[{index}] must be an object")
            token = item.get("token") or item.get("secret") or item.get("key")
            if not isinstance(token, str) or not token.strip():
                raise RuntimeError(f"API_AUTH_KEYS[{index}] requires a non-empty token")
            key_id = item.get("id") or item.get("key_id") or f"key-{index + 1}"
            label = item.get("label") or item.get("name") or str(key_id)
            created_at = item.get("created_at")
            if created_at is not None:
                created_at = str(created_at)
            add_key(
                key_id=str(key_id),
                label=str(label),
                token=token,
                scopes=item.get("scopes", ["admin"]),
                created_at=created_at,
                revoked=bool(item.get("revoked", False)),
            )

    # Legacy multi-token list (full admin access).
    multi_raw = os.getenv("API_AUTH_TOKENS", "").strip()
    legacy_tokens: list[str] = []
    if multi_raw:
        if multi_raw.startswith("["):
            try:
                parsed = json.loads(multi_raw)
            except json.JSONDecodeError as exc:
                raise RuntimeError(
                    "API_AUTH_TOKENS must be a JSON array or comma-separated list"
                ) from exc
            if not isinstance(parsed, list):
                raise RuntimeError("API_AUTH_TOKENS JSON value must be an array of strings")
            legacy_tokens.extend(str(item).strip() for item in parsed if str(item).strip())
        else:
            legacy_tokens.extend(part.strip() for part in multi_raw.split(",") if part.strip())

    single = os.getenv("API_AUTH_TOKEN", "").strip()
    if single:
        legacy_tokens.append(single)

    for index, token in enumerate(legacy_tokens):
        if token in seen_tokens:
            continue
        digest = hashlib.sha256(token.encode("utf-8")).hexdigest()[:8]
        add_key(
            key_id=f"legacy-{digest}" if index or len(legacy_tokens) > 1 else "primary",
            label="Primary token"
            if index == 0 and len(legacy_tokens) == 1
            else f"Legacy token {index + 1}",
            token=token,
            scopes=["admin"],
            created_at=None,
            revoked=False,
        )

    return keys


def _load_api_auth_tokens() -> list:
    """Backward-compatible raw token list (active keys only)."""
    return [key["token"] for key in _load_api_auth_keys() if not key.get("revoked")]


API_AUTH_KEYS: list[dict[str, Any]] = []
API_AUTH_TOKENS: list[str] = []
API_AUTH_TOKEN = ""


def reload_api_auth_registry() -> list[dict[str, Any]]:
    """Reload the auth registry from the current process environment.

    ``unittest discover`` imports package directories before test modules. That
    can import this module before a test bootstrap has installed its isolated
    environment. The server calls this function during its own import so the
    registry reflects the environment that actually starts the application.
    """
    global API_AUTH_KEYS, API_AUTH_TOKENS, API_AUTH_TOKEN

    API_AUTH_KEYS = _load_api_auth_keys()
    API_AUTH_TOKENS = [key["token"] for key in API_AUTH_KEYS if not key.get("revoked")]
    # Backward-compatible alias used by docs and older code paths.
    API_AUTH_TOKEN = API_AUTH_TOKENS[0] if API_AUTH_TOKENS else ""
    return API_AUTH_KEYS


reload_api_auth_registry()


def _runtime_server():
    """Return the loaded server module when available (patch surface for tests)."""
    return sys.modules.get("recon_operator.server")


def _live_api_auth_keys() -> list[dict[str, Any]]:
    server = _runtime_server()
    if server is not None and hasattr(server, "API_AUTH_KEYS"):
        return server.API_AUTH_KEYS
    return API_AUTH_KEYS


def _live_api_auth_tokens() -> list[str]:
    server = _runtime_server()
    if server is not None and hasattr(server, "API_AUTH_TOKENS"):
        return server.API_AUTH_TOKENS
    return API_AUTH_TOKENS


def _live_api_auth_required() -> bool:
    server = _runtime_server()
    if server is not None and hasattr(server, "API_AUTH_REQUIRED"):
        return bool(server.API_AUTH_REQUIRED)
    config = import_module("recon_operator.config")

    return bool(config.API_AUTH_REQUIRED)


def _live_api_auth_header() -> str:
    server = _runtime_server()
    if server is not None and hasattr(server, "API_AUTH_HEADER"):
        return str(server.API_AUTH_HEADER)
    config = import_module("recon_operator.config")

    return str(config.API_AUTH_HEADER)


def _resolve_api_key(candidate: str) -> dict[str, Any] | None:
    """Return the matching non-revoked key record for a presented token."""
    if not candidate or not isinstance(candidate, str):
        return None

    # Prefer structured key registry. Use compare_digest directly (it handles
    # different lengths in constant time for str); avoid early len() checks
    # that would leak token length via timing.
    for key in _live_api_auth_keys():
        if key.get("revoked"):
            continue
        allowed = str(key.get("token") or "")
        if not allowed:
            continue
        try:
            if secrets.compare_digest(candidate, allowed):
                return key
        except TypeError:
            continue

    # Fallback for tests that patch API_AUTH_TOKENS only.
    for allowed in _live_api_auth_tokens():
        if not allowed or not isinstance(allowed, str):
            continue
        try:
            matched = secrets.compare_digest(candidate, allowed)
        except TypeError:
            continue
        if matched:
            digest = hashlib.sha256(allowed.encode("utf-8")).hexdigest()[:8]
            return {
                "id": f"legacy-{digest}",
                "label": "Legacy token",
                "token": allowed,
                "scopes": ["admin"],
                "effective_scopes": sorted(API_KEY_SCOPES),
                "created_at": None,
                "revoked": False,
            }
    return None


def _token_is_authorized(candidate: str) -> bool:
    """Multi-token check with compare_digest when lengths match."""
    return _resolve_api_key(candidate) is not None


def scopes_allow(have: Any, required: Any) -> bool:
    """Return True when effective scopes satisfy the required set."""
    have_set = set(have or [])
    need_set = set(required or [])
    if not need_set:
        return True
    if "admin" in have_set:
        return True
    if "scan" in have_set:
        have_set.add("read")
    return need_set.issubset(have_set)


def owner_id_from_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def current_owner_id() -> str:
    try:
        return getattr(g, "owner_id", "local")
    except RuntimeError:
        # Outside a request context (startup tasks, unit helpers).
        return "local"


def current_api_key_id() -> str:
    try:
        return getattr(g, "api_key_id", "local")
    except RuntimeError:
        return "local"


def current_scopes() -> frozenset:
    try:
        scopes = getattr(g, "scopes", None)
        if scopes is not None:
            return frozenset(scopes)
    except RuntimeError:
        pass
    return frozenset(API_KEY_SCOPES) if not _live_api_auth_required() else frozenset()


def require_api_auth(*required_scopes: str):
    """Authenticate the request and optionally enforce least-privilege scopes.

    Scope hierarchy: ``admin`` includes all; ``scan`` includes ``read``.
    """
    if not _live_api_auth_required():
        g.owner_id = "local"
        g.api_key_id = "local"
        g.api_key_label = "local"
        g.scopes = frozenset(API_KEY_SCOPES)
        return None

    header = _live_api_auth_header()
    token = request.headers.get(header)
    if not token:
        return jsonify({"error": f"API token missing ({header})"}), 401
    key = _resolve_api_key(token)
    if key is None:
        return jsonify({"error": "Invalid API token"}), 403
    if key.get("revoked"):
        return jsonify({"error": "API key has been revoked"}), 403

    g.owner_id = owner_id_from_token(token)
    g.api_key_id = key["id"]
    g.api_key_label = key.get("label") or key["id"]
    g.scopes = _expand_scopes(list(key.get("scopes") or []))

    if required_scopes and not scopes_allow(g.scopes, required_scopes):
        return (
            jsonify(
                {
                    "error": "Insufficient API key scope",
                    "required": sorted(set(required_scopes)),
                    "scopes": sorted(g.scopes),
                }
            ),
            403,
        )
    return None
