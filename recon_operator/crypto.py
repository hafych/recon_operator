"""Fernet helpers with multi-key rotation support.

Primary key (``FERNET_KEY``) encrypts new data. Previous keys
(``FERNET_PREVIOUS_KEYS``) can still decrypt older results.
"""

from __future__ import annotations

import json
import os
from collections.abc import Sequence

from cryptography.fernet import Fernet, MultiFernet


def _parse_key_list(raw: str) -> list[str]:
    raw = (raw or "").strip()
    if not raw:
        return []
    if raw.startswith("["):
        try:
            parsed = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise RuntimeError(
                "FERNET_PREVIOUS_KEYS must be a JSON array or comma-separated list"
            ) from exc
        if not isinstance(parsed, list):
            raise RuntimeError("FERNET_PREVIOUS_KEYS JSON value must be an array of strings")
        return [str(item).strip() for item in parsed if str(item).strip()]
    return [part.strip() for part in raw.split(",") if part.strip()]


def load_fernet_key_material() -> list[str]:
    """Load primary + previous Fernet keys from the environment.

    Returns a non-empty list with the primary key first. Raises RuntimeError
    when the primary key is missing or any key is invalid Fernet material.
    """
    primary = os.getenv("FERNET_KEY", "").strip()
    if not primary:
        raise RuntimeError(
            "FERNET_KEY is not set. Provide it in .env or the environment. "
            "Without it stored results cannot be decrypted."
        )
    previous = _parse_key_list(os.getenv("FERNET_PREVIOUS_KEYS", ""))
    # Deduplicate while preserving order (primary first).
    ordered: list[str] = []
    seen = set()
    for key in [primary, *previous]:
        if key in seen:
            continue
        seen.add(key)
        ordered.append(key)
    # Validate each key early.
    for index, key in enumerate(ordered):
        try:
            Fernet(key.encode() if isinstance(key, str) else key)
        except Exception as exc:
            label = "FERNET_KEY" if index == 0 else f"FERNET_PREVIOUS_KEYS[{index - 1}]"
            raise RuntimeError(
                f"Invalid {label}. Check the format (must be a valid Fernet key)."
            ) from exc
    return ordered


def build_fernet_cipher(keys: Sequence[str] | None = None) -> Fernet | MultiFernet:
    """Build a cipher that encrypts with the first key and decrypts with all.

    Single-key deployments return a plain ``Fernet`` instance so existing
    tests that patch or inspect ``cipher`` keep working. Multi-key deployments
    return ``MultiFernet``.
    """
    material = list(keys) if keys is not None else load_fernet_key_material()
    if not material:
        raise RuntimeError("At least one Fernet key is required")
    instances = [Fernet(key.encode() if isinstance(key, str) else key) for key in material]
    if len(instances) == 1:
        return instances[0]
    return MultiFernet(instances)
