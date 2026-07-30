"""Backward-compatible entrypoint for Recon Operator.

Implementation lives in :mod:`recon_operator.server`. This module aliases itself to
that implementation so existing imports and tests (``import autonmap``) keep working.
"""

from __future__ import annotations

import sys

from recon_operator import server as _server

# Make ``import autonmap`` resolve to the package implementation module so
# attribute patches and shared mutable state remain consistent.
sys.modules[__name__] = _server

if __name__ == "__main__":
    import asyncio

    try:
        asyncio.run(_server.main())
    except KeyboardInterrupt:
        _server.log_event("KeyboardInterrupt received")
        raise SystemExit(130)
    except Exception as e:  # pragma: no cover - process entry
        _server.log_event(f"Critical error: {e}")
        raise SystemExit(1)
