"""Regression tests for auth configuration bootstrap order."""

from __future__ import annotations

import os
import subprocess
import sys
import unittest
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]


class AuthBootstrapTests(unittest.TestCase):
    def test_server_refreshes_registry_after_early_auth_import(self):
        code = """
import os
from recon_operator import auth

assert auth.API_AUTH_TOKENS == []
os.environ["API_AUTH_REQUIRED"] = "true"
os.environ["API_AUTH_TOKEN"] = "late-test-token"
os.environ["FERNET_KEY"] = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
os.environ["STATE_DB_PATH"] = ":memory:"

import autonmap

assert autonmap.API_AUTH_TOKEN == "late-test-token"
assert autonmap.API_AUTH_TOKENS == ["late-test-token"]
"""
        clean_env = {
            key: value
            for key, value in os.environ.items()
            if not key.startswith("API_AUTH_") and key != "FERNET_KEY"
        }
        completed = subprocess.run(
            [sys.executable, "-c", code],
            cwd=str(PROJECT_ROOT),
            env=clean_env,
            capture_output=True,
            text=True,
            timeout=20,
            check=False,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)


if __name__ == "__main__":
    unittest.main()
