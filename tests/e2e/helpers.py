"""Shared helpers for Playwright e2e suites."""

from __future__ import annotations

import os
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]

DEFAULT_TOKEN = "e2e-browser-token-aaaaaaaa"
DEFAULT_FERNET = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="


def free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def wait_for_live(base_url: str, timeout: float = 30.0) -> None:
    deadline = time.time() + timeout
    last_error = None
    while time.time() < deadline:
        try:
            with urllib.request.urlopen(f"{base_url}/live", timeout=1.5) as response:
                if response.status == 200:
                    return
        except (urllib.error.URLError, TimeoutError, ConnectionError) as exc:
            last_error = exc
            time.sleep(0.2)
    raise TimeoutError(f"Server did not become live at {base_url}/live: {last_error}")


class DashboardServer:
    """Start a local Recon Operator instance for browser tests."""

    def __init__(self, token: str = DEFAULT_TOKEN, fernet: str = DEFAULT_FERNET) -> None:
        self.token = token
        self.fernet = fernet
        self.base_url = ""
        self._tmpdir: tempfile.TemporaryDirectory | None = None
        self._server: subprocess.Popen | None = None

    def start(self) -> str:
        self._tmpdir = tempfile.TemporaryDirectory(prefix="recon-e2e-")
        port = free_port()
        self.base_url = f"http://127.0.0.1:{port}"
        env = os.environ.copy()
        env.update(
            {
                "API_AUTH_REQUIRED": "true",
                "API_AUTH_TOKEN": self.token,
                "FERNET_KEY": self.fernet,
                "APP_HOST": "127.0.0.1",
                "APP_PORT": str(port),
                "STATE_DB_PATH": str(Path(self._tmpdir.name) / "state.db"),
                "RESULTS_DIR": str(Path(self._tmpdir.name) / "results"),
                "SCAN_LOG_PATH": str(Path(self._tmpdir.name) / "scan.log"),
                "TELEGRAM_BOT_TOKEN": "",
                "TELEGRAM_CHAT_ID": "",
                "INITIAL_TASKS": "[]",
            }
        )
        self._server = subprocess.Popen(
            [sys.executable, str(ROOT / "autonmap.py")],
            cwd=str(ROOT),
            env=env,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        try:
            wait_for_live(self.base_url)
        except Exception:
            self.stop()
            raise
        return self.base_url

    def stop(self) -> None:
        if self._server is not None:
            self._server.terminate()
            try:
                self._server.wait(timeout=10)
            except subprocess.TimeoutExpired:
                self._server.kill()
                self._server.wait(timeout=5)
            self._server = None
        if self._tmpdir is not None:
            self._tmpdir.cleanup()
            self._tmpdir = None
