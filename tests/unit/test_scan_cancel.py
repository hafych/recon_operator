"""Tests for hard cancel of scan process groups and schema bridge."""

from __future__ import annotations

import os
import signal
import subprocess
import sys
import time
import unittest

os.environ.setdefault("API_AUTH_REQUIRED", "true")
os.environ.setdefault("API_AUTH_TOKEN", "test-token")
os.environ.setdefault("FERNET_KEY", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")

from scan_engine import (
    SCHEMA_VERSION,
    _register_process,
    _run_tracked,
    _unregister_process,
    ensure_operator_result,
    kill_active_process,
)


class ProcessCancelTests(unittest.TestCase):
    def test_kill_active_process_stops_sleep(self):
        token = "cancel-token-test"
        # Long sleep in its own process group.
        proc = subprocess.Popen(
            [sys.executable, "-c", "import time; time.sleep(30)"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
        )
        _register_process(token, proc)
        try:
            self.assertIsNone(proc.poll())
            killed = kill_active_process(token)
            self.assertTrue(killed)
            # Process should exit shortly after SIGTERM/SIGKILL.
            deadline = time.time() + 5
            while proc.poll() is None and time.time() < deadline:
                time.sleep(0.05)
            self.assertIsNotNone(proc.poll())
            # Second kill is a no-op.
            self.assertFalse(kill_active_process(token))
        finally:
            if proc.poll() is None:
                try:
                    os.killpg(proc.pid, signal.SIGKILL)
                except OSError:
                    proc.kill()
            _unregister_process(token, proc)

    def test_run_tracked_registers_and_clears(self):
        token = "tracked-token"
        completed = _run_tracked(
            [sys.executable, "-c", "print('ok')"],
            timeout=5,
            process_token=token,
        )
        self.assertEqual(completed.returncode, 0)
        self.assertIn("ok", completed.stdout or "")
        self.assertFalse(kill_active_process(token))


class ProcessCancelExtraTests(unittest.TestCase):
    def test_kill_missing_token_returns_false(self):
        self.assertFalse(kill_active_process(""))
        self.assertFalse(kill_active_process("no-such-token"))

    def test_run_tracked_timeout_terminates(self):
        token = "timeout-token"
        with self.assertRaises(subprocess.TimeoutExpired):
            _run_tracked(
                [sys.executable, "-c", "import time; time.sleep(30)"],
                timeout=0.2,
                process_token=token,
            )
        self.assertFalse(kill_active_process(token))

    def test_ensure_operator_result_empty_hosts(self):
        out = ensure_operator_result({"hosts": []}, target="x", scan_type="Ping")
        self.assertEqual(out["schema"], SCHEMA_VERSION)
        self.assertEqual(out["target"], "x")


class SchemaBridgeTests(unittest.TestCase):
    def test_ensure_operator_result_from_ai_report_shape(self):
        ai_shape = {
            "schema": "ai-nmap-report/v1",
            "hosts": [
                {
                    "id": "10.0.0.1",
                    "status": "up",
                    "hostnames": ["lab"],
                    "ports": [
                        {
                            "port": 22,
                            "protocol": "tcp",
                            "state": "open",
                            "service": {"name": "ssh", "product": "OpenSSH", "version": "8"},
                        }
                    ],
                }
            ],
            "stats": {"hosts": 1, "hosts_up": 1, "open_ports": 1},
        }
        out = ensure_operator_result(ai_shape, target="10.0.0.1", scan_type="Version")
        self.assertEqual(out["schema"], SCHEMA_VERSION)
        self.assertIn("protocols", out["hosts"][0])
        self.assertEqual(out["hosts"][0]["host"], "10.0.0.1")
        self.assertEqual(out["hosts"][0]["protocols"]["tcp"][0]["name"], "ssh")

    def test_ensure_operator_result_passthrough(self):
        op = {
            "schema": SCHEMA_VERSION,
            "hosts": [
                {
                    "host": "10.0.0.2",
                    "state": "up",
                    "protocols": {"tcp": [{"port": 80, "state": "open", "name": "http"}]},
                }
            ],
        }
        out = ensure_operator_result(op)
        self.assertIs(out["hosts"][0]["host"], "10.0.0.2")
        self.assertEqual(out["hosts"][0]["protocols"]["tcp"][0]["port"], 80)


class CancelJobHttpTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        import autonmap

        self.autonmap = autonmap
        autonmap.scan_jobs.clear()
        autonmap.rate_limits.clear()
        self.client = autonmap.app.test_client()

    async def test_cancel_job_reports_process_killed_flag(self):
        autonmap = self.autonmap
        job_id = "job-hard-cancel"
        # Register a long-running process under the job id.
        proc = subprocess.Popen(
            [sys.executable, "-c", "import time; time.sleep(60)"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
        )
        _register_process(job_id, proc)
        autonmap.scan_jobs[job_id] = {
            "job_id": job_id,
            "target": "127.0.0.1",
            "scan_type": "Ping",
            "status": "running",
            "kind": "immediate",
            "owner_id": autonmap.owner_id_from_token("test-token"),
            "created_at": autonmap._utc_now_iso(),
            "task": None,
            "error": None,
            "result": None,
            "result_file": None,
        }
        try:
            response = await self.client.delete(
                f"/jobs/{job_id}",
                headers={"X-API-KEY": "test-token"},
            )
            payload = await response.get_json()
            self.assertEqual(response.status_code, 200)
            self.assertTrue(payload.get("process_killed"))
            self.assertEqual(autonmap.scan_jobs[job_id]["status"], "cancelled")
            deadline = time.time() + 5
            while proc.poll() is None and time.time() < deadline:
                time.sleep(0.05)
            self.assertIsNotNone(proc.poll())
        finally:
            if proc.poll() is None:
                try:
                    os.killpg(proc.pid, signal.SIGKILL)
                except OSError:
                    proc.kill()
            _unregister_process(job_id, proc)


if __name__ == "__main__":
    unittest.main()
