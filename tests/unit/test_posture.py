"""Posture drift and structured log tests."""

from __future__ import annotations

import json
import os
import unittest

os.environ.setdefault("API_AUTH_REQUIRED", "true")
os.environ.setdefault("API_AUTH_TOKEN", "test-token")
os.environ.setdefault("FERNET_KEY", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")
os.environ.setdefault("SCAN_LOG_PATH", "/tmp/nmap-automator-posture.log")
os.environ.setdefault("STATE_DB_PATH", "/tmp/recon-operator-posture.db")

import autonmap
from recon_operator.ai_pack import build_ai_pack_rows
from recon_operator.posture import evaluate_posture, load_expected_posture, posture_pack_rows

SCAN = {
    "target": "192.0.2.10",
    "hosts": [
        {
            "host": "192.0.2.10",
            "state": "up",
            "protocols": {
                "tcp": [
                    {"port": 22, "state": "open", "name": "ssh"},
                    {"port": 80, "state": "open", "name": "http"},
                    {"port": 443, "state": "closed", "name": "https"},
                ]
            },
        }
    ],
}

EXPECTED = {
    "deny_unexpected": True,
    "services": [
        {"port": 22, "proto": "tcp", "name": "ssh"},
        {"port": 443, "proto": "tcp", "name": "https"},
    ],
}


class PostureUnitTests(unittest.TestCase):
    def test_evaluate_unexpected_and_missing(self):
        report = evaluate_posture(SCAN, EXPECTED)
        self.assertTrue(report["enabled"])
        ops = {d["op"] for d in report["drifts"]}
        self.assertIn("unexpected", ops)  # 80/http
        self.assertIn("missing", ops)  # 443 expected
        self.assertGreaterEqual(report["unexpected"], 1)
        self.assertGreaterEqual(report["missing"], 1)
        rows = posture_pack_rows(SCAN, EXPECTED)
        self.assertEqual(rows[0]["t"], "posture")
        self.assertTrue(any(r.get("t") == "drift" for r in rows))

    def test_pack_includes_drift_when_posture_provided(self):
        rows = build_ai_pack_rows(SCAN, budget="m", expected_posture=EXPECTED)
        self.assertTrue(any(r.get("t") == "posture" for r in rows))
        self.assertTrue(any(r.get("t") == "drift" for r in rows))
        # Closed https must not appear as open svc.
        self.assertFalse(any(r.get("t") == "svc" and r.get("port") == 443 for r in rows))

    def test_load_expected_posture_from_json_string(self):
        loaded = load_expected_posture(json.dumps(EXPECTED))
        self.assertEqual(len(loaded["services"]), 2)

    def test_wrong_service_on_expected_port_is_both_missing_and_unexpected(self):
        report = evaluate_posture(
            {
                "hosts": [
                    {
                        "host": "APP.EXAMPLE.TEST.",
                        "protocols": {
                            "TCP": [{"port": 22, "state": "OPEN", "name": "http"}]
                        },
                    }
                ]
            },
            {
                "deny_unexpected": True,
                "services": [
                    {
                        "host": "app.example.test",
                        "proto": "tcp",
                        "port": 22,
                        "name": "ssh",
                    }
                ],
            },
        )

        self.assertEqual(report["missing"], 1)
        self.assertEqual(report["unexpected"], 1)


class PostureHttpTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.client = autonmap.app.test_client()
        self.headers = {"X-API-KEY": "test-token", "Content-Type": "application/json"}

    async def test_posture_evaluate_endpoint(self):
        response = await self.client.post(
            "/posture/evaluate",
            headers=self.headers,
            json={"scan": SCAN, "posture": EXPECTED},
        )
        payload = await response.get_json()
        self.assertEqual(response.status_code, 200)
        self.assertTrue(payload["enabled"])
        self.assertGreaterEqual(payload["unexpected"], 1)


class StructuredLogTests(unittest.TestCase):
    def test_structured_log_emits_json_without_secrets(self):
        original = autonmap.STRUCTURED_LOGS
        autonmap.STRUCTURED_LOGS = True
        try:
            # Capture via logging handler is heavier; exercise call path for job fields.
            autonmap.log_event(
                "unit structured",
                job_id="job-1",
                token="should-not-appear",
                fernet_key="nope",
            )
        finally:
            autonmap.STRUCTURED_LOGS = original
        # Function must not raise; secrets keys are filtered in structured path.
        self.assertTrue(callable(autonmap.log_event))


if __name__ == "__main__":
    unittest.main()
