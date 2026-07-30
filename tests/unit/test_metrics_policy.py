"""Metrics exposure policy regression."""

from __future__ import annotations

import os
import unittest

os.environ.setdefault("API_AUTH_REQUIRED", "true")
os.environ.setdefault("API_AUTH_TOKEN", "test-token")
os.environ.setdefault("FERNET_KEY", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")
os.environ.setdefault("SCAN_LOG_PATH", "/tmp/nmap-automator-metrics-policy.log")
os.environ.setdefault("STATE_DB_PATH", "/tmp/recon-operator-metrics-policy.db")

import autonmap


class MetricsPolicyTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.client = autonmap.app.test_client()
        self._orig = autonmap.METRICS_AUTH_REQUIRED

    async def asyncTearDown(self):
        autonmap.METRICS_AUTH_REQUIRED = self._orig

    async def test_metrics_open_by_default(self):
        autonmap.METRICS_AUTH_REQUIRED = False
        response = await self.client.get("/metrics")
        body = await response.get_data(as_text=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn("recon_operator_up", body)

    async def test_metrics_requires_auth_when_enabled(self):
        autonmap.METRICS_AUTH_REQUIRED = True
        denied = await self.client.get("/metrics")
        self.assertEqual(denied.status_code, 401)
        allowed = await self.client.get("/metrics", headers={"X-API-KEY": "test-token"})
        body = await allowed.get_data(as_text=True)
        self.assertEqual(allowed.status_code, 200)
        self.assertIn("recon_operator_up", body)
        self.assertNotIn("test-token", body)


if __name__ == "__main__":
    unittest.main()
