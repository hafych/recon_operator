"""Tests for named recon presets and scan wiring."""

from __future__ import annotations

import os
import unittest

os.environ.setdefault("API_AUTH_REQUIRED", "true")
os.environ.setdefault("API_AUTH_TOKEN", "test-token")
os.environ.setdefault("FERNET_KEY", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")
os.environ.setdefault("SCAN_LOG_PATH", "/tmp/nmap-automator-presets.log")
os.environ.setdefault("STATE_DB_PATH", "/tmp/recon-operator-presets.db")

import autonmap
from recon_operator.presets import (
    PHASE_ORDER,
    apply_preset_to_payload,
    get_preset,
    list_presets,
    next_phase,
)


class PresetUnitTests(unittest.TestCase):
    def test_list_and_apply_map_preset(self):
        presets = list_presets()
        self.assertTrue(any(p["id"] == "discovery" for p in presets))
        self.assertEqual(PHASE_ORDER[0], "discovery")
        merged, err = apply_preset_to_payload({"target": "127.0.0.1", "preset": "map"})
        self.assertIsNone(err)
        assert merged is not None
        self.assertEqual(merged["scan_type"], "Version")
        self.assertTrue(merged["ports"])
        self.assertEqual(merged["preset_phase"], "PB-MAP")
        self.assertEqual(next_phase("map"), "safe")
        self.assertIsNone(get_preset("nope"))

    def test_preset_rejects_incompatible_explicit_scan_type(self):
        merged, err = apply_preset_to_payload(
            {"target": "127.0.0.1", "preset": "map", "scan_type": "Ping"}
        )
        self.assertIsNone(merged)
        self.assertIn("requires scan_type=Version", err)


class PresetHttpTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        autonmap.scan_jobs.clear()
        autonmap.scan_tasks.clear()
        autonmap.rate_limits.clear()
        self.client = autonmap.app.test_client()
        self.headers = {"X-API-KEY": "test-token", "Content-Type": "application/json"}

    async def test_list_presets_and_scan_with_preset(self):
        listed = await self.client.get("/presets", headers={"X-API-KEY": "test-token"})
        body = await listed.get_json()
        self.assertEqual(listed.status_code, 200)
        self.assertIn("discovery", body["phases"])
        self.assertTrue(any(p["id"] == "map" for p in body["presets"]))

        original = autonmap.create_scan_job
        captured = {}

        async def fake_create(target, scan_type, **kwargs):
            captured["target"] = target
            captured["scan_type"] = scan_type
            captured["ports"] = kwargs.get("ports")
            captured["kind"] = kwargs.get("kind")
            return {
                "job_id": "preset-job-1",
                "target": target,
                "scan_type": scan_type,
                "ports": kwargs.get("ports"),
                "status": "queued",
                "kind": kwargs.get("kind"),
            }

        autonmap.create_scan_job = fake_create
        try:
            response = await self.client.post(
                "/scan",
                headers=self.headers,
                json={"target": "127.0.0.1", "preset": "map"},
            )
            payload = await response.get_json()
        finally:
            autonmap.create_scan_job = original

        self.assertEqual(response.status_code, 202)
        self.assertEqual(captured["scan_type"], "Version")
        self.assertTrue(captured["ports"])
        self.assertEqual(payload["preset"], "map")
        self.assertEqual(payload["preset_phase"], "PB-MAP")
        self.assertEqual(payload["next_preset"], "safe")
        self.assertEqual(payload["scan_type"], "Version")


if __name__ == "__main__":
    unittest.main()
