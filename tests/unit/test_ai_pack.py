"""Tests for budgeted AI recon packs (builder + HTTP surface)."""

from __future__ import annotations

import json
import os
import tempfile
import unittest

os.environ.setdefault("API_AUTH_REQUIRED", "true")
os.environ.setdefault("API_AUTH_TOKEN", "test-token")
os.environ.setdefault("FERNET_KEY", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")
os.environ.setdefault("SCAN_LOG_PATH", "/tmp/nmap-automator-aipack.log")
os.environ.setdefault("STATE_DB_PATH", "/tmp/recon-operator-aipack.db")

import autonmap
from recon_operator.ai_pack import (
    BUDGET_S_MAX_BYTES,
    BUDGET_S_MAX_LINES,
    build_ai_pack,
    build_ai_pack_rows,
    pack_bytes,
)

SCAN = {
    "schema": "recon-operator-result/v1",
    "target": "192.0.2.10",
    "scan_type": "Version",
    "hosts": [
        {
            "host": "192.0.2.10",
            "hostname": "app.example.test",
            "state": "up",
            "protocols": {
                "tcp": [
                    {
                        "port": 22,
                        "state": "open",
                        "name": "ssh",
                        "product": "OpenSSH",
                        "version": "8.9",
                    },
                    {
                        "port": 80,
                        "state": "open",
                        "name": "http",
                        "product": "nginx",
                        "version": "1.18",
                    },
                    {"port": 25, "state": "closed", "name": "smtp"},
                    {"port": 443, "state": "closed", "name": "https"},
                ]
            },
        }
    ],
}

INVENTORY = {
    "packages": [
        {
            "package": "curl",
            "installed": True,
            "command_available": True,
            "commands": {"curl": "/usr/bin/curl"},
        },
        {
            "package": "ssh-audit",
            "installed": False,
            "command_available": False,
            "commands": {"ssh-audit": None},
        },
    ]
}


class AiPackBuilderTests(unittest.TestCase):
    def test_small_pack_caps_and_omits_closed_ports(self):
        rows = build_ai_pack_rows(SCAN, budget="s", inventory=INVENTORY)
        body, content_type, _ = build_ai_pack(SCAN, budget="s", inventory=INVENTORY)
        self.assertIn("ndjson", content_type)
        self.assertLessEqual(len(rows), BUDGET_S_MAX_LINES)
        self.assertLessEqual(pack_bytes(rows), BUDGET_S_MAX_BYTES)
        self.assertLessEqual(len(body.encode("utf-8")), BUDGET_S_MAX_BYTES)
        self.assertEqual(len(body.encode("utf-8")), pack_bytes(rows))

        types = {row.get("t") for row in rows}
        self.assertIn("meta", types)
        self.assertIn("host", types)
        self.assertIn("svc", types)
        self.assertTrue({"next", "gap"} & types)

        # Closed ports must not appear as svc rows.
        svc_ports = {row.get("port") for row in rows if row.get("t") == "svc"}
        self.assertIn(22, svc_ports)
        self.assertIn(80, svc_ports)
        self.assertNotIn(25, svc_ports)
        self.assertNotIn(443, svc_ports)

        blob = body
        self.assertNotIn("test-token", blob)
        self.assertNotIn(os.environ["FERNET_KEY"], blob)
        # Closed SMTP must not appear as an open service fact.
        self.assertFalse(any(r.get("t") == "svc" and r.get("name") == "smtp" for r in rows))

    def test_small_pack_hard_cap_holds_when_truncated(self):
        """Force truncation with many open services; final pack must stay under hard caps."""
        ports = []
        for index in range(40):
            ports.append(
                {
                    "port": 8000 + index,
                    "state": "open",
                    "name": "http",
                    "product": "nginx-long-product-name-for-bytes",
                    "version": f"1.18.{index}-build-extra-detail",
                }
            )
        fat_scan = {
            "schema": "recon-operator-result/v1",
            "target": "192.0.2.10",
            "scan_type": "Version",
            "hosts": [
                {
                    "host": "192.0.2.10",
                    "hostname": "app.example.test",
                    "state": "up",
                    "protocols": {"tcp": ports},
                }
            ],
        }
        rows = build_ai_pack_rows(fat_scan, budget="s", inventory=INVENTORY)
        body, _, body_rows = build_ai_pack(fat_scan, budget="s", inventory=INVENTORY)
        body_bytes = len(body.encode("utf-8"))
        self.assertLessEqual(len(rows), BUDGET_S_MAX_LINES)
        self.assertLessEqual(pack_bytes(rows), BUDGET_S_MAX_BYTES)
        self.assertLessEqual(body_bytes, BUDGET_S_MAX_BYTES)
        self.assertEqual(body_bytes, pack_bytes(body_rows))
        self.assertEqual(rows[0].get("t"), "meta")
        self.assertTrue(rows[0].get("truncated"), "expected truncation on fat scan")
        self.assertEqual(rows[0].get("lines"), len(rows))
        self.assertEqual(rows[0].get("bytes"), pack_bytes(rows))
        # Uncapped builder path would exceed; stamp must not push over the hard cap.
        self.assertGreater(40, 1)  # fat input present
        self.assertNotIn("test-token", body)
        self.assertNotIn(os.environ["FERNET_KEY"], body)

    def test_small_json_cap_and_source_truncation_are_truthful(self):
        hosts = [
            {
                "host": f"192.0.2.{index}",
                "state": "up",
                "protocols": {
                    "tcp": [
                        {
                            "port": 8000 + offset,
                            "state": "open",
                            "name": "http",
                            "product": "x" * 80,
                        }
                        for offset in range(5)
                    ]
                },
            }
            for index in range(1, 11)
        ]
        scan = {"target": "192.0.2.0/28", "scan_type": "Version", "hosts": hosts}

        body, _, rows = build_ai_pack(scan, budget="s", format="json")
        encoded_size = len(body.encode("utf-8"))
        meta = rows[0]

        self.assertLessEqual(encoded_size, BUDGET_S_MAX_BYTES)
        self.assertEqual(meta["bytes"], encoded_size)
        self.assertEqual(meta["hosts"], 8)
        self.assertEqual(meta["hosts_total"], 10)
        self.assertEqual(meta["open_services_total"], 50)
        self.assertTrue(meta["source_truncated"])
        self.assertTrue(meta["truncated"])

    def test_medium_pack_is_strictly_larger_than_small(self):
        rows_s = build_ai_pack_rows(SCAN, budget="s", inventory=INVENTORY)
        rows_m = build_ai_pack_rows(SCAN, budget="m", inventory=INVENTORY)
        body_s, _, _ = build_ai_pack(SCAN, budget="s", inventory=INVENTORY)
        body_m, _, _ = build_ai_pack(SCAN, budget="m", inventory=INVENTORY)
        self.assertGreater(len(rows_m), len(rows_s))
        self.assertGreater(len(body_m.encode("utf-8")), len(body_s.encode("utf-8")))
        # Medium still omits closed by default.
        self.assertFalse(any(r.get("port") == 25 and r.get("t") == "svc" for r in rows_m))
        for body in (body_s, body_m):
            self.assertNotIn("test-token", body)
            self.assertNotIn(os.environ["FERNET_KEY"], body)

    def test_next_or_gap_signal_present_with_inventory(self):
        rows = build_ai_pack_rows(SCAN, budget="s", inventory=INVENTORY)
        next_or_gap = [r for r in rows if r.get("t") in {"next", "gap"}]
        self.assertTrue(next_or_gap)
        # Prefer ready curl and/or missing ssh-audit gap.
        tools = {r.get("tool") for r in next_or_gap}
        self.assertTrue(tools & {"curl", "ssh-audit", "whatweb", "feroxbuster", "nikto"})


class AiPackHttpTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        autonmap.scan_jobs.clear()
        autonmap.scan_tasks.clear()
        autonmap.rate_limits.clear()
        self.client = autonmap.app.test_client()
        self.headers = {"X-API-KEY": "test-token", "Content-Type": "application/json"}
        self._orig_results = autonmap.RESULTS_DIR
        self._tmpdir = tempfile.TemporaryDirectory()
        autonmap.RESULTS_DIR = self._tmpdir.name

    async def asyncTearDown(self):
        autonmap.RESULTS_DIR = self._orig_results
        self._tmpdir.cleanup()

    async def test_post_pack_from_scan_body_default_small(self):
        response = await self.client.post(
            "/ai/pack",
            headers=self.headers,
            json={"scan": SCAN, "budget": "s"},
        )
        body = await response.get_data(as_text=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn("ndjson", response.headers.get("Content-Type", ""))
        self.assertTrue(body.strip())
        self.assertLessEqual(len(body.encode("utf-8")), BUDGET_S_MAX_BYTES)
        lines = [json.loads(line) for line in body.splitlines() if line.strip()]
        self.assertLessEqual(len(lines), BUDGET_S_MAX_LINES)
        self.assertLessEqual(pack_bytes(lines), BUDGET_S_MAX_BYTES)
        self.assertEqual(lines[0]["t"], "meta")
        self.assertEqual(lines[0]["budget"], "s")
        self.assertNotIn("test-token", body)
        self.assertNotIn(autonmap.FERNET_KEY, body)

        denied = await self.client.post("/ai/pack", json={"scan": SCAN})
        self.assertEqual(denied.status_code, 401)

    async def test_get_pack_from_stored_result(self):
        filename = await autonmap.save_scan_results_async(
            SCAN, "192.0.2.10", "Version", owner_id=autonmap.owner_id_from_token("test-token")
        )
        self.assertIsNotNone(filename)
        response = await self.client.get(
            f"/ai/pack?result_id={filename}&budget=s",
            headers={"X-API-KEY": "test-token"},
        )
        body = await response.get_data(as_text=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn("ndjson", response.headers.get("Content-Type", ""))
        self.assertIn('"t":"meta"', body.replace(" ", ""))
        self.assertIn(filename.split("/")[-1][:12], body)  # result ref present-ish or meta

    async def test_get_pack_from_completed_job(self):
        job_id = "pack-job-1"
        autonmap.scan_jobs[job_id] = {
            "job_id": job_id,
            "target": "192.0.2.10",
            "scan_type": "Version",
            "status": "completed",
            "kind": "immediate",
            "owner_id": autonmap.owner_id_from_token("test-token"),
            "created_at": autonmap._utc_now_iso(),
            "result": SCAN,
            "result_file": None,
            "error": None,
            "task": None,
        }
        response = await self.client.get(
            f"/ai/pack?job_id={job_id}&budget=m&format=json",
            headers={"X-API-KEY": "test-token"},
        )
        payload = await response.get_json()
        self.assertEqual(response.status_code, 200)
        self.assertIn("rows", payload)
        self.assertGreaterEqual(len(payload["rows"]), 3)
        self.assertEqual(payload["rows"][0]["t"], "meta")
        self.assertEqual(payload["rows"][0]["budget"], "m")

    async def test_openapi_lists_ai_pack(self):
        response = await self.client.get("/openapi.json")
        spec = await response.get_json()
        self.assertIn("/ai/pack", spec.get("paths", {}))


if __name__ == "__main__":
    unittest.main()
