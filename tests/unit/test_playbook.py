"""Playbook chain runner tests."""

from __future__ import annotations

import asyncio
import os
import unittest

os.environ.setdefault("API_AUTH_REQUIRED", "true")
os.environ.setdefault("API_AUTH_TOKEN", "test-token")
os.environ.setdefault("FERNET_KEY", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")
os.environ.setdefault("SCAN_LOG_PATH", "/tmp/nmap-automator-playbook.log")
os.environ.setdefault("STATE_DB_PATH", "/tmp/recon-operator-playbook.db")

import autonmap
from recon_operator.playbook import (
    build_engagement_record,
    list_playbooks,
    resolve_phases,
)


class PlaybookUnitTests(unittest.TestCase):
    def test_resolve_standard_and_custom_phases(self):
        phases, pb_id, err = resolve_phases(playbook="standard")
        self.assertIsNone(err)
        self.assertEqual(pb_id, "standard")
        self.assertEqual(phases, ["discovery", "map", "safe"])
        phases2, pb2, err2 = resolve_phases(phases=["discovery", "map"])
        self.assertIsNone(err2)
        self.assertEqual(pb2, "custom")
        self.assertEqual(phases2, ["discovery", "map"])
        _, _, err3 = resolve_phases(phases=["nope"])
        self.assertIsNotNone(err3)
        books = list_playbooks()
        self.assertTrue(any(b["id"] == "quick" for b in books))

    def test_build_engagement_record(self):
        rec = build_engagement_record(
            target="127.0.0.1",
            phase_ids=["discovery", "map"],
            playbook_id="quick",
            owner_id="owner",
        )
        self.assertEqual(rec["status"], "queued")
        self.assertEqual(len(rec["steps"]), 2)
        self.assertEqual(rec["steps"][0]["phase"], "discovery")
        self.assertEqual(rec["steps"][0]["status"], "pending")


class PlaybookHttpTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        autonmap.scan_jobs.clear()
        autonmap.scan_tasks.clear()
        autonmap.engagements.clear()
        autonmap._engagement_tasks.clear()
        autonmap.rate_limits.clear()
        self.client = autonmap.app.test_client()
        self.headers = {"X-API-KEY": "test-token", "Content-Type": "application/json"}
        self._orig_run = autonmap._run_scan_job

        async def fast_run(job_id, *, already_claimed=False):
            await autonmap._set_job_fields(
                job_id,
                status="running",
                started_at=autonmap._utc_now_iso(),
            )
            await asyncio.sleep(0)
            await autonmap._set_job_fields(
                job_id,
                status="completed",
                finished_at=autonmap._utc_now_iso(),
                result={
                    "target": "127.0.0.1",
                    "hosts": [
                        {
                            "host": "127.0.0.1",
                            "state": "up",
                            "protocols": {"tcp": []},
                        }
                    ],
                },
                result_file=f"fake_{job_id}.json",
                error=None,
            )

        autonmap._run_scan_job = fast_run

    async def asyncTearDown(self):
        for task in list(autonmap._engagement_tasks.values()):
            if task and not task.done():
                task.cancel()
        autonmap._run_scan_job = self._orig_run
        autonmap.engagements.clear()
        autonmap._engagement_tasks.clear()
        autonmap.scan_jobs.clear()

    async def test_playbook_run_completes_phases(self):
        response = await self.client.post(
            "/playbook/run",
            headers=self.headers,
            json={"target": "127.0.0.1", "playbook": "quick"},
        )
        payload = await response.get_json()
        self.assertEqual(response.status_code, 202)
        engagement_id = payload["engagement_id"]
        self.assertEqual(payload["playbook"], "quick")
        self.assertEqual(len(payload["steps"]), 2)

        # Poll until complete.
        final = None
        for _ in range(50):
            status = await self.client.get(
                f"/playbook/{engagement_id}",
                headers={"X-API-KEY": "test-token"},
            )
            final = await status.get_json()
            if final.get("status") in {"completed", "failed", "cancelled"}:
                break
            await asyncio.sleep(0.05)
        self.assertIsNotNone(final)
        self.assertEqual(final["status"], "completed")
        self.assertEqual(final["steps"][0]["phase"], "discovery")
        self.assertEqual(final["steps"][0]["status"], "completed")
        self.assertEqual(final["steps"][1]["phase"], "map")
        self.assertEqual(final["steps"][1]["status"], "completed")
        self.assertTrue(final["steps"][0]["job_id"])
        self.assertTrue(final["steps"][1]["job_id"])

    async def test_playbook_lists_on_presets(self):
        response = await self.client.get("/presets", headers={"X-API-KEY": "test-token"})
        body = await response.get_json()
        self.assertEqual(response.status_code, 200)
        self.assertTrue(any(p.get("id") == "standard" for p in body.get("playbooks") or []))

    async def test_playbook_cancel_and_unknown(self):
        response = await self.client.post(
            "/playbook/run",
            headers=self.headers,
            json={"target": "127.0.0.1", "phases": ["discovery", "map", "safe"]},
        )
        payload = await response.get_json()
        self.assertEqual(response.status_code, 202)
        engagement_id = payload["engagement_id"]
        cancelled = await self.client.delete(
            f"/playbook/{engagement_id}",
            headers={"X-API-KEY": "test-token"},
        )
        body = await cancelled.get_json()
        self.assertEqual(cancelled.status_code, 200)
        self.assertEqual(body.get("status"), "cancelled")

        missing = await self.client.get(
            "/playbook/does-not-exist",
            headers={"X-API-KEY": "test-token"},
        )
        self.assertEqual(missing.status_code, 404)

        bad = await self.client.post(
            "/playbook/run",
            headers=self.headers,
            json={"target": "127.0.0.1", "playbook": "nope"},
        )
        self.assertEqual(bad.status_code, 400)

    async def test_playbook_stops_on_failed_job(self):
        async def fail_run(job_id, *, already_claimed=False):
            await autonmap._set_job_fields(
                job_id,
                status="failed",
                finished_at=autonmap._utc_now_iso(),
                error="forced fail",
            )

        autonmap._run_scan_job = fail_run
        response = await self.client.post(
            "/playbook/run",
            headers=self.headers,
            json={"target": "127.0.0.1", "playbook": "quick"},
        )
        payload = await response.get_json()
        engagement_id = payload["engagement_id"]
        final = None
        for _ in range(40):
            status = await self.client.get(
                f"/playbook/{engagement_id}",
                headers={"X-API-KEY": "test-token"},
            )
            final = await status.get_json()
            if final.get("status") in {"completed", "failed", "cancelled"}:
                break
            await asyncio.sleep(0.05)
        self.assertEqual(final["status"], "failed")
        self.assertEqual(final["steps"][0]["status"], "failed")
        self.assertEqual(final["steps"][1]["status"], "skipped")


if __name__ == "__main__":
    unittest.main()
