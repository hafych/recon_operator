from __future__ import annotations

import asyncio
import os
import tempfile
import threading
import unittest
from pathlib import Path
from unittest import mock

os.environ.setdefault("API_AUTH_REQUIRED", "true")
os.environ.setdefault("API_AUTH_TOKEN", "test-token")
os.environ.setdefault("FERNET_KEY", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")
os.environ.setdefault("SCAN_LOG_PATH", "/tmp/recon-operator-logic-regressions.log")
os.environ.setdefault("STATE_DB_PATH", "/tmp/recon-operator-logic-regressions.db")

import autonmap
import kali_ai_scan
import scan_engine
from recon_operator.ai_pack import build_ai_pack_rows
from recon_operator.posture import evaluate_posture
from state_store import StateStore


class ScanAndPackLogicRegressionTests(unittest.TestCase):
    def test_rustscan_parser_does_not_treat_ip_octets_as_ports(self):
        output = "127.0.0.1 -> [22,443]\nOpen 10.0.0.1:8080\nOpen [2001:db8::1]:8443\n"

        self.assertEqual(scan_engine._parse_rustscan_output(output), [22, 443, 8080, 8443])

    def test_posture_summary_counts_all_drift_when_rows_are_capped(self):
        scan = {
            "hosts": [
                {
                    "host": "192.0.2.1",
                    "protocols": {
                        "tcp": [
                            {"port": port, "state": "open", "name": "unknown"}
                            for port in range(1000, 1005)
                        ]
                    },
                }
            ]
        }

        report = evaluate_posture(
            scan,
            {"deny_unexpected": True, "services": []},
            max_rows=2,
        )

        self.assertEqual(report["unexpected"], 5)
        self.assertEqual(len(report["drifts"]), 2)

    def test_posture_protocol_matching_is_case_insensitive(self):
        scan = {
            "hosts": [
                {
                    "host": "192.0.2.1",
                    "protocols": {
                        "TCP": [{"port": 443, "state": "open", "name": "https"}],
                    },
                }
            ]
        }

        report = evaluate_posture(
            scan,
            {
                "deny_unexpected": True,
                "services": [{"port": 443, "proto": "tcp", "name": "https"}],
            },
        )

        self.assertEqual(report["missing"], 0)
        self.assertEqual(report["unexpected"], 0)

    def test_large_pack_can_include_closed_services(self):
        scan = {
            "target": "192.0.2.1",
            "scan_type": "Version",
            "hosts": [
                {
                    "host": "192.0.2.1",
                    "state": "up",
                    "protocols": {
                        "tcp": [
                            {"port": 22, "state": "open", "name": "ssh"},
                            {"port": 25, "state": "closed", "name": "smtp"},
                        ]
                    },
                }
            ],
        }

        rows = build_ai_pack_rows(scan, budget="l", include_closed=True)
        services = [row for row in rows if row.get("t") == "svc"]

        self.assertTrue(rows[0]["include_closed"])
        self.assertEqual(rows[0]["closed_services"], 1)
        self.assertTrue(
            any(row.get("port") == 25 and row.get("state") == "closed" for row in services)
        )

    def test_pack_keeps_hosts_that_have_no_open_services(self):
        scan = {
            "target": "192.0.2.1",
            "scan_type": "Ping",
            "hosts": [
                {
                    "host": "192.0.2.1",
                    "hostname": "host.example.test",
                    "state": "up",
                    "protocols": {},
                }
            ],
        }

        rows = build_ai_pack_rows(scan, budget="s")

        self.assertEqual(rows[0]["hosts"], 1)
        self.assertTrue(
            any(
                row.get("t") == "host"
                and row.get("ip") == "192.0.2.1"
                and row.get("status") == "up"
                for row in rows
            )
        )


class PersistenceLogicRegressionTests(unittest.TestCase):
    def test_pruning_never_deletes_queued_or_running_jobs(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = StateStore(str(Path(tmp) / "state.db"))
            for job_id, status, created_at in (
                ("running-old", "running", "t0"),
                ("queued", "queued", "t1"),
                ("done", "completed", "t2"),
            ):
                store.upsert_job(
                    {
                        "job_id": job_id,
                        "target": "127.0.0.1",
                        "scan_type": "Ping",
                        "status": status,
                        "kind": "immediate",
                        "created_at": created_at,
                    }
                )

            deleted = store.prune_jobs(2)
            remaining = {job["job_id"] for job in store.list_jobs()}

        self.assertEqual(deleted, 1)
        self.assertEqual(remaining, {"running-old", "queued"})

    def test_parsing_into_arbitrary_output_does_not_prune_sibling_directories(self):
        xml = '<nmaprun scanner="nmap"><runstats/></nmaprun>'
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            victim = root / "unrelated-project"
            victim.mkdir()
            (victim / "keep.txt").write_text("keep", encoding="utf-8")
            os.utime(victim, (1, 1))
            source = root / "source.xml"
            source.write_text(xml, encoding="utf-8")

            with (
                mock.patch.object(kali_ai_scan, "AI_REPORTS_MAX_DIRS", 1),
                mock.patch.object(kali_ai_scan, "nmap_version", return_value={}),
                mock.patch.object(kali_ai_scan, "package_status", return_value={}),
                mock.patch.object(kali_ai_scan, "apt_policy", return_value={}),
            ):
                kali_ai_scan.create_artifacts(source, root / "parsed-report")

            self.assertTrue((victim / "keep.txt").is_file())

    def test_managed_retention_ignores_unrelated_directories(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            unrelated = root / "unrelated-project"
            unrelated.mkdir()
            incomplete = root / "20260730_110000_000001_active"
            incomplete.mkdir()
            older = root / "20260730_120000_000001_target"
            newer = root / "20260730_120000_000002_target"
            older.mkdir()
            newer.mkdir()
            (older / "manifest.json").write_text("{}", encoding="utf-8")
            (newer / "manifest.json").write_text("{}", encoding="utf-8")
            os.utime(older, (1, 1))
            os.utime(newer, (2, 2))

            with mock.patch.object(kali_ai_scan, "AI_REPORTS_MAX_DIRS", 1):
                summary = kali_ai_scan.apply_report_retention(root, managed_only=True)

            self.assertTrue(unrelated.is_dir())
            self.assertTrue(incomplete.is_dir())
            self.assertFalse(older.exists())
            self.assertTrue(newer.is_dir())
            self.assertEqual(summary, {"deleted": 1, "remaining": 1})

    def test_scan_runs_in_same_second_use_distinct_directories(self):
        moments = [
            kali_ai_scan.dt.datetime(2026, 7, 30, 12, 0, 0, 1),
            kali_ai_scan.dt.datetime(2026, 7, 30, 12, 0, 0, 2),
        ]
        with tempfile.TemporaryDirectory() as tmp:
            args = kali_ai_scan.build_parser().parse_args(["run", "127.0.0.1", "--out", tmp])
            artifacts = mock.Mock(
                return_value={
                    "artifacts": {},
                    "stats": {},
                }
            )
            with (
                mock.patch.object(kali_ai_scan.shutil, "which", return_value="/usr/bin/nmap"),
                mock.patch.object(kali_ai_scan.dt, "datetime") as clock,
                mock.patch.object(
                    kali_ai_scan.subprocess,
                    "run",
                    return_value=mock.Mock(returncode=0),
                ),
                mock.patch.object(kali_ai_scan, "create_artifacts", artifacts),
                mock.patch.object(kali_ai_scan, "apply_report_retention"),
            ):
                clock.now.side_effect = moments
                self.assertEqual(kali_ai_scan.run_scan(args), 0)
                self.assertEqual(kali_ai_scan.run_scan(args), 0)

            output_dirs = [call.args[1] for call in artifacts.call_args_list]

        self.assertNotEqual(output_dirs[0], output_dirs[1])


class ServerLogicRegressionTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        self.original_store = autonmap.state_store
        self.original_results_dir = autonmap.RESULTS_DIR
        self.original_scan_runner = autonmap._run_scan_job
        autonmap.state_store = StateStore(str(Path(self.tempdir.name) / "state.db"))
        autonmap.RESULTS_DIR = str(Path(self.tempdir.name) / "results")
        autonmap.scan_jobs.clear()
        autonmap.scan_tasks.clear()
        autonmap.engagements.clear()
        autonmap._engagement_tasks.clear()
        autonmap.rate_limits.clear()
        self.client = autonmap.app.test_client()
        self.headers = {
            "X-API-KEY": "test-token",
            "Content-Type": "application/json",
        }

    async def asyncTearDown(self):
        tasks = [
            task
            for task in [
                *autonmap._engagement_tasks.values(),
                *(job.get("task") for job in autonmap.scan_jobs.values()),
            ]
            if task is not None and not task.done()
        ]
        for task in tasks:
            task.cancel()
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)
        autonmap._run_scan_job = self.original_scan_runner
        autonmap.state_store = self.original_store
        autonmap.RESULTS_DIR = self.original_results_dir
        autonmap.scan_jobs.clear()
        autonmap.scan_tasks.clear()
        autonmap.engagements.clear()
        autonmap._engagement_tasks.clear()
        self.tempdir.cleanup()

    async def test_result_filename_cannot_escape_results_directory(self):
        filename = await autonmap.save_scan_results_async(
            {"hosts": []},
            "target",
            "/../../escaped",
            owner_id="local",
        )

        self.assertNotIn("/", filename)
        self.assertTrue((Path(autonmap.RESULTS_DIR) / filename).is_file())
        self.assertEqual(
            [
                path
                for path in Path(self.tempdir.name).iterdir()
                if path.is_file() and path.name != "state.db"
            ],
            [],
        )

    async def test_jobs_list_includes_durable_jobs_owned_by_another_worker(self):
        owner = autonmap.owner_id_from_token("test-token")
        autonmap.state_store.upsert_job(
            {
                "job_id": "remote-job",
                "target": "127.0.0.1",
                "scan_type": "Ping",
                "status": "running",
                "kind": "immediate",
                "owner_id": owner,
                "created_at": "2026-01-01T00:00:00+00:00",
                "lease_owner": "other-worker",
                "lease_until": 9_999_999_999,
            }
        )

        response = await self.client.get("/jobs", headers=self.headers)
        payload = await response.get_json()

        self.assertEqual(response.status_code, 200)
        self.assertEqual([job["job_id"] for job in payload], ["remote-job"])

    async def test_playbook_cancel_cancels_its_running_scan_job(self):
        started = asyncio.Event()
        never_finish = asyncio.Event()

        async def slow_run(job_id, *, already_claimed=False):
            await autonmap._set_job_fields(
                job_id,
                status="running",
                started_at=autonmap._utc_now_iso(),
            )
            started.set()
            await never_finish.wait()

        autonmap._run_scan_job = slow_run
        response = await self.client.post(
            "/playbook/run",
            headers=self.headers,
            json={"target": "127.0.0.1", "playbook": "quick"},
        )
        record = await response.get_json()
        await asyncio.wait_for(started.wait(), timeout=2)

        cancelled = await self.client.delete(
            f"/playbook/{record['engagement_id']}",
            headers=self.headers,
        )
        payload = await cancelled.get_json()
        await asyncio.sleep(0)
        step = autonmap.engagements[record["engagement_id"]]["steps"][0]
        job = autonmap.scan_jobs[step["job_id"]]

        self.assertEqual(cancelled.status_code, 200)
        self.assertEqual(payload["status"], "cancelled")
        self.assertEqual(step["status"], "cancelled")
        self.assertEqual(job["status"], "cancelled")
        self.assertTrue(job["task"].done())

    async def test_scan_runner_stops_after_remote_worker_cancels_lease(self):
        job_id = "remote-cancel"
        started = threading.Event()
        process_stopped = threading.Event()
        job = {
            "job_id": job_id,
            "target": "127.0.0.1",
            "scan_type": "Ping",
            "status": "running",
            "kind": "immediate",
            "owner_id": autonmap.owner_id_from_token("test-token"),
            "created_at": "2026-01-01T00:00:00+00:00",
            "started_at": "2026-01-01T00:00:00+00:00",
            "lease_owner": autonmap.WORKER_ID,
            "lease_until": 9_999_999_999,
            "task": None,
        }
        autonmap.scan_jobs[job_id] = job
        autonmap.state_store.upsert_job(job)

        def blocking_scan(*_args, **_kwargs):
            started.set()
            process_stopped.wait(timeout=2)
            return {"hosts": []}

        def stop_process(_job_id):
            process_stopped.set()
            return True

        with (
            mock.patch.object(autonmap, "scan_network", side_effect=blocking_scan),
            mock.patch.object(autonmap, "kill_active_process", side_effect=stop_process) as kill,
            mock.patch.object(autonmap, "JOB_LEASE_SECONDS", 0.15),
        ):
            task = asyncio.create_task(autonmap._run_scan_job(job_id, already_claimed=True))
            job["task"] = task
            self.assertTrue(await asyncio.to_thread(started.wait, 1))
            durable = autonmap.state_store.get_job(job_id)
            durable.update(
                {
                    "status": "cancelled",
                    "finished_at": "2026-01-01T00:00:01+00:00",
                    "error": "Scan cancelled",
                    "lease_owner": None,
                    "lease_until": None,
                }
            )
            autonmap.state_store.upsert_job(durable)

            result = await asyncio.wait_for(
                asyncio.gather(task, return_exceptions=True),
                timeout=2,
            )

        self.assertIsInstance(result[0], asyncio.CancelledError)
        self.assertEqual(autonmap.scan_jobs[job_id]["status"], "cancelled")
        kill.assert_called_with(job_id)

    async def test_scan_completion_cannot_resurrect_remote_cancellation(self):
        job_id = "remote-cancel-at-finish"
        started = threading.Event()
        finish_scan = threading.Event()
        job = {
            "job_id": job_id,
            "target": "127.0.0.1",
            "scan_type": "Ping",
            "status": "running",
            "kind": "immediate",
            "owner_id": autonmap.owner_id_from_token("test-token"),
            "created_at": "2026-01-01T00:00:00+00:00",
            "started_at": "2026-01-01T00:00:00+00:00",
            "lease_owner": autonmap.WORKER_ID,
            "lease_until": 9_999_999_999,
            "task": None,
        }
        autonmap.scan_jobs[job_id] = job
        autonmap.state_store.upsert_job(job)

        def finishing_scan(*_args, **_kwargs):
            started.set()
            finish_scan.wait(timeout=2)
            return {"hosts": []}

        save_result = mock.AsyncMock(return_value="must-not-be-written.json")
        with (
            mock.patch.object(autonmap, "scan_network", side_effect=finishing_scan),
            mock.patch.object(autonmap, "save_scan_results_async", save_result),
        ):
            task = asyncio.create_task(autonmap._run_scan_job(job_id, already_claimed=True))
            job["task"] = task
            self.assertTrue(await asyncio.to_thread(started.wait, 1))
            durable = autonmap.state_store.get_job(job_id)
            durable.update(
                {
                    "status": "cancelled",
                    "finished_at": "2026-01-01T00:00:01+00:00",
                    "error": "Scan cancelled",
                    "lease_owner": None,
                    "lease_until": None,
                }
            )
            autonmap.state_store.upsert_job(durable)
            finish_scan.set()
            await asyncio.wait_for(task, timeout=2)

        self.assertEqual(autonmap.scan_jobs[job_id]["status"], "cancelled")
        self.assertEqual(autonmap.state_store.get_job(job_id)["status"], "cancelled")
        save_result.assert_not_awaited()

    async def test_malformed_posture_is_a_client_error(self):
        response = await self.client.post(
            "/posture/evaluate",
            headers=self.headers,
            json={
                "scan": {"hosts": []},
                "posture": {
                    "services": [{"port": "not-a-port", "proto": "tcp"}],
                },
            },
        )
        payload = await response.get_json()

        self.assertEqual(response.status_code, 400)
        self.assertIn("port must be int", payload["error"])

    async def test_posture_without_configuration_returns_disabled_report(self):
        with mock.patch.object(autonmap, "load_expected_posture", return_value=None):
            response = await self.client.post(
                "/posture/evaluate",
                headers=self.headers,
                json={"scan": {"hosts": []}},
            )
        payload = await response.get_json()

        self.assertEqual(response.status_code, 200)
        self.assertFalse(payload["enabled"])

    async def test_missing_durable_playbook_job_fails_instead_of_polling_forever(self):
        result = await asyncio.wait_for(
            autonmap._wait_job_terminal("missing-job"),
            timeout=0.5,
        )

        self.assertEqual(result["status"], "failed")
        self.assertIn("durable state", result["error"])

    async def test_scan_is_not_accepted_when_durable_insert_fails(self):
        with mock.patch.object(
            autonmap.state_store,
            "insert_job_with_capacity",
            side_effect=RuntimeError("disk unavailable"),
        ):
            response = await self.client.post(
                "/scan",
                headers=self.headers,
                json={"target": "127.0.0.1", "scan_type": "Ping"},
            )

        self.assertEqual(response.status_code, 500)
        self.assertEqual(autonmap.scan_jobs, {})

    async def test_schedule_delete_failure_does_not_stop_the_live_schedule(self):
        owner = autonmap.owner_id_from_token("test-token")
        task_id = autonmap.make_task_id("127.0.0.1", "Ping", owner)
        autonmap.state_store.upsert_scheduled_task(
            task_id,
            "127.0.0.1",
            "Ping",
            30,
            owner_id=owner,
            created_at=autonmap._utc_now_iso(),
        )
        live_task = asyncio.create_task(asyncio.Event().wait())
        autonmap.scan_tasks[task_id] = live_task
        try:
            with mock.patch.object(
                autonmap.state_store,
                "delete_scheduled_task",
                side_effect=RuntimeError("disk unavailable"),
            ):
                response = await self.client.delete(
                    f"/tasks/{task_id}",
                    headers=self.headers,
                )

            self.assertEqual(response.status_code, 503)
            self.assertFalse(live_task.done())
            self.assertIn(task_id, autonmap.scan_tasks)
        finally:
            live_task.cancel()
            await asyncio.gather(live_task, return_exceptions=True)
            autonmap.scan_tasks.pop(task_id, None)


if __name__ == "__main__":
    unittest.main()
