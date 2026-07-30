import asyncio
import concurrent.futures
import json
import math
import os
import stat
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest import mock

# Path is used by retention and result tests.

os.environ["API_AUTH_REQUIRED"] = "true"
os.environ["API_AUTH_TOKEN"] = "test-token"
os.environ["FERNET_KEY"] = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
os.environ["SCAN_LOG_PATH"] = "/tmp/nmap-automator-test.log"
os.environ["TELEGRAM_BOT_TOKEN"] = ""
os.environ["TELEGRAM_CHAT_ID"] = ""
os.environ["RESULTS_MAX_FILES"] = "500"
os.environ["RESULTS_MAX_AGE_DAYS"] = "0"
os.environ["STATE_DB_PATH"] = "/tmp/recon-operator-test.db"

import autonmap


class PayloadValidationTests(unittest.TestCase):
    def test_scan_type_is_case_insensitive_and_canonical(self):
        target, scan_type, interval, ports, scripts, discovery, error = (
            autonmap._validate_scan_payload(
                {
                    "target": "127.0.0.1",
                    "scan_type": "tcp",
                    "interval": 5,
                    "ports": "22,80",
                    "discovery": "auto",
                }
            )
        )

        self.assertIsNone(error)
        self.assertEqual(target, "127.0.0.1")
        self.assertEqual(scan_type, "TCP")
        self.assertEqual(interval, 5.0)
        self.assertEqual(ports, "22,80")
        self.assertIsNone(scripts)
        self.assertEqual(discovery, "auto")

    def test_bad_interval_is_rejected(self):
        *_, error = autonmap._validate_scan_payload(
            {"target": "127.0.0.1", "scan_type": "Ping", "interval": 0}
        )

        self.assertEqual(error, "interval must be a positive number")

    def test_schedule_interval_is_bounded(self):
        *_, short_error = autonmap._validate_scan_payload(
            {
                "target": "127.0.0.1",
                "scan_type": "Ping",
                "interval": autonmap.MIN_SCHEDULE_INTERVAL_MINUTES - 0.5,
            }
        )
        *_, long_error = autonmap._validate_scan_payload(
            {
                "target": "127.0.0.1",
                "scan_type": "Ping",
                "interval": autonmap.MAX_SCHEDULE_INTERVAL_MINUTES + 1,
            }
        )

        self.assertIn("at least", short_error)
        self.assertIn("at most", long_error)

    def test_default_scan_type_is_unprivileged_tcp(self):
        _, scan_type, _, _, _, _, error = autonmap._validate_scan_payload({"target": "127.0.0.1"})

        self.assertIsNone(error)
        self.assertEqual(scan_type, "TCP")

    def test_oversized_network_is_rejected(self):
        *_, error = autonmap._validate_scan_payload({"target": "10.0.0.0/8", "scan_type": "Ping"})

        self.assertEqual(error, "Invalid IP, CIDR, or hostname")

    def test_version_and_vuln_profiles_are_accepted(self):
        for profile in ("Version", "Safe", "Vuln", "Full", "Hybrid", "HybridNaabu"):
            with self.subTest(profile=profile):
                _, scan_type, _, _, _, _, error = autonmap._validate_scan_payload(
                    {"target": "127.0.0.1", "scan_type": profile}
                )
                self.assertIsNone(error)
                self.assertEqual(scan_type, profile)

    def test_invalid_ports_are_rejected(self):
        *_, error = autonmap._validate_scan_payload(
            {"target": "127.0.0.1", "scan_type": "TCP", "ports": "80;id"}
        )
        self.assertIn("ports", error.lower())

    def test_syntactically_valid_domain_does_not_require_dns(self):
        self.assertTrue(autonmap.validate_ip_or_host("offline-host.example.invalid"))


class ScanExecutionTests(unittest.TestCase):
    def test_scan_network_uses_unified_engine(self):
        captured = {}

        def fake_run(
            target,
            scan_type,
            host_timeout_sec,
            max_retries,
            scan_timeout_sec,
            ports=None,
            scripts=None,
            discovery=None,
            **_kwargs,
        ):
            captured.update(
                {
                    "target": target,
                    "scan_type": scan_type,
                    "host_timeout_sec": host_timeout_sec,
                    "max_retries": max_retries,
                    "scan_timeout_sec": scan_timeout_sec,
                    "ports": ports,
                    "scripts": scripts,
                    "discovery": discovery,
                }
            )
            return {"hosts": [], "scan_count": 0}

        with mock.patch("autonmap.run_nmap_scan", side_effect=fake_run):
            result = autonmap.scan_network("127.0.0.1", "Ping")

        self.assertEqual(result["hosts"], [])
        self.assertEqual(captured["scan_timeout_sec"], autonmap.SCAN_TIMEOUT_SECONDS)
        self.assertEqual(captured["scan_type"], "Ping")


class TaskCleanupTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        autonmap.scan_tasks.clear()
        autonmap.scan_jobs.clear()
        autonmap.rate_limits.clear()

    async def test_finished_tasks_are_removed(self):
        task = asyncio.create_task(asyncio.sleep(0))
        await task
        autonmap.scan_tasks["127.0.0.1-Ping"] = task

        removed = autonmap._cleanup_finished_tasks()

        self.assertEqual(removed, ["127.0.0.1-Ping"])
        self.assertEqual(autonmap.scan_tasks, {})


class RateLimitTests(unittest.TestCase):
    def setUp(self):
        autonmap.rate_limits.clear()
        # Force memory backend for unit tests of the in-process path.
        autonmap._redis_init_attempted = True
        autonmap._redis_available = False
        autonmap._redis_client = None

    def tearDown(self):
        autonmap.rate_limits.clear()
        autonmap._redis_init_attempted = False
        autonmap._redis_available = False
        autonmap._redis_client = None

    def test_stale_client_is_evicted_when_bucket_table_is_full(self):
        original_limit = autonmap.MAX_RATE_LIMIT_CLIENTS
        original_client_key = autonmap._client_key
        now = autonmap.time.time()
        autonmap.MAX_RATE_LIMIT_CLIENTS = 2
        autonmap.rate_limits["active"] = [now]
        autonmap.rate_limits["stale"] = [now - autonmap.RATE_LIMIT_WINDOW_SECONDS - 1]
        autonmap._client_key = lambda: "new"
        try:
            allowed = autonmap.check_rate_limit()
        finally:
            autonmap.MAX_RATE_LIMIT_CLIENTS = original_limit
            autonmap._client_key = original_client_key

        self.assertTrue(allowed)
        self.assertNotIn("stale", autonmap.rate_limits)
        self.assertIn("new", autonmap.rate_limits)

    def test_redis_sliding_window_blocks_and_allows(self):
        class FakeRedis:
            def __init__(self):
                self.store = {}

            def eval(self, _script, _numkeys, key, now, window, limit, member):
                now_f = float(now)
                window_f = float(window)
                limit_i = int(limit)
                members = [
                    (name, score)
                    for name, score in self.store.get(key, [])
                    if score > now_f - window_f
                ]
                if len(members) >= limit_i:
                    self.store[key] = members
                    return 0
                members.append((member, now_f))
                self.store[key] = members
                return 1

        fake = FakeRedis()
        bucket = "127.0.0.1:otestowner01"
        original_max = autonmap.MAX_REQUESTS_PER_WINDOW
        autonmap.MAX_REQUESTS_PER_WINDOW = 2
        try:
            self.assertTrue(autonmap._check_rate_limit_redis(fake, bucket))
            self.assertTrue(autonmap._check_rate_limit_redis(fake, bucket))
            self.assertFalse(autonmap._check_rate_limit_redis(fake, bucket))
        finally:
            autonmap.MAX_REQUESTS_PER_WINDOW = original_max
        key = f"{autonmap.REDIS_RATE_LIMIT_PREFIX}{bucket}"
        self.assertEqual(len(fake.store.get(key, [])), 2)

    def test_rate_limit_backend_reports_memory_without_redis_url(self):
        original_url = autonmap.REDIS_URL
        original_attempted = autonmap._redis_init_attempted
        original_available = autonmap._redis_available
        original_client = autonmap._redis_client
        try:
            autonmap.REDIS_URL = ""
            autonmap._redis_init_attempted = False
            autonmap._redis_available = False
            autonmap._redis_client = None
            self.assertEqual(autonmap.rate_limit_backend(), "memory")
        finally:
            autonmap.REDIS_URL = original_url
            autonmap._redis_init_attempted = original_attempted
            autonmap._redis_available = original_available
            autonmap._redis_client = original_client

    def test_bucket_key_includes_owner_when_enabled(self):
        original_flag = autonmap.RATE_LIMIT_INCLUDE_OWNER
        original_client_key = autonmap._client_key
        autonmap._client_key = lambda: "10.0.0.1"
        try:
            autonmap.RATE_LIMIT_INCLUDE_OWNER = False
            self.assertEqual(autonmap._rate_limit_bucket_key(), "10.0.0.1")
            autonmap.RATE_LIMIT_INCLUDE_OWNER = True
            # Outside request context owner falls back to IP-only.
            self.assertEqual(autonmap._rate_limit_bucket_key(), "10.0.0.1")
        finally:
            autonmap.RATE_LIMIT_INCLUDE_OWNER = original_flag
            autonmap._client_key = original_client_key

    def test_peer_trust_and_forwarded_ip_parsing(self):
        original_mode = autonmap.TRUSTED_PROXY_MODE
        original_proxies = list(autonmap.TRUSTED_PROXIES)
        try:
            autonmap.TRUSTED_PROXY_MODE = True
            autonmap.TRUSTED_PROXIES[:] = ["10.0.0.0/8", "127.0.0.1"]
            self.assertTrue(autonmap._peer_is_trusted_proxy("10.1.2.3"))
            self.assertTrue(autonmap._peer_is_trusted_proxy("127.0.0.1"))
            self.assertFalse(autonmap._peer_is_trusted_proxy("8.8.8.8"))
            self.assertFalse(autonmap._peer_is_trusted_proxy("unknown"))
            self.assertEqual(autonmap._first_valid_ip("203.0.113.9, 10.0.0.1"), "203.0.113.9")
            self.assertEqual(autonmap._first_valid_ip("not-an-ip, 198.51.100.4"), "198.51.100.4")
            self.assertIsNone(autonmap._first_valid_ip("bogus"))
        finally:
            autonmap.TRUSTED_PROXY_MODE = original_mode
            autonmap.TRUSTED_PROXIES[:] = original_proxies

    def test_client_key_uses_xff_only_from_trusted_peer(self):
        original_mode = autonmap.TRUSTED_PROXY_MODE
        original_proxies = list(autonmap.TRUSTED_PROXIES)
        try:
            autonmap.TRUSTED_PROXY_MODE = True
            autonmap.TRUSTED_PROXIES[:] = ["127.0.0.1"]

            class _Req:
                def __init__(self, remote_addr, headers):
                    self.remote_addr = remote_addr
                    self.headers = headers

            original_request = autonmap.request
            try:
                autonmap.request = _Req("127.0.0.1", {"X-Forwarded-For": "203.0.113.50, 10.0.0.2"})
                self.assertEqual(autonmap._client_key(), "203.0.113.50")

                autonmap.request = _Req("8.8.8.8", {"X-Forwarded-For": "203.0.113.50"})
                self.assertEqual(autonmap._client_key(), "8.8.8.8")

                autonmap.request = _Req("127.0.0.1", {"X-Real-IP": "198.51.100.7"})
                self.assertEqual(autonmap._client_key(), "198.51.100.7")
            finally:
                autonmap.request = original_request
        finally:
            autonmap.TRUSTED_PROXY_MODE = original_mode
            autonmap.TRUSTED_PROXIES[:] = original_proxies

    def test_load_trusted_proxies_from_env(self):
        with mock.patch.dict(
            os.environ,
            {"TRUSTED_PROXIES": "127.0.0.1, 10.0.0.0/8, 127.0.0.1"},
            clear=False,
        ):
            self.assertEqual(
                autonmap._load_trusted_proxies(),
                ["127.0.0.1", "10.0.0.0/8"],
            )
        with mock.patch.dict(
            os.environ,
            {"TRUSTED_PROXIES": '["192.0.2.1"]'},
            clear=False,
        ):
            self.assertEqual(autonmap._load_trusted_proxies(), ["192.0.2.1"])
        with mock.patch.dict(os.environ, {"TRUSTED_PROXIES": "[not-json"}, clear=False):
            with self.assertRaises(RuntimeError):
                autonmap._load_trusted_proxies()


class ResultPersistenceTests(unittest.IsolatedAsyncioTestCase):
    async def test_encrypted_results_are_owner_only(self):
        original_results_dir = autonmap.RESULTS_DIR
        original_sender = autonmap.send_telegram_message

        async def ignore_message(_message):
            return None

        with tempfile.TemporaryDirectory() as tmp:
            autonmap.RESULTS_DIR = tmp
            autonmap.send_telegram_message = ignore_message
            try:
                filename = await autonmap.save_scan_results_async(
                    {"hosts": []}, "127.0.0.1", "Ping"
                )
            finally:
                autonmap.RESULTS_DIR = original_results_dir
                autonmap.send_telegram_message = original_sender

            files = [name for name in os.listdir(tmp) if name.endswith(".json")]
            self.assertEqual(len(files), 1)
            self.assertEqual(filename, files[0])
            mode = stat.S_IMODE(os.stat(os.path.join(tmp, files[0])).st_mode)
            self.assertEqual(mode, 0o600)

    def test_retention_deletes_excess_files(self):
        original_max = autonmap.RESULTS_MAX_FILES
        autonmap.RESULTS_MAX_FILES = 2
        try:
            with tempfile.TemporaryDirectory() as tmp:
                for index in range(4):
                    path = Path(tmp) / f"host_Ping_20260101_00000{index}_00000{index}.json"
                    path.write_bytes(b"x")
                    os.utime(path, (index + 1, index + 1))
                summary = autonmap.apply_results_retention(tmp)
                remaining = list(Path(tmp).glob("*.json"))
        finally:
            autonmap.RESULTS_MAX_FILES = original_max

        self.assertEqual(summary["remaining"], 2)
        self.assertEqual(summary["deleted"], 2)
        self.assertEqual(len(remaining), 2)


class ApiTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        autonmap.scan_tasks.clear()
        autonmap.scan_jobs.clear()
        autonmap.rate_limits.clear()
        self.client = autonmap.app.test_client()

    async def test_tasks_requires_api_token(self):
        response = await self.client.get("/tasks")

        self.assertEqual(response.status_code, 401)

    async def test_health_reports_status(self):
        original_check = autonmap._check_nmap_available
        autonmap._check_nmap_available = lambda: True
        try:
            response = await self.client.get("/health")
            payload = await response.get_json()
        finally:
            autonmap._check_nmap_available = original_check

        self.assertEqual(response.status_code, 200)
        self.assertEqual(payload["status"], "healthy")
        self.assertIn("jobs_count", payload)
        self.assertIn("fernet_key_count", payload)
        self.assertGreaterEqual(payload["fernet_key_count"], 1)
        self.assertEqual(payload["api_auth_header"], autonmap.API_AUTH_HEADER)
        self.assertEqual(payload["api_auth_required"], autonmap.API_AUTH_REQUIRED)

    async def test_audit_requires_admin_and_lists_events(self):
        autonmap.record_audit_event(
            "scan.create",
            target="127.0.0.1",
            scan_type="Ping",
            job_id="audit-job-1",
            status="queued",
            actor_key_id="primary",
            actor_owner_prefix="abcd12345678",
        )
        denied = await self.client.get("/audit")
        self.assertEqual(denied.status_code, 401)

        response = await self.client.get(
            "/audit?limit=10&action=scan.create",
            headers={"X-API-KEY": "test-token"},
        )
        payload = await response.get_json()
        self.assertEqual(response.status_code, 200)
        self.assertGreaterEqual(payload["count"], 1)
        self.assertTrue(any(ev.get("job_id") == "audit-job-1" for ev in payload["events"]))
        # Secrets must never appear in audit payloads.
        blob = str(payload)
        self.assertNotIn("test-token", blob)
        self.assertNotIn(autonmap.FERNET_KEY, blob)

    async def test_dashboard_loads(self):
        response = await self.client.get("/")
        body = await response.get_data(as_text=True)

        self.assertEqual(response.status_code, 200)
        self.assertIn("Recon Operator", body)
        self.assertIn("Scan History", body)
        self.assertIn("Import XML", body)
        self.assertIn("Diff last two", body)
        self.assertIn("AI Brief", body)
        self.assertIn("Engagement preset", body)
        self.assertIn("/static/dashboard.css", body)
        self.assertIn("/static/dashboard.js", body)
        self.assertIn("/static/favicon.svg", body)
        self.assertNotIn("__CSP_NONCE__", body)
        self.assertIn('nonce="', body)
        csp = response.headers["Content-Security-Policy"]
        self.assertIn("nonce-", csp)
        self.assertIn("'self'", csp)
        self.assertNotIn("unsafe-inline", csp)

        js_response = await self.client.get("/static/dashboard.js")
        js_body = await js_response.get_data(as_text=True)
        self.assertEqual(js_response.status_code, 200)
        self.assertIn("waitForJob", js_body)
        self.assertIn("observations", js_body)
        self.assertIn("health.api_auth_header", js_body)
        self.assertIn("health.api_auth_required", js_body)
        self.assertIn("resetOwnerWorkspace", js_body)
        self.assertIn("report.ports_opened", js_body)
        self.assertIn("public", js_response.headers.get("Cache-Control", ""))

        css_response = await self.client.get("/static/dashboard.css")
        css_body = await css_response.get_data(as_text=True)
        self.assertEqual(css_response.status_code, 200)
        self.assertIn(":focus-visible", css_body)

        favicon = await self.client.get("/favicon.ico")
        self.assertEqual(favicon.status_code, 200)
        self.assertIn("public", favicon.headers.get("Cache-Control", ""))

    async def test_responses_include_security_headers(self):
        response = await self.client.get("/health")

        self.assertEqual(response.headers["Cache-Control"], "no-store")
        self.assertEqual(response.headers["X-Frame-Options"], "DENY")
        self.assertIn("frame-ancestors 'none'", response.headers["Content-Security-Policy"])
        self.assertIn("default-src 'none'", response.headers["Content-Security-Policy"])

    async def test_non_import_json_uses_the_smaller_route_body_limit(self):
        original = autonmap.MAX_REQUEST_BODY_BYTES
        autonmap.MAX_REQUEST_BODY_BYTES = 64
        try:
            response = await self.client.post(
                "/scan",
                headers={"X-API-KEY": "test-token", "Content-Type": "application/json"},
                data=json.dumps({"target": "127.0.0.1", "padding": "x" * 100}),
            )
        finally:
            autonmap.MAX_REQUEST_BODY_BYTES = original
        self.assertEqual(response.status_code, 413)

    async def test_scan_queues_job_by_default(self):
        async def fake_create(
            target,
            scan_type,
            kind="immediate",
            ports=None,
            scripts=None,
            discovery=None,
            owner_id=None,
        ):
            return {
                "job_id": "job-1",
                "target": target,
                "scan_type": scan_type,
                "status": "queued",
                "created_at": "now",
                "kind": kind,
                "ports": ports,
                "scripts": scripts,
                "discovery": discovery,
                "owner_id": owner_id,
            }

        original = autonmap.create_scan_job
        autonmap.create_scan_job = fake_create
        try:
            response = await self.client.post(
                "/scan",
                headers={"X-API-KEY": "test-token"},
                json={"target": "127.0.0.1", "scan_type": "Ping"},
            )
            payload = await response.get_json()
        finally:
            autonmap.create_scan_job = original

        self.assertEqual(response.status_code, 202)
        self.assertEqual(payload["job_id"], "job-1")
        self.assertEqual(payload["status"], "queued")

    async def test_scan_wait_mode_returns_result(self):
        original_scan = autonmap.async_scan

        async def fake_scan(
            target, scan_type, ports=None, scripts=None, discovery=None, owner_id=None
        ):
            return {"hosts": [], "target": target, "scan_type": scan_type}

        autonmap.async_scan = fake_scan
        try:
            response = await self.client.post(
                "/scan?wait=1",
                headers={"X-API-KEY": "test-token"},
                json={"target": "127.0.0.1", "scan_type": "Ping"},
            )
            payload = await response.get_json()
        finally:
            autonmap.async_scan = original_scan

        self.assertEqual(response.status_code, 200)
        self.assertEqual(payload["target"], "127.0.0.1")

    async def test_scan_timeout_returns_gateway_timeout(self):
        original_scan = autonmap.async_scan

        async def timeout_scan(
            target, scan_type, ports=None, scripts=None, discovery=None, owner_id=None
        ):
            raise TimeoutError("scan took too long")

        autonmap.async_scan = timeout_scan
        try:
            response = await self.client.post(
                "/scan?wait=1",
                headers={"X-API-KEY": "test-token"},
                json={"target": "127.0.0.1", "scan_type": "Ping"},
            )
            payload = await response.get_json()
        finally:
            autonmap.async_scan = original_scan

        self.assertEqual(response.status_code, 504)
        self.assertIn("scan took too long", payload["error"])

    async def test_schedule_rejects_tasks_above_configured_limit(self):
        original_limit = autonmap.MAX_SCHEDULED_TASKS
        autonmap.MAX_SCHEDULED_TASKS = 1
        try:
            autonmap.state_store.upsert_scheduled_task(
                "oexisting00001-127.0.0.1-Ping",
                "127.0.0.1",
                "Ping",
                30,
                owner_id="local",
                created_at="t0",
            )
            response = await self.client.post(
                "/schedule",
                headers={"X-API-KEY": "test-token"},
                json={"target": "127.0.0.1", "scan_type": "TCP", "interval": 30},
            )
            payload = await response.get_json()
        finally:
            autonmap.MAX_SCHEDULED_TASKS = original_limit
            try:
                autonmap.state_store.delete_scheduled_task("oexisting00001-127.0.0.1-Ping")
            except Exception:
                pass
            autonmap.scan_tasks.clear()

        self.assertEqual(response.status_code, 429)
        self.assertIn("limit", payload["error"].lower())

    async def test_jobs_and_results_endpoints(self):
        sample = {
            "hosts": [{"host": "127.0.0.1", "hostname": "N/A", "state": "up", "protocols": {}}],
            "scan_count": 1,
        }
        original_results_dir = autonmap.RESULTS_DIR
        with tempfile.TemporaryDirectory() as tmp:
            autonmap.RESULTS_DIR = tmp
            filename = await autonmap.save_scan_results_async(
                sample,
                "127.0.0.1",
                "Ping",
                owner_id=autonmap.owner_id_from_token("test-token"),
            )
            list_response = await self.client.get("/results", headers={"X-API-KEY": "test-token"})
            list_payload = await list_response.get_json()
            get_response = await self.client.get(
                f"/results/{filename}", headers={"X-API-KEY": "test-token"}
            )
            get_payload = await get_response.get_json()
            autonmap.RESULTS_DIR = original_results_dir

        self.assertEqual(list_response.status_code, 200)
        self.assertEqual(list_payload["count"], 1)
        self.assertEqual(get_response.status_code, 200)
        self.assertEqual(get_payload["result"]["scan_count"], 1)

        autonmap.scan_jobs["job-x"] = {
            "job_id": "job-x",
            "target": "127.0.0.1",
            "scan_type": "Ping",
            "status": "completed",
            "created_at": "t0",
            "started_at": "t1",
            "finished_at": "t2",
            "error": None,
            "result": sample,
            "result_file": filename,
            "kind": "immediate",
            "task": None,
        }
        job_response = await self.client.get("/jobs/job-x", headers={"X-API-KEY": "test-token"})
        job_payload = await job_response.get_json()
        self.assertEqual(job_response.status_code, 200)
        self.assertEqual(job_payload["status"], "completed")
        self.assertEqual(job_payload["result"]["scan_count"], 1)

        list_jobs = await self.client.get("/jobs", headers={"X-API-KEY": "test-token"})
        list_jobs_payload = await list_jobs.get_json()
        self.assertEqual(list_jobs.status_code, 200)
        self.assertTrue(any(job["job_id"] == "job-x" for job in list_jobs_payload))

    async def test_create_scan_job_completes_with_mocked_engine(self):
        original_results_dir = autonmap.RESULTS_DIR
        original_scan = autonmap.scan_network
        original_sender = autonmap.send_telegram_message

        async def ignore_message(_message):
            return None

        def fake_scan(
            target,
            scan_type,
            ports=None,
            scripts=None,
            discovery=None,
            owner_id=None,
            process_token=None,
            **_kwargs,
        ):
            return {
                "hosts": [{"host": target, "hostname": "N/A", "state": "up", "protocols": {}}],
                "scan_count": 1,
                "target": target,
                "scan_type": scan_type,
            }

        with tempfile.TemporaryDirectory() as tmp:
            autonmap.RESULTS_DIR = tmp
            autonmap.scan_network = fake_scan
            autonmap.send_telegram_message = ignore_message
            try:
                job = await autonmap.create_scan_job("127.0.0.1", "Ping")
                job_id = job["job_id"]
                for _ in range(50):
                    async with autonmap._jobs_lock:
                        status = autonmap.scan_jobs[job_id]["status"]
                        result_file = autonmap.scan_jobs[job_id].get("result_file")
                    if status in {"completed", "failed", "timeout"}:
                        break
                    await asyncio.sleep(0.02)
            finally:
                autonmap.RESULTS_DIR = original_results_dir
                autonmap.scan_network = original_scan
                autonmap.send_telegram_message = original_sender

        self.assertEqual(status, "completed")
        self.assertIsNotNone(result_file)

    async def test_import_and_diff_endpoints(self):
        sample_xml = """<?xml version="1.0"?>
<nmaprun scanner="nmap" args="nmap" start="1" version="7.95" xmloutputversion="1.05">
  <host>
    <status state="up"/>
    <address addr="192.0.2.10" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="22"><state state="open"/><service name="ssh"/></port>
    </ports>
  </host>
</nmaprun>
"""
        baseline = {
            "hosts": [
                {
                    "host": "192.0.2.10",
                    "hostname": "N/A",
                    "state": "up",
                    "protocols": {"tcp": [{"port": 22, "state": "open", "name": "ssh"}]},
                }
            ]
        }
        current = {
            "hosts": [
                {
                    "host": "192.0.2.10",
                    "hostname": "N/A",
                    "state": "up",
                    "protocols": {
                        "tcp": [
                            {"port": 22, "state": "open", "name": "ssh"},
                            {"port": 80, "state": "open", "name": "http"},
                        ]
                    },
                }
            ]
        }
        original_results_dir = autonmap.RESULTS_DIR
        original_sender = autonmap.send_telegram_message

        async def ignore_message(_message):
            return None

        with tempfile.TemporaryDirectory() as tmp:
            autonmap.RESULTS_DIR = tmp
            autonmap.send_telegram_message = ignore_message
            try:
                import_response = await self.client.post(
                    "/results/import",
                    headers={"X-API-KEY": "test-token"},
                    json={"xml": sample_xml, "target": "192.0.2.10"},
                )
                import_payload = await import_response.get_json()
                diff_response = await self.client.post(
                    "/results/diff",
                    headers={"X-API-KEY": "test-token"},
                    json={"baseline": baseline, "current": current},
                )
                diff_payload = await diff_response.get_json()
            finally:
                autonmap.RESULTS_DIR = original_results_dir
                autonmap.send_telegram_message = original_sender

        self.assertEqual(import_response.status_code, 201)
        self.assertEqual(import_payload["result"]["hosts"][0]["host"], "192.0.2.10")
        self.assertEqual(diff_response.status_code, 200)
        self.assertTrue(diff_payload["summary"]["changed"])
        self.assertEqual(diff_payload["summary"]["ports_opened"], 1)

    async def test_cancel_job_endpoint(self):
        autonmap.scan_jobs["job-cancel"] = {
            "job_id": "job-cancel",
            "target": "127.0.0.1",
            "scan_type": "Ping",
            "status": "queued",
            "created_at": "t0",
            "started_at": None,
            "finished_at": None,
            "error": None,
            "result": None,
            "result_file": None,
            "kind": "immediate",
            "task": None,
        }
        response = await self.client.delete("/jobs/job-cancel", headers={"X-API-KEY": "test-token"})
        payload = await response.get_json()
        self.assertEqual(response.status_code, 200)
        self.assertIn("cancelled", payload["message"].lower())
        self.assertEqual(autonmap.scan_jobs["job-cancel"]["status"], "cancelled")

    async def test_dashboard_exposes_accessible_controls_and_feedback(self):
        response = await self.client.get("/")
        body = await response.get_data(as_text=True)

        self.assertIn('role="status" aria-live="polite"', body)
        self.assertIn('role="tablist"', body)
        self.assertIn('aria-selected="true"', body)
        self.assertIn('for="toolsBox"', body)
        self.assertIn('for="resultBox"', body)

        css_response = await self.client.get("/static/dashboard.css")
        css_body = await css_response.get_data(as_text=True)
        self.assertIn(":focus-visible", css_body)

        js_response = await self.client.get("/static/dashboard.js")
        js_body = await js_response.get_data(as_text=True)
        self.assertIn("refresh({ announce: false })", js_body)


class JobLeaseRuntimeTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        autonmap.scan_jobs.clear()
        autonmap.rate_limits.clear()
        self._leader = autonmap._is_scheduler_leader

    async def asyncTearDown(self):
        for job in list(autonmap.scan_jobs.values()):
            task = job.get("task")
            if task is not None and not task.done():
                task.cancel()
        autonmap.scan_jobs.clear()
        autonmap.rate_limits.clear()
        autonmap._is_scheduler_leader = self._leader

    async def test_scheduler_leader_sync_and_stop(self):
        async def noop_periodic(*_args, **_kwargs):
            await asyncio.Event().wait()

        original_periodic = autonmap.periodic_scan
        original_list = autonmap.state_store.list_scheduled_tasks
        autonmap.periodic_scan = noop_periodic
        autonmap.state_store.list_scheduled_tasks = lambda owner_id=None: [
            {
                "task_id": "oleaderlocal-127.0.0.1-Ping",
                "target": "127.0.0.1",
                "scan_type": "Ping",
                "interval_minutes": 15,
                "ports": None,
                "scripts": None,
                "discovery": None,
                "owner_id": "local",
            }
        ]
        try:
            autonmap._is_scheduler_leader = True
            await autonmap.sync_scheduled_tasks_from_store()
            self.assertIn("oleaderlocal-127.0.0.1-Ping", autonmap.scan_tasks)
            await autonmap.stop_all_local_schedules()
            self.assertEqual(autonmap.scan_tasks, {})
        finally:
            autonmap.periodic_scan = original_periodic
            autonmap.state_store.list_scheduled_tasks = original_list
            for task in list(autonmap.scan_tasks.values()):
                task.cancel()
            autonmap.scan_tasks.clear()

    def test_try_become_scheduler_leader_paths(self):
        original_acquire = autonmap.state_store.try_acquire_leadership
        original_redis = autonmap._try_redis_leadership
        original_release = autonmap._release_redis_leadership
        releases = []
        try:
            autonmap._try_redis_leadership = lambda *_a, **_k: True
            autonmap.state_store.try_acquire_leadership = lambda *_a, **_k: True
            self.assertTrue(autonmap.try_become_scheduler_leader())

            autonmap.state_store.try_acquire_leadership = lambda *_a, **_k: False
            autonmap._release_redis_leadership = lambda name: releases.append(name)
            self.assertFalse(autonmap.try_become_scheduler_leader())
            self.assertEqual(releases, [autonmap.SCHEDULER_LOCK_NAME])

            autonmap._try_redis_leadership = lambda *_a, **_k: False
            self.assertFalse(autonmap.try_become_scheduler_leader())
        finally:
            autonmap.state_store.try_acquire_leadership = original_acquire
            autonmap._try_redis_leadership = original_redis
            autonmap._release_redis_leadership = original_release

    async def test_scheduler_leader_loop_gain_and_loss(self):
        async def noop_periodic(*_args, **_kwargs):
            await asyncio.Event().wait()

        original_periodic = autonmap.periodic_scan
        original_list = autonmap.state_store.list_scheduled_tasks
        original_try = autonmap.try_become_scheduler_leader
        original_leader = autonmap._is_scheduler_leader
        calls = {"n": 0}

        def fake_try():
            calls["n"] += 1
            # First call gains leadership, then loses it.
            return calls["n"] == 1

        stop = asyncio.Event()
        autonmap.periodic_scan = noop_periodic
        autonmap.state_store.list_scheduled_tasks = lambda owner_id=None: [
            {
                "task_id": "oloop-127.0.0.1-Ping",
                "target": "127.0.0.1",
                "scan_type": "Ping",
                "interval_minutes": 20,
                "ports": None,
                "scripts": None,
                "discovery": None,
                "owner_id": "local",
            }
        ]
        autonmap.try_become_scheduler_leader = fake_try
        autonmap._is_scheduler_leader = False
        original_poll = autonmap.SCHEDULER_LEADER_POLL_SECONDS
        autonmap.SCHEDULER_LEADER_POLL_SECONDS = 1
        try:
            task = asyncio.create_task(autonmap.scheduler_leader_loop(stop))
            await asyncio.sleep(0.05)
            self.assertTrue(autonmap._is_scheduler_leader)
            self.assertIn("oloop-127.0.0.1-Ping", autonmap.scan_tasks)
            # Second iteration loses leadership.
            await asyncio.sleep(1.2)
            self.assertFalse(autonmap._is_scheduler_leader)
            stop.set()
            await asyncio.wait_for(task, timeout=2)
        finally:
            stop.set()
            autonmap.periodic_scan = original_periodic
            autonmap.state_store.list_scheduled_tasks = original_list
            autonmap.try_become_scheduler_leader = original_try
            autonmap._is_scheduler_leader = original_leader
            autonmap.SCHEDULER_LEADER_POLL_SECONDS = original_poll
            for task in list(autonmap.scan_tasks.values()):
                task.cancel()
            autonmap.scan_tasks.clear()

    async def test_run_scan_job_skips_when_claim_fails(self):
        autonmap.scan_jobs["j-skip"] = {
            "job_id": "j-skip",
            "target": "127.0.0.1",
            "scan_type": "Ping",
            "status": "queued",
            "created_at": "t0",
            "kind": "immediate",
            "task": None,
            "owner_id": "local",
        }
        original_claim = autonmap._claim_job_for_worker
        original_get = autonmap.state_store.get_job
        autonmap._claim_job_for_worker = lambda _job_id: None
        autonmap.state_store.get_job = lambda _job_id: {
            "job_id": "j-skip",
            "target": "127.0.0.1",
            "scan_type": "Ping",
            "status": "running",
            "lease_owner": "other-worker",
            "kind": "immediate",
            "created_at": "t0",
            "owner_id": "local",
            "task": None,
        }
        try:
            await autonmap._run_scan_job("j-skip")
            self.assertEqual(autonmap.scan_jobs["j-skip"]["lease_owner"], "other-worker")
            self.assertIsNone(autonmap.scan_jobs["j-skip"].get("task"))
        finally:
            autonmap._claim_job_for_worker = original_claim
            autonmap.state_store.get_job = original_get

    async def test_adopt_claimed_job_runs_with_already_claimed(self):
        original_scan = autonmap.scan_network
        original_sender = autonmap.send_telegram_message
        original_results = autonmap.RESULTS_DIR
        original_release = autonmap.state_store.release_job_lease
        original_renew = autonmap._renew_job_lease

        async def ignore_message(_message):
            return None

        def fake_scan(*_a, **_k):
            return {"hosts": [], "scan_count": 0}

        with tempfile.TemporaryDirectory() as tmp:
            autonmap.RESULTS_DIR = tmp
            autonmap.scan_network = fake_scan
            autonmap.send_telegram_message = ignore_message
            autonmap.state_store.release_job_lease = lambda *_a, **_k: None
            autonmap._renew_job_lease = lambda _job_id: True
            try:
                claimed = {
                    "job_id": "j-adopt",
                    "target": "127.0.0.1",
                    "scan_type": "Ping",
                    "status": "running",
                    "created_at": "t0",
                    "started_at": "t1",
                    "kind": "immediate",
                    "owner_id": "local",
                    "lease_owner": autonmap.WORKER_ID,
                    "lease_until": time.time() + 60,
                    "ports": None,
                    "scripts": None,
                    "discovery": None,
                    "result": None,
                    "result_file": None,
                    "error": None,
                    "finished_at": None,
                    "task": None,
                }
                await autonmap._adopt_claimed_job(claimed)
                for _ in range(50):
                    status = autonmap.scan_jobs["j-adopt"]["status"]
                    if status in {"completed", "failed", "timeout"}:
                        break
                    await asyncio.sleep(0.02)
            finally:
                autonmap.scan_network = original_scan
                autonmap.send_telegram_message = original_sender
                autonmap.RESULTS_DIR = original_results
                autonmap.state_store.release_job_lease = original_release
                autonmap._renew_job_lease = original_renew

        self.assertEqual(autonmap.scan_jobs["j-adopt"]["status"], "completed")


class NamedApiKeyScopeTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        autonmap.scan_tasks.clear()
        autonmap.scan_jobs.clear()
        autonmap.rate_limits.clear()
        self.client = autonmap.app.test_client()
        self.original_keys = list(autonmap.API_AUTH_KEYS)
        self.original_tokens = list(autonmap.API_AUTH_TOKENS)
        autonmap.API_AUTH_KEYS = [
            {
                "id": "reader",
                "label": "Read only",
                "token": "read-token-aaaaaaaa",
                "scopes": ["read"],
                "effective_scopes": ["read"],
                "created_at": "2026-07-16T00:00:00+00:00",
                "revoked": False,
            },
            {
                "id": "scanner",
                "label": "Scanner",
                "token": "scan-token-bbbbbbbb",
                "scopes": ["scan"],
                "effective_scopes": ["read", "scan"],
                "created_at": None,
                "revoked": False,
            },
            {
                "id": "admin",
                "label": "Admin",
                "token": "admin-token-cccccccc",
                "scopes": ["admin"],
                "effective_scopes": ["admin", "read", "scan"],
                "created_at": None,
                "revoked": False,
            },
            {
                "id": "revoked-key",
                "label": "Revoked",
                "token": "revoked-token-dddddd",
                "scopes": ["admin"],
                "effective_scopes": ["admin", "read", "scan"],
                "created_at": None,
                "revoked": True,
            },
        ]
        autonmap.API_AUTH_TOKENS = [
            key["token"] for key in autonmap.API_AUTH_KEYS if not key["revoked"]
        ]

    async def asyncTearDown(self):
        autonmap.API_AUTH_KEYS = self.original_keys
        autonmap.API_AUTH_TOKENS = self.original_tokens
        autonmap.scan_tasks.clear()
        autonmap.scan_jobs.clear()
        autonmap.rate_limits.clear()

    def test_scope_hierarchy_helpers(self):
        self.assertTrue(autonmap.scopes_allow(["admin"], ["scan", "read"]))
        self.assertTrue(autonmap.scopes_allow(["scan"], ["read"]))
        self.assertFalse(autonmap.scopes_allow(["read"], ["scan"]))
        self.assertEqual(
            sorted(autonmap._expand_scopes(["scan"])),
            ["read", "scan"],
        )
        self.assertEqual(
            sorted(autonmap._expand_scopes(["admin"])),
            ["admin", "read", "scan"],
        )

    def test_load_named_keys_from_env(self):
        raw = json.dumps(
            [
                {
                    "id": "ops",
                    "label": "Ops",
                    "token": "named-ops-token-1",
                    "scopes": ["scan", "read"],
                    "created_at": "2026-01-01T00:00:00Z",
                },
                {
                    "id": "viewer",
                    "token": "named-view-token-2",
                    "scopes": "read",
                    "revoked": True,
                },
            ]
        )
        with mock.patch.dict(
            os.environ,
            {
                "API_AUTH_KEYS": raw,
                "API_AUTH_TOKEN": "",
                "API_AUTH_TOKENS": "",
            },
            clear=False,
        ):
            keys = autonmap._load_api_auth_keys()
        self.assertEqual(len(keys), 2)
        self.assertEqual(keys[0]["id"], "ops")
        self.assertEqual(keys[0]["label"], "Ops")
        self.assertIn("scan", keys[0]["scopes"])
        self.assertTrue(keys[1]["revoked"])

        with mock.patch.dict(
            os.environ,
            {"API_AUTH_KEYS": '{"not":"list"}', "API_AUTH_TOKEN": "x", "API_AUTH_TOKENS": ""},
            clear=False,
        ):
            with self.assertRaises(RuntimeError):
                autonmap._load_api_auth_keys()

    async def test_whoami_and_scope_enforcement(self):
        who = await self.client.get("/auth/whoami", headers={"X-API-KEY": "read-token-aaaaaaaa"})
        who_payload = await who.get_json()
        self.assertEqual(who.status_code, 200)
        self.assertEqual(who_payload["key_id"], "reader")
        self.assertEqual(who_payload["label"], "Read only")
        self.assertIn("read", who_payload["scopes"])
        self.assertNotIn("scan", who_payload["scopes"])

        read_ok = await self.client.get("/results", headers={"X-API-KEY": "read-token-aaaaaaaa"})
        self.assertEqual(read_ok.status_code, 200)

        scan_denied = await self.client.post(
            "/scan",
            headers={"X-API-KEY": "read-token-aaaaaaaa"},
            json={"target": "127.0.0.1", "scan_type": "Ping"},
        )
        denied_payload = await scan_denied.get_json()
        self.assertEqual(scan_denied.status_code, 403)
        self.assertIn("scope", denied_payload["error"].lower())

        async def fake_create(*_a, **_k):
            return {
                "job_id": "job-scoped",
                "target": "127.0.0.1",
                "scan_type": "Ping",
                "status": "queued",
                "created_at": "now",
                "kind": "immediate",
            }

        original = autonmap.create_scan_job
        autonmap.create_scan_job = fake_create
        try:
            scan_ok = await self.client.post(
                "/scan",
                headers={"X-API-KEY": "scan-token-bbbbbbbb"},
                json={"target": "127.0.0.1", "scan_type": "Ping"},
            )
        finally:
            autonmap.create_scan_job = original
        self.assertEqual(scan_ok.status_code, 202)

        revoked = await self.client.get(
            "/auth/whoami", headers={"X-API-KEY": "revoked-token-dddddd"}
        )
        self.assertEqual(revoked.status_code, 403)


class TargetAllowlistTests(unittest.TestCase):
    def test_empty_allowlist_permits_any_valid_target(self):
        self.assertTrue(autonmap.target_in_allowlist("8.8.8.8", allowlist=[]))
        self.assertIsNone(autonmap.target_allowlist_error("evil.example", allowlist=[]))

    def test_ip_and_cidr_rules(self):
        rules = ["127.0.0.1", "10.0.0.0/8", "192.0.2.0/24"]
        self.assertTrue(autonmap.target_in_allowlist("127.0.0.1", allowlist=rules))
        self.assertTrue(autonmap.target_in_allowlist("10.1.2.3", allowlist=rules))
        self.assertTrue(autonmap.target_in_allowlist("10.0.0.0/16", allowlist=rules))
        self.assertTrue(autonmap.target_in_allowlist("192.0.2.10", allowlist=rules))
        self.assertFalse(autonmap.target_in_allowlist("8.8.8.8", allowlist=rules))
        self.assertFalse(autonmap.target_in_allowlist("172.16.0.0/12", allowlist=rules))
        error = autonmap.target_allowlist_error("8.8.8.8", allowlist=rules)
        self.assertIn("allowlist", error.lower())

    def test_hostname_and_wildcard_rules(self):
        rules = ["localhost", "lab.example.com", "*.corp.example"]
        self.assertTrue(autonmap.target_in_allowlist("localhost", allowlist=rules))
        self.assertTrue(autonmap.target_in_allowlist("LAB.EXAMPLE.COM", allowlist=rules))
        self.assertTrue(autonmap.target_in_allowlist("app.corp.example", allowlist=rules))
        self.assertFalse(autonmap.target_in_allowlist("corp.example", allowlist=rules))
        self.assertFalse(autonmap.target_in_allowlist("evil.com", allowlist=rules))
        # IP-shaped rules must not match hostnames by string equality alone.
        self.assertFalse(autonmap.target_in_allowlist("lab.example.com", allowlist=["10.0.0.0/8"]))

    def test_payload_validation_enforces_allowlist(self):
        original = list(autonmap.TARGET_ALLOWLIST)
        autonmap.TARGET_ALLOWLIST[:] = ["127.0.0.1"]
        try:
            *_, ok_error = autonmap._validate_scan_payload(
                {"target": "127.0.0.1", "scan_type": "Ping"}
            )
            *_, denied = autonmap._validate_scan_payload(
                {"target": "192.0.2.1", "scan_type": "Ping"}
            )
        finally:
            autonmap.TARGET_ALLOWLIST[:] = original

        self.assertIsNone(ok_error)
        self.assertIn("allowlist", denied.lower())

    def test_load_target_allowlist_from_env_and_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "scope.txt"
            path.write_text("# engagement\n10.0.0.0/8\nlab.local\n\n", encoding="utf-8")
            with mock.patch.dict(
                os.environ,
                {
                    "TARGET_ALLOWLIST": "127.0.0.1, 127.0.0.1",
                    "TARGET_ALLOWLIST_FILE": str(path),
                },
                clear=False,
            ):
                loaded = autonmap._load_target_allowlist()
        self.assertEqual(loaded, ["127.0.0.1", "10.0.0.0/8", "lab.local"])

        with mock.patch.dict(
            os.environ,
            {"TARGET_ALLOWLIST": '["192.0.2.1"]', "TARGET_ALLOWLIST_FILE": ""},
            clear=False,
        ):
            self.assertEqual(autonmap._load_target_allowlist(), ["192.0.2.1"])

        with mock.patch.dict(
            os.environ,
            {"TARGET_ALLOWLIST": "[not-json", "TARGET_ALLOWLIST_FILE": ""},
            clear=False,
        ):
            with self.assertRaises(RuntimeError):
                autonmap._load_target_allowlist()

        with mock.patch.dict(
            os.environ,
            {
                "TARGET_ALLOWLIST": "",
                "TARGET_ALLOWLIST_FILE": "/tmp/recon-operator-missing-allowlist.txt",
            },
            clear=False,
        ):
            with self.assertRaises(RuntimeError):
                autonmap._load_target_allowlist()


class PayloadHardeningRegressionTests(unittest.TestCase):
    def test_non_finite_intervals_are_rejected(self):
        for interval in (math.nan, math.inf, -math.inf):
            with self.subTest(interval=interval):
                *_, error = autonmap._validate_scan_payload(
                    {"target": "127.0.0.1", "scan_type": "Ping", "interval": interval}
                )

                self.assertEqual(error, "interval must be a finite number")

    def test_targets_are_canonicalized_before_task_ids_are_built(self):
        cases = {
            "LOCALHOST": "localhost",
            "Example.COM": "example.com",
            "192.0.2.7/24": "192.0.2.0/24",
            "2001:0db8::1": "2001:db8::1",
        }

        for supplied, expected in cases.items():
            with self.subTest(target=supplied):
                target, _, _, _, _, _, error = autonmap._validate_scan_payload(
                    {"target": supplied, "scan_type": "Ping", "interval": 5}
                )

                self.assertIsNone(error)
                self.assertEqual(target, expected)


class CacheSingleFlightRegressionTests(unittest.TestCase):
    def test_concurrent_cache_misses_build_inventory_once(self):
        original_builder = autonmap.build_tool_inventory
        original_cache = dict(autonmap.tool_inventory_cache)
        calls = 0
        calls_lock = threading.Lock()
        start = threading.Barrier(8)

        def fake_builder(expand=False):
            nonlocal calls
            with calls_lock:
                calls += 1
            time.sleep(0.05)
            return {"expand": expand}

        def load_inventory(_index):
            start.wait(timeout=2)
            return autonmap.get_cached_tool_inventory(False)

        autonmap.tool_inventory_cache.clear()
        autonmap.build_tool_inventory = fake_builder
        try:
            with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
                results = list(pool.map(load_inventory, range(8)))
        finally:
            autonmap.build_tool_inventory = original_builder
            autonmap.tool_inventory_cache.clear()
            autonmap.tool_inventory_cache.update(original_cache)

        self.assertEqual(calls, 1)
        self.assertEqual(results, [{"expand": False}] * 8)


class AuthAndCoverageRegressionTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        autonmap.scan_tasks.clear()
        autonmap.scan_jobs.clear()
        autonmap.rate_limits.clear()
        self.client = autonmap.app.test_client()

    def test_multi_token_authorization(self):
        original = list(autonmap.API_AUTH_TOKENS)
        autonmap.API_AUTH_TOKENS = ["alpha-token-111", "beta-token-2222"]
        try:
            self.assertTrue(autonmap._token_is_authorized("alpha-token-111"))
            self.assertTrue(autonmap._token_is_authorized("beta-token-2222"))
            self.assertFalse(autonmap._token_is_authorized("nope"))
            self.assertFalse(autonmap._token_is_authorized("alpha-token-11"))
        finally:
            autonmap.API_AUTH_TOKENS = original

    async def test_invalid_token_is_rejected(self):
        response = await self.client.get("/tasks", headers={"X-API-KEY": "wrong-token"})
        payload = await response.get_json()
        self.assertEqual(response.status_code, 403)
        self.assertIn("Invalid", payload["error"])

    async def test_schedule_create_list_and_cancel(self):
        async def noop_periodic(*_args, **_kwargs):
            await asyncio.Event().wait()

        original = autonmap.periodic_scan
        autonmap.periodic_scan = noop_periodic
        # Shared test DB may retain schedules from earlier cases.
        for row in list(autonmap.state_store.list_scheduled_tasks()):
            try:
                autonmap.state_store.delete_scheduled_task(row["task_id"])
            except Exception:
                pass
        try:
            create = await self.client.post(
                "/schedule",
                headers={"X-API-KEY": "test-token"},
                json={"target": "127.0.0.1", "scan_type": "Ping", "interval": 30},
            )
            created = await create.get_json()
            self.assertEqual(create.status_code, 200, created)
            task_id = created["task_id"]
            self.assertTrue(task_id.startswith("o"))

            listed = await self.client.get("/tasks", headers={"X-API-KEY": "test-token"})
            listed_payload = await listed.get_json()
            self.assertTrue(any(item["id"] == task_id for item in listed_payload))

            cancelled = await self.client.delete(
                f"/tasks/{task_id}", headers={"X-API-KEY": "test-token"}
            )
            self.assertEqual(cancelled.status_code, 200)
        finally:
            autonmap.periodic_scan = original
            for task in list(autonmap.scan_tasks.values()):
                task.cancel()
            autonmap.scan_tasks.clear()
            for row in list(autonmap.state_store.list_scheduled_tasks()):
                try:
                    autonmap.state_store.delete_scheduled_task(row["task_id"])
                except Exception:
                    pass

    def test_result_visibility_by_owner_prefix(self):
        owner_a = autonmap.owner_id_from_token("token-a-aaaaaaaa")
        owner_b = autonmap.owner_id_from_token("token-b-bbbbbbbb")
        file_a = f"{autonmap.owner_result_prefix(owner_a)}host_Ping_20260101_000000_1.json"
        file_b = f"{autonmap.owner_result_prefix(owner_b)}host_Ping_20260101_000000_2.json"
        legacy = "legacy_Ping_20260101_000000_3.json"
        self.assertTrue(autonmap.result_visible_to_owner(file_a, owner_a))
        self.assertFalse(autonmap.result_visible_to_owner(file_b, owner_a))
        # Default LEGACY_RESULTS_SHARED=true keeps pre-ownership files visible.
        original_legacy = autonmap.LEGACY_RESULTS_SHARED
        try:
            autonmap.LEGACY_RESULTS_SHARED = True
            self.assertTrue(autonmap.result_visible_to_owner(legacy, owner_a))
            autonmap.LEGACY_RESULTS_SHARED = False
            self.assertFalse(autonmap.result_visible_to_owner(legacy, owner_a))
            self.assertTrue(autonmap.result_visible_to_owner(file_a, owner_a))
        finally:
            autonmap.LEGACY_RESULTS_SHARED = original_legacy

    async def test_rate_limit_blocks_excess_requests(self):
        original_max = autonmap.MAX_REQUESTS_PER_WINDOW
        original_key = autonmap._client_key
        autonmap.MAX_REQUESTS_PER_WINDOW = 1
        autonmap._client_key = lambda: "rate-test-client"
        autonmap.rate_limits.clear()
        try:
            first = await self.client.get("/tools", headers={"X-API-KEY": "test-token"})
            second = await self.client.get("/tools", headers={"X-API-KEY": "test-token"})
        finally:
            autonmap.MAX_REQUESTS_PER_WINDOW = original_max
            autonmap._client_key = original_key
            autonmap.rate_limits.clear()

        self.assertEqual(first.status_code, 200)
        self.assertEqual(second.status_code, 429)

    async def test_result_path_traversal_is_rejected(self):
        response = await self.client.get(
            "/results/../secrets.json",
            headers={"X-API-KEY": "test-token"},
        )
        self.assertEqual(response.status_code, 404)

    async def test_load_persisted_state_requeues_expired_inflight(self):
        original_results = list(autonmap.scan_jobs.items())
        autonmap.scan_jobs.clear()

        def fake_list_jobs(limit=200):
            return [
                {
                    "job_id": "inflight-1",
                    "target": "127.0.0.1",
                    "scan_type": "Ping",
                    "status": "running",
                    "kind": "immediate",
                    "created_at": "t0",
                    "lease_owner": "old-worker",
                    "lease_until": time.time() - 10,
                    "task": None,
                }
            ]

        def fake_list_tasks():
            return []

        original_jobs = autonmap.state_store.list_jobs
        original_tasks = autonmap.state_store.list_scheduled_tasks
        original_upsert = autonmap.state_store.upsert_job
        autonmap.state_store.list_jobs = fake_list_jobs
        autonmap.state_store.list_scheduled_tasks = fake_list_tasks
        autonmap.state_store.upsert_job = mock.Mock()
        try:
            await autonmap.load_persisted_state()
            self.assertEqual(autonmap.scan_jobs["inflight-1"]["status"], "running")
            autonmap.state_store.upsert_job.assert_not_called()
        finally:
            autonmap.state_store.list_jobs = original_jobs
            autonmap.state_store.list_scheduled_tasks = original_tasks
            autonmap.state_store.upsert_job = original_upsert
            autonmap.scan_jobs.clear()
            for key, value in original_results:
                autonmap.scan_jobs[key] = value

    def test_retention_by_age(self):
        original_age = autonmap.RESULTS_MAX_AGE_DAYS
        original_max = autonmap.RESULTS_MAX_FILES
        autonmap.RESULTS_MAX_AGE_DAYS = 1
        autonmap.RESULTS_MAX_FILES = 100
        try:
            with tempfile.TemporaryDirectory() as tmp:
                old = Path(tmp) / "old_Ping_20260101_000000_1.json"
                new = Path(tmp) / "new_Ping_20260102_000000_1.json"
                old.write_bytes(b"old")
                new.write_bytes(b"new")
                now = time.time()
                os.utime(old, (now - 3 * 86400, now - 3 * 86400))
                os.utime(new, (now, now))
                summary = autonmap.apply_results_retention(tmp)
                names = {path.name for path in Path(tmp).glob("*.json")}
        finally:
            autonmap.RESULTS_MAX_AGE_DAYS = original_age
            autonmap.RESULTS_MAX_FILES = original_max

        self.assertEqual(summary["deleted"], 1)
        self.assertEqual(names, {"new_Ping_20260102_000000_1.json"})


class ReadinessRegressionTests(unittest.IsolatedAsyncioTestCase):
    async def test_health_returns_service_unavailable_without_nmap(self):
        original_check = autonmap._check_nmap_available
        autonmap._check_nmap_available = lambda: False
        try:
            response = await autonmap.app.test_client().get("/health")
            payload = await response.get_json()
        finally:
            autonmap._check_nmap_available = original_check

        self.assertEqual(response.status_code, 503)
        self.assertEqual(payload["status"], "unhealthy")
        self.assertFalse(payload["nmap_available"])
        self.assertFalse(payload["ready"])

    async def test_liveness_stays_up_without_nmap(self):
        original_check = autonmap._check_nmap_available
        autonmap._check_nmap_available = lambda: False
        client = autonmap.app.test_client()
        try:
            live = await client.get("/live")
            ready = await client.get("/ready")
            live_payload = await live.get_json()
            ready_payload = await ready.get_json()
        finally:
            autonmap._check_nmap_available = original_check

        self.assertEqual(live.status_code, 200)
        self.assertEqual(live_payload["status"], "live")
        self.assertEqual(ready.status_code, 503)
        self.assertEqual(ready_payload["status"], "not_ready")

    async def test_openapi_document_is_valid_shape(self):
        response = await autonmap.app.test_client().get("/openapi.json")
        payload = await response.get_json()
        self.assertEqual(response.status_code, 200)
        self.assertEqual(payload["openapi"], "3.0.3")
        self.assertIn("/scan", payload["paths"])
        self.assertIn("/live", payload["paths"])
        self.assertIn("ApiKeyAuth", payload["components"]["securitySchemes"])


class ReleaseDCoverageTests(unittest.IsolatedAsyncioTestCase):
    """Coverage sprint for Release D: jobs, tools, planner, ownership edges."""

    async def asyncSetUp(self):
        autonmap.scan_tasks.clear()
        autonmap.scan_jobs.clear()
        autonmap.rate_limits.clear()
        self.client = autonmap.app.test_client()
        self.headers = {"X-API-KEY": "test-token"}

    async def asyncTearDown(self):
        for task in list(autonmap.scan_tasks.values()):
            task.cancel()
        autonmap.scan_tasks.clear()
        autonmap.scan_jobs.clear()
        autonmap.rate_limits.clear()

    def test_parse_helpers_and_token_loader(self):
        self.assertTrue(autonmap._parse_bool_env("MISSING_BOOL_FOR_TEST", True))
        with mock.patch.dict(os.environ, {"BOOL_TEST_FLAG": "yes"}, clear=False):
            self.assertTrue(autonmap._parse_bool_env("BOOL_TEST_FLAG", False))
        with mock.patch.dict(os.environ, {"BOOL_TEST_FLAG": "0"}, clear=False):
            self.assertFalse(autonmap._parse_bool_env("BOOL_TEST_FLAG", True))
        with mock.patch.dict(os.environ, {"BOOL_TEST_FLAG": "maybe"}, clear=False):
            with self.assertRaises(RuntimeError):
                autonmap._parse_bool_env("BOOL_TEST_FLAG", True)

        with mock.patch.dict(os.environ, {"INT_TEST_FLAG": "12"}, clear=False):
            self.assertEqual(
                autonmap._parse_int_env("INT_TEST_FLAG", 1, min_value=1, max_value=20), 12
            )
        with mock.patch.dict(os.environ, {"INT_TEST_FLAG": "nope"}, clear=False):
            with self.assertRaises(RuntimeError):
                autonmap._parse_int_env("INT_TEST_FLAG", 1)
        with mock.patch.dict(os.environ, {"INT_TEST_FLAG": "0"}, clear=False):
            with self.assertRaises(RuntimeError):
                autonmap._parse_int_env("INT_TEST_FLAG", 1, min_value=1)
        with mock.patch.dict(os.environ, {"INT_TEST_FLAG": "99"}, clear=False):
            with self.assertRaises(RuntimeError):
                autonmap._parse_int_env("INT_TEST_FLAG", 1, max_value=10)

        with mock.patch.dict(
            os.environ,
            {"API_AUTH_TOKENS": '["tok-a","tok-b"]', "API_AUTH_TOKEN": "tok-c"},
            clear=False,
        ):
            tokens = autonmap._load_api_auth_tokens()
        self.assertEqual(tokens, ["tok-a", "tok-b", "tok-c"])

        with mock.patch.dict(
            os.environ,
            {"API_AUTH_TOKENS": "alpha, beta, alpha", "API_AUTH_TOKEN": ""},
            clear=False,
        ):
            self.assertEqual(autonmap._load_api_auth_tokens(), ["alpha", "beta"])

        with mock.patch.dict(
            os.environ, {"API_AUTH_TOKENS": "{bad", "API_AUTH_TOKEN": ""}, clear=False
        ):
            # Non-JSON multi form is treated as a single comma-separated token.
            self.assertEqual(autonmap._load_api_auth_tokens(), ["{bad"])

        with mock.patch.dict(
            os.environ, {"API_AUTH_TOKENS": "[not-json", "API_AUTH_TOKEN": ""}, clear=False
        ):
            with self.assertRaises(RuntimeError):
                autonmap._load_api_auth_tokens()

        self.assertEqual(autonmap._parse_optional_limit(None, 50, 500), 50)
        self.assertEqual(autonmap._parse_optional_limit("abc", 50, 500), 50)
        self.assertEqual(autonmap._parse_optional_limit("0", 50, 500), 50)
        self.assertEqual(autonmap._parse_optional_limit("999", 50, 100), 100)
        self.assertEqual(autonmap._parse_optional_limit("7", 50, 500), 7)

        self.assertIsNone(autonmap._normalize_scan_type(""))
        self.assertIsNone(autonmap._normalize_scan_type("Nope"))
        self.assertEqual(autonmap._normalize_scan_type("ping"), "Ping")
        self.assertIn("'Ping'", autonmap.get_scan_type_choices())

        args = autonmap.build_scan_args("Ping")
        self.assertIn("Ping", args)
        with self.assertRaises(ValueError):
            autonmap.build_scan_args("NotAType")

        self.assertFalse(autonmap.validate_ip_or_host(""))
        self.assertFalse(autonmap.validate_ip_or_host("host;rm"))
        self.assertFalse(autonmap.validate_ip_or_host("a" * 300))
        self.assertEqual(autonmap._canonicalize_valid_target("Example.COM"), "example.com")

    def test_payload_validation_edge_cases(self):
        *_, error = autonmap._validate_scan_payload(None)
        self.assertIn("body", error.lower())
        *_, error = autonmap._validate_scan_payload({})
        self.assertEqual(error, "target is required")
        *_, error = autonmap._validate_scan_payload({"target": "127.0.0.1", "scan_type": 1})
        self.assertIn("scan_type", error)
        *_, error = autonmap._validate_scan_payload({"target": "127.0.0.1", "scan_type": "Nope"})
        self.assertIn("Invalid scan_type", error)
        *_, error = autonmap._validate_scan_payload(
            {"target": "127.0.0.1", "scan_type": "Ping", "scripts": "bad;script"}
        )
        self.assertIsNotNone(error)
        *_, error = autonmap._validate_scan_payload(
            {"target": "127.0.0.1", "scan_type": "Ping", "discovery": "masscan"}
        )
        self.assertIsNotNone(error)
        *_, error = autonmap._validate_scan_payload(
            {"target": "127.0.0.1", "scan_type": "Ping", "interval": True}
        )
        self.assertEqual(error, "interval must be a number")

    def test_job_and_owner_helpers(self):
        self.assertTrue(autonmap.job_visible_to_owner({"owner_id": None}, "abc"))
        self.assertTrue(autonmap.job_visible_to_owner({"owner_id": "owner-a"}, "owner-a"))
        self.assertFalse(autonmap.job_visible_to_owner({"owner_id": "owner-a"}, "owner-b"))
        task_id = autonmap.make_task_id("127.0.0.1", "Ping", "deadbeefcafe01")
        self.assertTrue(task_id.startswith("odeadbeefcafe-"))
        self.assertEqual(autonmap.owner_result_prefix("deadbeefcafe01"), "odeadbeefcafe_")
        self.assertEqual(autonmap.current_owner_id(), "local")

    def test_rate_limit_evicts_oldest_when_bucket_table_full(self):
        original_limit = autonmap.MAX_RATE_LIMIT_CLIENTS
        original_key = autonmap._client_key
        now = time.time()
        autonmap.MAX_RATE_LIMIT_CLIENTS = 1
        autonmap.rate_limits.clear()
        autonmap.rate_limits["busy"] = [now]
        autonmap._client_key = lambda: "other"
        try:
            allowed = autonmap.check_rate_limit()
        finally:
            autonmap.MAX_RATE_LIMIT_CLIENTS = original_limit
            autonmap._client_key = original_key
            remaining = dict(autonmap.rate_limits)
            autonmap.rate_limits.clear()
        self.assertTrue(allowed)
        self.assertIn("other", remaining)
        self.assertNotIn("busy", remaining)

    async def test_cleanup_finished_task_with_exception(self):
        async def boom():
            raise RuntimeError("task boom")

        task = asyncio.create_task(boom())
        try:
            await task
        except RuntimeError:
            pass
        autonmap.scan_tasks["boom-task"] = task
        removed = autonmap._cleanup_finished_tasks()
        self.assertEqual(removed, ["boom-task"])
        self.assertEqual(autonmap.scan_tasks, {})

    async def test_save_empty_results_returns_none(self):
        self.assertIsNone(await autonmap.save_scan_results_async({}, "127.0.0.1", "Ping"))

    async def test_run_scan_job_failure_and_timeout_paths(self):
        original_scan = autonmap.scan_network
        original_sender = autonmap.send_telegram_message

        async def ignore_message(_message):
            return None

        autonmap.send_telegram_message = ignore_message
        try:
            autonmap.scan_jobs["fail-job"] = {
                "job_id": "fail-job",
                "target": "127.0.0.1",
                "scan_type": "Ping",
                "status": "running",
                "created_at": "t0",
                "started_at": "t1",
                "finished_at": None,
                "error": None,
                "result": None,
                "result_file": None,
                "kind": "immediate",
                "owner_id": "local",
                "task": None,
            }

            def boom(*_a, **_k):
                raise RuntimeError("engine failed")

            autonmap.scan_network = boom
            # already_claimed bypasses SQLite claim (unit path without prior persist).
            await autonmap._run_scan_job("fail-job", already_claimed=True)
            self.assertEqual(autonmap.scan_jobs["fail-job"]["status"], "failed")
            self.assertIn("engine failed", autonmap.scan_jobs["fail-job"]["error"])

            autonmap.scan_jobs["timeout-job"] = {
                "job_id": "timeout-job",
                "target": "127.0.0.1",
                "scan_type": "Ping",
                "status": "running",
                "created_at": "t0",
                "started_at": "t1",
                "finished_at": None,
                "error": None,
                "result": None,
                "result_file": None,
                "kind": "immediate",
                "owner_id": "local",
                "task": None,
            }

            def timeout(*_a, **_k):
                raise TimeoutError("took too long")

            autonmap.scan_network = timeout
            await autonmap._run_scan_job("timeout-job", already_claimed=True)
            self.assertEqual(autonmap.scan_jobs["timeout-job"]["status"], "timeout")
        finally:
            autonmap.scan_network = original_scan
            autonmap.send_telegram_message = original_sender
            autonmap.scan_jobs.clear()

    async def test_async_scan_returns_result_and_raises_on_failure(self):
        original_scan = autonmap.scan_network
        original_sender = autonmap.send_telegram_message
        original_results_dir = autonmap.RESULTS_DIR

        async def ignore_message(_message):
            return None

        def fake_scan(target, scan_type, ports=None, scripts=None, discovery=None, **_k):
            return {"hosts": [], "scan_count": 0, "target": target, "scan_type": scan_type}

        with tempfile.TemporaryDirectory() as tmp:
            autonmap.RESULTS_DIR = tmp
            autonmap.scan_network = fake_scan
            autonmap.send_telegram_message = ignore_message
            try:
                result = await autonmap.async_scan("127.0.0.1", "Ping", owner_id="local")
                self.assertEqual(result["scan_count"], 0)

                def boom(*_a, **_k):
                    raise RuntimeError("async fail")

                autonmap.scan_network = boom
                with self.assertRaises(RuntimeError):
                    await autonmap.async_scan("127.0.0.1", "Ping", owner_id="local")
            finally:
                autonmap.scan_network = original_scan
                autonmap.send_telegram_message = original_sender
                autonmap.RESULTS_DIR = original_results_dir

    async def test_prune_jobs_and_persist_errors(self):
        original_max = autonmap.MAX_SCAN_JOBS
        original_persist = autonmap.state_store.upsert_job
        original_delete = autonmap.state_store.delete_job
        autonmap.MAX_SCAN_JOBS = 2
        autonmap.scan_jobs.clear()
        for index in range(4):
            job_id = f"old-{index}"
            autonmap.scan_jobs[job_id] = {
                "job_id": job_id,
                "target": "127.0.0.1",
                "scan_type": "Ping",
                "status": "completed",
                "created_at": f"t{index}",
                "finished_at": f"t{index}",
                "task": None,
            }

        def boom_delete(_job_id):
            raise RuntimeError("delete failed")

        autonmap.state_store.delete_job = boom_delete
        try:
            async with autonmap._jobs_lock:
                await autonmap._prune_jobs_locked()
            self.assertLessEqual(len(autonmap.scan_jobs), 2)

            def boom_upsert(_job):
                raise RuntimeError("upsert failed")

            autonmap.state_store.upsert_job = boom_upsert
            with self.assertRaisesRegex(RuntimeError, "upsert failed"):
                autonmap._persist_job({"job_id": "x", "status": "completed"})
        finally:
            autonmap.MAX_SCAN_JOBS = original_max
            autonmap.state_store.upsert_job = original_persist
            autonmap.state_store.delete_job = original_delete
            autonmap.scan_jobs.clear()

    async def test_job_ownership_and_cancel_terminal(self):
        owner = autonmap.owner_id_from_token("test-token")
        other = autonmap.owner_id_from_token("other-token")
        autonmap.scan_jobs["owned"] = {
            "job_id": "owned",
            "target": "127.0.0.1",
            "scan_type": "Ping",
            "status": "completed",
            "created_at": "t0",
            "finished_at": "t1",
            "error": None,
            "result": {"hosts": []},
            "result_file": None,
            "kind": "immediate",
            "owner_id": owner,
            "task": None,
        }
        autonmap.scan_jobs["foreign"] = {
            "job_id": "foreign",
            "target": "127.0.0.1",
            "scan_type": "Ping",
            "status": "queued",
            "created_at": "t0",
            "finished_at": None,
            "error": None,
            "result": None,
            "result_file": None,
            "kind": "immediate",
            "owner_id": other,
            "task": None,
        }

        listed = await self.client.get("/jobs", headers=self.headers)
        listed_payload = await listed.get_json()
        ids = {job["job_id"] for job in listed_payload}
        self.assertIn("owned", ids)
        self.assertNotIn("foreign", ids)

        foreign = await self.client.get("/jobs/foreign", headers=self.headers)
        self.assertEqual(foreign.status_code, 404)

        missing = await self.client.get("/jobs/missing-id", headers=self.headers)
        self.assertEqual(missing.status_code, 404)

        cancel_done = await self.client.delete("/jobs/owned", headers=self.headers)
        cancel_payload = await cancel_done.get_json()
        self.assertEqual(cancel_done.status_code, 200)
        self.assertIn("already", cancel_payload["message"].lower())

        unauth = await self.client.get("/jobs")
        self.assertEqual(unauth.status_code, 401)

    async def test_schedule_duplicate_and_validation_errors(self):
        async def noop_periodic(*_args, **_kwargs):
            await asyncio.Event().wait()

        original = autonmap.periodic_scan
        autonmap.periodic_scan = noop_periodic
        for row in list(autonmap.state_store.list_scheduled_tasks()):
            try:
                autonmap.state_store.delete_scheduled_task(row["task_id"])
            except Exception:
                pass
        try:
            first = await self.client.post(
                "/schedule",
                headers=self.headers,
                json={"target": "127.0.0.1", "scan_type": "Ping", "interval": 30},
            )
            first_payload = await first.get_json()
            self.assertEqual(first.status_code, 200, first_payload)
            second = await self.client.post(
                "/schedule",
                headers=self.headers,
                json={"target": "127.0.0.1", "scan_type": "Ping", "interval": 30},
            )
            payload = await second.get_json()
            self.assertEqual(second.status_code, 400)
            self.assertIn("already", payload["error"].lower())

            bad = await self.client.post(
                "/schedule",
                headers=self.headers,
                json={"target": "not a host!!!", "scan_type": "Ping", "interval": 30},
            )
            self.assertEqual(bad.status_code, 400)

            unauth = await self.client.post(
                "/schedule", json={"target": "127.0.0.1", "scan_type": "Ping", "interval": 30}
            )
            self.assertEqual(unauth.status_code, 401)
        finally:
            autonmap.periodic_scan = original
            for row in list(autonmap.state_store.list_scheduled_tasks()):
                try:
                    autonmap.state_store.delete_scheduled_task(row["task_id"])
                except Exception:
                    pass
            for task in list(autonmap.scan_tasks.values()):
                task.cancel()
            autonmap.scan_tasks.clear()

    async def test_tasks_hide_other_owner_and_cancel_missing(self):
        class Pending:
            @staticmethod
            def done():
                return False

            @staticmethod
            def cancelled():
                return False

            @staticmethod
            def cancel():
                return None

        owner = autonmap.owner_id_from_token("test-token")[:12]
        autonmap.scan_tasks[f"o{owner}-127.0.0.1-Ping"] = Pending()
        # Pre-ownership task ids without the o{hash}- prefix stay visible.
        autonmap.scan_tasks["127.0.0.1-legacy-Ping"] = Pending()
        autonmap.scan_tasks["oforeignowner1-127.0.0.1-TCP"] = Pending()

        listed = await self.client.get("/tasks", headers=self.headers)
        payload = await listed.get_json()
        ids = {item["id"] for item in payload}
        self.assertIn(f"o{owner}-127.0.0.1-Ping", ids)
        self.assertIn("127.0.0.1-legacy-Ping", ids)
        self.assertNotIn("oforeignowner1-127.0.0.1-TCP", ids)

        missing = await self.client.delete("/tasks/missing-task", headers=self.headers)
        self.assertEqual(missing.status_code, 404)
        foreign = await self.client.delete(
            "/tasks/oforeignowner1-127.0.0.1-TCP", headers=self.headers
        )
        self.assertEqual(foreign.status_code, 404)

    async def test_legacy_results_hidden_when_flag_off(self):
        original_flag = autonmap.LEGACY_RESULTS_SHARED
        original_dir = autonmap.RESULTS_DIR
        sample = {"hosts": [], "scan_count": 0}
        encrypted = autonmap.cipher.encrypt(b'{"hosts":[]}')
        with tempfile.TemporaryDirectory() as tmp:
            autonmap.RESULTS_DIR = tmp
            legacy = Path(tmp) / "legacy_Ping_20260101_000000_1.json"
            legacy.write_bytes(encrypted)
            owned_name = (
                f"{autonmap.owner_result_prefix(autonmap.owner_id_from_token('test-token'))}"
                f"host_Ping_20260101_000000_2.json"
            )
            (Path(tmp) / owned_name).write_bytes(encrypted)
            try:
                autonmap.LEGACY_RESULTS_SHARED = False
                listed = await self.client.get("/results", headers=self.headers)
                payload = await listed.get_json()
                names = {item["id"] for item in payload["results"]}
                self.assertNotIn(legacy.name, names)
                self.assertIn(owned_name, names)

                hidden = await self.client.get(f"/results/{legacy.name}", headers=self.headers)
                self.assertEqual(hidden.status_code, 404)

                autonmap.LEGACY_RESULTS_SHARED = True
                listed_shared = await self.client.get("/results", headers=self.headers)
                shared_payload = await listed_shared.get_json()
                shared_names = {item["id"] for item in shared_payload["results"]}
                self.assertIn(legacy.name, shared_names)
            finally:
                autonmap.LEGACY_RESULTS_SHARED = original_flag
                autonmap.RESULTS_DIR = original_dir

        # silence unused
        self.assertEqual(sample["scan_count"], 0)

    async def test_get_result_corrupt_and_bad_token_payload(self):
        original_dir = autonmap.RESULTS_DIR
        with tempfile.TemporaryDirectory() as tmp:
            autonmap.RESULTS_DIR = tmp
            name = (
                f"{autonmap.owner_result_prefix(autonmap.owner_id_from_token('test-token'))}"
                f"host_Ping_20260101_000000_9.json"
            )
            path = Path(tmp) / name
            path.write_bytes(b"not-a-fernet-token")
            try:
                response = await self.client.get(f"/results/{name}", headers=self.headers)
                payload = await response.get_json()
                self.assertEqual(response.status_code, 500)
                self.assertIn("decrypt", payload["error"].lower())
            finally:
                autonmap.RESULTS_DIR = original_dir

    async def test_diff_by_result_id_and_import_raw_xml(self):
        sample_xml = """<?xml version="1.0"?>
<nmaprun scanner="nmap" args="nmap" start="1" version="7.95" xmloutputversion="1.05">
  <host>
    <status state="up"/>
    <address addr="192.0.2.20" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="443"><state state="open"/><service name="https"/></port>
    </ports>
  </host>
</nmaprun>
"""
        original_dir = autonmap.RESULTS_DIR
        original_sender = autonmap.send_telegram_message

        async def ignore_message(_message):
            return None

        with tempfile.TemporaryDirectory() as tmp:
            autonmap.RESULTS_DIR = tmp
            autonmap.send_telegram_message = ignore_message
            try:
                import_response = await self.client.post(
                    "/results/import?target=192.0.2.20",
                    headers={**self.headers, "Content-Type": "application/xml"},
                    data=sample_xml.encode("utf-8"),
                )
                import_payload = await import_response.get_json()
                self.assertEqual(import_response.status_code, 201)
                result_id = import_payload["id"]

                bad_import = await self.client.post(
                    "/results/import",
                    headers=self.headers,
                    json={"xml": 123},
                )
                self.assertEqual(bad_import.status_code, 400)

                empty_import = await self.client.post(
                    "/results/import",
                    headers={**self.headers, "Content-Type": "application/xml"},
                    data=b"",
                )
                self.assertEqual(empty_import.status_code, 400)

                baseline = {
                    "hosts": [
                        {
                            "host": "192.0.2.20",
                            "hostname": "N/A",
                            "state": "up",
                            "protocols": {},
                        }
                    ]
                }
                diff_response = await self.client.post(
                    "/results/diff",
                    headers=self.headers,
                    json={"baseline": baseline, "current": {"id": result_id}},
                )
                self.assertEqual(diff_response.status_code, 200)

                bad_diff = await self.client.post(
                    "/results/diff",
                    headers=self.headers,
                    json={"baseline": "missing.json", "current": baseline},
                )
                self.assertEqual(bad_diff.status_code, 400)

                no_body = await self.client.post(
                    "/results/diff",
                    headers={**self.headers, "Content-Type": "text/plain"},
                    data=b"not-json",
                )
                self.assertEqual(no_body.status_code, 400)
            finally:
                autonmap.RESULTS_DIR = original_dir
                autonmap.send_telegram_message = original_sender

    async def test_tools_ai_context_and_recon_plan_formats(self):
        inventory = {
            "schema": "pentest-tool-inventory/v1",
            "summary": {
                "packages_checked": 0,
                "available": 0,
                "missing": 0,
                "missing_packages": [],
            },
            "packages": [],
            "tools": [],
            "profiles": [{"profile": "core", "install": "kali-linux-core"}],
            "ai_handoff": {"prompt_hint": "use available tools only"},
        }
        original = autonmap.get_cached_tool_inventory
        autonmap.get_cached_tool_inventory = lambda expand=False: inventory
        try:
            jsonl = await self.client.get("/tools/ai-context", headers=self.headers)
            self.assertEqual(jsonl.status_code, 200)
            self.assertIn("ndjson", jsonl.headers.get("Content-Type", ""))

            md = await self.client.get("/tools/ai-context?format=markdown", headers=self.headers)
            self.assertEqual(md.status_code, 200)
            self.assertIn("markdown", md.headers.get("Content-Type", ""))

            plan = await self.client.post(
                "/recon/plan",
                headers=self.headers,
                json={
                    "hosts": [
                        {
                            "host": "192.0.2.30",
                            "hostname": "N/A",
                            "state": "up",
                            "protocols": {"tcp": [{"port": 80, "state": "open", "name": "http"}]},
                        }
                    ]
                },
            )
            self.assertEqual(plan.status_code, 200)

            plan_md = await self.client.post(
                "/recon/plan?format=md",
                headers=self.headers,
                json={
                    "hosts": [
                        {
                            "host": "192.0.2.30",
                            "hostname": "N/A",
                            "state": "up",
                            "protocols": {"tcp": [{"port": 22, "state": "open", "name": "ssh"}]},
                        }
                    ]
                },
            )
            self.assertEqual(plan_md.status_code, 200)
            self.assertIn("markdown", plan_md.headers.get("Content-Type", ""))

            plan_jsonl = await self.client.post(
                "/recon/plan?format=jsonl",
                headers=self.headers,
                json={
                    "hosts": [
                        {
                            "host": "192.0.2.30",
                            "hostname": "N/A",
                            "state": "up",
                            "protocols": {"tcp": [{"port": 443, "state": "open", "name": "https"}]},
                        }
                    ]
                },
            )
            self.assertEqual(plan_jsonl.status_code, 200)

            bad_plan = await self.client.post(
                "/recon/plan", headers=self.headers, json={"no_hosts": True}
            )
            self.assertEqual(bad_plan.status_code, 400)
            not_json = await self.client.post(
                "/recon/plan",
                headers={**self.headers, "Content-Type": "text/plain"},
                data=b"x",
            )
            self.assertEqual(not_json.status_code, 400)
        finally:
            autonmap.get_cached_tool_inventory = original

    async def test_api_docs_and_scan_validation_errors(self):
        docs = await self.client.get("/api/docs")
        payload = await docs.get_json()
        self.assertEqual(docs.status_code, 200)
        self.assertEqual(payload["version"], autonmap.VERSION)
        self.assertIn("POST /scan", payload["endpoints"])

        bad_scan = await self.client.post(
            "/scan", headers=self.headers, json={"target": "bad host!!"}
        )
        self.assertEqual(bad_scan.status_code, 400)

        unauth = await self.client.post("/scan", json={"target": "127.0.0.1"})
        self.assertEqual(unauth.status_code, 401)

        health = await self.client.get("/health")
        # nmap may or may not be available; payload shape matters
        health_payload = await health.get_json()
        self.assertIn("legacy_results_shared", health_payload)
        self.assertIn(health.status_code, {200, 503})

    async def test_load_initial_tasks_and_persisted_schedules(self):
        async def noop_periodic(*_args, **_kwargs):
            await asyncio.Event().wait()

        original_periodic = autonmap.periodic_scan
        original_env = os.environ.get("INITIAL_TASKS")
        autonmap.periodic_scan = noop_periodic
        try:
            os.environ["INITIAL_TASKS"] = "[]"
            await autonmap.load_initial_tasks()

            os.environ["INITIAL_TASKS"] = "not-json"
            await autonmap.load_initial_tasks()

            os.environ["INITIAL_TASKS"] = '{"not":"list"}'
            await autonmap.load_initial_tasks()

            os.environ["INITIAL_TASKS"] = json.dumps(
                [
                    {"target": "127.0.0.1", "scan_type": "Ping", "interval": 45},
                    "bad-entry",
                    {"target": "%%%", "scan_type": "Ping"},
                ]
            )
            await autonmap.load_initial_tasks()
            registered_rows = autonmap.state_store.list_scheduled_tasks()
            registered = {row["task_id"] for row in registered_rows}
            self.assertTrue(any("Ping" in task_id for task_id in registered))
            ping_row = next(row for row in registered_rows if row["scan_type"] == "Ping")
            self.assertEqual(
                ping_row["owner_id"],
                autonmap.owner_id_from_token("test-token"),
            )
            # Schedules are durable-only until a leader syncs them into memory.
            self.assertFalse(any("Ping" in task_id for task_id in autonmap.scan_tasks))

            def fake_list_tasks():
                return [
                    {
                        "task_id": "orestoredlocal-127.0.0.1-TCP",
                        "target": "127.0.0.1",
                        "scan_type": "TCP",
                        "interval_minutes": 60,
                        "ports": None,
                        "scripts": None,
                        "discovery": None,
                        "owner_id": "local",
                    }
                ]

            original_list = autonmap.state_store.list_scheduled_tasks
            original_jobs = autonmap.state_store.list_jobs
            original_leader = autonmap._is_scheduler_leader
            autonmap.state_store.list_scheduled_tasks = fake_list_tasks
            autonmap.state_store.list_jobs = lambda limit=200: []
            try:
                await autonmap.load_persisted_state()
                self.assertNotIn("orestoredlocal-127.0.0.1-TCP", autonmap.scan_tasks)
                autonmap._is_scheduler_leader = True
                await autonmap.sync_scheduled_tasks_from_store()
                self.assertIn("orestoredlocal-127.0.0.1-TCP", autonmap.scan_tasks)
            finally:
                autonmap.state_store.list_scheduled_tasks = original_list
                autonmap.state_store.list_jobs = original_jobs
                autonmap._is_scheduler_leader = original_leader
        finally:
            autonmap.periodic_scan = original_periodic
            if original_env is None:
                os.environ.pop("INITIAL_TASKS", None)
            else:
                os.environ["INITIAL_TASKS"] = original_env
            for task in list(autonmap.scan_tasks.values()):
                task.cancel()
            autonmap.scan_tasks.clear()

    async def test_send_telegram_paths_and_nmap_check(self):
        await autonmap.send_telegram_message("no bot configured")

        class FakeBot:
            def __init__(self):
                self.calls = []

            async def send_message(self, chat_id, text):
                self.calls.append((chat_id, text))

        original_bot = autonmap.bot
        original_chat = autonmap.CHAT_ID
        fake = FakeBot()
        autonmap.bot = fake
        autonmap.CHAT_ID = "chat-1"
        try:
            await autonmap.send_telegram_message("hello")
            self.assertEqual(fake.calls, [("chat-1", "hello")])

            class BoomBot:
                async def send_message(self, chat_id, text):
                    raise RuntimeError("network")

            autonmap.bot = BoomBot()
            await autonmap.send_telegram_message("fail path")
        finally:
            autonmap.bot = original_bot
            autonmap.CHAT_ID = original_chat

        with mock.patch("autonmap.shutil.which", return_value=None):
            self.assertFalse(autonmap._check_nmap_available())

        with (
            mock.patch("autonmap.shutil.which", return_value="/usr/bin/nmap"),
            mock.patch(
                "autonmap.subprocess.run",
                side_effect=FileNotFoundError(),
            ),
        ):
            self.assertFalse(autonmap._check_nmap_available())

    async def test_safe_result_path_rejects_bad_names(self):
        self.assertIsNone(autonmap._safe_result_path("../etc/passwd"))
        self.assertIsNone(autonmap._safe_result_path("no-extension"))
        self.assertIsNone(autonmap._safe_result_path("bad name with spaces.json"))

    async def test_scan_wait_internal_error(self):
        original = autonmap.async_scan

        async def boom(*_a, **_k):
            raise RuntimeError("unexpected")

        autonmap.async_scan = boom
        try:
            response = await self.client.post(
                "/scan?wait=1",
                headers=self.headers,
                json={"target": "127.0.0.1", "scan_type": "Ping"},
            )
            payload = await response.get_json()
        finally:
            autonmap.async_scan = original
        self.assertEqual(response.status_code, 500)
        self.assertIn("Internal", payload["error"])

    async def test_periodic_scan_handles_errors_and_cancel(self):
        original_async = autonmap.async_scan
        original_sender = autonmap.send_telegram_message
        calls = {"n": 0}

        async def ignore_message(_message):
            return None

        async def flaky(*_a, **_k):
            calls["n"] += 1
            if calls["n"] == 1:
                raise RuntimeError("first fail")
            raise asyncio.CancelledError()

        original_leader = autonmap._is_scheduler_leader
        autonmap.async_scan = flaky
        autonmap.send_telegram_message = ignore_message
        autonmap._is_scheduler_leader = True
        try:
            await autonmap.periodic_scan("127.0.0.1", "Ping", 0.0001, owner_id="local")
        finally:
            autonmap.async_scan = original_async
            autonmap.send_telegram_message = original_sender
            autonmap._is_scheduler_leader = original_leader
        self.assertGreaterEqual(calls["n"], 1)

        with self.assertRaises(ValueError):
            await autonmap.periodic_scan("127.0.0.1", "Ping", 0)
        with self.assertRaises(ValueError):
            await autonmap.periodic_scan("127.0.0.1", "Ping", "nope")

    async def test_retention_missing_dir_and_result_files_empty(self):
        summary = autonmap.apply_results_retention("/tmp/recon-operator-missing-dir-xyz")
        self.assertEqual(summary, {"deleted": 0, "remaining": 0})
        original = autonmap.RESULTS_DIR
        autonmap.RESULTS_DIR = "/tmp/recon-operator-missing-dir-xyz"
        try:
            self.assertEqual(autonmap._result_files(), [])
        finally:
            autonmap.RESULTS_DIR = original


if __name__ == "__main__":
    unittest.main()
