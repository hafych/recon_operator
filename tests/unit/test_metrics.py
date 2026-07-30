"""Unit tests for the Prometheus metrics registry and scrape surface."""

from __future__ import annotations

import asyncio
import os
import time
import unittest

os.environ.setdefault("API_AUTH_REQUIRED", "true")
os.environ.setdefault("API_AUTH_TOKEN", "test-token")
os.environ.setdefault("FERNET_KEY", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")
os.environ.setdefault("SCAN_LOG_PATH", "/tmp/nmap-automator-metrics.log")
os.environ.setdefault("STATE_DB_PATH", "/tmp/recon-operator-metrics.db")

import autonmap
from recon_operator.metrics import MetricsRegistry


class MetricsRegistryTests(unittest.TestCase):
    def test_counters_gauges_histogram_render_prometheus(self):
        reg = MetricsRegistry(duration_buckets=(1.0, 5.0, 30.0))
        reg.inc("recon_operator_jobs_created_total", kind="immediate")
        reg.inc("recon_operator_jobs_finished_total", status="completed", scan_type="Ping")
        reg.set_gauge("recon_operator_jobs_queued", 2)
        reg.observe(
            "recon_operator_scan_duration_seconds", 2.5, scan_type="Ping", status="completed"
        )
        text = reg.render_prometheus(info_labels={"version": "test", "product": "Recon Operator"})
        self.assertIn("# TYPE recon_operator_jobs_created_total counter", text)
        self.assertIn('recon_operator_jobs_created_total{kind="immediate"} 1', text)
        self.assertIn(
            'recon_operator_jobs_finished_total{scan_type="Ping",status="completed"} 1',
            text,
        )
        self.assertIn("recon_operator_jobs_queued 2", text)
        self.assertIn("recon_operator_scan_duration_seconds_count", text)
        self.assertIn('le="5"', text)
        self.assertIn('le="+Inf"', text)
        self.assertIn('product="Recon Operator"', text)
        self.assertIn("recon_operator_up 1", text)


class MetricsEndpointTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        autonmap.scan_jobs.clear()
        autonmap.scan_tasks.clear()
        autonmap.rate_limits.clear()
        autonmap.METRICS.reset()
        self.client = autonmap.app.test_client()

    async def test_metrics_endpoint_exposes_job_activity_series(self):
        # Drive the shipped create_scan_job path so counters update for real.
        original_run = autonmap._run_scan_job

        async def fake_run(job_id, *, already_claimed=False):
            await autonmap._set_job_fields(
                job_id,
                status="running",
                started_at=autonmap._utc_now_iso(),
                _metrics_started_mono=time.monotonic(),
            )
            await autonmap._set_job_fields(
                job_id,
                status="completed",
                finished_at=autonmap._utc_now_iso(),
                result={"ok": True},
                error=None,
            )

        autonmap._run_scan_job = fake_run
        try:
            job = await autonmap.create_scan_job("127.0.0.1", "Ping", kind="immediate")
            self.assertEqual(job["status"], "queued")
            # Allow the task to finish.
            await asyncio.sleep(0.05)
            for _ in range(20):
                current = autonmap.scan_jobs.get(job["job_id"])
                if current and current.get("status") == "completed":
                    break
                await asyncio.sleep(0.05)
        finally:
            autonmap._run_scan_job = original_run

        response = await self.client.get("/metrics")
        body = await response.get_data(as_text=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn("text/plain", response.headers.get("Content-Type", ""))
        self.assertIn("recon_operator_jobs_created_total", body)
        self.assertIn("recon_operator_jobs_finished_total", body)
        self.assertIn('status="completed"', body)
        self.assertIn("recon_operator_jobs_queued", body)
        self.assertIn("recon_operator_jobs_running", body)
        self.assertIn("recon_operator_scan_duration_seconds", body)
        self.assertIn(f'version="{autonmap.VERSION}"', body)
        # No secrets in scrape output.
        self.assertNotIn("test-token", body)
        self.assertNotIn(autonmap.FERNET_KEY, body)

        health = await self.client.get("/health")
        payload = await health.get_json()
        self.assertEqual(payload.get("metrics_path"), "/metrics")
        self.assertIn("jobs_queued", payload)
        self.assertIn("jobs_running", payload)

    async def test_openapi_and_docs_advertise_metrics(self):
        openapi = await self.client.get("/openapi.json")
        spec = await openapi.get_json()
        self.assertIn("/metrics", spec.get("paths", {}))

        docs = await self.client.get("/api/docs")
        body = await docs.get_json()
        self.assertEqual(body.get("probes", {}).get("metrics"), "/metrics")
        self.assertIn("GET /metrics", body.get("endpoints", {}))

    async def test_http_counter_and_metrics_openapi_policy_match_runtime(self):
        await self.client.get("/live")
        scrape = await self.client.get("/metrics")
        text = await scrape.get_data(as_text=True)
        self.assertIn("recon_operator_http_requests_total", text)
        self.assertIn('route="/live"', text)

        original = autonmap.METRICS_AUTH_REQUIRED
        try:
            autonmap.METRICS_AUTH_REQUIRED = True
            spec = autonmap.build_openapi_spec()
        finally:
            autonmap.METRICS_AUTH_REQUIRED = original
        self.assertEqual(spec["paths"]["/metrics"]["get"]["security"], [{"ApiKeyAuth": []}])


if __name__ == "__main__":
    unittest.main()
