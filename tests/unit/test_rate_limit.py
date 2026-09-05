"""Unit coverage for recon_operator.rate_limit (source of truth)."""

from __future__ import annotations

import os
import unittest

os.environ.setdefault("API_AUTH_REQUIRED", "true")
os.environ.setdefault("API_AUTH_TOKEN", "test-token")
os.environ.setdefault("FERNET_KEY", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")
os.environ.setdefault("SCAN_LOG_PATH", "/tmp/nmap-automator-ratelimit.log")
os.environ.setdefault("STATE_DB_PATH", "/tmp/recon-operator-ratelimit.db")

import autonmap
import recon_operator.rate_limit as rl


class RateLimitModuleTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.client = autonmap.app.test_client()
        rl.reset_rate_limit_state()
        autonmap.rate_limits.clear()
        self._orig_max = autonmap.MAX_REQUESTS_PER_WINDOW
        self._orig_clients = autonmap.MAX_RATE_LIMIT_CLIENTS
        self._orig_window = autonmap.RATE_LIMIT_WINDOW_SECONDS

    async def asyncTearDown(self):
        autonmap.MAX_REQUESTS_PER_WINDOW = self._orig_max
        autonmap.MAX_RATE_LIMIT_CLIENTS = self._orig_clients
        autonmap.RATE_LIMIT_WINDOW_SECONDS = self._orig_window
        rl.reset_rate_limit_state()
        autonmap.rate_limits.clear()

    def test_shared_state_with_server(self):
        self.assertIs(autonmap.rate_limits, rl.rate_limits)
        self.assertIs(autonmap._rate_limit_lock, rl._rate_limit_lock)
        self.assertEqual(autonmap._REDIS_RATE_LIMIT_LUA, rl._REDIS_RATE_LIMIT_LUA)

    def test_first_valid_ip(self):
        self.assertEqual(rl._first_valid_ip("10.0.0.1, 10.0.0.2"), "10.0.0.1")
        self.assertEqual(rl._first_valid_ip("  not-an-ip , 192.168.1.1 "), "192.168.1.1")
        self.assertIsNone(rl._first_valid_ip(",,,"))
        self.assertIsNone(rl._first_valid_ip("not-an-ip"))
        # IPv4 host:port stripped.
        self.assertEqual(rl._first_valid_ip("10.0.0.5:5000"), "10.0.0.5")

    def test_peer_is_trusted_proxy_rejects_bad(self):
        self.assertFalse(rl._peer_is_trusted_proxy(""))
        self.assertFalse(rl._peer_is_trusted_proxy("unknown"))
        self.assertFalse(rl._peer_is_trusted_proxy("not-an-ip"))
        # Default config has no proxies → loopback is untrusted.
        self.assertFalse(rl._peer_is_trusted_proxy("127.0.0.1"))

    def test_memory_bucket_allows_then_blocks(self):
        autonmap.MAX_REQUESTS_PER_WINDOW = 2
        self.assertTrue(rl._check_rate_limit_memory("bkt"))
        self.assertTrue(rl._check_rate_limit_memory("bkt"))
        self.assertFalse(rl._check_rate_limit_memory("bkt"))

    def test_memory_evicts_when_table_full(self):
        autonmap.MAX_RATE_LIMIT_CLIENTS = 1
        autonmap.MAX_REQUESTS_PER_WINDOW = 10
        rl.rate_limits["busy"] = [9999999999.0]
        self.assertTrue(rl._check_rate_limit_memory("new"))
        self.assertIn("new", rl.rate_limits)

    def test_redis_path_uses_lua(self):
        calls = {}

        class FakeRedis:
            def eval(self, lua, n, key, now, window, limit, member):
                calls["lua"] = lua
                calls["key"] = key
                return 1

        self.assertTrue(rl._check_rate_limit_redis(FakeRedis(), "bkt"))
        self.assertIn("ZREMRANGEBYSCORE", calls["lua"])
        self.assertTrue(calls["key"].endswith("bkt"))

    def test_redis_denied_and_fallback(self):
        class Deny:
            def eval(self, *a, **k):
                return 0

        class Boom:
            def eval(self, *a, **k):
                raise RuntimeError("down")

        self.assertFalse(rl._check_rate_limit_redis(Deny(), "bkt"))
        autonmap.MAX_REQUESTS_PER_WINDOW = 5
        self.assertTrue(rl._check_rate_limit_redis(Boom(), "fallback-bkt"))

    def test_backend_reports_memory_without_redis(self):
        self.assertEqual(rl.rate_limit_backend(), "memory")
        self.assertEqual(autonmap.rate_limit_backend(), "memory")

    def test_live_value_prefers_server_override(self):
        autonmap.MAX_REQUESTS_PER_WINDOW = 1
        rl.rate_limits.clear()
        self.assertTrue(rl._check_rate_limit_memory("live-bkt"))
        self.assertFalse(rl._check_rate_limit_memory("live-bkt"))

    async def test_client_key_defaults_to_peer(self):
        async with autonmap.app.test_request_context("/", method="GET"):
            from quart import request as qrequest

            qrequest.remote_addr = "10.9.9.9"
            self.assertEqual(rl._client_key(), "10.9.9.9")

    async def test_check_rate_limit_end_to_end(self):
        autonmap.MAX_REQUESTS_PER_WINDOW = 1
        async with autonmap.app.test_request_context("/", method="GET"):
            from quart import request as qrequest

            qrequest.remote_addr = "10.8.8.8"
            self.assertTrue(rl.check_rate_limit())
            self.assertFalse(rl.check_rate_limit())
        # Server wrapper delegates to the same shared buckets.
        async with autonmap.app.test_request_context("/", method="GET"):
            from quart import request as qrequest2

            qrequest2.remote_addr = "10.8.8.9"
            self.assertTrue(autonmap.check_rate_limit())

    async def test_read_endpoints_are_rate_limited(self):
        autonmap.MAX_REQUESTS_PER_WINDOW = 1
        headers = {"X-API-KEY": "test-token"}
        first = await self.client.get("/presets", headers=headers)
        self.assertEqual(first.status_code, 200)
        second = await self.client.get("/presets", headers=headers)
        self.assertEqual(second.status_code, 429)


if __name__ == "__main__":
    unittest.main()
