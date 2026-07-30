"""Smoke tests for the recon_operator package boundary."""

from __future__ import annotations

import os
import unittest

os.environ.setdefault("API_AUTH_REQUIRED", "true")
os.environ.setdefault("API_AUTH_TOKEN", "test-token")
os.environ.setdefault("FERNET_KEY", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")
os.environ.setdefault("SCAN_LOG_PATH", "/tmp/nmap-automator-pkg.log")
os.environ.setdefault("STATE_DB_PATH", "/tmp/recon-operator-pkg.db")

import autonmap
from recon_operator import api, auth, config, jobs, scheduler


class PackageLayoutTests(unittest.TestCase):
    def test_autonmap_aliases_server_implementation(self):
        from recon_operator import server

        self.assertIs(autonmap, server)
        self.assertEqual(autonmap.VERSION, "1.11.2")
        self.assertIs(autonmap.app, server.app)

    def test_package_surfaces_reexport_server_symbols(self):
        self.assertEqual(config.VERSION, autonmap.VERSION)
        self.assertIs(config.app, autonmap.app)
        self.assertIs(api.app, autonmap.app)
        self.assertIs(auth.require_api_auth, autonmap.require_api_auth)
        self.assertIs(auth._load_api_auth_keys, autonmap._load_api_auth_keys)
        self.assertIs(auth.scopes_allow, autonmap.scopes_allow)
        self.assertIs(jobs.create_scan_job, autonmap.create_scan_job)
        self.assertIs(scheduler.periodic_scan, autonmap.periodic_scan)
        self.assertIs(jobs.scan_jobs, autonmap.scan_jobs)
        # Leaf modules own config/auth implementations (not lazy server proxies).
        self.assertEqual(config.APP_PORT, autonmap.APP_PORT)
        self.assertEqual(auth.API_KEY_SCOPES, autonmap.API_KEY_SCOPES)
        self.assertTrue(callable(config._parse_bool_env))
        self.assertTrue(callable(auth.owner_id_from_token))


if __name__ == "__main__":
    unittest.main()
