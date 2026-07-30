"""Retest/defense pack and CLI pack entry tests."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

os.environ.setdefault("API_AUTH_REQUIRED", "true")
os.environ.setdefault("API_AUTH_TOKEN", "test-token")
os.environ.setdefault("FERNET_KEY", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")
os.environ.setdefault("SCAN_LOG_PATH", "/tmp/nmap-automator-retest.log")
os.environ.setdefault("STATE_DB_PATH", "/tmp/recon-operator-retest.db")

import autonmap
from recon_operator.ai_pack import (
    BUDGET_S_MAX_BYTES,
    build_ai_pack,
    build_retest_pack_rows,
    pack_bytes,
    pack_from_json_file,
)

BASELINE = {
    "target": "192.0.2.10",
    "scan_type": "Version",
    "hosts": [
        {
            "host": "192.0.2.10",
            "state": "up",
            "protocols": {
                "tcp": [
                    {"port": 22, "state": "open", "name": "ssh", "product": "OpenSSH"},
                    {"port": 80, "state": "closed", "name": "http"},
                ]
            },
        }
    ],
}

CURRENT = {
    "target": "192.0.2.10",
    "scan_type": "Version",
    "hosts": [
        {
            "host": "192.0.2.10",
            "state": "up",
            "protocols": {
                "tcp": [
                    {"port": 22, "state": "open", "name": "ssh", "product": "OpenSSH"},
                    {
                        "port": 80,
                        "state": "open",
                        "name": "http",
                        "product": "nginx",
                    },
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


class RetestPackTests(unittest.TestCase):
    def test_retest_pack_highlights_opened_service_and_defense(self):
        rows = build_retest_pack_rows(BASELINE, CURRENT, budget="s", inventory=INVENTORY)
        body, _, _ = build_ai_pack(
            CURRENT, budget="s", inventory=INVENTORY, baseline=BASELINE, mode="retest"
        )
        self.assertLessEqual(pack_bytes(rows), BUDGET_S_MAX_BYTES)
        self.assertLessEqual(len(body.encode("utf-8")), BUDGET_S_MAX_BYTES)
        self.assertEqual(rows[0].get("mode"), "retest")
        types = [r.get("t") for r in rows]
        self.assertIn("diff", types)
        self.assertIn("change", types)
        self.assertIn("finding", types)
        self.assertIn("defense", types)
        changes = [r for r in rows if r.get("t") == "change"]
        self.assertTrue(any(c.get("op") == "opened" and c.get("port") == 80 for c in changes))
        self.assertTrue(any(str(c.get("id", "")).startswith("C-") for c in changes))
        findings = [r for r in rows if r.get("t") == "finding"]
        self.assertTrue(any(str(f.get("id", "")).startswith("F-") for f in findings))
        self.assertNotIn("test-token", body)
        self.assertNotIn(os.environ["FERNET_KEY"], body)
        # Closed-only baseline noise not listed as open svc without being open now.
        svc_ports = {r.get("port") for r in rows if r.get("t") == "svc"}
        self.assertIn(80, svc_ports)
        self.assertIn(22, svc_ports)

    def test_cli_pack_and_retest_from_files(self):
        with tempfile.TemporaryDirectory() as tmp:
            base_path = Path(tmp) / "base.json"
            cur_path = Path(tmp) / "cur.json"
            base_path.write_text(json.dumps(BASELINE), encoding="utf-8")
            cur_path.write_text(json.dumps(CURRENT), encoding="utf-8")
            body, ctype, rows = pack_from_json_file(
                str(cur_path), budget="s", baseline_path=str(base_path)
            )
            self.assertIn("ndjson", ctype)
            self.assertTrue(any(r.get("t") == "change" for r in rows))
            self.assertLessEqual(len(body.encode("utf-8")), BUDGET_S_MAX_BYTES)

            # Module CLI entry.
            proc = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "recon_operator",
                    "pack",
                    str(cur_path),
                    "--budget",
                    "s",
                    "--baseline",
                    str(base_path),
                ],
                cwd=str(Path(__file__).resolve().parents[2]),
                capture_output=True,
                text=True,
                check=False,
                env={
                    **os.environ,
                    "API_AUTH_REQUIRED": "true",
                    "API_AUTH_TOKEN": "test-token",
                    "FERNET_KEY": os.environ["FERNET_KEY"],
                },
            )
            self.assertEqual(proc.returncode, 0, proc.stderr)
            self.assertIn('"t":"diff"', proc.stdout.replace(" ", ""))


class RetestHttpTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        autonmap.rate_limits.clear()
        self.client = autonmap.app.test_client()
        self.headers = {"X-API-KEY": "test-token", "Content-Type": "application/json"}

    async def test_post_retest_pack(self):
        response = await self.client.post(
            "/ai/pack?mode=retest&budget=s",
            headers=self.headers,
            json={"scan": CURRENT, "baseline": BASELINE},
        )
        body = await response.get_data(as_text=True)
        self.assertEqual(response.status_code, 200)
        self.assertLessEqual(len(body.encode("utf-8")), BUDGET_S_MAX_BYTES)
        self.assertIn('"t":"change"', body.replace(" ", ""))
        self.assertIn('"t":"diff"', body.replace(" ", ""))
        self.assertNotIn("test-token", body)
        self.assertNotIn(autonmap.FERNET_KEY, body)


if __name__ == "__main__":
    unittest.main()
