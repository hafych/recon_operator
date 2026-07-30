import json
import os
import unittest

os.environ.setdefault("API_AUTH_REQUIRED", "true")
os.environ.setdefault("API_AUTH_TOKEN", "test-token")
os.environ.setdefault("FERNET_KEY", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")
os.environ.setdefault("TELEGRAM_BOT_TOKEN", "")
os.environ.setdefault("TELEGRAM_CHAT_ID", "")
os.environ.setdefault("STATE_DB_PATH", "/tmp/recon-operator-test.db")

import autonmap
from recon_planner import build_recon_plan, recon_plan_to_jsonl, recon_plan_to_markdown

SCAN = {
    "hosts": [
        {
            "host": "192.0.2.10",
            "hostname": "app.example.test",
            "state": "up",
            "protocols": {
                "tcp": [
                    {"port": 80, "state": "open", "name": "http"},
                    {"port": 22, "state": "open", "name": "ssh"},
                    {"port": 25, "state": "closed", "name": "smtp"},
                ]
            },
        }
    ]
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


class ReconPlannerTests(unittest.TestCase):
    def test_build_recon_plan_uses_open_services_and_tool_status(self):
        plan = build_recon_plan(SCAN, inventory=INVENTORY)
        commands = [row["command"] for row in plan["recommendations"]]

        self.assertIn("curl -k -I http://192.0.2.10", commands)
        self.assertTrue(
            any(
                row["tool"] == "curl" and row["status"] == "ready"
                for row in plan["recommendations"]
            )
        )
        self.assertTrue(
            any(
                row["tool"] == "ssh-audit" and row["status"] == "missing"
                for row in plan["recommendations"]
            )
        )
        self.assertFalse(any("smtp" in row["command"] for row in plan["recommendations"]))

    def test_recon_plan_formats_are_ai_readable(self):
        plan = build_recon_plan(SCAN, inventory=INVENTORY)
        jsonl_rows = [json.loads(line) for line in recon_plan_to_jsonl(plan).splitlines()]
        markdown = recon_plan_to_markdown(plan)

        self.assertEqual(jsonl_rows[0]["record_type"], "summary")
        self.assertEqual(jsonl_rows[1]["record_type"], "recon_step")
        self.assertIn("Recon Plan", markdown)

    def test_recon_plan_skips_invalid_ports(self):
        scan_with_invalid_port = {
            "hosts": [
                {
                    "host": "203.0.113.5",
                    "hostname": "bad.example.test",
                    "state": "up",
                    "protocols": {
                        "tcp": [
                            {"port": "22", "state": "open", "name": "ssh"},
                            {"port": "80/tcp", "state": "open", "name": "http"},
                        ]
                    },
                }
            ]
        }
        plan = build_recon_plan(scan_with_invalid_port, inventory=INVENTORY)
        row_services = {row["service"] for row in plan["recommendations"]}
        self.assertIn("ssh", row_services)
        self.assertNotIn("http", row_services)

    def test_recon_plan_rejects_command_injection_fields(self):
        malicious_scan = {
            "hosts": [
                {
                    "host": "127.0.0.1; touch /tmp/owned",
                    "hostname": "safe.example",
                    "state": "up",
                    "protocols": {"tcp": [{"port": 80, "state": "open", "name": "http"}]},
                },
                {
                    "host": "127.0.0.1",
                    "hostname": "bad.example; touch /tmp/owned",
                    "state": "up",
                    "protocols": {"udp": [{"port": 53, "state": "open", "name": "dns"}]},
                },
            ]
        }

        plan = build_recon_plan(malicious_scan, inventory=INVENTORY)
        commands = [row["command"] for row in plan["recommendations"]]

        self.assertTrue(commands)
        self.assertFalse(any("touch" in command or ";" in command for command in commands))

    def test_protocol_ipv6_domain_and_partial_inventory_are_handled(self):
        scan = {
            "hosts": [
                {
                    "host": "2001:db8::10",
                    "state": "up",
                    "protocols": {
                        "tcp": [{"port": 22, "state": "open", "name": "ssh"}],
                        "udp": [
                            {"port": 80, "state": "open", "name": "http"},
                            {"port": 53, "state": "open", "name": "domain"},
                        ],
                    },
                }
            ]
        }
        inventory = {
            "packages": [
                {
                    "package": "ssh-audit",
                    "installed": True,
                    "command_available": True,
                    "commands": {"ssh-audit": None},
                }
            ]
        }

        plan = build_recon_plan(scan, inventory=inventory)
        rows = plan["recommendations"]

        ssh = next(row for row in rows if row["tool"] == "ssh-audit")
        self.assertEqual(ssh["status"], "missing")
        self.assertIn("[2001:db8::10]:22", ssh["command"])
        self.assertFalse(any(row["profile"] == "web" and row["protocol"] == "udp" for row in rows))
        self.assertTrue(any(row["tool"] == "dig" and row["protocol"] == "udp" for row in rows))
        self.assertFalse(any(row["tool"] == "dnsrecon" for row in rows))
        self.assertTrue(
            all(row["status"] == "unknown" for row in rows if row["tool"] not in {"ssh-audit"})
        )


class ReconPlanApiTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.client = autonmap.app.test_client()

    async def test_recon_plan_endpoint_returns_json(self):
        original_inventory = autonmap.get_cached_tool_inventory
        autonmap.get_cached_tool_inventory = lambda expand=False: INVENTORY
        try:
            response = await self.client.post(
                "/recon/plan",
                headers={"X-API-KEY": "test-token"},
                json={"scan": SCAN},
            )
            body = await response.get_json()
        finally:
            autonmap.get_cached_tool_inventory = original_inventory

        self.assertEqual(response.status_code, 200)
        self.assertEqual(body["schema"], "service-recon-plan/v1")
        self.assertGreater(body["summary"]["recommendations"], 0)
