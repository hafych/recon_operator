import json
import os
import tempfile
import unittest

os.environ.setdefault("API_AUTH_TOKEN", "test-token")
os.environ.setdefault("FERNET_KEY", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")
os.environ.setdefault("TELEGRAM_BOT_TOKEN", "")
os.environ.setdefault("TELEGRAM_CHAT_ID", "")
os.environ.setdefault("STATE_DB_PATH", "/tmp/recon-operator-test.db")

import autonmap
import tool_inventory
from tool_inventory import inventory_to_jsonl, inventory_to_markdown, parse_apt_depends


class ToolInventoryFormatTests(unittest.TestCase):
    def test_parse_apt_depends_extracts_real_dependencies(self):
        stdout = """
          Depends: nmap
          Depends: python3
          Depends: <mail-transport-agent>
          Recommends: wireshark
        """

        self.assertEqual(parse_apt_depends(stdout), ["nmap", "python3"])

    def test_inventory_formats_are_ai_readable(self):
        inventory = {
            "schema": "pentest-tool-inventory/v1",
            "generated_at": "2026-07-09T00:00:00Z",
            "profiles": [{"name": "recon", "metapackage": "kali-tools-information-gathering"}],
            "summary": {
                "packages_checked": 1,
                "available": 1,
                "missing": 0,
                "missing_packages": [],
            },
            "packages": [
                {
                    "package": "nmap",
                    "category": "recon",
                    "installed": True,
                    "apt": {"available": True},
                    "commands": [{"name": "nmap", "present": True, "path": "/usr/bin/nmap"}],
                }
            ],
            "ai_handoff": {"prompt_hint": "Use installed tools only.", "recommended_files": []},
        }

        jsonl_rows = [json.loads(line) for line in inventory_to_jsonl(inventory).splitlines()]
        markdown = inventory_to_markdown(inventory)

        self.assertEqual(jsonl_rows[0]["record_type"], "summary")
        self.assertEqual(jsonl_rows[1]["record_type"], "tool")
        self.assertIn("nmap", markdown)

    def test_inventory_to_markdown_handles_dict_commands_payload(self):
        inventory = {
            "schema": "pentest-tool-inventory/v1",
            "generated_at": "2026-07-09T00:00:00Z",
            "profiles": [],
            "summary": {
                "packages_checked": 1,
                "available": 1,
                "missing": 0,
                "missing_packages": [],
            },
            "packages": [
                {
                    "package": "nmap",
                    "category": "recon",
                    "installed": True,
                    "command_available": True,
                    "commands": {"nmap": "/usr/bin/nmap"},
                }
            ],
            "ai_handoff": {"prompt_hint": "Use installed tools only.", "recommended_files": []},
        }

        markdown = inventory_to_markdown(inventory)
        self.assertIn("Available Tools", markdown)
        self.assertIn("`nmap` (recon)", markdown)

    def test_build_inventory_expands_selected_profiles(self):
        original_status = tool_inventory.package_status
        original_dependencies = tool_inventory.metapackage_dependencies

        def fake_status(package):
            return {
                "package": package,
                "installed": package == "nmap",
                "version": "test",
                "category": "test",
                "commands": {},
                "command_available": package == "nmap",
                "apt": {"available": True},
            }

        tool_inventory.package_status = fake_status
        tool_inventory.metapackage_dependencies = lambda package: [f"{package}-dependency"]
        try:
            inventory = tool_inventory.build_tool_inventory(profiles=["ai"], expand=True)
        finally:
            tool_inventory.package_status = original_status
            tool_inventory.metapackage_dependencies = original_dependencies

        package_names = {row["package"] for row in inventory["packages"]}
        self.assertIn("llm-tools-nmap-dependency", package_names)
        self.assertGreater(inventory["summary"]["packages_checked"], 1)


class ToolInventoryApiTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.client = autonmap.app.test_client()

    async def test_tools_endpoint_requires_auth(self):
        response = await self.client.get("/tools")

        self.assertEqual(response.status_code, 401)

    async def test_tools_endpoint_returns_inventory(self):
        original_builder = autonmap.build_tool_inventory
        original_cache = dict(autonmap.tool_inventory_cache)
        autonmap.tool_inventory_cache.clear()

        def fake_inventory(expand=False):
            return {
                "schema": "pentest-tool-inventory/v1",
                "generated_at": "2026-07-09T00:00:00Z",
                "source": "test",
                "profiles": [],
                "summary": {
                    "packages_checked": 1,
                    "available": 1,
                    "missing": 0,
                    "missing_packages": [],
                },
                "packages": [],
                "ai_handoff": {"prompt_hint": "test", "recommended_files": []},
            }

        autonmap.build_tool_inventory = fake_inventory
        try:
            response = await self.client.get("/tools", headers={"X-API-KEY": "test-token"})
            body = await response.get_json()
        finally:
            autonmap.build_tool_inventory = original_builder
            autonmap.tool_inventory_cache.clear()
            autonmap.tool_inventory_cache.update(original_cache)

        self.assertEqual(response.status_code, 200)
        self.assertEqual(body["schema"], "pentest-tool-inventory/v1")

    async def test_tools_ai_context_returns_jsonl(self):
        original_builder = autonmap.build_tool_inventory
        original_cache = dict(autonmap.tool_inventory_cache)
        autonmap.tool_inventory_cache.clear()

        def fake_inventory(expand=False):
            return {
                "schema": "pentest-tool-inventory/v1",
                "generated_at": "2026-07-09T00:00:00Z",
                "profiles": [],
                "summary": {
                    "packages_checked": 0,
                    "available": 0,
                    "missing": 0,
                    "missing_packages": [],
                },
                "packages": [],
                "ai_handoff": {"prompt_hint": "test", "recommended_files": []},
            }

        autonmap.build_tool_inventory = fake_inventory
        try:
            response = await self.client.get(
                "/tools/ai-context?format=jsonl",
                headers={"X-API-KEY": "test-token"},
            )
            body = await response.get_data(as_text=True)
        finally:
            autonmap.build_tool_inventory = original_builder
            autonmap.tool_inventory_cache.clear()
            autonmap.tool_inventory_cache.update(original_cache)

        self.assertEqual(response.status_code, 200)
        self.assertIn('"record_type"', body)

    async def test_dashboard_contains_tool_inventory_panel(self):
        response = await self.client.get("/")
        body = await response.get_data(as_text=True)

        self.assertIn("Tool Inventory", body)
        self.assertIn("lastRefresh", body)
        self.assertIn("lastScanMeta", body)

    def test_cli_exports_json_and_markdown(self):
        original = tool_inventory.build_tool_inventory

        def fake_inventory(profiles=None, expand=False):
            return {
                "schema": "pentest-tool-inventory/v1",
                "generated_at": "2026-07-09T00:00:00Z",
                "source": "test",
                "profiles": [{"profile": "core", "install": "kali-linux-core"}],
                "summary": {
                    "packages_checked": 1,
                    "available": 1,
                    "missing": 0,
                    "missing_packages": [],
                },
                "packages": [
                    {
                        "package": "nmap",
                        "category": "recon",
                        "installed": True,
                        "command_available": True,
                        "commands": {"nmap": "/usr/bin/nmap"},
                    }
                ],
                "ai_handoff": {"prompt_hint": "test", "recommended_files": []},
            }

        tool_inventory.build_tool_inventory = fake_inventory
        try:
            with tempfile.TemporaryDirectory() as tmp:
                out = os.path.join(tmp, "inv.json")
                code = tool_inventory.main(["--format", "json", "-o", out])
                self.assertEqual(code, 0)
                with open(out, encoding="utf-8") as handle:
                    payload = json.load(handle)
                self.assertEqual(payload["schema"], "pentest-tool-inventory/v1")

                md_code = tool_inventory.main(["--format", "markdown"])
                self.assertEqual(md_code, 0)
        finally:
            tool_inventory.build_tool_inventory = original
