"""CLI coverage for recon_operator.__main__ (serve/pack/presets)."""

from __future__ import annotations

import json
import os
import tempfile
import unittest
from unittest.mock import patch

os.environ.setdefault("API_AUTH_REQUIRED", "true")
os.environ.setdefault("API_AUTH_TOKEN", "test-token")
os.environ.setdefault("FERNET_KEY", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")
os.environ.setdefault("SCAN_LOG_PATH", "/tmp/nmap-automator-maincli.log")
os.environ.setdefault("STATE_DB_PATH", "/tmp/recon-operator-maincli.db")

from recon_operator.__main__ import build_parser, main


class MainCliTests(unittest.TestCase):
    def test_parser_has_subcommands(self):
        parser = build_parser()
        for cmd in ("serve", "pack", "presets"):
            args = parser.parse_args([cmd] if cmd != "pack" else [cmd, "x.json"])
            self.assertTrue(callable(getattr(args, "func", None)))

    def test_presets_command_outputs_json(self):
        with patch("sys.stdout") as fake_out:
            chunks = []
            fake_out.write.side_effect = chunks.append
            rc = main(["presets"])
        self.assertEqual(rc, 0)
        payload = json.loads("".join(chunks))
        self.assertIn("presets", payload)
        self.assertIn("phases", payload)

    def test_pack_command_builds_budget(self):
        scan = {
            "target": "127.0.0.1",
            "scan_type": "TCP",
            "hosts": [
                {
                    "address": "127.0.0.1",
                    "ports": [{"port": 80, "proto": "tcp", "state": "open"}],
                }
            ],
        }
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", delete=False, encoding="utf-8"
        ) as handle:
            json.dump(scan, handle)
            path = handle.name
        try:
            with patch("sys.stdout") as fake_out:
                chunks = []
                fake_out.write.side_effect = chunks.append
                rc = main(["pack", path, "--budget", "s", "--format", "jsonl"])
            self.assertEqual(rc, 0)
            self.assertTrue("".join(chunks).strip())
        finally:
            os.unlink(path)

    def test_pack_command_missing_file_fails(self):
        with patch("sys.stderr"):
            rc = main(["pack", "/tmp/recon-operator-no-such-scan.json"])
        self.assertEqual(rc, 1)

    def test_help_exits_zero(self):
        with patch("sys.stdout"):
            with self.assertRaises(SystemExit) as ctx:
                main(["--help"])
            self.assertEqual(ctx.exception.code, 0)


if __name__ == "__main__":
    unittest.main()
