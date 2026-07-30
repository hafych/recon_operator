import contextlib
import io
import os
import stat
import tempfile
import unittest
from argparse import Namespace
from pathlib import Path
from unittest import mock

from defusedxml.common import EntitiesForbidden

import kali_ai_scan

SAMPLE_XML = """<?xml version="1.0"?>
<nmaprun scanner="nmap" args="nmap -sT -oX sample.xml 127.0.0.1" start="1" version="7.99" xmloutputversion="1.05">
  <host>
    <status state="up" reason="localhost-response"/>
    <address addr="127.0.0.1" addrtype="ipv4"/>
    <hostnames>
      <hostname name="localhost" type="user"/>
    </hostnames>
    <ports>
      <port protocol="tcp" portid="22">
        <state state="open" reason="syn-ack"/>
        <service name="ssh" product="OpenSSH" version="9.9" extrainfo="Ubuntu" tunnel="ssl"/>
        <script id="banner" output="SSH server"/>
      </port>
      <port protocol="tcp" portid="80">
        <state state="closed" reason="reset"/>
        <service name="http"/>
      </port>
    </ports>
    <hostscript><script id="uptime" output="1 day"/></hostscript>
    <os><osmatch name="Linux" accuracy="98"><osclass vendor="Linux" osfamily="Linux"/></osmatch></os>
    <trace port="22" proto="tcp"><hop ttl="1" ipaddr="127.0.0.1" rtt="0.1"/></trace>
  </host>
</nmaprun>
"""


class KaliAiScanTests(unittest.TestCase):
    def test_target_filter_accepts_hosts_and_rejects_shell_syntax(self):
        for target in ("127.0.0.1", "example.com", "10.0.0.0/24", "192.0.2.1-10"):
            kali_ai_scan.reject_suspicious_target(target)

        with self.assertRaises(SystemExit):
            kali_ai_scan.reject_suspicious_target("127.0.0.1; touch /tmp/owned")
        with self.assertRaises(SystemExit):
            kali_ai_scan.reject_suspicious_target("-iL")

    def test_parse_nmap_xml(self):
        with tempfile.TemporaryDirectory() as tmp:
            xml_path = Path(tmp) / "sample.xml"
            xml_path.write_text(SAMPLE_XML, encoding="utf-8")

            report = kali_ai_scan.parse_nmap_xml(xml_path)

        self.assertEqual(report["schema"], kali_ai_scan.SCHEMA_VERSION)
        self.assertEqual(report["nmap_version"], "7.99")
        self.assertEqual(report["stats"], {"hosts": 1, "hosts_up": 1, "open_ports": 1})
        self.assertEqual(report["hosts"][0]["id"], "127.0.0.1")
        self.assertEqual(report["hosts"][0]["ports"][0]["service"]["name"], "ssh")
        self.assertEqual(report["hosts"][0]["ports"][0]["reason"], "syn-ack")
        self.assertEqual(report["hosts"][0]["ports"][0]["scripts"][0]["id"], "banner")
        self.assertEqual(report["hosts"][0]["host_scripts"][0]["id"], "uptime")
        self.assertEqual(report["hosts"][0]["os_matches"][0]["name"], "Linux")
        self.assertEqual(report["hosts"][0]["trace"]["hops"][0]["ttl"], "1")

    def test_write_observations_jsonl(self):
        with tempfile.TemporaryDirectory() as tmp:
            xml_path = Path(tmp) / "sample.xml"
            out_path = Path(tmp) / "observations.jsonl"
            xml_path.write_text(SAMPLE_XML, encoding="utf-8")
            report = kali_ai_scan.parse_nmap_xml(xml_path)

            kali_ai_scan.write_observations(out_path, report)
            lines = out_path.read_text(encoding="utf-8").splitlines()

        self.assertEqual(len(lines), 3)
        self.assertIn('"type": "host"', lines[0])
        self.assertIn('"type": "service"', lines[1])
        self.assertIn("tcp/22 open", lines[1])

    def test_parse_nmap_xml_rejects_entities(self):
        xml_with_entity = """<?xml version="1.0"?>
<!DOCTYPE nmaprun [<!ENTITY secret SYSTEM "file:///etc/passwd">]>
<nmaprun scanner="nmap" version="7.99"><host><hostnames><hostname name="&secret;"/></hostnames></host></nmaprun>
"""
        with tempfile.TemporaryDirectory() as tmp:
            xml_path = Path(tmp) / "entity.xml"
            xml_path.write_text(xml_with_entity, encoding="utf-8")

            with self.assertRaises(EntitiesForbidden):
                kali_ai_scan.parse_nmap_xml(xml_path)

    def test_parse_nmap_xml_rejects_non_nmap_document(self):
        with tempfile.TemporaryDirectory() as tmp:
            xml_path = Path(tmp) / "other.xml"
            xml_path.write_text("<root />", encoding="utf-8")

            with self.assertRaisesRegex(ValueError, "nmaprun"):
                kali_ai_scan.parse_nmap_xml(xml_path)

    def test_create_artifacts_writes_complete_handoff(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            xml_path = root / "sample.xml"
            output_path = root / "report"
            xml_path.write_text(SAMPLE_XML, encoding="utf-8")

            original_version = kali_ai_scan.nmap_version
            original_packages = kali_ai_scan.package_status
            original_policy = kali_ai_scan.apt_policy
            kali_ai_scan.nmap_version = lambda: {"ok": True, "stdout": "Nmap 7.99"}
            kali_ai_scan.package_status = lambda packages: {
                "available": True,
                "packages": {name: {"ok": True} for name in packages},
            }
            kali_ai_scan.apt_policy = lambda package: {"ok": True, "package": package}
            try:
                manifest = kali_ai_scan.create_artifacts(xml_path, output_path)
            finally:
                kali_ai_scan.nmap_version = original_version
                kali_ai_scan.package_status = original_packages
                kali_ai_scan.apt_policy = original_policy

            self.assertEqual(manifest["stats"]["open_ports"], 1)
            for filename in (
                "nmap.xml",
                "hosts.json",
                "observations.jsonl",
                "summary.md",
                "manifest.json",
            ):
                self.assertTrue((output_path / filename).is_file())

    def test_run_scan_enforces_total_timeout(self):
        with tempfile.TemporaryDirectory() as tmp:
            args = Namespace(
                target="127.0.0.1",
                out=tmp,
                profile="tcp",
                host_timeout="30s",
                max_retries=1,
                ports=None,
                scan_timeout=1,
            )
            original_which = kali_ai_scan.shutil.which
            original_run = kali_ai_scan.subprocess.run
            kali_ai_scan.shutil.which = lambda _name: "/usr/bin/nmap"

            def timeout_run(*_args, **_kwargs):
                raise kali_ai_scan.subprocess.TimeoutExpired("nmap", 1)

            kali_ai_scan.subprocess.run = timeout_run
            try:
                with contextlib.redirect_stderr(io.StringIO()):
                    exit_code = kali_ai_scan.run_scan(args)
            finally:
                kali_ai_scan.shutil.which = original_which
                kali_ai_scan.subprocess.run = original_run

            self.assertEqual(exit_code, 124)

    def test_artifacts_are_private_and_output_is_atomic(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            xml_path = root / "sample.xml"
            output_path = root / "report"
            xml_path.write_text(SAMPLE_XML, encoding="utf-8")

            original_version = kali_ai_scan.nmap_version
            original_packages = kali_ai_scan.package_status
            original_policy = kali_ai_scan.apt_policy
            kali_ai_scan.nmap_version = lambda: {"ok": True}
            kali_ai_scan.package_status = lambda _packages: {"available": False}
            kali_ai_scan.apt_policy = lambda _package: {"available": False}
            try:
                kali_ai_scan.create_artifacts(xml_path, output_path)
            finally:
                kali_ai_scan.nmap_version = original_version
                kali_ai_scan.package_status = original_packages
                kali_ai_scan.apt_policy = original_policy

            self.assertEqual(stat.S_IMODE(output_path.stat().st_mode), 0o700)
            for artifact in output_path.iterdir():
                self.assertEqual(stat.S_IMODE(artifact.stat().st_mode), 0o600, artifact.name)
            self.assertEqual(list(output_path.glob(".*.tmp")), [])

    def test_failed_directory_publish_removes_in_progress_output(self):
        with tempfile.TemporaryDirectory() as tmp:
            args = Namespace(
                target="127.0.0.1",
                out=tmp,
                profile="tcp",
                host_timeout="30s",
                max_retries=1,
                ports=None,
                scan_timeout=10,
            )
            with (
                mock.patch.object(kali_ai_scan.shutil, "which", return_value="/usr/bin/nmap"),
                mock.patch.object(
                    kali_ai_scan.subprocess,
                    "run",
                    return_value=mock.Mock(returncode=0),
                ),
                mock.patch.object(kali_ai_scan.os, "replace", side_effect=OSError("publish")),
                contextlib.redirect_stderr(io.StringIO()),
            ):
                code = kali_ai_scan.run_scan(args)

            self.assertEqual(code, 1)
            self.assertEqual(list(Path(tmp).glob(".in-progress-*")), [])


class CliValidationRegressionTests(unittest.TestCase):
    def test_cli_rejects_unbounded_or_invalid_nmap_limits(self):
        invalid_arguments = (
            ["run", "127.0.0.1", "--scan-timeout", "0"],
            ["run", "127.0.0.1", "--scan-timeout", "-1"],
            ["run", "127.0.0.1", "--host-timeout", "0s"],
            ["run", "127.0.0.1", "--host-timeout", "nan"],
            ["run", "127.0.0.1", "--max-retries", "-1"],
        )

        for arguments in invalid_arguments:
            with self.subTest(arguments=arguments):
                with contextlib.redirect_stderr(io.StringIO()):
                    with self.assertRaises(SystemExit):
                        kali_ai_scan.build_parser().parse_args(arguments)

    def test_cli_accepts_bounded_limits_and_zero_retries(self):
        args = kali_ai_scan.build_parser().parse_args(
            [
                "run",
                "127.0.0.1",
                "--scan-timeout",
                "1",
                "--host-timeout",
                "500ms",
                "--max-retries",
                "0",
            ]
        )

        self.assertEqual(args.scan_timeout, 1)
        self.assertEqual(args.host_timeout, "500ms")
        self.assertEqual(args.max_retries, 0)

    def test_report_retention_keeps_newest_dirs(self):
        original_max = kali_ai_scan.AI_REPORTS_MAX_DIRS
        kali_ai_scan.AI_REPORTS_MAX_DIRS = 2
        try:
            with tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                for index in range(4):
                    path = root / f"report-{index}"
                    path.mkdir()
                    (path / "summary.md").write_text("x", encoding="utf-8")
                    # Ensure deterministic mtime ordering.
                    os.utime(path, (index + 1, index + 1))
                summary = kali_ai_scan.apply_report_retention(root)
                remaining = sorted(path.name for path in root.iterdir() if path.is_dir())
        finally:
            kali_ai_scan.AI_REPORTS_MAX_DIRS = original_max

        self.assertEqual(summary["remaining"], 2)
        self.assertEqual(remaining, ["report-2", "report-3"])


if __name__ == "__main__":
    unittest.main()
