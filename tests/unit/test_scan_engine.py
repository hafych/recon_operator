import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import scan_engine
from kali_ai_scan import parse_nmap_xml

SAMPLE_XML = """<?xml version="1.0"?>
<nmaprun scanner="nmap" args="nmap -sT" start="1" version="7.95" xmloutputversion="1.05">
  <host>
    <status state="up"/>
    <address addr="127.0.0.1" addrtype="ipv4"/>
    <hostnames><hostname name="localhost"/></hostnames>
    <ports>
      <port protocol="tcp" portid="22">
        <state state="open"/>
        <service name="ssh" product="OpenSSH" version="9.0"/>
      </port>
      <port protocol="tcp" portid="80">
        <state state="closed"/>
        <service name="http"/>
      </port>
    </ports>
  </host>
</nmaprun>
"""


class ScanEngineUnitTests(unittest.TestCase):
    def test_report_to_api_result_groups_protocols(self):
        with tempfile.TemporaryDirectory() as tmp:
            xml_path = Path(tmp) / "sample.xml"
            xml_path.write_text(SAMPLE_XML, encoding="utf-8")
            report = parse_nmap_xml(xml_path)

        result = scan_engine.report_to_api_result(report, target="127.0.0.1", scan_type="TCP")

        self.assertEqual(result["schema"], scan_engine.SCHEMA_VERSION)
        self.assertEqual(result["scan_count"], 1)
        host = result["hosts"][0]
        self.assertEqual(host["host"], "127.0.0.1")
        self.assertEqual(host["hostname"], "localhost")
        self.assertEqual(host["state"], "up")
        self.assertEqual(host["protocols"]["tcp"][0]["port"], 22)
        self.assertEqual(host["protocols"]["tcp"][0]["name"], "ssh")
        self.assertEqual(result["stats"]["open_ports"], 1)

    def test_build_nmap_command_uses_argv_and_profile(self):
        command = scan_engine.build_nmap_command(
            "127.0.0.1",
            "Ping",
            host_timeout_sec=30,
            max_retries=1,
            xml_path=Path("/tmp/out.xml"),
            nmap_executable="/usr/bin/nmap",
        )

        self.assertEqual(
            command,
            [
                "/usr/bin/nmap",
                "-sn",
                "--host-timeout",
                "30s",
                "--max-retries",
                "1",
                "-oX",
                "/tmp/out.xml",
                "127.0.0.1",
            ],
        )

    def test_run_nmap_scan_parses_xml_from_subprocess(self):
        def fake_run(command, capture_output, check, text, timeout):
            xml_path = Path(command[command.index("-oX") + 1])
            xml_path.write_text(SAMPLE_XML, encoding="utf-8")
            return mock.Mock(returncode=0, stdout="", stderr="")

        with mock.patch("scan_engine.subprocess.run", side_effect=fake_run):
            with mock.patch("scan_engine.shutil.which", return_value="/usr/bin/nmap"):
                result = scan_engine.run_nmap_scan(
                    "127.0.0.1",
                    "TCP",
                    host_timeout_sec=10,
                    max_retries=0,
                    scan_timeout_sec=30,
                )

        self.assertEqual(result["hosts"][0]["host"], "127.0.0.1")
        self.assertEqual(result["target"], "127.0.0.1")
        self.assertEqual(result["scan_type"], "TCP")

    def test_run_nmap_scan_timeout_raises(self):
        with mock.patch(
            "scan_engine.subprocess.run",
            side_effect=__import__("subprocess").TimeoutExpired(cmd="nmap", timeout=1),
        ):
            with mock.patch("scan_engine.shutil.which", return_value="/usr/bin/nmap"):
                with self.assertRaises(scan_engine.NmapTimeoutError):
                    scan_engine.run_nmap_scan("127.0.0.1", "Ping", scan_timeout_sec=1)

    def test_build_command_includes_ports_and_scripts(self):
        command = scan_engine.build_nmap_command(
            "127.0.0.1",
            "Version",
            host_timeout_sec=30,
            max_retries=1,
            xml_path=Path("/tmp/out.xml"),
            nmap_executable="/usr/bin/nmap",
            ports="22,80",
            scripts="banner",
        )
        self.assertIn("-p", command)
        self.assertIn("22,80", command)
        self.assertIn("--script", command)
        self.assertIn("banner", command)
        self.assertIn("-sV", command)

    def test_parse_naabu_and_rustscan_outputs(self):
        naabu = scan_engine._parse_naabu_output(
            '{"ip":"127.0.0.1","port":22}\n127.0.0.1:80\nprogress 99\n'
        )
        rust = scan_engine._parse_rustscan_output("127.0.0.1 -> [22,443]\nOpen 10.0.0.1:8080\n")
        self.assertEqual(naabu, [22, 80])
        self.assertIn(22, rust)
        self.assertIn(443, rust)

    def test_hybrid_scan_uses_discovered_ports(self):
        def fake_discover(target, engine="auto", ports_hint=None, timeout_sec=120, **_kwargs):
            return {
                "engine": "naabu",
                "command": ["naabu", "-host", target],
                "ports": [22, 80],
                "returncode": 0,
                "stderr": "",
            }

        def fake_run(command, capture_output, check, text, timeout):
            xml_path = Path(command[command.index("-oX") + 1])
            xml_path.write_text(SAMPLE_XML, encoding="utf-8")
            self.assertIn("-p", command)
            self.assertIn("22,80", command)
            self.assertIn("-sV", command)
            return mock.Mock(returncode=0, stdout="", stderr="")

        with mock.patch("scan_engine.discover_open_ports", side_effect=fake_discover):
            with mock.patch("scan_engine.subprocess.run", side_effect=fake_run):
                with mock.patch("scan_engine.shutil.which", return_value="/usr/bin/nmap"):
                    result = scan_engine.run_nmap_scan(
                        "127.0.0.1",
                        "Hybrid",
                        host_timeout_sec=10,
                        max_retries=0,
                        scan_timeout_sec=60,
                    )

        self.assertEqual(result["scan_type"], "Hybrid")
        self.assertEqual(result["discovery"]["ports"], [22, 80])
        self.assertEqual(result["nmap_profile"], "Version")

    def test_discovery_nonzero_is_failure_even_when_stdout_contains_ports(self):
        completed = subprocess.CompletedProcess(
            ["naabu"],
            returncode=2,
            stdout='{"port":22}\n',
            stderr="probe failed",
        )
        with (
            mock.patch("scan_engine.resolve_discovery_engine", return_value="naabu"),
            mock.patch("scan_engine.shutil.which", return_value="/usr/bin/naabu"),
            mock.patch("scan_engine._run_tracked", return_value=completed),
        ):
            with self.assertRaisesRegex(scan_engine.DiscoveryError, "status 2"):
                scan_engine.discover_open_ports("127.0.0.1")

    def test_cancellation_before_registration_prevents_process_start(self):
        token = "cancel-before-popen"
        scan_engine.prepare_process_token(token)
        scan_engine.mark_process_cancelled(token)
        try:
            with mock.patch("scan_engine.subprocess.Popen") as popen:
                with self.assertRaises(scan_engine.ScanCancelledError):
                    scan_engine._run_tracked(
                        ["/usr/bin/true"],
                        timeout=1,
                        process_token=token,
                    )
            popen.assert_not_called()
        finally:
            scan_engine.clear_process_token(token)

    def test_report_bridge_preserves_script_os_trace_and_reason_evidence(self):
        report = {
            "hosts": [
                {
                    "id": "192.0.2.1",
                    "status": "up",
                    "hostnames": [],
                    "ports": [
                        {
                            "protocol": "tcp",
                            "port": 443,
                            "state": "open",
                            "reason": "syn-ack",
                            "service": {
                                "name": "https",
                                "product": "nginx",
                                "version": "1",
                                "extrainfo": "tls",
                                "tunnel": "ssl",
                            },
                            "scripts": [{"id": "http-title", "output": "Home"}],
                        }
                    ],
                    "host_scripts": [{"id": "uptime", "output": "1 day"}],
                    "os_matches": [{"name": "Linux", "accuracy": "98"}],
                    "trace": {"hops": [{"ttl": "1", "ip": "192.0.2.254"}]},
                }
            ]
        }

        result = scan_engine.report_to_api_result(report, target="192.0.2.1", scan_type="Safe")
        host = result["hosts"][0]
        port = host["protocols"]["tcp"][0]

        self.assertEqual(port["reason"], "syn-ack")
        self.assertEqual(port["tunnel"], "ssl")
        self.assertEqual(port["scripts"][0]["id"], "http-title")
        self.assertEqual(host["host_scripts"][0]["id"], "uptime")
        self.assertEqual(host["os_matches"][0]["name"], "Linux")
        self.assertEqual(host["trace"]["hops"][0]["ttl"], "1")

    def test_diff_detects_opened_port(self):
        baseline = {
            "hosts": [
                {
                    "host": "10.0.0.1",
                    "protocols": {"tcp": [{"port": 22, "state": "open", "name": "ssh"}]},
                }
            ]
        }
        current = {
            "hosts": [
                {
                    "host": "10.0.0.1",
                    "protocols": {
                        "tcp": [
                            {"port": 22, "state": "open", "name": "ssh"},
                            {"port": 443, "state": "open", "name": "https"},
                        ]
                    },
                }
            ]
        }
        diff = scan_engine.diff_scan_results(baseline, current)
        self.assertTrue(diff["summary"]["changed"])
        self.assertEqual(diff["ports_opened"][0]["port"], 443)


if __name__ == "__main__":
    unittest.main()
