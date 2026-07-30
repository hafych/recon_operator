"""Unified recon scan engine (Nmap runner + result normalization + diff).

Runs Nmap via argv (no shell), writes XML privately, parses with defusedxml
through kali_ai_scan, and normalizes into the operator API result shape.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import signal
import subprocess
import tempfile
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Sequence, Tuple

from kali_ai_scan import parse_nmap_xml

PRODUCT_NAME = "Recon Operator"
SCHEMA_VERSION = "recon-operator-result/v1"

# Active child processes keyed by optional token (usually job_id) for hard cancel.
_ACTIVE_PROCS: Dict[str, subprocess.Popen] = {}
_PROCESS_CANCEL_EVENTS: Dict[str, threading.Event] = {}
_PROC_LOCK = threading.Lock()

# API scan type names → Nmap argv fragments (multi-profile, not Nmap-only product).
SCAN_TYPE_ARGS: Dict[str, List[str]] = {
    "SYN": ["-sS"],
    "TCP": ["-sT"],
    "UDP": ["-sU"],
    "Aggressive": ["-A"],
    "OS": ["-O"],
    "Ping": ["-sn"],
    "Version": ["-sV"],
    "Safe": ["-sV", "--script", "safe"],
    "Vuln": ["-sV", "--script", "vuln"],
    "Full": ["-sT", "-sV", "-sC"],
}

# Hybrid profiles: fast port discovery, then Nmap service detection on found ports.
HYBRID_SCAN_TYPES: Dict[str, str] = {
    "Hybrid": "auto",
    "HybridNaabu": "naabu",
    "HybridRustScan": "rustscan",
}
DISCOVERY_ENGINES = ("auto", "naabu", "rustscan", "none")
HYBRID_NMAP_PROFILE = "Version"

PORTS_RE = re.compile(r"^[0-9A-Za-z:,\-]{1,200}$")
SCRIPTS_RE = re.compile(r"^[A-Za-z0-9_.,+\-*/]{1,300}$")


class NmapNotFoundError(RuntimeError):
    """Raised when the nmap executable is missing from PATH."""


class NmapScanError(RuntimeError):
    """Raised when Nmap exits non-zero or produces unusable output."""


class NmapTimeoutError(TimeoutError):
    """Raised when the total Nmap process timeout is exceeded."""


class DiscoveryError(RuntimeError):
    """Raised when a hybrid discovery frontend fails hard."""


class ScanCancelledError(RuntimeError):
    """Raised when a tracked scan process is killed via cancel (job_id token)."""


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _register_process(token: Optional[str], proc: subprocess.Popen) -> None:
    if not token:
        return
    with _PROC_LOCK:
        previous = _ACTIVE_PROCS.get(token)
        _ACTIVE_PROCS[token] = proc
    if previous is not None and previous.poll() is None and previous is not proc:
        _terminate_process(previous)


def prepare_process_token(token: str) -> None:
    """Create cancellation state before executor work can start."""
    if not token:
        return
    with _PROC_LOCK:
        _PROCESS_CANCEL_EVENTS[token] = threading.Event()


def mark_process_cancelled(token: str) -> None:
    """Record cancellation even if a subprocess has not registered yet."""
    if not token:
        return
    with _PROC_LOCK:
        event = _PROCESS_CANCEL_EVENTS.setdefault(token, threading.Event())
        event.set()


def process_cancelled(token: Optional[str]) -> bool:
    if not token:
        return False
    with _PROC_LOCK:
        event = _PROCESS_CANCEL_EVENTS.get(token)
        return bool(event and event.is_set())


def clear_process_token(token: str) -> None:
    if not token:
        return
    with _PROC_LOCK:
        _PROCESS_CANCEL_EVENTS.pop(token, None)


def _unregister_process(token: Optional[str], proc: Optional[subprocess.Popen] = None) -> None:
    if not token:
        return
    with _PROC_LOCK:
        current = _ACTIVE_PROCS.get(token)
        if current is None:
            return
        if proc is None or current is proc:
            _ACTIVE_PROCS.pop(token, None)


def _terminate_process(proc: subprocess.Popen) -> None:
    """Terminate a process and its group (started with start_new_session=True)."""
    if proc.poll() is not None:
        return
    try:
        os.killpg(proc.pid, signal.SIGTERM)
    except (ProcessLookupError, PermissionError, OSError):
        try:
            proc.terminate()
        except OSError:
            return
    try:
        proc.wait(timeout=2)
        return
    except subprocess.TimeoutExpired:
        pass
    try:
        os.killpg(proc.pid, signal.SIGKILL)
    except (ProcessLookupError, PermissionError, OSError):
        try:
            proc.kill()
        except OSError:
            return
    try:
        proc.wait(timeout=2)
    except subprocess.TimeoutExpired:
        pass


def kill_active_process(token: str) -> bool:
    """Kill the process group registered under ``token`` (typically a job_id).

    Returns True if a live process was signalled.
    """
    if not token:
        return False
    with _PROC_LOCK:
        proc = _ACTIVE_PROCS.get(token)
    if proc is None:
        return False
    if proc.poll() is not None:
        _unregister_process(token, proc)
        return False
    _terminate_process(proc)
    _unregister_process(token, proc)
    return True


def _run_tracked(
    command: Sequence[str],
    *,
    timeout: Optional[float],
    process_token: Optional[str] = None,
) -> subprocess.CompletedProcess:
    """Run argv command; when ``process_token`` is set, enable process-group cancel.

    Without a token, uses ``subprocess.run`` (compatible with existing unit mocks).
    """
    if not process_token:
        return subprocess.run(
            list(command),
            capture_output=True,
            check=False,
            text=True,
            timeout=timeout,
        )
    if process_cancelled(process_token):
        raise ScanCancelledError("Scan cancelled before process start")
    try:
        proc = subprocess.Popen(
            list(command),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            start_new_session=True,
        )
    except FileNotFoundError:
        raise
    _register_process(process_token, proc)
    if process_cancelled(process_token):
        _terminate_process(proc)
        _unregister_process(process_token, proc)
        for stream in (proc.stdout, proc.stderr):
            if stream is not None and not stream.closed:
                stream.close()
        raise ScanCancelledError("Scan cancelled during process start")
    try:
        try:
            stdout, stderr = proc.communicate(timeout=timeout)
        except subprocess.TimeoutExpired:
            _terminate_process(proc)
            _unregister_process(process_token, proc)
            raise
        completed = subprocess.CompletedProcess(
            args=list(command),
            returncode=proc.returncode if proc.returncode is not None else -1,
            stdout=stdout,
            stderr=stderr,
        )
        if process_cancelled(process_token):
            raise ScanCancelledError("Scan process terminated by cancel")
        return completed
    finally:
        _unregister_process(process_token, proc)
        for stream in (proc.stdout, proc.stderr):
            if stream is not None and not stream.closed:
                stream.close()


def supported_scan_types() -> Sequence[str]:
    return tuple(list(SCAN_TYPE_ARGS.keys()) + list(HYBRID_SCAN_TYPES.keys()))


def validate_discovery(discovery: Optional[str]) -> Tuple[Optional[str], Optional[str]]:
    if discovery is None:
        return None, None
    if not isinstance(discovery, str):
        return None, "discovery must be a string"
    cleaned = discovery.strip().lower()
    if not cleaned:
        return None, None
    if cleaned not in DISCOVERY_ENGINES:
        return None, f"Invalid discovery. Allowed: {', '.join(DISCOVERY_ENGINES)}"
    return cleaned, None


def validate_ports_expression(ports: Optional[str]) -> Tuple[Optional[str], Optional[str]]:
    if ports is None:
        return None, None
    if not isinstance(ports, str):
        return None, "ports must be a string"
    cleaned = ports.strip()
    if not cleaned:
        return None, None
    if not PORTS_RE.fullmatch(cleaned):
        return None, "ports has invalid syntax (use Nmap port expressions only)"
    return cleaned, None


def validate_scripts_expression(scripts: Optional[str]) -> Tuple[Optional[str], Optional[str]]:
    if scripts is None:
        return None, None
    if not isinstance(scripts, str):
        return None, "scripts must be a string"
    cleaned = scripts.strip()
    if not cleaned:
        return None, None
    if not SCRIPTS_RE.fullmatch(cleaned):
        return None, "scripts has invalid syntax (NSE names only)"
    if any(token in cleaned for token in (";", "|", "`", "$", "(", ")", "<", ">", "\n")):
        return None, "scripts has invalid syntax (NSE names only)"
    return cleaned, None


def build_nmap_command(
    target: str,
    scan_type: str,
    *,
    host_timeout_sec: int,
    max_retries: int,
    xml_path: Path,
    nmap_executable: Optional[str] = None,
    ports: Optional[str] = None,
    scripts: Optional[str] = None,
) -> List[str]:
    if scan_type not in SCAN_TYPE_ARGS:
        raise ValueError(f"Unsupported scan_type: {scan_type}")

    executable = nmap_executable or shutil.which("nmap")
    if not executable:
        raise NmapNotFoundError("nmap not found on PATH")

    command = [
        executable,
        *SCAN_TYPE_ARGS[scan_type],
        "--host-timeout",
        f"{host_timeout_sec}s",
        "--max-retries",
        str(max_retries),
    ]
    if ports:
        command.extend(["-p", ports])
    if scripts:
        # Allow extra scripts even when the profile already sets --script.
        command.extend(["--script", scripts])
    command.extend(["-oX", str(xml_path), target])
    return command


def _normalize_ports(ports: Sequence[int], *, limit: int = 2000) -> List[int]:
    unique = sorted({int(port) for port in ports if 1 <= int(port) <= 65535})
    return unique[:limit]


def _parse_naabu_output(stdout: str) -> List[int]:
    ports: List[int] = []
    for line in stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        if line.startswith("{"):
            try:
                payload = json.loads(line)
            except json.JSONDecodeError:
                continue
            value = payload.get("port")
            if value is not None:
                try:
                    ports.append(int(value))
                except (TypeError, ValueError):
                    pass
            continue
        if ":" in line:
            # host:port style
            tail = line.rsplit(":", 1)[-1]
            if tail.isdigit():
                ports.append(int(tail))
                continue
    return _normalize_ports(ports)


def _parse_rustscan_output(stdout: str) -> List[int]:
    ports: List[int] = []
    for line in stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        # Greppable: Open 127.0.0.1:22 or 127.0.0.1 -> [22,80]
        if "->" in line and "[" in line and "]" in line:
            bracket = line[line.find("[") + 1 : line.rfind("]")]
            for token in bracket.split(","):
                token = token.strip()
                if token.isdigit():
                    ports.append(int(token))
            continue
        endpoint_match = re.fullmatch(
            r"(?:Open\s+)?(?:\[[0-9A-Fa-f:.%]+\]|[A-Za-z0-9_.-]+):([1-9]\d{0,4})",
            line,
            flags=re.IGNORECASE,
        )
        if endpoint_match:
            ports.append(int(endpoint_match.group(1)))
            continue
        port_only_match = re.fullmatch(
            r"Open\s+([1-9]\d{0,4})",
            line,
            flags=re.IGNORECASE,
        )
        if port_only_match:
            ports.append(int(port_only_match.group(1)))
    return _normalize_ports(ports)


def available_discovery_engines() -> Dict[str, Optional[str]]:
    return {
        "naabu": shutil.which("naabu"),
        "rustscan": shutil.which("rustscan"),
        "nmap": shutil.which("nmap"),
    }


def resolve_discovery_engine(requested: str) -> str:
    engines = available_discovery_engines()
    if requested == "auto":
        if engines["naabu"]:
            return "naabu"
        if engines["rustscan"]:
            return "rustscan"
        raise DiscoveryError(
            "No discovery frontend found. Install naabu or rustscan, or use a direct Nmap profile."
        )
    if requested == "naabu":
        if not engines["naabu"]:
            raise DiscoveryError("naabu not found on PATH")
        return "naabu"
    if requested == "rustscan":
        if not engines["rustscan"]:
            raise DiscoveryError("rustscan not found on PATH")
        return "rustscan"
    raise DiscoveryError(f"Unsupported discovery engine: {requested}")


def discover_open_ports(
    target: str,
    *,
    engine: str = "auto",
    ports_hint: Optional[str] = None,
    timeout_sec: int = 120,
    process_token: Optional[str] = None,
) -> dict:
    """Run Naabu or RustScan (argv only) and return open TCP ports."""
    resolved = resolve_discovery_engine(engine)
    if resolved == "naabu":
        command = [shutil.which("naabu"), "-host", target, "-silent", "-json"]
        if ports_hint:
            command.extend(["-p", ports_hint])
        parser = _parse_naabu_output
    else:
        command = [
            shutil.which("rustscan"),
            "-a",
            target,
            "--greppable",
            "--ulimit",
            "5000",
        ]
        if ports_hint and PORTS_RE.fullmatch(ports_hint):
            # RustScan -p accepts ranges/lists in many versions.
            command.extend(["-p", ports_hint])
        parser = _parse_rustscan_output

    try:
        completed = _run_tracked(
            command,
            timeout=timeout_sec,
            process_token=process_token,
        )
    except subprocess.TimeoutExpired as exc:
        raise DiscoveryError(
            f"{resolved} exceeded the {timeout_sec}-second discovery timeout"
        ) from exc
    except FileNotFoundError as exc:
        raise DiscoveryError(f"{resolved} not found on PATH") from exc

    ports = parser(completed.stdout or "")
    if completed.returncode != 0:
        detail = (completed.stderr or completed.stdout or "").strip()[:2000]
        suffix = f": {detail}" if detail else ""
        raise DiscoveryError(
            f"{resolved} exited with status {completed.returncode}{suffix}"
        )
    return {
        "engine": resolved,
        "command": command,
        "ports": ports,
        "returncode": completed.returncode,
        "stderr": (completed.stderr or "").strip()[:2000],
    }


def ensure_operator_result(
    payload: dict,
    *,
    target: str = "",
    scan_type: str = "",
    ports: Optional[str] = None,
    scripts: Optional[str] = None,
) -> dict:
    """Normalize either ``ai-nmap-report/v1`` or operator result into operator shape.

    - Operator shape hosts use ``protocols`` maps (already returned as-is, schema filled).
    - ``kali_ai_scan`` / raw parse hosts use a flat ``ports`` list → :func:`report_to_api_result`.
    """
    if not isinstance(payload, dict):
        raise ValueError("payload must be a dict")
    hosts = payload.get("hosts")
    if not isinstance(hosts, list):
        raise ValueError("payload.hosts must be a list")
    if not hosts:
        out = dict(payload)
        out["schema"] = SCHEMA_VERSION
        out.setdefault("product", PRODUCT_NAME)
        out.setdefault("target", target or payload.get("target") or "")
        out.setdefault("scan_type", scan_type or payload.get("scan_type") or "")
        return out
    first = hosts[0] if isinstance(hosts[0], dict) else {}
    if "protocols" in first:
        out = dict(payload)
        out["schema"] = SCHEMA_VERSION
        out.setdefault("product", PRODUCT_NAME)
        if target and not out.get("target"):
            out["target"] = target
        if scan_type and not out.get("scan_type"):
            out["scan_type"] = scan_type
        return out
    # Flat ports list (ai-nmap-report / parse_nmap_xml shape).
    return report_to_api_result(
        payload,
        target=target or str(payload.get("target") or ""),
        scan_type=scan_type or str(payload.get("scan_type") or "Import"),
        ports=ports if ports is not None else payload.get("ports"),
        scripts=scripts if scripts is not None else payload.get("scripts"),
    )


def report_to_api_result(
    report: dict,
    *,
    target: str = "",
    scan_type: str = "",
    ports: Optional[str] = None,
    scripts: Optional[str] = None,
) -> dict:
    """Convert a kali_ai_scan XML report into the dashboard/API host shape."""
    hosts = []
    for host in report.get("hosts", []):
        if not isinstance(host, dict):
            continue
        host_id = str(host.get("id") or "").strip()
        if not host_id and host.get("addresses"):
            for address in host["addresses"]:
                if isinstance(address, dict) and address.get("addr"):
                    host_id = str(address["addr"])
                    break
        if not host_id:
            host_id = "unknown"

        hostnames = host.get("hostnames") or []
        hostname = hostnames[0] if hostnames else "N/A"
        protocols: Dict[str, list] = {}
        for port in host.get("ports") or []:
            if not isinstance(port, dict):
                continue
            protocol = str(port.get("protocol") or "tcp")
            service = port.get("service") if isinstance(port.get("service"), dict) else {}
            protocols.setdefault(protocol, []).append(
                {
                    "port": port.get("port"),
                    "state": port.get("state", "unknown"),
                    "name": service.get("name") or "unknown",
                    "product": service.get("product") or "unknown",
                    "version": service.get("version") or "unknown",
                    "extrainfo": service.get("extrainfo") or "",
                    "tunnel": service.get("tunnel") or "",
                    "reason": port.get("reason") or "",
                    "scripts": list(port.get("scripts") or []),
                }
            )
        for port_list in protocols.values():
            port_list.sort(key=lambda item: int(item.get("port") or 0))

        hosts.append(
            {
                "host": host_id,
                "hostname": hostname or "N/A",
                "state": host.get("status") or "unknown",
                "protocols": protocols,
                "host_scripts": list(host.get("host_scripts") or []),
                "os_matches": list(host.get("os_matches") or []),
                "trace": host.get("trace"),
            }
        )

    stats = report.get("stats") if isinstance(report.get("stats"), dict) else {}
    open_ports = sum(
        1
        for host in hosts
        for port_list in (host.get("protocols") or {}).values()
        for port in port_list
        if port.get("state") == "open"
    )
    service_counts: Dict[str, int] = {}
    for host in hosts:
        for port_list in (host.get("protocols") or {}).values():
            for port in port_list:
                if port.get("state") != "open":
                    continue
                name = str(port.get("name") or "unknown")
                service_counts[name] = service_counts.get(name, 0) + 1

    return {
        "schema": SCHEMA_VERSION,
        "product": PRODUCT_NAME,
        "scan_time": utc_now_iso(),
        "scan_count": len(hosts),
        "target": target,
        "scan_type": scan_type,
        "ports": ports,
        "scripts": scripts,
        "stats": {
            "hosts": stats.get("hosts", len(hosts)),
            "hosts_up": stats.get(
                "hosts_up",
                sum(1 for host in hosts if host.get("state") == "up"),
            ),
            "open_ports": stats.get("open_ports", open_ports),
            "services": dict(sorted(service_counts.items(), key=lambda item: (-item[1], item[0]))),
        },
        "hosts": hosts,
    }


def _open_port_index(result: dict) -> Dict[str, Dict[Tuple[str, int], dict]]:
    index: Dict[str, Dict[Tuple[str, int], dict]] = {}
    for host in result.get("hosts") or []:
        if not isinstance(host, dict):
            continue
        host_id = str(host.get("host") or "")
        if not host_id:
            continue
        port_map: Dict[Tuple[str, int], dict] = {}
        for protocol, ports in (host.get("protocols") or {}).items():
            if not isinstance(ports, list):
                continue
            for port in ports:
                if not isinstance(port, dict) or port.get("state") != "open":
                    continue
                try:
                    number = int(port.get("port"))
                except (TypeError, ValueError):
                    continue
                port_map[(str(protocol), number)] = port
        index[host_id] = port_map
    return index


def diff_scan_results(baseline: dict, current: dict) -> dict:
    """Compare two API-shaped scan results for host/port changes."""
    base_hosts = _open_port_index(baseline if isinstance(baseline, dict) else {})
    curr_hosts = _open_port_index(current if isinstance(current, dict) else {})

    base_ids = set(base_hosts)
    curr_ids = set(curr_hosts)

    hosts_added = sorted(curr_ids - base_ids)
    hosts_removed = sorted(base_ids - curr_ids)

    ports_opened = []
    ports_closed = []
    for host_id in sorted(base_ids & curr_ids):
        before = base_hosts[host_id]
        after = curr_hosts[host_id]
        for key in sorted(after.keys() - before.keys()):
            protocol, port = key
            service = after[key]
            ports_opened.append(
                {
                    "host": host_id,
                    "protocol": protocol,
                    "port": port,
                    "service": service.get("name") or "unknown",
                }
            )
        for key in sorted(before.keys() - after.keys()):
            protocol, port = key
            service = before[key]
            ports_closed.append(
                {
                    "host": host_id,
                    "protocol": protocol,
                    "port": port,
                    "service": service.get("name") or "unknown",
                }
            )

    for host_id in hosts_added:
        for protocol, port in sorted(curr_hosts[host_id].keys()):
            service = curr_hosts[host_id][(protocol, port)]
            ports_opened.append(
                {
                    "host": host_id,
                    "protocol": protocol,
                    "port": port,
                    "service": service.get("name") or "unknown",
                }
            )
    for host_id in hosts_removed:
        for protocol, port in sorted(base_hosts[host_id].keys()):
            service = base_hosts[host_id][(protocol, port)]
            ports_closed.append(
                {
                    "host": host_id,
                    "protocol": protocol,
                    "port": port,
                    "service": service.get("name") or "unknown",
                }
            )

    return {
        "schema": "recon-operator-diff/v1",
        "product": PRODUCT_NAME,
        "summary": {
            "hosts_added": len(hosts_added),
            "hosts_removed": len(hosts_removed),
            "ports_opened": len(ports_opened),
            "ports_closed": len(ports_closed),
            "changed": bool(hosts_added or hosts_removed or ports_opened or ports_closed),
        },
        "hosts_added": hosts_added,
        "hosts_removed": hosts_removed,
        "ports_opened": ports_opened,
        "ports_closed": ports_closed,
        "baseline": {
            "scan_time": baseline.get("scan_time") if isinstance(baseline, dict) else None,
            "target": baseline.get("target") if isinstance(baseline, dict) else None,
        },
        "current": {
            "scan_time": current.get("scan_time") if isinstance(current, dict) else None,
            "target": current.get("target") if isinstance(current, dict) else None,
        },
    }


def _empty_discovery_result(
    target: str,
    scan_type: str,
    *,
    discovery: dict,
    scripts: Optional[str] = None,
) -> dict:
    result = report_to_api_result(
        {
            "hosts": [],
            "stats": {"hosts": 0, "hosts_up": 0, "open_ports": 0},
        },
        target=target,
        scan_type=scan_type,
        ports="",
        scripts=scripts,
    )
    result["discovery"] = discovery
    result["message"] = "Discovery found no open ports; Nmap service scan skipped"
    return result


def run_nmap_scan(
    target: str,
    scan_type: str,
    *,
    host_timeout_sec: int = 300,
    max_retries: int = 2,
    scan_timeout_sec: int = 1800,
    nmap_executable: Optional[str] = None,
    ports: Optional[str] = None,
    scripts: Optional[str] = None,
    discovery: Optional[str] = None,
    process_token: Optional[str] = None,
) -> dict:
    """Run recon scan: optional hybrid discovery + Nmap service/port scan.

    When ``process_token`` is set (typically a job id), the running process group
    can be killed via :func:`kill_active_process`.
    """
    requested_type = scan_type
    nmap_type = scan_type
    effective_ports = ports
    discovery_meta = None

    hybrid_engine = HYBRID_SCAN_TYPES.get(scan_type)
    discovery_mode = discovery
    if hybrid_engine:
        discovery_mode = hybrid_engine
        nmap_type = HYBRID_NMAP_PROFILE
    if discovery_mode and discovery_mode != "none":
        discovery_budget = max(30, min(300, scan_timeout_sec // 2))
        discovery_meta = discover_open_ports(
            target,
            engine=discovery_mode,
            ports_hint=ports,
            timeout_sec=discovery_budget,
            process_token=process_token,
        )
        found = discovery_meta.get("ports") or []
        if not found:
            return _empty_discovery_result(
                target,
                requested_type,
                discovery=discovery_meta,
                scripts=scripts,
            )
        effective_ports = ",".join(str(port) for port in found)
        if nmap_type not in SCAN_TYPE_ARGS:
            nmap_type = HYBRID_NMAP_PROFILE

    if nmap_type not in SCAN_TYPE_ARGS:
        raise ValueError(f"Unsupported scan_type: {requested_type}")

    temporary_directory = tempfile.mkdtemp(prefix="recon-operator-")
    xml_path = Path(temporary_directory) / "scan.xml"
    try:
        xml_path.touch(mode=0o600, exist_ok=True)
        command = build_nmap_command(
            target,
            nmap_type,
            host_timeout_sec=host_timeout_sec,
            max_retries=max_retries,
            xml_path=xml_path,
            nmap_executable=nmap_executable,
            ports=effective_ports,
            scripts=scripts,
        )
        nmap_timeout = scan_timeout_sec
        if discovery_meta is not None:
            nmap_timeout = max(60, scan_timeout_sec - 5)
        try:
            completed = _run_tracked(
                command,
                timeout=nmap_timeout,
                process_token=process_token,
            )
        except subprocess.TimeoutExpired as exc:
            raise NmapTimeoutError(f"Nmap did not finish within {nmap_timeout} seconds") from exc
        except FileNotFoundError as exc:
            raise NmapNotFoundError("nmap not found on PATH") from exc

        if completed.returncode != 0:
            detail = (completed.stderr or completed.stdout or "").strip()
            # Negative or signalled exits after cancel.
            if process_cancelled(process_token) and completed.returncode in (
                -signal.SIGTERM,
                -signal.SIGKILL,
                137,
                143,
            ):
                raise ScanCancelledError("Scan process terminated by cancel")
            suffix = f": {detail}" if detail else ""
            raise NmapScanError(f"nmap exited with status {completed.returncode}{suffix}")

        if not xml_path.is_file() or xml_path.stat().st_size == 0:
            if process_cancelled(process_token):
                # Cancelled mid-write can leave empty XML.
                raise ScanCancelledError("Scan cancelled before XML was produced")
            raise NmapScanError("nmap finished without producing XML output")

        report = parse_nmap_xml(xml_path)
        result = report_to_api_result(
            report,
            target=target,
            scan_type=requested_type,
            ports=effective_ports,
            scripts=scripts,
        )
        result["command"] = command
        result["nmap_profile"] = nmap_type
        if discovery_meta is not None:
            result["discovery"] = discovery_meta
        return result
    finally:
        try:
            if xml_path.exists():
                xml_path.unlink()
        except OSError:
            pass
        try:
            os.rmdir(temporary_directory)
        except OSError:
            pass


def import_nmap_xml(
    xml_bytes: bytes,
    *,
    target: str = "",
    scan_type: str = "Import",
) -> dict:
    """Parse untrusted Nmap XML bytes into an API result (size-limited by caller)."""
    temporary_directory = tempfile.mkdtemp(prefix="recon-operator-import-")
    xml_path = Path(temporary_directory) / "import.xml"
    try:
        xml_path.write_bytes(xml_bytes)
        os.chmod(xml_path, 0o600)
        report = parse_nmap_xml(xml_path)
        result = report_to_api_result(report, target=target, scan_type=scan_type)
        result["source"] = "xml-import"
        return result
    finally:
        try:
            xml_path.unlink(missing_ok=True)
        except OSError:
            pass
        try:
            os.rmdir(temporary_directory)
        except OSError:
            pass
