"""Expected service posture and drift detection for defense verification.

Operators declare which services should be exposed; compare against a parsed
scan result to produce machine-readable drift rows for AI packs and retests.
"""

from __future__ import annotations

import ipaddress
import json
import os
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple


def _normalize_host(value: Any) -> Optional[str]:
    text = str(value or "").strip()
    if not text:
        return None
    try:
        return str(ipaddress.ip_address(text))
    except ValueError:
        return text.rstrip(".").lower()


def _service_name_matches(expected: str, observed: str) -> bool:
    return expected in {"unknown", "*"} or observed == "unknown" or expected == observed


def _open_service_keys(scan: Dict[str, Any]) -> Set[Tuple[str, str, int, str]]:
    """Return set of (host, proto, port, service_name) for open ports."""
    found: Set[Tuple[str, str, int, str]] = set()
    hosts = scan.get("hosts") if isinstance(scan, dict) else None
    if not isinstance(hosts, list):
        return found
    for host_row in hosts:
        if not isinstance(host_row, dict):
            continue
        host = _normalize_host(host_row.get("host"))
        if not host:
            continue
        protocols = host_row.get("protocols") or {}
        if not isinstance(protocols, dict):
            continue
        for protocol, ports in protocols.items():
            if not isinstance(ports, list):
                continue
            for port_row in ports:
                if not isinstance(port_row, dict):
                    continue
                if str(port_row.get("state") or "").lower() != "open":
                    continue
                try:
                    port = int(port_row.get("port"))
                except (TypeError, ValueError):
                    continue
                name = str(port_row.get("name") or "unknown").lower()
                found.add((host, str(protocol or "tcp").lower(), port, name))
    return found


def load_expected_posture(
    raw: Optional[str] = None,
    *,
    file_path: Optional[str] = None,
) -> Optional[Dict[str, Any]]:
    """Load expected posture from explicit JSON, env, or file.

    Shape::

        {
          "deny_unexpected": true,
          "services": [
            {"port": 22, "proto": "tcp", "name": "ssh"},
            {"port": 443, "proto": "tcp", "name": "https"}
          ]
        }

    Host is optional; when omitted, rules apply to any host in the scan.
    """
    text = (raw or "").strip()
    if not text:
        text = os.getenv("EXPECTED_POSTURE", "").strip()
    path = (file_path or os.getenv("EXPECTED_POSTURE_FILE", "")).strip()
    if not text and path:
        p = Path(path)
        if not p.is_file():
            raise RuntimeError(f"EXPECTED_POSTURE_FILE not found: {path}")
        text = p.read_text(encoding="utf-8")
    if not text:
        return None
    try:
        parsed = json.loads(text)
    except json.JSONDecodeError as exc:
        raise RuntimeError("EXPECTED_POSTURE must be valid JSON") from exc
    if not isinstance(parsed, dict):
        raise RuntimeError("EXPECTED_POSTURE must be a JSON object")
    services = parsed.get("services")
    if services is None:
        services = []
    if not isinstance(services, list):
        raise RuntimeError("EXPECTED_POSTURE.services must be an array")
    deny_unexpected = parsed.get("deny_unexpected", True)
    if not isinstance(deny_unexpected, bool):
        raise RuntimeError("EXPECTED_POSTURE.deny_unexpected must be boolean")
    normalized: List[Dict[str, Any]] = []
    for index, item in enumerate(services):
        if not isinstance(item, dict):
            raise RuntimeError(f"EXPECTED_POSTURE.services[{index}] must be an object")
        raw_port = item.get("port")
        if isinstance(raw_port, bool):
            raise RuntimeError(f"EXPECTED_POSTURE.services[{index}].port must be int")
        if isinstance(raw_port, float) and not raw_port.is_integer():
            raise RuntimeError(f"EXPECTED_POSTURE.services[{index}].port must be int")
        try:
            port = int(raw_port)
        except (TypeError, ValueError) as exc:
            raise RuntimeError(f"EXPECTED_POSTURE.services[{index}].port must be int") from exc
        if not 1 <= port <= 65535:
            raise RuntimeError(f"EXPECTED_POSTURE.services[{index}].port out of range")
        normalized.append(
            {
                "host": _normalize_host(item.get("host")),
                "proto": str(item.get("proto") or item.get("protocol") or "tcp").lower(),
                "port": port,
                "name": str(item.get("name") or item.get("service") or "unknown").lower(),
            }
        )
    return {
        "deny_unexpected": deny_unexpected,
        "services": normalized,
    }


def evaluate_posture(
    scan: Dict[str, Any],
    expected: Optional[Dict[str, Any]],
    *,
    max_rows: int = 40,
) -> Dict[str, Any]:
    """Compare open services to expected posture.

    Returns summary + drift list::

        {"t":"drift","op":"unexpected"|"missing", "id":"DRIFT-...", ...}
    """
    if not expected or not isinstance(expected, dict):
        return {
            "enabled": False,
            "deny_unexpected": False,
            "expected_count": 0,
            "open_count": 0,
            "unexpected": 0,
            "missing": 0,
            "drifts": [],
        }

    open_keys = _open_service_keys(scan)
    deny_unexpected = bool(expected.get("deny_unexpected", True))
    expected_services = expected.get("services") or []
    if not isinstance(expected_services, list):
        expected_services = []

    drifts: List[Dict[str, Any]] = []
    # Missing expected services.
    for rule in expected_services:
        if not isinstance(rule, dict):
            continue
        port = int(rule["port"])
        proto = str(rule.get("proto") or "tcp")
        name = str(rule.get("name") or "unknown").lower()
        host_rule = rule.get("host")
        matched = False
        for host, p_proto, p_port, p_name in open_keys:
            if p_port != port or p_proto != proto:
                continue
            if host_rule and host != _normalize_host(host_rule):
                continue
            if not _service_name_matches(name, p_name):
                continue
            matched = True
            break
        if not matched:
            host_label = host_rule or "*"
            drifts.append(
                {
                    "t": "drift",
                    "op": "missing",
                    "id": f"DRIFT-MISS-{proto}{port}",
                    "host": host_label,
                    "port": port,
                    "proto": proto,
                    "service": name,
                    "advice": f"Expected {proto}/{port} ({name}) not observed open.",
                }
            )

    # Unexpected open services.
    if deny_unexpected:
        expected_ports: Set[Tuple[Optional[str], str, int, str]] = set()
        for rule in expected_services:
            if not isinstance(rule, dict):
                continue
            expected_ports.add(
                (
                    _normalize_host(rule.get("host")),
                    str(rule.get("proto") or "tcp").lower(),
                    int(rule["port"]),
                    str(rule.get("name") or "unknown").lower(),
                )
            )
        for host, proto, port, name in sorted(open_keys):
            allowed = False
            for host_rule, e_proto, e_port, e_name in expected_ports:
                if e_proto == proto and e_port == port and _service_name_matches(e_name, name):
                    if host_rule is None or host_rule == host:
                        allowed = True
                        break
            if not allowed:
                drifts.append(
                    {
                        "t": "drift",
                        "op": "unexpected",
                        "id": f"DRIFT-UNX-{proto}{port}-{host[:8]}",
                        "host": host,
                        "port": port,
                        "proto": proto,
                        "service": name,
                        "advice": (f"Unexpected open {proto}/{port} ({name}) vs expected posture."),
                    }
                )

    unexpected = sum(1 for drift in drifts if drift.get("op") == "unexpected")
    missing = sum(1 for drift in drifts if drift.get("op") == "missing")
    drifts = drifts[: max(0, int(max_rows))]
    return {
        "enabled": True,
        "deny_unexpected": deny_unexpected,
        "expected_count": len(expected_services),
        "open_count": len(open_keys),
        "unexpected": unexpected,
        "missing": missing,
        "drifts": drifts,
    }


def posture_pack_rows(
    scan: Dict[str, Any],
    expected: Optional[Dict[str, Any]],
    *,
    max_rows: int = 12,
) -> List[Dict[str, Any]]:
    """Rows suitable for inclusion in an AI pack."""
    report = evaluate_posture(scan, expected, max_rows=max_rows)
    if not report.get("enabled"):
        return []
    rows: List[Dict[str, Any]] = [
        {
            "t": "posture",
            "expected": report["expected_count"],
            "open": report["open_count"],
            "unexpected": report["unexpected"],
            "missing": report["missing"],
            "deny_unexpected": report["deny_unexpected"],
        }
    ]
    rows.extend(report.get("drifts") or [])
    return rows
