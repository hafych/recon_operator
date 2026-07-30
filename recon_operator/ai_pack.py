"""Budgeted AI recon packs (token-efficient handoff).

Storage keeps full-fidelity scan results. This module builds progressive
disclosure packs for LLMs/agents: small (brief) and medium (session).
Closed ports are omitted by default. No secrets are ever included.
"""

from __future__ import annotations

import json
from typing import Any, Dict, Iterable, List, Optional, Sequence, Set, Tuple

from recon_operator.posture import load_expected_posture, posture_pack_rows
from recon_planner import build_recon_plan
from scan_engine import diff_scan_results

SCHEMA_VERSION = "recon-ai-pack/v1"

# Hard caps for budget=s (enforced after build; builder also tries to stay under).
BUDGET_S_MAX_BYTES = 4 * 1024
BUDGET_S_MAX_LINES = 100

# Soft targets used while building (leave headroom for meta).
_BUDGET_LIMITS = {
    "s": {
        "max_hosts": 8,
        "max_services": 24,
        "max_findings": 16,
        "max_next": 6,
        "max_gap": 4,
        "max_defense": 6,
        "max_ask": 3,
        "max_inv": 6,
        "max_changes": 8,
        "max_drift": 8,
        "include_plan": True,
        "include_defense": True,
        "prefer_ready_next": True,
    },
    "m": {
        "max_hosts": 32,
        "max_services": 80,
        "max_findings": 40,
        "max_next": 20,
        "max_gap": 12,
        "max_defense": 16,
        "max_ask": 5,
        "max_inv": 16,
        "max_changes": 24,
        "max_drift": 20,
        "include_plan": True,
        "include_defense": True,
        "prefer_ready_next": False,
    },
    "l": {
        "max_hosts": 256,
        "max_services": 500,
        "max_findings": 200,
        "max_next": 80,
        "max_gap": 40,
        "max_defense": 40,
        "max_ask": 8,
        "max_inv": 40,
        "max_changes": 80,
        "max_drift": 60,
        "include_plan": True,
        "include_defense": True,
        "prefer_ready_next": False,
    },
}

# Simple defense/hardening hints (no exploitation).
_DEFENSE_HINTS: Dict[str, Tuple[str, str]] = {
    "ssh": (
        "D-SSH-01",
        "Restrict SSH to management networks; prefer key-only auth and fail2ban/rate limits.",
    ),
    "http": (
        "D-HTTP-01",
        "Terminate TLS, disable unused methods, keep server headers minimal, patch web stack.",
    ),
    "https": (
        "D-TLS-01",
        "Enforce modern TLS only; check certificate validity and HSTS where appropriate.",
    ),
    "microsoft-ds": (
        "D-SMB-01",
        "Avoid exposing SMB to untrusted networks; require signing and disable guest if unused.",
    ),
    "netbios-ssn": (
        "D-SMB-01",
        "Avoid exposing SMB/NetBIOS to untrusted networks; require signing where possible.",
    ),
    "ftp": (
        "D-FTP-01",
        "Prefer SFTP/FTPS; disable anonymous FTP; isolate file services.",
    ),
    "domain": (
        "D-DNS-01",
        "Limit recursion and zone transfers; expose DNS only as intended for the engagement.",
    ),
    "ms-wbt-server": (
        "D-RDP-01",
        "Do not expose RDP to the internet; require NLA and network restrictions.",
    ),
    "rdp": (
        "D-RDP-01",
        "Do not expose RDP to the internet; require NLA and network restrictions.",
    ),
}


def normalize_budget(raw: Any) -> str:
    value = str(raw or "s").strip().lower()
    if value in {"s", "small", "brief"}:
        return "s"
    if value in {"m", "medium", "session"}:
        return "m"
    if value in {"l", "large", "full", "archive"}:
        return "l"
    raise ValueError("budget must be one of: s, m, l (or small/medium/large)")


def _iter_services(
    scan: Dict[str, Any],
    *,
    states: Set[str],
) -> Iterable[Dict[str, Any]]:
    hosts = scan.get("hosts") if isinstance(scan, dict) else None
    if not isinstance(hosts, list):
        return
    for host_row in hosts:
        if not isinstance(host_row, dict):
            continue
        host = str(host_row.get("host") or "").strip()
        if not host:
            continue
        hostname = host_row.get("hostname")
        if hostname in (None, "", "N/A"):
            hostname = None
        host_state = str(host_row.get("state") or "unknown")
        protocols = host_row.get("protocols") or {}
        if not isinstance(protocols, dict):
            continue
        for protocol, ports in protocols.items():
            if not isinstance(ports, list):
                continue
            for port_row in ports:
                if not isinstance(port_row, dict):
                    continue
                port_state = str(port_row.get("state") or "unknown").lower()
                if port_state not in states:
                    continue
                try:
                    port = int(port_row.get("port"))
                except (TypeError, ValueError):
                    continue
                if not 1 <= port <= 65535:
                    continue
                yield {
                    "host": host,
                    "hostname": hostname,
                    "host_state": host_state,
                    "protocol": str(protocol or "tcp"),
                    "port": port,
                    "state": port_state,
                    "name": str(port_row.get("name") or "unknown").lower(),
                    "product": port_row.get("product"),
                    "version": port_row.get("version"),
                }


def _iter_open_services(scan: Dict[str, Any]) -> Iterable[Dict[str, Any]]:
    yield from _iter_services(scan, states={"open"})


def _finding_for_service(svc: Dict[str, Any], index: int) -> Dict[str, Any]:
    service = svc["name"]
    code = service.upper().replace("/", "-")[:12] or "SVC"
    title = f"Open {svc['protocol']}/{svc['port']} ({service})"
    product = svc.get("product")
    if product and product not in (None, "", "unknown"):
        version = svc.get("version")
        if version and version not in (None, "", "unknown"):
            title = f"{title}: {product} {version}"
        else:
            title = f"{title}: {product}"
    return {
        "t": "finding",
        "id": f"F-{code}-{index:02d}",
        "sev": "info",
        "title": title,
        "host": svc["host"],
        "port": svc["port"],
        "proto": svc["protocol"],
        "service": service,
    }


def _defense_for_service(svc: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    service = svc["name"]
    hint = _DEFENSE_HINTS.get(service)
    if not hint:
        # token match
        for key, value in _DEFENSE_HINTS.items():
            if key in service:
                hint = value
                break
    if not hint:
        return None
    defense_id, advice = hint
    return {
        "t": "defense",
        "id": defense_id,
        "host": svc["host"],
        "port": svc["port"],
        "service": service,
        "advice": advice,
    }


def _line_bytes(row: Dict[str, Any]) -> int:
    return len(json.dumps(row, ensure_ascii=False, separators=(",", ":")).encode("utf-8")) + 1


def build_ai_pack_rows(
    scan: Dict[str, Any],
    *,
    budget: str = "s",
    inventory: Optional[Dict[str, Any]] = None,
    include_closed: bool = False,
    job_id: Optional[str] = None,
    result_id: Optional[str] = None,
    plan: Optional[Dict[str, Any]] = None,
    expected_posture: Optional[Dict[str, Any]] = None,
) -> List[Dict[str, Any]]:
    """Build ordered pack rows for the given budget.

    Closed ports are omitted unless ``include_closed`` is true (rarely needed).
    """
    budget_key = normalize_budget(budget)
    limits = _BUDGET_LIMITS[budget_key]
    if not isinstance(scan, dict):
        raise ValueError("scan must be a parsed result object")
    if expected_posture is None:
        try:
            expected_posture = load_expected_posture()
        except RuntimeError:
            expected_posture = None

    include_closed_effective = bool(include_closed and budget_key == "l")
    hosts_seen_all: List[str] = []
    host_meta: Dict[str, Dict[str, Any]] = {}
    scan_hosts = scan.get("hosts")
    for host_row in scan_hosts if isinstance(scan_hosts, list) else []:
        if not isinstance(host_row, dict):
            continue
        host = str(host_row.get("host") or "").strip()
        if not host:
            continue
        if host not in host_meta:
            hosts_seen_all.append(host)
            hostname = host_row.get("hostname")
            host_meta[host] = {
                "t": "host",
                "ip": host,
                "hostname": hostname if hostname not in (None, "", "N/A") else None,
                "status": str(host_row.get("state") or "unknown"),
            }

    hosts_seen = hosts_seen_all[: int(limits["max_hosts"])]
    allowed_hosts = set(hosts_seen)
    max_services = int(limits["max_services"])
    all_open_services = list(_iter_open_services(scan))
    eligible_open_services = [
        service for service in all_open_services if service["host"] in allowed_hosts
    ]
    open_services = eligible_open_services[:max_services]
    all_closed_services: List[Dict[str, Any]] = []
    eligible_closed_services: List[Dict[str, Any]] = []
    if include_closed_effective:
        all_closed_services = list(_iter_services(scan, states={"closed"}))
        eligible_closed_services = [
            service for service in all_closed_services if service["host"] in allowed_hosts
        ]
    closed_services = eligible_closed_services[
        : max(0, max_services - len(open_services))
    ]
    services = open_services + closed_services
    source_truncated = (
        len(hosts_seen) < len(hosts_seen_all)
        or len(open_services) < len(all_open_services)
        or (
            include_closed_effective
            and len(closed_services) < len(all_closed_services)
        )
    )

    rows: List[Dict[str, Any]] = []
    meta = {
        "t": "meta",
        "schema": SCHEMA_VERSION,
        "budget": budget_key,
        "target": scan.get("target"),
        "scan_type": scan.get("scan_type"),
        "open_services": len(open_services),
        "closed_services": len(closed_services),
        "hosts": len(hosts_seen),
        "open_services_total": len(all_open_services),
        "closed_services_total": len(all_closed_services),
        "hosts_total": len(hosts_seen_all),
        "source_truncated": source_truncated,
        "truncated": source_truncated,
        "include_closed": include_closed_effective,
        "guardrail": "authorized-enumeration-only; no auto-exploit",
        "usage": "Prefer this pack over full result JSON in LLM context",
    }
    if job_id:
        meta["job_id"] = str(job_id)[:64]
    if result_id:
        meta["result_id"] = str(result_id)[:260]
    rows.append(meta)

    for host in hosts_seen:
        row = dict(host_meta[host])
        if not row.get("hostname"):
            row.pop("hostname", None)
        rows.append(row)

    for svc in services:
        svc_row = {
            "t": "svc",
            "ip": svc["host"],
            "port": svc["port"],
            "proto": svc["protocol"],
            "name": svc["name"],
            "state": svc["state"],
        }
        if svc.get("hostname"):
            svc_row["hostname"] = svc["hostname"]
        product = svc.get("product")
        if product and product not in (None, "", "unknown"):
            svc_row["product"] = product
        version = svc.get("version")
        if version and version not in (None, "", "unknown"):
            svc_row["version"] = version
        rows.append(svc_row)

    findings = []
    for index, svc in enumerate(open_services, start=1):
        if len(findings) >= int(limits["max_findings"]):
            break
        findings.append(_finding_for_service(svc, index))
    rows.extend(findings)

    defense_rows: List[Dict[str, Any]] = []
    if limits["include_defense"]:
        seen_defense: Set[str] = set()
        for svc in open_services:
            if len(defense_rows) >= int(limits["max_defense"]):
                break
            defense = _defense_for_service(svc)
            if not defense:
                continue
            key = f"{defense['id']}:{defense['host']}:{defense['port']}"
            if key in seen_defense:
                continue
            seen_defense.add(key)
            defense_rows.append(defense)
        rows.extend(defense_rows)

    # Plan-derived next/gap signals.
    if limits["include_plan"]:
        plan_obj = plan
        if plan_obj is None:
            plan_obj = build_recon_plan(scan, inventory=inventory)
        recommendations = plan_obj.get("recommendations") if isinstance(plan_obj, dict) else []
        if not isinstance(recommendations, list):
            recommendations = []
        ready = [r for r in recommendations if isinstance(r, dict) and r.get("status") == "ready"]
        missing = [
            r for r in recommendations if isinstance(r, dict) and r.get("status") == "missing"
        ]
        unknown = [
            r for r in recommendations if isinstance(r, dict) and r.get("status") == "unknown"
        ]
        next_pool = ready if limits["prefer_ready_next"] else (ready + unknown + missing)
        if not limits["prefer_ready_next"]:
            # Still put ready first for usefulness.
            next_pool = ready + [r for r in recommendations if r not in ready]

        next_count = 0
        for rec in next_pool:
            if next_count >= int(limits["max_next"]):
                break
            if not isinstance(rec, dict):
                continue
            if rec.get("host") and rec["host"] not in allowed_hosts and allowed_hosts:
                continue
            rows.append(
                {
                    "t": "next",
                    "tool": rec.get("tool"),
                    "status": rec.get("status"),
                    "host": rec.get("host"),
                    "port": rec.get("port"),
                    "service": rec.get("service"),
                    "cmd": rec.get("command"),
                    "purpose": rec.get("purpose"),
                }
            )
            next_count += 1

        gap_count = 0
        seen_packages: Set[str] = set()
        for rec in missing:
            if gap_count >= int(limits["max_gap"]):
                break
            package = str(rec.get("package") or rec.get("tool") or "")
            if not package or package in seen_packages:
                continue
            seen_packages.add(package)
            rows.append(
                {
                    "t": "gap",
                    "tool": rec.get("tool"),
                    "package": package,
                    "status": "missing",
                    "hint": f"Install package '{package}' to enable {rec.get('tool')}",
                }
            )
            gap_count += 1

        # Inventory delta: only packages relevant to open-service plan steps.
        inv_rows = _inventory_delta_rows(
            recommendations,
            max_rows=int(limits["max_inv"]),
        )
        rows.extend(inv_rows)

    # Defense posture drift (optional expected posture).
    posture_rows = posture_pack_rows(scan, expected_posture, max_rows=int(limits["max_drift"]))
    rows.extend(posture_rows)

    # Clarifying questions (cheap, capped).
    ask_rows: List[Dict[str, Any]] = []
    if open_services:
        ask_rows.append(
            {
                "t": "ask",
                "q": "Which of these open services are intentionally exposed on this engagement scope?",
            }
        )
    if any(service["name"] in {"http", "https"} for service in open_services):
        ask_rows.append(
            {
                "t": "ask",
                "q": "Is web content scanning authorized beyond passive header/fingerprint checks?",
            }
        )
    if any(service["name"] == "ssh" for service in open_services):
        ask_rows.append(
            {
                "t": "ask",
                "q": "Should SSH be reachable only from a management network?",
            }
        )
    rows.extend(ask_rows[: int(limits["max_ask"])])

    # Enforce hard caps for budget=s after build (trim tail, keep meta).
    if budget_key == "s":
        rows = _apply_budget_s_hard_caps(rows)

    return rows


def _enforce_hard_caps(
    rows: List[Dict[str, Any]], *, max_lines: int, max_bytes: int
) -> List[Dict[str, Any]]:
    if not rows:
        return rows
    kept: List[Dict[str, Any]] = [rows[0]]
    size = _line_bytes(rows[0])
    for row in rows[1:]:
        if len(kept) >= max_lines:
            break
        line_size = _line_bytes(row)
        if size + line_size > max_bytes:
            break
        kept.append(row)
        size += line_size
    if kept and kept[0].get("t") == "meta":
        kept[0] = dict(kept[0])
        kept[0]["truncated"] = bool(
            kept[0].get("truncated") or len(kept) < len(rows)
        )
    return kept


def _stamp_budget_s_meta(
    rows: List[Dict[str, Any]], *, truncated: bool, original_len: int
) -> List[Dict[str, Any]]:
    """Attach truncated/lines/bytes to meta so the serialized size is self-consistent."""
    if not rows:
        return rows
    rest = list(rows[1:]) if rows[0].get("t") == "meta" else list(rows)
    meta = (
        dict(rows[0])
        if rows[0].get("t") == "meta"
        else {
            "t": "meta",
            "schema": SCHEMA_VERSION,
            "budget": "s",
        }
    )
    meta.pop("bytes", None)
    meta["truncated"] = bool(
        meta.get("truncated") or truncated or len(rows) < original_len
    )
    meta["lines"] = 1 + len(rest)
    provisional = [meta] + rest
    # Iterate a few times so the decimal width of ``bytes`` stabilizes.
    for _ in range(4):
        meta = dict(provisional[0])
        meta["bytes"] = pack_bytes(provisional)
        provisional[0] = meta
    return provisional


def _apply_budget_s_hard_caps(rows: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Trim until the final stamped pack fits both hard caps (no post-stamp overflow)."""
    if not rows:
        return rows
    original_len = len(rows)
    kept = _enforce_hard_caps(rows, max_lines=BUDGET_S_MAX_LINES, max_bytes=BUDGET_S_MAX_BYTES)
    truncated = len(kept) < original_len

    while kept:
        stamped = _stamp_budget_s_meta(kept, truncated=truncated, original_len=original_len)
        size = pack_bytes(stamped)
        if size <= BUDGET_S_MAX_BYTES and len(stamped) <= BUDGET_S_MAX_LINES:
            return stamped
        if len(kept) <= 1:
            # Only meta left: strip verbose keys, then fall back to minimal meta.
            meta = (
                dict(stamped[0])
                if stamped
                else {
                    "t": "meta",
                    "schema": SCHEMA_VERSION,
                    "budget": "s",
                }
            )
            for key in ("usage", "guardrail", "open_services", "hosts", "include_closed"):
                meta.pop(key, None)
            meta["truncated"] = True
            slim = _stamp_budget_s_meta([meta], truncated=True, original_len=original_len)
            if pack_bytes(slim) <= BUDGET_S_MAX_BYTES:
                return slim
            return [
                {
                    "t": "meta",
                    "schema": SCHEMA_VERSION,
                    "budget": "s",
                    "truncated": True,
                }
            ]
        truncated = True
        kept = kept[:-1]
    return kept


def pack_bytes(rows: Sequence[Dict[str, Any]]) -> int:
    return sum(_line_bytes(row) for row in rows)


def pack_to_ndjson(rows: Sequence[Dict[str, Any]]) -> str:
    return (
        "\n".join(json.dumps(row, ensure_ascii=False, separators=(",", ":")) for row in rows) + "\n"
    )


def pack_to_json(rows: Sequence[Dict[str, Any]]) -> str:
    return json.dumps(
        {"schema": SCHEMA_VERSION, "rows": list(rows)},
        ensure_ascii=False,
        separators=(",", ":"),
    )


def _serialized_pack_bytes(rows: Sequence[Dict[str, Any]], fmt: str) -> int:
    if fmt == "json":
        body = pack_to_json(rows)
    else:
        body = pack_to_ndjson(rows)
    return len(body.encode("utf-8"))


def _stamp_serialized_meta(
    rows: List[Dict[str, Any]],
    *,
    fmt: str,
    truncated: bool,
    original_len: int,
) -> List[Dict[str, Any]]:
    """Stamp metadata for the actual response serialization, including wrapper bytes."""
    if not rows:
        return rows
    rest = list(rows[1:]) if rows[0].get("t") == "meta" else list(rows)
    meta = (
        dict(rows[0])
        if rows[0].get("t") == "meta"
        else {"t": "meta", "schema": SCHEMA_VERSION, "budget": "s"}
    )
    meta.pop("bytes", None)
    meta["truncated"] = bool(
        meta.get("truncated") or truncated or len(rows) < original_len
    )
    meta["lines"] = 1 + len(rest)
    stamped = [meta] + rest
    for _ in range(6):
        next_meta = dict(stamped[0])
        next_meta["bytes"] = _serialized_pack_bytes(stamped, fmt)
        stamped[0] = next_meta
    return stamped


def _fit_budget_s_serialization(
    rows: List[Dict[str, Any]], *, fmt: str
) -> List[Dict[str, Any]]:
    """Make the final JSON or JSONL representation honor the advertised hard cap."""
    if not rows:
        return rows
    original_len = len(rows)
    kept = list(rows[:BUDGET_S_MAX_LINES])
    truncated = len(kept) < original_len
    while kept:
        stamped = _stamp_serialized_meta(
            kept,
            fmt=fmt,
            truncated=truncated,
            original_len=original_len,
        )
        if _serialized_pack_bytes(stamped, fmt) <= BUDGET_S_MAX_BYTES:
            return stamped
        if len(kept) > 1:
            truncated = True
            kept.pop()
            continue
        meta = dict(stamped[0])
        for key in (
            "usage",
            "guardrail",
            "open_services",
            "closed_services",
            "hosts",
            "include_closed",
        ):
            meta.pop(key, None)
        meta["truncated"] = True
        slim = _stamp_serialized_meta(
            [meta],
            fmt=fmt,
            truncated=True,
            original_len=original_len,
        )
        if _serialized_pack_bytes(slim, fmt) <= BUDGET_S_MAX_BYTES:
            return slim
        return [
            {
                "t": "meta",
                "schema": SCHEMA_VERSION,
                "budget": "s",
                "truncated": True,
            }
        ]
    return kept


def _inventory_delta_rows(
    recommendations: Sequence[Dict[str, Any]], *, max_rows: int
) -> List[Dict[str, Any]]:
    """Compact package readiness rows only for tools tied to open services."""
    rows: List[Dict[str, Any]] = []
    seen: Set[str] = set()
    for rec in recommendations:
        if not isinstance(rec, dict):
            continue
        package = str(rec.get("package") or rec.get("tool") or "").strip()
        if not package or package in seen:
            continue
        seen.add(package)
        status = str(rec.get("status") or "unknown")
        rows.append(
            {
                "t": "inv",
                "package": package,
                "tool": rec.get("tool"),
                "status": status,
                "service": rec.get("service"),
                "reason": f"relevant to open {rec.get('service') or 'service'}",
            }
        )
        if len(rows) >= max_rows:
            break
    return rows


def _change_finding_id(kind: str, host: str, protocol: str, port: int) -> str:
    host_part = "".join(ch for ch in host if ch.isalnum())[:8] or "host"
    return f"C-{kind[:3].upper()}-{host_part}-{protocol}{port}"


def build_retest_pack_rows(
    baseline: Dict[str, Any],
    current: Dict[str, Any],
    *,
    budget: str = "s",
    inventory: Optional[Dict[str, Any]] = None,
    expected_posture: Optional[Dict[str, Any]] = None,
) -> List[Dict[str, Any]]:
    """Compact retest brief: current open services + defense + diff-focused changes."""
    if not isinstance(baseline, dict) or not isinstance(current, dict):
        raise ValueError("baseline and current must be parsed scan objects")
    budget_key = normalize_budget(budget)
    limits = _BUDGET_LIMITS[budget_key]
    diff = diff_scan_results(baseline, current)

    # Start from current pack (open services, findings, defense, next/gap).
    rows = build_ai_pack_rows(
        current,
        budget=budget,
        inventory=inventory,
        expected_posture=expected_posture,
    )
    if rows and rows[0].get("t") == "meta":
        meta = dict(rows[0])
        meta["mode"] = "retest"
        meta["usage"] = "Retest brief: prioritize t=change and t=diff; full archive via /results"
        summary = diff.get("summary") if isinstance(diff.get("summary"), dict) else {}
        meta["diff_changed"] = bool(summary.get("changed"))
        meta["ports_opened"] = int(summary.get("ports_opened") or 0)
        meta["ports_closed"] = int(summary.get("ports_closed") or 0)
        rows[0] = meta

    # Insert diff summary + change rows after meta.
    insert_at = 1
    diff_row = {
        "t": "diff",
        "changed": bool((diff.get("summary") or {}).get("changed")),
        "hosts_added": len(diff.get("hosts_added") or []),
        "hosts_removed": len(diff.get("hosts_removed") or []),
        "ports_opened": len(diff.get("ports_opened") or []),
        "ports_closed": len(diff.get("ports_closed") or []),
    }
    change_rows: List[Dict[str, Any]] = []
    for item in diff.get("ports_opened") or []:
        if not isinstance(item, dict):
            continue
        host = str(item.get("host") or "")
        protocol = str(item.get("protocol") or "tcp")
        try:
            port = int(item.get("port"))
        except (TypeError, ValueError):
            continue
        change_rows.append(
            {
                "t": "change",
                "op": "opened",
                "id": _change_finding_id("open", host, protocol, port),
                "host": host,
                "port": port,
                "proto": protocol,
                "service": item.get("service") or item.get("name") or "unknown",
            }
        )
        if len(change_rows) >= int(limits["max_changes"]):
            break
    if len(change_rows) < int(limits["max_changes"]):
        for item in diff.get("ports_closed") or []:
            if not isinstance(item, dict):
                continue
            host = str(item.get("host") or "")
            protocol = str(item.get("protocol") or "tcp")
            try:
                port = int(item.get("port"))
            except (TypeError, ValueError):
                continue
            change_rows.append(
                {
                    "t": "change",
                    "op": "closed",
                    "id": _change_finding_id("cls", host, protocol, port),
                    "host": host,
                    "port": port,
                    "proto": protocol,
                    "service": item.get("service") or item.get("name") or "unknown",
                }
            )
            if len(change_rows) >= int(limits["max_changes"]):
                break

    rows = rows[:insert_at] + [diff_row] + change_rows + rows[insert_at:]
    if budget_key == "s":
        rows = _apply_budget_s_hard_caps(rows)
        if rows and rows[0].get("t") == "meta":
            rows[0] = dict(rows[0])
            rows[0]["mode"] = "retest"
    return rows


def build_ai_pack(
    scan: Dict[str, Any],
    *,
    budget: str = "s",
    inventory: Optional[Dict[str, Any]] = None,
    format: str = "jsonl",
    job_id: Optional[str] = None,
    result_id: Optional[str] = None,
    plan: Optional[Dict[str, Any]] = None,
    include_closed: bool = False,
    baseline: Optional[Dict[str, Any]] = None,
    mode: Optional[str] = None,
    expected_posture: Optional[Dict[str, Any]] = None,
) -> Tuple[str, str, List[Dict[str, Any]]]:
    """Return (body, content_type, rows).

    When ``mode=retest`` or ``baseline`` is provided, builds a retest-oriented pack.
    """
    mode_key = str(mode or "").strip().lower()
    if baseline is not None or mode_key in {"retest", "diff"}:
        if baseline is None:
            raise ValueError("retest mode requires baseline scan object")
        rows = build_retest_pack_rows(
            baseline,
            scan,
            budget=budget,
            inventory=inventory,
            expected_posture=expected_posture,
        )
    else:
        rows = build_ai_pack_rows(
            scan,
            budget=budget,
            inventory=inventory,
            include_closed=include_closed,
            job_id=job_id,
            result_id=result_id,
            plan=plan,
            expected_posture=expected_posture,
        )
    fmt = str(format or "jsonl").strip().lower()
    fmt_key = "json" if fmt in {"json", "application/json"} else "jsonl"
    if normalize_budget(budget) == "s":
        rows = _fit_budget_s_serialization(rows, fmt=fmt_key)
    if fmt_key == "json":
        return pack_to_json(rows), "application/json; charset=utf-8", rows
    return pack_to_ndjson(rows), "application/x-ndjson; charset=utf-8", rows


def pack_from_json_file(
    path: str,
    *,
    budget: str = "s",
    inventory: Optional[Dict[str, Any]] = None,
    format: str = "jsonl",
    baseline_path: Optional[str] = None,
) -> Tuple[str, str, List[Dict[str, Any]]]:
    """Offline helper: load scan JSON from disk and build a pack (CLI path)."""
    from pathlib import Path

    from scan_engine import ensure_operator_result

    text = Path(path).read_text(encoding="utf-8")
    scan = json.loads(text)
    if not isinstance(scan, dict):
        raise ValueError("scan file must contain a JSON object")
    # Allow {scan: {...}} wrappers.
    if "hosts" not in scan and isinstance(scan.get("scan"), dict):
        scan = scan["scan"]
    if "hosts" not in scan and isinstance(scan.get("result"), dict):
        scan = scan["result"]
    scan = ensure_operator_result(scan)
    baseline = None
    if baseline_path:
        base_raw = json.loads(Path(baseline_path).read_text(encoding="utf-8"))
        if isinstance(base_raw, dict):
            if "hosts" in base_raw:
                baseline = base_raw
            elif isinstance(base_raw.get("scan"), dict):
                baseline = base_raw["scan"]
            elif isinstance(base_raw.get("result"), dict):
                baseline = base_raw["result"]
        if baseline is None:
            raise ValueError("baseline file must contain a parsed scan object")
        baseline = ensure_operator_result(baseline)
    return build_ai_pack(
        scan,
        budget=budget,
        inventory=inventory,
        format=format,
        baseline=baseline,
        mode="retest" if baseline is not None else None,
    )
