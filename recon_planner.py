"""Build AI-readable safe recon plans from parsed Nmap results."""

import ipaddress
import json
import re
import shlex
from typing import Dict, List

SCHEMA_VERSION = "service-recon-plan/v1"

HTTP_PORTS = {80, 443, 8000, 8080, 8081, 8443, 8888}
TLS_PORTS = {443, 8443, 9443}
HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}\.?$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)*"
    r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.?$"
)

SERVICE_PROFILES = [
    {
        "name": "web",
        "protocols": {"tcp"},
        "ports": HTTP_PORTS,
        "services": {"http", "https", "http-proxy", "http-alt", "ssl/http"},
        "steps": [
            {
                "tool": "curl",
                "package": "curl",
                "purpose": "Capture HTTP headers.",
                "command": "curl -k -I {url}",
            },
            {
                "tool": "whatweb",
                "package": "whatweb",
                "purpose": "Fingerprint web technologies.",
                "command": "whatweb {url}",
            },
            {
                "tool": "feroxbuster",
                "package": "feroxbuster",
                "purpose": "Enumerate common web paths without exploitation.",
                "command": "feroxbuster -u {url} -k -w /usr/share/seclists/Discovery/Web-Content/common.txt",
            },
            {
                "tool": "nikto",
                "package": "nikto",
                "purpose": "Run a standard web server misconfiguration check.",
                "command": "nikto -h {url}",
            },
        ],
    },
    {
        "name": "ssh",
        "protocols": {"tcp"},
        "ports": {22, 2222},
        "services": {"ssh"},
        "steps": [
            {
                "tool": "ssh-audit",
                "package": "ssh-audit",
                "purpose": "Audit SSH algorithms and banner safely.",
                "command": "ssh-audit {endpoint}",
            }
        ],
    },
    {
        "name": "smb",
        "protocols": {"tcp"},
        "ports": {139, 445},
        "services": {"microsoft-ds", "netbios-ssn", "smb"},
        "steps": [
            {
                "tool": "nmap",
                "package": "nmap",
                "purpose": "Enumerate SMB metadata with safe NSE scripts.",
                "command": "nmap --script smb-os-discovery,smb-enum-shares -p{port} {host}",
            },
            {
                "tool": "smbclient",
                "package": "smbclient",
                "purpose": "List anonymous SMB shares when allowed.",
                "command": "smbclient -L //{host}/ -N",
            },
            {
                "tool": "enum4linux-ng",
                "package": "enum4linux-ng",
                "purpose": "Collect SMB/NetBIOS enumeration data.",
                "command": "enum4linux-ng -A {host}",
            },
        ],
    },
    {
        "name": "dns",
        "protocols": {"tcp", "udp"},
        "ports": {53},
        "services": {"domain", "dns"},
        "steps": [
            {
                "tool": "dig",
                "package": "dnsutils",
                "purpose": "Query DNS server metadata.",
                "command": "dig @{host} version.bind chaos txt",
            },
            {
                "tool": "dnsrecon",
                "package": "dnsrecon",
                "purpose": "Run DNS enumeration for the authorized target name.",
                "command": "dnsrecon -d {name} -n {host}",
                "requires_hostname": True,
            },
        ],
    },
    {
        "name": "tls",
        "protocols": {"tcp"},
        "ports": TLS_PORTS,
        "services": {"ssl", "https", "ssl/http"},
        "steps": [
            {
                "tool": "sslscan",
                "package": "sslscan",
                "purpose": "Inspect TLS protocols and certificates.",
                "command": "sslscan {endpoint}",
            }
        ],
    },
    {
        "name": "ftp",
        "protocols": {"tcp"},
        "ports": {21},
        "services": {"ftp"},
        "steps": [
            {
                "tool": "nmap",
                "package": "nmap",
                "purpose": "Check anonymous FTP and service metadata.",
                "command": "nmap --script ftp-anon,ftp-syst -p{port} {host}",
            }
        ],
    },
    {
        "name": "rpc",
        "protocols": {"tcp"},
        "ports": {111},
        "services": {"rpcbind", "sunrpc"},
        "steps": [
            {
                "tool": "rpcinfo",
                "package": "rpcbind",
                "purpose": "List RPC programs exposed by the host.",
                "command": "rpcinfo -p {host}",
            }
        ],
    },
]


def _inventory_status(inventory: Dict) -> Dict[str, bool]:
    status = {}
    for package in inventory.get("packages", []) if inventory else []:
        if not isinstance(package, dict):
            continue
        package_ready = bool(package.get("installed") or package.get("command_available"))
        package_name = str(package.get("package") or "").strip()
        if package_name:
            status[package_name] = package_ready
        commands = package.get("commands", {})
        if isinstance(commands, dict):
            for command, path in commands.items():
                command_name = str(command or "").strip()
                if command_name:
                    # An explicit command probe is more precise than package
                    # installation state: installed packages can still lack a
                    # particular binary or have a broken PATH.
                    status[command_name] = bool(path)
        elif isinstance(commands, list):
            for command in commands:
                if isinstance(command, dict):
                    command_name = str(command.get("name") or "").strip()
                    if command_name:
                        status[command_name] = bool(
                            command.get("present") or command.get("path")
                        )
    return status


def _service_matches(profile: Dict, protocol: str, port: int, service: str) -> bool:
    if protocol not in profile.get("protocols", {"tcp"}):
        return False
    if port in profile["ports"]:
        return True

    service = str(service or "").lower().strip()
    if not service:
        return False

    if service in profile["services"]:
        return True

    service_tokens = {token for token in re.split(r"[^a-z0-9]+", service) if token}
    return any(token in profile["services"] for token in service_tokens)


def _url(host: str, port: int, service: str) -> str:
    scheme = (
        "https"
        if port in TLS_PORTS or "https" in service.lower() or "ssl" in service.lower()
        else "http"
    )
    url_host = f"[{host}]" if ":" in host and not host.startswith("[") else host
    if (scheme == "http" and port == 80) or (scheme == "https" and port == 443):
        return f"{scheme}://{url_host}"
    return f"{scheme}://{url_host}:{port}"


def _validated_host(value: object) -> str:
    host = str(value or "").strip()
    if not host or len(host) > 253:
        return ""
    try:
        ipaddress.ip_address(host)
        return host
    except ValueError:
        return host.rstrip(".") if HOSTNAME_RE.fullmatch(host) else ""


def _validated_hostname(value: object) -> str:
    hostname = str(value or "").strip()
    try:
        ipaddress.ip_address(hostname.rstrip("."))
        return ""
    except ValueError:
        pass
    return hostname.rstrip(".") if HOSTNAME_RE.fullmatch(hostname) else ""


def _format_command(template: str, host: str, hostname: str, port: int, service: str) -> str:
    name = hostname if hostname and hostname != "N/A" else host
    endpoint_host = f"[{host}]" if ":" in host and not host.startswith("[") else host
    return template.format(
        host=shlex.quote(host),
        hostname=shlex.quote(hostname),
        name=shlex.quote(name),
        endpoint=shlex.quote(f"{endpoint_host}:{port}"),
        port=port,
        service=shlex.quote(service),
        url=shlex.quote(_url(host, port, service)),
    )


def build_recon_plan(scan: Dict, inventory: Dict = None) -> Dict:
    tool_status = _inventory_status(inventory or {})
    recommendations = []
    seen = set()
    hosts = scan.get("hosts", []) if isinstance(scan, dict) else []

    for host_row in hosts:
        if not isinstance(host_row, dict):
            continue
        host = _validated_host(host_row.get("host"))
        if not host:
            continue
        hostname = _validated_hostname(host_row.get("hostname"))
        protocols = host_row.get("protocols", {})
        if not isinstance(protocols, dict):
            continue
        for protocol, ports in protocols.items():
            if not isinstance(ports, list):
                continue
            protocol = str(protocol or "").strip().lower()
            if protocol not in {"tcp", "udp"}:
                continue
            for port_row in ports:
                if not isinstance(port_row, dict):
                    continue
                if str(port_row.get("state") or "").lower() != "open":
                    continue
                try:
                    port = int(port_row.get("port", 0))
                except (TypeError, ValueError):
                    continue
                if not 1 <= port <= 65535:
                    continue
                service = str(port_row.get("name") or "unknown").lower()
                for profile in SERVICE_PROFILES:
                    if not _service_matches(profile, protocol, port, service):
                        continue
                    for step in profile["steps"]:
                        if step.get("requires_hostname") and not hostname:
                            continue
                        command = _format_command(step["command"], host, hostname, port, service)
                        dedupe_key = (host, protocol, port, step["tool"], command)
                        if dedupe_key in seen:
                            continue
                        seen.add(dedupe_key)
                        ready = tool_status.get(step["tool"])
                        if ready is None:
                            ready = tool_status.get(step["package"])
                        recommendations.append(
                            {
                                "record_type": "recon_step",
                                "host": host,
                                "hostname": hostname,
                                "protocol": protocol,
                                "port": port,
                                "service": service,
                                "profile": profile["name"],
                                "tool": step["tool"],
                                "package": step["package"],
                                "status": "ready"
                                if ready is True
                                else "missing"
                                if ready is False
                                else "unknown",
                                "purpose": step["purpose"],
                                "command": command,
                                "safety": "authorized-enumeration-only",
                            }
                        )

    summary = {
        "hosts": len(hosts),
        "recommendations": len(recommendations),
        "ready": sum(1 for row in recommendations if row["status"] == "ready"),
        "missing": sum(1 for row in recommendations if row["status"] == "missing"),
        "unknown": sum(1 for row in recommendations if row["status"] == "unknown"),
    }
    return {
        "schema": SCHEMA_VERSION,
        "source": "Nmap parsed services plus local Kali tool inventory",
        "summary": summary,
        "recommendations": recommendations,
        "ai_handoff": {
            "prompt_hint": "Use ready commands first. Treat missing commands as install suggestions, not completed evidence.",
            "guardrail": "Only run against systems covered by explicit authorization.",
        },
    }


def recon_plan_to_jsonl(plan: Dict) -> str:
    rows = [
        {
            "schema": plan["schema"],
            "record_type": "summary",
            **plan["summary"],
            **plan["ai_handoff"],
        }
    ]
    rows.extend({"schema": plan["schema"], **row} for row in plan["recommendations"])
    return "\n".join(json.dumps(row, ensure_ascii=False) for row in rows) + "\n"


def recon_plan_to_markdown(plan: Dict) -> str:
    lines: List[str] = [
        "# Recon Plan",
        "",
        f"- Schema: `{plan['schema']}`",
        f"- Recommendations: `{plan['summary']['recommendations']}`",
        f"- Ready: `{plan['summary']['ready']}`",
        f"- Missing: `{plan['summary']['missing']}`",
        "",
    ]
    for row in plan["recommendations"]:
        lines.extend(
            [
                f"## {row['host']} {row['protocol']}/{row['port']} {row['service']} -> {row['tool']} [{row['status']}]",
                "",
                row["purpose"],
                "",
                "```bash",
                row["command"],
                "```",
                "",
            ]
        )
    return "\n".join(lines).rstrip() + "\n"
