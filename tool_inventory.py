"""Kali-oriented tool inventory and AI handoff helpers."""

from __future__ import annotations

import argparse
import json
import shutil
import sys
from collections.abc import Iterable

from kali_ai_scan import apt_policy, run_command, utc_now

SCHEMA_VERSION = "pentest-tool-inventory/v1"

KALI_METAPACKAGE_PROFILES = {
    "core": ["kali-linux-core", "kali-linux-headless", "kali-linux-default"],
    "recon": ["kali-tools-information-gathering", "kali-tools-vulnerability"],
    "web": ["kali-tools-web", "kali-tools-database"],
    "wireless": ["kali-tools-802-11", "kali-tools-bluetooth"],
    "exploitation": ["kali-tools-exploitation", "kali-tools-post-exploitation"],
    "passwords": ["kali-tools-passwords", "kali-tools-gpu"],
    "forensics": ["kali-tools-forensics", "kali-tools-respond", "kali-tools-recover"],
    "reverse": ["kali-tools-reverse-engineering"],
    "reporting": ["kali-tools-reporting"],
    "radio": ["kali-tools-rfid", "kali-tools-sdr"],
    "voip": ["kali-tools-voip"],
    "social": ["kali-tools-social-engineering"],
    "ai": ["llm-tools-nmap"],
}

ESSENTIAL_TOOLS = {
    "nmap": {"commands": ["nmap"], "category": "recon"},
    "llm-tools-nmap": {"commands": [], "category": "ai"},
    "python3": {"commands": ["python3"], "category": "runtime"},
    "curl": {"commands": ["curl"], "category": "utility"},
    "dnsrecon": {"commands": ["dnsrecon"], "category": "dns"},
    "dnsutils": {"commands": ["dig"], "category": "dns"},
    "enum4linux-ng": {"commands": ["enum4linux-ng"], "category": "smb"},
    "jq": {"commands": ["jq"], "category": "utility"},
    "git": {"commands": ["git"], "category": "utility"},
    "nikto": {"commands": ["nikto"], "category": "web"},
    "rpcbind": {"commands": ["rpcinfo"], "category": "rpc"},
    "sqlmap": {"commands": ["sqlmap"], "category": "web"},
    "smbclient": {"commands": ["smbclient"], "category": "smb"},
    "ssh-audit": {"commands": ["ssh-audit"], "category": "ssh"},
    "sslscan": {"commands": ["sslscan"], "category": "tls"},
    "wireshark": {"commands": ["wireshark", "tshark"], "category": "sniffing"},
    "whatweb": {"commands": ["whatweb"], "category": "web"},
    "metasploit-framework": {"commands": ["msfconsole"], "category": "exploitation"},
    "hydra": {"commands": ["hydra"], "category": "passwords"},
    "john": {"commands": ["john"], "category": "passwords"},
    "hashcat": {"commands": ["hashcat"], "category": "passwords"},
    "aircrack-ng": {"commands": ["aircrack-ng"], "category": "wireless"},
    "gobuster": {"commands": ["gobuster"], "category": "web"},
    "ffuf": {"commands": ["ffuf"], "category": "web"},
    "feroxbuster": {"commands": ["feroxbuster"], "category": "web"},
    "seclists": {"commands": [], "category": "wordlists"},
    "exploitdb": {"commands": ["searchsploit"], "category": "exploitation"},
    "dradis": {"commands": [], "category": "reporting"},
    "faraday": {"commands": ["faraday"], "category": "reporting"},
}


def all_profile_packages() -> list[str]:
    packages = []
    for profile_packages in KALI_METAPACKAGE_PROFILES.values():
        packages.extend(profile_packages)
    return sorted(set(packages))


def parse_apt_depends(stdout: str) -> list[str]:
    packages = []
    for raw_line in stdout.splitlines():
        line = raw_line.strip()
        if not line.startswith("Depends:"):
            continue
        package = line.split(":", 1)[1].strip()
        if not package or package.startswith("<"):
            continue
        packages.append(package.split()[0])
    return sorted(set(packages))


def metapackage_dependencies(package: str) -> list[str]:
    if not shutil.which("apt-cache"):
        return []
    result = run_command(["apt-cache", "depends", package])
    if not result.get("ok"):
        return []
    return parse_apt_depends(result.get("stdout", ""))


def package_status(package: str) -> dict:
    result = run_command(
        ["dpkg-query", "-W", "-f=${binary:Package}\t${Version}\t${db:Status-Status}\n", package]
    )
    installed = False
    version = ""
    if result.get("ok") and result.get("stdout"):
        fields = result["stdout"].split("\t")
        installed = len(fields) >= 3 and fields[2] == "installed"
        version = fields[1] if len(fields) >= 2 else ""

    commands = ESSENTIAL_TOOLS.get(package, {}).get("commands", [package])
    command_paths = {command: shutil.which(command) for command in commands}
    return {
        "package": package,
        "installed": installed,
        "version": version,
        "category": ESSENTIAL_TOOLS.get(package, {}).get("category", "official-kali"),
        "commands": command_paths,
        "command_available": any(command_paths.values()) if command_paths else installed,
        "apt": apt_policy(package),
    }


def selected_metapackages(profiles: Iterable[str] = None) -> list[str]:
    if profiles is None:
        return all_profile_packages()

    packages = []
    for profile in profiles:
        packages.extend(KALI_METAPACKAGE_PROFILES.get(profile, []))
    return sorted(set(packages))


def build_tool_inventory(profiles: Iterable[str] = None, expand: bool = False) -> dict:
    profile_names = (
        list(KALI_METAPACKAGE_PROFILES)
        if profiles is None
        else [name for name in profiles if name in KALI_METAPACKAGE_PROFILES]
    )
    metapackages = selected_metapackages(profile_names)
    discovered_packages = set(ESSENTIAL_TOOLS)
    discovered_packages.update(metapackages)

    profile_rows = []
    for profile in profile_names:
        profile_metapackages = KALI_METAPACKAGE_PROFILES[profile]
        meta_rows = []
        profile_deps = set()
        for metapackage in profile_metapackages:
            deps = metapackage_dependencies(metapackage) if expand else []
            profile_deps.update(deps)
            meta_rows.append(
                {
                    "metapackage": metapackage,
                    "dependencies": deps,
                    "install": f"sudo apt install -y {metapackage}",
                }
            )
        if expand:
            discovered_packages.update(profile_deps)
        profile_rows.append(
            {
                "profile": profile,
                "metapackages": meta_rows,
                "install": f"sudo apt install -y {' '.join(profile_metapackages)}",
            }
        )

    packages = [package_status(package) for package in sorted(discovered_packages)]
    installed_count = sum(
        1 for package in packages if package["installed"] or package["command_available"]
    )
    missing = [
        package["package"]
        for package in packages
        if not package["installed"] and not package["command_available"]
    ]

    return {
        "schema": SCHEMA_VERSION,
        "generated_at": utc_now(),
        "source": "Kali official apt packages and metapackages when apt-cache/dpkg-query are available",
        "profiles": profile_rows,
        "summary": {
            "packages_checked": len(packages),
            "available": installed_count,
            "missing": len(missing),
            "missing_packages": missing,
            "kali_detected": shutil.which("apt-cache") is not None
            and shutil.which("dpkg-query") is not None,
        },
        "packages": packages,
        "ai_handoff": {
            "recommended_files": [
                "tool-inventory.json",
                "tool-inventory.jsonl",
                "tool-inventory.md",
            ],
            "prompt_hint": "Use this inventory to decide which installed, official tools can support the authorized pentest workflow. Do not suggest tools marked missing unless you also include the apt install command.",
        },
    }


def inventory_to_jsonl(inventory: dict) -> str:
    rows = [
        {
            "schema": inventory["schema"],
            "record_type": "summary",
            "type": "summary",
            **inventory["summary"],
            "prompt_hint": inventory["ai_handoff"]["prompt_hint"],
        }
    ]
    for package in inventory["packages"]:
        commands = package.get("commands", [])
        if isinstance(commands, dict):
            command_available = bool(package.get("command_available") or any(commands.values()))
        else:
            command_available = bool(
                package.get("command_available")
                or any(
                    command.get("present") or command.get("path")
                    for command in commands
                    if isinstance(command, dict)
                )
            )
        rows.append(
            {
                "schema": inventory["schema"],
                "record_type": "tool",
                "type": "tool",
                "package": package["package"],
                "category": package["category"],
                "installed": package["installed"],
                "command_available": command_available,
                "commands": commands,
                "llm_hint": f"{package['package']} is {'available' if package['installed'] or command_available else 'missing'} for {package['category']} work",
            }
        )
    return "\n".join(json.dumps(row, ensure_ascii=False) for row in rows) + "\n"


def inventory_to_markdown(inventory: dict) -> str:
    lines = [
        "# Pentest Tool Inventory",
        "",
        f"- Schema: `{inventory['schema']}`",
        f"- Packages checked: `{inventory['summary']['packages_checked']}`",
        f"- Available: `{inventory['summary']['available']}`",
        f"- Missing: `{inventory['summary']['missing']}`",
        "",
        "## Missing Packages",
        "",
    ]
    missing = inventory["summary"]["missing_packages"]
    lines.extend(f"- `{package}`" for package in missing[:80])
    if len(missing) > 80:
        lines.append(f"- ...and {len(missing) - 80} more")

    lines.extend(["", "## Available Tools", ""])
    available = [
        package
        for package in inventory["packages"]
        if package.get("installed")
        or package.get("command_available")
        or any(
            bool(command.get("present") or command.get("path"))
            for command in package.get("commands", [])
            if isinstance(command, dict)
        )
    ]
    lines.extend(f"- `{package['package']}` ({package['category']})" for package in available[:80])
    if len(available) > 80:
        lines.append(f"- ...and {len(available) - 80} more")

    lines.extend(["", "## Profiles", ""])
    for profile in inventory["profiles"]:
        name = profile.get("profile") or profile.get("name")
        install = profile.get("install") or profile.get("metapackage")
        lines.append(f"- `{name}`: `{install}`")

    return "\n".join(lines).rstrip() + "\n"


def build_cli_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Export local Kali/pentest tool inventory for operators and AI handoff."
    )
    parser.add_argument(
        "--format",
        choices=("json", "jsonl", "markdown", "md"),
        default="json",
        help="Output format (default: json)",
    )
    parser.add_argument(
        "--expand",
        action="store_true",
        help="Expand metapackage dependency trees (slower)",
    )
    parser.add_argument(
        "--profiles",
        nargs="*",
        default=None,
        help="Optional profile names (default: all official profiles)",
    )
    parser.add_argument(
        "-o",
        "--output",
        help="Write to file instead of stdout",
    )
    return parser


def main(argv: list[str] = None) -> int:
    parser = build_cli_parser()
    args = parser.parse_args(argv)
    inventory = build_tool_inventory(profiles=args.profiles, expand=args.expand)
    fmt = args.format.lower()
    if fmt == "json":
        content = json.dumps(inventory, indent=2, ensure_ascii=False) + "\n"
    elif fmt == "jsonl":
        content = inventory_to_jsonl(inventory)
    else:
        content = inventory_to_markdown(inventory)

    if args.output:
        with open(args.output, "w", encoding="utf-8") as handle:
            handle.write(content)
        print(f"Wrote inventory to {args.output}")
    else:
        sys.stdout.write(content)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
