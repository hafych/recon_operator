"""CLI entry: ``python -m recon_operator`` (serve) or ``python -m recon_operator pack``."""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
from collections.abc import Sequence


def _cmd_serve(_args: argparse.Namespace) -> int:
    from recon_operator.server import log_event, main

    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        log_event("KeyboardInterrupt received")
        return 130
    except Exception as exc:  # pragma: no cover - process entry
        log_event(f"Critical error: {exc}")
        return 1
    return 0


def _cmd_pack(args: argparse.Namespace) -> int:
    from recon_operator.ai_pack import pack_from_json_file

    try:
        body, _content_type, _rows = pack_from_json_file(
            args.scan,
            budget=args.budget,
            format=args.format,
            baseline_path=args.baseline,
        )
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"pack failed: {exc}", file=sys.stderr)
        return 1
    sys.stdout.write(body)
    if not body.endswith("\n"):
        sys.stdout.write("\n")
    return 0


def _cmd_presets(_args: argparse.Namespace) -> int:
    from recon_operator.presets import PHASE_ORDER, list_presets

    payload = {"phases": PHASE_ORDER, "presets": list_presets()}
    json.dump(payload, sys.stdout, ensure_ascii=False, indent=2)
    sys.stdout.write("\n")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="recon_operator",
        description="Recon Operator: serve API or build low-token AI packs offline.",
    )
    sub = parser.add_subparsers(dest="command")

    serve = sub.add_parser("serve", help="Start the HTTP API (default)")
    serve.set_defaults(func=_cmd_serve)

    pack = sub.add_parser(
        "pack",
        help="Build a budgeted AI recon pack from a parsed scan JSON file (no server)",
    )
    pack.add_argument("scan", help="Path to parsed scan result JSON")
    pack.add_argument(
        "--budget",
        default="s",
        help="Pack budget: s|m|l (default s)",
    )
    pack.add_argument(
        "--format",
        default="jsonl",
        choices=("jsonl", "json"),
        help="Output format (default jsonl)",
    )
    pack.add_argument(
        "--baseline",
        default=None,
        help="Optional baseline scan JSON for retest/diff pack mode",
    )
    pack.set_defaults(func=_cmd_pack)

    presets = sub.add_parser("presets", help="List named recon presets / phases as JSON")
    presets.set_defaults(func=_cmd_presets)

    return parser


def main(argv: Sequence[str] | None = None) -> int:
    argv_list = list(sys.argv[1:] if argv is None else argv)
    # Default to serve when no subcommand (backward compatible).
    if not argv_list or argv_list[0] not in {"serve", "pack", "presets", "-h", "--help"}:
        if argv_list and argv_list[0] not in {"serve", "pack", "presets"}:
            # Unknown first token → treat as serve (legacy).
            pass
        if not argv_list or argv_list[0] not in {"serve", "pack", "presets", "-h", "--help"}:
            argv_list = ["serve", *argv_list]

    parser = build_parser()
    args = parser.parse_args(argv_list)
    func = getattr(args, "func", None)
    if func is None:
        parser.print_help()
        return 2
    return int(func(args))


def run() -> None:
    raise SystemExit(main())


if __name__ == "__main__":
    run()
