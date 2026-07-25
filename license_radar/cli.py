"""Command-line entry point: `license-radar scan <path>`."""

import argparse
import json
import sys
from pathlib import Path

from license_radar.policy import load_policy, violates
from license_radar.scanner import scan_path


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="license-radar")
    subparsers = parser.add_subparsers(dest="command", required=True)

    scan = subparsers.add_parser("scan", help="Scan a project for license risk")
    scan.add_argument("path", type=Path, help="Directory or manifest file to scan")
    scan.add_argument("--policy", type=Path, default=None, help="Path to a JSON policy file")
    scan.add_argument("--json", action="store_true", help="Emit machine-readable JSON")
    scan.add_argument(
        "--online", action="store_true",
        help="Query PyPI/npm registries for packages missing from the local DB",
    )

    return parser


def run_scan(args) -> int:
    findings = scan_path(args.path, online=args.online)
    policy = load_policy(args.policy)

    rows = [
        {
            "ecosystem": f.ecosystem,
            "package": f.package,
            "license": f.license or "UNKNOWN",
            "tier": f.tier,
            "violation": violates(f, policy),
        }
        for f in findings
    ]
    has_violation = any(row["violation"] for row in rows)

    if args.json:
        print(json.dumps({"findings": rows, "violation": has_violation}, indent=2))
    else:
        if not rows:
            print("No dependencies found.")
        for row in rows:
            flag = " !!" if row["violation"] else ""
            print(f"[{row['ecosystem']}] {row['package']}: {row['license']} ({row['tier']}){flag}")
        print()
        print("VIOLATIONS FOUND" if has_violation else "OK — no policy violations")

    return 1 if has_violation else 0


def main(argv=None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command == "scan":
        return run_scan(args)
    parser.print_help()
    return 1


if __name__ == "__main__":
    sys.exit(main())
