"""Command-line entry point: `license-radar scan|report <path>`."""

import argparse
import datetime
import json
import sys
from pathlib import Path

from license_radar.license_key import PURCHASE_LINK, resolve_key, verify_license_key
from license_radar.policy import load_policy, violates
from license_radar.report import render_html_report
from license_radar.scanner import scan_path, scan_path_detailed

# Exit codes: 0 = clean, 1 = policy violation, 2 = license gate not satisfied,
# 3 = could not write the report file.
EXIT_OK = 0
EXIT_VIOLATION = 1
EXIT_LOCKED = 2
EXIT_IO_ERROR = 3


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

    report = subparsers.add_parser(
        "report",
        help="[Pro] Generate a standalone HTML compliance audit report",
    )
    report.add_argument("path", type=Path, help="Directory or manifest file to scan")
    report.add_argument("--policy", type=Path, default=None, help="Path to a JSON policy file")
    report.add_argument(
        "--online", action="store_true",
        help="Query PyPI/npm registries for packages missing from the local DB",
    )
    report.add_argument(
        "--output", "-o", type=Path, default=None,
        help="Write the HTML report to this file (default: stdout)",
    )
    report.add_argument(
        "--license-key", default=None,
        help="Pro license key (falls back to the LICENSE_RADAR_KEY env var)",
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

    return EXIT_VIOLATION if has_violation else EXIT_OK


def _relativize(manifest: Path, root: Path) -> str:
    """Render a manifest path relative to the scanned root for the report.

    Falls back to the manifest's own name/path if it is not located under
    ``root`` (e.g. when a single manifest file was scanned directly).
    """
    base = root if root.is_dir() else root.parent
    try:
        return str(manifest.relative_to(base))
    except ValueError:
        return manifest.name


def run_report(args) -> int:
    key = resolve_key(args.license_key)
    if not verify_license_key(key):
        print(
            "license-radar report is a Pro feature. A valid license key is "
            "required.\nUnlock it (one-time) here: " + PURCHASE_LINK + "\n"
            "Then pass --license-key <KEY> or set LICENSE_RADAR_KEY. "
            "The free `license-radar scan` command is unaffected.",
            file=sys.stderr,
        )
        return EXIT_LOCKED

    findings, manifests = scan_path_detailed(args.path, online=args.online)
    policy = load_policy(args.policy)
    generated_at = datetime.datetime.now().isoformat(timespec="seconds")
    scope = [_relativize(m, args.path) for m in manifests]
    html_doc = render_html_report(
        findings, policy, generated_at=generated_at, manifests=scope
    )

    if args.output is not None:
        # A paying user typically points --output into a reports/ directory that
        # may not exist yet; create it rather than aborting with a traceback.
        try:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(html_doc, encoding="utf-8")
        except OSError as exc:
            print(
                f"license-radar: could not write report to {args.output}: {exc}",
                file=sys.stderr,
            )
            return EXIT_IO_ERROR
        print(f"Report written to {args.output}", file=sys.stderr)
    else:
        sys.stdout.write(html_doc)

    has_violation = any(violates(f, policy) for f in findings)
    return EXIT_VIOLATION if has_violation else EXIT_OK


def main(argv=None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command == "scan":
        return run_scan(args)
    if args.command == "report":
        return run_report(args)
    parser.print_help()
    return EXIT_VIOLATION


if __name__ == "__main__":
    sys.exit(main())
