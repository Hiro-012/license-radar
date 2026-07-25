"""Combine parsing, license lookup, and risk classification into a report."""

from dataclasses import dataclass
from pathlib import Path

from license_radar import license_db
from license_radar.classify import classify_license
from license_radar.parsers import discover_manifests, parse_manifest


@dataclass
class Finding:
    ecosystem: str
    package: str
    license: str | None
    tier: str


def scan_manifest(path: Path, online: bool = False) -> list[Finding]:
    ecosystem, names = parse_manifest(path)
    findings = []
    for name in names:
        spdx = license_db.lookup(ecosystem, name)
        if spdx is None and online:
            from license_radar.remote import fetch_remote_license

            spdx = fetch_remote_license(ecosystem, name)
        findings.append(Finding(ecosystem, name, spdx, classify_license(spdx)))
    return findings


def scan_path(root: Path, online: bool = False) -> list[Finding]:
    findings = []
    for manifest in discover_manifests(root):
        findings.extend(scan_manifest(manifest, online=online))
    return findings
