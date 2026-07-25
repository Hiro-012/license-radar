"""Decide pass/fail for a scan based on a configurable risk policy.

The default policy fails a scan (non-zero exit code) if any dependency
falls into the "strong-copyleft" or "unknown" tier. This mirrors the most
common compliance requirement for closed-source commercial projects.
"""

import json
from pathlib import Path

from license_radar.classify import tier_rank

DEFAULT_POLICY = {
    "fail_at_or_above": "strong-copyleft",
    "treat_unknown_as_violation": True,
}


def load_policy(path: Path | None) -> dict:
    if path is None:
        return dict(DEFAULT_POLICY)
    policy = dict(DEFAULT_POLICY)
    policy.update(json.loads(path.read_text()))
    return policy


def violates(finding, policy: dict) -> bool:
    if finding.tier == "unknown":
        return bool(policy.get("treat_unknown_as_violation", True))
    threshold = policy.get("fail_at_or_above", "strong-copyleft")
    return tier_rank(finding.tier) >= tier_rank(threshold)
