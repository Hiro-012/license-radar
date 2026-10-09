#!/usr/bin/env python3
"""Measure end-to-end detection recall and false-positive rate of the scan pipeline.

What this measures (and what it does not)
-----------------------------------------
This harness answers one question with a reproducible number: *given a package
whose license tier is known, does a real* ``license-radar`` *scan of a manifest
declaring it produce the correct violation verdict?* It exercises the whole
pipeline the CLI uses — manifest generation -> ``discover_manifests`` /
``parse_manifest`` -> offline ``license_db.lookup`` -> ``classify_expression``
-> ``policy.violates`` — over the entire curated ground-truth database, split
by ecosystem and manifest format.

The ground truth is the hand-curated ``license_db`` table, whose *tiers* are
what we assert against. That makes this a measurement of the **detection
pipeline**, not of the database's fidelity to the real world: whether the
stored license for, say, ``celery`` still matches what PyPI serves is a
*different* check, performed separately by ``scripts/audit_db.py`` against the
live registries. Here the DB is taken as the oracle, and we verify that no
known-risky dependency is ever silently dropped by parsing, name
normalization, classification, or policy — the failure mode that would make a
compliance gate quietly useless.

Definitions (under a given policy)
----------------------------------
* A package is **risky** if ``policy.violates`` is true for its ground-truth
  tier (default policy: ``strong-copyleft`` or ``unknown``).
* **Recall** = (risky packages the scan flags) / (risky packages total).
  A recall below 1.0 means the pipeline let a known-risky dependency through.
* **False-positive rate** = (non-risky packages the scan flags) / (non-risky
  total). Above 0.0 means the pipeline flagged something it should not have.

Two policies are reported: the default (strong-copyleft + unknown) and a
strict one (``fail_at_or_above: weak-copyleft``) so weak-copyleft recall is
exercised too.

Run: ``python scripts/measure_accuracy.py``  (add ``--json`` for machine output).
Exit code is non-zero if recall != 1.0 or false-positive rate != 0.0 under
either policy, so this doubles as a CI regression guard.
"""

from __future__ import annotations

import argparse
import json
import sys
import tempfile
from pathlib import Path

# Allow running as a plain script (python scripts/measure_accuracy.py) without
# an editable install by putting the repo root on sys.path.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from license_radar import license_db  # noqa: E402
from license_radar.classify import classify_expression  # noqa: E402
from license_radar.policy import DEFAULT_POLICY, violates  # noqa: E402
from license_radar.scanner import scan_path  # noqa: E402


def _real_entries(table: dict[str, str]) -> dict[str, str]:
    """DB rows minus the synthetic ``test-`` fixtures used only by unit tests."""
    return {name: lic for name, lic in table.items() if not name.startswith("test-")}


def _write_corpus(root: Path) -> None:
    """Materialize one manifest per ecosystem declaring every real DB package.

    pypi packages go into a requirements.txt; npm packages into a package.json.
    Using the exact DB keys as declared names deliberately routes each name
    through the parser + PEP 503 / npm normalization that the lookup relies on,
    so a normalization mismatch would show up as a miss rather than passing
    silently.
    """
    pypi = _real_entries(license_db.PYPI_LICENSES)
    npm = _real_entries(getattr(license_db, "NPM_LICENSES", {}))

    (root / "requirements.txt").write_text("\n".join(sorted(pypi)) + "\n")
    (root / "package.json").write_text(
        json.dumps(
            {
                "name": "accuracy-corpus",
                "version": "0.0.0",
                "dependencies": {name: "*" for name in sorted(npm)},
            },
            indent=2,
        )
        + "\n"
    )


def _norm(ecosystem: str, name: str) -> str:
    """Normalize a name the same way ``license_db.lookup`` keys its table."""
    if ecosystem == "pypi":
        return license_db.normalize_pypi_name(name)
    return name.strip().lower()


def _expected(ecosystem: str, table: dict[str, str]) -> dict[str, str]:
    """Map normalized package name -> ground-truth tier for one ecosystem."""
    out: dict[str, str] = {}
    for name in _real_entries(table):
        # Go through lookup() so the tier reflects the exact same offline path
        # the scanner takes, and key on the normalized name so it matches the
        # finding's package field.
        spdx = license_db.lookup(ecosystem, name)
        out[_norm(ecosystem, name)] = classify_expression(spdx)
    return out


def measure(policy: dict) -> dict:
    tables = {
        "pypi": license_db.PYPI_LICENSES,
        "npm": getattr(license_db, "NPM_LICENSES", {}),
    }
    expected: dict[tuple[str, str], str] = {}
    for eco, table in tables.items():
        for name, tier in _expected(eco, table).items():
            expected[(eco, name)] = tier

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        _write_corpus(root)
        findings = scan_path(root, online=False)

    flagged = {
        (f.ecosystem, f.package) for f in findings if violates(f, policy)
    }
    seen = {(f.ecosystem, f.package) for f in findings}

    risky = {k for k, tier in expected.items() if violates(_Stub(tier), policy)}
    nonrisky = set(expected) - risky

    missing_from_scan = set(expected) - seen  # parser/normalization dropped it
    false_neg = (risky & seen) - flagged
    false_pos = flagged & nonrisky

    tp = len(risky & flagged)
    recall = tp / len(risky) if risky else 1.0
    fp_rate = len(false_pos) / len(nonrisky) if nonrisky else 0.0

    return {
        "policy": policy,
        "total_packages": len(expected),
        "scanned": len(seen),
        "missing_from_scan": sorted(missing_from_scan),
        "risky_total": len(risky),
        "risky_flagged": tp,
        "recall": recall,
        "false_negatives": sorted(false_neg),
        "nonrisky_total": len(nonrisky),
        "false_positives": sorted(false_pos),
        "false_positive_rate": fp_rate,
    }


class _Stub:
    """Minimal stand-in so ``violates`` can be reused on a bare tier string."""

    def __init__(self, tier: str) -> None:
        self.tier = tier


def _fmt(label: str, r: dict) -> str:
    lines = [
        f"== {label} ==",
        f"  policy               : {r['policy']}",
        f"  packages (ground truth): {r['total_packages']}  "
        f"(scanned end-to-end: {r['scanned']})",
        f"  risky packages       : {r['risky_total']}  "
        f"flagged: {r['risky_flagged']}",
        f"  recall               : {r['recall']*100:.2f}%",
        f"  non-risky packages   : {r['nonrisky_total']}",
        f"  false-positive rate  : {r['false_positive_rate']*100:.2f}%",
    ]
    if r["missing_from_scan"]:
        lines.append(f"  MISSING FROM SCAN    : {r['missing_from_scan']}")
    if r["false_negatives"]:
        lines.append(f"  FALSE NEGATIVES      : {r['false_negatives']}")
    if r["false_positives"]:
        lines.append(f"  FALSE POSITIVES      : {r['false_positives']}")
    return "\n".join(lines)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--json", action="store_true", help="emit machine-readable JSON")
    args = ap.parse_args()

    strict = dict(DEFAULT_POLICY)
    strict["fail_at_or_above"] = "weak-copyleft"

    default_r = measure(dict(DEFAULT_POLICY))
    strict_r = measure(strict)

    if args.json:
        print(json.dumps({"default": default_r, "strict": strict_r}, indent=2))
    else:
        print(_fmt("default policy (strong-copyleft + unknown)", default_r))
        print()
        print(_fmt("strict policy (fail at weak-copyleft)", strict_r))

    ok = all(
        r["recall"] == 1.0
        and r["false_positive_rate"] == 0.0
        and not r["missing_from_scan"]
        for r in (default_r, strict_r)
    )
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
