"""Accuracy validation against a hand-labeled ground-truth fixture set.

This is the numeric check required by the project's "definition of done":
it measures how well the offline scanner (no --online network lookups)
reproduces known-correct license tiers and policy violation calls.
"""

from pathlib import Path

from license_radar.policy import load_policy, violates
from license_radar.scanner import scan_manifest

FIXTURES = Path(__file__).parent / "fixtures"

# ground truth: (ecosystem, package) -> (expected_tier, expected_violation)
GROUND_TRUTH = {
    ("pypi", "requests"): ("permissive", False),
    ("pypi", "flask"): ("permissive", False),
    ("pypi", "numpy"): ("permissive", False),
    ("pypi", "pytest"): ("permissive", False),
    ("pypi", "pyyaml"): ("permissive", False),
    ("pypi", "certifi"): ("weak-copyleft", False),
    ("pypi", "psycopg2"): ("weak-copyleft", False),
    ("pypi", "pyqt5"): ("strong-copyleft", True),
    ("pypi", "tqdm"): ("weak-copyleft", False),
    # Real copyleft packages resolved from live registry queries (not memory):
    # pylint = GPL-2.0-or-later, orjson = "MPL-2.0 AND (Apache-2.0 OR MIT)"
    # (AND -> the more restrictive MPL-2.0 tier applies), paramiko = LGPL-2.1.
    # They add real GPL/MPL/LGPL cases so accuracy is measured against
    # real-world contamination, not only synthetic fixtures.
    ("pypi", "pylint"): ("strong-copyleft", True),
    ("pypi", "orjson"): ("weak-copyleft", False),
    ("pypi", "paramiko"): ("weak-copyleft", False),
    ("pypi", "unlisted-package-not-in-db"): ("unknown", True),
    ("pypi", "test-strong-copyleft-pkg"): ("strong-copyleft", True),
    ("pypi", "test-weak-copyleft-pkg"): ("weak-copyleft", False),
    ("pypi", "test-permissive-pkg"): ("permissive", False),
    ("pypi", "test-proprietary-pkg"): ("unknown", True),
    ("npm", "react"): ("permissive", False),
    ("npm", "lodash"): ("permissive", False),
    ("npm", "axios"): ("permissive", False),
    ("npm", "pm2"): ("strong-copyleft", True),
    ("npm", "test-strong-copyleft-pkg"): ("strong-copyleft", True),
    ("npm", "eslint"): ("permissive", False),
    ("npm", "typescript"): ("permissive", False),
    ("npm", "unlisted-dev-package"): ("unknown", True),
}


def _run_scan():
    policy = load_policy(None)
    findings = []
    findings.extend(scan_manifest(FIXTURES / "pypi_project" / "requirements.txt"))
    findings.extend(scan_manifest(FIXTURES / "npm_project" / "package.json"))
    return findings, policy


def test_ground_truth_coverage_is_complete():
    findings, _ = _run_scan()
    keys = {(f.ecosystem, f.package) for f in findings}
    assert keys == set(GROUND_TRUTH.keys()), "fixture files and ground truth table drifted apart"


def test_tier_classification_accuracy():
    findings, _ = _run_scan()
    correct = 0
    for f in findings:
        expected_tier, _ = GROUND_TRUTH[(f.ecosystem, f.package)]
        if f.tier == expected_tier:
            correct += 1
    accuracy = correct / len(findings)
    assert accuracy == 1.0, f"tier classification accuracy was {accuracy:.2%}, expected 100%"


def test_policy_violation_precision_and_recall():
    findings, policy = _run_scan()

    tp = fp = fn = tn = 0
    for f in findings:
        _, expected_violation = GROUND_TRUTH[(f.ecosystem, f.package)]
        predicted_violation = violates(f, policy)
        if predicted_violation and expected_violation:
            tp += 1
        elif predicted_violation and not expected_violation:
            fp += 1
        elif not predicted_violation and expected_violation:
            fn += 1
        else:
            tn += 1

    precision = tp / (tp + fp) if (tp + fp) else 1.0
    recall = tp / (tp + fn) if (tp + fn) else 1.0

    assert precision == 1.0, f"precision was {precision:.2%} (fp={fp})"
    assert recall == 1.0, f"recall was {recall:.2%} (fn={fn})"


def test_strong_copyleft_in_setup_cfg_is_flagged_end_to_end():
    """A strong-copyleft dep declared only in setup.cfg must be caught.

    This exercises the full path (discover -> parse setup.cfg -> classify ->
    policy) for the legacy manifest format, separate from the precision/recall
    corpus above so those metrics stay pinned to their fixtures.
    """
    policy = load_policy(None)
    findings = scan_manifest(FIXTURES / "setupcfg_project" / "setup.cfg")
    by_pkg = {f.package: f for f in findings}
    assert set(by_pkg) == {"requests", "pyqt5"}
    assert by_pkg["pyqt5"].tier == "strong-copyleft"
    assert violates(by_pkg["pyqt5"], policy) is True
    assert violates(by_pkg["requests"], policy) is False


def test_strong_copyleft_via_requirements_include_is_flagged_end_to_end():
    """A strong-copyleft dep reachable only through a ``-r`` include must be caught.

    Exercises the full path (parse requirements.txt -> follow ``-r base.txt`` ->
    classify -> policy) for pip's include mechanism, kept out of the
    precision/recall corpus so those metrics stay pinned to their fixtures.
    """
    policy = load_policy(None)
    findings = scan_manifest(FIXTURES / "req_includes" / "requirements.txt")
    by_pkg = {f.package: f for f in findings}
    # pyqt5 lives only in base.txt, pulled in via -r.
    assert "pyqt5" in by_pkg
    assert by_pkg["pyqt5"].tier == "strong-copyleft"
    assert violates(by_pkg["pyqt5"], policy) is True
    assert violates(by_pkg["flask"], policy) is False


def test_strong_copyleft_in_pipfile_is_flagged_end_to_end():
    """A strong-copyleft dep declared only in a Pipfile must be caught.

    Exercises the full path (discover -> parse Pipfile -> classify -> policy)
    for the Pipenv manifest format, kept out of the precision/recall corpus so
    those metrics stay pinned to their fixtures.
    """
    policy = load_policy(None)
    findings = scan_manifest(FIXTURES / "pipfile_project" / "Pipfile")
    by_pkg = {f.package: f for f in findings}
    assert set(by_pkg) == {"requests", "pyqt5"}
    assert by_pkg["pyqt5"].tier == "strong-copyleft"
    assert violates(by_pkg["pyqt5"], policy) is True
    assert violates(by_pkg["requests"], policy) is False


def test_local_db_coverage_on_fixture_set():
    """What fraction of fixture packages resolve to a known license without --online.

    This is the honest limitation metric: the static DB is a small
    curated table (~220 packages), not a full registry mirror. Packages
    outside it report as 'unknown' unless --online is used.
    """
    findings, _ = _run_scan()
    known = sum(1 for f in findings if f.license is not None)
    coverage = known / len(findings)
    # 23 of 25 fixture packages resolve to a license string in the static
    # DB by construction (test-proprietary-pkg has a non-SPDX license
    # string but is still "known"); only the two deliberately
    # unlisted-* packages are missing. This documents that ratio rather
    # than aspiring to 100%.
    assert coverage == 23 / 25
