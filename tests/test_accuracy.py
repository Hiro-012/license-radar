"""End-to-end detection recall / false-positive regression guard.

Drives ``scripts/measure_accuracy.py`` over the full curated ground-truth
database and asserts the scan pipeline (parse -> lookup -> classify -> policy)
flags every known-risky dependency and nothing that is not. See that script's
module docstring for what this does and does not measure — in particular, the
database's fidelity to live registries is checked separately by
``scripts/audit_db.py``, not here.

If a future parser/normalization/classification change ever lets a known
copyleft dependency slip through, recall drops below 1.0 and this test fails.
"""

import importlib.util
from pathlib import Path

from license_radar.policy import DEFAULT_POLICY

_SPEC = importlib.util.spec_from_file_location(
    "measure_accuracy",
    Path(__file__).resolve().parent.parent / "scripts" / "measure_accuracy.py",
)
measure_accuracy = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(measure_accuracy)


def _strict_policy():
    p = dict(DEFAULT_POLICY)
    p["fail_at_or_above"] = "weak-copyleft"
    return p


def test_default_policy_recall_and_false_positive():
    r = measure_accuracy.measure(dict(DEFAULT_POLICY))
    assert r["missing_from_scan"] == [], r["missing_from_scan"]
    assert r["risky_total"] > 0  # the corpus actually contains risky packages
    assert r["recall"] == 1.0, r["false_negatives"]
    assert r["false_positive_rate"] == 0.0, r["false_positives"]


def test_strict_policy_includes_weak_copyleft_recall():
    r = measure_accuracy.measure(_strict_policy())
    # Strict policy must catch strictly more (weak-copyleft becomes a violation).
    default = measure_accuracy.measure(dict(DEFAULT_POLICY))
    assert r["risky_total"] > default["risky_total"]
    assert r["recall"] == 1.0, r["false_negatives"]
    assert r["false_positive_rate"] == 0.0, r["false_positives"]


def test_every_real_db_package_is_scanned_end_to_end():
    r = measure_accuracy.measure(dict(DEFAULT_POLICY))
    # No package the DB knows about is silently dropped by parsing/normalization.
    assert r["scanned"] == r["total_packages"]
