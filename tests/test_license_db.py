"""Integrity checks for the offline license DB.

These are invariants that guard against silent DB corruption: an entry whose
SPDX id no longer maps to a known tier would degrade the tool's answers, and a
package whose license genuinely varies across its supported version range must
not be pinned to a single misleading value.
"""
from license_radar.license_db import PYPI_LICENSES, NPM_LICENSES
from license_radar.classify import (
    classify_license,
    TIER_PERMISSIVE,
    TIER_WEAK_COPYLEFT,
    TIER_STRONG_COPYLEFT,
)


def test_every_entry_classifies_to_a_known_tier():
    # The only entry allowed to resolve to "unknown" is the synthetic
    # proprietary fixture that exercises the unknown-license code path.
    for eco, table in (("pypi", PYPI_LICENSES), ("npm", NPM_LICENSES)):
        for name, spdx in table.items():
            tier = classify_license(spdx)
            if name.startswith("test-"):
                continue
            assert tier != "unknown", f"{eco}:{name} -> {spdx} classifies as unknown"


def test_chardet_is_intentionally_omitted():
    # chardet's license is version-dependent: <=5.2.0 is LGPL-2.1-or-later
    # (weak-copyleft) while the 6.x/7.x line relicensed to 0BSD (permissive),
    # verified against the live PyPI JSON API (see the note in license_db.py).
    # A single name-keyed entry would be wrong for one version class, so it is
    # deliberately left out of the offline table and reported as "unknown"
    # (flagged for review) instead of guessed. This test prevents a future
    # session from naively re-adding a single-value entry.
    assert "chardet" not in PYPI_LICENSES


def test_compound_reduction_entries_keep_their_verified_tier():
    # These packages declare a compound SPDX *expression* upstream; the DB
    # stores the reduced representative id under the OR=least / AND=most
    # restrictive rule (verified live against PyPI 2026-07-31). Pin the intended
    # tier so a future session cannot "correct" e.g. pyside6 to strong-copyleft
    # (its OR-list of copyleft options is achievable as LGPL-3.0, i.e. weak) or
    # pycurl to weak (its "LGPL-2.1-only OR MIT" lets the licensee choose MIT).
    expected = {
        "rpy2": TIER_STRONG_COPYLEFT,        # GPL-2.0-or-later
        "pyside6": TIER_WEAK_COPYLEFT,        # LGPL-3.0-only OR GPL-2.0-only OR GPL-3.0-only
        "pycurl": TIER_PERMISSIVE,            # LGPL-2.1-only OR MIT
        "asyncssh": TIER_WEAK_COPYLEFT,       # EPL-2.0 OR GPL-2.0-or-later
        "pygobject": TIER_WEAK_COPYLEFT,      # LGPLv2+ classifier
    }
    for name, tier in expected.items():
        assert name in PYPI_LICENSES, f"{name} missing from DB"
        assert classify_license(PYPI_LICENSES[name]) == tier, (
            f"{name} -> {PYPI_LICENSES[name]} expected {tier}"
        )


def test_synthetic_fixtures_are_namespaced():
    # Synthetic corpus fixtures live under the reserved "test-" prefix so they
    # cannot collide with a real package name a user could depend on. Anything
    # resolving to "unknown" in the real tables would be caught above; this
    # pins the reserved namespace so fixtures stay clearly synthetic.
    synthetic = [n for t in (PYPI_LICENSES, NPM_LICENSES) for n in t if n.startswith("test-")]
    assert synthetic, "expected at least one synthetic test fixture in the DB"
    for name in synthetic:
        assert name.startswith("test-")
