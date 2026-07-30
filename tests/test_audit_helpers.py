"""Offline unit tests for the DB-audit registry-parsing helpers.

The audit script itself (``scripts/audit_db.py``) hits the network and is run
manually / in scheduled CI, so it is not part of this deterministic suite. But
its pure payload-reduction helpers -- the logic that turns a registry JSON blob
into a single SPDX-ish token -- must stay correct, so they are exercised here
with hand-built payloads and no network.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))

from audit_db import (  # noqa: E402
    registry_tier,
    spdx_from_npm_payload,
    spdx_from_pypi_payload,
    tier_of_expression,
)
from license_radar.classify import (  # noqa: E402
    TIER_PERMISSIVE,
    TIER_STRONG_COPYLEFT,
    TIER_UNKNOWN,
    TIER_WEAK_COPYLEFT,
)


class TestPyPIPayload:
    def test_prefers_license_expression(self):
        info = {
            "license_expression": "GPL-2.0-or-later",
            "license": "should be ignored",
            "classifiers": ["License :: OSI Approved :: MIT License"],
        }
        assert spdx_from_pypi_payload(info) == "GPL-2.0-or-later"

    def test_falls_back_to_known_classifier(self):
        info = {
            "license_expression": "",
            "license": "",
            "classifiers": [
                "Programming Language :: Python :: 3",
                "License :: OSI Approved :: Apache Software License",
            ],
        }
        assert spdx_from_pypi_payload(info) == "Apache-2.0"

    def test_ambiguous_bsd_classifier_is_not_mapped(self):
        # A bare "BSD License" trove string does not say 2- vs 3-clause, so the
        # audit must leave it unmapped (-> UNVERIFIABLE), never guess.
        info = {
            "license_expression": "",
            "license": "",
            "classifiers": ["License :: OSI Approved :: BSD License"],
        }
        assert spdx_from_pypi_payload(info) is None

    def test_falls_back_to_short_free_text(self):
        info = {"license_expression": "", "license": "MIT", "classifiers": []}
        assert spdx_from_pypi_payload(info) == "MIT"

    def test_rejects_full_license_text_dump(self):
        blob = "Permission is hereby granted, free of charge, to any person " * 3
        info = {"license_expression": "", "license": blob, "classifiers": []}
        assert spdx_from_pypi_payload(info) is None

    def test_empty_payload_returns_none(self):
        assert spdx_from_pypi_payload({}) is None


class TestNpmPayload:
    def test_reads_latest_version_license(self):
        doc = {
            "dist-tags": {"latest": "7.0.3"},
            "versions": {"7.0.3": {"license": "AGPL-3.0"}},
        }
        assert spdx_from_npm_payload(doc) == "AGPL-3.0"

    def test_handles_legacy_object_license(self):
        doc = {
            "dist-tags": {"latest": "1.0.0"},
            "versions": {"1.0.0": {"license": {"type": "ISC", "url": "x"}}},
        }
        assert spdx_from_npm_payload(doc) == "ISC"

    def test_falls_back_to_top_level_license(self):
        doc = {"dist-tags": {"latest": "1.0.0"}, "versions": {}, "license": "MIT"}
        assert spdx_from_npm_payload(doc) == "MIT"

    def test_missing_license_returns_none(self):
        doc = {"dist-tags": {"latest": "1.0.0"}, "versions": {"1.0.0": {}}}
        assert spdx_from_npm_payload(doc) is None


class TestTierOfExpression:
    """The compound-SPDX -> tier reducer used to audit dual-licensed packages."""

    def test_single_atom_passes_through(self):
        assert tier_of_expression("Apache-2.0") == TIER_PERMISSIVE
        assert tier_of_expression("GPL-3.0-only") == TIER_STRONG_COPYLEFT

    def test_and_takes_most_restrictive(self):
        # Must satisfy both -> the stronger obligation dominates.
        assert tier_of_expression("MPL-2.0 AND MIT") == TIER_WEAK_COPYLEFT
        assert tier_of_expression("GPL-3.0-only AND MIT") == TIER_STRONG_COPYLEFT
        assert tier_of_expression("Apache-2.0 AND MIT") == TIER_PERMISSIVE

    def test_or_takes_least_restrictive(self):
        # May choose either -> the weaker obligation is achievable.
        assert tier_of_expression("MIT OR Apache-2.0") == TIER_PERMISSIVE
        assert tier_of_expression("GPL-3.0-only OR MIT") == TIER_PERMISSIVE
        assert tier_of_expression("GPL-3.0-only OR LGPL-3.0-only") == TIER_WEAK_COPYLEFT

    def test_nested_parentheses(self):
        # orjson's real expression: the MPL-2.0 obligation is unavoidable.
        assert (
            tier_of_expression("MPL-2.0 AND (Apache-2.0 OR MIT)")
            == TIER_WEAK_COPYLEFT
        )
        # A permissive-only tree stays permissive however it is grouped.
        assert (
            tier_of_expression("(MIT OR Apache-2.0) AND (BSD-3-Clause OR ISC)")
            == TIER_PERMISSIVE
        )

    def test_unknown_atom_makes_whole_expression_unknown(self):
        # A min()/max() must never silently swallow an unclassifiable branch.
        assert tier_of_expression("MIT AND LicenseRef-Proprietary") == TIER_UNKNOWN
        assert tier_of_expression("MIT OR SomethingWeird-9.9") == TIER_UNKNOWN

    def test_all_permissive_compound_resolves(self):
        # numpy's real registry expression: every atom (incl. CC0-1.0) is
        # permissive, so the whole AND-tree is permissive -- no longer punted.
        assert (
            tier_of_expression("BSD-3-Clause AND 0BSD AND MIT AND Zlib AND CC0-1.0")
            == TIER_PERMISSIVE
        )

    def test_free_text_is_not_an_expression(self):
        assert tier_of_expression("Apache License 2.0") == TIER_UNKNOWN
        assert tier_of_expression("3-Clause BSD License") == TIER_UNKNOWN
        assert tier_of_expression("LGPL with exceptions") == TIER_UNKNOWN

    def test_malformed_expressions(self):
        assert tier_of_expression("MIT AND") == TIER_UNKNOWN
        assert tier_of_expression("(MIT OR Apache-2.0") == TIER_UNKNOWN
        assert tier_of_expression("MIT, Apache-2.0") == TIER_UNKNOWN

    def test_empty_and_none(self):
        assert tier_of_expression("") == TIER_UNKNOWN
        assert tier_of_expression(None) == TIER_UNKNOWN
        assert tier_of_expression("   ") == TIER_UNKNOWN


class TestRegistryTier:
    """registry_tier() must keep the existing classify path intact and only add
    the compound fallback on top of it."""

    def test_single_id_matches_classify(self):
        assert registry_tier("MPL-2.0") == TIER_WEAK_COPYLEFT

    def test_free_text_alias_still_resolves(self):
        # Regression guard: classify_license's loose aliases must keep working
        # and must NOT be broken by the tokenizer (which would split them).
        assert registry_tier("BSD") == TIER_PERMISSIVE
        assert registry_tier("Apache 2.0") == TIER_PERMISSIVE

    def test_verbose_free_text_forms_resolve(self):
        # Real registry-declared forms that were falsely UNVERIFIABLE before:
        # tier-unambiguous free text that classify_license now aliases.
        assert registry_tier("Apache License 2.0") == TIER_PERMISSIVE
        assert registry_tier("3-Clause BSD License") == TIER_PERMISSIVE
        assert registry_tier("LGPL-2.1") == TIER_WEAK_COPYLEFT
        assert registry_tier("MIT-CMU") == TIER_PERMISSIVE

    def test_compound_resolves_via_fallback(self):
        assert registry_tier("MPL-2.0 AND (Apache-2.0 OR MIT)") == TIER_WEAK_COPYLEFT
        assert registry_tier("Apache-2.0 OR BSD-3-Clause") == TIER_PERMISSIVE

    def test_still_unverifiable_when_truly_ambiguous(self):
        assert registry_tier("LGPL with exceptions") == TIER_UNKNOWN
        assert registry_tier(None) == TIER_UNKNOWN
