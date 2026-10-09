"""Offline unit tests for the DB-audit registry-parsing helpers.

The audit script itself (``scripts/audit_db.py``) hits the network and is run
manually / in scheduled CI, so it is not part of this deterministic suite. But
its pure payload-reduction helpers -- the logic that turns a registry JSON blob
into a single SPDX-ish token -- must stay correct, so they are exercised here
with hand-built payloads and no network.
"""

import http.client
import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))

import audit_db  # noqa: E402
from audit_db import (  # noqa: E402
    pypi_tier_hint,
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

    def test_maps_psf_classifier_to_single_id(self):
        # matplotlib declares only this classifier (its `license` field is the
        # full license text). PSF-2.0 is a single, tier-unambiguous id, so it
        # is safe to map -- unlike a bare "BSD License".
        info = {
            "license_expression": "",
            "license": "License agreement for matplotlib ... (full text)",
            "classifiers": [
                "License :: OSI Approved :: Python Software Foundation License",
            ],
        }
        assert spdx_from_pypi_payload(info) == "PSF-2.0"

    def test_falls_back_to_short_free_text(self):
        info = {"license_expression": "", "license": "MIT", "classifiers": []}
        assert spdx_from_pypi_payload(info) == "MIT"

    def test_accepts_single_line_compound_expression(self):
        # pyside6 declares its full SPDX expression only in the free-text
        # `license` field (44 chars, single line). The cap (100, matching
        # remote.py) must let it through so the audit tiers it the same way the
        # --online scanner does, rather than punting it to UNVERIFIABLE.
        expr = "LGPL-3.0-only OR GPL-2.0-only OR GPL-3.0-only"
        info = {"license_expression": "", "license": expr, "classifiers": []}
        assert spdx_from_pypi_payload(info) == expr

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


class TestPyPITierHint:
    """The tier-level fallback for id-ambiguous but tier-unambiguous OSI
    classifiers (e.g. a bare "BSD License"). It must pin a tier without ever
    fabricating a clause count, and must not fire on anything else."""

    def test_bare_bsd_classifier_is_permissive(self):
        info = {"classifiers": ["License :: OSI Approved :: BSD License"]}
        tier, tail = pypi_tier_hint(info)
        assert tier == TIER_PERMISSIVE
        assert tail == "BSD License"

    def test_no_matching_classifier_is_unknown(self):
        # An id we already resolve elsewhere must NOT be swallowed here; the
        # hint is a last resort, so it only fires for the family classifiers.
        info = {"classifiers": ["License :: OSI Approved :: MIT License"]}
        assert pypi_tier_hint(info) == (TIER_UNKNOWN, None)

    def test_no_license_classifier_is_unknown(self):
        info = {"classifiers": ["Programming Language :: Python :: 3"]}
        assert pypi_tier_hint(info) == (TIER_UNKNOWN, None)

    def test_empty_payload_is_unknown(self):
        assert pypi_tier_hint({}) == (TIER_UNKNOWN, None)

    def test_hint_does_not_override_concrete_spdx(self):
        # A package with both a concrete id AND a bare BSD classifier must be
        # resolved by the concrete id path (spdx_from_pypi_payload), so the
        # audit only consults the hint when that path yields UNKNOWN.
        info = {
            "license_expression": "",
            "license": "",
            "classifiers": [
                "License :: OSI Approved :: MIT License",
                "License :: OSI Approved :: BSD License",
            ],
        }
        assert spdx_from_pypi_payload(info) == "MIT"


class _FakeResp:
    """Minimal stand-in for an http.client.HTTPResponse for json.load()."""

    def __init__(self, payload):
        self._data = json.dumps(payload).encode()

    def read(self, *args):
        return self._data

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False


class TestHttpJsonRetries:
    """A single transient wire failure must not abort the ~230-request audit.

    Regression guard for the crash observed in practice: a partially-read body
    raises http.client.IncompleteRead, which is NOT a urllib URLError, so it
    slipped past _audit_one's except clause and pool.map re-raised it -- taking
    down every other package's result. _http_json now retries transient errors,
    and _audit_one catches whatever survives as a fail-soft ERROR row.
    """

    def _patch_urlopen(self, monkeypatch, side_effects):
        """Feed urlopen a queue: an exception is raised, else a _FakeResp."""
        calls = {"n": 0}
        queue = list(side_effects)

        def fake_urlopen(req, timeout=None):
            calls["n"] += 1
            item = queue.pop(0)
            if isinstance(item, Exception):
                raise item
            return _FakeResp(item)

        monkeypatch.setattr(audit_db.urllib.request, "urlopen", fake_urlopen)
        monkeypatch.setattr(audit_db.time, "sleep", lambda *a: None)
        return calls

    def test_retries_incomplete_read_then_succeeds(self, monkeypatch):
        calls = self._patch_urlopen(
            monkeypatch,
            [http.client.IncompleteRead(b"partial"), {"ok": True}],
        )
        assert audit_db._http_json("https://example/x", backoff=0) == {"ok": True}
        assert calls["n"] == 2  # one failed attempt, one success

    def test_gives_up_after_exhausting_retries(self, monkeypatch):
        calls = self._patch_urlopen(
            monkeypatch,
            [http.client.IncompleteRead(b"a")] * 3,
        )
        with pytest.raises(http.client.IncompleteRead):
            audit_db._http_json("https://example/x", retries=3, backoff=0)
        assert calls["n"] == 3  # exactly HTTP_RETRIES attempts, no more

    def test_does_not_retry_http_error(self, monkeypatch):
        # A 404 is permanent (package genuinely absent) -- retrying would only
        # hammer the registry. It must raise on the first attempt.
        err = audit_db.urllib.error.HTTPError(
            "https://example/x", 404, "Not Found", {}, None
        )
        calls = self._patch_urlopen(monkeypatch, [err])
        with pytest.raises(audit_db.urllib.error.HTTPError):
            audit_db._http_json("https://example/x", backoff=0)
        assert calls["n"] == 1

    def test_audit_one_reports_error_instead_of_crashing(self, monkeypatch):
        # After retries are exhausted the IncompleteRead reaches _audit_one; it
        # must be caught as an ERROR row (fail-soft), never propagate to pool.map.
        monkeypatch.setattr(
            audit_db,
            "_http_json",
            lambda *a, **k: (_ for _ in ()).throw(http.client.IncompleteRead(b"x")),
        )
        row = audit_db._audit_one("pypi", "somepkg", "MIT")
        assert row["status"] == "ERROR"
        assert row["name"] == "somepkg"
