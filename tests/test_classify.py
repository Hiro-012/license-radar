from license_radar.classify import classify_expression, classify_license, tier_rank

def test_permissive():
    assert classify_license("MIT") == "permissive"
    assert classify_license("Apache-2.0") == "permissive"

def test_weak_copyleft():
    assert classify_license("MPL-2.0") == "weak-copyleft"
    assert classify_license("LGPL-3.0-only") == "weak-copyleft"

def test_strong_copyleft():
    assert classify_license("GPL-3.0-only") == "strong-copyleft"
    assert classify_license("AGPL-3.0-only") == "strong-copyleft"

def test_unknown():
    assert classify_license(None) == "unknown"
    assert classify_license("LicenseRef-Proprietary") == "unknown"

def test_aliases_from_free_text_registry_fields():
    assert classify_license("MIT License") == "permissive"
    assert classify_license("GPLv3") == "strong-copyleft"
    assert classify_license("BSD") == "permissive"

def test_public_domain_and_academic_permissive_ids():
    # CC0-1.0 (public-domain dedication) and MIT-CMU are permissive SPDX ids
    # that registries really declare (numpy's compound expr, pillow). Before
    # they were classified `unknown` -> a false positive under a default policy.
    assert classify_license("CC0-1.0") == "permissive"
    assert classify_license("MIT-CMU") == "permissive"

def test_verbose_free_text_aliases():
    # Longer free-text forms seen verbatim in PyPI's `license` field.
    assert classify_license("Apache License 2.0") == "permissive"
    assert classify_license("3-Clause BSD License") == "permissive"
    # A bare LGPL version is tier-unambiguous (both -only/-or-later are weak).
    assert classify_license("LGPL-2.1") == "weak-copyleft"

def test_tier_rank_orders_by_risk():
    assert tier_rank("permissive") < tier_rank("weak-copyleft") < tier_rank("strong-copyleft") < tier_rank("unknown")


class TestClassifyExpression:
    """The scanner classifies via classify_expression: single ids keep behaving
    exactly like classify_license, and compound SPDX expressions (which modern
    registries declare verbatim) now resolve by operator semantics instead of
    collapsing to `unknown`."""

    def test_single_id_matches_classify_license(self):
        assert classify_expression("MIT") == "permissive"
        assert classify_expression("GPL-3.0-only") == "strong-copyleft"
        assert classify_expression("MPL-2.0") == "weak-copyleft"
        assert classify_expression(None) == "unknown"

    def test_free_text_alias_still_resolves(self):
        # The single-id path (with its loose aliases) must win before the
        # tokenizer ever sees these -- they are not valid SPDX expressions.
        assert classify_expression("BSD") == "permissive"
        assert classify_expression("Apache License 2.0") == "permissive"

    def test_or_takes_least_restrictive(self):
        # Real registry expressions that were wrongly `unknown` (a false
        # positive under a default policy) before compound support:
        assert classify_expression("Apache-2.0 OR BSD-2-Clause") == "permissive"  # packaging
        assert classify_expression("LGPL-2.1-only OR MIT") == "permissive"  # pycurl
        # pyside6: every option is copyleft, weakest is LGPL -> weak-copyleft.
        assert (
            classify_expression("LGPL-3.0-only OR GPL-2.0-only OR GPL-3.0-only")
            == "weak-copyleft"
        )

    def test_and_takes_most_restrictive(self):
        # orjson's real expression: the MPL-2.0 obligation is unavoidable.
        assert classify_expression("MPL-2.0 AND (Apache-2.0 OR MIT)") == "weak-copyleft"
        assert classify_expression("Apache-2.0 AND MIT") == "permissive"

    def test_unresolvable_expression_stays_unknown(self):
        # An unknown atom or non-SPDX free text must not be guessed.
        assert classify_expression("MIT AND LicenseRef-Proprietary") == "unknown"
        assert classify_expression("LGPL with exceptions") == "unknown"
        assert classify_expression("MIT, Apache-2.0") == "unknown"
