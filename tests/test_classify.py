from license_radar.classify import classify_license, tier_rank

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
