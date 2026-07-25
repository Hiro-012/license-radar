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

def test_tier_rank_orders_by_risk():
    assert tier_rank("permissive") < tier_rank("weak-copyleft") < tier_rank("strong-copyleft") < tier_rank("unknown")
