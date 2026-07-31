"""Classify an SPDX license identifier into a compliance risk tier."""

PERMISSIVE = {
    "MIT", "MIT-0", "MIT-CMU", "ISC", "BSD-2-Clause", "BSD-3-Clause",
    "Apache-2.0", "HPND", "Python-2.0", "PSF-2.0", "Unlicense", "0BSD",
    "Zlib", "BSL-1.0", "BlueOak-1.0.0", "CC0-1.0",
}

WEAK_COPYLEFT = {
    "MPL-2.0", "LGPL-2.1-only", "LGPL-2.1-or-later",
    "LGPL-3.0-only", "LGPL-3.0-or-later", "EPL-1.0", "EPL-2.0",
}

STRONG_COPYLEFT = {
    "GPL-2.0-only", "GPL-2.0-or-later", "GPL-3.0-only", "GPL-3.0-or-later",
    "AGPL-3.0-only", "AGPL-3.0-or-later", "SSPL-1.0",
}

TIER_PERMISSIVE = "permissive"
TIER_WEAK_COPYLEFT = "weak-copyleft"
TIER_STRONG_COPYLEFT = "strong-copyleft"
TIER_UNKNOWN = "unknown"

_RANK = {
    TIER_PERMISSIVE: 0,
    TIER_WEAK_COPYLEFT: 1,
    TIER_STRONG_COPYLEFT: 2,
    TIER_UNKNOWN: 3,
}

# Loose aliases seen in free-text "license" fields returned by registry
# APIs (as opposed to a strict SPDX id from our own curated DB). Every entry
# here is unambiguous *at the tier level*: a bare version like "LGPL-2.1" maps
# to a concrete id whose tier is the same for the -only/-or-later variants, so
# the choice of variant never changes the compliance verdict.
_ALIASES = {
    "MIT LICENSE": "MIT",
    "BSD": "BSD-3-Clause",
    "BSD LICENSE": "BSD-3-Clause",
    "3-CLAUSE BSD LICENSE": "BSD-3-Clause",
    "APACHE SOFTWARE LICENSE": "Apache-2.0",
    "APACHE 2.0": "Apache-2.0",
    "APACHE LICENSE 2.0": "Apache-2.0",
    "GPLV3": "GPL-3.0-only",
    "GPL V3": "GPL-3.0-only",
    "GPL-3.0": "GPL-3.0-only",
    "GPL-2.0": "GPL-2.0-only",
    "LGPLV3": "LGPL-3.0-only",
    "LGPL-3.0": "LGPL-3.0-only",
    "LGPL-2.1": "LGPL-2.1-only",
    "AGPLV3": "AGPL-3.0-only",
    "AGPL-3.0": "AGPL-3.0-only",
}


def _normalize(spdx: str) -> str:
    key = spdx.strip().upper()
    return _ALIASES.get(key, spdx.strip())


def classify_license(spdx: str | None) -> str:
    if not spdx:
        return TIER_UNKNOWN
    normalized = _normalize(spdx)
    if normalized in PERMISSIVE:
        return TIER_PERMISSIVE
    if normalized in WEAK_COPYLEFT:
        return TIER_WEAK_COPYLEFT
    if normalized in STRONG_COPYLEFT:
        return TIER_STRONG_COPYLEFT
    return TIER_UNKNOWN


def tier_rank(tier: str) -> int:
    return _RANK.get(tier, _RANK[TIER_UNKNOWN])


def classify_expression(spdx: str | None) -> str:
    """Classify a license value that may be a single id *or* a compound SPDX
    expression (``A AND B``, ``A OR (B AND C)``).

    Tries the single-id path first (``classify_license``, including its loose
    free-text aliases); only when that yields ``unknown`` does it fall back to
    full SPDX-expression evaluation. This ordering keeps every string that
    already resolved resolving exactly the same way -- the compound path is
    purely additive -- while letting the scanner correctly tier the compound
    expressions modern registries declare (e.g. ``LGPL-2.1-only OR MIT`` ->
    permissive, since the licensee may choose MIT).

    Imported lazily to avoid a circular import: ``spdx_expr`` resolves each
    atom through ``classify_license`` from this module.
    """
    tier = classify_license(spdx)
    if tier != TIER_UNKNOWN:
        return tier
    from license_radar.spdx_expr import tier_of_expression

    return tier_of_expression(spdx)
