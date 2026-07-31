#!/usr/bin/env python3
"""Audit the offline license DB against the live PyPI / npm registries.

Why this exists
---------------
``license_radar`` ships a hand-curated, *name-keyed* offline table mapping a
package to a single SPDX license id (``license_radar/license_db.py``). That
design is fast and network-free, but it has one structural blind spot: a
package can be *relicensed* upstream over time, and a name-keyed entry then
silently returns a stale answer. For a license-compliance tool the worst
failure is a confident wrong answer -- e.g. flagging a now-permissive package
as a copyleft violation (false positive), or missing a real copyleft
obligation (false negative).

This actually happened: ``chardet`` relicensed from LGPL-2.1 to 0BSD in its
6.x/7.x line, which is why that entry was removed from the DB on 2026-07-29.
That fix was found by a *manual* one-off audit whose script was never
committed. This module makes the audit a committed, repeatable artifact so the
same class of drift is caught mechanically instead of by luck.

What it checks
--------------
For every *real* (non ``test-`` synthetic) entry it fetches the registry's
declared license, reduces both the DB value and the registry value to a
compliance **tier** using the shipping ``classify_license`` logic, and
compares the tiers. It reports:

* ``DRIFT``        -- DB tier and registry tier disagree. Needs human review.
                      This is the signal that matters (the chardet case).
* ``OK``           -- tiers agree.
* ``UNVERIFIABLE`` -- the registry's license metadata is too vague to map to a
                      known tier (e.g. a compound expression containing an atom
                      we cannot classify, an exception-bearing ``"LGPL with
                      exceptions"`` string, or missing metadata). Not a
                      mismatch -- we simply cannot confirm from the registry, so
                      we do not cry wolf. Note some trove classifiers name a
                      license *family* whose exact SPDX id is unrecoverable but
                      whose compliance *tier* is certain (a bare ``"BSD
                      License"`` is always permissive); because the audit
                      compares tiers, those are resolved via a tier-level
                      fallback rather than being punted (see ``_CLASSIFIER_TIER``).

Compound SPDX expressions (``A AND B``, ``A OR (B AND C)``) are resolved to a
single tier the same way the hand-curated DB collapses them -- ``AND`` takes
the most restrictive operand, ``OR`` the least -- so real-world dual-licensed
packages (e.g. ``orjson`` = ``MPL-2.0 AND (Apache-2.0 OR MIT)``) are actually
drift-checked instead of being waved through as UNVERIFIABLE. If *any* atom in
the expression is unclassifiable the whole row stays UNVERIFIABLE.
* ``ERROR``        -- network / 404 / parse failure for that package.

Tier comparison (rather than exact-string comparison) is deliberate: the DB
intentionally collapses compound expressions and BSD variants to a single
representative id, so exact-string matching would produce noise. What we
actually care about is whether the *risk classification* a user sees is still
correct.

Exit status
-----------
``0`` when there are zero ``DRIFT`` rows, ``1`` otherwise. ``UNVERIFIABLE`` and
``ERROR`` rows do not fail the run on their own (they are network/metadata
noise, not DB defects), but they are always printed so a human can skim them.
Pass ``--strict`` to also fail on ``ERROR`` rows.

This script needs network access and is therefore *not* part of the
deterministic ``pytest`` suite. It is meant to be run manually by a maintainer
or on a schedule in CI (see ``.github/workflows/audit-license-db.yml``). The
pure, offline helpers (registry-payload -> SPDX reduction) are unit-tested in
``tests/test_audit_helpers.py`` so the parsing logic itself stays covered
without a network dependency.
"""

from __future__ import annotations

import argparse
import json
import sys
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

# Allow running as `python scripts/audit_db.py` from the repo root.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from license_radar.classify import (  # noqa: E402
    TIER_PERMISSIVE,
    TIER_STRONG_COPYLEFT,
    TIER_UNKNOWN,
    TIER_WEAK_COPYLEFT,
    classify_license,
    tier_rank,
)
from license_radar.license_db import (  # noqa: E402
    NPM_LICENSES,
    PYPI_LICENSES,
)

USER_AGENT = "license-radar-db-audit/1.0 (+https://pypi.org/project/license-radar/)"
TIMEOUT = 20

# Trove "License :: OSI Approved :: X" classifier tails -> SPDX id, limited to
# ids that reduce to an unambiguous tier. Anything not listed here (e.g. a bare
# "BSD License", which does not say 2- vs 3-clause) is intentionally left
# unmapped so the row becomes UNVERIFIABLE rather than a spurious DRIFT.
_CLASSIFIER_SPDX = {
    "MIT License": "MIT",
    "MIT No Attribution License (MIT-0)": "MIT-0",
    "Apache Software License": "Apache-2.0",
    "ISC License (ISCL)": "ISC",
    "The Unlicense (Unlicense)": "Unlicense",
    "zlib/libpng License": "Zlib",
    "Mozilla Public License 2.0 (MPL 2.0)": "MPL-2.0",
    "GNU General Public License v2 (GPLv2)": "GPL-2.0-only",
    "GNU General Public License v2 or later (GPLv2+)": "GPL-2.0-or-later",
    "GNU General Public License v3 (GPLv3)": "GPL-3.0-only",
    "GNU General Public License v3 or later (GPLv3+)": "GPL-3.0-or-later",
    "GNU Lesser General Public License v2 (LGPLv2)": "LGPL-2.1-only",
    "GNU Lesser General Public License v2 or later (LGPLv2+)": "LGPL-2.1-or-later",
    "GNU Lesser General Public License v3 (LGPLv3)": "LGPL-3.0-only",
    "GNU Lesser General Public License v3 or later (LGPLv3+)": "LGPL-3.0-or-later",
    "GNU Affero General Public License v3": "AGPL-3.0-only",
    "GNU Affero General Public License v3 or later (AGPLv3+)": "AGPL-3.0-or-later",
    # PSF-2.0 is a single, tier-unambiguous SPDX id (permissive); matplotlib
    # declares only this classifier (its `license` field is the full license
    # text), so without this row it escapes drift monitoring entirely.
    "Python Software Foundation License": "PSF-2.0",
}

# Some OSI-Approved trove tails name a *family* rather than a single SPDX id
# (e.g. a bare "BSD License" that does not say 2- vs 3-clause). Their exact id
# is unrecoverable, so they must never be turned into a fake SPDX string
# (``spdx_from_pypi_payload`` still returns None for them). But their compliance
# *tier* is certain -- every license the trove classifier can denote sits in
# the same tier -- and the audit compares tiers, not ids. Mapping the tail
# straight to a tier lets these packages be drift-checked (if one relicensed to
# copyleft its classifier would change and the audit would flag DRIFT) without
# ever asserting a clause count we do not know.
_CLASSIFIER_TIER = {
    # BSD-2-Clause / BSD-3-Clause / 0BSD are all permissive; no copyleft
    # license is ever tagged "License :: OSI Approved :: BSD License".
    "BSD License": TIER_PERMISSIVE,
}


# Tiers ordered from least to most restrictive, indexed by ``tier_rank``.
# Only the three concrete tiers appear here (rank 0-2); ``unknown`` (rank 3)
# never results from a fully-resolved expression because any unknown atom
# aborts evaluation.
_TIERS_BY_RANK = (TIER_PERMISSIVE, TIER_WEAK_COPYLEFT, TIER_STRONG_COPYLEFT)


class _ExprError(Exception):
    """Raised internally when an SPDX expression cannot be fully resolved."""


def _tokenize_spdx(expr: str):
    """Split an SPDX expression into (), AND, OR and identifier tokens.

    Returns a token list, or None if a character outside the SPDX-expression
    grammar is seen (which makes the whole string UNVERIFIABLE rather than a
    guess). Identifiers are returned as ``("ID", text)`` tuples.
    """
    tokens = []
    i, n = 0, len(expr)
    while i < n:
        c = expr[i]
        if c.isspace():
            i += 1
            continue
        if c in "()":
            tokens.append(c)
            i += 1
            continue
        j = i
        while j < n and (expr[j].isalnum() or expr[j] in ".-+_"):
            j += 1
        if j == i:  # a stray character (comma, slash, ...) -> not an SPDX expr
            return None
        word = expr[i:j]
        upper = word.upper()
        if upper == "AND":
            tokens.append("AND")
        elif upper == "OR":
            tokens.append("OR")
        elif upper == "WITH":
            # License-exception operator; tier-neutral but we do not model
            # exceptions, so refuse the whole expression rather than guess.
            return None
        else:
            tokens.append(("ID", word))
        i = j
    return tokens


def _parse_or(toks, pos):
    # 'A OR B': the licensee may satisfy *either* license, so the effective
    # obligation is the LEAST restrictive operand (min rank).
    tier, pos = _parse_and(toks, pos)
    rank = tier_rank(tier)
    while pos < len(toks) and toks[pos] == "OR":
        rtier, pos = _parse_and(toks, pos + 1)
        rank = min(rank, tier_rank(rtier))
    return _TIERS_BY_RANK[rank], pos


def _parse_and(toks, pos):
    # 'A AND B': the licensee must satisfy *both*, so the effective obligation
    # is the MOST restrictive operand (max rank).
    tier, pos = _parse_atom(toks, pos)
    rank = tier_rank(tier)
    while pos < len(toks) and toks[pos] == "AND":
        rtier, pos = _parse_atom(toks, pos + 1)
        rank = max(rank, tier_rank(rtier))
    return _TIERS_BY_RANK[rank], pos


def _parse_atom(toks, pos):
    if pos >= len(toks):
        raise _ExprError("unexpected end of expression")
    tok = toks[pos]
    if tok == "(":
        tier, pos = _parse_or(toks, pos + 1)
        if pos >= len(toks) or toks[pos] != ")":
            raise _ExprError("unbalanced parenthesis")
        return tier, pos + 1
    if isinstance(tok, tuple) and tok[0] == "ID":
        tier = classify_license(tok[1])
        if tier == TIER_UNKNOWN:
            # One unresolvable atom makes the whole expression unverifiable;
            # we never let a min()/max() silently swallow an unknown branch.
            raise _ExprError(f"unknown license id: {tok[1]}")
        return tier, pos + 1
    raise _ExprError("expected a license id or '('")


def tier_of_expression(expr: str | None) -> str:
    """Resolve a compound SPDX expression (``A AND B``, ``A OR (B AND C)``) to
    a single compliance tier, or ``TIER_UNKNOWN`` if it cannot be fully and
    unambiguously resolved.

    Semantics mirror how the hand-curated DB collapses compound licenses:
    ``AND`` takes the most restrictive operand, ``OR`` the least. Any unknown
    atom, unsupported operator (``WITH``), stray character, or leftover token
    yields ``TIER_UNKNOWN`` -- the audit refuses to guess rather than risk a
    spurious DRIFT/OK. Pure/offline: safe to unit-test.
    """
    if not expr or not expr.strip():
        return TIER_UNKNOWN
    toks = _tokenize_spdx(expr)
    if not toks:
        return TIER_UNKNOWN
    try:
        tier, pos = _parse_or(toks, 0)
    except _ExprError:
        return TIER_UNKNOWN
    if pos != len(toks):  # trailing tokens -> free text, not an SPDX expression
        return TIER_UNKNOWN
    return tier


def registry_tier(reg_spdx: str | None) -> str:
    """Best-effort compliance tier for a registry-declared license string.

    First tries ``classify_license`` directly (single ids and the loose
    free-text aliases it already understands); only when that is ``unknown``
    does it fall back to compound-expression evaluation. This ordering keeps
    every string that resolved before resolving exactly the same way -- the
    compound path is purely additive.
    """
    tier = classify_license(reg_spdx)
    if tier != TIER_UNKNOWN:
        return tier
    return tier_of_expression(reg_spdx)


def _http_json(url: str) -> dict:
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
        return json.load(resp)


def spdx_from_pypi_payload(info: dict) -> str | None:
    """Reduce a PyPI ``info`` object to a single SPDX-ish token, or None.

    Priority: ``license_expression`` (modern SPDX) -> a License classifier we
    can map -> the free-text ``license`` field. Returns None when nothing
    usable is present. Pure/offline: safe to unit-test.
    """
    expr = (info.get("license_expression") or "").strip()
    if expr:
        return expr

    for classifier in info.get("classifiers", []) or []:
        if not classifier.startswith("License :: "):
            continue
        tail = classifier.rsplit(" :: ", 1)[-1].strip()
        if tail in _CLASSIFIER_SPDX:
            return _CLASSIFIER_SPDX[tail]

    free = (info.get("license") or "").strip()
    # Guard against packages that dump their whole license text into the field.
    if free and len(free) <= 40 and "\n" not in free:
        return free
    return None


def pypi_tier_hint(info: dict):
    """Compliance tier for a package whose only usable metadata is a
    tier-unambiguous-but-id-ambiguous OSI classifier (see ``_CLASSIFIER_TIER``).

    Returns ``(tier, classifier_tail)`` so the caller can display the real
    classifier string rather than a guessed SPDX id, or ``(TIER_UNKNOWN, None)``
    when no such classifier is present. Pure/offline: safe to unit-test.

    This is a deliberate fallback used only after ``spdx_from_pypi_payload`` +
    ``registry_tier`` come up empty, so it never overrides a concrete SPDX
    reduction.
    """
    for classifier in info.get("classifiers", []) or []:
        if not classifier.startswith("License :: "):
            continue
        tail = classifier.rsplit(" :: ", 1)[-1].strip()
        if tail in _CLASSIFIER_TIER:
            return _CLASSIFIER_TIER[tail], tail
    return TIER_UNKNOWN, None


def spdx_from_npm_payload(doc: dict) -> str | None:
    """Reduce an npm registry document to a single SPDX token, or None."""
    latest = doc.get("dist-tags", {}).get("latest")
    version_doc = doc.get("versions", {}).get(latest, {}) if latest else {}
    lic = version_doc.get("license") or doc.get("license")
    if isinstance(lic, dict):  # legacy npm {type, url} shape
        lic = lic.get("type")
    if isinstance(lic, str) and lic.strip():
        return lic.strip()
    return None


def _audit_one(ecosystem: str, name: str, db_spdx: str) -> dict:
    db_tier = classify_license(db_spdx)
    info = {}
    try:
        if ecosystem == "pypi":
            payload = _http_json(f"https://pypi.org/pypi/{name}/json")
            info = payload.get("info", {})
            reg_spdx = spdx_from_pypi_payload(info)
        else:
            payload = _http_json(f"https://registry.npmjs.org/{name}")
            reg_spdx = spdx_from_npm_payload(payload)
    except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError, ValueError) as exc:
        return {"eco": ecosystem, "name": name, "status": "ERROR",
                "db": db_spdx, "reg": None, "detail": str(exc)[:80]}

    reg_tier = registry_tier(reg_spdx)
    if reg_tier == TIER_UNKNOWN and ecosystem == "pypi":
        # Last resort: a tier-unambiguous OSI classifier (e.g. bare "BSD
        # License") we cannot pin to one SPDX id but can pin to one tier.
        hint_tier, hint_tail = pypi_tier_hint(info)
        if hint_tier != TIER_UNKNOWN:
            reg_tier = hint_tier
            reg_spdx = hint_tail
    if reg_spdx is None or reg_tier == TIER_UNKNOWN:
        status = "UNVERIFIABLE"
    elif reg_tier == db_tier:
        status = "OK"
    else:
        status = "DRIFT"
    return {"eco": ecosystem, "name": name, "status": status,
            "db": f"{db_spdx} ({db_tier})",
            "reg": f"{reg_spdx} ({reg_tier})", "detail": ""}


def _real_entries():
    for name, spdx in sorted(PYPI_LICENSES.items()):
        if not name.startswith("test-"):
            yield ("pypi", name, spdx)
    for name, spdx in sorted(NPM_LICENSES.items()):
        if not name.startswith("test-"):
            yield ("npm", name, spdx)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--strict", action="store_true",
                        help="also exit non-zero on ERROR rows")
    parser.add_argument("--jobs", type=int, default=8,
                        help="parallel registry requests (default: 8)")
    args = parser.parse_args(argv)

    entries = list(_real_entries())
    print(f"Auditing {len(entries)} real DB entries against live registries...\n")

    with ThreadPoolExecutor(max_workers=args.jobs) as pool:
        results = list(pool.map(lambda e: _audit_one(*e), entries))

    buckets = {"DRIFT": [], "UNVERIFIABLE": [], "ERROR": [], "OK": []}
    for row in results:
        buckets[row["status"]].append(row)

    for status in ("DRIFT", "ERROR", "UNVERIFIABLE"):
        rows = buckets[status]
        if not rows:
            continue
        print(f"--- {status} ({len(rows)}) ---")
        for r in rows:
            line = f"  {r['eco']:4} {r['name']:24} db={r['db']}"
            if r["reg"]:
                line += f"  registry={r['reg']}"
            if r["detail"]:
                line += f"  [{r['detail']}]"
            print(line)
        print()

    total = len(results)
    print(
        "Summary: "
        f"{len(buckets['OK'])} OK, "
        f"{len(buckets['DRIFT'])} DRIFT, "
        f"{len(buckets['UNVERIFIABLE'])} UNVERIFIABLE, "
        f"{len(buckets['ERROR'])} ERROR "
        f"(of {total})"
    )

    if buckets["DRIFT"]:
        print("\nDRIFT rows indicate the offline DB tier no longer matches the "
              "registry. Re-verify each against the live API and update "
              "license_radar/license_db.py (or remove the entry if the license "
              "is version-dependent, as was done for chardet).")
        return 1
    if args.strict and buckets["ERROR"]:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
