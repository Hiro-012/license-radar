"""Resolve a compound SPDX license expression to a single compliance tier.

Real registries increasingly declare *expressions* rather than a single id --
``Apache-2.0 OR BSD-2-Clause`` (packaging), ``LGPL-2.1-only OR MIT`` (pycurl),
``MPL-2.0 AND (Apache-2.0 OR MIT)`` (orjson). The compliance tier of such an
expression follows directly from the SPDX operator semantics, so it can be
computed without ever guessing at a license:

* ``A AND B`` -- the licensee must satisfy *both*, so the effective obligation
  is the **most** restrictive operand (max tier rank).
* ``A OR B``  -- the licensee may satisfy *either*, so the effective obligation
  is the **least** restrictive operand (min tier rank).

Parentheses group as usual and ``AND`` binds tighter than ``OR`` (SPDX spec).
Any atom we cannot classify, an unsupported operator (``WITH``, since we do not
model license exceptions), a stray character, or a leftover/unbalanced token
makes the whole expression ``TIER_UNKNOWN`` -- the resolver refuses to guess
rather than let a ``min()``/``max()`` silently swallow an unclassifiable branch.

Everything here is pure and offline (no network, no I/O), so it is safe to unit
test and safe to call from the hot path of a scan.
"""

from __future__ import annotations

from license_radar.classify import (
    TIER_PERMISSIVE,
    TIER_STRONG_COPYLEFT,
    TIER_UNKNOWN,
    TIER_WEAK_COPYLEFT,
    classify_license,
    tier_rank,
)

# Tiers ordered from least to most restrictive, indexed by ``tier_rank``.
# Only the three concrete tiers appear here (rank 0-2); ``unknown`` (rank 3)
# never results from a fully-resolved expression because any unknown atom
# aborts evaluation.
_TIERS_BY_RANK = (TIER_PERMISSIVE, TIER_WEAK_COPYLEFT, TIER_STRONG_COPYLEFT)


class _ExprError(Exception):
    """Raised internally when an SPDX expression cannot be fully resolved."""


def _tokenize_spdx(expr: str):
    """Split an SPDX expression into ``(``, ``)``, AND, OR and identifier tokens.

    Returns a token list, or None if a character outside the SPDX-expression
    grammar is seen (which makes the whole string UNKNOWN rather than a guess).
    Identifiers are returned as ``("ID", text)`` tuples.
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
            # One unresolvable atom makes the whole expression unknown; we
            # never let a min()/max() silently swallow an unknown branch.
            raise _ExprError(f"unknown license id: {tok[1]}")
        return tier, pos + 1
    raise _ExprError("expected a license id or '('")


def tier_of_expression(expr: str | None) -> str:
    """Resolve a compound SPDX expression (``A AND B``, ``A OR (B AND C)``) to
    a single compliance tier, or ``TIER_UNKNOWN`` if it cannot be fully and
    unambiguously resolved.

    ``AND`` takes the most restrictive operand, ``OR`` the least. Any unknown
    atom, unsupported operator (``WITH``), stray character, or leftover token
    yields ``TIER_UNKNOWN`` -- we refuse to guess rather than risk a wrong
    verdict. Pure/offline: safe to unit-test and safe on the scan hot path.
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
