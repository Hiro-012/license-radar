"""Optional live license lookup against public registry APIs.

Used only when the caller passes --online, since it requires network
access and is therefore excluded from the deterministic offline test
suite. Falls back to None (unknown) on any network or parsing error —
a scan should degrade gracefully, not crash, when a registry is
unreachable.
"""

import json
import urllib.parse
import urllib.request

_TIMEOUT = 5.0


def reduce_pypi_info(info: dict) -> str | None:
    """Reduce a PyPI ``info`` object to a single SPDX id or expression, or None.

    Priority mirrors what modern PyPI actually populates: the SPDX
    ``license_expression`` field first (this is where dual-licensed packages now
    declare ``Apache-2.0 OR BSD-2-Clause`` etc.), then an OSI-Approved trove
    classifier, then the legacy free-text ``license`` field. The free-text
    field is length-guarded so a package that dumps its whole license text into
    it does not become a bogus token. Pure/offline: safe to unit-test.
    """
    expr = (info.get("license_expression") or "").strip()
    if expr:
        return expr

    for classifier in info.get("classifiers", []) or []:
        if classifier.startswith("License :: OSI Approved ::"):
            return classifier.rsplit("::", 1)[-1].strip()

    license_field = (info.get("license") or "").strip()
    # The legacy free-text field is where older metadata still puts a
    # single-line SPDX expression (e.g. pyside6's 44-char
    # "LGPL-3.0-only OR GPL-2.0-only OR GPL-3.0-only"), so a 40-char cap is too
    # tight. Guard instead against the real hazard -- a package dumping its
    # whole license *text* here -- via the newline check plus a generous cap
    # that no SPDX expression approaches but prose blows past. A non-SPDX line
    # that slips through still classifies to `unknown` (the safe side).
    if license_field and len(license_field) <= 100 and "\n" not in license_field:
        return license_field

    return None


def fetch_pypi_license(name: str) -> str | None:
    url = f"https://pypi.org/pypi/{name}/json"
    try:
        with urllib.request.urlopen(url, timeout=_TIMEOUT) as resp:
            data = json.loads(resp.read())
    except (OSError, ValueError):
        return None

    return reduce_pypi_info(data.get("info", {}))


def fetch_npm_license(name: str) -> str | None:
    url = f"https://registry.npmjs.org/{urllib.parse.quote(name, safe='')}"
    try:
        with urllib.request.urlopen(url, timeout=_TIMEOUT) as resp:
            data = json.loads(resp.read())
    except (OSError, ValueError):
        return None

    license_field = data.get("license")
    if isinstance(license_field, str):
        return license_field
    if isinstance(license_field, dict):
        return license_field.get("type")
    return None


def fetch_remote_license(ecosystem: str, name: str) -> str | None:
    if ecosystem == "pypi":
        return fetch_pypi_license(name)
    if ecosystem == "npm":
        return fetch_npm_license(name)
    return None
