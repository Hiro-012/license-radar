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


def fetch_pypi_license(name: str) -> str | None:
    url = f"https://pypi.org/pypi/{name}/json"
    try:
        with urllib.request.urlopen(url, timeout=_TIMEOUT) as resp:
            data = json.loads(resp.read())
    except (OSError, ValueError):
        return None

    info = data.get("info", {})
    license_field = (info.get("license") or "").strip()
    if license_field and len(license_field) < 40:
        return license_field

    for classifier in info.get("classifiers", []):
        if classifier.startswith("License :: OSI Approved ::"):
            return classifier.rsplit("::", 1)[-1].strip()

    return None


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
