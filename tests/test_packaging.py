"""Packaging-manifest invariants.

The PyPI publish pipeline builds from ``pyproject.toml``. A malformed manifest
does not fail any behavioural test, so a corrupt manifest can merge cleanly and
only surface as a failed release job — exactly what happened when a merge left
two ``version =`` keys in ``[project]``, which is invalid TOML and silently
broke the 0.1.10 publish. These checks make that failure mode deterministic and
catch it in the normal test run, before it reaches the release workflow.
"""
import tomllib
from pathlib import Path

import license_radar

PYPROJECT = Path(__file__).resolve().parent.parent / "pyproject.toml"


def _load():
    # tomllib rejects duplicate keys ("Cannot overwrite a value"), so a
    # successful load already proves there is no duplicate version key.
    with open(PYPROJECT, "rb") as fh:
        return tomllib.load(fh)


def test_pyproject_is_valid_toml():
    data = _load()
    assert data["project"]["name"] == "license-radar"


def test_project_declares_exactly_one_version():
    # Belt-and-suspenders against the specific corruption: even if a future
    # TOML parser tolerated duplicate keys, the raw text must carry a single
    # top-level ``version =`` assignment.
    raw = PYPROJECT.read_text()
    version_lines = [
        ln for ln in raw.splitlines() if ln.strip().startswith("version =")
    ]
    assert len(version_lines) == 1, f"expected one version line, found {version_lines}"


def test_package_version_matches_manifest():
    # __init__.py drifted (stuck at 0.1.0 for ten releases) because nothing
    # enforced it; keep the runtime __version__ in lock-step with the manifest
    # the wheel is actually built and published from.
    manifest_version = _load()["project"]["version"]
    assert license_radar.__version__ == manifest_version, (
        f"__version__={license_radar.__version__} != pyproject {manifest_version}"
    )
