from pathlib import Path

from license_radar.parsers import discover_manifests, parse_manifest

FIXTURES = Path(__file__).parent / "fixtures"


def test_parse_requirements_txt():
    ecosystem, names = parse_manifest(FIXTURES / "pypi_project" / "requirements.txt")
    assert ecosystem == "pypi"
    assert "requests" in names
    assert "flask" in names
    assert "pyqt5" in names
    assert len(names) == 13


def test_parse_package_json():
    ecosystem, names = parse_manifest(FIXTURES / "npm_project" / "package.json")
    assert ecosystem == "npm"
    assert "react" in names
    assert "eslint" in names
    assert len(names) == 7


def test_discover_manifests_in_directory():
    found = discover_manifests(FIXTURES / "pypi_project")
    found_names = {p.name for p in found}
    assert found_names == {"requirements.txt"}

    found = discover_manifests(FIXTURES / "npm_project")
    found_names = {p.name for p in found}
    assert found_names == {"package.json"}
