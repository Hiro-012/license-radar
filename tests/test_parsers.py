from pathlib import Path

from license_radar.parsers import discover_manifests, parse_manifest

FIXTURES = Path(__file__).parent / "fixtures"


def test_parse_requirements_txt():
    ecosystem, names = parse_manifest(FIXTURES / "pypi_project" / "requirements.txt")
    assert ecosystem == "pypi"
    assert "requests" in names
    assert "flask" in names
    assert "pyqt5" in names
    assert len(names) == 17


def test_parse_requirements_follows_r_includes():
    # A thin requirements.txt that defers to other files via -r / --requirement
    # must contribute the included files' packages, de-duplicated, with cycles
    # guarded against.
    ecosystem, names = parse_manifest(FIXTURES / "req_includes" / "requirements.txt")
    assert ecosystem == "pypi"
    # pyqt5 and numpy are reachable only through the includes.
    assert set(names) == {"flask", "requests", "pyqt5", "numpy"}
    # flask appears both inline and in base.txt: reported once.
    assert names.count("flask") == 1


def test_discover_manifests_does_not_pick_up_bare_include_files():
    # base.txt / extra.txt do not match the requirements*.txt pattern, so a
    # directory scan finds only requirements.txt; the includes reach the rest.
    found = discover_manifests(FIXTURES / "req_includes")
    assert {p.name for p in found} == {"requirements.txt"}


def test_parse_package_json():
    ecosystem, names = parse_manifest(FIXTURES / "npm_project" / "package.json")
    assert ecosystem == "npm"
    assert "react" in names
    assert "eslint" in names
    assert len(names) == 8


def test_pyproject_pep621_includes_optional_dependencies():
    # A copyleft dependency hidden in a `test`/`docs` extra is still declared
    # by the project and must be scanned, not silently skipped.
    ecosystem, names = parse_manifest(
        FIXTURES / "sections" / "pep621" / "pyproject.toml"
    )
    assert ecosystem == "pypi"
    assert set(names) == {"requests", "flask", "pytest", "coverage", "sphinx"}


def test_pyproject_poetry_includes_group_dependencies():
    # Poetry 1.2+ moved dev/test/docs deps into [tool.poetry.group.*] tables;
    # they were previously missed. `python` is excluded as it is the runtime.
    ecosystem, names = parse_manifest(
        FIXTURES / "sections" / "poetry" / "pyproject.toml"
    )
    assert ecosystem == "pypi"
    assert "python" not in names
    assert set(names) == {"requests", "flask", "pytest", "black", "sphinx"}


def test_package_json_includes_optional_and_peer_dependencies():
    ecosystem, names = parse_manifest(FIXTURES / "sections" / "npm" / "package.json")
    assert ecosystem == "npm"
    assert set(names) == {"react", "eslint", "fsevents", "typescript"}


def test_parse_setup_cfg_install_requires_and_extras():
    # Legacy setup.cfg projects declare deps under [options] install_requires
    # and [options.extras_require]; a copyleft dep hidden in either is still
    # declared by the project and must be scanned. Environment markers
    # (e.g. `; python_version >= "3.9"`) must not become part of the name.
    ecosystem, names = parse_manifest(FIXTURES / "sections" / "setupcfg" / "setup.cfg")
    assert ecosystem == "pypi"
    assert set(names) == {"requests", "flask", "numpy", "pytest", "coverage", "sphinx"}


def test_discover_manifests_finds_setup_cfg():
    found = discover_manifests(FIXTURES / "sections" / "setupcfg")
    assert {p.name for p in found} == {"setup.cfg"}


def test_parse_pipfile_packages_and_dev_packages():
    # A Pipenv Pipfile declares deps under [packages] and [dev-packages]; a
    # copyleft dep in either is still declared by the project and must be
    # scanned. The [requires] python_version is runtime metadata, not a
    # dependency, and must not appear as a package.
    ecosystem, names = parse_manifest(FIXTURES / "sections" / "pipfile" / "Pipfile")
    assert ecosystem == "pypi"
    assert "python_version" not in names
    assert set(names) == {"requests", "flask", "gunicorn", "pytest", "sphinx"}


def test_discover_manifests_finds_pipfile():
    found = discover_manifests(FIXTURES / "sections" / "pipfile")
    assert {p.name for p in found} == {"Pipfile"}


def test_discover_manifests_in_directory():
    found = discover_manifests(FIXTURES / "pypi_project")
    found_names = {p.name for p in found}
    assert found_names == {"requirements.txt"}

    found = discover_manifests(FIXTURES / "npm_project")
    found_names = {p.name for p in found}
    assert found_names == {"package.json"}


def test_discover_manifests_is_recursive_over_monorepo():
    # A monorepo declares manifests in nested subprojects; a compliance scan
    # must find all of them, not just the ones at the root.
    found = discover_manifests(FIXTURES / "monorepo")
    rel = {p.relative_to(FIXTURES / "monorepo").as_posix() for p in found}
    assert rel == {
        "pyproject.toml",
        "services/api/requirements.txt",
        "frontend/package.json",
    }


def test_discover_manifests_skips_vendored_and_virtualenv_dirs():
    # Manifests inside node_modules/ or venv/ belong to dependencies or the
    # environment, not to what the project declares, and must be skipped.
    found = discover_manifests(FIXTURES / "monorepo")
    parts = {part for p in found for part in p.parts}
    assert "node_modules" not in parts
    assert "venv" not in parts
