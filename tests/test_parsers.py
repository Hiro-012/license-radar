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


def test_parse_requirements_vcs_url_and_editable_refs():
    # VCS/URL direct references and editable installs must contribute the real
    # package name (carried in #egg=), never the URL scheme. Regression guard:
    # a `git+https://…#egg=foolib` line previously yielded the bogus name "git"
    # (a spurious `unknown` violation) while dropping "foolib" entirely, and an
    # editable `-e …#egg=barlib` was skipped wholesale. An inline comment on a
    # normal requirement must not be mistaken for an #egg fragment either.
    ecosystem, names = parse_manifest(FIXTURES / "req_vcs" / "requirements.txt")
    assert ecosystem == "pypi"
    assert set(names) == {
        "requests",  # inline `# comment` stripped, not read as an egg fragment
        "foolib",    # git+https://…#egg=foolib  (was "git" before)
        "barlib",    # -e git+https://…#egg=barlib  (was dropped before)
        "quuxlib",   # hg+https://…#egg=quuxlib
        "bazlib",    # named plainly; the bare archive URL adds no second entry
        "mypkg",     # PEP 508 direct reference `name @ git+https://…`
    }
    # The URL schemes must never leak in as package names, and a bare archive
    # URL (no #egg=) and a local editable (`-e .`) contribute nothing.
    for bogus in ("git", "https", "http", "hg", "mercurial"):
        assert bogus not in names


def test_parse_requirements_joins_backslash_continuations():
    # pip joins a physical line ending in `\` onto the next line. Parsing raw
    # physical lines instead mis-read the continuation of an environment marker
    # as a package: `pkg; marker \` / `    and platform_system ...` surfaced a
    # phantom `and` (a spurious `unknown` violation under the default policy),
    # and hash-pinned requirements spread over several `\`-continued lines must
    # still contribute only the leading package name.
    ecosystem, names = parse_manifest(FIXTURES / "req_continuation" / "requirements.txt")
    assert ecosystem == "pypi"
    assert set(names) == {"pysdl2", "foolib", "requests"}
    # The marker keyword must never leak in as a package name.
    assert "and" not in names


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


def test_pyproject_poetry_includes_legacy_dev_dependencies():
    # Poetry < 1.2 declares dev deps in a flat [tool.poetry.dev-dependencies]
    # table (not the group syntax). Many un-migrated projects still use it; a
    # copyleft dev dependency there (python-levenshtein is GPL) was previously
    # missed entirely. `python` is excluded as it is the runtime.
    ecosystem, names = parse_manifest(
        FIXTURES / "sections" / "poetry-legacy" / "pyproject.toml"
    )
    assert ecosystem == "pypi"
    assert "python" not in names
    assert set(names) == {"requests", "pytest", "python-levenshtein"}


def test_pyproject_includes_pep735_dependency_groups():
    # PEP 735 [dependency-groups] is a standard table (pip --group, PDM, Hatch);
    # a copyleft dep declared only in a test/lint group there was previously
    # missed. `include-group` tables reference other groups and must not add a
    # bogus name.
    ecosystem, names = parse_manifest(
        FIXTURES / "sections" / "dependency-groups" / "pyproject.toml"
    )
    assert ecosystem == "pypi"
    assert set(names) == {"requests", "pytest", "python-levenshtein", "ruff"}


def test_pyproject_includes_pdm_dev_dependencies():
    # PDM keeps dev-only deps under [tool.pdm.dev-dependencies] as groups of
    # requirement strings; a copyleft dep declared only there (python-levenshtein
    # is GPL) was previously missed.
    ecosystem, names = parse_manifest(FIXTURES / "sections" / "pdm" / "pyproject.toml")
    assert ecosystem == "pypi"
    assert set(names) == {"requests", "pytest", "python-levenshtein", "ruff"}


def test_pyproject_includes_hatch_env_dependencies():
    # Hatch stores dev/test/lint deps under [tool.hatch.envs.<name>] in
    # `dependencies` / `extra-dependencies`; a copyleft dep declared only in a
    # Hatch env (python-levenshtein is GPL) was previously missed. Non-list env
    # keys (e.g. [tool.hatch.envs.lint.scripts]) must not add a bogus name.
    ecosystem, names = parse_manifest(
        FIXTURES / "sections" / "hatch" / "pyproject.toml"
    )
    assert ecosystem == "pypi"
    assert "check" not in names
    assert set(names) == {"requests", "pytest", "coverage", "python-levenshtein", "ruff"}


def test_package_json_includes_optional_and_peer_dependencies():
    ecosystem, names = parse_manifest(FIXTURES / "sections" / "npm" / "package.json")
    assert ecosystem == "npm"
    assert set(names) == {"react", "eslint", "fsevents", "typescript"}


def test_parse_setup_cfg_install_requires_and_extras():
    # Legacy setup.cfg projects declare deps under [options] install_requires,
    # tests_require, setup_requires and [options.extras_require]; a copyleft dep
    # hidden in any of them is still declared by the project and must be scanned
    # (python-levenshtein sits in tests_require here, mirroring the setup.py
    # parser). Environment markers (e.g. `; python_version >= "3.9"`) must not
    # become part of the name.
    ecosystem, names = parse_manifest(FIXTURES / "sections" / "setupcfg" / "setup.cfg")
    assert ecosystem == "pypi"
    assert set(names) == {
        "requests",
        "flask",
        "numpy",
        "setuptools-scm",
        "pytest",
        "python-levenshtein",
        "coverage",
        "sphinx",
    }


def test_discover_manifests_finds_setup_cfg():
    found = discover_manifests(FIXTURES / "sections" / "setupcfg")
    assert {p.name for p in found} == {"setup.cfg"}


def test_parse_setup_py_static_install_requires_and_extras():
    # Many legacy projects declare deps only in setup.py via install_requires /
    # extras_require / tests_require. They are read statically (never executed);
    # the `REQUIRES = [...]` variable is resolved, environment markers are
    # stripped from the name, and a non-literal element (`_dynamic`) is skipped
    # rather than fabricated into a bogus package name.
    ecosystem, names = parse_manifest(FIXTURES / "sections" / "setuppy" / "setup.py")
    assert ecosystem == "pypi"
    assert "some-package" not in names
    assert "_dynamic" not in names
    assert set(names) == {
        "requests",
        "flask",
        "python-levenshtein",
        "sphinx",
        "pytest",
        "coverage",
        "nose",
    }


def test_parse_setup_py_syntax_error_is_skipped(tmp_path):
    # A setup.py that does not parse must be skipped, not raise.
    bad = tmp_path / "setup.py"
    bad.write_text("setup(install_requires=[\n")  # unterminated
    ecosystem, names = parse_manifest(bad)
    assert ecosystem == "pypi"
    assert names == []


def test_discover_manifests_finds_setup_py():
    found = discover_manifests(FIXTURES / "sections" / "setuppy")
    assert {p.name for p in found} == {"setup.py"}


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
