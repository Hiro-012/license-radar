"""Extract dependency names from common manifest file formats."""

import configparser
import json
import os
import re
import tomllib
from pathlib import Path

_REQ_LINE_RE = re.compile(r"^\s*([A-Za-z0-9._-]+)")

# A pip requirements file can pull in another with ``-r other.txt`` or
# ``--requirement other.txt`` (``--requirement=other.txt`` is also accepted).
_REQ_INCLUDE_RE = re.compile(r"^(?:-r|--requirement)(?:\s+|=)(\S.*)$")

# Directories that hold *dependency-internal* manifests (the packages
# themselves) or unrelated tooling state, not the project's own declared
# dependencies. Scanning into them would be slow and semantically wrong:
# a compliance scan is about what a project declares, not the vendored copy
# of every transitive package's own manifest.
_SKIP_DIRS = frozenset(
    {
        ".git",
        ".hg",
        ".svn",
        "node_modules",
        "bower_components",
        "vendor",
        ".venv",
        "venv",
        "env",
        ".env",
        ".tox",
        ".nox",
        "__pycache__",
        "site-packages",
        ".mypy_cache",
        ".pytest_cache",
        ".ruff_cache",
        ".cache",
        "dist",
        "build",
        ".eggs",
        ".next",
        ".nuxt",
        ".gradle",
        ".idea",
        ".vscode",
    }
)


def _dedupe(names: list[str]) -> list[str]:
    """Order-preserving de-duplication.

    A package may be declared in more than one section (e.g. both
    ``dependencies`` and ``optionalDependencies``); it should be reported once.
    """
    seen: set[str] = set()
    result: list[str] = []
    for name in names:
        if name not in seen:
            seen.add(name)
            result.append(name)
    return result


def _requirement_include_target(line: str) -> str | None:
    """Return the file referenced by a ``-r``/``--requirement`` line, else None."""
    match = _REQ_INCLUDE_RE.match(line)
    if not match:
        return None
    target = match.group(1).strip().strip("\"'")
    return target or None


def parse_requirements_txt(path: Path, _seen: set[Path] | None = None) -> list[str]:
    """Parse a pip requirements file, following ``-r``/``--requirement`` includes.

    pip lets one requirements file pull in another with ``-r other.txt``; the
    included file's packages are just as much a declared dependency as those
    listed inline. A copyleft dependency living only in an included file (e.g. a
    thin ``requirements.txt`` doing ``-r prod.txt``) would otherwise be silently
    skipped. Includes are resolved relative to the including file's directory,
    cycles are guarded against, and a missing target is ignored. ``-c`` /
    ``--constraint`` files only pin versions of already-required packages, so
    they are deliberately not followed.
    """
    if _seen is None:
        _seen = set()
    try:
        resolved = path.resolve()
    except OSError:
        resolved = path
    if resolved in _seen:
        return []
    _seen.add(resolved)

    names: list[str] = []
    for raw_line in path.read_text().splitlines():
        line = raw_line.split("#", 1)[0].strip()
        if not line:
            continue
        include = _requirement_include_target(line)
        if include is not None:
            target = path.parent / include
            if target.exists():
                names.extend(parse_requirements_txt(target, _seen))
            continue
        if line.startswith(("-", "--")):
            continue
        match = _REQ_LINE_RE.match(line)
        if match:
            names.append(match.group(1))
    return _dedupe(names)


def _add_req_strings(names: list[str], deps) -> None:
    """Append names parsed from a list of PEP 508 requirement strings."""
    for dep in deps:
        match = _REQ_LINE_RE.match(dep.strip())
        if match:
            names.append(match.group(1))


def parse_pyproject_toml(path: Path) -> list[str]:
    data = tomllib.loads(path.read_text())
    names: list[str] = []

    project = data.get("project", {})

    # PEP 621 core dependencies.
    _add_req_strings(names, project.get("dependencies", []))

    # PEP 621 optional dependencies (extras): a table of extra-name -> list of
    # requirement strings. A copyleft dependency hidden in a `test`/`docs`
    # extra is still a dependency the project declares, so it must be scanned.
    for extra_deps in project.get("optional-dependencies", {}).values():
        _add_req_strings(names, extra_deps)

    poetry = data.get("tool", {}).get("poetry", {})

    # Poetry main dependencies (a table of name -> version spec).
    for name in poetry.get("dependencies", {}):
        if name.lower() != "python":
            names.append(name)

    # Legacy Poetry (< 1.2) dev dependencies: [tool.poetry.dev-dependencies].
    # This flat table predates the group syntax below and is still used by many
    # existing projects that have not migrated. A copyleft dependency declared
    # here (e.g. a GPL test helper) would otherwise be silently skipped.
    for name in poetry.get("dev-dependencies", {}):
        if name.lower() != "python":
            names.append(name)

    # Poetry 1.2+ dependency groups: [tool.poetry.group.<name>.dependencies].
    # Dev/test/docs dependencies moved here from the legacy dev-dependencies
    # table and were previously missed entirely.
    for group in poetry.get("group", {}).values():
        if not isinstance(group, dict):
            continue
        for name in group.get("dependencies", {}):
            if name.lower() != "python":
                names.append(name)

    return _dedupe(names)


def _split_cfg_list(value: str) -> list[str]:
    """Split a setup.cfg list-valued option into individual requirement lines.

    setuptools stores ``install_requires`` / ``extras_require`` entries one per
    line. A leading ``file:`` directive (setuptools reads the list from another
    file) is not a requirement and is skipped.
    """
    lines = []
    for raw in value.splitlines():
        line = raw.strip()
        if not line or line.startswith("file:"):
            continue
        lines.append(line)
    return lines


def parse_setup_cfg(path: Path) -> list[str]:
    """Parse a legacy ``setup.cfg`` for the project's declared dependencies.

    Many Python projects still declare dependencies only in ``setup.cfg`` under
    ``[options] install_requires`` and ``[options.extras_require]``. A copyleft
    dependency declared there is exactly what a compliance scan must catch, so
    it is read the same as its ``pyproject.toml`` equivalent.
    """
    # interpolation=None: a version spec may legitimately contain a bare '%'.
    parser = configparser.ConfigParser(interpolation=None)
    try:
        parser.read_string(path.read_text())
    except configparser.Error:
        return []

    names: list[str] = []

    if parser.has_option("options", "install_requires"):
        _add_req_strings(
            names, _split_cfg_list(parser.get("options", "install_requires"))
        )

    # [options.extras_require]: each option is an extra name whose value is a
    # list of requirement strings, mirroring PEP 621 optional-dependencies.
    if parser.has_section("options.extras_require"):
        for _extra, value in parser.items("options.extras_require"):
            _add_req_strings(names, _split_cfg_list(value))

    return _dedupe(names)


def parse_pipfile(path: Path) -> list[str]:
    """Parse a Pipenv ``Pipfile`` for the project's declared dependencies.

    A ``Pipfile`` is TOML: ``[packages]`` and ``[dev-packages]`` are tables
    keyed by package name (the value is a version spec string or a table with
    ``version``/``extras``). Many projects declare their dependencies only in a
    Pipfile, so a copyleft dependency listed there would otherwise be silently
    skipped. The ``[requires]`` section (e.g. ``python_version``) describes the
    runtime, not dependencies, and is deliberately not read.
    """
    try:
        data = tomllib.loads(path.read_text())
    except tomllib.TOMLDecodeError:
        return []

    names: list[str] = []
    for section in ("packages", "dev-packages"):
        table = data.get(section, {})
        if isinstance(table, dict):
            names.extend(table.keys())
    return _dedupe(names)


def parse_package_json(path: Path) -> list[str]:
    data = json.loads(path.read_text())
    names: list[str] = []
    # optionalDependencies are installed when available; peerDependencies are
    # declared as required alongside the package. Both are dependencies the
    # project declares, so both are in scope for a license-compliance scan.
    for section in (
        "dependencies",
        "devDependencies",
        "optionalDependencies",
        "peerDependencies",
    ):
        names.extend(data.get(section, {}).keys())
    return _dedupe(names)


def _matches_manifest(name: str) -> tuple[str, object] | None:
    if name == "pyproject.toml":
        return "pypi", parse_pyproject_toml
    if name == "package.json":
        return "npm", parse_package_json
    if name == "setup.cfg":
        return "pypi", parse_setup_cfg
    if name == "Pipfile":
        return "pypi", parse_pipfile
    if name.startswith("requirements") and name.endswith(".txt"):
        return "pypi", parse_requirements_txt
    return None


def _is_skipped_dir(name: str) -> bool:
    return name in _SKIP_DIRS or name.endswith(".egg-info")


def discover_manifests(root: Path) -> list[Path]:
    """Find every recognized manifest under ``root`` (recursively).

    Directories that hold vendored dependencies, virtualenvs, or tooling
    caches (see ``_SKIP_DIRS``) are pruned so a scan reflects the manifests a
    project actually declares, including those nested in monorepo subprojects
    (e.g. ``services/api/requirements.txt``), not the manifests bundled inside
    its dependencies.
    """
    if root.is_file():
        return [root] if _matches_manifest(root.name) else []

    found: list[Path] = []
    for dirpath, dirnames, filenames in os.walk(root):
        # Prune skipped directories in place so os.walk does not descend into them.
        dirnames[:] = [d for d in dirnames if not _is_skipped_dir(d)]
        for filename in filenames:
            if _matches_manifest(filename):
                found.append(Path(dirpath) / filename)
    return sorted(found)


def parse_manifest(path: Path) -> tuple[str, list[str]]:
    match = _matches_manifest(path.name)
    if match is None:
        raise ValueError(f"unrecognized manifest file: {path.name}")
    ecosystem, parser = match
    return ecosystem, parser(path)
