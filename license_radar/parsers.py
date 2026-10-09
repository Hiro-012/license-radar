"""Extract dependency names from common manifest file formats."""

import ast
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

# pip treats ``#`` as starting a comment only when it is at the start of the
# line or preceded by whitespace. An inline ``#egg=<name>`` URL fragment has no
# space before the ``#`` and is therefore NOT a comment — a naive
# ``split("#")`` would wrongly drop it and lose the package name it carries.
_COMMENT_RE = re.compile(r"(?:^|\s)#.*$")

# An editable install: ``-e <target>`` / ``--editable <target>`` where target
# is a VCS/URL/local ref (the requirement name, if any, rides in a ``#egg=``).
_EDITABLE_RE = re.compile(r"^(?:-e|--editable)(?:\s+|=)")

# A bare VCS or URL requirement line: ``git+https://…``, ``hg+…``, or a plain
# ``https://…`` archive URL. The leading token is a scheme, not a package name,
# so it must never be emitted as one.
_URL_LINE_RE = re.compile(r"^(?:[a-z][a-z0-9+.\-]*://|(?:git|hg|bzr|svn)\+)")

# ``#egg=<name>`` / ``&egg=<name>`` fragment naming the package a VCS/URL ref
# installs. This is the only reliable package name such a line carries.
_EGG_RE = re.compile(r"[#&]egg=([A-Za-z0-9._-]+)")

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


def _join_continuations(text: str) -> list[str]:
    """Join pip line continuations into logical lines, mirroring pip.

    A physical line ending in a backslash continues onto the next line; pip
    parses the joined result as one requirement. Iterating raw physical lines
    instead mis-reads the continuation of an environment marker as a package:
    ``pkg; python_version >= "3.8" \\`` followed by ``    and platform_system
    == "Linux"`` would surface a phantom ``and`` dependency (a spurious
    ``unknown`` violation under the default policy). The whitespace before the
    backslash is preserved on join so adjacent tokens are not glued together.
    """
    logical: list[str] = []
    buf: str | None = None
    for physical in text.splitlines():
        stripped = physical.rstrip()
        if stripped.endswith("\\"):
            piece = stripped[:-1]
            buf = piece if buf is None else buf + piece
        elif buf is not None:
            logical.append(buf + physical)
            buf = None
        else:
            logical.append(physical)
    if buf is not None:
        logical.append(buf)
    return logical


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
    for raw_line in _join_continuations(path.read_text()):
        line = _COMMENT_RE.sub("", raw_line).strip()
        if not line:
            continue
        include = _requirement_include_target(line)
        if include is not None:
            target = path.parent / include
            if target.exists():
                names.extend(parse_requirements_txt(target, _seen))
            continue
        # Editable installs (``-e <url>#egg=name``) are skipped by the generic
        # option guard below, so handle them first: the package name, if the ref
        # names one, lives only in an ``#egg=`` fragment.
        if _EDITABLE_RE.match(line):
            egg = _EGG_RE.search(line)
            if egg:
                names.append(egg.group(1))
            continue
        if line.startswith(("-", "--")):
            continue
        # A bare VCS/URL requirement: the leading token is a scheme, so only an
        # ``#egg=`` fragment can name the package. Without one, emit nothing
        # rather than a bogus ``git``/``https`` name (which would surface as a
        # spurious ``unknown`` violation). A PEP 508 direct reference
        # (``name @ git+https://…``) does not start with a scheme, so it falls
        # through to the name-first match below and keeps its real name.
        if _URL_LINE_RE.match(line):
            egg = _EGG_RE.search(line)
            if egg:
                names.append(egg.group(1))
            continue
        match = _REQ_LINE_RE.match(line)
        if match:
            names.append(match.group(1))
    return _dedupe(names)


def _add_req_strings(names: list[str], deps) -> None:
    """Append names parsed from a list of PEP 508 requirement strings.

    Non-string entries are skipped: a PEP 735 dependency group may contain
    ``{include-group = "other"}`` tables that reference another group rather
    than declare a package, and those carry no requirement string of their own.
    """
    for dep in deps:
        if not isinstance(dep, str):
            continue
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

    # PEP 735 dependency groups: top-level [dependency-groups] table of
    # group-name -> list of PEP 508 requirement strings (an entry may instead be
    # a {include-group = "..."} table, handled by _add_req_strings skipping
    # non-strings). This standard is emitted by pip's --group and adopted by
    # PDM/Hatch; a copyleft dep declared only in a test/lint group here would
    # otherwise be silently skipped.
    dependency_groups = data.get("dependency-groups", {})
    if isinstance(dependency_groups, dict):
        for group_deps in dependency_groups.values():
            if isinstance(group_deps, list):
                _add_req_strings(names, group_deps)

    # PDM dev dependencies: [tool.pdm.dev-dependencies] table of
    # group-name -> list of PEP 508 requirement strings. PDM keeps dev-only
    # dependencies here (they are not expressible in PEP 621), so a copyleft
    # dev/test dependency declared only under PDM was previously missed.
    pdm_dev = data.get("tool", {}).get("pdm", {}).get("dev-dependencies", {})
    if isinstance(pdm_dev, dict):
        for group_deps in pdm_dev.values():
            if isinstance(group_deps, list):
                _add_req_strings(names, group_deps)

    # Hatch environments: [tool.hatch.envs.<name>] tables carry a project's
    # dev/test/lint dependencies as PEP 508 requirement strings under two keys:
    # `dependencies` (the env's full set) and `extra-dependencies` (added on top
    # of the project's own). Hatch is a PyPA tool and this is where many projects
    # keep their test/lint dependencies, so a copyleft dependency declared only
    # in a Hatch env was previously missed entirely. Other keys in the env table
    # (scripts, overrides, matrix, ...) are not requirement lists and are ignored
    # by the isinstance-list guard.
    hatch_envs = data.get("tool", {}).get("hatch", {}).get("envs", {})
    if isinstance(hatch_envs, dict):
        for env in hatch_envs.values():
            if not isinstance(env, dict):
                continue
            for key in ("dependencies", "extra-dependencies"):
                env_deps = env.get(key, [])
                if isinstance(env_deps, list):
                    _add_req_strings(names, env_deps)

    return _dedupe(names)


def _literal_strings(node: ast.AST, env: dict[str, ast.AST]) -> list[str]:
    """Collect string literals from a list/tuple/set node (or a name bound to one).

    ``env`` maps module-level variable names to the value node they were assigned,
    so the very common ``REQUIRES = [...]; setup(install_requires=REQUIRES)``
    pattern is resolved. Only *literal* strings are collected: a computed entry
    (a call, an f-string, a concatenation) carries no reliable package name and
    is skipped rather than guessed at. A single indirection through a name is
    resolved; deeper chains are not, to avoid unbounded/ cyclic resolution.
    """
    if isinstance(node, ast.Name):
        node = env.get(node.id)
        if node is None:
            return []
    if not isinstance(node, (ast.List, ast.Tuple, ast.Set)):
        return []
    strings: list[str] = []
    for element in node.elts:
        if isinstance(element, ast.Constant) and isinstance(element.value, str):
            strings.append(element.value)
    return strings


def _extras_strings(node: ast.AST, env: dict[str, ast.AST]) -> list[str]:
    """Collect requirement strings from an ``extras_require`` dict node.

    ``extras_require`` maps an extra name to a list of requirement strings
    (mirroring PEP 621 optional-dependencies). Each value list is resolved with
    :func:`_literal_strings`; a value that is not a literal list is skipped.
    """
    if isinstance(node, ast.Name):
        node = env.get(node.id)
        if node is None:
            return []
    if not isinstance(node, ast.Dict):
        return []
    strings: list[str] = []
    for value in node.values:
        strings.extend(_literal_strings(value, env))
    return strings


def _is_setup_call(node: ast.AST) -> bool:
    """True if ``node`` is a call to ``setup(...)`` / ``setuptools.setup(...)``."""
    if not isinstance(node, ast.Call):
        return False
    func = node.func
    if isinstance(func, ast.Name):
        return func.id == "setup"
    if isinstance(func, ast.Attribute):
        return func.attr == "setup"
    return False


def parse_setup_py(path: Path) -> list[str]:
    """Statically extract declared dependencies from a legacy ``setup.py``.

    A great many established Python projects still declare their dependencies
    only in ``setup.py`` via ``install_requires`` / ``extras_require`` /
    ``tests_require`` keyword arguments to ``setup()``. A copyleft dependency
    living there is exactly what a compliance scan must catch, yet it was
    previously invisible (only ``setup.cfg`` was read).

    The file is parsed with :mod:`ast` and **never executed** — running an
    arbitrary ``setup.py`` would be unsafe. Only literal requirement strings are
    read (including through one module-level variable assignment, the common
    ``REQUIRES = [...]`` pattern); dependencies assembled dynamically at build
    time cannot be resolved statically and are skipped rather than guessed at,
    so this can under-report but never fabricates a package name. A file that
    does not parse is skipped.
    """
    try:
        tree = ast.parse(path.read_text())
    except (SyntaxError, ValueError):
        return []

    # Map module-level variable names to their assigned value node so a
    # ``install_requires=REQUIRES`` reference can be resolved to its literal.
    env: dict[str, ast.AST] = {}
    for stmt in tree.body:
        if isinstance(stmt, ast.Assign):
            for target in stmt.targets:
                if isinstance(target, ast.Name):
                    env[target.id] = stmt.value
        elif isinstance(stmt, ast.AnnAssign) and isinstance(stmt.target, ast.Name):
            if stmt.value is not None:
                env[stmt.target.id] = stmt.value

    names: list[str] = []
    for node in ast.walk(tree):
        if not _is_setup_call(node):
            continue
        for keyword in node.keywords:
            if keyword.arg in ("install_requires", "tests_require", "setup_requires"):
                _add_req_strings(names, _literal_strings(keyword.value, env))
            elif keyword.arg == "extras_require":
                _add_req_strings(names, _extras_strings(keyword.value, env))
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

    # [options] carries the project's requirement lists. install_requires is the
    # runtime set; tests_require / setup_requires are the (deprecated but still
    # widely present in existing projects) test- and build-time sets. setuptools
    # reads all three, and each is exactly what parse_setup_py already collects
    # from the equivalent setup() keywords, so a copyleft dependency declared
    # only in a setup.cfg tests_require/setup_requires must be caught too — not
    # missed while its setup.py twin is flagged.
    for option in ("install_requires", "tests_require", "setup_requires"):
        if parser.has_option("options", option):
            _add_req_strings(names, _split_cfg_list(parser.get("options", option)))

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
    if name == "setup.py":
        return "pypi", parse_setup_py
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
