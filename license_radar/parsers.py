"""Extract dependency names from common manifest file formats."""

import json
import re
import tomllib
from pathlib import Path

_REQ_LINE_RE = re.compile(r"^\s*([A-Za-z0-9._-]+)")


def parse_requirements_txt(path: Path) -> list[str]:
    names = []
    for raw_line in path.read_text().splitlines():
        line = raw_line.split("#", 1)[0].strip()
        if not line or line.startswith(("-", "--")):
            continue
        match = _REQ_LINE_RE.match(line)
        if match:
            names.append(match.group(1))
    return names


def parse_pyproject_toml(path: Path) -> list[str]:
    data = tomllib.loads(path.read_text())
    names = []

    project_deps = data.get("project", {}).get("dependencies", [])
    for dep in project_deps:
        match = _REQ_LINE_RE.match(dep.strip())
        if match:
            names.append(match.group(1))

    poetry_deps = (
        data.get("tool", {}).get("poetry", {}).get("dependencies", {})
    )
    for name in poetry_deps:
        if name.lower() != "python":
            names.append(name)

    return names


def parse_package_json(path: Path) -> list[str]:
    data = json.loads(path.read_text())
    names = []
    for section in ("dependencies", "devDependencies"):
        names.extend(data.get(section, {}).keys())
    return names


def _matches_manifest(name: str) -> tuple[str, object] | None:
    if name == "pyproject.toml":
        return "pypi", parse_pyproject_toml
    if name == "package.json":
        return "npm", parse_package_json
    if name.startswith("requirements") and name.endswith(".txt"):
        return "pypi", parse_requirements_txt
    return None


def discover_manifests(root: Path) -> list[Path]:
    if root.is_file():
        return [root] if _matches_manifest(root.name) else []
    return sorted(p for p in root.iterdir() if p.is_file() and _matches_manifest(p.name))


def parse_manifest(path: Path) -> tuple[str, list[str]]:
    match = _matches_manifest(path.name)
    if match is None:
        raise ValueError(f"unrecognized manifest file: {path.name}")
    ecosystem, parser = match
    return ecosystem, parser(path)
