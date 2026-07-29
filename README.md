# license-radar

[![PyPI version](https://img.shields.io/pypi/v/license-radar.svg)](https://pypi.org/project/license-radar/)
[![Python versions](https://img.shields.io/pypi/pyversions/license-radar.svg)](https://pypi.org/project/license-radar/)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

Scan a project's dependency manifests (`requirements.txt`, `pyproject.toml`,
`setup.cfg`, `Pipfile`, `package.json`) for license compliance risk before a
GPL/AGPL dependency turns into a legal problem for a closed-source product.

## Why

Pulling in a GPL- or AGPL-licensed dependency can obligate a company to open
its own source, or expose it to a lawsuit — and it usually happens by
accident, several dependency layers deep. Existing SCA/security scanners
focus on vulnerabilities; license risk is often an afterthought bolted onto
an expensive enterprise product. This is a small, focused tool that does
just the license check, fast, in CI.

## Install

```bash
pip install license-radar
```

## Usage

```bash
license-radar scan .                 # scan a directory tree (recurses into subprojects)
license-radar scan requirements.txt   # scan a single manifest
license-radar scan . --online         # also query PyPI/npm for packages not in the local DB
license-radar scan . --json           # machine-readable output for CI
license-radar scan . --policy policy.json
```

Directory scans recurse into subdirectories, so monorepos with manifests in
nested subprojects (e.g. `services/api/requirements.txt`,
`frontend/package.json`) are covered in a single run. Vendored and environment
directories (`node_modules`, `.venv`, `vendor`, `dist`, VCS/cache dirs, …) are
skipped so the scan reflects what the project itself declares, not the
manifests bundled inside its dependencies.

Within each manifest, every section that declares the project's own
dependencies is scanned — not just the primary one. For `pyproject.toml` that
includes PEP 621 `[project.optional-dependencies]` extras and Poetry
`[tool.poetry.group.*.dependencies]` groups; for legacy `setup.cfg` it includes
`[options] install_requires` and `[options.extras_require]`; for Pipenv
`Pipfile` it includes `[packages]` and `[dev-packages]`; for `package.json`
it includes `optionalDependencies` and `peerDependencies`. A copyleft
dependency hidden in a `test`/`docs` extra or an optional group is exactly the
kind of accidental exposure this tool exists to catch.

Requirements files that pull in other files with pip's `-r other.txt` /
`--requirement other.txt` directive are followed (resolved relative to the
including file, with cycle guarding), so a dependency declared only in an
included file — e.g. a thin `requirements.txt` that does `-r prod.txt` — is
scanned too. `-c`/`--constraint` files only pin versions of already-required
packages, so they are not followed.

Exit code is `1` if any dependency violates the policy (useful as a CI gate),
`0` otherwise.

### pre-commit

This repo is a [pre-commit](https://pre-commit.com) hook source. Add to a
project's `.pre-commit-config.yaml`:

```yaml
repos:
  - repo: https://github.com/Hiro-012/claude-
    rev: <commit SHA of a published license-radar version>
    hooks:
      - id: license-radar
```

(This repo doesn't tag releases yet — pin a commit SHA from the history of
`pyproject.toml` version bumps until versioned tags are published.)

The hook runs on any commit that touches `requirements*.txt`, `pyproject.toml`,
`setup.cfg`, `Pipfile`, or `package.json`, and blocks the commit if a new
dependency violates policy.

### Policy

By default, any `strong-copyleft` (GPL/AGPL/SSPL) or `unknown` license is a
violation. Override with a JSON file:

```json
{
  "fail_at_or_above": "weak-copyleft",
  "treat_unknown_as_violation": false
}
```

## How it classifies

Licenses are normalized to an SPDX id and bucketed into four tiers:
`permissive` < `weak-copyleft` < `strong-copyleft` < `unknown`. See
`license_radar/classify.py` for the exact lists.

## Limitations

The offline database (`license_radar/license_db.py`) is a hand-curated table
of ~150 common PyPI/npm packages (each entry verified against the live
registry JSON API), not a registry mirror — use `--online` for full coverage
against live PyPI/npm metadata (adds a network dependency and is not covered
by the deterministic test suite).

## License

MIT

## Support

`license-radar` is built and maintained independently under the **HiroCheck**
name. It's free under the MIT license, its default scan runs entirely on your
machine, it sends no telemetry, and no paid tier gates the core check.

If it caught a license problem for you — or you'd just like to see the offline
database and manifest coverage keep growing — a one-off contribution funds the
time that goes into it:

**→ https://buy.stripe.com/bJeeVe2te0U16Ln1yudMI00**

Not in a position to chip in? Starring the repo, or opening an issue when the
database gets a package's license wrong, helps just as much and costs nothing.
