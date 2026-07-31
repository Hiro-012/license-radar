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
includes PEP 621 `[project.optional-dependencies]` extras, Poetry
`[tool.poetry.group.*.dependencies]` groups, and the legacy Poetry (< 1.2)
`[tool.poetry.dev-dependencies]` table; for legacy `setup.cfg` it includes
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
of ~235 common PyPI/npm packages (each entry verified against the live
registry JSON API), not a registry mirror — use `--online` for full coverage
against live PyPI/npm metadata (adds a network dependency and is not covered
by the deterministic test suite). Compound SPDX license expressions that
registries declare — `A OR B` (the licensee may choose, so the *least*
restrictive operand governs) and `A AND B` (both apply, so the *most*
restrictive governs) — are resolved to a single tier by operator semantics
rather than reported as `unknown`. For example `pycurl`'s
`LGPL-2.1-only OR MIT` resolves to `permissive` (MIT is a valid choice) and
`pyside6`'s `LGPL-3.0-only OR GPL-2.0-only OR GPL-3.0-only` to `weak-copyleft`
(LGPL is the least restrictive option); any operand the classifier cannot
resolve leaves the whole expression `unknown` rather than guessed.

Because the offline table is keyed by package name only, a package whose
license changed across its version history cannot be pinned to a single
correct value. Such packages are deliberately left out of the table and
reported as `unknown` (flagged for review) rather than guessed — for example
`chardet`, which is LGPL-2.1-or-later up to 5.2.0 but relicensed to 0BSD in
its 6.x/7.x line. Use `--online` with a pinned version, or check the specific
version you depend on, when a dependency is reported this way.

To keep the offline table honest as upstream licenses change, every real entry
is reconciled against the live PyPI/npm registries by `scripts/audit_db.py`,
which compares each package's stored risk tier with the registry's current
declared license and reports any drift. It runs on a schedule and on any change
to the database in CI (`.github/workflows/audit-license-db.yml`); the `chardet`
relicensing above is the kind of drift it exists to catch. The classifier
recognizes registries' free-text and compound license strings where they are
tier-unambiguous (`Apache License 2.0`, `3-Clause BSD License`, `LGPL-2.1`,
`CC0-1.0`, `MIT-CMU`, `Python Software Foundation License`, and `AND`/`OR`
expressions). Some trove classifiers name a license *family* whose exact SPDX
id is unrecoverable (a bare `BSD License` does not say 2- vs 3-clause) but whose
compliance tier is certain; because the audit compares tiers, those are still
drift-checked rather than punted. Entries the registry leaves genuinely
tier-ambiguous or unlabeled are reported as `UNVERIFIABLE` and left for human
review rather than guessed. A recent live run reconciled 232 entries as
231 OK / 0 drift / 1 unverifiable.

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
