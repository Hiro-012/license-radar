# license-radar

Scan a project's dependency manifests (`requirements.txt`, `pyproject.toml`,
`package.json`) for license compliance risk before a GPL/AGPL dependency
turns into a legal problem for a closed-source product.

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
license-radar scan .                 # scan a directory (auto-detects manifests)
license-radar scan requirements.txt   # scan a single manifest
license-radar scan . --online         # also query PyPI/npm for packages not in the local DB
license-radar scan . --json           # machine-readable output for CI
license-radar scan . --policy policy.json
```

Exit code is `1` if any dependency violates the policy (useful as a CI gate),
`0` otherwise.

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

The offline database (`license_radar/license_db.py`) is a small, hand-curated
table of common packages, not a registry mirror — use `--online` for full
coverage against live PyPI/npm metadata (adds a network dependency and is
not covered by the deterministic test suite).

## License

MIT
