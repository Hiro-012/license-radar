"""Tests for the Pro license-key gate on the `report` command.

Covers the three required behaviors:
  * a valid key passes and produces a report,
  * an invalid or missing key is rejected with a non-zero exit code,
  * the free `scan` command still works with no key supplied at all.

The plaintext key is NOT stored in the repo (only its SHA-256 hash), so these
tests synthesize a key locally whose hash is patched in, rather than hardcoding
the real one. That validates the verification logic end-to-end without leaking
a working key.
"""

import hashlib
from pathlib import Path

import pytest

from license_radar import cli, license_key
from license_radar.license_key import verify_license_key

FIXTURES = Path(__file__).parent / "fixtures"
CLEAN = str(FIXTURES / "npm_project" / "package.json")  # has a strong-copyleft dep -> violation
PYPI = str(FIXTURES / "pypi_project")


def _patch_valid_key(monkeypatch, plaintext: str) -> None:
    """Point the module's expected hash at a locally-chosen plaintext key."""
    digest = hashlib.sha256(plaintext.encode("utf-8")).hexdigest()
    monkeypatch.setattr(license_key, "VALID_KEY_HASH", digest)


def test_verify_rejects_empty_and_none():
    assert verify_license_key(None) is False
    assert verify_license_key("") is False
    assert verify_license_key("   ") is False


def test_verify_accepts_matching_key_and_strips_whitespace(monkeypatch):
    _patch_valid_key(monkeypatch, "SECRET-KEY-123")
    assert verify_license_key("SECRET-KEY-123") is True
    # surrounding whitespace is normalized away before hashing
    assert verify_license_key("  SECRET-KEY-123\n") is True
    assert verify_license_key("wrong-key") is False


def test_report_without_key_is_rejected(monkeypatch, tmp_path, capsys):
    # ensure no env var leaks a key into the test
    monkeypatch.delenv("LICENSE_RADAR_KEY", raising=False)
    out = tmp_path / "r.html"
    rc = cli.main(["report", PYPI, "-o", str(out)])
    assert rc == cli.EXIT_LOCKED
    assert not out.exists()  # nothing written when locked
    err = capsys.readouterr().err
    assert "Pro feature" in err
    assert license_key.PURCHASE_LINK in err


def test_report_with_invalid_key_is_rejected(monkeypatch, tmp_path):
    monkeypatch.delenv("LICENSE_RADAR_KEY", raising=False)
    _patch_valid_key(monkeypatch, "the-real-key")
    out = tmp_path / "r.html"
    rc = cli.main(["report", PYPI, "-o", str(out), "--license-key", "not-the-key"])
    assert rc == cli.EXIT_LOCKED
    assert not out.exists()


def test_report_with_valid_key_writes_html(monkeypatch, tmp_path):
    monkeypatch.delenv("LICENSE_RADAR_KEY", raising=False)
    _patch_valid_key(monkeypatch, "the-real-key")
    out = tmp_path / "report.html"
    rc = cli.main(["report", PYPI, "-o", str(out), "--license-key", "the-real-key"])
    # pypi_project contains strong-copyleft deps, so a violation exit is expected
    assert rc == cli.EXIT_VIOLATION
    assert out.exists()
    body = out.read_text(encoding="utf-8")
    assert "<!DOCTYPE html>" in body
    assert "License compliance audit" in body
    assert "pyqt5" in body  # a known strong-copyleft package in the fixture
    assert "manifest file" in body  # the audit-scope block names what was covered


def test_report_creates_missing_output_parent_dirs(monkeypatch, tmp_path):
    """--output into a not-yet-existing directory should just work, not crash."""
    _patch_valid_key(monkeypatch, "the-real-key")
    monkeypatch.delenv("LICENSE_RADAR_KEY", raising=False)
    out = tmp_path / "reports" / "nested" / "audit.html"  # parents do not exist
    rc = cli.main(["report", PYPI, "-o", str(out), "--license-key", "the-real-key"])
    assert rc in (cli.EXIT_OK, cli.EXIT_VIOLATION)  # wrote successfully
    assert out.exists()
    assert "<!DOCTYPE html>" in out.read_text(encoding="utf-8")


def test_report_write_failure_exits_cleanly(monkeypatch, tmp_path, capsys):
    """An unwritable --output yields a clean error + non-zero exit, not a traceback."""
    _patch_valid_key(monkeypatch, "the-real-key")
    monkeypatch.delenv("LICENSE_RADAR_KEY", raising=False)
    # A path whose parent is an existing *file* cannot be created or written.
    blocker = tmp_path / "blocker"
    blocker.write_text("not a directory", encoding="utf-8")
    out = blocker / "audit.html"
    rc = cli.main(["report", PYPI, "-o", str(out), "--license-key", "the-real-key"])
    assert rc == cli.EXIT_IO_ERROR
    err = capsys.readouterr().err
    assert "could not write report" in err
    assert "Traceback" not in err  # failure is reported, not dumped


def test_report_reads_key_from_env(monkeypatch, tmp_path):
    _patch_valid_key(monkeypatch, "env-key")
    monkeypatch.setenv("LICENSE_RADAR_KEY", "env-key")
    out = tmp_path / "report.html"
    rc = cli.main(["report", PYPI, "-o", str(out)])
    assert rc in (cli.EXIT_OK, cli.EXIT_VIOLATION)  # unlocked (not EXIT_LOCKED)
    assert out.exists()


def test_free_scan_still_works_with_no_key(monkeypatch, capsys):
    """The free path must not require or reference a license key at all."""
    monkeypatch.delenv("LICENSE_RADAR_KEY", raising=False)
    rc = cli.main(["scan", PYPI])
    # scan exits 1 here only because the fixture has real violations; the point
    # is that it runs and produces output without any key.
    assert rc in (cli.EXIT_OK, cli.EXIT_VIOLATION)
    out = capsys.readouterr().out
    assert "license-radar" not in out.lower() or "Pro feature" not in out
    assert "OK" in out or "VIOLATIONS FOUND" in out
