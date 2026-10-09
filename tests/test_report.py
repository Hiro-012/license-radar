"""Tests for the Pro HTML report renderer, focused on the audit-scope block.

These are deterministic, offline unit tests: ``render_html_report`` takes a
caller-supplied timestamp and manifest list, so no clock or filesystem walk is
involved. The gate/CLI wiring is covered separately in ``test_license_gate``.
"""

from license_radar.report import render_html_report
from license_radar.scanner import Finding

POLICY = {"fail_at_or_above": "strong-copyleft", "treat_unknown_as_violation": True}


def _findings():
    return [
        Finding("pypi", "requests", "Apache-2.0", "permissive"),
        Finding("pypi", "pyqt5", "GPL-3.0-only", "strong-copyleft"),
    ]


def test_report_lists_audited_manifests_as_scope():
    manifests = ["requirements.txt", "services/api/requirements.txt"]
    html = render_html_report(
        _findings(), POLICY, generated_at="2026-08-02T00:00:00", manifests=manifests
    )
    # scope count and each audited file are stated explicitly
    assert "2 manifest files audited" in html
    assert "<li>requirements.txt</li>" in html
    assert "<li>services/api/requirements.txt</li>" in html


def test_report_scope_is_singular_for_one_manifest():
    html = render_html_report(
        _findings(), POLICY, generated_at="t", manifests=["setup.cfg"]
    )
    assert "1 manifest file audited" in html
    assert "manifest files audited" not in html  # singular noun, no trailing 's'


def test_report_omits_scope_block_when_manifests_absent():
    # Backward compatible: no manifests -> no scope section, still valid HTML.
    html = render_html_report(_findings(), POLICY, generated_at="t")
    assert "manifest file" not in html
    assert 'class="scope"' not in html
    assert "<!DOCTYPE html>" in html


def test_report_escapes_manifest_paths():
    html = render_html_report(
        _findings(), POLICY, generated_at="t", manifests=["a&b/<x>.txt"]
    )
    assert "a&amp;b/&lt;x&gt;.txt" in html
    assert "<x>.txt" not in html  # raw angle brackets must not leak through
