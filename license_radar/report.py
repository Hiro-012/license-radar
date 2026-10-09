"""Generate a standalone HTML license-compliance audit report.

This is the Pro (paid) feature. It turns a scan's findings into a
self-contained HTML document suitable for handing to legal/compliance review:
a summary of counts per risk tier, the policy that was applied, and a full
per-dependency table with violations highlighted. The report is a single file
with inline CSS and no external assets, so it can be archived or emailed as-is.

The free ``scan`` command is unaffected; only report generation is gated.
"""

import html
from collections import Counter

from license_radar import __version__
from license_radar.policy import violates

_TIER_LABEL = {
    "permissive": "Permissive",
    "weak-copyleft": "Weak copyleft",
    "strong-copyleft": "Strong copyleft",
    "unknown": "Unknown",
}
_TIER_ORDER = ["strong-copyleft", "unknown", "weak-copyleft", "permissive"]


def _rows(findings, policy):
    for f in findings:
        yield {
            "ecosystem": f.ecosystem,
            "package": f.package,
            "license": f.license or "UNKNOWN",
            "tier": f.tier,
            "violation": violates(f, policy),
        }


def _scope_html(manifests) -> str:
    """Render the 'files audited' scope block, or empty string if unknown.

    A credible compliance artifact must state what it examined. ``manifests``
    is an optional list of caller-supplied path strings (relative to the scan
    root); when omitted the block is skipped so the report stays valid.
    """
    if not manifests:
        return ""
    items = "".join(f"<li>{html.escape(str(m))}</li>" for m in manifests)
    n = len(manifests)
    noun = "manifest file" if n == 1 else "manifest files"
    return (
        f'<p class="policy">Scope: {n} {noun} audited.</p>'
        f'<ul class="scope">{items}</ul>'
    )


def render_html_report(
    findings, policy, *, generated_at: str | None = None, manifests=None
) -> str:
    """Render an HTML audit report string from scan findings and a policy.

    ``generated_at`` is an optional caller-supplied timestamp string. It is not
    computed here so the output stays deterministic (and testable); the CLI
    passes the current time. ``manifests`` is an optional list of the manifest
    paths the scan covered, rendered as an explicit audit-scope section.
    """
    rows = list(_rows(findings, policy))
    tier_counts = Counter(r["tier"] for r in rows)
    violation_count = sum(1 for r in rows if r["violation"])
    threshold = policy.get("fail_at_or_above", "strong-copyleft")

    summary_cells = "".join(
        f'<div class="stat"><span class="num">{tier_counts.get(t, 0)}</span>'
        f'<span class="lbl">{html.escape(_TIER_LABEL[t])}</span></div>'
        for t in _TIER_ORDER
    )

    body_rows = []
    for r in rows:
        cls = ' class="violation"' if r["violation"] else ""
        flag = "VIOLATION" if r["violation"] else "ok"
        body_rows.append(
            f"<tr{cls}>"
            f"<td>{html.escape(r['ecosystem'])}</td>"
            f"<td>{html.escape(r['package'])}</td>"
            f"<td>{html.escape(r['license'])}</td>"
            f"<td>{html.escape(_TIER_LABEL.get(r['tier'], r['tier']))}</td>"
            f"<td>{flag}</td>"
            "</tr>"
        )
    table_body = "\n".join(body_rows) or (
        '<tr><td colspan="5">No dependencies found.</td></tr>'
    )

    verdict = (
        f"{violation_count} policy violation(s) found"
        if violation_count
        else "No policy violations"
    )
    verdict_cls = "fail" if violation_count else "pass"
    ts = html.escape(generated_at) if generated_at else "unspecified"

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>license-radar audit report</title>
<style>
:root {{ color-scheme: light dark; }}
body {{ font-family: -apple-system, Segoe UI, Roboto, sans-serif; margin: 2rem auto;
  max-width: 52rem; padding: 0 1rem; line-height: 1.5; }}
h1 {{ margin-bottom: 0.2rem; }}
.meta {{ color: #666; font-size: 0.85rem; margin-bottom: 1.5rem; }}
.verdict {{ font-weight: 700; padding: 0.6rem 0.9rem; border-radius: 6px; margin: 1rem 0; }}
.verdict.pass {{ background: #e6f4ea; color: #1e7e34; }}
.verdict.fail {{ background: #fdecea; color: #c0392b; }}
.stats {{ display: flex; gap: 0.75rem; flex-wrap: wrap; margin: 1rem 0 1.5rem; }}
.stat {{ display: flex; flex-direction: column; align-items: center; border: 1px solid #ccc;
  border-radius: 6px; padding: 0.5rem 1rem; min-width: 5rem; }}
.stat .num {{ font-size: 1.5rem; font-weight: 700; }}
.stat .lbl {{ font-size: 0.75rem; color: #666; }}
table {{ border-collapse: collapse; width: 100%; font-size: 0.9rem; }}
th, td {{ text-align: left; padding: 0.4rem 0.6rem; border-bottom: 1px solid #ddd; }}
th {{ border-bottom: 2px solid #999; }}
tr.violation {{ background: #fdecea; }}
tr.violation td {{ font-weight: 600; }}
.policy {{ font-size: 0.85rem; color: #444; margin: 1rem 0 0.25rem; }}
ul.scope {{ font-size: 0.85rem; color: #444; margin: 0 0 1rem; padding-left: 1.5rem; }}
footer {{ margin-top: 2rem; color: #888; font-size: 0.8rem; }}
</style>
</head>
<body>
<h1>License compliance audit</h1>
<p class="meta">Generated by license-radar {html.escape(__version__)} &middot; {ts}</p>
<div class="verdict {verdict_cls}">{html.escape(verdict)}</div>
<div class="stats">{summary_cells}</div>
<p class="policy">Policy: fail at or above <strong>{html.escape(threshold)}</strong>;
unknown licenses treated as
{"violations" if policy.get("treat_unknown_as_violation", True) else "acceptable"}.</p>
{_scope_html(manifests)}
<table>
<thead><tr><th>Ecosystem</th><th>Package</th><th>License</th><th>Tier</th><th>Status</th></tr></thead>
<tbody>
{table_body}
</tbody>
</table>
<footer>This report reflects a static analysis of declared dependency manifests.
It is an aid to license review, not legal advice.</footer>
</body>
</html>
"""
