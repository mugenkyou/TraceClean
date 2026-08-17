"""Self-contained HTML Report Generator for TraceClean Phase 2.

HTML-escapes all attacker-controlled finding content to prevent XSS.
"""

from __future__ import annotations

import html
import json
from typing import Any

from provenance.schema import ProvenanceScanResult


def generate_html_report(scan_result: ProvenanceScanResult) -> str:
    """Generate self-contained offline HTML forensic audit report."""
    res_dict = scan_result.to_dict()
    safe_filename = html.escape(scan_result.original_filename)
    safe_kind = html.escape(scan_result.kind)
    status = html.escape(scan_result.verification_status)
    status_reason = html.escape(scan_result.status_reason)

    score_val = scan_result.score.score
    score_display = f"{score_val:.1f}" if score_val is not None else "N/A (Inconclusive)"
    score_derivation = html.escape(scan_result.score.derivation)

    # Findings rows
    findings_rows = []
    for f in scan_result.findings:
        safe_signal = html.escape(f.signal)
        safe_cat = html.escape(f.category)
        safe_conf = html.escape(f.confidence)
        safe_sev = html.escape(f.severity)
        safe_loc = html.escape(f.location)
        safe_ev = html.escape(json.dumps(f.evidence, ensure_ascii=False))

        findings_rows.append(
            f"""
            <tr>
              <td><code>{safe_signal}</code></td>
              <td><span class="badge cat-{safe_cat}">{safe_cat}</span></td>
              <td><span class="badge sev-{safe_sev}">{safe_sev}</span></td>
              <td>{safe_conf}</td>
              <td>{safe_loc}</td>
              <td><pre class="evidence-box">{safe_ev}</pre></td>
            </tr>
            """
        )

    table_body = "".join(findings_rows) if findings_rows else "<tr><td colspan='6'>No provenance findings detected.</td></tr>"

    missing_html = ""
    if scan_result.missing_tools:
        safe_tools = html.escape(", ".join(scan_result.missing_tools))
        missing_html = f"""
        <div class="alert warning">
          <strong>Degraded Capabilities:</strong> Missing server tools (<code>{safe_tools}</code>) limited deep inspection.
        </div>
        """

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>TraceClean Forensic Audit Report &mdash; {safe_filename}</title>
  <style>
    body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #07090e; color: #f8fafc; margin: 0; padding: 2rem; line-height: 1.5; }}
    .card {{ background: #0f1420; border: 1px solid rgba(255,255,255,0.1); border-radius: 12px; padding: 2rem; max-width: 960px; margin: 0 auto 2rem; box-shadow: 0 10px 30px rgba(0,0,0,0.5); }}
    h1, h2, h3 {{ font-family: sans-serif; color: #fff; margin-top: 0; }}
    .grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 1rem; margin-bottom: 2rem; }}
    .metric {{ background: rgba(255,255,255,0.03); padding: 1rem; border-radius: 8px; border: 1px solid rgba(255,255,255,0.05); }}
    .metric-title {{ font-size: 0.75rem; color: #94a3b8; text-transform: uppercase; }}
    .metric-val {{ font-size: 1.5rem; font-weight: 700; color: #00f2fe; margin-top: 0.25rem; }}
    .alert {{ padding: 1rem; border-radius: 8px; margin-bottom: 1.5rem; }}
    .alert.warning {{ background: rgba(245, 158, 11, 0.15); border: 1px solid #f59e0b; color: #f59e0b; }}
    table {{ width: 100%; border-collapse: collapse; margin-top: 1rem; font-size: 0.9rem; }}
    th, td {{ text-align: left; padding: 0.75rem; border-bottom: 1px solid rgba(255,255,255,0.08); }}
    th {{ background: rgba(255,255,255,0.03); color: #94a3b8; font-weight: 600; }}
    .badge {{ font-size: 0.75rem; font-weight: 600; padding: 0.2rem 0.5rem; border-radius: 4px; text-transform: uppercase; }}
    .sev-critical {{ background: rgba(239, 68, 68, 0.2); color: #ef4444; }}
    .sev-high {{ background: rgba(245, 158, 11, 0.2); color: #f59e0b; }}
    .sev-medium {{ background: rgba(99, 102, 241, 0.2); color: #6366f1; }}
    .sev-low {{ background: rgba(16, 185, 129, 0.2); color: #10b981; }}
    .evidence-box {{ font-family: monospace; font-size: 0.75rem; color: #a5f3fc; white-space: pre-wrap; margin: 0; max-height: 100px; overflow-y: auto; }}
    .footer {{ font-size: 0.8rem; color: #64748b; margin-top: 2rem; border-top: 1px solid rgba(255,255,255,0.1); padding-top: 1rem; }}
  </style>
</head>
<body>
  <div class="card">
    <h1>TraceClean Forensic Audit Report</h1>
    <p>File: <strong>{safe_filename}</strong> &bull; Kind: <strong>{safe_kind}</strong> &bull; Size: <strong>{(scan_result.size / 1024):.1f} KB</strong></p>

    {missing_html}

    <div class="grid">
      <div class="metric">
        <div class="metric-title">Exposure Score</div>
        <div class="metric-val">{score_display}</div>
      </div>
      <div class="metric">
        <div class="metric-title">Verification Status</div>
        <div class="metric-val" style="font-size: 1.1rem; color: #fff;">{status}</div>
      </div>
      <div class="metric">
        <div class="metric-title">Findings Count</div>
        <div class="metric-val">{len(scan_result.findings)}</div>
      </div>
    </div>

    <div style="background: rgba(0,0,0,0.3); padding: 1rem; border-radius: 8px; margin-bottom: 2rem;">
      <strong>Score Derivation:</strong> {score_derivation}
    </div>

    <h2>Normalized Provenance Findings</h2>
    <table>
      <thead>
        <tr>
          <th>Signal</th>
          <th>Category</th>
          <th>Severity</th>
          <th>Confidence</th>
          <th>Location</th>
          <th>Evidence</th>
        </tr>
      </thead>
      <tbody>
        {table_body}
      </tbody>
    </table>

    <div class="footer">
      <strong>Disclaimer:</strong> The Exposure Score measures physical metadata signals and steganographic carriers only. It is not an AI-generated content probability. Generated by TraceClean Engine v1.0.
    </div>
  </div>
</body>
</html>
"""
