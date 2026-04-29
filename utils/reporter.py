"""Report generation: HTML, PDF, and JSON.

The HTML report is a self-contained dark-themed document with an
executive summary, severity breakdown, and a per-finding table. The PDF
mirrors the same content using fpdf2 (so no external binaries like
wkhtmltopdf are required). JSON output is the raw findings dump for
machine consumption.
"""
from __future__ import annotations

import html
import json
import os
from datetime import datetime, timezone
from typing import Optional

from .findings import Finding, ScanContext, SEVERITY_LEVELS


SEVERITY_COLOR = {
    "CRITICAL": "#ff3860",
    "HIGH": "#ff6b35",
    "MEDIUM": "#ffb347",
    "LOW": "#3abff8",
    "INFO": "#9aa0a6",
}

DISCLAIMER = (
    "VulnScan Pro is intended for AUTHORIZED security testing only. "
    "Running this tool against systems you do not own or have explicit "
    "written permission to test is illegal in most jurisdictions."
)


# ---------------------------------------------------------------------------
# HTML
# ---------------------------------------------------------------------------
def _summary_cards(ctx: ScanContext) -> str:
    counts = ctx.severity_counts()
    cards = []
    for sev in SEVERITY_LEVELS:
        cards.append(
            f"""
            <div class="card" style="border-left: 6px solid {SEVERITY_COLOR[sev]};">
                <div class="card-count">{counts[sev]}</div>
                <div class="card-label">{sev}</div>
            </div>
            """
        )
    return "\n".join(cards)


def _findings_rows(ctx: ScanContext) -> str:
    if not ctx.findings:
        return (
            "<tr><td colspan='7' class='no-findings'>"
            "No findings recorded. Either the target is hardened or no "
            "modules were enabled.</td></tr>"
        )
    rows = []
    sev_order = {s: i for i, s in enumerate(SEVERITY_LEVELS)}
    sorted_findings = sorted(ctx.findings, key=lambda f: sev_order.get(f.severity, 99))
    for idx, f in enumerate(sorted_findings, start=1):
        rows.append(
            f"""
            <tr>
                <td>{idx}</td>
                <td><span class="sev" style="background:{SEVERITY_COLOR[f.severity]}">{f.severity}</span></td>
                <td>{html.escape(f.module)}</td>
                <td>{html.escape(f.name)}</td>
                <td class="url">{html.escape(f.url)}</td>
                <td>{f.cvss:.1f}</td>
                <td>
                    <details>
                        <summary>View details</summary>
                        <p><strong>Description:</strong> {html.escape(f.description)}</p>
                        <p><strong>Parameter:</strong> {html.escape(f.parameter or '-')}
                        &nbsp;|&nbsp; <strong>Method:</strong> {html.escape(f.method)}</p>
                        <p><strong>Payload:</strong> <code>{html.escape(f.payload or '-')}</code></p>
                        <p><strong>Evidence:</strong></p>
                        <pre>{html.escape(f.evidence or '-')}</pre>
                        <p><strong>Remediation:</strong> {html.escape(f.remediation or '-')}</p>
                        <p><em>Detected at {html.escape(f.timestamp)}</em></p>
                    </details>
                </td>
            </tr>
            """
        )
    return "\n".join(rows)


HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8" />
<title>VulnScan Pro Report - {target}</title>
<style>
    :root {{ color-scheme: dark; }}
    body {{
        background: #0f1115; color: #e6e6e6;
        font-family: -apple-system, "Segoe UI", Roboto, sans-serif;
        margin: 0; padding: 0;
    }}
    header {{
        padding: 32px; background: linear-gradient(135deg,#1f2937,#0f172a);
        border-bottom: 1px solid #334155;
    }}
    header h1 {{ margin: 0; font-size: 28px; letter-spacing: 0.5px; }}
    header p {{ margin: 4px 0 0; color: #9aa0a6; }}
    .container {{ padding: 24px 32px; max-width: 1200px; margin: 0 auto; }}
    .summary {{ display: grid; grid-template-columns: repeat(5, 1fr); gap: 12px; margin: 24px 0; }}
    .card {{
        background: #1a1d24; padding: 16px; border-radius: 8px;
        text-align: center;
    }}
    .card-count {{ font-size: 32px; font-weight: 700; }}
    .card-label {{ font-size: 12px; letter-spacing: 1px; color: #9aa0a6; }}
    .meta-grid {{
        display: grid; grid-template-columns: repeat(2, 1fr); gap: 8px 24px;
        background: #1a1d24; padding: 16px; border-radius: 8px;
    }}
    .meta-grid div span {{ color: #9aa0a6; margin-right: 8px; }}
    h2 {{ margin-top: 32px; border-bottom: 1px solid #334155; padding-bottom: 6px; }}
    table {{
        width: 100%; border-collapse: collapse; background: #1a1d24;
        border-radius: 8px; overflow: hidden;
    }}
    th, td {{ padding: 10px 12px; text-align: left; vertical-align: top;
              border-bottom: 1px solid #2a2f3a; font-size: 14px; }}
    th {{ background: #11141a; text-transform: uppercase; font-size: 12px;
          letter-spacing: 0.5px; color: #9aa0a6; }}
    tr:last-child td {{ border-bottom: none; }}
    .sev {{
        display: inline-block; padding: 2px 8px; border-radius: 4px;
        font-size: 11px; font-weight: 700; color: #0f1115;
    }}
    td.url {{ word-break: break-all; max-width: 260px; }}
    .no-findings {{ text-align: center; color: #9aa0a6; padding: 24px; }}
    pre {{ background: #0a0c10; padding: 8px; border-radius: 4px; overflow-x: auto; }}
    code {{ background: #0a0c10; padding: 2px 4px; border-radius: 3px; }}
    footer {{ margin: 48px 0 24px; text-align: center; color: #5a6270; font-size: 12px; }}
    .disclaimer {{
        background: #2a1a1a; border-left: 4px solid #ff3860; padding: 12px 16px;
        border-radius: 4px; margin-bottom: 24px; color: #ffd5d5;
    }}
    details summary {{ cursor: pointer; color: #58a6ff; }}
</style>
</head>
<body>
<header>
    <h1>VulnScan Pro - Vulnerability Report</h1>
    <p>Target: <strong>{target}</strong></p>
</header>
<div class="container">
    <div class="disclaimer"><strong>Disclaimer:</strong> {disclaimer}</div>

    <h2>Executive Summary</h2>
    <p>{summary_text}</p>
    <div class="summary">{cards}</div>

    <h2>Scan Metadata</h2>
    <div class="meta-grid">
        <div><span>Started:</span>{started}</div>
        <div><span>Finished:</span>{finished}</div>
        <div><span>Duration:</span>{duration}</div>
        <div><span>Total findings:</span>{total}</div>
        <div><span>Server:</span>{server}</div>
        <div><span>Technology:</span>{tech}</div>
        <div><span>WAF:</span>{waf}</div>
        <div><span>Modules run:</span>{modules}</div>
    </div>

    <h2>Findings</h2>
    <table>
        <thead>
            <tr>
                <th>#</th><th>Severity</th><th>Module</th><th>Name</th>
                <th>URL</th><th>CVSS</th><th>Details</th>
            </tr>
        </thead>
        <tbody>{rows}</tbody>
    </table>

    <footer>Generated by VulnScan Pro &middot; {generated}</footer>
</div>
</body>
</html>
"""


def _summary_text(ctx: ScanContext) -> str:
    counts = ctx.severity_counts()
    total = sum(counts.values())
    if total == 0:
        return (
            "No vulnerabilities were identified during this scan. Continue "
            "to monitor the application and re-run periodically."
        )
    parts = [f"{counts[s]} {s.lower()}" for s in SEVERITY_LEVELS if counts[s]]
    return (
        f"The scan identified <strong>{total}</strong> issues "
        f"({', '.join(parts)}). Review and triage the findings below; "
        "critical and high issues should be remediated as a priority."
    )


def write_html_report(ctx: ScanContext, path: str) -> str:
    metadata = ctx.metadata or {}
    started = ctx.started_at or "-"
    finished = ctx.finished_at or "-"
    try:
        s = datetime.strptime(ctx.started_at, "%Y-%m-%d %H:%M:%S UTC")
        f = datetime.strptime(ctx.finished_at, "%Y-%m-%d %H:%M:%S UTC")
        duration = f"{(f - s).total_seconds():.1f}s"
    except Exception:
        duration = "-"

    html_content = HTML_TEMPLATE.format(
        target=html.escape(ctx.target_url),
        disclaimer=html.escape(DISCLAIMER),
        summary_text=_summary_text(ctx),
        cards=_summary_cards(ctx),
        rows=_findings_rows(ctx),
        started=html.escape(started),
        finished=html.escape(finished),
        duration=html.escape(duration),
        total=str(len(ctx.findings)),
        server=html.escape(str(metadata.get("server", "Unknown"))),
        tech=html.escape(str(metadata.get("technology", "Unknown"))),
        waf=html.escape(str(metadata.get("waf", "Not detected"))),
        modules=html.escape(", ".join(metadata.get("modules", [])) or "-"),
        generated=datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
    )

    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(html_content)
    return path


# ---------------------------------------------------------------------------
# JSON
# ---------------------------------------------------------------------------
def write_json_report(ctx: ScanContext, path: str) -> str:
    payload = {
        "target": ctx.target_url,
        "started_at": ctx.started_at,
        "finished_at": ctx.finished_at,
        "metadata": ctx.metadata,
        "severity_counts": ctx.severity_counts(),
        "findings": [f.to_dict() for f in ctx.findings],
        "disclaimer": DISCLAIMER,
    }
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=2, default=str)
    return path


# ---------------------------------------------------------------------------
# PDF
# ---------------------------------------------------------------------------
def write_pdf_report(ctx: ScanContext, path: str) -> Optional[str]:
    try:
        from fpdf import FPDF
    except ImportError:
        return None

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------
    # fpdf2's core fonts only render Latin-1 characters. Any character
    # outside that range is replaced with '?' so we never crash on emoji
    # or non-ASCII content scraped from the target.
    def latin(text: str) -> str:
        if text is None:
            return ""
        return str(text).encode("latin-1", "replace").decode("latin-1")

    pdf = FPDF()
    pdf.set_auto_page_break(auto=True, margin=15)
    pdf.add_page()

    # Width available inside the page margins. Used to break long
    # tokens that would otherwise overflow the cell.
    available_width = pdf.w - pdf.l_margin - pdf.r_margin

    # Pre-wrap text manually using the actual rendered string width.
    # fpdf2's default WORD wrap mode raises "Not enough horizontal
    # space to render a single character" if a single token is wider
    # than the cell, and CHAR mode can spin forever in pathological
    # cases. Splitting long tokens into measured chunks side-steps
    # both problems.
    def soft_wrap(text: str) -> str:
        if not text:
            return ""
        # Leave ~5% safety margin to account for floating-point.
        max_w = available_width * 0.95
        out: list = []
        for line in str(text).splitlines() or [""]:
            tokens = []
            for token in line.split(" "):
                if pdf.get_string_width(latin(token)) <= max_w:
                    tokens.append(token)
                    continue
                # Break into measured chunks.
                buf = ""
                for ch in token:
                    if pdf.get_string_width(latin(buf + ch)) > max_w:
                        if buf:
                            tokens.append(buf)
                        buf = ch
                    else:
                        buf += ch
                if buf:
                    tokens.append(buf)
            out.append(" ".join(tokens))
        return "\n".join(out)

    def safe(text: str) -> str:
        return latin(soft_wrap(text))

    # fpdf2's default for multi_cell leaves the cursor at the right edge,
    # which makes the *next* multi_cell think it has zero remaining width.
    # This wrapper always resets x back to the left margin.
    def mcell(height: float, text: str, **kwargs) -> None:
        try:
            pdf.multi_cell(
                0, height, safe(text),
                new_x="LMARGIN", new_y="NEXT", **kwargs,
            )
        except TypeError:
            # Older fpdf2 without new_x/new_y kwargs.
            pdf.multi_cell(0, height, safe(text), **kwargs)
            pdf.set_x(pdf.l_margin)

    # Title block
    pdf.set_font("Helvetica", "B", 18)
    pdf.cell(0, 10, latin("VulnScan Pro - Vulnerability Report"), ln=True)
    pdf.set_font("Helvetica", "", 11)
    mcell(6, f"Target: {ctx.target_url}")
    pdf.cell(0, 6, latin(f"Started: {ctx.started_at}    Finished: {ctx.finished_at}"), ln=True)
    pdf.ln(2)

    # Disclaimer
    pdf.set_fill_color(255, 235, 235)
    pdf.set_text_color(150, 0, 0)
    pdf.set_font("Helvetica", "B", 10)
    mcell(6, f"DISCLAIMER: {DISCLAIMER}", border=1, fill=True)
    pdf.set_text_color(0, 0, 0)
    pdf.ln(2)

    # Executive summary
    counts = ctx.severity_counts()
    total = sum(counts.values())
    pdf.set_font("Helvetica", "B", 13)
    pdf.cell(0, 8, "Executive Summary", ln=True)
    pdf.set_font("Helvetica", "", 11)
    mcell(
        6,
        f"Total findings: {total}. "
        + ", ".join(f"{counts[s]} {s}" for s in SEVERITY_LEVELS),
    )
    pdf.ln(2)

    # Metadata
    metadata = ctx.metadata or {}
    pdf.set_font("Helvetica", "B", 13)
    pdf.cell(0, 8, "Scan Metadata", ln=True)
    pdf.set_font("Helvetica", "", 11)
    for label, key in [
        ("Server", "server"),
        ("Technology", "technology"),
        ("WAF", "waf"),
    ]:
        mcell(6, f"{label}: {metadata.get(key, 'Unknown')}")
    mcell(6, "Modules: " + ", ".join(metadata.get("modules", [])))
    pdf.ln(2)

    # Findings
    pdf.set_font("Helvetica", "B", 13)
    pdf.cell(0, 8, "Findings", ln=True)
    pdf.set_font("Helvetica", "", 11)
    if not ctx.findings:
        mcell(6, "No findings recorded.")
    else:
        sev_order = {s: i for i, s in enumerate(SEVERITY_LEVELS)}
        sorted_findings = sorted(ctx.findings, key=lambda f: sev_order.get(f.severity, 99))
        for idx, f in enumerate(sorted_findings, start=1):
            pdf.set_font("Helvetica", "B", 11)
            mcell(6, f"{idx}. [{f.severity}] {f.name} (CVSS {f.cvss:.1f})")
            pdf.set_font("Helvetica", "", 10)
            mcell(5, f"Module: {f.module}    Method: {f.method}    Param: {f.parameter or '-'}")
            mcell(5, f"URL: {f.url}")
            mcell(5, f"Description: {f.description}")
            if f.payload:
                mcell(5, f"Payload: {f.payload}")
            if f.evidence:
                evidence_short = f.evidence if len(f.evidence) < 600 else f.evidence[:600] + "..."
                mcell(5, f"Evidence: {evidence_short}")
            if f.remediation:
                mcell(5, f"Remediation: {f.remediation}")
            pdf.ln(2)

    os.makedirs(os.path.dirname(path), exist_ok=True)
    pdf.output(path)
    return path
