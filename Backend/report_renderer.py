#!/usr/bin/env python3
"""
SASTify HTML Report Renderer

Loads the extracted report template (Backend/templates/report_template.html)
and populates $variable placeholders using Python's string.Template.

Falls back to a minimal inline template when the file cannot be found.
"""

import html as _html
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from string import Template
from typing import Dict, List, Optional

# ── Severity ordering (matches cli.py) ─────────────────────────────
SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]

SUPPORTED_LANGUAGES = {
    ".py": "python",
    ".js": "javascript",
    ".jsx": "javascript",
    ".ts": "typescript",
    ".tsx": "typescript",
    ".java": "java",
    ".kt": "kotlin",
    ".kts": "kotlin",
    ".swift": "swift",
    ".dart": "dart",
    ".php": "php",
    ".vue": "vue",
}


def _html_escape(text) -> str:
    """Escape text for safe HTML rendering."""
    if not isinstance(text, str):
        text = str(text)
    return _html.escape(text, quote=True)


def _severity_index(severity_str: str) -> int:
    """Get severity sort index; defaults to medium (2) for unknowns."""
    try:
        return SEVERITY_ORDER.index(severity_str.lower())
    except (ValueError, AttributeError):
        return 2


def _compute_risk_grade(severity_counts: Dict[str, int]) -> str:
    """Compute a letter grade from severity counts."""
    score = (
        severity_counts.get("critical", 0) * 10
        + severity_counts.get("high", 0) * 7
        + severity_counts.get("medium", 0) * 4
        + severity_counts.get("low", 0) * 1
    )
    if score == 0:
        return "A"
    if score < 20:
        return "B"
    if score < 50:
        return "C"
    if score < 100:
        return "D"
    return "F"


# ── Vulnerability card renderer ────────────────────────────────────

def _render_vulnerability_cards(vulnerabilities: List[Dict]) -> str:
    """Pre-render the HTML for each vulnerability card.

    Returns a single string of card <div>s ready to drop into the template.
    """
    if not vulnerabilities:
        return ""

    sorted_vulns = sorted(
        vulnerabilities,
        key=lambda v: _severity_index(v.get("severity", "medium")),
    )

    cards: list[str] = []
    for i, vuln in enumerate(sorted_vulns):
        sev = vuln.get("severity", "Medium").lower()
        vuln_type = vuln.get("type", "Unknown")
        file_path = vuln.get("file", "unknown")
        line_num = vuln.get("line", "?")
        snippet = _html_escape(vuln.get("snippet", ""))
        desc = _html_escape(vuln.get("description", ""))
        is_ai = vuln.get("ai_analyzed", False)
        is_fp = vuln.get("ai_is_false_positive", False)

        ext = os.path.splitext(file_path)[1].lower()
        lang = SUPPORTED_LANGUAGES.get(ext, "text")

        card_class = f"vuln-card {sev}"
        if is_fp:
            card_class += " false-positive"

        # Badges
        badges = f'<span class="badge {sev}">{sev}</span>'
        if is_ai:
            if is_fp:
                badges += ' <span class="badge fp">🤖 Likely False Positive</span>'
            else:
                badges += ' <span class="badge ai">🤖 AI Verified</span>'

        # Code block
        code_html = ""
        if snippet:
            code_html = f'''
                <div class="code-block">
                    <div class="code-header">
                        <span class="code-lang">{lang}</span>
                        <button class="copy-btn" onclick="copyCode(this)">📋 Copy</button>
                    </div>
                    <div class="code-content">{snippet[:500] if snippet else "No code snippet available"}</div>
                </div>'''

        # AI analysis section
        ai_html = ""
        if is_ai:
            ai_explanation = _html_escape(
                vuln.get("ai_detailed_explanation", vuln.get("ai_explanation", ""))
            )
            ai_fix = _html_escape(vuln.get("ai_fix_suggestion", ""))
            ai_confidence = vuln.get("ai_confidence", 0.5)
            pct = int(ai_confidence * 100)

            ai_html = f'''
                <div class="ai-analysis">
                    <div class="ai-header">AI Security Analysis</div>
                    <div class="confidence-row">
                        <span class="confidence-text">Confidence</span>
                        <div class="confidence-bar">
                            <div class="confidence-fill" style="width: {pct}%"></div>
                        </div>
                        <span class="confidence-text">{pct}%</span>
                    </div>'''

            if is_fp:
                fp_reason = _html_escape(vuln.get("ai_false_positive_reason", ""))
                if fp_reason:
                    ai_html += f'''
                    <div class="info-box success">
                        <div class="info-box-header">✅ Why This Is Likely a False Positive</div>
                        <div class="info-box-content">{fp_reason}</div>
                    </div>'''

            if ai_explanation and ai_explanation not in (
                "No explanation provided",
                "No detailed explanation provided",
            ):
                ai_html += f'''
                    <div class="info-box danger">
                        <div class="info-box-header">⚠️ Why This Is Dangerous</div>
                        <div class="info-box-content"><p>{ai_explanation}</p></div>
                    </div>'''

            if ai_fix and ai_fix != "No fix suggested" and not is_fp:
                ai_html += f'''
                    <div style="margin: 1.5rem 0;">
                        <h4 style="color: var(--success); margin-bottom: 1rem;">🔧 Secure Code Fix</h4>
                        <div class="code-block">
                            <div class="code-header">
                                <span class="code-lang">{lang}</span>
                                <button class="copy-btn" onclick="copyCode(this)">📋 Copy Fix</button>
                            </div>
                            <div class="code-content" style="color: #4ade80;">{ai_fix}</div>
                        </div>
                    </div>'''

            # Remediation steps
            remediation_steps = vuln.get("ai_remediation_steps", [])
            if remediation_steps:
                ai_html += '''
                    <div style="margin: 1.5rem 0;">
                        <h4 style="color: var(--text-primary); margin-bottom: 1rem;">📋 Remediation Steps</h4>
                        <ol class="remediation-steps">'''
                for step in remediation_steps[:5]:
                    if isinstance(step, str):
                        ai_html += f"\n                            <li><span>{_html_escape(step)}</span></li>"
                ai_html += """
                        </ol>
                    </div>"""

            # Security references
            security_refs = vuln.get("ai_security_references", [])
            if security_refs:
                ai_html += '''
                    <div style="margin-top: 1.5rem;">
                        <h4 style="color: var(--text-muted); font-size: 0.9rem; margin-bottom: 0.5rem;">Security References</h4>
                        <div class="security-refs">'''
                for ref in security_refs[:5]:
                    if isinstance(ref, str):
                        ai_html += f'\n                            <span class="ref-tag">{_html_escape(ref)}</span>'
                ai_html += """
                        </div>
                    </div>"""

            ai_html += "\n                </div>"

        card = f'''        <div class="{card_class}" style="animation-delay: {i * 0.05}s">
            <div class="vuln-header">
                <div class="vuln-title">
                    <span class="vuln-type">{_html_escape(vuln_type.replace("_", " ").title())}</span>
                    <span class="vuln-location">📁 {_html_escape(os.path.basename(file_path))} : Line {line_num}</span>
                </div>
                <div class="badges">{badges}</div>
            </div>
            <div class="vuln-body">
                <p style="color: var(--text-secondary); margin-bottom: 1rem;">{desc}</p>
                {code_html}
                {ai_html}
            </div>
        </div>
'''
        cards.append(card)

    return "\n".join(cards)


# ── Minimal fallback template ──────────────────────────────────────

_FALLBACK_TEMPLATE = """<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8"><title>$title</title>
<style>body{font-family:sans-serif;max-width:900px;margin:2rem auto;padding:0 1rem;}
.stat{display:inline-block;margin:0.5rem;padding:1rem;border:1px solid #ddd;border-radius:8px;text-align:center;}
.vuln{border-left:4px solid #999;padding:1rem;margin:1rem 0;background:#f9f9f9;border-radius:4px;}
</style></head><body>
<h1>SASTify Security Report</h1>
<p>Generated: $scan_date</p>
<div><div class="stat"><strong>$files_scanned</strong><br>Files</div>
<div class="stat"><strong>$total_vulnerabilities</strong><br>Issues</div>
<div class="stat"><strong>$critical_count</strong><br>Critical</div>
<div class="stat"><strong>$high_count</strong><br>High</div>
<div class="stat"><strong>$medium_count</strong><br>Medium</div>
<div class="stat"><strong>$low_count</strong><br>Low</div></div>
<h2>Findings</h2>
$vulnerability_cards
<footer><p>SASTify v$version</p></footer>
</body></html>"""


# ── Public API ─────────────────────────────────────────────────────

def render_html_report(
    results: dict,
    template_path: Optional[str] = None,
) -> str:
    """Load the HTML template, populate variables, and return the report.

    Parameters
    ----------
    results : dict
        A dict with at least:
          - ``vulnerabilities`` : List[Dict]  – scan findings
          - ``files_scanned``   : int         – number of files
        Optional keys:
          - ``scan_duration`` : str (e.g. "2.3s")
          - ``version``       : str (e.g. "2.0.0")
          - ``title``         : str

    template_path : str, optional
        Path to the template HTML file.  Defaults to
        ``Backend/templates/report_template.html`` relative to this file.

    Returns
    -------
    str
        Complete HTML string ready to be written to a file.
    """
    vulnerabilities: List[Dict] = results.get("vulnerabilities", [])
    files_scanned: int = results.get("files_scanned", 0)

    # ── Severity counts ────────────────────────────────────────────
    severity_counts: Dict[str, int] = {s: 0 for s in SEVERITY_ORDER}
    for v in vulnerabilities:
        sev = v.get("severity", "medium").lower()
        if sev in severity_counts:
            severity_counts[sev] += 1

    # ── AI stats ───────────────────────────────────────────────────
    ai_analyzed = sum(1 for v in vulnerabilities if v.get("ai_analyzed"))
    ai_fp = sum(1 for v in vulnerabilities if v.get("ai_is_false_positive"))
    ai_confirmed = ai_analyzed - ai_fp

    # ── Risk grade ─────────────────────────────────────────────────
    risk_grade = _compute_risk_grade(severity_counts)

    # ── Template variables ─────────────────────────────────────────
    variables = {
        "title": results.get("title", "SASTify Security Report"),
        "scan_date": datetime.now().strftime("%B %d, %Y at %H:%M:%S"),
        "total_vulnerabilities": str(len(vulnerabilities)),
        "critical_count": str(severity_counts["critical"]),
        "high_count": str(severity_counts["high"]),
        "medium_count": str(severity_counts["medium"]),
        "low_count": str(severity_counts["low"]),
        "ai_analyzed_count": str(ai_analyzed),
        "ai_confirmed_count": str(ai_confirmed),
        "risk_grade": risk_grade.lower(),
        "risk_grade_letter": risk_grade,
        "files_scanned": str(files_scanned),
        "scan_duration": results.get("scan_duration", "N/A"),
        "version": results.get("version", "2.0.0"),
        "vulnerability_cards": _render_vulnerability_cards(vulnerabilities),
        "severity_chart_data": json.dumps(severity_counts),
    }

    # ── Load template ──────────────────────────────────────────────
    if template_path is None:
        template_path = str(
            Path(__file__).parent / "templates" / "report_template.html"
        )

    try:
        with open(template_path, "r", encoding="utf-8") as f:
            template_str = f.read()
    except FileNotFoundError:
        template_str = _FALLBACK_TEMPLATE

    tmpl = Template(template_str)
    return tmpl.safe_substitute(variables)
