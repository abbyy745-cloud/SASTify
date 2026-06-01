#!/usr/bin/env python3
"""
SASTify FERPA Compliance Report Generator

Generates a premium, self-contained HTML compliance report for EdTech
organizations. Maps scan findings to FERPA regulatory categories and
produces a board-ready document with:

  - Executive summary with compliance score & risk level
  - Five FERPA compliance categories (PII, Transmission, Access, Storage, Logging)
  - Detailed findings with CWE references and FERPA regulation mappings
  - Prioritized remediation roadmap
"""

from datetime import datetime, timezone
from typing import Dict, List, Optional
import html as _html
import json


class FERPAReportGenerator:
    """Generate a self-contained HTML FERPA compliance report from scan results."""

    # ── FERPA compliance categories ────────────────────────────────────
    CATEGORIES = {
        "student_pii_protection": {
            "title": "Student PII Protection",
            "icon": "🛡️",
            "regulation": "§99.3 — Definition of Education Records",
            "description": "Detects exposure, leakage, or insecure handling of personally identifiable student information.",
            "keywords": [
                "hardcoded_secret", "pii_leakage", "pii_exposure",
                "Student PII", "student_data", "hardcoded_pii",
                "Student Email", "Student SSN", "Student Health",
                "Minor Student", "Student Location",
                "information_exposure", "unsafe_identifier",
            ],
        },
        "data_transmission_security": {
            "title": "Data Transmission Security",
            "icon": "🔒",
            "regulation": "§99.35 — Conditions for Disclosure",
            "description": "Identifies insecure data transmission channels that could expose student records in transit.",
            "keywords": [
                "insecure_http", "ssl_verification_disabled", "ssl_issues",
                "missing_tls", "weak_crypto", "weak_cipher",
                "http://", "Grade Passback Without SSL",
                "cleartext", "no_encryption",
            ],
        },
        "access_control": {
            "title": "Access Control & Authorization",
            "icon": "🔐",
            "regulation": "§99.31 — Prior Consent for Disclosure",
            "description": "Checks for missing authentication, broken access controls, and unprotected student-data endpoints.",
            "keywords": [
                "missing_auth", "unprotected_endpoint", "broken_access",
                "access_control", "Teacher Impersonation",
                "Cross-Student Data Access", "Bulk Student Data Export",
                "unsafe_route", "Course Admin Access",
                "Parent Access to Wrong Child", "Student Accessing Teacher",
                "Class Enrollment Bypass",
            ],
        },
        "data_storage": {
            "title": "Data Storage & Retention",
            "icon": "💾",
            "regulation": "§99.31(a)(1) — Legitimate Educational Interest",
            "description": "Flags plaintext passwords, insecure storage, and unencrypted student data at rest.",
            "keywords": [
                "plaintext_password", "insecure_storage", "weak_encryption",
                "Unencrypted Student Data", "insecure_deserialization",
                "hardcoded_secret", "hardcoded_ai_key",
                "LTI Secret in Code", "Canvas API Token",
            ],
        },
        "logging_monitoring": {
            "title": "Logging & Audit Trails",
            "icon": "📋",
            "regulation": "§99.32 — Record of Disclosures",
            "description": "Detects PII leaking into logs, missing audit trails, and excessive data in error messages.",
            "keywords": [
                "pii_in_log", "pii_leakage_log", "missing_audit",
                "Student PII in Logs", "stacktrace",
                "verbose_error", "information_exposure",
            ],
        },
    }

    # ── Severity weights for scoring ──────────────────────────────────
    SEVERITY_WEIGHTS = {
        "critical": 15,
        "high": 8,
        "medium": 3,
        "low": 1,
    }

    # ── CWE to FERPA regulation map ──────────────────────────────────
    CWE_FERPA_MAP = {
        "CWE-532": "§99.3 — PII in Log Files",
        "CWE-598": "§99.35 — PII in Query Strings",
        "CWE-312": "§99.31 — Plaintext Storage of PII",
        "CWE-615": "§99.3 — Comments Containing PII",
        "CWE-285": "§99.31 — Improper Access Control",
        "CWE-639": "§99.31 — Insecure Direct Object Reference",
        "CWE-200": "§99.3 — Information Exposure",
        "CWE-311": "§99.35 — Missing Encryption of Sensitive Data",
        "CWE-79":  "§99.3 — Cross-Site Scripting (Student Data)",
        "CWE-89":  "§99.31 — SQL Injection on Student Records",
        "CWE-306": "§99.31 — Missing Authentication",
        "CWE-434": "§99.35 — Unrestricted Upload",
        "CWE-20":  "§99.31 — Improper Input Validation",
        "CWE-521": "§99.31 — Weak Password Requirements",
        "CWE-770": "§99.31 — Allocation Without Limits",
        "CWE-1021": "§99.35 — Improper Restriction of Rendered UI",
    }

    # ──────────────────────────────────────────────────────────────────

    def __init__(self, scan_results: List[Dict], project_name: str = "Project"):
        self.scan_results = scan_results or []
        self.project_name = project_name

    # ── Public API ────────────────────────────────────────────────────

    def generate(self) -> str:
        """Return a complete self-contained HTML FERPA compliance report."""
        score = self._calculate_compliance_score()
        categories = self._categorize_findings()
        roadmap = self._generate_remediation_roadmap()

        has_critical_pii = any(
            v.get("severity", "").lower() == "critical"
            for v in categories.get("student_pii_protection", [])
        )
        pass_fail = "FAIL" if has_critical_pii else "PASS"
        risk_level = self._risk_level(score)

        severity_counts = self._count_severities()
        unique_files = {v.get("file", "unknown") for v in self.scan_results}
        scan_date = datetime.now().strftime("%B %d, %Y at %H:%M")

        return self._render_html(
            score=score,
            pass_fail=pass_fail,
            risk_level=risk_level,
            categories=categories,
            roadmap=roadmap,
            severity_counts=severity_counts,
            scan_date=scan_date,
            unique_files=len(unique_files),
        )

    # ── Internal helpers ──────────────────────────────────────────────

    def _calculate_compliance_score(self) -> int:
        score = 100
        for v in self.scan_results:
            sev = v.get("severity", "medium").lower()
            # Extra penalty if it touches Student PII
            is_pii = self._matches_category(v, "student_pii_protection")
            weight = self.SEVERITY_WEIGHTS.get(sev, 1)
            if is_pii and sev == "critical":
                weight = 15  # already critical-PII weight
            score -= weight
        return max(0, min(100, score))

    def _categorize_findings(self) -> Dict[str, List[Dict]]:
        cats: Dict[str, List[Dict]] = {k: [] for k in self.CATEGORIES}
        for v in self.scan_results:
            placed = False
            for cat_key in self.CATEGORIES:
                if self._matches_category(v, cat_key):
                    cats[cat_key].append(v)
                    placed = True
                    break
            if not placed:
                # default bucket — access control is broad enough
                cats["access_control"].append(v)
        return cats

    def _matches_category(self, vuln: Dict, cat_key: str) -> bool:
        keywords = self.CATEGORIES[cat_key]["keywords"]
        vuln_type = vuln.get("type", "")
        vuln_desc = vuln.get("description", "")
        combined = f"{vuln_type} {vuln_desc}".lower()
        return any(kw.lower() in combined for kw in keywords)

    def _map_to_ferpa_regulation(self, vuln_type: str) -> str:
        """Map a vulnerability type string to the most relevant FERPA section."""
        vt = vuln_type.lower()
        if any(k in vt for k in ("pii", "student", "email", "ssn", "health", "location")):
            return "§99.3 — Definition of Education Records"
        if any(k in vt for k in ("auth", "access", "impersonat", "bypass", "route")):
            return "§99.31 — Prior Consent for Disclosure"
        if any(k in vt for k in ("ssl", "tls", "http", "encrypt", "cipher", "transmit")):
            return "§99.35 — Conditions for Disclosure"
        if any(k in vt for k in ("log", "audit", "stacktrace", "verbose")):
            return "§99.32 — Record of Disclosures"
        if any(k in vt for k in ("storage", "plaintext", "secret", "key", "token")):
            return "§99.31(a)(1) — Legitimate Educational Interest"
        return "§99.31 — General FERPA Compliance"

    def _generate_remediation_roadmap(self) -> List[Dict]:
        roadmap: List[Dict] = []
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        sorted_vulns = sorted(
            self.scan_results,
            key=lambda v: severity_order.get(v.get("severity", "medium").lower(), 4),
        )
        seen_types: set = set()
        for v in sorted_vulns:
            vtype = v.get("type", "Unknown")
            if vtype in seen_types:
                continue
            seen_types.add(vtype)
            roadmap.append({
                "priority": v.get("severity", "medium").upper(),
                "category": vtype.replace("_", " ").title(),
                "action": v.get("remediation", v.get("description", "Review and fix this issue")),
                "ferpa_ref": self._map_to_ferpa_regulation(vtype),
                "effort": self._estimate_effort(v.get("severity", "medium")),
            })
        return roadmap

    @staticmethod
    def _estimate_effort(severity: str) -> str:
        return {"critical": "Immediate", "high": "1-2 days", "medium": "1 week", "low": "Backlog"}.get(severity.lower(), "TBD")

    def _risk_level(self, score: int) -> str:
        if score >= 90:
            return "Low"
        if score >= 70:
            return "Medium"
        if score >= 40:
            return "High"
        return "Critical"

    def _count_severities(self) -> Dict[str, int]:
        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for v in self.scan_results:
            sev = v.get("severity", "medium").lower()
            if sev in counts:
                counts[sev] += 1
        return counts

    @staticmethod
    def _esc(text) -> str:
        if not isinstance(text, str):
            text = str(text)
        return _html.escape(text, quote=True)

    # ── Full HTML Renderer ────────────────────────────────────────────

    def _render_html(self, *, score, pass_fail, risk_level, categories,
                     roadmap, severity_counts, scan_date, unique_files) -> str:

        risk_color_map = {"Critical": "#ef4444", "High": "#f97316", "Medium": "#eab308", "Low": "#22c55e"}
        risk_color = risk_color_map.get(risk_level, "#6366f1")
        pass_color = "#22c55e" if pass_fail == "PASS" else "#ef4444"
        total_findings = len(self.scan_results)

        # ---------- Vulnerability cards ----------
        vuln_cards_html = self._render_vuln_cards(categories)

        # ---------- Category summary cards ----------
        cat_summary_html = self._render_category_summary(categories)

        # ---------- Roadmap rows ----------
        roadmap_html = self._render_roadmap(roadmap)

        # ---------- Score gauge path ----------
        circumference = 2 * 3.14159 * 54
        dash = circumference * score / 100
        gap = circumference - dash

        return f'''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SASTify FERPA Compliance Report — {self._esc(self.project_name)}</title>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet">
    <style>
        /* ─── Reset & Foundations ─────────────────────────────── */
        *, *::before, *::after {{ margin: 0; padding: 0; box-sizing: border-box; }}

        :root {{
            --bg-deep:   #050609;
            --bg-body:   #0a0a0f;
            --bg-card:   rgba(255,255,255,0.03);
            --bg-card-hover: rgba(255,255,255,0.055);
            --bg-glass:  rgba(255,255,255,0.04);
            --bg-input:  rgba(255,255,255,0.06);
            --text-primary:   #e2e8f0;
            --text-secondary: #94a3b8;
            --text-muted:     #64748b;
            --accent:    #6366f1;
            --accent2:   #8b5cf6;
            --accent-glow: rgba(99,102,241,0.15);
            --gradient:  linear-gradient(135deg, #6366f1 0%, #8b5cf6 50%, #a78bfa 100%);
            --critical:  #ef4444;
            --high:      #f97316;
            --medium:    #eab308;
            --low:       #22c55e;
            --border:    rgba(255,255,255,0.06);
            --border-accent: rgba(99,102,241,0.3);
            --radius:    12px;
            --radius-lg: 20px;
            --shadow:    0 4px 24px rgba(0,0,0,0.4);
            --shadow-glow: 0 0 40px rgba(99,102,241,0.08);
        }}

        html {{ scroll-behavior: smooth; }}

        body {{
            font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
            background: var(--bg-body);
            color: var(--text-primary);
            min-height: 100vh;
            line-height: 1.7;
            -webkit-font-smoothing: antialiased;
        }}

        /* ─── Layout ─────────────────────────────────────────── */
        .container {{
            max-width: 1140px;
            margin: 0 auto;
            padding: 0 2rem;
        }}

        /* ─── Top Gradient Bar ──────────────────────────────── */
        .top-bar {{
            height: 4px;
            background: var(--gradient);
        }}

        /* ─── Header ─────────────────────────────────────────── */
        .report-header {{
            text-align: center;
            padding: 3.5rem 0 2rem;
        }}
        .report-header .logo {{
            font-size: 2.25rem;
            font-weight: 800;
            letter-spacing: -0.5px;
            background: var(--gradient);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
        }}
        .report-header .report-type {{
            font-size: 1.05rem;
            font-weight: 500;
            color: var(--text-secondary);
            margin-top: 0.3rem;
            letter-spacing: 2px;
            text-transform: uppercase;
        }}
        .report-header .meta-row {{
            display: flex;
            justify-content: center;
            gap: 2rem;
            margin-top: 1rem;
            flex-wrap: wrap;
        }}
        .report-header .meta-item {{
            display: flex;
            align-items: center;
            gap: 0.4rem;
            font-size: 0.85rem;
            color: var(--text-muted);
        }}

        /* ─── Executive Summary ──────────────────────────────── */
        .exec-summary {{
            display: grid;
            grid-template-columns: 220px 1fr;
            gap: 2rem;
            margin: 2rem 0 2.5rem;
            padding: 2rem;
            background: var(--bg-card);
            border: 1px solid var(--border);
            border-radius: var(--radius-lg);
            box-shadow: var(--shadow-glow);
        }}
        .score-gauge {{
            display: flex;
            flex-direction: column;
            align-items: center;
            justify-content: center;
        }}
        .score-gauge svg {{ filter: drop-shadow(0 0 12px rgba(99,102,241,0.25)); }}
        .score-gauge .score-label {{
            margin-top: 0.6rem;
            font-size: 0.8rem;
            text-transform: uppercase;
            letter-spacing: 1.5px;
            color: var(--text-muted);
        }}
        .exec-details {{ display: flex; flex-direction: column; justify-content: center; gap: 1rem; }}
        .exec-row {{ display: flex; gap: 1.5rem; flex-wrap: wrap; }}
        .exec-chip {{
            display: flex;
            align-items: center;
            gap: 0.5rem;
            padding: 0.55rem 1.1rem;
            background: var(--bg-glass);
            border: 1px solid var(--border);
            border-radius: 999px;
            font-size: 0.85rem;
            color: var(--text-secondary);
        }}
        .exec-chip .dot {{
            width: 10px;
            height: 10px;
            border-radius: 50%;
            flex-shrink: 0;
        }}
        .exec-chip strong {{ color: var(--text-primary); font-weight: 600; }}

        /* ─── Severity Pills Grid ────────────────────────────── */
        .sev-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(130px, 1fr));
            gap: 1rem;
            margin-bottom: 2.5rem;
        }}
        .sev-pill {{
            display: flex;
            flex-direction: column;
            align-items: center;
            padding: 1.2rem 0.5rem;
            background: var(--bg-card);
            border: 1px solid var(--border);
            border-radius: var(--radius);
            transition: transform 0.2s ease, box-shadow 0.2s ease;
        }}
        .sev-pill:hover {{
            transform: translateY(-3px);
            box-shadow: var(--shadow);
        }}
        .sev-pill .sev-count {{
            font-size: 2rem;
            font-weight: 700;
            line-height: 1;
        }}
        .sev-pill .sev-name {{
            font-size: 0.7rem;
            text-transform: uppercase;
            letter-spacing: 1px;
            margin-top: 0.4rem;
            color: var(--text-muted);
        }}
        .sev-pill.critical .sev-count {{ color: var(--critical); }}
        .sev-pill.high .sev-count     {{ color: var(--high); }}
        .sev-pill.medium .sev-count   {{ color: var(--medium); }}
        .sev-pill.low .sev-count      {{ color: var(--low); }}
        .sev-pill.total .sev-count    {{ color: var(--accent); }}

        /* ─── Section Header ─────────────────────────────────── */
        .section {{
            margin-bottom: 2.5rem;
        }}
        .section-title {{
            display: flex;
            align-items: center;
            gap: 0.75rem;
            font-size: 1.2rem;
            font-weight: 700;
            margin-bottom: 1.25rem;
            padding-bottom: 0.75rem;
            border-bottom: 1px solid var(--border);
        }}
        .section-title .icon {{ font-size: 1.3rem; }}
        .section-title .pill {{
            margin-left: auto;
            font-size: 0.7rem;
            font-weight: 600;
            padding: 0.25rem 0.7rem;
            background: var(--accent);
            color: #fff;
            border-radius: 999px;
        }}

        /* ─── Category Cards ─────────────────────────────────── */
        .cat-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(320px, 1fr));
            gap: 1.25rem;
        }}
        .cat-card {{
            background: var(--bg-card);
            border: 1px solid var(--border);
            border-radius: var(--radius);
            padding: 1.5rem;
            transition: border-color 0.25s ease, box-shadow 0.25s ease;
        }}
        .cat-card:hover {{
            border-color: var(--border-accent);
            box-shadow: var(--shadow-glow);
        }}
        .cat-card .cat-head {{
            display: flex;
            justify-content: space-between;
            align-items: flex-start;
            margin-bottom: 0.6rem;
        }}
        .cat-card .cat-name {{
            font-size: 1rem;
            font-weight: 600;
        }}
        .cat-card .cat-count {{
            font-size: 0.7rem;
            font-weight: 600;
            padding: 0.2rem 0.55rem;
            border-radius: 999px;
            background: var(--bg-glass);
            border: 1px solid var(--border);
            color: var(--text-secondary);
        }}
        .cat-card .cat-count.has-issues {{ background: rgba(239,68,68,0.12); color: var(--critical); border-color: rgba(239,68,68,0.25); }}
        .cat-card .cat-count.clean {{ background: rgba(34,197,94,0.12); color: var(--low); border-color: rgba(34,197,94,0.25); }}
        .cat-card .cat-desc {{
            font-size: 0.82rem;
            color: var(--text-muted);
            line-height: 1.6;
        }}
        .cat-card .cat-reg {{
            display: inline-block;
            margin-top: 0.75rem;
            font-family: 'JetBrains Mono', monospace;
            font-size: 0.72rem;
            padding: 0.25rem 0.6rem;
            background: rgba(99,102,241,0.1);
            border: 1px solid rgba(99,102,241,0.2);
            border-radius: 6px;
            color: var(--accent2);
        }}
        .cat-card .cat-status {{
            display: flex;
            align-items: center;
            gap: 0.4rem;
            margin-top: 0.6rem;
            font-size: 0.8rem;
            font-weight: 500;
        }}
        .cat-card .cat-status.pass {{ color: var(--low); }}
        .cat-card .cat-status.fail {{ color: var(--critical); }}

        /* ─── Vulnerability Detail Cards ─────────────────────── */
        .vuln-card {{
            background: var(--bg-card);
            border: 1px solid var(--border);
            border-radius: var(--radius);
            margin-bottom: 1rem;
            overflow: hidden;
            transition: border-color 0.2s ease;
            animation: fadeUp 0.35s ease both;
        }}
        .vuln-card:hover {{ border-color: var(--border-accent); }}
        .vuln-card.sev-critical {{ border-left: 4px solid var(--critical); }}
        .vuln-card.sev-high     {{ border-left: 4px solid var(--high); }}
        .vuln-card.sev-medium   {{ border-left: 4px solid var(--medium); }}
        .vuln-card.sev-low      {{ border-left: 4px solid var(--low); }}

        .vuln-head {{
            display: flex;
            justify-content: space-between;
            align-items: flex-start;
            padding: 1.15rem 1.25rem;
            background: rgba(255,255,255,0.015);
            flex-wrap: wrap;
            gap: 0.6rem;
        }}
        .vuln-head .vuln-title {{
            display: flex;
            flex-direction: column;
            gap: 0.25rem;
        }}
        .vuln-head .vuln-type {{
            font-size: 1rem;
            font-weight: 600;
        }}
        .vuln-head .vuln-loc {{
            font-family: 'JetBrains Mono', monospace;
            font-size: 0.78rem;
            color: var(--text-muted);
        }}
        .vuln-head .badges {{ display: flex; gap: 0.45rem; flex-wrap: wrap; }}

        .badge {{
            font-size: 0.62rem;
            font-weight: 700;
            padding: 0.25rem 0.55rem;
            border-radius: 4px;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }}
        .badge.critical {{ background: var(--critical); color: #fff; }}
        .badge.high     {{ background: var(--high); color: #fff; }}
        .badge.medium   {{ background: var(--medium); color: #1a1a1a; }}
        .badge.low      {{ background: var(--low); color: #fff; }}
        .badge.ferpa    {{ background: rgba(139,92,246,0.15); color: var(--accent2); border: 1px solid rgba(139,92,246,0.3); }}
        .badge.cwe      {{ background: rgba(99,102,241,0.12); color: var(--accent); border: 1px solid rgba(99,102,241,0.25); }}

        .vuln-body {{
            padding: 1.15rem 1.25rem;
        }}
        .vuln-body .vuln-desc {{
            font-size: 0.9rem;
            color: var(--text-secondary);
            margin-bottom: 0.8rem;
            line-height: 1.65;
        }}

        .code-block {{
            background: #0f1117;
            border: 1px solid rgba(255,255,255,0.06);
            border-radius: 8px;
            overflow: hidden;
            margin: 0.8rem 0;
        }}
        .code-header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 0.5rem 1rem;
            background: rgba(255,255,255,0.03);
            border-bottom: 1px solid rgba(255,255,255,0.05);
        }}
        .code-lang {{
            font-family: 'JetBrains Mono', monospace;
            font-size: 0.65rem;
            color: var(--text-muted);
            text-transform: uppercase;
            letter-spacing: 1px;
        }}
        .code-content {{
            padding: 0.9rem 1rem;
            font-family: 'JetBrains Mono', monospace;
            font-size: 0.78rem;
            line-height: 1.6;
            color: #c9d1d9;
            white-space: pre-wrap;
            word-break: break-all;
            overflow-x: auto;
        }}

        .remediation-box {{
            background: rgba(34,197,94,0.06);
            border: 1px solid rgba(34,197,94,0.15);
            border-radius: 8px;
            padding: 0.9rem 1rem;
            margin-top: 0.8rem;
        }}
        .remediation-box .rem-label {{
            font-size: 0.72rem;
            font-weight: 700;
            text-transform: uppercase;
            letter-spacing: 1px;
            color: var(--low);
            margin-bottom: 0.4rem;
        }}
        .remediation-box .rem-text {{
            font-size: 0.85rem;
            color: var(--text-secondary);
            line-height: 1.6;
        }}

        /* ─── Roadmap ────────────────────────────────────────── */
        .roadmap-table {{
            width: 100%;
            border-collapse: separate;
            border-spacing: 0;
            font-size: 0.85rem;
        }}
        .roadmap-table thead th {{
            text-align: left;
            padding: 0.8rem 1rem;
            font-size: 0.7rem;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 1px;
            color: var(--text-muted);
            background: rgba(255,255,255,0.02);
            border-bottom: 1px solid var(--border);
        }}
        .roadmap-table tbody td {{
            padding: 0.85rem 1rem;
            border-bottom: 1px solid var(--border);
            color: var(--text-secondary);
            vertical-align: top;
        }}
        .roadmap-table tbody tr:hover td {{
            background: rgba(255,255,255,0.015);
        }}
        .roadmap-table .priority-badge {{
            display: inline-block;
            font-size: 0.62rem;
            font-weight: 700;
            padding: 0.2rem 0.55rem;
            border-radius: 4px;
            text-transform: uppercase;
        }}
        .priority-badge.CRITICAL {{ background: var(--critical); color: #fff; }}
        .priority-badge.HIGH     {{ background: var(--high); color: #fff; }}
        .priority-badge.MEDIUM   {{ background: var(--medium); color: #1a1a1a; }}
        .priority-badge.LOW      {{ background: var(--low); color: #fff; }}

        /* ─── Footer ─────────────────────────────────────────── */
        .report-footer {{
            text-align: center;
            padding: 2.5rem 0 3rem;
            margin-top: 2rem;
            border-top: 1px solid var(--border);
            color: var(--text-muted);
            font-size: 0.82rem;
        }}
        .report-footer a {{
            color: var(--accent);
            text-decoration: none;
        }}
        .report-footer a:hover {{ text-decoration: underline; }}
        .report-footer .disclaimer {{
            margin-top: 0.6rem;
            font-size: 0.72rem;
            color: var(--text-muted);
            opacity: 0.7;
        }}

        /* ─── Animations ─────────────────────────────────────── */
        @keyframes fadeUp {{
            from {{ opacity: 0; transform: translateY(12px); }}
            to   {{ opacity: 1; transform: translateY(0); }}
        }}

        /* ─── Print ──────────────────────────────────────────── */
        @media print {{
            body {{ background: #fff; color: #1a1a1a; }}
            .vuln-card, .cat-card, .exec-summary, .sev-pill {{
                background: #f8f9fa;
                border-color: #dee2e6;
                box-shadow: none;
            }}
            .top-bar {{ display: none; }}
        }}

        /* ─── Responsive ─────────────────────────────────────── */
        @media (max-width: 768px) {{
            .container {{ padding: 0 1rem; }}
            .exec-summary {{ grid-template-columns: 1fr; text-align: center; }}
            .score-gauge {{ margin-bottom: 1rem; }}
            .cat-grid {{ grid-template-columns: 1fr; }}
            .sev-grid {{ grid-template-columns: repeat(2, 1fr); }}
            .roadmap-table {{ font-size: 0.78rem; }}
        }}
    </style>
</head>
<body>
    <div class="top-bar"></div>
    <div class="container">

        <!-- ═══ HEADER ═══ -->
        <header class="report-header">
            <div class="logo">SASTify</div>
            <div class="report-type">FERPA Compliance Report</div>
            <div class="meta-row">
                <span class="meta-item">📁 {self._esc(self.project_name)}</span>
                <span class="meta-item">📅 {scan_date}</span>
                <span class="meta-item">📄 {unique_files} file{"s" if unique_files != 1 else ""} in scope</span>
                <span class="meta-item">🔍 {total_findings} finding{"s" if total_findings != 1 else ""}</span>
            </div>
        </header>

        <!-- ═══ EXECUTIVE SUMMARY ═══ -->
        <div class="exec-summary">
            <div class="score-gauge">
                <svg width="140" height="140" viewBox="0 0 120 120">
                    <circle cx="60" cy="60" r="54" fill="none" stroke="rgba(255,255,255,0.05)" stroke-width="8"/>
                    <circle cx="60" cy="60" r="54" fill="none" stroke="{risk_color}" stroke-width="8"
                            stroke-dasharray="{dash:.1f} {gap:.1f}"
                            stroke-linecap="round"
                            transform="rotate(-90 60 60)"
                            style="transition: stroke-dasharray 1s ease;"/>
                    <text x="60" y="55" text-anchor="middle" fill="{risk_color}"
                          font-size="32" font-weight="800" font-family="Inter, sans-serif">{score}</text>
                    <text x="60" y="72" text-anchor="middle" fill="{risk_color}"
                          font-size="10" font-weight="500" font-family="Inter, sans-serif" opacity="0.8">/ 100</text>
                </svg>
                <span class="score-label">Compliance Score</span>
            </div>
            <div class="exec-details">
                <div class="exec-row">
                    <span class="exec-chip">
                        <span class="dot" style="background:{pass_color}"></span>
                        Determination: <strong style="color:{pass_color}">{pass_fail}</strong>
                    </span>
                    <span class="exec-chip">
                        <span class="dot" style="background:{risk_color}"></span>
                        Risk Level: <strong style="color:{risk_color}">{risk_level}</strong>
                    </span>
                </div>
                <div class="exec-row">
                    <span class="exec-chip">📊 Total Findings: <strong>{total_findings}</strong></span>
                    <span class="exec-chip">🏫 Project: <strong>{self._esc(self.project_name)}</strong></span>
                </div>
                <p style="font-size:0.82rem; color:var(--text-muted); line-height:1.6; margin-top:0.4rem;">
                    {"⚠️ <strong style='color:var(--critical)'>Critical PII issues detected.</strong> The project does not meet FERPA compliance requirements. Immediate remediation is required before processing student data." if pass_fail == "FAIL" else "✅ No critical PII issues found. The project meets baseline FERPA compliance requirements. Continue monitoring and address remaining findings."}
                </p>
            </div>
        </div>

        <!-- ═══ SEVERITY OVERVIEW ═══ -->
        <div class="sev-grid">
            <div class="sev-pill total">
                <span class="sev-count">{total_findings}</span>
                <span class="sev-name">Total</span>
            </div>
            <div class="sev-pill critical">
                <span class="sev-count">{severity_counts["critical"]}</span>
                <span class="sev-name">Critical</span>
            </div>
            <div class="sev-pill high">
                <span class="sev-count">{severity_counts["high"]}</span>
                <span class="sev-name">High</span>
            </div>
            <div class="sev-pill medium">
                <span class="sev-count">{severity_counts["medium"]}</span>
                <span class="sev-name">Medium</span>
            </div>
            <div class="sev-pill low">
                <span class="sev-count">{severity_counts["low"]}</span>
                <span class="sev-name">Low</span>
            </div>
        </div>

        <!-- ═══ FERPA COMPLIANCE CATEGORIES ═══ -->
        <div class="section">
            <div class="section-title">
                <span class="icon">📋</span>
                FERPA Compliance Categories
                <span class="pill">5 categories</span>
            </div>
            <div class="cat-grid">
{cat_summary_html}
            </div>
        </div>

        <!-- ═══ DETAILED FINDINGS ═══ -->
        <div class="section">
            <div class="section-title">
                <span class="icon">🔍</span>
                Detailed Findings
                <span class="pill">{total_findings} issues</span>
            </div>
{vuln_cards_html}
        </div>

        <!-- ═══ REMEDIATION ROADMAP ═══ -->
        <div class="section">
            <div class="section-title">
                <span class="icon">🗺️</span>
                Remediation Roadmap
                <span class="pill">{len(roadmap)} actions</span>
            </div>
            <div style="overflow-x:auto;">
                <table class="roadmap-table">
                    <thead>
                        <tr>
                            <th style="width:90px">Priority</th>
                            <th>Category</th>
                            <th>Action Required</th>
                            <th style="width:160px">FERPA Reference</th>
                            <th style="width:90px">Effort</th>
                        </tr>
                    </thead>
                    <tbody>
{roadmap_html}
                    </tbody>
                </table>
            </div>
        </div>

        <!-- ═══ FOOTER ═══ -->
        <footer class="report-footer">
            <p>Generated by <a href="https://github.com/abbyy745-cloud/SASTify">SASTify</a> — FERPA Compliance Analysis Engine</p>
            <p class="disclaimer">
                This report is generated by automated static analysis and should be reviewed by qualified personnel.
                It does not constitute legal advice. Consult with a FERPA compliance officer for authoritative guidance.
            </p>
        </footer>
    </div>
</body>
</html>'''

    # ── Sub-renderers ─────────────────────────────────────────────────

    def _render_category_summary(self, categories: Dict[str, List[Dict]]) -> str:
        html_parts = []
        for cat_key, cat_info in self.CATEGORIES.items():
            findings = categories.get(cat_key, [])
            count = len(findings)
            count_class = "has-issues" if count > 0 else "clean"
            status_class = "fail" if count > 0 else "pass"
            status_icon = "⚠️" if count > 0 else "✅"
            status_text = f"{count} issue{'s' if count != 1 else ''} found" if count > 0 else "No issues"

            html_parts.append(f'''                <div class="cat-card">
                    <div class="cat-head">
                        <span class="cat-name">{cat_info["icon"]} {cat_info["title"]}</span>
                        <span class="cat-count {count_class}">{count}</span>
                    </div>
                    <p class="cat-desc">{cat_info["description"]}</p>
                    <span class="cat-reg">{cat_info["regulation"]}</span>
                    <div class="cat-status {status_class}">{status_icon} {status_text}</div>
                </div>''')
        return "\n".join(html_parts)

    def _render_vuln_cards(self, categories: Dict[str, List[Dict]]) -> str:
        import os
        html_parts = []
        idx = 0
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}

        for cat_key, cat_info in self.CATEGORIES.items():
            findings = categories.get(cat_key, [])
            if not findings:
                continue

            # Sort findings within category by severity
            sorted_findings = sorted(
                findings,
                key=lambda v: severity_order.get(v.get("severity", "medium").lower(), 4),
            )

            html_parts.append(f'''            <h3 style="font-size:0.95rem; font-weight:600; color:var(--text-secondary); margin: 1.5rem 0 0.75rem; padding-left:0.25rem;">
                {cat_info["icon"]} {cat_info["title"]}
            </h3>''')

            for v in sorted_findings:
                sev = v.get("severity", "Medium").lower()
                vtype = v.get("type", "Unknown")
                file_path = v.get("file", "unknown")
                line_num = v.get("line", "?")
                snippet = self._esc(v.get("snippet", ""))
                desc = self._esc(v.get("description", "No description available."))
                cwe = v.get("cwe_id", v.get("cwe", ""))
                remediation = self._esc(v.get("remediation", v.get("ai_fix_suggestion", "")))
                ferpa_reg = self._map_to_ferpa_regulation(vtype)

                # File extension for language label
                ext = os.path.splitext(file_path)[1].lstrip(".")
                lang_map = {"py": "python", "js": "javascript", "ts": "typescript",
                            "java": "java", "kt": "kotlin", "swift": "swift",
                            "dart": "dart", "php": "php"}
                lang = lang_map.get(ext, ext or "text")

                badges_html = f'<span class="badge {sev}">{sev}</span>'
                if cwe:
                    ferpa_from_cwe = self.CWE_FERPA_MAP.get(cwe, "")
                    badges_html += f' <span class="badge cwe">{self._esc(cwe)}</span>'
                    if ferpa_from_cwe:
                        ferpa_reg = ferpa_from_cwe
                badges_html += f' <span class="badge ferpa">{self._esc(ferpa_reg)}</span>'

                code_html = ""
                if snippet:
                    code_html = f'''
                    <div class="code-block">
                        <div class="code-header">
                            <span class="code-lang">{lang}</span>
                        </div>
                        <div class="code-content">{snippet[:600]}</div>
                    </div>'''

                rem_html = ""
                if remediation:
                    rem_html = f'''
                    <div class="remediation-box">
                        <div class="rem-label">🔧 Remediation</div>
                        <div class="rem-text">{remediation}</div>
                    </div>'''

                html_parts.append(f'''            <div class="vuln-card sev-{sev}" style="animation-delay:{idx * 0.04}s">
                <div class="vuln-head">
                    <div class="vuln-title">
                        <span class="vuln-type">{self._esc(vtype.replace("_", " ").title())}</span>
                        <span class="vuln-loc">📁 {self._esc(os.path.basename(file_path))} : Line {line_num}</span>
                    </div>
                    <div class="badges">{badges_html}</div>
                </div>
                <div class="vuln-body">
                    <p class="vuln-desc">{desc}</p>{code_html}{rem_html}
                </div>
            </div>''')
                idx += 1

        if not html_parts:
            html_parts.append('''            <div style="text-align:center; padding:3rem 0; color:var(--text-muted);">
                <p style="font-size:1.5rem; margin-bottom:0.5rem;">✅</p>
                <p>No FERPA-relevant vulnerabilities detected.</p>
            </div>''')

        return "\n".join(html_parts)

    def _render_roadmap(self, roadmap: List[Dict]) -> str:
        if not roadmap:
            return '                        <tr><td colspan="5" style="text-align:center; color:var(--text-muted); padding:2rem;">No remediation actions required.</td></tr>'

        rows = []
        for item in roadmap:
            priority = item["priority"]
            rows.append(f'''                        <tr>
                            <td><span class="priority-badge {priority}">{priority}</span></td>
                            <td style="font-weight:500; color:var(--text-primary);">{self._esc(item["category"])}</td>
                            <td>{self._esc(item["action"][:200])}</td>
                            <td><span style="font-family:'JetBrains Mono',monospace; font-size:0.75rem; color:var(--accent2);">{self._esc(item["ferpa_ref"])}</span></td>
                            <td style="font-weight:500;">{self._esc(item["effort"])}</td>
                        </tr>''')
        return "\n".join(rows)
