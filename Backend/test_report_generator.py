#!/usr/bin/env python3
"""
SASTify Test Case Report Generator

Generates a dedicated HTML report with all AI-suggested test cases,
grouped by vulnerability type for easy copy-paste integration.
"""

import os
from typing import List, Dict
from datetime import datetime


class TestReportGenerator:
    """
    Generates a comprehensive test case report from AI-analyzed vulnerabilities.
    """
    
    def __init__(self):
        self.test_types = ['unit', 'security', 'integration']
    
    def generate_report(self, vulnerabilities: List[Dict], output_path: str) -> bool:
        """
        Generate a test case report from analyzed vulnerabilities.
        
        Args:
            vulnerabilities: List of vulnerability dicts with AI analysis
            output_path: Path to write the HTML report
            
        Returns:
            True if report was generated successfully
        """
        # Filter to only AI-analyzed vulnerabilities with test cases
        analyzed = [v for v in vulnerabilities 
                   if v.get('ai_analyzed') and v.get('ai_test_suggestions')]
        
        if not analyzed:
            print("No test cases available - AI analysis may not have been run")
            return False
        
        html = self._generate_html(analyzed)
        
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(html)
        
        return True
    
    def _generate_html(self, vulnerabilities: List[Dict]) -> str:
        """Generate the HTML content for the test report"""
        
        # Group test cases by vulnerability type
        grouped_tests = {}
        total_tests = 0
        
        for vuln in vulnerabilities:
            vuln_type = vuln.get('type', 'Unknown')
            tests = vuln.get('ai_test_suggestions', [])
            
            if vuln_type not in grouped_tests:
                grouped_tests[vuln_type] = {
                    'vulnerabilities': [],
                    'test_count': 0
                }
            
            grouped_tests[vuln_type]['vulnerabilities'].append({
                'file': vuln.get('file', 'unknown'),
                'line': vuln.get('line', '?'),
                'severity': vuln.get('severity', 'Medium'),
                'tests': tests
            })
            grouped_tests[vuln_type]['test_count'] += len(tests)
            total_tests += len(tests)
        
        # Count by test type
        type_counts = {t: 0 for t in self.test_types}
        for vuln in vulnerabilities:
            for test in vuln.get('ai_test_suggestions', []):
                if isinstance(test, dict):
                    test_type = test.get('type', 'unit').lower()
                    if test_type in type_counts:
                        type_counts[test_type] += 1
        
        html = f'''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SASTify Test Cases Report</title>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet">
    <style>
        :root {{
            --bg-primary: #f8fafc;
            --bg-secondary: #ffffff;
            --bg-card: #ffffff;
            --bg-glass: #f1f5f9;
            --text-primary: #1e293b;
            --text-secondary: #64748b;
            --text-muted: #94a3b8;
            --accent-primary: #10b981;
            --accent-secondary: #34d399;
            --accent-gradient: linear-gradient(135deg, #10b981 0%, #34d399 100%);
            --critical: #dc2626;
            --high: #ea580c;
            --medium: #ca8a04;
            --low: #2563eb;
            --unit: #2563eb;
            --security: #dc2626;
            --integration: #7c3aed;
            --border: #e2e8f0;
            --shadow: 0 1px 3px rgba(0,0,0,0.1), 0 1px 2px rgba(0,0,0,0.06);
            --shadow-lg: 0 10px 15px -3px rgba(0,0,0,0.1), 0 4px 6px -2px rgba(0,0,0,0.05);
        }}
        
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        
        body {{
            font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
            background: var(--bg-primary);
            color: var(--text-primary);
            min-height: 100vh;
            line-height: 1.6;
        }}
        
        .container {{
            max-width: 1000px;
            margin: 0 auto;
            padding: 2rem;
        }}
        
        .header {{
            text-align: center;
            padding: 2rem 0;
            margin-bottom: 2rem;
        }}
        
        .logo {{
            font-size: 2rem;
            font-weight: 700;
            background: var(--accent-gradient);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
            margin-bottom: 0.5rem;
        }}
        
        .subtitle {{
            color: var(--text-secondary);
            font-size: 1rem;
        }}
        
        .timestamp {{
            color: var(--text-muted);
            font-size: 0.85rem;
            margin-top: 0.5rem;
        }}
        
        /* Stats */
        .stats-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(130px, 1fr));
            gap: 1rem;
            margin-bottom: 1.5rem;
        }}
        
        .stat-card {{
            background: var(--bg-secondary);
            border: 1px solid var(--border);
            border-radius: 10px;
            padding: 1rem;
            text-align: center;
            box-shadow: var(--shadow);
        }}
        
        .stat-card.unit {{ border-top: 3px solid var(--unit); }}
        .stat-card.security {{ border-top: 3px solid var(--security); }}
        .stat-card.integration {{ border-top: 3px solid var(--integration); }}
        
        .stat-value {{
            font-size: 1.75rem;
            font-weight: 700;
        }}
        
        .stat-label {{
            color: var(--text-secondary);
            font-size: 0.75rem;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            margin-top: 0.25rem;
        }}
        
        /* Quick Actions */
        .quick-actions {{
            display: flex;
            gap: 0.75rem;
            margin-bottom: 1.5rem;
            flex-wrap: wrap;
        }}
        
        .action-btn {{
            background: var(--bg-secondary);
            border: 1px solid var(--border);
            color: var(--text-primary);
            padding: 0.6rem 1.25rem;
            border-radius: 8px;
            font-size: 0.85rem;
            cursor: pointer;
            transition: all 0.2s ease;
            display: flex;
            align-items: center;
            gap: 0.5rem;
            box-shadow: var(--shadow);
        }}
        
        .action-btn:hover {{
            background: var(--accent-primary);
            border-color: var(--accent-primary);
            color: white;
        }}
        
        .action-btn.primary {{
            background: var(--accent-primary);
            border-color: var(--accent-primary);
            color: white;
        }}
        
        /* Vulnerability Group */
        .vuln-group {{
            margin-bottom: 1.5rem;
        }}
        
        .group-header {{
            display: flex;
            align-items: center;
            gap: 1rem;
            padding: 1rem;
            background: var(--bg-secondary);
            border: 1px solid var(--border);
            border-radius: 10px 10px 0 0;
            cursor: pointer;
            box-shadow: var(--shadow);
        }}
        
        .group-header:hover {{
            border-color: var(--accent-primary);
        }}
        
        .group-title {{
            font-size: 1rem;
            font-weight: 600;
            flex: 1;
        }}
        
        .group-count {{
            background: var(--accent-primary);
            color: white;
            font-size: 0.7rem;
            font-weight: 600;
            padding: 0.2rem 0.6rem;
            border-radius: 999px;
        }}
        
        .toggle-icon {{
            color: var(--text-muted);
            transition: transform 0.2s ease;
        }}
        
        .group-header.active .toggle-icon {{
            transform: rotate(180deg);
        }}
        
        .group-content {{
            display: none;
            border: 1px solid var(--border);
            border-top: none;
            border-radius: 0 0 10px 10px;
            padding: 1rem;
            background: var(--bg-glass);
        }}
        
        .group-content.show {{
            display: block;
        }}
        
        /* Test Case Card */
        .test-card {{
            background: var(--bg-secondary);
            border: 1px solid var(--border);
            border-radius: 8px;
            margin-bottom: 0.75rem;
            overflow: hidden;
            box-shadow: var(--shadow);
        }}
        
        .test-card:last-child {{
            margin-bottom: 0;
        }}
        
        .test-header {{
            display: flex;
            align-items: center;
            gap: 0.75rem;
            padding: 0.75rem 1rem;
            background: var(--bg-glass);
            flex-wrap: wrap;
        }}
        
        .test-type-badge {{
            font-size: 0.6rem;
            font-weight: 600;
            padding: 0.2rem 0.5rem;
            border-radius: 4px;
            text-transform: uppercase;
        }}
        
        .test-type-badge.unit {{ background: var(--unit); color: white; }}
        .test-type-badge.security {{ background: var(--security); color: white; }}
        .test-type-badge.integration {{ background: var(--integration); color: white; }}
        
        .test-name {{
            font-weight: 500;
            flex: 1;
            font-size: 0.95rem;
        }}
        
        .test-source {{
            font-family: 'JetBrains Mono', monospace;
            font-size: 0.75rem;
            color: var(--text-muted);
        }}
        
        .test-body {{
            padding: 1rem;
        }}
        
        .test-desc {{
            color: var(--text-secondary);
            margin-bottom: 0.75rem;
            font-size: 0.9rem;
        }}
        
        /* Code Block */
        .code-block {{
            background: #1e293b;
            border-radius: 8px;
            overflow: hidden;
            margin: 0.75rem 0;
        }}
        
        .code-header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 0.5rem 1rem;
            background: #334155;
            border-bottom: 1px solid #475569;
        }}
        
        .code-lang {{
            font-size: 0.65rem;
            color: #94a3b8;
            text-transform: uppercase;
        }}
        
        .copy-btn {{
            background: transparent;
            border: 1px solid #475569;
            color: #94a3b8;
            padding: 0.2rem 0.5rem;
            border-radius: 4px;
            font-size: 0.65rem;
            cursor: pointer;
            transition: all 0.2s ease;
        }}
        
        .copy-btn:hover {{
            background: var(--accent-primary);
            border-color: var(--accent-primary);
            color: white;
        }}
        
        .code-content {{
            padding: 0.75rem 1rem;
            font-family: 'JetBrains Mono', monospace;
            font-size: 0.8rem;
            line-height: 1.5;
            overflow-x: auto;
            white-space: pre-wrap;
            color: #e2e8f0;
        }}
        
        /* Test Inputs */
        .test-inputs {{
            margin-top: 0.75rem;
            padding-top: 0.75rem;
            border-top: 1px solid var(--border);
        }}
        
        .test-inputs-label {{
            font-size: 0.7rem;
            color: var(--text-muted);
            text-transform: uppercase;
            letter-spacing: 0.5px;
            margin-bottom: 0.5rem;
        }}
        
        .input-tag {{
            display: inline-block;
            background: #fef2f2;
            border: 1px solid #fecaca;
            color: var(--critical);
            font-family: 'JetBrains Mono', monospace;
            font-size: 0.75rem;
            padding: 0.25rem 0.5rem;
            border-radius: 4px;
            margin: 0.2rem;
        }}
        
        .expected {{
            margin-top: 0.5rem;
            color: var(--text-secondary);
            font-size: 0.85rem;
        }}
        
        /* Footer */
        .footer {{
            text-align: center;
            padding: 1.5rem 0;
            margin-top: 2rem;
            border-top: 1px solid var(--border);
            color: var(--text-muted);
            font-size: 0.85rem;
        }}
        
        .footer a {{
            color: var(--accent-primary);
            text-decoration: none;
        }}
        
        @media (max-width: 768px) {{
            .container {{ padding: 1rem; }}
            .stats-grid {{ grid-template-columns: repeat(2, 1fr); }}
            .quick-actions {{ flex-direction: column; }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <header class="header">
            <h1 class="logo">Test Cases</h1>
            <p class="subtitle">AI-Generated Security Test Suite</p>
            <p class="timestamp">Generated: {datetime.now().strftime("%B %d, %Y at %H:%M:%S")}</p>
        </header>
        
        <div class="stats-grid">
            <div class="stat-card">
                <div class="stat-value">{total_tests}</div>
                <div class="stat-label">Total Tests</div>
            </div>
            <div class="stat-card unit">
                <div class="stat-value">{type_counts.get('unit', 0)}</div>
                <div class="stat-label">Unit Tests</div>
            </div>
            <div class="stat-card security">
                <div class="stat-value">{type_counts.get('security', 0)}</div>
                <div class="stat-label">Security Tests</div>
            </div>
            <div class="stat-card integration">
                <div class="stat-value">{type_counts.get('integration', 0)}</div>
                <div class="stat-label">Integration</div>
            </div>
        </div>
        
        <div class="quick-actions">
            <button class="action-btn primary" onclick="copyAllTests()">📋 Copy All Test Code</button>
            <button class="action-btn" onclick="expandAll()">📂 Expand All</button>
            <button class="action-btn" onclick="collapseAll()">📁 Collapse All</button>
        </div>
'''
        
        # Generate test groups
        for vuln_type, data in grouped_tests.items():
            html += f'''
        <div class="vuln-group">
            <div class="group-header" onclick="toggleGroup(this)">
                <span class="group-title">🔐 {vuln_type.replace('_', ' ').title()}</span>
                <span class="group-count">{data['test_count']} tests</span>
                <span class="toggle-icon">▼</span>
            </div>
            <div class="group-content">
'''
            
            for vuln_data in data['vulnerabilities']:
                for test in vuln_data['tests']:
                    if isinstance(test, dict):
                        test_type = test.get('type', 'unit')
                        test_name = test.get('name', 'Test Case').replace('<', '&lt;').replace('>', '&gt;')
                        test_desc = test.get('description', '').replace('<', '&lt;').replace('>', '&gt;')
                        test_code = test.get('code', '').replace('<', '&lt;').replace('>', '&gt;')
                        test_inputs = test.get('test_inputs', [])
                        expected = test.get('expected_behavior', '').replace('<', '&lt;').replace('>', '&gt;')
                        
                        file_basename = os.path.basename(vuln_data['file'])
                        
                        html += f'''
                <div class="test-card">
                    <div class="test-header">
                        <span class="test-type-badge {test_type}">{test_type}</span>
                        <span class="test-name">{test_name}</span>
                        <span class="test-source">{file_basename}:{vuln_data['line']}</span>
                    </div>
                    <div class="test-body">
                        <p class="test-desc">{test_desc}</p>
'''
                        if test_code:
                            html += f'''
                        <div class="code-block">
                            <div class="code-header">
                                <span class="code-lang">test</span>
                                <button class="copy-btn" onclick="copyCode(this)">📋 Copy</button>
                            </div>
                            <div class="code-content">{test_code}</div>
                        </div>
'''
                        
                        if test_inputs:
                            html += '''
                        <div class="test-inputs">
                            <div class="test-inputs-label">Attack Payloads / Test Inputs</div>
'''
                            for inp in test_inputs[:8]:
                                safe_inp = str(inp).replace('<', '&lt;').replace('>', '&gt;')[:80]
                                html += f'                            <span class="input-tag">{safe_inp}</span>\n'
                            html += '                        </div>\n'
                        
                        if expected:
                            html += f'''
                        <p class="expected"><strong>Expected:</strong> {expected}</p>
'''
                        
                        html += '''                    </div>
                </div>
'''
            
            html += '''            </div>
        </div>
'''
        
        html += '''
        <footer class="footer">
            <p>Generated by <a href="https://github.com/abbyy745-cloud/SASTify">SASTify</a></p>
            <p style="margin-top: 0.5rem; font-size: 0.8rem;">Copy these tests into your test suite to validate security fixes 🛡️</p>
        </footer>
    </div>
    
    <script>
        function toggleGroup(header) {
            const content = header.nextElementSibling;
            header.classList.toggle('active');
            content.classList.toggle('show');
        }
        
        function expandAll() {
            document.querySelectorAll('.group-header').forEach(h => {
                h.classList.add('active');
                h.nextElementSibling.classList.add('show');
            });
        }
        
        function collapseAll() {
            document.querySelectorAll('.group-header').forEach(h => {
                h.classList.remove('active');
                h.nextElementSibling.classList.remove('show');
            });
        }
        
        function copyCode(btn) {
            const code = btn.closest('.code-block').querySelector('.code-content').textContent;
            navigator.clipboard.writeText(code).then(() => {
                const orig = btn.textContent;
                btn.textContent = '✓ Copied!';
                btn.style.background = '#10b981';
                btn.style.borderColor = '#10b981';
                setTimeout(() => {
                    btn.textContent = orig;
                    btn.style.background = '';
                    btn.style.borderColor = '';
                }, 2000);
            });
        }
        
        function copyAllTests() {
            const allCode = [];
            document.querySelectorAll('.code-content').forEach(el => {
                allCode.push(el.textContent);
            });
            const combined = allCode.join('\\n\\n// ---\\n\\n');
            navigator.clipboard.writeText(combined).then(() => {
                const btn = document.querySelector('.action-btn.primary');
                const orig = btn.textContent;
                btn.textContent = '✓ All Tests Copied!';
                setTimeout(() => btn.textContent = orig, 2000);
            });
        }
        
        // Auto-expand first group
        const firstGroup = document.querySelector('.group-header');
        if (firstGroup) firstGroup.click();
    </script>
</body>
</html>'''
        
        return html
