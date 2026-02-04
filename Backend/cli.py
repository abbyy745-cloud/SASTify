#!/usr/bin/env python3
"""
SASTify CLI - Command Line Interface

Professional CLI for CI/CD pipeline integration:
- Multiple output formats (JSON, SARIF, Table, HTML)
- Severity filtering
- Exit codes for CI gates
- Configuration file support
"""

import argparse
import json
import sys
import os
import glob
import hashlib
from typing import List, Dict, Optional
from pathlib import Path
from datetime import datetime

# Add parent to path for imports
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from enhanced_rule_engine import EnhancedRuleEngine
from edtech_rules import EdTechRuleEngine
from sarif_formatter import SarifFormatter
from colorama import init, Fore, Style

# AI Analysis support
try:
    from deepseek_api import SecureDeepSeekAPI
    AI_AVAILABLE = True
except ImportError:
    AI_AVAILABLE = False

# Test Report Generator
try:
    from test_report_generator import TestReportGenerator
    TEST_REPORT_AVAILABLE = True
except ImportError:
    TEST_REPORT_AVAILABLE = False

# Initialize colorama for Windows
init()


# Exit codes
EXIT_SUCCESS = 0
EXIT_VULNERABILITIES_FOUND = 1
EXIT_ERROR = 2


class SASTifyCLI:
    """
    Command-line interface for SASTify security scanner.
    
    Supports multiple output formats and CI/CD integration.
    """
    
    SUPPORTED_LANGUAGES = {
        '.py': 'python',
        '.js': 'javascript',
        '.jsx': 'javascript',
        '.ts': 'typescript',
        '.tsx': 'typescript',
        '.java': 'java',
        '.kt': 'kotlin',
        '.kts': 'kotlin',
        '.swift': 'swift',
        '.dart': 'dart',
        '.php': 'php',
        '.vue': 'vue',
    }
    
    SEVERITY_ORDER = ['critical', 'high', 'medium', 'low', 'info']
    
    def __init__(self):
        self.rule_engine = EnhancedRuleEngine()
        self.edtech_engine = EdTechRuleEngine()
        self.sarif_formatter = SarifFormatter()
        self.config = {}
    
    def run(self, args: argparse.Namespace) -> int:
        """Main entry point"""
        try:
            # Load config file if exists
            self._load_config(args.config)
            
            # Initialize AI analyzer if requested
            ai_analyzer = None
            if getattr(args, 'ai_analysis', False):
                api_key = getattr(args, 'api_key', None) or os.getenv('DEEPSEEK_API_KEY')
                if api_key and AI_AVAILABLE:
                    ai_analyzer = SecureDeepSeekAPI(api_key=api_key)
                    if args.verbose:
                        print(f"{Fore.CYAN}AI analysis enabled{Style.RESET_ALL}")
                elif not AI_AVAILABLE:
                    if args.verbose:
                        print(f"{Fore.YELLOW}Warning: AI analysis requested but deepseek_api module not available{Style.RESET_ALL}")
                else:
                    if args.verbose:
                        print(f"{Fore.YELLOW}Warning: AI analysis requested but no API key provided{Style.RESET_ALL}")
            
            # Collect files to scan
            files = self._collect_files(args.path, args.languages, args.exclude)
            
            if not files:
                self._print_error("No files found to scan")
                return EXIT_ERROR
            
            if args.verbose:
                print(f"{Fore.CYAN}Found {len(files)} files to scan{Style.RESET_ALL}")
            
            # Scan all files
            all_vulnerabilities = []
            for filepath in files:
                vulns = self._scan_file(filepath, args.verbose)
                all_vulnerabilities.extend(vulns)
            
            # Filter by severity
            if args.severity:
                severities = [s.lower() for s in args.severity.split(',')]
                all_vulnerabilities = [
                    v for v in all_vulnerabilities
                    if v.get('severity', '').lower() in severities
                ]
            
            # Run AI analysis if enabled
            if ai_analyzer and all_vulnerabilities:
                max_issues = getattr(args, 'max_ai_issues', 20)
                all_vulnerabilities = self._run_ai_analysis(
                    all_vulnerabilities, 
                    ai_analyzer, 
                    max_issues,
                    args.verbose
                )
            
            # Output results
            self._output_results(
                all_vulnerabilities, 
                args.format, 
                args.output,
                len(files)
            )
            
            # Generate test case report if requested
            test_report_path = getattr(args, 'test_report', None)
            if test_report_path and all_vulnerabilities:
                if TEST_REPORT_AVAILABLE:
                    if args.verbose:
                        print(f"{Fore.CYAN}Generating test case report...{Style.RESET_ALL}")
                    generator = TestReportGenerator()
                    if generator.generate_report(all_vulnerabilities, test_report_path):
                        print(f"{Fore.GREEN}Test case report saved to: {test_report_path}{Style.RESET_ALL}")
                    else:
                        print(f"{Fore.YELLOW}No test cases to include in report{Style.RESET_ALL}")
                else:
                    print(f"{Fore.YELLOW}Warning: Test report requested but test_report_generator module not available{Style.RESET_ALL}")
            
            # Determine exit code
            if args.fail_on:
                fail_severities = [s.lower() for s in args.fail_on.split(',')]
                for vuln in all_vulnerabilities:
                    if vuln.get('severity', '').lower() in fail_severities:
                        return EXIT_VULNERABILITIES_FOUND
            
            return EXIT_SUCCESS
            
        except Exception as e:
            self._print_error(f"Scan failed: {str(e)}")
            if args.verbose:
                import traceback
                traceback.print_exc()
            return EXIT_ERROR
    
    def _load_config(self, config_path: Optional[str]):
        """Load configuration from file"""
        paths_to_try = [
            config_path,
            '.sastifyrc',
            '.sastifyrc.json',
            '.sastify.json',
            'sastify.config.json'
        ]
        
        for path in paths_to_try:
            if path and os.path.exists(path):
                with open(path, 'r') as f:
                    self.config = json.load(f)
                return
    
    def _collect_files(self, path: str, languages: Optional[str], 
                       exclude: Optional[str]) -> List[str]:
        """Collect files to scan"""
        files = []
        
        # Parse language filter
        lang_filter = None
        if languages:
            lang_filter = [l.strip().lower() for l in languages.split(',')]
        
        # Parse exclude patterns
        exclude_patterns = []
        if exclude:
            exclude_patterns = [p.strip() for p in exclude.split(',')]
        
        # Add config excludes
        exclude_patterns.extend(self.config.get('exclude', []))
        
        # Collect files
        if os.path.isfile(path):
            files = [path]
        else:
            for root, dirs, filenames in os.walk(path):
                # Skip excluded directories
                dirs[:] = [d for d in dirs if not any(
                    self._matches_pattern(os.path.join(root, d), p) 
                    for p in exclude_patterns
                )]
                
                for filename in filenames:
                    filepath = os.path.join(root, filename)
                    ext = os.path.splitext(filename)[1].lower()
                    
                    # Check if supported
                    if ext not in self.SUPPORTED_LANGUAGES:
                        continue
                    
                    # Check language filter
                    if lang_filter:
                        file_lang = self.SUPPORTED_LANGUAGES[ext]
                        if file_lang not in lang_filter:
                            continue
                    
                    # Check exclude patterns
                    if any(self._matches_pattern(filepath, p) for p in exclude_patterns):
                        continue
                    
                    files.append(filepath)
        
        return files
    
    def _matches_pattern(self, path: str, pattern: str) -> bool:
        """Check if path matches glob pattern"""
        from fnmatch import fnmatch
        path = path.replace('\\', '/')
        return fnmatch(path, pattern) or fnmatch(os.path.basename(path), pattern)
    
    def _scan_file(self, filepath: str, verbose: bool) -> List[Dict]:
        """Scan a single file"""
        ext = os.path.splitext(filepath)[1].lower()
        language = self.SUPPORTED_LANGUAGES.get(ext, 'unknown')
        
        if verbose:
            print(f"  Scanning: {filepath}")
        
        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                code = f.read()
        except Exception as e:
            if verbose:
                print(f"  {Fore.YELLOW}Warning: Could not read {filepath}: {e}{Style.RESET_ALL}")
            return []
        
        vulnerabilities = []
        
        # Main rule engine scan
        try:
            vulns = self.rule_engine.scan_with_ast_analysis(code, language, filepath)
            for v in vulns:
                v['file'] = filepath
            vulnerabilities.extend(vulns)
        except Exception as e:
            if verbose:
                print(f"  {Fore.YELLOW}Warning: AST scan failed for {filepath}: {e}{Style.RESET_ALL}")
        
        # EdTech rules scan
        try:
            edtech_vulns = self.edtech_engine.scan_code(code, language, filepath)
            for v in edtech_vulns:
                v['file'] = filepath
            vulnerabilities.extend(edtech_vulns)
        except Exception:
            pass
        
        return vulnerabilities
    
    def _run_ai_analysis(self, vulnerabilities: List[Dict], ai_analyzer, 
                         max_issues: int, verbose: bool) -> List[Dict]:
        """Run AI analysis on vulnerabilities to add explanations and fix suggestions"""
        if verbose:
            print(f"\n{Fore.CYAN}Running AI analysis on top {min(len(vulnerabilities), max_issues)} issues...{Style.RESET_ALL}")
        
        # Sort by severity to prioritize critical/high issues
        sorted_vulns = sorted(
            vulnerabilities,
            key=lambda v: self.SEVERITY_ORDER.index(v.get('severity', 'medium').lower())
        )
        
        analyzed_count = 0
        for i, vuln in enumerate(sorted_vulns):
            if analyzed_count >= max_issues:
                break
            
            try:
                # Read the code context for better AI analysis
                code_snippet = vuln.get('snippet', '')
                if not code_snippet and vuln.get('file'):
                    try:
                        with open(vuln['file'], 'r', encoding='utf-8', errors='ignore') as f:
                            lines = f.readlines()
                            line_num = vuln.get('line', 1) - 1
                            start = max(0, line_num - 5)
                            end = min(len(lines), line_num + 10)
                            code_snippet = ''.join(lines[start:end])
                    except:
                        pass
                
                if not code_snippet:
                    continue
                
                # Determine language from file extension
                ext = os.path.splitext(vuln.get('file', ''))[1].lower()
                language = self.SUPPORTED_LANGUAGES.get(ext, 'unknown')
                
                context = {
                    'confidence': vuln.get('confidence', 0.8),
                    'severity': vuln.get('severity', 'Medium'),
                    'scanner': vuln.get('scanner', 'unknown'),
                    'line': vuln.get('line', 0)
                }
                
                if verbose:
                    print(f"  Analyzing: {vuln.get('type', 'unknown')} in {os.path.basename(vuln.get('file', 'unknown'))}")
                
                # Call AI API
                ai_result = ai_analyzer.analyze_vulnerability(
                    code_snippet, 
                    language, 
                    vuln.get('type', 'unknown'),
                    context
                )
                
                # Add AI results to vulnerability - comprehensive fields
                vuln['ai_analyzed'] = True
                vuln['ai_explanation'] = ai_result.get('explanation', '')
                vuln['ai_detailed_explanation'] = ai_result.get('detailed_explanation', ai_result.get('explanation', ''))
                vuln['ai_vulnerability_summary'] = ai_result.get('vulnerability_summary', '')
                vuln['ai_fix_suggestion'] = ai_result.get('suggested_fix', '')
                vuln['ai_is_false_positive'] = not ai_result.get('is_confirmed_vulnerability', True)
                vuln['ai_confidence'] = ai_result.get('confidence', 0.5)
                vuln['ai_risk_level'] = ai_result.get('risk_level', vuln.get('severity', 'Medium'))
                vuln['ai_test_suggestions'] = ai_result.get('suggested_test_cases', [])
                
                # New comprehensive fields
                vuln['ai_attack_scenario'] = ai_result.get('attack_scenario', {})
                vuln['ai_impact_analysis'] = ai_result.get('impact_analysis', {})
                vuln['ai_remediation_steps'] = ai_result.get('remediation_steps', [])
                vuln['ai_security_references'] = ai_result.get('security_references', [])
                
                if vuln['ai_is_false_positive']:
                    vuln['ai_false_positive_reason'] = ai_result.get('false_positive_reason', '')
                
                analyzed_count += 1
                
            except Exception as e:
                if verbose:
                    print(f"  {Fore.YELLOW}Warning: AI analysis failed for issue {i}: {e}{Style.RESET_ALL}")
        
        if verbose:
            print(f"{Fore.GREEN}AI analysis completed for {analyzed_count} issues{Style.RESET_ALL}\n")
        
        return sorted_vulns
    
    def _output_results(self, vulnerabilities: List[Dict], format: str, 
                        output: Optional[str], file_count: int):
        """Output results in specified format"""
        
        if format == 'json':
            result = self._format_json(vulnerabilities, file_count)
            content = json.dumps(result, indent=2)
        
        elif format == 'sarif':
            result = self.sarif_formatter.format({'vulnerabilities': vulnerabilities})
            content = json.dumps(result, indent=2)
        
        elif format == 'table':
            content = self._format_table(vulnerabilities, file_count)
        
        elif format == 'html':
            content = self._format_html(vulnerabilities, file_count)
        
        elif format == 'summary':
            content = self._format_summary(vulnerabilities, file_count)
        
        else:
            content = self._format_table(vulnerabilities, file_count)
        
        # Output
        if output:
            with open(output, 'w', encoding='utf-8') as f:
                f.write(content)
            print(f"{Fore.GREEN}✓ Report saved to {output}{Style.RESET_ALL}")
        else:
            print(content)
    
    def _format_json(self, vulnerabilities: List[Dict], file_count: int) -> Dict:
        """Format as JSON"""
        # Count by severity
        severity_counts = {s: 0 for s in self.SEVERITY_ORDER}
        for v in vulnerabilities:
            sev = v.get('severity', 'medium').lower()
            if sev in severity_counts:
                severity_counts[sev] += 1
        
        return {
            'scan_time': datetime.utcnow().isoformat(),
            'files_scanned': file_count,
            'total_vulnerabilities': len(vulnerabilities),
            'severity_counts': severity_counts,
            'vulnerabilities': vulnerabilities
        }
    
    def _format_table(self, vulnerabilities: List[Dict], file_count: int) -> str:
        """Format as colored table"""
        lines = []
        
        # Header
        lines.append(f"\n{Fore.CYAN}{'=' * 70}{Style.RESET_ALL}")
        lines.append(f"{Fore.CYAN}SASTify Security Scan Results{Style.RESET_ALL}")
        lines.append(f"{Fore.CYAN}{'=' * 70}{Style.RESET_ALL}\n")
        
        # Summary
        severity_counts = {s: 0 for s in self.SEVERITY_ORDER}
        for v in vulnerabilities:
            sev = v.get('severity', 'medium').lower()
            if sev in severity_counts:
                severity_counts[sev] += 1
        
        lines.append(f"Files scanned: {file_count}")
        lines.append(f"Vulnerabilities found: {len(vulnerabilities)}")
        lines.append("")
        
        # Severity breakdown
        severity_colors = {
            'critical': Fore.RED + Style.BRIGHT,
            'high': Fore.RED,
            'medium': Fore.YELLOW,
            'low': Fore.BLUE,
            'info': Fore.CYAN
        }
        
        for sev in self.SEVERITY_ORDER:
            count = severity_counts[sev]
            if count > 0:
                color = severity_colors.get(sev, '')
                lines.append(f"  {color}{sev.upper()}: {count}{Style.RESET_ALL}")
        
        lines.append("")
        
        # Vulnerability details
        if vulnerabilities:
            lines.append(f"{Fore.WHITE}{'─' * 70}{Style.RESET_ALL}")
            
            # Sort by severity
            sorted_vulns = sorted(
                vulnerabilities,
                key=lambda v: self.SEVERITY_ORDER.index(v.get('severity', 'medium').lower())
            )
            
            for vuln in sorted_vulns[:50]:  # Limit output
                sev = vuln.get('severity', 'Medium').lower()
                color = severity_colors.get(sev, '')
                
                lines.append(f"\n{color}[{sev.upper()}]{Style.RESET_ALL} {vuln.get('type', 'Unknown')}")
                lines.append(f"  File: {vuln.get('file', 'unknown')}")
                lines.append(f"  Line: {vuln.get('line', '?')}")
                
                snippet = vuln.get('snippet', '')[:80]
                if snippet:
                    lines.append(f"  Code: {snippet}")
                
                desc = vuln.get('description', '')[:100]
                if desc:
                    lines.append(f"  {Fore.WHITE}{desc}{Style.RESET_ALL}")
            
            if len(vulnerabilities) > 50:
                lines.append(f"\n... and {len(vulnerabilities) - 50} more")
        
        lines.append(f"\n{Fore.CYAN}{'=' * 70}{Style.RESET_ALL}\n")
        
        return '\n'.join(lines)
    
    def _format_summary(self, vulnerabilities: List[Dict], file_count: int) -> str:
        """Format as brief summary"""
        severity_counts = {s: 0 for s in self.SEVERITY_ORDER}
        for v in vulnerabilities:
            sev = v.get('severity', 'medium').lower()
            if sev in severity_counts:
                severity_counts[sev] += 1
        
        parts = [f"{sev}: {severity_counts[sev]}" for sev in self.SEVERITY_ORDER if severity_counts[sev] > 0]
        summary = ", ".join(parts) if parts else "No vulnerabilities"
        
        return f"SASTify: Scanned {file_count} files | {summary}"
    
    def _format_html(self, vulnerabilities: List[Dict], file_count: int) -> str:
        """Format as premium HTML report with comprehensive AI analysis"""
        # Count by severity
        severity_counts = {s: 0 for s in self.SEVERITY_ORDER}
        for v in vulnerabilities:
            sev = v.get('severity', 'medium').lower()
            if sev in severity_counts:
                severity_counts[sev] += 1
        
        # Count AI analyzed
        ai_analyzed_count = sum(1 for v in vulnerabilities if v.get('ai_analyzed'))
        ai_false_positives = sum(1 for v in vulnerabilities if v.get('ai_is_false_positive'))
        ai_confirmed = ai_analyzed_count - ai_false_positives
        
        # Calculate risk score
        risk_score = (severity_counts['critical'] * 10 + severity_counts['high'] * 7 + 
                      severity_counts['medium'] * 4 + severity_counts['low'] * 1)
        risk_grade = 'A' if risk_score == 0 else 'B' if risk_score < 20 else 'C' if risk_score < 50 else 'D' if risk_score < 100 else 'F'
        
        html = f'''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SASTify Security Report</title>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet">
    <style>
        :root {{
            --bg-primary: #0a0a0f;
            --bg-secondary: #12121a;
            --bg-card: rgba(255, 255, 255, 0.03);
            --bg-glass: rgba(255, 255, 255, 0.05);
            --text-primary: #f0f0f5;
            --text-secondary: #8888a0;
            --text-muted: #555566;
            --accent-primary: #6366f1;
            --accent-secondary: #8b5cf6;
            --accent-gradient: linear-gradient(135deg, #6366f1 0%, #8b5cf6 50%, #a855f7 100%);
            --critical: #ef4444;
            --high: #f97316;
            --medium: #eab308;
            --low: #3b82f6;
            --info: #06b6d4;
            --success: #22c55e;
            --border-subtle: rgba(255, 255, 255, 0.08);
            --shadow-glow: 0 0 40px rgba(99, 102, 241, 0.15);
        }}
        
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        
        body {{
            font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
            background: var(--bg-primary);
            color: var(--text-primary);
            min-height: 100vh;
            line-height: 1.6;
        }}
        
        .container {{
            max-width: 1400px;
            margin: 0 auto;
            padding: 2rem;
        }}
        
        /* Header */
        .header {{
            text-align: center;
            padding: 3rem 0;
            border-bottom: 1px solid var(--border-subtle);
            margin-bottom: 2rem;
        }}
        
        .logo {{
            font-size: 3rem;
            font-weight: 700;
            background: var(--accent-gradient);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
            margin-bottom: 0.5rem;
        }}
        
        .logo::before {{
            content: '🛡️ ';
            -webkit-text-fill-color: initial;
        }}
        
        .subtitle {{
            color: var(--text-secondary);
            font-size: 1rem;
            font-weight: 400;
        }}
        
        .timestamp {{
            color: var(--text-muted);
            font-size: 0.85rem;
            margin-top: 1rem;
        }}
        
        /* Risk Score Card */
        .risk-score-section {{
            display: flex;
            justify-content: center;
            margin-bottom: 2rem;
        }}
        
        .risk-score-card {{
            background: var(--bg-glass);
            backdrop-filter: blur(20px);
            border: 1px solid var(--border-subtle);
            border-radius: 24px;
            padding: 2rem 4rem;
            text-align: center;
            box-shadow: var(--shadow-glow);
        }}
        
        .risk-grade {{
            font-size: 5rem;
            font-weight: 700;
            line-height: 1;
            margin-bottom: 0.5rem;
        }}
        
        .risk-grade.grade-a {{ color: var(--success); }}
        .risk-grade.grade-b {{ color: var(--low); }}
        .risk-grade.grade-c {{ color: var(--medium); }}
        .risk-grade.grade-d {{ color: var(--high); }}
        .risk-grade.grade-f {{ color: var(--critical); }}
        
        .risk-label {{
            color: var(--text-secondary);
            font-size: 0.9rem;
            text-transform: uppercase;
            letter-spacing: 2px;
        }}
        
        /* Stats Grid */
        .stats-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(160px, 1fr));
            gap: 1rem;
            margin-bottom: 3rem;
        }}
        
        .stat-card {{
            background: var(--bg-glass);
            backdrop-filter: blur(10px);
            border: 1px solid var(--border-subtle);
            border-radius: 16px;
            padding: 1.5rem;
            text-align: center;
            transition: all 0.3s ease;
            position: relative;
            overflow: hidden;
        }}
        
        .stat-card::before {{
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            right: 0;
            height: 3px;
            background: var(--accent-gradient);
            opacity: 0;
            transition: opacity 0.3s ease;
        }}
        
        .stat-card:hover {{
            transform: translateY(-4px);
            border-color: rgba(99, 102, 241, 0.3);
        }}
        
        .stat-card:hover::before {{
            opacity: 1;
        }}
        
        .stat-card.critical {{ border-left: 3px solid var(--critical); }}
        .stat-card.high {{ border-left: 3px solid var(--high); }}
        .stat-card.medium {{ border-left: 3px solid var(--medium); }}
        .stat-card.low {{ border-left: 3px solid var(--low); }}
        .stat-card.ai {{ border-left: 3px solid var(--accent-primary); }}
        
        .stat-value {{
            font-size: 2.5rem;
            font-weight: 700;
            color: var(--text-primary);
            line-height: 1.2;
        }}
        
        .stat-label {{
            color: var(--text-secondary);
            font-size: 0.8rem;
            text-transform: uppercase;
            letter-spacing: 1px;
            margin-top: 0.5rem;
        }}
        
        /* Section Headers */
        .section-header {{
            display: flex;
            align-items: center;
            gap: 1rem;
            margin: 2.5rem 0 1.5rem;
            padding-bottom: 1rem;
            border-bottom: 1px solid var(--border-subtle);
        }}
        
        .section-header h2 {{
            font-size: 1.5rem;
            font-weight: 600;
            color: var(--text-primary);
        }}
        
        .section-header .count {{
            background: var(--accent-gradient);
            color: white;
            font-size: 0.8rem;
            font-weight: 600;
            padding: 0.25rem 0.75rem;
            border-radius: 999px;
        }}
        
        /* Vulnerability Cards */
        .vuln-card {{
            background: var(--bg-card);
            border: 1px solid var(--border-subtle);
            border-radius: 16px;
            margin-bottom: 1.5rem;
            overflow: hidden;
            transition: all 0.3s ease;
        }}
        
        .vuln-card:hover {{
            border-color: rgba(99, 102, 241, 0.3);
            box-shadow: 0 10px 40px rgba(0, 0, 0, 0.3);
        }}
        
        .vuln-card.critical {{ border-left: 4px solid var(--critical); }}
        .vuln-card.high {{ border-left: 4px solid var(--high); }}
        .vuln-card.medium {{ border-left: 4px solid var(--medium); }}
        .vuln-card.low {{ border-left: 4px solid var(--low); }}
        .vuln-card.false-positive {{ opacity: 0.7; border-left-color: var(--success); }}
        
        .vuln-header {{
            display: flex;
            justify-content: space-between;
            align-items: flex-start;
            padding: 1.5rem;
            background: var(--bg-glass);
            flex-wrap: wrap;
            gap: 1rem;
        }}
        
        .vuln-title {{
            display: flex;
            flex-direction: column;
            gap: 0.5rem;
        }}
        
        .vuln-type {{
            font-size: 1.2rem;
            font-weight: 600;
            color: var(--text-primary);
        }}
        
        .vuln-location {{
            font-family: 'JetBrains Mono', monospace;
            font-size: 0.85rem;
            color: var(--text-secondary);
        }}
        
        .vuln-location a {{
            color: var(--accent-primary);
            text-decoration: none;
        }}
        
        .vuln-location a:hover {{
            text-decoration: underline;
        }}
        
        .badges {{
            display: flex;
            gap: 0.5rem;
            flex-wrap: wrap;
        }}
        
        .badge {{
            font-size: 0.7rem;
            font-weight: 600;
            padding: 0.35rem 0.75rem;
            border-radius: 6px;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }}
        
        .badge.critical {{ background: var(--critical); color: white; }}
        .badge.high {{ background: var(--high); color: white; }}
        .badge.medium {{ background: var(--medium); color: #111; }}
        .badge.low {{ background: var(--low); color: white; }}
        .badge.ai {{ background: var(--accent-gradient); color: white; }}
        .badge.fp {{ background: var(--success); color: white; }}
        
        .vuln-body {{
            padding: 1.5rem;
        }}
        
        /* Code Snippet */
        .code-block {{
            background: #0d0d12;
            border: 1px solid var(--border-subtle);
            border-radius: 12px;
            overflow: hidden;
            margin: 1rem 0;
        }}
        
        .code-header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 0.75rem 1rem;
            background: rgba(255, 255, 255, 0.02);
            border-bottom: 1px solid var(--border-subtle);
        }}
        
        .code-lang {{
            font-size: 0.75rem;
            color: var(--text-muted);
            text-transform: uppercase;
            letter-spacing: 1px;
        }}
        
        .copy-btn {{
            background: transparent;
            border: 1px solid var(--border-subtle);
            color: var(--text-secondary);
            padding: 0.35rem 0.75rem;
            border-radius: 6px;
            font-size: 0.75rem;
            cursor: pointer;
            transition: all 0.2s ease;
        }}
        
        .copy-btn:hover {{
            background: var(--accent-primary);
            border-color: var(--accent-primary);
            color: white;
        }}
        
        .code-content {{
            padding: 1rem;
            font-family: 'JetBrains Mono', monospace;
            font-size: 0.85rem;
            line-height: 1.6;
            overflow-x: auto;
            white-space: pre-wrap;
            color: #e0e0e8;
        }}
        
        /* AI Analysis Sections */
        .ai-analysis {{
            margin-top: 1.5rem;
            padding-top: 1.5rem;
            border-top: 1px solid var(--border-subtle);
        }}
        
        .ai-header {{
            display: flex;
            align-items: center;
            gap: 0.5rem;
            font-size: 1.1rem;
            font-weight: 600;
            color: var(--accent-secondary);
            margin-bottom: 1rem;
        }}
        
        .ai-header::before {{
            content: '🤖';
        }}
        
        /* Info Boxes */
        .info-box {{
            background: rgba(99, 102, 241, 0.08);
            border: 1px solid rgba(99, 102, 241, 0.2);
            border-radius: 12px;
            padding: 1.25rem;
            margin: 1rem 0;
        }}
        
        .info-box.danger {{
            background: rgba(239, 68, 68, 0.08);
            border-color: rgba(239, 68, 68, 0.2);
        }}
        
        .info-box.success {{
            background: rgba(34, 197, 94, 0.08);
            border-color: rgba(34, 197, 94, 0.2);
        }}
        
        .info-box.warning {{
            background: rgba(234, 179, 8, 0.08);
            border-color: rgba(234, 179, 8, 0.2);
        }}
        
        .info-box-header {{
            display: flex;
            align-items: center;
            gap: 0.5rem;
            font-weight: 600;
            margin-bottom: 0.75rem;
            color: var(--text-primary);
        }}
        
        .info-box-content {{
            color: var(--text-secondary);
            font-size: 0.95rem;
            line-height: 1.7;
        }}
        
        .info-box-content p {{
            margin-bottom: 0.75rem;
        }}
        
        .info-box-content p:last-child {{
            margin-bottom: 0;
        }}
        
        /* Attack Scenario */
        .attack-scenario {{
            background: var(--bg-glass);
            border: 1px solid var(--border-subtle);
            border-radius: 12px;
            padding: 1.25rem;
            margin: 1rem 0;
        }}
        
        .attack-header {{
            display: flex;
            align-items: center;
            gap: 0.5rem;
            font-weight: 600;
            margin-bottom: 1rem;
            color: var(--critical);
        }}
        
        .attack-payloads {{
            display: flex;
            flex-wrap: wrap;
            gap: 0.5rem;
            margin-top: 1rem;
        }}
        
        .payload-tag {{
            background: rgba(239, 68, 68, 0.15);
            border: 1px solid rgba(239, 68, 68, 0.3);
            color: var(--critical);
            font-family: 'JetBrains Mono', monospace;
            font-size: 0.8rem;
            padding: 0.35rem 0.75rem;
            border-radius: 6px;
        }}
        
        /* Impact Grid */
        .impact-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 1rem;
            margin: 1rem 0;
        }}
        
        .impact-card {{
            background: var(--bg-glass);
            border: 1px solid var(--border-subtle);
            border-radius: 10px;
            padding: 1rem;
        }}
        
        .impact-label {{
            font-size: 0.75rem;
            text-transform: uppercase;
            letter-spacing: 1px;
            color: var(--text-muted);
            margin-bottom: 0.5rem;
        }}
        
        .impact-value {{
            font-weight: 600;
            color: var(--text-primary);
        }}
        
        .impact-value.high {{ color: var(--critical); }}
        .impact-value.medium {{ color: var(--medium); }}
        .impact-value.low {{ color: var(--success); }}
        
        /* Remediation Steps */
        .remediation-steps {{
            list-style: none;
            counter-reset: step;
        }}
        
        .remediation-steps li {{
            counter-increment: step;
            display: flex;
            gap: 1rem;
            margin-bottom: 1rem;
            padding: 1rem;
            background: rgba(34, 197, 94, 0.05);
            border-radius: 10px;
            border-left: 3px solid var(--success);
        }}
        
        .remediation-steps li::before {{
            content: counter(step);
            display: flex;
            align-items: center;
            justify-content: center;
            min-width: 28px;
            height: 28px;
            background: var(--success);
            color: white;
            font-weight: 600;
            font-size: 0.85rem;
            border-radius: 50%;
        }}
        
        /* Test Cases */
        .test-cases-section {{
            margin-top: 1.5rem;
        }}
        
        .test-case-header {{
            display: flex;
            align-items: center;
            justify-content: space-between;
            cursor: pointer;
            padding: 1rem;
            background: var(--bg-glass);
            border: 1px solid var(--border-subtle);
            border-radius: 10px;
            margin-top: 0.5rem;
            transition: all 0.2s ease;
        }}
        
        .test-case-header:hover {{
            border-color: rgba(99, 102, 241, 0.3);
        }}
        
        .test-case-title {{
            display: flex;
            align-items: center;
            gap: 0.75rem;
        }}
        
        .test-type-badge {{
            font-size: 0.65rem;
            font-weight: 600;
            padding: 0.25rem 0.5rem;
            border-radius: 4px;
            text-transform: uppercase;
        }}
        
        .test-type-badge.unit {{ background: var(--low); color: white; }}
        .test-type-badge.security {{ background: var(--critical); color: white; }}
        .test-type-badge.integration {{ background: var(--accent-primary); color: white; }}
        
        .test-case-content {{
            display: none;
            padding: 1rem;
            border: 1px solid var(--border-subtle);
            border-top: none;
            border-radius: 0 0 10px 10px;
            background: var(--bg-secondary);
        }}
        
        .test-case-content.show {{
            display: block;
        }}
        
        .test-desc {{
            color: var(--text-secondary);
            margin-bottom: 1rem;
            font-size: 0.9rem;
        }}
        
        .toggle-icon {{
            color: var(--text-muted);
            transition: transform 0.2s ease;
        }}
        
        .test-case-header.active .toggle-icon {{
            transform: rotate(180deg);
        }}
        
        /* Security References */
        .security-refs {{
            display: flex;
            flex-wrap: wrap;
            gap: 0.5rem;
            margin-top: 1rem;
        }}
        
        .ref-tag {{
            background: var(--bg-glass);
            border: 1px solid var(--border-subtle);
            color: var(--accent-primary);
            font-size: 0.8rem;
            padding: 0.35rem 0.75rem;
            border-radius: 6px;
        }}
        
        /* Confidence Bar */
        .confidence-row {{
            display: flex;
            align-items: center;
            gap: 1rem;
            margin: 1rem 0;
        }}
        
        .confidence-bar {{
            flex: 1;
            height: 6px;
            background: var(--bg-glass);
            border-radius: 3px;
            overflow: hidden;
        }}
        
        .confidence-fill {{
            height: 100%;
            background: var(--accent-gradient);
            border-radius: 3px;
            transition: width 0.5s ease;
        }}
        
        .confidence-text {{
            font-size: 0.85rem;
            color: var(--text-secondary);
            min-width: 60px;
        }}
        
        /* Footer */
        .footer {{
            text-align: center;
            padding: 3rem 0;
            margin-top: 3rem;
            border-top: 1px solid var(--border-subtle);
            color: var(--text-muted);
        }}
        
        .footer a {{
            color: var(--accent-primary);
            text-decoration: none;
        }}
        
        /* Animations */
        @keyframes fadeIn {{
            from {{ opacity: 0; transform: translateY(10px); }}
            to {{ opacity: 1; transform: translateY(0); }}
        }}
        
        .vuln-card {{
            animation: fadeIn 0.3s ease forwards;
        }}
        
        /* Responsive */
        @media (max-width: 768px) {{
            .container {{ padding: 1rem; }}
            .risk-score-card {{ padding: 1.5rem 2rem; }}
            .risk-grade {{ font-size: 3.5rem; }}
            .stats-grid {{ grid-template-columns: repeat(2, 1fr); }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <header class="header">
            <h1 class="logo">SASTify</h1>
            <p class="subtitle">AI-Powered Security Analysis Report</p>
            <p class="timestamp">Generated: {datetime.now().strftime("%B %d, %Y at %H:%M:%S")}</p>
        </header>
        
        <div class="risk-score-section">
            <div class="risk-score-card">
                <div class="risk-grade grade-{risk_grade.lower()}">{risk_grade}</div>
                <div class="risk-label">Security Grade</div>
            </div>
        </div>
        
        <div class="stats-grid">
            <div class="stat-card">
                <div class="stat-value">{file_count}</div>
                <div class="stat-label">Files Scanned</div>
            </div>
            <div class="stat-card">
                <div class="stat-value">{len(vulnerabilities)}</div>
                <div class="stat-label">Total Issues</div>
            </div>
            <div class="stat-card critical">
                <div class="stat-value">{severity_counts['critical']}</div>
                <div class="stat-label">Critical</div>
            </div>
            <div class="stat-card high">
                <div class="stat-value">{severity_counts['high']}</div>
                <div class="stat-label">High</div>
            </div>
            <div class="stat-card medium">
                <div class="stat-value">{severity_counts['medium']}</div>
                <div class="stat-label">Medium</div>
            </div>
            <div class="stat-card low">
                <div class="stat-value">{severity_counts['low']}</div>
                <div class="stat-label">Low</div>
            </div>
            <div class="stat-card ai">
                <div class="stat-value">{ai_analyzed_count}</div>
                <div class="stat-label">AI Analyzed</div>
            </div>
            <div class="stat-card ai">
                <div class="stat-value">{ai_confirmed}</div>
                <div class="stat-label">Confirmed</div>
            </div>
        </div>
        
        <div class="section-header">
            <h2>🔍 Vulnerability Details</h2>
            <span class="count">{len(vulnerabilities)} issues</span>
        </div>
'''
        
        # Sort by severity
        sorted_vulns = sorted(
            vulnerabilities,
            key=lambda v: self.SEVERITY_ORDER.index(v.get('severity', 'medium').lower())
        )
        
        for i, vuln in enumerate(sorted_vulns):
            sev = vuln.get('severity', 'Medium').lower()
            vuln_type = vuln.get('type', 'Unknown')
            file_path = vuln.get('file', 'unknown')
            line_num = vuln.get('line', '?')
            snippet = vuln.get('snippet', '').replace('<', '&lt;').replace('>', '&gt;')
            desc = vuln.get('description', '').replace('<', '&lt;').replace('>', '&gt;')
            is_ai_analyzed = vuln.get('ai_analyzed', False)
            is_false_positive = vuln.get('ai_is_false_positive', False)
            
            card_class = f"vuln-card {sev}"
            if is_false_positive:
                card_class += " false-positive"
            
            # Determine file extension for syntax highlighting
            ext = os.path.splitext(file_path)[1].lower()
            lang = self.SUPPORTED_LANGUAGES.get(ext, 'text')
            
            html += f'''
        <div class="{card_class}" style="animation-delay: {i * 0.05}s">
            <div class="vuln-header">
                <div class="vuln-title">
                    <span class="vuln-type">{vuln_type.replace('_', ' ').title()}</span>
                    <span class="vuln-location">📁 {os.path.basename(file_path)} : Line {line_num}</span>
                </div>
                <div class="badges">
                    <span class="badge {sev}">{sev}</span>
'''
            if is_ai_analyzed:
                if is_false_positive:
                    html += '                    <span class="badge fp">🤖 Likely False Positive</span>\n'
                else:
                    html += '                    <span class="badge ai">🤖 AI Verified</span>\n'
            
            html += f'''                </div>
            </div>
            <div class="vuln-body">
                <p style="color: var(--text-secondary); margin-bottom: 1rem;">{desc}</p>
                
                <div class="code-block">
                    <div class="code-header">
                        <span class="code-lang">{lang}</span>
                        <button class="copy-btn" onclick="copyCode(this)">📋 Copy</button>
                    </div>
                    <div class="code-content">{snippet[:500] if snippet else 'No code snippet available'}</div>
                </div>
'''
            
            # Add comprehensive AI Analysis Section
            if is_ai_analyzed:
                ai_explanation = vuln.get('ai_detailed_explanation', vuln.get('ai_explanation', '')).replace('<', '&lt;').replace('>', '&gt;')
                ai_summary = vuln.get('ai_vulnerability_summary', '').replace('<', '&lt;').replace('>', '&gt;')
                ai_fix = vuln.get('ai_fix_suggestion', '').replace('<', '&lt;').replace('>', '&gt;')
                ai_confidence = vuln.get('ai_confidence', 0.5)
                ai_risk = vuln.get('ai_risk_level', sev)
                ai_tests = vuln.get('ai_test_suggestions', [])
                fp_reason = vuln.get('ai_false_positive_reason', '').replace('<', '&lt;').replace('>', '&gt;')
                attack_scenario = vuln.get('ai_attack_scenario', {})
                impact_analysis = vuln.get('ai_impact_analysis', {})
                remediation_steps = vuln.get('ai_remediation_steps', [])
                security_refs = vuln.get('ai_security_references', [])
                
                html += '''
                <div class="ai-analysis">
                    <div class="ai-header">AI Security Analysis</div>
                    
                    <div class="confidence-row">
                        <span class="confidence-text">Confidence</span>
                        <div class="confidence-bar">
                            <div class="confidence-fill" style="width: ''' + str(int(ai_confidence * 100)) + '''%"></div>
                        </div>
                        <span class="confidence-text">''' + str(int(ai_confidence * 100)) + '''%</span>
                    </div>
'''
                
                # False positive reason
                if is_false_positive and fp_reason:
                    html += f'''
                    <div class="info-box success">
                        <div class="info-box-header">✅ Why This Is Likely a False Positive</div>
                        <div class="info-box-content">{fp_reason}</div>
                    </div>
'''
                
                # Detailed Explanation
                if ai_explanation and ai_explanation != 'No explanation provided' and ai_explanation != 'No detailed explanation provided':
                    html += f'''
                    <div class="info-box danger">
                        <div class="info-box-header">⚠️ Why This Is Dangerous</div>
                        <div class="info-box-content"><p>{ai_explanation}</p></div>
                    </div>
'''
                
                # Attack Scenario
                if attack_scenario and isinstance(attack_scenario, dict):
                    attack_desc = attack_scenario.get('description', '').replace('<', '&lt;').replace('>', '&gt;')
                    payloads = attack_scenario.get('example_payloads', [])
                    attacker_goal = attack_scenario.get('attacker_goal', '').replace('<', '&lt;').replace('>', '&gt;')
                    
                    if attack_desc:
                        html += f'''
                    <div class="attack-scenario">
                        <div class="attack-header">🎯 Attack Scenario</div>
                        <p style="color: var(--text-secondary); margin-bottom: 0.75rem;">{attack_desc}</p>
'''
                        if attacker_goal:
                            html += f'                        <p style="color: var(--text-muted); font-size: 0.9rem;"><strong>Attacker Goal:</strong> {attacker_goal}</p>\n'
                        
                        if payloads:
                            html += '                        <div class="attack-payloads">\n'
                            for payload in payloads[:5]:
                                if isinstance(payload, str):
                                    safe_payload = payload.replace('<', '&lt;').replace('>', '&gt;')[:100]
                                    html += f'                            <span class="payload-tag">{safe_payload}</span>\n'
                            html += '                        </div>\n'
                        html += '                    </div>\n'
                
                # Impact Analysis
                if impact_analysis and isinstance(impact_analysis, dict):
                    html += '''
                    <div style="margin: 1.5rem 0;">
                        <h4 style="color: var(--text-primary); margin-bottom: 1rem;">📊 Impact Analysis</h4>
                        <div class="impact-grid">
'''
                    for impact_key in ['confidentiality', 'integrity', 'availability', 'compliance']:
                        impact_val = impact_analysis.get(impact_key, '')
                        if impact_val:
                            safe_val = str(impact_val).replace('<', '&lt;').replace('>', '&gt;')
                            impact_class = 'high' if 'high' in safe_val.lower() else 'medium' if 'medium' in safe_val.lower() else 'low'
                            html += f'''
                            <div class="impact-card">
                                <div class="impact-label">{impact_key.title()}</div>
                                <div class="impact-value {impact_class}">{safe_val[:100]}</div>
                            </div>
'''
                    html += '''                        </div>
                    </div>
'''
                
                # Suggested Fix
                if ai_fix and ai_fix != 'No fix suggested' and not is_false_positive:
                    html += f'''
                    <div style="margin: 1.5rem 0;">
                        <h4 style="color: var(--success); margin-bottom: 1rem;">🔧 Secure Code Fix</h4>
                        <div class="code-block">
                            <div class="code-header">
                                <span class="code-lang">{lang}</span>
                                <button class="copy-btn" onclick="copyCode(this)">📋 Copy Fix</button>
                            </div>
                            <div class="code-content" style="color: #4ade80;">{ai_fix}</div>
                        </div>
                    </div>
'''
                
                # Remediation Steps
                if remediation_steps and len(remediation_steps) > 0:
                    html += '''
                    <div style="margin: 1.5rem 0;">
                        <h4 style="color: var(--text-primary); margin-bottom: 1rem;">📋 Remediation Steps</h4>
                        <ol class="remediation-steps">
'''
                    for step in remediation_steps[:5]:
                        if isinstance(step, str):
                            safe_step = step.replace('<', '&lt;').replace('>', '&gt;')
                            html += f'                            <li><span>{safe_step}</span></li>\n'
                    html += '''                        </ol>
                    </div>
'''
                
                # Test Cases
                if ai_tests and len(ai_tests) > 0:
                    html += '''
                    <div class="test-cases-section">
                        <h4 style="color: var(--text-primary); margin-bottom: 0.5rem;">🧪 Suggested Test Cases</h4>
'''
                    for j, test in enumerate(ai_tests):
                        if isinstance(test, dict):
                            test_type = test.get('type', 'unit')
                            test_name = test.get('name', 'Test Case').replace('<', '&lt;').replace('>', '&gt;')
                            test_desc = test.get('description', '').replace('<', '&lt;').replace('>', '&gt;')
                            test_code = test.get('code', '').replace('<', '&lt;').replace('>', '&gt;')
                            test_inputs = test.get('test_inputs', [])
                            expected = test.get('expected_behavior', '').replace('<', '&lt;').replace('>', '&gt;')
                            
                            html += f'''
                        <div class="test-case-header" onclick="toggleTest(this)">
                            <div class="test-case-title">
                                <span class="test-type-badge {test_type}">{test_type}</span>
                                <span style="font-weight: 500;">{test_name}</span>
                            </div>
                            <span class="toggle-icon">▼</span>
                        </div>
                        <div class="test-case-content">
                            <p class="test-desc">{test_desc}</p>
'''
                            if test_code:
                                html += f'''
                            <div class="code-block">
                                <div class="code-header">
                                    <span class="code-lang">{lang}</span>
                                    <button class="copy-btn" onclick="copyCode(this)">📋 Copy</button>
                                </div>
                                <div class="code-content">{test_code}</div>
                            </div>
'''
                            if test_inputs:
                                html += '                            <p style="margin-top: 0.75rem; color: var(--text-muted);"><strong>Test Inputs:</strong> '
                                html += ', '.join([f'<code style="background: var(--bg-glass); padding: 0.2rem 0.5rem; border-radius: 4px;">{str(inp).replace("<", "&lt;").replace(">", "&gt;")[:50]}</code>' for inp in test_inputs[:5]])
                                html += '</p>\n'
                            if expected:
                                html += f'                            <p style="margin-top: 0.5rem; color: var(--text-muted);"><strong>Expected:</strong> {expected}</p>\n'
                            html += '                        </div>\n'
                    html += '                    </div>\n'
                
                # Security References
                if security_refs and len(security_refs) > 0:
                    html += '''
                    <div style="margin-top: 1.5rem;">
                        <h4 style="color: var(--text-muted); font-size: 0.9rem; margin-bottom: 0.5rem;">Security References</h4>
                        <div class="security-refs">
'''
                    for ref in security_refs[:5]:
                        if isinstance(ref, str):
                            safe_ref = ref.replace('<', '&lt;').replace('>', '&gt;')
                            html += f'                            <span class="ref-tag">{safe_ref}</span>\n'
                    html += '''                        </div>
                    </div>
'''
                
                html += '                </div>\n'  # Close ai-analysis
            
            html += '''            </div>
        </div>
'''
        
        html += '''
        <footer class="footer">
            <p>Generated by <a href="https://github.com/abbyy745-cloud/SASTify">SASTify</a> — AI-Powered Security Analysis</p>
            <p style="margin-top: 0.5rem; font-size: 0.8rem;">Protecting your code, one vulnerability at a time 🛡️</p>
        </footer>
    </div>
    
    <script>
        function copyCode(btn) {
            const codeContent = btn.closest('.code-block').querySelector('.code-content');
            const text = codeContent.textContent;
            navigator.clipboard.writeText(text).then(() => {
                const originalText = btn.textContent;
                btn.textContent = '✓ Copied!';
                btn.style.background = 'var(--success)';
                btn.style.borderColor = 'var(--success)';
                setTimeout(() => {
                    btn.textContent = originalText;
                    btn.style.background = '';
                    btn.style.borderColor = '';
                }, 2000);
            });
        }
        
        function toggleTest(header) {
            const content = header.nextElementSibling;
            header.classList.toggle('active');
            content.classList.toggle('show');
        }
        
        // Auto-expand first test case in each vulnerability
        document.querySelectorAll('.test-cases-section').forEach(section => {
            const firstHeader = section.querySelector('.test-case-header');
            if (firstHeader) {
                firstHeader.click();
            }
        });
    </script>
</body>
</html>'''
        
        return html
    
    def _print_error(self, message: str):
        """Print error message"""
        print(f"{Fore.RED}✗ Error: {message}{Style.RESET_ALL}", file=sys.stderr)


def create_config():
    """Create a sample configuration file"""
    config = {
        "rules": {
            "enable": ["all"],
            "disable": [],
            "severity_override": {}
        },
        "exclude": [
            "**/node_modules/**",
            "**/vendor/**",
            "**/.git/**",
            "**/dist/**",
            "**/build/**",
            "**/__pycache__/**",
            "**/venv/**",
            "**/*.min.js"
        ],
        "languages": ["python", "javascript", "typescript", "java", "swift", "kotlin", "dart", "php"],
        "output": {
            "format": "table",
            "colors": True
        },
        "ci": {
            "fail_on": ["critical", "high"]
        }
    }
    
    with open('.sastifyrc.json', 'w') as f:
        json.dump(config, f, indent=2)
    
    print(f"{Fore.GREEN}✓ Created .sastifyrc.json{Style.RESET_ALL}")


def main():
    """CLI entry point"""
    parser = argparse.ArgumentParser(
        prog='sastify',
        description='SASTify - AI-Powered Security Scanner for Code',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  sastify scan ./src                     Scan directory
  sastify scan ./src -f sarif -o report.sarif   SARIF output
  sastify scan ./src --fail-on critical,high    CI gate
  sastify scan ./src -l python,java      Filter languages
  sastify init                           Create config file
'''
    )
    
    subparsers = parser.add_subparsers(dest='command', help='Commands')
    
    # Scan command
    scan_parser = subparsers.add_parser('scan', help='Scan files for vulnerabilities')
    scan_parser.add_argument('path', help='File or directory to scan')
    scan_parser.add_argument('-f', '--format', 
                            choices=['json', 'sarif', 'table', 'html', 'summary'],
                            default='table',
                            help='Output format (default: table)')
    scan_parser.add_argument('-o', '--output', help='Output file path')
    scan_parser.add_argument('-l', '--languages', 
                            help='Languages to scan (comma-separated)')
    scan_parser.add_argument('-s', '--severity',
                            help='Filter by severity (comma-separated)')
    scan_parser.add_argument('--fail-on',
                            help='Exit with code 1 if vulnerabilities of these severities found')
    scan_parser.add_argument('-e', '--exclude',
                            help='Exclude patterns (comma-separated glob patterns)')
    scan_parser.add_argument('-c', '--config', help='Config file path')
    scan_parser.add_argument('-v', '--verbose', action='store_true',
                            help='Verbose output')
    
    # AI Analysis arguments
    scan_parser.add_argument('-a', '--ai-analysis', action='store_true',
                            help='Enable AI-powered analysis for vulnerabilities')
    scan_parser.add_argument('--api-key',
                            help='DeepSeek API key (or set DEEPSEEK_API_KEY env var)')
    scan_parser.add_argument('--max-ai-issues', type=int, default=20,
                            help='Maximum number of issues to analyze with AI (default: 20)')
    scan_parser.add_argument('--test-report',
                            help='Generate a separate test cases HTML report at this path')
    
    # Init command
    init_parser = subparsers.add_parser('init', help='Create configuration file')
    
    # Version
    parser.add_argument('--version', action='version', version='SASTify 1.0.0')
    
    args = parser.parse_args()
    
    if args.command == 'scan':
        cli = SASTifyCLI()
        sys.exit(cli.run(args))
    elif args.command == 'init':
        create_config()
    else:
        parser.print_help()


if __name__ == '__main__':
    main()
