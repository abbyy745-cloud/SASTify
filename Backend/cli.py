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
                            start = max(0, line_num - 2)
                            end = min(len(lines), line_num + 3)
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
                
                # Add AI results to vulnerability
                vuln['ai_analyzed'] = True
                vuln['ai_explanation'] = ai_result.get('explanation', '')
                vuln['ai_fix_suggestion'] = ai_result.get('suggested_fix', '')
                vuln['ai_is_false_positive'] = not ai_result.get('is_confirmed_vulnerability', True)
                vuln['ai_confidence'] = ai_result.get('confidence', 0.5)
                vuln['ai_risk_level'] = ai_result.get('risk_level', vuln.get('severity', 'Medium'))
                vuln['ai_test_suggestions'] = ai_result.get('suggested_test_cases', [])
                
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
        """Format as HTML report"""
        # Count by severity
        severity_counts = {s: 0 for s in self.SEVERITY_ORDER}
        for v in vulnerabilities:
            sev = v.get('severity', 'medium').lower()
            if sev in severity_counts:
                severity_counts[sev] += 1
        
        html = f'''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SASTify Security Report</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{ 
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, sans-serif;
            background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
            color: #e8e8e8;
            min-height: 100vh;
            padding: 2rem;
        }}
        .container {{ max-width: 1200px; margin: 0 auto; }}
        h1 {{ 
            font-size: 2.5rem; 
            margin-bottom: 1rem;
            background: linear-gradient(90deg, #00d4ff, #7b2ff7);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
        }}
        .summary {{ 
            display: grid; 
            grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
            gap: 1rem;
            margin: 2rem 0;
        }}
        .stat-card {{
            background: rgba(255,255,255,0.05);
            border-radius: 12px;
            padding: 1.5rem;
            text-align: center;
            backdrop-filter: blur(10px);
            border: 1px solid rgba(255,255,255,0.1);
        }}
        .stat-card.critical {{ border-left: 4px solid #ff4757; }}
        .stat-card.high {{ border-left: 4px solid #ff6b6b; }}
        .stat-card.medium {{ border-left: 4px solid #ffa502; }}
        .stat-card.low {{ border-left: 4px solid #3498db; }}
        .stat-value {{ font-size: 2rem; font-weight: bold; }}
        .stat-label {{ color: #888; margin-top: 0.5rem; }}
        .vuln-list {{ margin-top: 2rem; }}
        .vuln-card {{
            background: rgba(255,255,255,0.03);
            border-radius: 8px;
            padding: 1rem 1.5rem;
            margin-bottom: 1rem;
            border-left: 4px solid #666;
        }}
        .vuln-card.critical {{ border-left-color: #ff4757; }}
        .vuln-card.high {{ border-left-color: #ff6b6b; }}
        .vuln-card.medium {{ border-left-color: #ffa502; }}
        .vuln-card.low {{ border-left-color: #3498db; }}
        .vuln-header {{ display: flex; justify-content: space-between; align-items: center; }}
        .vuln-type {{ font-weight: bold; font-size: 1.1rem; }}
        .severity-badge {{
            padding: 0.25rem 0.75rem;
            border-radius: 999px;
            font-size: 0.75rem;
            font-weight: bold;
            text-transform: uppercase;
        }}
        .severity-badge.critical {{ background: #ff4757; }}
        .severity-badge.high {{ background: #ff6b6b; }}
        .severity-badge.medium {{ background: #ffa502; color: #000; }}
        .severity-badge.low {{ background: #3498db; }}
        .vuln-location {{ color: #888; margin: 0.5rem 0; font-size: 0.9rem; }}
        .vuln-snippet {{ 
            background: rgba(0,0,0,0.3); 
            padding: 0.75rem; 
            border-radius: 4px;
            font-family: monospace;
            overflow-x: auto;
            margin: 0.5rem 0;
        }}
        .vuln-desc {{ color: #aaa; font-size: 0.9rem; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>🔒 SASTify Security Report</h1>
        <p>Generated: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</p>
        
        <div class="summary">
            <div class="stat-card">
                <div class="stat-value">{file_count}</div>
                <div class="stat-label">Files Scanned</div>
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
        </div>
        
        <div class="vuln-list">
            <h2>Vulnerabilities</h2>
'''
        
        # Sort by severity
        sorted_vulns = sorted(
            vulnerabilities,
            key=lambda v: self.SEVERITY_ORDER.index(v.get('severity', 'medium').lower())
        )
        
        for vuln in sorted_vulns:
            sev = vuln.get('severity', 'Medium').lower()
            snippet = vuln.get('snippet', '').replace('<', '&lt;').replace('>', '&gt;')
            desc = vuln.get('description', '').replace('<', '&lt;').replace('>', '&gt;')
            
            html += f'''
            <div class="vuln-card {sev}">
                <div class="vuln-header">
                    <span class="vuln-type">{vuln.get('type', 'Unknown')}</span>
                    <span class="severity-badge {sev}">{sev}</span>
                </div>
                <div class="vuln-location">📁 {vuln.get('file', 'unknown')} : Line {vuln.get('line', '?')}</div>
                <div class="vuln-snippet">{snippet[:200]}</div>
                <div class="vuln-desc">{desc}</div>
            </div>
'''
        
        html += '''
        </div>
    </div>
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
