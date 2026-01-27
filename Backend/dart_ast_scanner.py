"""
Dart AST Security Scanner

Real AST-based security analysis for Dart/Flutter using tree-sitter.
Provides semantic understanding of code structure for accurate vulnerability detection.

Detection capabilities:
- Platform channel injection
- Insecure storage (SharedPreferences, flutter_secure_storage)
- Network security (HTTP, certificate pinning)
- WebView vulnerabilities
- Deep link injection
- Cryptographic issues
"""

from typing import List, Dict, Set, Optional, Any
from dataclasses import dataclass

from tree_sitter_scanner import (
    TreeSitterScanner, MobileLanguage, Vulnerability, TaintInfo,
    TREE_SITTER_AVAILABLE
)

# Fallback to regex analyzer if tree-sitter not available
try:
    from dart_analyzer import DartAnalyzer
except ImportError:
    DartAnalyzer = None


class DartASTScanner(TreeSitterScanner):
    """
    Dart/Flutter security scanner using tree-sitter AST.
    """
    
    # Taint sources
    TAINT_SOURCES = {
        # Platform channels
        'MethodChannel': 'platform_channel',
        'invokeMethod': 'platform_channel',
        'setMethodCallHandler': 'platform_channel',
        'EventChannel': 'platform_channel',
        
        # Deep links
        'getInitialLink': 'deep_link',
        'linkStream': 'deep_link',
        'getInitialUri': 'deep_link',
        'uriLinkStream': 'deep_link',
        
        # User input
        'TextEditingController': 'user_input',
        'controller.text': 'user_input',
        'TextField': 'user_input',
        'TextFormField': 'user_input',
        
        # Network
        'Response': 'network_response',
        'http.get': 'network_response',
        'http.post': 'network_response',
        'dio': 'network_response',
        
        # File input
        'File': 'file_input',
        'readAsString': 'file_input',
        'readAsBytes': 'file_input',
    }
    
    # Dangerous sinks
    SINKS = {
        # SQL Injection (sqflite)
        'rawQuery': ('sql_injection', 'CWE-89', 'Critical'),
        'rawInsert': ('sql_injection', 'CWE-89', 'Critical'),
        'rawUpdate': ('sql_injection', 'CWE-89', 'Critical'),
        'rawDelete': ('sql_injection', 'CWE-89', 'Critical'),
        'execute': ('sql_injection', 'CWE-89', 'High'),
        
        # Platform channel (native code injection)
        'invokeMethod': ('platform_injection', 'CWE-78', 'High'),
        
        # WebView
        'loadUrl': ('webview_injection', 'CWE-749', 'High'),
        'evaluateJavascript': ('xss', 'CWE-79', 'Critical'),
        'loadHtmlString': ('xss', 'CWE-79', 'High'),
        'runJavaScript': ('xss', 'CWE-79', 'Critical'),
        
        # URL Launcher
        'launch': ('url_injection', 'CWE-601', 'High'),
        'launchUrl': ('url_injection', 'CWE-601', 'High'),
        'canLaunch': ('url_injection', 'CWE-601', 'Low'),
        
        # File operations
        'File': ('path_traversal', 'CWE-22', 'High'),
        'writeAsString': ('path_traversal', 'CWE-22', 'High'),
        'writeAsBytes': ('path_traversal', 'CWE-22', 'High'),
        
        # HTML Parsing
        'innerHtml': ('xss', 'CWE-79', 'High'),
        'setInnerHtml': ('xss', 'CWE-79', 'High'),
    }
    
    # Sanitizers
    SANITIZERS = {
        'Uri.encodeComponent': 'url_encoding',
        'HtmlEscape': 'html_escape',
        'htmlEscape': 'html_escape',
        'sanitize': 'sanitization',
        'validate': 'validation',
        'escape': 'escaping',
    }
    
    # Weak crypto
    WEAK_CRYPTO = {
        'md5': ('weak_hash', 'CWE-328', 'Medium', 'MD5 is deprecated.'),
        'sha1': ('weak_hash', 'CWE-328', 'Medium', 'SHA1 is deprecated.'),
        'Random()': ('insecure_random', 'CWE-338', 'High', 'Use Random.secure().'),
        'Random.secure': ('secure_random', 'CWE-338', 'Info', 'Secure random is good.'),
    }
    
    # Insecure storage
    INSECURE_STORAGE = {
        'SharedPreferences': ('shared_prefs', 'CWE-312', 'High', 'SharedPreferences not encrypted.'),
        'setString': ('shared_prefs_write', 'CWE-312', 'Medium', 'Check if storing sensitive data.'),
        'FlutterSecureStorage': ('secure_storage', 'CWE-312', 'Info', 'Secure storage is good.'),
    }
    
    # Network issues
    NETWORK_ISSUES = {
        'http://': ('cleartext_http', 'CWE-319', 'High', 'Cleartext HTTP.'),
        'allowBadCertificates': ('bad_cert', 'CWE-295', 'Critical', 'Bad certificates allowed.'),
        'badCertificateCallback': ('custom_cert', 'CWE-295', 'High', 'Custom certificate callback.'),
    }
    
    def __init__(self):
        super().__init__(MobileLanguage.DART)
        self.in_function: Optional[str] = None
        self.in_class: Optional[str] = None
        self.async_functions: Set[str] = set()
    
    def scan(self, code: str, filename: str = "") -> List[Dict]:
        """Scan Dart code for security vulnerabilities"""
        self.issues = []
        self.tainted_vars = {}
        self.async_functions = set()
        
        tree = self.parse(code)
        
        if tree is None:
            # Fallback to regex analyzer
            if DartAnalyzer:
                return DartAnalyzer().scan(code, filename)
            return []
        
        # Multi-phase analysis
        self._find_taint_sources(tree)
        self._track_taint_propagation(tree)
        self._check_sinks(tree, code)
        self._check_hardcoded_secrets(tree)
        self._check_weak_crypto(tree, code)
        self._check_insecure_storage(tree, code)
        self._check_network_security(tree, code)
        self._check_webview_security(tree, code)
        self._check_platform_channels(tree, code)
        
        return self._to_dict_list(filename)
    
    def _find_taint_sources(self, tree):
        """Find all taint sources in the code"""
        for node in self.find_nodes_by_type(tree, [
            'method_invocation', 
            'function_expression_invocation',
            'identifier'
        ]):
            text = self.get_node_text(node)
            
            for source, taint_type in self.TAINT_SOURCES.items():
                if source in text:
                    # Find assigned variable
                    parent = node.parent
                    while parent and parent.type not in [
                        'variable_declaration',
                        'initialized_variable_definition',
                        'assignment_expression'
                    ]:
                        parent = parent.parent
                    
                    if parent:
                        # Extract variable name
                        for child in parent.children:
                            if child.type == 'identifier':
                                var_name = self.get_node_text(child)
                                if var_name not in ['var', 'final', 'const', 'late']:
                                    self.mark_tainted(var_name, source, node.start_point[0] + 1, taint_type)
                                break
    
    def _track_taint_propagation(self, tree):
        """Track taint through assignments"""
        for node in self.find_nodes_by_type(tree, [
            'variable_declaration',
            'initialized_variable_definition',
            'assignment_expression'
        ]):
            text = self.get_node_text(node)
            
            if '=' in text:
                parts = text.split('=', 1)
                var_part = parts[0].strip()
                value_part = parts[1].strip() if len(parts) > 1 else ""
                
                # Extract variable name
                var_tokens = var_part.split()
                var_name = var_tokens[-1] if var_tokens else None
                
                if var_name and value_part and var_name not in ['var', 'final', 'const']:
                    for tainted_var, taint_info in list(self.tainted_vars.items()):
                        if tainted_var in value_part:
                            is_sanitized = any(san in value_part for san in self.SANITIZERS)
                            
                            if not is_sanitized:
                                self.mark_tainted(
                                    var_name,
                                    f"propagated from {tainted_var}",
                                    node.start_point[0] + 1,
                                    taint_info.taint_type
                                )
                            else:
                                self.mark_tainted(var_name, tainted_var, node.start_point[0] + 1)
                                self.mark_sanitized(var_name, "sanitizer")
    
    def _check_sinks(self, tree, code: str):
        """Check if tainted data reaches sinks"""
        for node in self.find_nodes_by_type(tree, ['method_invocation', 'function_expression_invocation']):
            text = self.get_node_text(node)
            
            for sink, (vuln_type, cwe, severity) in self.SINKS.items():
                if sink in text:
                    found_taint = False
                    
                    for tainted_var, taint_info in self.tainted_vars.items():
                        if tainted_var in text and not taint_info.is_sanitized:
                            self.add_issue(
                                vuln_type=vuln_type,
                                severity=severity,
                                node=node,
                                description=f"{vuln_type.replace('_', ' ').title()}: '{tainted_var}' flows to '{sink}'",
                                cwe_id=cwe,
                                confidence=0.9,
                                taint_source=taint_info.source,
                                taint_sink=sink,
                                remediation=self._get_remediation(vuln_type)
                            )
                            found_taint = True
                            break
                    
                    # Check for string interpolation
                    if not found_taint and ('$' in text or '+' in text):
                        self.add_issue(
                            vuln_type=vuln_type,
                            severity=severity,
                            node=node,
                            description=f"Potential {vuln_type.replace('_', ' ')}: String interpolation in '{sink}'",
                            cwe_id=cwe,
                            confidence=0.7,
                            taint_sink=sink,
                            remediation=self._get_remediation(vuln_type)
                        )
    
    def _check_hardcoded_secrets(self, tree):
        """Check for hardcoded secrets"""
        secret_patterns = [
            ('password', 'hardcoded_password'),
            ('apiKey', 'hardcoded_api_key'),
            ('api_key', 'hardcoded_api_key'),
            ('secret', 'hardcoded_secret'),
            ('token', 'hardcoded_token'),
            ('privateKey', 'hardcoded_private_key'),
        ]
        
        for node in self.find_nodes_by_type(tree, [
            'variable_declaration',
            'initialized_variable_definition'
        ]):
            if self.is_inside_comment(node):
                continue
            
            text = self.get_node_text(node)
            text_lower = text.lower()
            
            for pattern, vuln_type in secret_patterns:
                if pattern.lower() in text_lower:
                    # Check for string literal
                    if "'" in text or '"' in text:
                        # Extract string value
                        import re
                        strings = re.findall(r'["\']([^"\']{10,})["\']', text)
                        
                        for s in strings:
                            if 'test' in s.lower() or 'example' in s.lower():
                                continue
                            if 'Environment' in text or 'dotenv' in text:
                                continue
                            
                            self.add_issue(
                                vuln_type=vuln_type,
                                severity='Critical',
                                node=node,
                                description=f"Hardcoded secret: {pattern}",
                                cwe_id='CWE-798',
                                confidence=0.85,
                                remediation='Use flutter_secure_storage or environment variables.'
                            )
                            break
    
    def _check_weak_crypto(self, tree, code: str):
        """Check for weak cryptography"""
        for pattern, (vuln_type, cwe, severity, desc) in self.WEAK_CRYPTO.items():
            if severity == 'Info':
                continue
            
            if pattern in code:
                for node in self.find_nodes_by_type(tree, ['identifier', 'method_invocation']):
                    if pattern in self.get_node_text(node):
                        self.add_issue(
                            vuln_type=f'weak_crypto_{vuln_type}',
                            severity=severity,
                            node=node,
                            description=desc,
                            cwe_id=cwe,
                            confidence=0.9,
                            remediation='Use SHA-256 and Random.secure().'
                        )
                        break
    
    def _check_insecure_storage(self, tree, code: str):
        """Check for insecure storage"""
        sensitive_keywords = ['password', 'token', 'secret', 'key', 'credential', 'auth']
        
        for node in self.find_nodes_by_type(tree, ['method_invocation']):
            text = self.get_node_text(node)
            
            for storage, (vuln_type, cwe, severity, desc) in self.INSECURE_STORAGE.items():
                if severity == 'Info':
                    continue
                
                if storage in text:
                    # Check context
                    line_num = node.start_point[0]
                    code_lines = code.split('\n')
                    context = code_lines[line_num] if line_num < len(code_lines) else ""
                    
                    if any(kw in context.lower() for kw in sensitive_keywords):
                        self.add_issue(
                            vuln_type=vuln_type,
                            severity=severity,
                            node=node,
                            description=f"Sensitive data in {storage}",
                            cwe_id=cwe,
                            confidence=0.85,
                            remediation='Use flutter_secure_storage for sensitive data.'
                        )
    
    def _check_network_security(self, tree, code: str):
        """Check for network security issues"""
        for pattern, (vuln_type, cwe, severity, desc) in self.NETWORK_ISSUES.items():
            if pattern in code:
                if pattern == 'http://' and ('localhost' in code or '127.0.0.1' in code):
                    continue
                
                for node in self.find_nodes_by_type(tree, ['string_literal', 'identifier']):
                    node_text = self.get_node_text(node)
                    if pattern in node_text:
                        if pattern == 'http://' and ('localhost' in node_text or '127.0.0.1' in node_text):
                            continue
                        
                        self.add_issue(
                            vuln_type=vuln_type,
                            severity=severity,
                            node=node,
                            description=desc,
                            cwe_id=cwe,
                            confidence=0.9,
                            remediation='Use HTTPS with certificate pinning.'
                        )
                        break
    
    def _check_webview_security(self, tree, code: str):
        """Check for WebView security issues"""
        webview_issues = {
            'javascriptMode: JavascriptMode.unrestricted': ('js_unrestricted', 'CWE-749', 'Medium', 'JavaScript unrestricted in WebView.'),
            'gestureNavigationEnabled: true': ('gesture_nav', 'CWE-749', 'Low', 'Gesture navigation enabled.'),
        }
        
        for pattern, (vuln_type, cwe, severity, desc) in webview_issues.items():
            if pattern in code:
                for node in self.find_nodes_by_type(tree, ['named_argument', 'argument']):
                    if pattern in self.get_node_text(node):
                        self.add_issue(
                            vuln_type=vuln_type,
                            severity=severity,
                            node=node,
                            description=desc,
                            cwe_id=cwe,
                            confidence=0.9,
                            remediation='Restrict JavaScript when not needed.'
                        )
                        break
    
    def _check_platform_channels(self, tree, code: str):
        """Check for platform channel security"""
        if 'MethodChannel' in code or 'EventChannel' in code:
            for node in self.find_nodes_by_type(tree, ['method_invocation']):
                text = self.get_node_text(node)
                
                if 'invokeMethod' in text:
                    # Check if passing user input directly
                    for tainted_var, taint_info in self.tainted_vars.items():
                        if tainted_var in text and not taint_info.is_sanitized:
                            self.add_issue(
                                vuln_type='platform_channel_injection',
                                severity='High',
                                node=node,
                                description=f"Tainted data '{tainted_var}' passed to platform channel",
                                cwe_id='CWE-78',
                                confidence=0.85,
                                taint_source=taint_info.source,
                                remediation='Validate data before sending to native code.'
                            )
                            break
    
    def _get_remediation(self, vuln_type: str) -> str:
        """Get remediation advice"""
        return {
            'sql_injection': 'Use parameterized queries with sqflite.',
            'platform_injection': 'Validate data before platform channel calls.',
            'xss': 'Sanitize HTML. Avoid evaluateJavascript with user data.',
            'url_injection': 'Validate URLs. Use allowlist.',
            'path_traversal': 'Validate paths. Use path package.',
            'webview_injection': 'Restrict JavaScript. Validate URLs.',
            'hardcoded_password': 'Use flutter_secure_storage.',
        }.get(vuln_type, 'Review and fix the security issue.')


def scan_dart_ast(code: str, filename: str = "") -> List[Dict]:
    """Convenience function to scan Dart code"""
    return DartASTScanner().scan(code, filename)
