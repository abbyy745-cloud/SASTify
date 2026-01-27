"""
Swift AST Security Scanner

Real AST-based security analysis for Swift/iOS using tree-sitter.
Provides semantic understanding of code structure for accurate vulnerability detection.

Detection capabilities:
- SQL/Command/Code injection via string interpolation
- Insecure data storage (UserDefaults, Keychain misuse)
- Network security (ATS, certificate pinning)
- Cryptographic issues (weak algorithms, hardcoded keys)
- Authentication flaws
- Memory safety issues
- Information disclosure
"""

from typing import List, Dict, Set, Optional, Any
from dataclasses import dataclass

from tree_sitter_scanner import (
    TreeSitterScanner, MobileLanguage, Vulnerability, TaintInfo,
    TREE_SITTER_AVAILABLE
)

# Fallback to regex analyzer if tree-sitter not available
try:
    from swift_analyzer import SwiftAnalyzer
except ImportError:
    SwiftAnalyzer = None


class SwiftASTScanner(TreeSitterScanner):
    """
    Swift/iOS security scanner using tree-sitter AST.
    Detects vulnerabilities through semantic code analysis.
    """
    
    # Taint sources - user/external input
    TAINT_SOURCES = {
        # URL/Network input
        'URLSession': 'network_request',
        'URLRequest': 'network_request',
        'URLComponents': 'network_request',
        'dataTask': 'network_response',
        'downloadTask': 'network_response',
        
        # User input
        'UITextField': 'user_input',
        'UITextView': 'user_input',
        'textField': 'user_input',
        'text': 'user_input',
        
        # URL scheme / Deep links
        'openURL': 'deep_link',
        'openURLContexts': 'deep_link',
        'userActivity': 'deep_link',
        'webpageURL': 'deep_link',
        'queryItems': 'deep_link',
        
        # Pasteboard
        'UIPasteboard': 'pasteboard',
        'generalPasteboard': 'pasteboard',
        
        # File input
        'contentsOfFile': 'file_input',
        'contentsOf': 'file_input',
        'Data': 'file_input',
    }
    
    # Dangerous sinks - where tainted data shouldn't go
    SINKS = {
        # SQL Injection
        'sqlite3_exec': ('sql_injection', 'CWE-89', 'Critical'),
        'sqlite3_prepare': ('sql_injection', 'CWE-89', 'Critical'),
        'execute': ('sql_injection', 'CWE-89', 'High'),
        'executeQuery': ('sql_injection', 'CWE-89', 'High'),
        'executeUpdate': ('sql_injection', 'CWE-89', 'High'),
        'rawQuery': ('sql_injection', 'CWE-89', 'High'),
        
        # Command Injection
        'Process': ('command_injection', 'CWE-78', 'Critical'),
        'NSTask': ('command_injection', 'CWE-78', 'Critical'),
        'launchPath': ('command_injection', 'CWE-78', 'Critical'),
        'arguments': ('command_injection', 'CWE-78', 'High'),
        
        # XSS / JavaScript Injection
        'evaluateJavaScript': ('xss', 'CWE-79', 'Critical'),
        'loadHTMLString': ('xss', 'CWE-79', 'High'),
        'WKUserScript': ('xss', 'CWE-79', 'High'),
        
        # URL Injection
        'UIApplication.shared.open': ('url_injection', 'CWE-601', 'High'),
        'canOpenURL': ('url_injection', 'CWE-601', 'Medium'),
        
        # File operations
        'write': ('path_traversal', 'CWE-22', 'High'),
        'createFile': ('path_traversal', 'CWE-22', 'High'),
        'moveItem': ('path_traversal', 'CWE-22', 'High'),
        'copyItem': ('path_traversal', 'CWE-22', 'High'),
    }
    
    # Sanitizers that clean tainted data
    SANITIZERS = {
        'addingPercentEncoding': 'url_encoding',
        'replacingOccurrences': 'string_replacement',
        'trimmingCharacters': 'trimming',
        'filter': 'filtering',
        'validate': 'validation',
        'sanitize': 'sanitization',
        'escape': 'escaping',
    }
    
    # Weak cryptography
    WEAK_CRYPTO = {
        'CC_MD5': ('weak_hash', 'CWE-328', 'Medium', 'MD5 is deprecated. Use SHA-256 or SHA-3.'),
        'CC_SHA1': ('weak_hash', 'CWE-328', 'Medium', 'SHA1 is deprecated. Use SHA-256 or SHA-3.'),
        'Insecure.MD5': ('weak_hash', 'CWE-328', 'Medium', 'CryptoKit Insecure.MD5 is weak.'),
        'Insecure.SHA1': ('weak_hash', 'CWE-328', 'Medium', 'CryptoKit Insecure.SHA1 is weak.'),
        'kCCAlgorithmDES': ('weak_cipher', 'CWE-327', 'Critical', 'DES is broken. Use AES-256.'),
        'kCCAlgorithm3DES': ('weak_cipher', 'CWE-327', 'High', '3DES is weak. Use AES-256.'),
        'kCCOptionECBMode': ('weak_mode', 'CWE-327', 'High', 'ECB mode leaks patterns. Use GCM.'),
        'arc4random': ('weak_random', 'CWE-338', 'Low', 'Use SecRandomCopyBytes for crypto.'),
        'drand48': ('weak_random', 'CWE-338', 'High', 'drand48 is predictable.'),
        'rand': ('weak_random', 'CWE-338', 'High', 'rand() is not cryptographically secure.'),
    }
    
    # Insecure data storage
    INSECURE_STORAGE = {
        'UserDefaults': ('insecure_storage', 'CWE-312', 'High', 'UserDefaults is not encrypted.'),
        '@AppStorage': ('insecure_storage', 'CWE-312', 'High', '@AppStorage is not encrypted.'),
        '@SceneStorage': ('insecure_storage', 'CWE-312', 'High', '@SceneStorage is not encrypted.'),
        'NSFileProtectionNone': ('no_file_protection', 'CWE-312', 'High', 'No file protection.'),
        'kSecAttrAccessibleAlways': ('weak_keychain', 'CWE-311', 'High', 'Keychain always accessible.'),
    }
    
    # Network security issues
    NETWORK_ISSUES = {
        'NSAllowsArbitraryLoads': ('ats_disabled', 'CWE-319', 'Critical', 'App Transport Security disabled.'),
        'allowsInsecureHTTPLoads': ('insecure_http', 'CWE-319', 'High', 'Insecure HTTP allowed.'),
        'trustsAllCertificates': ('no_cert_validation', 'CWE-295', 'Critical', 'All certificates trusted.'),
        'disableEvaluation': ('no_ssl_eval', 'CWE-295', 'Critical', 'SSL evaluation disabled.'),
    }
    
    def __init__(self):
        super().__init__(MobileLanguage.SWIFT)
        self.in_function: Optional[str] = None
        self.in_class: Optional[str] = None
        self.string_interpolations: List[Dict] = []
    
    def scan(self, code: str, filename: str = "") -> List[Dict]:
        """Scan Swift code for security vulnerabilities"""
        self.issues = []
        self.tainted_vars = {}
        self.string_interpolations = []
        
        tree = self.parse(code)
        
        if tree is None:
            # Fallback to regex-based analyzer if tree-sitter unavailable
            if SwiftAnalyzer:
                return SwiftAnalyzer().scan(code, filename)
            return []
        
        # Phase 1: Identify taint sources
        self._find_taint_sources(tree)
        
        # Phase 2: Track taint propagation
        self._track_taint_propagation(tree)
        
        # Phase 3: Check for vulnerable sinks
        self._check_sinks(tree)
        
        # Phase 4: Check for hardcoded secrets
        self._check_hardcoded_secrets(tree)
        
        # Phase 5: Check for weak cryptography
        self._check_weak_crypto(tree)
        
        # Phase 6: Check insecure storage
        self._check_insecure_storage(tree, code)
        
        # Phase 7: Check network security
        self._check_network_security(tree, code)
        
        # Phase 8: Check for dangerous patterns
        self._check_dangerous_patterns(tree, code)
        
        return self._to_dict_list(filename)
    
    def _find_taint_sources(self, tree):
        """Find all taint sources in the code"""
        # Look for function calls that return tainted data
        for node in self.find_nodes_by_type(tree, ['call_expression', 'member_expression']):
            text = self.get_node_text(node)
            
            for source, taint_type in self.TAINT_SOURCES.items():
                if source in text:
                    # Find the assigned variable
                    parent = node.parent
                    while parent and parent.type not in ['property_declaration', 'variable_declaration', 'assignment']:
                        parent = parent.parent
                    
                    if parent:
                        # Find the variable name
                        for child in parent.children:
                            if child.type in ['pattern', 'simple_identifier']:
                                var_name = self.get_node_text(child)
                                self.mark_tainted(var_name, source, node.start_point[0] + 1, taint_type)
                                break
    
    def _track_taint_propagation(self, tree):
        """Track how tainted data flows through assignments"""
        for node in self.find_nodes_by_type(tree, ['property_declaration', 'variable_declaration']):
            # Get variable name
            var_name = None
            value_node = None
            
            for child in node.children:
                if child.type in ['pattern', 'simple_identifier']:
                    var_name = self.get_node_text(child)
                elif child.type in ['call_expression', 'simple_identifier', 'binary_expression']:
                    value_node = child
            
            if var_name and value_node:
                value_text = self.get_node_text(value_node)
                
                # Check if value contains tainted variable
                for tainted_var in self.tainted_vars:
                    if tainted_var in value_text:
                        # Check if sanitized
                        is_sanitized = any(san in value_text for san in self.SANITIZERS)
                        
                        if not is_sanitized:
                            self.mark_tainted(
                                var_name,
                                f"propagated from {tainted_var}",
                                node.start_point[0] + 1,
                                self.tainted_vars[tainted_var].taint_type
                            )
                        else:
                            # Mark as sanitized
                            self.mark_tainted(var_name, tainted_var, node.start_point[0] + 1)
                            self.mark_sanitized(var_name, "sanitizer_function")
    
    def _check_sinks(self, tree):
        """Check if tainted data reaches dangerous sinks"""
        for node in self.find_nodes_by_type(tree, ['call_expression']):
            text = self.get_node_text(node)
            
            # Check each sink
            for sink, (vuln_type, cwe, severity) in self.SINKS.items():
                if sink in text:
                    # Check if any argument is tainted
                    args_node = self.get_child_by_field(node, 'arguments') or node
                    args_text = self.get_node_text(args_node)
                    
                    for tainted_var, taint_info in self.tainted_vars.items():
                        if tainted_var in args_text and not taint_info.is_sanitized:
                            self.add_issue(
                                vuln_type=vuln_type,
                                severity=severity,
                                node=node,
                                description=f"{vuln_type.replace('_', ' ').title()}: Tainted variable '{tainted_var}' flows to sink '{sink}'",
                                cwe_id=cwe,
                                confidence=0.9,
                                taint_source=taint_info.source,
                                taint_sink=sink,
                                remediation=self._get_remediation(vuln_type)
                            )
                            break
                    
                    # Also check for string interpolation in sink
                    if '\\(' in text or '${' in text or '+' in text:
                        self.add_issue(
                            vuln_type=vuln_type,
                            severity=severity,
                            node=node,
                            description=f"Potential {vuln_type.replace('_', ' ')}: String interpolation in '{sink}'",
                            cwe_id=cwe,
                            confidence=0.75,
                            taint_sink=sink,
                            remediation=self._get_remediation(vuln_type)
                        )
    
    def _check_hardcoded_secrets(self, tree):
        """Check for hardcoded secrets in code"""
        secret_patterns = [
            ('password', 'hardcoded_password'),
            ('apiKey', 'hardcoded_api_key'),
            ('api_key', 'hardcoded_api_key'),
            ('secret', 'hardcoded_secret'),
            ('token', 'hardcoded_token'),
            ('private_key', 'hardcoded_private_key'),
            ('privateKey', 'hardcoded_private_key'),
        ]
        
        for node in self.find_nodes_by_type(tree, ['property_declaration', 'variable_declaration']):
            text = self.get_node_text(node).lower()
            
            # Skip if in comment
            if self.is_inside_comment(node):
                continue
            
            for pattern, vuln_type in secret_patterns:
                if pattern in text:
                    # Check if assigned a string literal
                    for child in node.children:
                        if child.type == 'line_string_literal' or child.type == 'string_literal':
                            string_content = self.get_node_text(child)
                            
                            # Skip empty, placeholder, or environment variable strings
                            if len(string_content) < 10:
                                continue
                            if 'test' in string_content.lower() or 'example' in string_content.lower():
                                continue
                            if 'Environment' in text or 'env' in text.lower():
                                continue
                            
                            self.add_issue(
                                vuln_type=vuln_type,
                                severity='Critical',
                                node=node,
                                description=f"Hardcoded secret: {pattern} assigned string literal",
                                cwe_id='CWE-798',
                                confidence=0.85,
                                remediation='Store secrets in Keychain with kSecAttrAccessibleWhenUnlockedThisDeviceOnly.'
                            )
                            break
    
    def _check_weak_crypto(self, tree):
        """Check for weak cryptographic algorithms"""
        for node in self.find_nodes_by_type(tree, ['call_expression', 'simple_identifier']):
            text = self.get_node_text(node)
            
            for weak_func, (vuln_type, cwe, severity, remediation) in self.WEAK_CRYPTO.items():
                if weak_func in text:
                    self.add_issue(
                        vuln_type=f'weak_crypto_{vuln_type}',
                        severity=severity,
                        node=node,
                        description=f"Weak cryptography: {weak_func}",
                        cwe_id=cwe,
                        confidence=0.9,
                        remediation=remediation
                    )
    
    def _check_insecure_storage(self, tree, code: str):
        """Check for insecure data storage patterns"""
        sensitive_keywords = ['password', 'token', 'secret', 'key', 'credential', 'auth']
        
        for node in self.find_nodes_by_type(tree, ['call_expression']):
            text = self.get_node_text(node)
            
            for storage, (vuln_type, cwe, severity, desc) in self.INSECURE_STORAGE.items():
                if storage in text:
                    # Check if storing sensitive data
                    line_start = node.start_point[0]
                    code_lines = code.split('\n')
                    context = code_lines[line_start] if line_start < len(code_lines) else ""
                    
                    if any(kw in context.lower() for kw in sensitive_keywords):
                        self.add_issue(
                            vuln_type=vuln_type,
                            severity=severity,
                            node=node,
                            description=f"Insecure storage: Sensitive data in {storage}",
                            cwe_id=cwe,
                            confidence=0.85,
                            remediation='Use Keychain for sensitive data storage.'
                        )
    
    def _check_network_security(self, tree, code: str):
        """Check for network security issues"""
        # Check for cleartext HTTP URLs
        for node in self.find_nodes_by_type(tree, ['line_string_literal', 'string_literal']):
            text = self.get_node_text(node)
            
            if 'http://' in text and 'localhost' not in text and '127.0.0.1' not in text:
                self.add_issue(
                    vuln_type='cleartext_http',
                    severity='High',
                    node=node,
                    description='Cleartext HTTP URL detected',
                    cwe_id='CWE-319',
                    confidence=0.9,
                    remediation='Use HTTPS for all network communications.'
                )
        
        # Check for network config issues
        for issue, (vuln_type, cwe, severity, desc) in self.NETWORK_ISSUES.items():
            if issue in code:
                for node in self.find_nodes_by_type(tree, ['simple_identifier', 'call_expression']):
                    if issue in self.get_node_text(node):
                        self.add_issue(
                            vuln_type=vuln_type,
                            severity=severity,
                            node=node,
                            description=desc,
                            cwe_id=cwe,
                            confidence=0.9,
                            remediation='Enable App Transport Security and implement certificate pinning.'
                        )
                        break
    
    def _check_dangerous_patterns(self, tree, code: str):
        """Check for other dangerous patterns"""
        # Force unwrap detection
        for node in self.find_nodes_by_type(tree, ['force_unwrap_expression']):
            self.add_issue(
                vuln_type='unsafe_optional',
                severity='Low',
                node=node,
                description='Force unwrap (!) can cause crashes',
                cwe_id='CWE-476',
                confidence=0.7,
                remediation='Use optional binding (if let, guard let) instead.'
            )
        
        # UIWebView (deprecated)
        if 'UIWebView' in code:
            for node in self.find_nodes_by_type(tree, ['simple_identifier']):
                if 'UIWebView' in self.get_node_text(node):
                    self.add_issue(
                        vuln_type='deprecated_api',
                        severity='High',
                        node=node,
                        description='UIWebView is deprecated and insecure',
                        cwe_id='CWE-477',
                        confidence=0.95,
                        remediation='Use WKWebView instead.'
                    )
                    break
    
    def _get_remediation(self, vuln_type: str) -> str:
        """Get remediation advice for vulnerability type"""
        return {
            'sql_injection': 'Use parameterized queries with sqlite3_bind_*.',
            'command_injection': 'Avoid Process with user input. Use argument arrays.',
            'xss': 'Sanitize input. Disable JavaScript when not needed.',
            'url_injection': 'Validate URLs. Use allowlists for URL schemes.',
            'path_traversal': 'Validate file paths. Use canonical paths.',
            'hardcoded_password': 'Store in Keychain. Use environment variables.',
            'hardcoded_api_key': 'Store in Keychain or secure config.',
            'hardcoded_secret': 'Use secure secret management.',
            'hardcoded_token': 'Store tokens securely. Rotate regularly.',
        }.get(vuln_type, 'Review and fix the security issue.')


def scan_swift_ast(code: str, filename: str = "") -> List[Dict]:
    """Convenience function to scan Swift code"""
    return SwiftASTScanner().scan(code, filename)
