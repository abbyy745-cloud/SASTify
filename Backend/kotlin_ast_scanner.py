"""
Kotlin AST Security Scanner

Real AST-based security analysis for Kotlin/Android using tree-sitter.
Provides semantic understanding of code structure for accurate vulnerability detection.

Detection capabilities:
- SQL/Intent/Command injection
- Insecure data storage (SharedPreferences, Room)
- Network security (SSL/TLS, certificate pinning)
- Cryptographic issues
- Component security (exported, permissions)
- WebView vulnerabilities
- Coroutine safety
"""

from typing import List, Dict, Set, Optional, Any
from dataclasses import dataclass

from tree_sitter_scanner import (
    TreeSitterScanner, MobileLanguage, Vulnerability, TaintInfo,
    TREE_SITTER_AVAILABLE
)

# Fallback to regex analyzer if tree-sitter not available
try:
    from kotlin_analyzer import KotlinAnalyzer
except ImportError:
    KotlinAnalyzer = None


class KotlinASTScanner(TreeSitterScanner):
    """
    Kotlin/Android security scanner using tree-sitter AST.
    Detects vulnerabilities through semantic code analysis.
    """
    
    # Taint sources - user/external input
    TAINT_SOURCES = {
        # Intent data
        'intent.data': 'deep_link',
        'intent.extras': 'intent_extra',
        'getStringExtra': 'intent_extra',
        'getIntExtra': 'intent_extra',
        'getBundleExtra': 'intent_extra',
        'getParcelableExtra': 'intent_extra',
        'getQueryParameter': 'deep_link_param',
        
        # User input
        'EditText': 'user_input',
        'getText()': 'user_input',
        '.text': 'user_input',
        'TextField': 'user_input',
        
        # Network
        'Response': 'network_response',
        'body()': 'network_response',
        'string()': 'network_response',
        'ResponseBody': 'network_response',
        
        # Clipboard
        'ClipboardManager': 'clipboard',
        'getPrimaryClip': 'clipboard',
        
        # SharedPreferences (potentially dangerous source)
        'getString': 'shared_prefs',
        'getInt': 'shared_prefs',
    }
    
    # Dangerous sinks
    SINKS = {
        # SQL Injection
        'rawQuery': ('sql_injection', 'CWE-89', 'Critical'),
        'execSQL': ('sql_injection', 'CWE-89', 'Critical'),
        'compileStatement': ('sql_injection', 'CWE-89', 'Critical'),
        'query': ('sql_injection', 'CWE-89', 'High'),
        'SimpleSQLiteQuery': ('sql_injection', 'CWE-89', 'High'),
        '@Query': ('sql_injection_room', 'CWE-89', 'High'),
        
        # Command Injection
        'Runtime.getRuntime().exec': ('command_injection', 'CWE-78', 'Critical'),
        'ProcessBuilder': ('command_injection', 'CWE-78', 'Critical'),
        
        # Intent Injection
        'startActivity': ('intent_injection', 'CWE-926', 'High'),
        'startActivityForResult': ('intent_injection', 'CWE-926', 'High'),
        'sendBroadcast': ('broadcast_injection', 'CWE-926', 'High'),
        'startService': ('service_injection', 'CWE-926', 'High'),
        'setComponent': ('component_injection', 'CWE-926', 'High'),
        'setClassName': ('component_injection', 'CWE-926', 'High'),
        'Intent.parseUri': ('intent_uri_injection', 'CWE-926', 'Critical'),
        
        # WebView
        'loadUrl': ('webview_injection', 'CWE-749', 'High'),
        'loadData': ('webview_injection', 'CWE-749', 'High'),
        'evaluateJavascript': ('xss', 'CWE-79', 'Critical'),
        'addJavascriptInterface': ('js_interface', 'CWE-749', 'High'),
        
        # Path Traversal
        'File': ('path_traversal', 'CWE-22', 'High'),
        'FileInputStream': ('path_traversal', 'CWE-22', 'High'),
        'FileOutputStream': ('path_traversal', 'CWE-22', 'High'),
        'openFileInput': ('path_traversal', 'CWE-22', 'High'),
        'openFileOutput': ('path_traversal', 'CWE-22', 'High'),
    }
    
    # Sanitizers
    SANITIZERS = {
        'replace': 'string_replacement',
        'filter': 'filtering',
        'trim': 'trimming',
        'sanitize': 'sanitization',
        'validate': 'validation',
        'escape': 'escaping',
        'encode': 'encoding',
        'URLEncoder.encode': 'url_encoding',
    }
    
    # Weak cryptography
    WEAK_CRYPTO = {
        'Cipher.getInstance("DES"': ('weak_cipher', 'CWE-327', 'Critical', 'DES is broken. Use AES-256.'),
        'Cipher.getInstance("DESede"': ('weak_cipher', 'CWE-327', 'High', '3DES is weak. Use AES-256.'),
        'Cipher.getInstance("AES")': ('ecb_mode', 'CWE-327', 'High', 'Default AES uses ECB. Specify GCM.'),
        'ECB': ('ecb_mode', 'CWE-327', 'High', 'ECB mode leaks patterns. Use GCM.'),
        'MessageDigest.getInstance("MD5"': ('weak_hash', 'CWE-328', 'Medium', 'MD5 is deprecated.'),
        'MessageDigest.getInstance("SHA-1"': ('weak_hash', 'CWE-328', 'Medium', 'SHA-1 is deprecated.'),
        'Random()': ('insecure_random', 'CWE-338', 'High', 'Use SecureRandom for security.'),
        'kotlin.random.Random': ('insecure_random', 'CWE-338', 'High', 'Use SecureRandom for security.'),
        'Math.random()': ('insecure_random', 'CWE-338', 'High', 'Math.random is predictable.'),
    }
    
    # Insecure configurations
    INSECURE_CONFIG = {
        'MODE_WORLD_READABLE': ('world_readable', 'CWE-732', 'Critical', 'World-readable files are insecure.'),
        'MODE_WORLD_WRITEABLE': ('world_writeable', 'CWE-732', 'Critical', 'World-writeable files are insecure.'),
        'android:exported="true"': ('exported_component', 'CWE-926', 'Medium', 'Exported component needs protection.'),
        'android:debuggable="true"': ('debuggable', 'CWE-215', 'High', 'Debuggable builds expose internals.'),
        'android:allowBackup="true"': ('backup_enabled', 'CWE-530', 'Medium', 'Backup may leak sensitive data.'),
        'setJavaScriptEnabled(true)': ('js_enabled', 'CWE-749', 'Medium', 'JavaScript in WebView is risky.'),
        'setAllowFileAccess(true)': ('file_access', 'CWE-749', 'High', 'File access in WebView is risky.'),
        'setAllowUniversalAccessFromFileURLs(true)': ('universal_access', 'CWE-749', 'Critical', 'Universal file access is dangerous.'),
    }
    
    # SSL/TLS issues
    SSL_ISSUES = {
        'checkServerTrusted': ('custom_trust', 'CWE-295', 'High', 'Custom TrustManager may bypass validation.'),
        'HostnameVerifier': ('custom_hostname', 'CWE-295', 'High', 'Custom HostnameVerifier may bypass validation.'),
        'ALLOW_ALL_HOSTNAME_VERIFIER': ('hostname_bypass', 'CWE-295', 'Critical', 'All hostnames allowed.'),
        'http://': ('cleartext_http', 'CWE-319', 'High', 'Cleartext HTTP transmission.'),
        'usesCleartextTraffic': ('cleartext_traffic', 'CWE-319', 'High', 'Cleartext traffic allowed.'),
    }
    
    def __init__(self):
        super().__init__(MobileLanguage.KOTLIN)
        self.in_function: Optional[str] = None
        self.in_class: Optional[str] = None
        self.suspend_functions: Set[str] = set()
    
    def scan(self, code: str, filename: str = "") -> List[Dict]:
        """Scan Kotlin code for security vulnerabilities"""
        self.issues = []
        self.tainted_vars = {}
        self.suspend_functions = set()
        
        tree = self.parse(code)
        
        if tree is None:
            # Fallback to regex-based analyzer
            if KotlinAnalyzer:
                return KotlinAnalyzer().scan(code, filename)
            return []
        
        # Multi-phase analysis
        self._find_taint_sources(tree)
        self._track_taint_propagation(tree)
        self._check_sinks(tree, code)
        self._check_hardcoded_secrets(tree)
        self._check_weak_crypto(tree, code)
        self._check_insecure_config(tree, code)
        self._check_ssl_issues(tree, code)
        self._check_component_security(tree, code)
        self._check_coroutine_safety(tree)
        self._check_null_safety(tree)
        
        return self._to_dict_list(filename)
    
    def _find_taint_sources(self, tree):
        """Find all taint sources in the code"""
        for node in self.find_nodes_by_type(tree, ['call_expression', 'navigation_expression']):
            text = self.get_node_text(node)
            
            for source, taint_type in self.TAINT_SOURCES.items():
                if source in text:
                    # Find assigned variable
                    parent = node.parent
                    while parent and parent.type not in ['property_declaration', 'variable_declaration']:
                        parent = parent.parent
                    
                    if parent:
                        for child in parent.children:
                            if child.type in ['simple_identifier', 'variable_declaration']:
                                var_text = self.get_node_text(child)
                                # Extract variable name
                                if '=' in var_text:
                                    var_name = var_text.split('=')[0].strip().split()[-1]
                                else:
                                    var_name = var_text.strip()
                                
                                if var_name and var_name not in ['val', 'var', 'let']:
                                    self.mark_tainted(var_name, source, node.start_point[0] + 1, taint_type)
                                break
    
    def _track_taint_propagation(self, tree):
        """Track taint through variable assignments"""
        for node in self.find_nodes_by_type(tree, ['property_declaration', 'variable_declaration', 'assignment']):
            text = self.get_node_text(node)
            
            # Find variable name and value
            if '=' in text:
                parts = text.split('=', 1)
                var_part = parts[0].strip()
                value_part = parts[1].strip() if len(parts) > 1 else ""
                
                # Extract variable name
                var_name = var_part.split()[-1] if var_part.split() else None
                
                if var_name and value_part:
                    # Check if value contains tainted variable
                    for tainted_var, taint_info in list(self.tainted_vars.items()):
                        if tainted_var in value_part:
                            # Check for sanitization
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
        """Check if tainted data reaches dangerous sinks"""
        for node in self.find_nodes_by_type(tree, ['call_expression', 'navigation_expression']):
            text = self.get_node_text(node)
            
            for sink, (vuln_type, cwe, severity) in self.SINKS.items():
                if sink in text:
                    # Check for tainted arguments
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
                    
                    # Check for string interpolation/concatenation
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
            ('private_key', 'hardcoded_private_key'),
        ]
        
        for node in self.find_nodes_by_type(tree, ['property_declaration', 'variable_declaration']):
            if self.is_inside_comment(node):
                continue
            
            text = self.get_node_text(node)
            text_lower = text.lower()
            
            for pattern, vuln_type in secret_patterns:
                if pattern.lower() in text_lower:
                    # Check for string literal assignment
                    for child in node.children:
                        if child.type in ['string_literal', 'line_string_literal']:
                            string_val = self.get_node_text(child)
                            
                            if len(string_val) < 10:
                                continue
                            if 'test' in string_val.lower() or 'example' in string_val.lower():
                                continue
                            if 'BuildConfig' in text or 'getString(' in text:
                                continue
                            
                            self.add_issue(
                                vuln_type=vuln_type,
                                severity='Critical',
                                node=node,
                                description=f"Hardcoded secret: {pattern} assigned string literal",
                                cwe_id='CWE-798',
                                confidence=0.85,
                                remediation='Use EncryptedSharedPreferences or Android Keystore.'
                            )
                            break
    
    def _check_weak_crypto(self, tree, code: str):
        """Check for weak cryptographic usage"""
        for pattern, (vuln_type, cwe, severity, desc) in self.WEAK_CRYPTO.items():
            if pattern in code:
                for node in self.find_nodes_by_type(tree, ['call_expression', 'simple_identifier']):
                    if pattern in self.get_node_text(node):
                        self.add_issue(
                            vuln_type=f'weak_crypto_{vuln_type}',
                            severity=severity,
                            node=node,
                            description=desc,
                            cwe_id=cwe,
                            confidence=0.9,
                            remediation='Use AES-256-GCM with SecureRandom.'
                        )
                        break
    
    def _check_insecure_config(self, tree, code: str):
        """Check for insecure configurations"""
        for pattern, (vuln_type, cwe, severity, desc) in self.INSECURE_CONFIG.items():
            if pattern in code:
                for node in self.find_nodes_by_type(tree, ['call_expression', 'simple_identifier', 'string_literal']):
                    if pattern in self.get_node_text(node):
                        self.add_issue(
                            vuln_type=vuln_type,
                            severity=severity,
                            node=node,
                            description=desc,
                            cwe_id=cwe,
                            confidence=0.9,
                            remediation='Review and fix configuration.'
                        )
                        break
    
    def _check_ssl_issues(self, tree, code: str):
        """Check for SSL/TLS issues"""
        for pattern, (vuln_type, cwe, severity, desc) in self.SSL_ISSUES.items():
            if pattern in code:
                # Skip localhost HTTP
                if pattern == 'http://' and ('localhost' in code or '127.0.0.1' in code):
                    continue
                
                for node in self.find_nodes_by_type(tree, ['call_expression', 'simple_identifier', 'string_literal']):
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
    
    def _check_component_security(self, tree, code: str):
        """Check for Android component security issues"""
        # Check for PendingIntent without FLAG_IMMUTABLE
        if 'PendingIntent' in code:
            for node in self.find_nodes_by_type(tree, ['call_expression']):
                text = self.get_node_text(node)
                if 'PendingIntent' in text:
                    if 'FLAG_IMMUTABLE' not in text and 'FLAG_MUTABLE' not in text:
                        # Check context (Android 12+ requires these flags)
                        self.add_issue(
                            vuln_type='pending_intent_mutable',
                            severity='High',
                            node=node,
                            description='PendingIntent without FLAG_IMMUTABLE/FLAG_MUTABLE',
                            cwe_id='CWE-926',
                            confidence=0.8,
                            remediation='Add FLAG_IMMUTABLE for security.'
                        )
    
    def _check_coroutine_safety(self, tree):
        """Check for coroutine safety issues"""
        for node in self.find_nodes_by_type(tree, ['call_expression']):
            text = self.get_node_text(node)
            
            if 'GlobalScope.launch' in text or 'GlobalScope.async' in text:
                self.add_issue(
                    vuln_type='global_scope_usage',
                    severity='Medium',
                    node=node,
                    description='GlobalScope can cause memory leaks',
                    cwe_id='CWE-401',
                    confidence=0.7,
                    remediation='Use viewModelScope or lifecycleScope instead.'
                )
    
    def _check_null_safety(self, tree):
        """Check for null safety issues"""
        for node in self.find_nodes_by_type(tree, ['postfix_unary_expression']):
            text = self.get_node_text(node)
            
            if '!!' in text:
                self.add_issue(
                    vuln_type='null_assertion',
                    severity='Low',
                    node=node,
                    description='Non-null assertion (!!) can cause crashes',
                    cwe_id='CWE-476',
                    confidence=0.6,
                    remediation='Use safe call (?.) or let { } block.'
                )
    
    def _get_remediation(self, vuln_type: str) -> str:
        """Get remediation advice"""
        return {
            'sql_injection': 'Use Room DAO with parameterized @Query.',
            'sql_injection_room': 'Avoid @RawQuery. Use @Query with parameters.',
            'command_injection': 'Avoid exec(). Use explicit command arrays.',
            'intent_injection': 'Validate intent data. Use explicit intents.',
            'broadcast_injection': 'Use LocalBroadcastManager or permissions.',
            'webview_injection': 'Validate URLs. Disable JS when not needed.',
            'xss': 'Sanitize input before evaluateJavascript.',
            'path_traversal': 'Validate paths. Use canonical paths.',
            'hardcoded_password': 'Use EncryptedSharedPreferences or Keystore.',
        }.get(vuln_type, 'Review and fix the security issue.')


def scan_kotlin_ast(code: str, filename: str = "") -> List[Dict]:
    """Convenience function to scan Kotlin code"""
    return KotlinASTScanner().scan(code, filename)
