"""
Python Security Rules - Comprehensive Structured Ruleset

Structured security rules for Python covering:
1. Injection (SQL, Command, Code, LDAP, Template)
2. Cryptographic Failures (Weak hashing, Hardcoded secrets, Insecure randomness)
3. Insecure Deserialization (Pickle, YAML, Marshal)
4. Path Traversal & File Operations
5. XSS & Template Security
6. SSL/TLS Misconfigurations
7. Information Exposure
8. SSRF, IDOR, Mass Assignment, Open Redirect
9. XXE, File Upload, Rate Limiting, Timing Attacks
"""

from dataclasses import dataclass, field
from typing import List, Dict, Optional
from enum import Enum
import re


class PySeverity(Enum):
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    INFO = "Info"


class PyRuleCategory(Enum):
    SQL_INJECTION = "sql_injection"
    CODE_INJECTION = "code_injection"
    SHELL_INJECTION = "shell_injection"
    HARDCODED_SECRETS = "hardcoded_secrets"
    INSECURE_DESERIALIZATION = "insecure_deserialization"
    PATH_TRAVERSAL = "path_traversal"
    XSS_TEMPLATE = "xss_template"
    INSECURE_RANDOMNESS = "insecure_randomness"
    SSL_TLS = "ssl_tls"
    INFORMATION_EXPOSURE = "information_exposure"
    FILE_PERMISSIONS = "file_permissions"
    WEAK_CRYPTOGRAPHY = "weak_cryptography"
    SSRF = "ssrf"
    JWT_SECURITY = "jwt_security"
    IDOR = "idor"
    MASS_ASSIGNMENT = "mass_assignment"
    OPEN_REDIRECT = "open_redirect"
    SSTI = "ssti"
    LDAP_INJECTION = "ldap_injection"
    XXE = "xxe"
    FILE_UPLOAD = "file_upload"
    RATE_LIMITING = "rate_limiting"
    TIMING_ATTACK = "timing_attack"
    SESSION_SECURITY = "session_security"
    DEBUG_CONFIG = "debug_configuration"


@dataclass
class PythonSecurityRule:
    """A single Python security rule"""
    id: str
    name: str
    description: str
    category: PyRuleCategory
    severity: PySeverity
    pattern: str
    remediation: str
    cwe_id: Optional[str] = None
    owasp_category: Optional[str] = None
    confidence: float = 0.8
    check_inside_strings: bool = False


class PythonRuleEngine:
    """Comprehensive Python Security Rule Engine"""

    def __init__(self):
        self.rules: Dict[str, PythonSecurityRule] = {}
        self._register_all_rules()

    def _register_all_rules(self):
        # ============================================
        # SQL INJECTION (4 rules)
        # ============================================
        self._register(PythonSecurityRule(
            id="PY-001", name="SQL Injection via Format String",
            description="SQL query constructed using Python f-string with user input",
            category=PyRuleCategory.SQL_INJECTION, severity=PySeverity.HIGH,
            pattern=r"cursor\.execute\s*\(\s*f\".*?\{.*\}.*?\"",
            remediation="Use parameterized queries: cursor.execute('SELECT * FROM users WHERE id = %s', (user_id,))",
            cwe_id="CWE-89", owasp_category="A03:2021-Injection"
        ))
        self._register(PythonSecurityRule(
            id="PY-002", name="SQL Injection via String Concatenation",
            description="SQL query built by concatenating strings with user input",
            category=PyRuleCategory.SQL_INJECTION, severity=PySeverity.HIGH,
            pattern=r"execute\s*\(\s*[\"'].*?\+.*?[\"']",
            remediation="Use parameterized queries instead of string concatenation",
            cwe_id="CWE-89", owasp_category="A03:2021-Injection"
        ))
        self._register(PythonSecurityRule(
            id="PY-003", name="SQL Injection via % Formatting",
            description="SQL query using old-style % formatting with user input",
            category=PyRuleCategory.SQL_INJECTION, severity=PySeverity.HIGH,
            pattern=r"cursor\.execute\s*\(\s*[\"'].*?%s.*?[\"']",
            remediation="Use parameterized queries with proper placeholders: cursor.execute('SELECT * FROM t WHERE id=%s', (val,))",
            cwe_id="CWE-89", owasp_category="A03:2021-Injection"
        ))
        self._register(PythonSecurityRule(
            id="PY-004", name="SQLite Injection",
            description="SQLite query using string formatting",
            category=PyRuleCategory.SQL_INJECTION, severity=PySeverity.HIGH,
            pattern=r"sqlite3\.connect.*execute.*%",
            remediation="Use parameterized queries with sqlite3",
            cwe_id="CWE-89", owasp_category="A03:2021-Injection"
        ))

        # ============================================
        # CODE INJECTION (5 rules)
        # ============================================
        self._register(PythonSecurityRule(
            id="PY-005", name="Dangerous eval() Usage",
            description="eval() executes arbitrary Python code and should never be used with user input",
            category=PyRuleCategory.CODE_INJECTION, severity=PySeverity.CRITICAL,
            pattern=r"eval\s*\(",
            remediation="Use ast.literal_eval() for safe evaluation of literals, or avoid eval entirely",
            cwe_id="CWE-95", owasp_category="A03:2021-Injection"
        ))
        self._register(PythonSecurityRule(
            id="PY-006", name="Dangerous exec() Usage",
            description="exec() executes arbitrary Python code dynamically",
            category=PyRuleCategory.CODE_INJECTION, severity=PySeverity.CRITICAL,
            pattern=r"exec\s*\(",
            remediation="Avoid exec() with user-controlled input. Use safer alternatives",
            cwe_id="CWE-95", owasp_category="A03:2021-Injection"
        ))
        self._register(PythonSecurityRule(
            id="PY-007", name="Dynamic Code Compilation",
            description="compile() can be used to dynamically compile and execute code",
            category=PyRuleCategory.CODE_INJECTION, severity=PySeverity.HIGH,
            pattern=r"compile\s*\(",
            remediation="Avoid compile() with user-controlled input",
            cwe_id="CWE-95", owasp_category="A03:2021-Injection", confidence=0.7
        ))
        self._register(PythonSecurityRule(
            id="PY-008", name="Dynamic Import",
            description="__import__() allows dynamically importing modules which could be exploited",
            category=PyRuleCategory.CODE_INJECTION, severity=PySeverity.HIGH,
            pattern=r"__import__\s*\(",
            remediation="Use static imports or importlib with validated module names",
            cwe_id="CWE-95", owasp_category="A03:2021-Injection"
        ))
        self._register(PythonSecurityRule(
            id="PY-009", name="Builtins Access via getattr",
            description="Accessing __builtins__ through getattr can enable code injection",
            category=PyRuleCategory.CODE_INJECTION, severity=PySeverity.MEDIUM,
            pattern=r"getattr\s*\(\s*__builtins__",
            remediation="Do not expose __builtins__ to dynamic attribute access",
            cwe_id="CWE-95", owasp_category="A03:2021-Injection", confidence=0.6
        ))

        # ============================================
        # HARDCODED SECRETS (4 rules)
        # ============================================
        self._register(PythonSecurityRule(
            id="PY-010", name="Hardcoded Password",
            description="Password value hardcoded directly in source code",
            category=PyRuleCategory.HARDCODED_SECRETS, severity=PySeverity.HIGH,
            pattern=r"(password|pwd|passwd)\s*=\s*[\"'](?!\s*$|.*\{|.*env|.*ENV|.*config|.*CONFIG|test|demo|example|placeholder|xxx|\*+)[A-Za-z0-9!@#$%^&*()_+\-=\[\]{};':,.<>?/~`]{8,}[\"']",
            remediation="Store secrets in environment variables or a secrets manager (e.g., AWS Secrets Manager, HashiCorp Vault)",
            cwe_id="CWE-798", owasp_category="A07:2021-Authentication Failures"
        ))
        self._register(PythonSecurityRule(
            id="PY-011", name="Hardcoded API Key",
            description="API key hardcoded directly in source code",
            category=PyRuleCategory.HARDCODED_SECRETS, severity=PySeverity.HIGH,
            pattern=r"(api_key|apiKey|apikey)\s*=\s*[\"'](?!\s*$|.*\{|.*env|.*ENV|.*config|.*CONFIG|test|demo|example|placeholder|xxx|your_|my_)[A-Za-z0-9_\-]{20,}[\"']",
            remediation="Load API keys from environment variables: os.environ.get('API_KEY')",
            cwe_id="CWE-798", owasp_category="A07:2021-Authentication Failures"
        ))
        self._register(PythonSecurityRule(
            id="PY-012", name="Hardcoded Secret Key",
            description="Secret or private key hardcoded in source code",
            category=PyRuleCategory.HARDCODED_SECRETS, severity=PySeverity.HIGH,
            pattern=r"(secret|secret_key|private_key)\s*=\s*[\"'](?!\s*$|.*\{|.*env|.*ENV|.*config|.*CONFIG|test|demo|example|placeholder|xxx)[A-Za-z0-9!@#$%^&*()_+\-=\[\]{};':,.<>?/~`]{16,}[\"']",
            remediation="Use environment variables or a secrets manager for secret keys",
            cwe_id="CWE-798", owasp_category="A07:2021-Authentication Failures"
        ))
        self._register(PythonSecurityRule(
            id="PY-013", name="Hardcoded AWS Credentials",
            description="AWS access key or secret hardcoded in source code",
            category=PyRuleCategory.HARDCODED_SECRETS, severity=PySeverity.HIGH,
            pattern=r"(aws_key|aws_secret|access_key|access_token)\s*=\s*[\"'](?!\s*$|.*\{|.*env|.*ENV|.*config|.*CONFIG|test|demo|example|AKIA)[A-Za-z0-9+/=]{20,}[\"']",
            remediation="Use AWS IAM roles or environment variables for credentials",
            cwe_id="CWE-798", owasp_category="A07:2021-Authentication Failures"
        ))

        # ============================================
        # INSECURE DESERIALIZATION (5 rules)
        # ============================================
        self._register(PythonSecurityRule(
            id="PY-014", name="Pickle Deserialization (loads)",
            description="pickle.loads() can execute arbitrary code during deserialization",
            category=PyRuleCategory.INSECURE_DESERIALIZATION, severity=PySeverity.HIGH,
            pattern=r"pickle\.loads\s*\(",
            remediation="Use JSON or other safe serialization formats. Never unpickle untrusted data",
            cwe_id="CWE-502", owasp_category="A08:2021-Software and Data Integrity Failures"
        ))
        self._register(PythonSecurityRule(
            id="PY-015", name="Pickle Deserialization (load)",
            description="pickle.load() can execute arbitrary code during deserialization",
            category=PyRuleCategory.INSECURE_DESERIALIZATION, severity=PySeverity.HIGH,
            pattern=r"pickle\.load\s*\(",
            remediation="Use JSON or other safe serialization formats. Never unpickle untrusted data",
            cwe_id="CWE-502", owasp_category="A08:2021-Software and Data Integrity Failures"
        ))
        self._register(PythonSecurityRule(
            id="PY-016", name="Unsafe YAML Loading",
            description="yaml.load() without SafeLoader can execute arbitrary Python code",
            category=PyRuleCategory.INSECURE_DESERIALIZATION, severity=PySeverity.MEDIUM,
            pattern=r"yaml\.load\s*\(",
            remediation="Use yaml.safe_load() instead of yaml.load()",
            cwe_id="CWE-502", owasp_category="A08:2021-Software and Data Integrity Failures", confidence=0.7
        ))
        self._register(PythonSecurityRule(
            id="PY-017", name="Marshal Deserialization",
            description="marshal.loads() can execute arbitrary code",
            category=PyRuleCategory.INSECURE_DESERIALIZATION, severity=PySeverity.MEDIUM,
            pattern=r"marshal\.loads\s*\(",
            remediation="Avoid marshal for untrusted data. Use JSON instead",
            cwe_id="CWE-502", owasp_category="A08:2021-Software and Data Integrity Failures", confidence=0.6
        ))
        self._register(PythonSecurityRule(
            id="PY-018", name="JSON with Custom Object Hook",
            description="json.loads() with object_hook can enable malicious object creation",
            category=PyRuleCategory.INSECURE_DESERIALIZATION, severity=PySeverity.LOW,
            pattern=r"json\.loads\s*\(.*?object_hook",
            remediation="Validate the object_hook function and ensure it doesn't create arbitrary objects",
            cwe_id="CWE-502", confidence=0.5
        ))

        # ============================================
        # PATH TRAVERSAL (4 rules)
        # ============================================
        self._register(PythonSecurityRule(
            id="PY-019", name="Path Traversal via String Concatenation (open)",
            description="File opened with user-controlled path via string concatenation",
            category=PyRuleCategory.PATH_TRAVERSAL, severity=PySeverity.MEDIUM,
            pattern=r"open\s*\(.*?\+.*?\)",
            remediation="Use os.path.abspath() and validate paths are within allowed directories",
            cwe_id="CWE-22", owasp_category="A01:2021-Broken Access Control", confidence=0.6
        ))
        self._register(PythonSecurityRule(
            id="PY-020", name="os.path.join with Parent Directory",
            description="os.path.join used with '..' which can escape intended directory",
            category=PyRuleCategory.PATH_TRAVERSAL, severity=PySeverity.HIGH,
            pattern=r"os\.path\.join.*\.\.",
            remediation="Validate and sanitize paths. Use os.path.realpath() and check prefix",
            cwe_id="CWE-22", owasp_category="A01:2021-Broken Access Control", confidence=0.7
        ))
        self._register(PythonSecurityRule(
            id="PY-021", name="Path Traversal Sequence",
            description="Direct use of '../' path traversal sequence detected",
            category=PyRuleCategory.PATH_TRAVERSAL, severity=PySeverity.MEDIUM,
            pattern=r"\.\./",
            remediation="Sanitize user input paths and validate against allowed directory",
            cwe_id="CWE-22", owasp_category="A01:2021-Broken Access Control", confidence=0.5
        ))
        self._register(PythonSecurityRule(
            id="PY-022", name="Path Traversal via file()",
            description="Legacy file() function with concatenated user input",
            category=PyRuleCategory.PATH_TRAVERSAL, severity=PySeverity.MEDIUM,
            pattern=r"file\s*\(.*?\+.*?\)",
            remediation="Use open() with validated paths instead of file()",
            cwe_id="CWE-22", confidence=0.6
        ))

        # ============================================
        # SHELL INJECTION (5 rules)
        # ============================================
        self._register(PythonSecurityRule(
            id="PY-023", name="OS Command Injection (os.system)",
            description="os.system() executes shell commands and is vulnerable to injection",
            category=PyRuleCategory.SHELL_INJECTION, severity=PySeverity.HIGH,
            pattern=r"os\.system\s*\(",
            remediation="Use subprocess.run() with a list of arguments and shell=False",
            cwe_id="CWE-78", owasp_category="A03:2021-Injection"
        ))
        self._register(PythonSecurityRule(
            id="PY-024", name="OS Command Injection (os.popen)",
            description="os.popen() executes shell commands and is vulnerable to injection",
            category=PyRuleCategory.SHELL_INJECTION, severity=PySeverity.HIGH,
            pattern=r"os\.popen\s*\(",
            remediation="Use subprocess.run() with shell=False and capture_output=True",
            cwe_id="CWE-78", owasp_category="A03:2021-Injection"
        ))
        self._register(PythonSecurityRule(
            id="PY-025", name="Subprocess with Shell",
            description="subprocess.call() may execute with shell=True enabling injection",
            category=PyRuleCategory.SHELL_INJECTION, severity=PySeverity.MEDIUM,
            pattern=r"subprocess\.call\s*\(",
            remediation="Use subprocess.run() with shell=False and pass command as a list",
            cwe_id="CWE-78", owasp_category="A03:2021-Injection", confidence=0.7
        ))
        self._register(PythonSecurityRule(
            id="PY-026", name="Subprocess Popen",
            description="subprocess.Popen() may be used with shell=True",
            category=PyRuleCategory.SHELL_INJECTION, severity=PySeverity.MEDIUM,
            pattern=r"subprocess\.Popen\s*\(",
            remediation="Ensure shell=False and pass command as a list",
            cwe_id="CWE-78", owasp_category="A03:2021-Injection", confidence=0.7
        ))
        self._register(PythonSecurityRule(
            id="PY-027", name="Legacy Command Execution",
            description="commands.getstatusoutput is deprecated and vulnerable to injection",
            category=PyRuleCategory.SHELL_INJECTION, severity=PySeverity.MEDIUM,
            pattern=r"commands\.getstatusoutput",
            remediation="Use subprocess.run() instead of deprecated commands module",
            cwe_id="CWE-78", owasp_category="A03:2021-Injection", confidence=0.6
        ))

        # ============================================
        # XSS & TEMPLATE SECURITY (3 rules)
        # ============================================
        self._register(PythonSecurityRule(
            id="PY-028", name="Flask render_template_string",
            description="render_template_string with user input enables XSS and SSTI",
            category=PyRuleCategory.XSS_TEMPLATE, severity=PySeverity.MEDIUM,
            pattern=r"flask\.render_template_string",
            remediation="Use render_template() with separate template files instead",
            cwe_id="CWE-79", owasp_category="A03:2021-Injection", confidence=0.7
        ))
        self._register(PythonSecurityRule(
            id="PY-029", name="Django Template Direct Construction",
            description="Directly constructing Django templates can bypass auto-escaping",
            category=PyRuleCategory.XSS_TEMPLATE, severity=PySeverity.MEDIUM,
            pattern=r"django\.template\.Template",
            remediation="Use Django template loader instead of direct Template construction",
            cwe_id="CWE-79", owasp_category="A03:2021-Injection", confidence=0.7
        ))
        self._register(PythonSecurityRule(
            id="PY-030", name="Django mark_safe Misuse",
            description="mark_safe() disables Django's auto-escaping, enabling XSS if used with user input",
            category=PyRuleCategory.XSS_TEMPLATE, severity=PySeverity.MEDIUM,
            pattern=r"mark_safe",
            remediation="Avoid mark_safe() with user-controlled content. Use Django's auto-escaping",
            cwe_id="CWE-79", owasp_category="A03:2021-Injection", confidence=0.6
        ))

        # ============================================
        # INSECURE RANDOMNESS (3 rules)
        # ============================================
        self._register(PythonSecurityRule(
            id="PY-031", name="Insecure Random (randint)",
            description="random.randint() is not cryptographically secure for security-sensitive operations",
            category=PyRuleCategory.INSECURE_RANDOMNESS, severity=PySeverity.LOW,
            pattern=r"random\.randint",
            remediation="Use secrets.token_hex() or secrets.randbelow() for security-sensitive operations",
            cwe_id="CWE-330", confidence=0.3
        ))
        self._register(PythonSecurityRule(
            id="PY-032", name="Insecure Random (choice)",
            description="random.choice() is not cryptographically secure",
            category=PyRuleCategory.INSECURE_RANDOMNESS, severity=PySeverity.LOW,
            pattern=r"random\.choice",
            remediation="Use secrets.choice() for security-sensitive selections",
            cwe_id="CWE-330", confidence=0.3
        ))
        self._register(PythonSecurityRule(
            id="PY-033", name="Insecure Random (random)",
            description="random.random() is predictable and not suitable for security tokens",
            category=PyRuleCategory.INSECURE_RANDOMNESS, severity=PySeverity.LOW,
            pattern=r"random\.random",
            remediation="Use secrets module for generating security tokens",
            cwe_id="CWE-330", confidence=0.3
        ))

        # ============================================
        # SSL/TLS (2 rules)
        # ============================================
        self._register(PythonSecurityRule(
            id="PY-034", name="SSL Verification Disabled",
            description="SSL certificate verification disabled (verify=False)",
            category=PyRuleCategory.SSL_TLS, severity=PySeverity.HIGH,
            pattern=r"verify\s*=\s*False",
            remediation="Always enable SSL verification: requests.get(url, verify=True)",
            cwe_id="CWE-295", owasp_category="A02:2021-Cryptographic Failures"
        ))
        self._register(PythonSecurityRule(
            id="PY-035", name="Unverified SSL Context",
            description="Creating unverified SSL context bypasses certificate validation",
            category=PyRuleCategory.SSL_TLS, severity=PySeverity.HIGH,
            pattern=r"ssl\._create_unverified_context",
            remediation="Use ssl.create_default_context() for proper certificate validation",
            cwe_id="CWE-295", owasp_category="A02:2021-Cryptographic Failures"
        ))

        # ============================================
        # INFORMATION EXPOSURE (3 rules)
        # ============================================
        self._register(PythonSecurityRule(
            id="PY-036", name="Password in Print Statement",
            description="Password value printed to stdout which may appear in logs",
            category=PyRuleCategory.INFORMATION_EXPOSURE, severity=PySeverity.MEDIUM,
            pattern=r"print\s*\(.*password.*\)",
            remediation="Never log password values. Use structured logging with sensitive field redaction",
            cwe_id="CWE-532", confidence=0.6
        ))
        self._register(PythonSecurityRule(
            id="PY-037", name="Password in Log Output",
            description="Password value written to application logs",
            category=PyRuleCategory.INFORMATION_EXPOSURE, severity=PySeverity.MEDIUM,
            pattern=r"logging\.info.*password",
            remediation="Use structured logging with sensitive field masking",
            cwe_id="CWE-532", confidence=0.6
        ))
        self._register(PythonSecurityRule(
            id="PY-038", name="Debug Mode Enabled",
            description="Debug mode enabled which exposes detailed error information",
            category=PyRuleCategory.DEBUG_CONFIG, severity=PySeverity.LOW,
            pattern=r"debug.*=.*True",
            remediation="Disable debug mode in production: DEBUG = False",
            cwe_id="CWE-215", confidence=0.5
        ))

        # ============================================
        # FILE PERMISSIONS (2 rules)
        # ============================================
        self._register(PythonSecurityRule(
            id="PY-039", name="World-Writable File Permission (0o777)",
            description="File created with world-writable permissions (0o777)",
            category=PyRuleCategory.FILE_PERMISSIONS, severity=PySeverity.MEDIUM,
            pattern=r"0o777",
            remediation="Use restrictive permissions: 0o600 for private files, 0o644 for read-only public",
            cwe_id="CWE-732", confidence=0.6
        ))
        self._register(PythonSecurityRule(
            id="PY-040", name="Overly Permissive File (0o666)",
            description="File created with overly permissive permissions (0o666)",
            category=PyRuleCategory.FILE_PERMISSIONS, severity=PySeverity.LOW,
            pattern=r"0o666",
            remediation="Use more restrictive permissions like 0o644",
            cwe_id="CWE-732", confidence=0.5
        ))

        # ============================================
        # WEAK CRYPTOGRAPHY (3 rules)
        # ============================================
        self._register(PythonSecurityRule(
            id="PY-041", name="MD5 Usage (Weak Hash)",
            description="MD5 is cryptographically broken and should not be used for security",
            category=PyRuleCategory.WEAK_CRYPTOGRAPHY, severity=PySeverity.MEDIUM,
            pattern=r"md5\s*\(",
            remediation="Use SHA-256 or SHA-3: hashlib.sha256(data).hexdigest()",
            cwe_id="CWE-328", owasp_category="A02:2021-Cryptographic Failures", confidence=0.7
        ))
        self._register(PythonSecurityRule(
            id="PY-042", name="SHA1 Usage (Weak Hash)",
            description="SHA1 is cryptographically weak and collision-vulnerable",
            category=PyRuleCategory.WEAK_CRYPTOGRAPHY, severity=PySeverity.MEDIUM,
            pattern=r"sha1\s*\(",
            remediation="Use SHA-256 or SHA-3 instead of SHA1",
            cwe_id="CWE-328", owasp_category="A02:2021-Cryptographic Failures", confidence=0.7
        ))
        self._register(PythonSecurityRule(
            id="PY-043", name="crypt Module Usage",
            description="crypt.crypt uses weak DES-based hashing by default",
            category=PyRuleCategory.WEAK_CRYPTOGRAPHY, severity=PySeverity.MEDIUM,
            pattern=r"crypt\.crypt",
            remediation="Use bcrypt or argon2 for password hashing",
            cwe_id="CWE-328", confidence=0.6
        ))

        # ============================================
        # SSRF (2 rules)
        # ============================================
        self._register(PythonSecurityRule(
            id="PY-044", name="SSRF via Requests Library",
            description="HTTP request made with user-controlled URL enabling SSRF",
            category=PyRuleCategory.SSRF, severity=PySeverity.HIGH,
            pattern=r"requests\.(get|post|put|delete)\s*\(.*(request|input|url|site).*\)",
            remediation="Validate and whitelist URLs. Block private IP ranges and internal hosts",
            cwe_id="CWE-918", owasp_category="A10:2021-SSRF", confidence=0.7
        ))
        self._register(PythonSecurityRule(
            id="PY-045", name="SSRF via urllib",
            description="urllib request with user-controlled URL enabling SSRF",
            category=PyRuleCategory.SSRF, severity=PySeverity.HIGH,
            pattern=r"urllib\.request\.urlopen\s*\(.*(request|input|url|site).*\)",
            remediation="Validate URLs against an allowlist before making requests",
            cwe_id="CWE-918", owasp_category="A10:2021-SSRF", confidence=0.7
        ))

        # ============================================
        # JWT SECURITY (2 rules)
        # ============================================
        self._register(PythonSecurityRule(
            id="PY-046", name="JWT None Algorithm",
            description="JWT signed with 'none' algorithm which disables signature verification",
            category=PyRuleCategory.JWT_SECURITY, severity=PySeverity.CRITICAL,
            pattern=r"jwt\.encode\s*\(.*algorithm\s*=\s*['\"]none['\"]",
            remediation="Always use strong algorithms like HS256 or RS256 for JWT signing",
            cwe_id="CWE-345", owasp_category="A02:2021-Cryptographic Failures"
        ))
        self._register(PythonSecurityRule(
            id="PY-047", name="Flask Debug Mode Config",
            description="Flask DEBUG set to True in config exposes debugger and stack traces",
            category=PyRuleCategory.DEBUG_CONFIG, severity=PySeverity.MEDIUM,
            pattern=r"app\.config\['DEBUG'\]\s*=\s*True",
            remediation="Set DEBUG = False in production",
            cwe_id="CWE-215"
        ))

        # ============================================
        # SESSION SECURITY (2 rules)
        # ============================================
        self._register(PythonSecurityRule(
            id="PY-048", name="Insecure Session Cookie (HttpOnly)",
            description="Session cookies without HttpOnly flag can be accessed by JavaScript",
            category=PyRuleCategory.SESSION_SECURITY, severity=PySeverity.HIGH,
            pattern=r"SESSION_COOKIE_HTTPONLY\s*=\s*False",
            remediation="Set SESSION_COOKIE_HTTPONLY = True",
            cwe_id="CWE-1004"
        ))
        self._register(PythonSecurityRule(
            id="PY-049", name="Insecure Session Cookie (Secure)",
            description="Session cookies sent over insecure HTTP connections",
            category=PyRuleCategory.SESSION_SECURITY, severity=PySeverity.HIGH,
            pattern=r"SESSION_COOKIE_SECURE\s*=\s*False",
            remediation="Set SESSION_COOKIE_SECURE = True to enforce HTTPS",
            cwe_id="CWE-614"
        ))

        # ============================================
        # IDOR (2 rules)
        # ============================================
        self._register(PythonSecurityRule(
            id="PY-050", name="IDOR via Direct Object Query",
            description="Database query using request parameter directly without authorization check",
            category=PyRuleCategory.IDOR, severity=PySeverity.HIGH,
            pattern=r"(Model|db|collection)\.(find|get|delete|update).*\(.*request\.(args|form|json)",
            remediation="Verify the requesting user has authorization to access the requested object",
            cwe_id="CWE-639", owasp_category="A01:2021-Broken Access Control", confidence=0.7
        ))
        self._register(PythonSecurityRule(
            id="PY-051", name="IDOR via get_object_or_404",
            description="Django get_object_or_404 with unsanitized request input",
            category=PyRuleCategory.IDOR, severity=PySeverity.HIGH,
            pattern=r"get_object_or_404\s*\(.*request\.(GET|POST)",
            remediation="Check object ownership before returning to user",
            cwe_id="CWE-639", owasp_category="A01:2021-Broken Access Control", confidence=0.7
        ))

        # ============================================
        # MASS ASSIGNMENT (2 rules)
        # ============================================
        self._register(PythonSecurityRule(
            id="PY-052", name="Mass Assignment via dict unpacking",
            description="Passing all request data directly to model update enables mass assignment",
            category=PyRuleCategory.MASS_ASSIGNMENT, severity=PySeverity.HIGH,
            pattern=r"\*\*request\.(json|form|data)",
            remediation="Whitelist allowed fields explicitly instead of passing all request data",
            cwe_id="CWE-915", owasp_category="A04:2021-Insecure Design"
        ))
        self._register(PythonSecurityRule(
            id="PY-053", name="Mass Assignment via update(**)",
            description="Model update with unpacked kwargs allows overwriting protected fields",
            category=PyRuleCategory.MASS_ASSIGNMENT, severity=PySeverity.HIGH,
            pattern=r"update\s*\(\s*\*\*",
            remediation="Explicitly specify allowed fields in update operations",
            cwe_id="CWE-915", confidence=0.7
        ))

        # ============================================
        # OPEN REDIRECT (2 rules)
        # ============================================
        self._register(PythonSecurityRule(
            id="PY-054", name="Open Redirect via Request Args",
            description="Redirect URL taken directly from user request parameters",
            category=PyRuleCategory.OPEN_REDIRECT, severity=PySeverity.HIGH,
            pattern=r"redirect\s*\(\s*request\.(args|GET|POST)",
            remediation="Validate redirect URLs against a whitelist of allowed domains",
            cwe_id="CWE-601", owasp_category="A01:2021-Broken Access Control"
        ))
        self._register(PythonSecurityRule(
            id="PY-055", name="Open Redirect via url_for",
            description="Redirect with url_for using user-controlled parameters",
            category=PyRuleCategory.OPEN_REDIRECT, severity=PySeverity.MEDIUM,
            pattern=r"redirect\s*\(\s*url_for\s*\(.*request",
            remediation="Validate redirect targets and use relative URLs only",
            cwe_id="CWE-601", confidence=0.7
        ))

        # ============================================
        # SSTI (3 rules)
        # ============================================
        self._register(PythonSecurityRule(
            id="PY-056", name="SSTI via render_template_string",
            description="Flask render_template_string with user input enables Server-Side Template Injection",
            category=PyRuleCategory.SSTI, severity=PySeverity.CRITICAL,
            pattern=r"render_template_string\s*\(.*request",
            remediation="Use render_template() with file-based templates instead of render_template_string()",
            cwe_id="CWE-1336", owasp_category="A03:2021-Injection"
        ))
        self._register(PythonSecurityRule(
            id="PY-057", name="SSTI via Template() with Request",
            description="Django/Jinja Template() constructed with user input enables SSTI",
            category=PyRuleCategory.SSTI, severity=PySeverity.HIGH,
            pattern=r"Template\s*\(.*request",
            remediation="Never construct templates from user-provided strings",
            cwe_id="CWE-1336", owasp_category="A03:2021-Injection"
        ))
        self._register(PythonSecurityRule(
            id="PY-058", name="SSTI via Jinja2 from_string",
            description="Jinja2 Environment.from_string enables SSTI",
            category=PyRuleCategory.SSTI, severity=PySeverity.HIGH,
            pattern=r"jinja2\.Environment.*from_string",
            remediation="Use template loader from files instead of from_string",
            cwe_id="CWE-1336", confidence=0.7
        ))

        # ============================================
        # LDAP INJECTION (2 rules)
        # ============================================
        self._register(PythonSecurityRule(
            id="PY-059", name="LDAP Injection via Request",
            description="LDAP operation with user-controlled filter parameters",
            category=PyRuleCategory.LDAP_INJECTION, severity=PySeverity.HIGH,
            pattern=r"ldap\.(search|bind|modify).*\(.*request",
            remediation="Use parameterized LDAP queries and escape special LDAP characters",
            cwe_id="CWE-90", owasp_category="A03:2021-Injection"
        ))
        self._register(PythonSecurityRule(
            id="PY-060", name="LDAP Filter Concatenation",
            description="LDAP filter constructed via string concatenation with user input",
            category=PyRuleCategory.LDAP_INJECTION, severity=PySeverity.HIGH,
            pattern=r"ldap_filter.*\+.*request",
            remediation="Use ldap.filter.escape_filter_chars() to sanitize user input",
            cwe_id="CWE-90", confidence=0.7
        ))

        # ============================================
        # XXE (4 rules)
        # ============================================
        self._register(PythonSecurityRule(
            id="PY-061", name="XXE via lxml etree.parse",
            description="lxml etree.parse() may process external entities in XML",
            category=PyRuleCategory.XXE, severity=PySeverity.MEDIUM,
            pattern=r"etree\.parse\s*\(",
            remediation="Use defusedxml library or disable external entity processing",
            cwe_id="CWE-611", owasp_category="A05:2021-Security Misconfiguration", confidence=0.6
        ))
        self._register(PythonSecurityRule(
            id="PY-062", name="XXE via etree.fromstring",
            description="etree.fromstring() may process external entities in XML strings",
            category=PyRuleCategory.XXE, severity=PySeverity.MEDIUM,
            pattern=r"etree\.fromstring\s*\(",
            remediation="Use defusedxml.lxml.fromstring() instead",
            cwe_id="CWE-611", confidence=0.6
        ))
        self._register(PythonSecurityRule(
            id="PY-063", name="XXE via minidom",
            description="xml.dom.minidom.parse() processes external entities by default",
            category=PyRuleCategory.XXE, severity=PySeverity.MEDIUM,
            pattern=r"xml\.dom\.minidom\.parse\s*\(",
            remediation="Use defusedxml library for safe XML parsing",
            cwe_id="CWE-611", confidence=0.6
        ))
        self._register(PythonSecurityRule(
            id="PY-064", name="XXE via SAX Parser",
            description="xml.sax.parse() processes external entities by default",
            category=PyRuleCategory.XXE, severity=PySeverity.MEDIUM,
            pattern=r"parseXML|xml\.sax\.parse",
            remediation="Use defusedxml library instead of standard xml parsers",
            cwe_id="CWE-611", confidence=0.6
        ))

        # ============================================
        # FILE UPLOAD (2 rules)
        # ============================================
        self._register(PythonSecurityRule(
            id="PY-065", name="Insecure File Save",
            description="File saved without using secure_filename() to sanitize the filename",
            category=PyRuleCategory.FILE_UPLOAD, severity=PySeverity.HIGH,
            pattern=r"save\s*\(.*filename.*\)(?!.*secure_filename)",
            remediation="Use werkzeug.utils.secure_filename() to sanitize uploaded filenames",
            cwe_id="CWE-434", owasp_category="A04:2021-Insecure Design", confidence=0.7
        ))
        self._register(PythonSecurityRule(
            id="PY-066", name="Unrestricted File Extensions",
            description="File upload allows all extensions including dangerous ones",
            category=PyRuleCategory.FILE_UPLOAD, severity=PySeverity.HIGH,
            pattern=r"allowed_extensions.*=.*\*",
            remediation="Whitelist specific safe file extensions (e.g., .pdf, .jpg, .png)",
            cwe_id="CWE-434"
        ))

        # ============================================
        # RATE LIMITING (1 rule)
        # ============================================
        self._register(PythonSecurityRule(
            id="PY-067", name="Missing Rate Limiting on Auth Endpoints",
            description="Authentication endpoints without rate limiting are vulnerable to brute force",
            category=PyRuleCategory.RATE_LIMITING, severity=PySeverity.MEDIUM,
            pattern=r"@app\.route.*login|@app\.route.*auth|@app\.route.*password",
            remediation="Add rate limiting with Flask-Limiter: @limiter.limit('5/minute')",
            cwe_id="CWE-307", confidence=0.5
        ))

        # ============================================
        # TIMING ATTACK (2 rules)
        # ============================================
        self._register(PythonSecurityRule(
            id="PY-068", name="Timing Attack on Password Comparison",
            description="String equality comparison for passwords leaks timing information",
            category=PyRuleCategory.TIMING_ATTACK, severity=PySeverity.MEDIUM,
            pattern=r"==\s*.*password|password.*==",
            remediation="Use hmac.compare_digest() for constant-time comparison",
            cwe_id="CWE-208", confidence=0.5
        ))
        self._register(PythonSecurityRule(
            id="PY-069", name="Timing Attack on Token Comparison",
            description="String equality comparison for tokens leaks timing information",
            category=PyRuleCategory.TIMING_ATTACK, severity=PySeverity.MEDIUM,
            pattern=r"if.*token\s*==\s*",
            remediation="Use hmac.compare_digest() for constant-time token comparison",
            cwe_id="CWE-208", confidence=0.5
        ))

    def _register(self, rule: PythonSecurityRule):
        self.rules[rule.id] = rule

    def get_rules_for_category(self, category: PyRuleCategory) -> List[PythonSecurityRule]:
        return [r for r in self.rules.values() if r.category == category]

    def scan_code(self, code: str, filename: str = "") -> List[Dict]:
        """Scan Python code against all structured rules"""
        issues = []
        lines = code.split('\n')
        total_lines = len(lines)

        for rule in self.rules.values():
            try:
                pattern = re.compile(rule.pattern, re.IGNORECASE | re.MULTILINE)
                for i, line in enumerate(lines, 1):
                    if pattern.search(line):
                        ctx_start = max(0, i - 4)
                        ctx_end = min(total_lines, i + 3)
                        context_lines = []
                        for ctx_i in range(ctx_start, ctx_end):
                            prefix = '>>> ' if ctx_i == i - 1 else '    '
                            context_lines.append(f'{prefix}{ctx_i + 1}: {lines[ctx_i]}')
                        snippet_context = '\n'.join(context_lines)

                        issues.append({
                            'rule_id': rule.id,
                            'type': rule.name,
                            'description': rule.description,
                            'category': rule.category.value,
                            'severity': rule.severity.value,
                            'line': i,
                            'snippet': line.strip(),
                            'snippet_context': snippet_context,
                            'remediation': rule.remediation,
                            'cwe_id': rule.cwe_id,
                            'owasp_category': rule.owasp_category,
                            'confidence': rule.confidence,
                            'scanner': 'python_security_rules'
                        })
            except re.error:
                pass

        return issues

    def get_statistics(self) -> Dict:
        stats = {'total_rules': len(self.rules), 'by_category': {}, 'by_severity': {}}
        for rule in self.rules.values():
            cat = rule.category.value
            sev = rule.severity.value
            stats['by_category'][cat] = stats['by_category'].get(cat, 0) + 1
            stats['by_severity'][sev] = stats['by_severity'].get(sev, 0) + 1
        return stats
