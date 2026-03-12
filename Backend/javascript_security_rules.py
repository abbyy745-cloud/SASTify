"""
JavaScript/TypeScript Security Rules - Comprehensive Structured Ruleset

Structured security rules for JavaScript and TypeScript covering:
1. Injection (SQL, NoSQL, Command, Code)
2. Cross-Site Scripting (DOM-based, Reflected)
3. Hardcoded Secrets & Credentials
4. Insecure Deserialization
5. Path Traversal & File Operations
6. Prototype Pollution
7. Insecure Communication & SSL
8. Information Exposure
9. CORS & Cookie Security
10. SSRF, IDOR, Mass Assignment, Open Redirect
11. SSTI, XXE, File Upload, Rate Limiting
"""

from dataclasses import dataclass, field
from typing import List, Dict, Optional
from enum import Enum
import re


class JSSeverity(Enum):
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    INFO = "Info"


class JSRuleCategory(Enum):
    SQL_INJECTION = "sql_injection"
    NOSQL_INJECTION = "nosql_injection"
    XSS = "xss"
    CODE_INJECTION = "code_injection"
    SHELL_INJECTION = "shell_injection"
    HARDCODED_SECRETS = "hardcoded_secrets"
    INSECURE_DESERIALIZATION = "insecure_deserialization"
    PATH_TRAVERSAL = "path_traversal"
    PROTOTYPE_POLLUTION = "prototype_pollution"
    INSECURE_COMMUNICATION = "insecure_communication"
    SSL_TLS = "ssl_tls"
    INFORMATION_EXPOSURE = "information_exposure"
    REGEX_DOS = "regex_dos"
    CORS = "cors"
    COOKIE_SECURITY = "cookie_security"
    SSRF = "ssrf"
    JWT_SECURITY = "jwt_security"
    IDOR = "idor"
    MASS_ASSIGNMENT = "mass_assignment"
    OPEN_REDIRECT = "open_redirect"
    SSTI = "ssti"
    XXE = "xxe"
    FILE_UPLOAD = "file_upload"
    RATE_LIMITING = "rate_limiting"
    TIMING_ATTACK = "timing_attack"
    DEBUG_CONFIG = "debug_configuration"


@dataclass
class JSSecurityRule:
    """A single JavaScript/TypeScript security rule"""
    id: str
    name: str
    description: str
    category: JSRuleCategory
    severity: JSSeverity
    pattern: str
    remediation: str
    cwe_id: Optional[str] = None
    owasp_category: Optional[str] = None
    confidence: float = 0.8
    check_inside_strings: bool = False


class JavaScriptRuleEngine:
    """Comprehensive JavaScript/TypeScript Security Rule Engine"""

    def __init__(self):
        self.rules: Dict[str, JSSecurityRule] = {}
        self._register_all_rules()

    def _register_all_rules(self):
        # ============================================
        # SQL INJECTION (4 rules)
        # ============================================
        self._register(JSSecurityRule(
            id="JS-001", name="SQL Injection via Template Literal",
            description="SQL query constructed using template literal with embedded expressions",
            category=JSRuleCategory.SQL_INJECTION, severity=JSSeverity.HIGH,
            pattern=r"\.query\s*\(\s*[`\"'].*?\$\{.*\}.*?[`\"']",
            remediation="Use parameterized queries: db.query('SELECT * FROM users WHERE id = ?', [userId])",
            cwe_id="CWE-89", owasp_category="A03:2021-Injection"
        ))
        self._register(JSSecurityRule(
            id="JS-002", name="SQL Injection via Concatenation",
            description="SQL query built using string concatenation with user input",
            category=JSRuleCategory.SQL_INJECTION, severity=JSSeverity.HIGH,
            pattern=r"\.query\s*\(\s*[`\"'].*?\+\s*.*?[`\"']",
            remediation="Use parameterized queries instead of string concatenation",
            cwe_id="CWE-89", owasp_category="A03:2021-Injection"
        ))
        self._register(JSSecurityRule(
            id="JS-003", name="SQL Injection via executeSql",
            description="Web SQL executeSql with concatenated user input",
            category=JSRuleCategory.SQL_INJECTION, severity=JSSeverity.HIGH,
            pattern=r"executeSql\s*\(.*?\+.*?\)",
            remediation="Use parameterized queries with prepared statements",
            cwe_id="CWE-89", owasp_category="A03:2021-Injection"
        ))
        self._register(JSSecurityRule(
            id="JS-004", name="MySQL Query Concatenation",
            description="MySQL query with string concatenation",
            category=JSRuleCategory.SQL_INJECTION, severity=JSSeverity.HIGH,
            pattern=r"mysql\.query.*\+",
            remediation="Use mysql2 with prepared statements: connection.execute('SELECT ? FROM ?', [cols, table])",
            cwe_id="CWE-89", owasp_category="A03:2021-Injection"
        ))

        # ============================================
        # NOSQL INJECTION (2 rules)
        # ============================================
        self._register(JSSecurityRule(
            id="JS-005", name="NoSQL Injection via $where",
            description="MongoDB $where operator with user input enables JavaScript injection",
            category=JSRuleCategory.NOSQL_INJECTION, severity=JSSeverity.CRITICAL,
            pattern=r"\$where.*req\.(body|query|params)",
            remediation="Never use $where with user input. Use standard query operators",
            cwe_id="CWE-943", owasp_category="A03:2021-Injection"
        ))
        self._register(JSSecurityRule(
            id="JS-006", name="NoSQL Injection via $regex",
            description="MongoDB $regex with user input can cause ReDoS or data extraction",
            category=JSRuleCategory.NOSQL_INJECTION, severity=JSSeverity.HIGH,
            pattern=r"\$regex.*req\.(body|query|params)",
            remediation="Sanitize user input before using in regex queries. Use mongo-sanitize",
            cwe_id="CWE-943", confidence=0.7
        ))

        # ============================================
        # XSS (8 rules)
        # ============================================
        self._register(JSSecurityRule(
            id="JS-007", name="DOM XSS via innerHTML",
            description="Setting innerHTML with user-controlled content enables XSS",
            category=JSRuleCategory.XSS, severity=JSSeverity.HIGH,
            pattern=r"\.innerHTML\s*=\s*.*?\+?.*?;",
            remediation="Use textContent instead of innerHTML, or sanitize with DOMPurify",
            cwe_id="CWE-79", owasp_category="A03:2021-Injection"
        ))
        self._register(JSSecurityRule(
            id="JS-008", name="DOM XSS via outerHTML",
            description="Setting outerHTML with user-controlled content enables XSS",
            category=JSRuleCategory.XSS, severity=JSSeverity.HIGH,
            pattern=r"\.outerHTML\s*=\s*.*?\+?.*?;",
            remediation="Use DOM API to create elements instead of outerHTML",
            cwe_id="CWE-79", owasp_category="A03:2021-Injection"
        ))
        self._register(JSSecurityRule(
            id="JS-009", name="DOM XSS via document.write",
            description="document.write() with user input enables XSS",
            category=JSRuleCategory.XSS, severity=JSSeverity.MEDIUM,
            pattern=r"document\.write\s*\(.*?\)",
            remediation="Use DOM APIs (createElement, appendChild) instead of document.write()",
            cwe_id="CWE-79", confidence=0.7
        ))
        self._register(JSSecurityRule(
            id="JS-010", name="Code Execution via eval()",
            description="eval() executes arbitrary JavaScript and is a critical XSS vector",
            category=JSRuleCategory.XSS, severity=JSSeverity.CRITICAL,
            pattern=r"eval\s*\(.*?\)",
            remediation="Avoid eval() entirely. Use JSON.parse() for data, or Function constructor as last resort",
            cwe_id="CWE-95", owasp_category="A03:2021-Injection"
        ))
        self._register(JSSecurityRule(
            id="JS-011", name="XSS via setTimeout String",
            description="setTimeout with string argument acts like eval()",
            category=JSRuleCategory.XSS, severity=JSSeverity.MEDIUM,
            pattern=r"setTimeout\s*\(\s*[\"'`]",
            remediation="Pass a function reference to setTimeout, not a string",
            cwe_id="CWE-79", confidence=0.6
        ))
        self._register(JSSecurityRule(
            id="JS-012", name="XSS via setInterval String",
            description="setInterval with string argument acts like eval()",
            category=JSRuleCategory.XSS, severity=JSSeverity.MEDIUM,
            pattern=r"setInterval\s*\(\s*[\"'`]",
            remediation="Pass a function reference to setInterval, not a string",
            cwe_id="CWE-79", confidence=0.6
        ))
        self._register(JSSecurityRule(
            id="JS-013", name="XSS via Function Constructor",
            description="Function() constructor can execute arbitrary code like eval()",
            category=JSRuleCategory.XSS, severity=JSSeverity.HIGH,
            pattern=r"Function\s*\(.*?\)",
            remediation="Avoid Function() constructor with user-controlled input",
            cwe_id="CWE-79", confidence=0.7
        ))
        self._register(JSSecurityRule(
            id="JS-014", name="DOM XSS via document.writeln",
            description="document.writeln() with user input enables XSS",
            category=JSRuleCategory.XSS, severity=JSSeverity.MEDIUM,
            pattern=r"document\.writeln\s*\(.*?\)",
            remediation="Use DOM APIs instead of document.writeln()",
            cwe_id="CWE-79", confidence=0.7
        ))

        # ============================================
        # HARDCODED SECRETS (3 rules)
        # ============================================
        self._register(JSSecurityRule(
            id="JS-015", name="Hardcoded Password/Secret",
            description="Password or secret key hardcoded in JavaScript source code",
            category=JSRuleCategory.HARDCODED_SECRETS, severity=JSSeverity.HIGH,
            pattern=r"(const|let|var)\s+.*?(password|pwd|apiKey|secretKey)\s*=\s*[\"'](?!\s*$|.*\{|.*env|.*ENV|.*process\.env|.*config|test|demo|example|placeholder|xxx|your_|my_)[A-Za-z0-9!@#$%^&*()_+\-=\[\]{};':,.<>?/~`]{8,}[\"']",
            remediation="Use process.env for secrets: const apiKey = process.env.API_KEY",
            cwe_id="CWE-798", owasp_category="A07:2021-Authentication Failures"
        ))
        self._register(JSSecurityRule(
            id="JS-016", name="Hardcoded Long Secret String",
            description="Long random-looking string likely a hardcoded secret",
            category=JSRuleCategory.HARDCODED_SECRETS, severity=JSSeverity.MEDIUM,
            pattern=r"=\s*[\"'](?!.*-.*-.*-.*-|http|https|www\.|localhost)[A-Za-z0-9]{40,}[\"']",
            remediation="Store long secrets in environment variables or a secrets manager",
            cwe_id="CWE-798", confidence=0.6
        ))
        self._register(JSSecurityRule(
            id="JS-017", name="Hardcoded JWT Secret",
            description="JWT signed with hardcoded secret key",
            category=JSRuleCategory.HARDCODED_SECRETS, severity=JSSeverity.HIGH,
            pattern=r"JWT\.sign\([^,]+,\s*[\"'](?!.*\{|.*env|.*ENV|.*process\.env|.*config)[A-Za-z0-9!@#$%^&*()_+\-=]{16,}[\"']",
            remediation="Load JWT secret from environment: jwt.sign(payload, process.env.JWT_SECRET)",
            cwe_id="CWE-798"
        ))

        # ============================================
        # INSECURE DESERIALIZATION (2 rules)
        # ============================================
        self._register(JSSecurityRule(
            id="JS-018", name="Unsafe JSON Parse",
            description="JSON.parse() with untrusted input may enable prototype pollution",
            category=JSRuleCategory.INSECURE_DESERIALIZATION, severity=JSSeverity.LOW,
            pattern=r"JSON\.parse\s*\(.*?\)",
            remediation="Validate JSON schema after parsing. Use json-schema validation",
            cwe_id="CWE-502", confidence=0.5
        ))
        self._register(JSSecurityRule(
            id="JS-019", name="Code Injection via eval Deserialization",
            description="Using eval() to deserialize data enables arbitrary code execution",
            category=JSRuleCategory.INSECURE_DESERIALIZATION, severity=JSSeverity.CRITICAL,
            pattern=r"eval\s*\(\s*(req\.|request\.|data|input|body)",
            remediation="Use JSON.parse() for data deserialization, never eval()",
            cwe_id="CWE-502", owasp_category="A08:2021-Software and Data Integrity Failures"
        ))

        # ============================================
        # PATH TRAVERSAL (4 rules)
        # ============================================
        self._register(JSSecurityRule(
            id="JS-020", name="Path Traversal via fs.readFile",
            description="File read with user-controlled path via string concatenation",
            category=JSRuleCategory.PATH_TRAVERSAL, severity=JSSeverity.MEDIUM,
            pattern=r"fs\.readFile\s*\(.*?\+.*?\)",
            remediation="Use path.resolve() and validate paths are within allowed directories",
            cwe_id="CWE-22", owasp_category="A01:2021-Broken Access Control", confidence=0.6
        ))
        self._register(JSSecurityRule(
            id="JS-021", name="Path Traversal via fs.writeFile",
            description="File write with user-controlled path via string concatenation",
            category=JSRuleCategory.PATH_TRAVERSAL, severity=JSSeverity.MEDIUM,
            pattern=r"fs\.writeFile\s*\(.*?\+.*?\)",
            remediation="Validate and sanitize file paths before writing",
            cwe_id="CWE-22", confidence=0.6
        ))
        self._register(JSSecurityRule(
            id="JS-022", name="Dynamic require() Injection",
            description="require() with concatenated path enables loading arbitrary modules",
            category=JSRuleCategory.PATH_TRAVERSAL, severity=JSSeverity.MEDIUM,
            pattern=r"require\s*\(.*?\+.*?\)",
            remediation="Use static require paths or validate against an allowlist",
            cwe_id="CWE-22", confidence=0.5
        ))
        self._register(JSSecurityRule(
            id="JS-023", name="Path Traversal Sequence",
            description="Direct use of '../' path traversal detected",
            category=JSRuleCategory.PATH_TRAVERSAL, severity=JSSeverity.MEDIUM,
            pattern=r"\.\./",
            remediation="Use path.normalize() and validate the resolved path prefix",
            cwe_id="CWE-22", confidence=0.5
        ))

        # ============================================
        # SHELL / CODE INJECTION (5 rules)
        # ============================================
        self._register(JSSecurityRule(
            id="JS-024", name="Command Injection via child_process.exec",
            description="child_process.exec() runs commands in a shell, enabling injection",
            category=JSRuleCategory.SHELL_INJECTION, severity=JSSeverity.HIGH,
            pattern=r"child_process\.exec\s*\(",
            remediation="Use child_process.execFile() with arguments array instead of exec()",
            cwe_id="CWE-78", owasp_category="A03:2021-Injection"
        ))
        self._register(JSSecurityRule(
            id="JS-025", name="Command Injection via spawn",
            description="child_process.spawn() may be used with user-controlled arguments",
            category=JSRuleCategory.SHELL_INJECTION, severity=JSSeverity.HIGH,
            pattern=r"child_process\.spawn\s*\(",
            remediation="Validate and sanitize all arguments passed to spawn()",
            cwe_id="CWE-78"
        ))
        self._register(JSSecurityRule(
            id="JS-026", name="Shell Injection via execFile",
            description="child_process.execFile with user-controlled arguments",
            category=JSRuleCategory.SHELL_INJECTION, severity=JSSeverity.MEDIUM,
            pattern=r"child_process\.execFile\s*\(",
            remediation="Validate all arguments and never pass user input directly",
            cwe_id="CWE-78", confidence=0.7
        ))
        self._register(JSSecurityRule(
            id="JS-027", name="VM Context Code Injection",
            description="vm.runInThisContext executes code in current V8 context",
            category=JSRuleCategory.CODE_INJECTION, severity=JSSeverity.HIGH,
            pattern=r"vm\.runInThisContext",
            remediation="Avoid vm module with user-controlled code. Use vm2 for sandboxing",
            cwe_id="CWE-94"
        ))
        self._register(JSSecurityRule(
            id="JS-028", name="VM New Context Code Injection",
            description="vm.runInNewContext can still escape sandbox",
            category=JSRuleCategory.CODE_INJECTION, severity=JSSeverity.HIGH,
            pattern=r"vm\.runInNewContext",
            remediation="Use vm2 or isolated-vm for safer sandboxing",
            cwe_id="CWE-94"
        ))

        # ============================================
        # PROTOTYPE POLLUTION (3 rules)
        # ============================================
        self._register(JSSecurityRule(
            id="JS-029", name="Prototype Pollution via __proto__",
            description="Direct __proto__ access enables prototype pollution attacks",
            category=JSRuleCategory.PROTOTYPE_POLLUTION, severity=JSSeverity.HIGH,
            pattern=r"__proto__",
            remediation="Use Object.create(null) for dictionaries, validate property names",
            cwe_id="CWE-1321", confidence=0.7
        ))
        self._register(JSSecurityRule(
            id="JS-030", name="Prototype Pollution via constructor.prototype",
            description="Accessing constructor.prototype enables prototype manipulation",
            category=JSRuleCategory.PROTOTYPE_POLLUTION, severity=JSSeverity.HIGH,
            pattern=r"constructor\.prototype",
            remediation="Freeze prototypes: Object.freeze(Object.prototype)",
            cwe_id="CWE-1321", confidence=0.7
        ))
        self._register(JSSecurityRule(
            id="JS-031", name="Prototype Pollution via Object.assign",
            description="Object.assign with __proto__ can pollute the object prototype",
            category=JSRuleCategory.PROTOTYPE_POLLUTION, severity=JSSeverity.HIGH,
            pattern=r"Object\.assign.*__proto__",
            remediation="Filter out __proto__, constructor, and prototype keys before Object.assign",
            cwe_id="CWE-1321"
        ))

        # ============================================
        # INSECURE COMMUNICATION (4 rules)
        # ============================================
        self._register(JSSecurityRule(
            id="JS-032", name="HTTP Without TLS",
            description="Using unencrypted HTTP which exposes data in transit",
            category=JSRuleCategory.INSECURE_COMMUNICATION, severity=JSSeverity.MEDIUM,
            pattern=r"http:\/\/",
            remediation="Use HTTPS for all communications",
            cwe_id="CWE-319", confidence=0.6
        ))
        self._register(JSSecurityRule(
            id="JS-033", name="Insecure WebSocket",
            description="Using unencrypted WebSocket (ws://) instead of secure (wss://)",
            category=JSRuleCategory.INSECURE_COMMUNICATION, severity=JSSeverity.MEDIUM,
            pattern=r"ws:\/\/",
            remediation="Use wss:// for WebSocket connections",
            cwe_id="CWE-319", confidence=0.6
        ))
        self._register(JSSecurityRule(
            id="JS-034", name="SSL Verification Disabled (rejectUnauthorized)",
            description="TLS certificate verification disabled with rejectUnauthorized: false",
            category=JSRuleCategory.SSL_TLS, severity=JSSeverity.HIGH,
            pattern=r"rejectUnauthorized\s*:\s*false",
            remediation="Set rejectUnauthorized: true to validate TLS certificates",
            cwe_id="CWE-295", owasp_category="A02:2021-Cryptographic Failures"
        ))
        self._register(JSSecurityRule(
            id="JS-035", name="SSL Verification Disabled (strictSSL)",
            description="SSL verification disabled with strictSSL: false",
            category=JSRuleCategory.SSL_TLS, severity=JSSeverity.HIGH,
            pattern=r"strictSSL\s*:\s*false",
            remediation="Set strictSSL: true to enable SSL certificate validation",
            cwe_id="CWE-295"
        ))

        # ============================================
        # INFORMATION EXPOSURE (3 rules)
        # ============================================
        self._register(JSSecurityRule(
            id="JS-036", name="Password Logged to Console",
            description="Password value logged to console which appears in server logs",
            category=JSRuleCategory.INFORMATION_EXPOSURE, severity=JSSeverity.MEDIUM,
            pattern=r"console\.log.*password",
            remediation="Never log sensitive values. Use structured logging with field masking",
            cwe_id="CWE-532", confidence=0.6
        ))
        self._register(JSSecurityRule(
            id="JS-037", name="Secret in Console Error",
            description="Secret value logged to console.error",
            category=JSRuleCategory.INFORMATION_EXPOSURE, severity=JSSeverity.MEDIUM,
            pattern=r"console\.error.*secret",
            remediation="Mask sensitive values in error logs",
            cwe_id="CWE-532", confidence=0.6
        ))
        self._register(JSSecurityRule(
            id="JS-038", name="Stack Trace in Response",
            description="Error stack trace sent in HTTP response exposes internals",
            category=JSRuleCategory.INFORMATION_EXPOSURE, severity=JSSeverity.MEDIUM,
            pattern=r"res\.send.*error.*stack",
            remediation="Send generic error messages to clients. Log stack traces server-side only",
            cwe_id="CWE-209", confidence=0.7
        ))

        # ============================================
        # REGEX DOS (2 rules)
        # ============================================
        self._register(JSSecurityRule(
            id="JS-039", name="ReDoS via Repeated Group (+)",
            description="Regex with repeated group (...)+ can cause catastrophic backtracking",
            category=JSRuleCategory.REGEX_DOS, severity=JSSeverity.LOW,
            pattern=r"\/\([^\)]*\)\+\/",
            remediation="Use re2 library for safe regex execution, or simplify the pattern",
            cwe_id="CWE-1333", confidence=0.5
        ))
        self._register(JSSecurityRule(
            id="JS-040", name="ReDoS via Repeated Group (*)",
            description="Regex with repeated group (...)* can cause catastrophic backtracking",
            category=JSRuleCategory.REGEX_DOS, severity=JSSeverity.LOW,
            pattern=r"\/\([^\)]*\)\*\/",
            remediation="Use re2 library for safe regex, or limit input length",
            cwe_id="CWE-1333", confidence=0.5
        ))

        # ============================================
        # CORS (2 rules)
        # ============================================
        self._register(JSSecurityRule(
            id="JS-041", name="CORS Wildcard Origin",
            description="Access-Control-Allow-Origin set to * allows any domain",
            category=JSRuleCategory.CORS, severity=JSSeverity.MEDIUM,
            pattern=r"Access-Control-Allow-Origin\s*:\s*\"\\*\"",
            remediation="Set specific allowed origins instead of wildcard",
            cwe_id="CWE-942", confidence=0.7
        ))
        self._register(JSSecurityRule(
            id="JS-042", name="Express CORS Wildcard",
            description="Express CORS middleware configured with origin: '*'",
            category=JSRuleCategory.CORS, severity=JSSeverity.MEDIUM,
            pattern=r"app\.use\s*\(\s*cors\s*\(\s*\{.*origin\s*:\s*'\*'",
            remediation="Configure specific allowed origins: cors({ origin: ['https://myapp.com'] })",
            cwe_id="CWE-942"
        ))

        # ============================================
        # COOKIE SECURITY (2 rules)
        # ============================================
        self._register(JSSecurityRule(
            id="JS-043", name="Cookie Without HttpOnly",
            description="Cookie accessible to JavaScript (httpOnly: false) enabling XSS theft",
            category=JSRuleCategory.COOKIE_SECURITY, severity=JSSeverity.MEDIUM,
            pattern=r"httpOnly\s*:\s*false",
            remediation="Set httpOnly: true to prevent JavaScript cookie access",
            cwe_id="CWE-1004", confidence=0.6
        ))
        self._register(JSSecurityRule(
            id="JS-044", name="Cookie Without Secure Flag",
            description="Cookie sent over insecure HTTP connections",
            category=JSRuleCategory.COOKIE_SECURITY, severity=JSSeverity.MEDIUM,
            pattern=r"secure\s*:\s*false",
            remediation="Set secure: true to only send cookies over HTTPS",
            cwe_id="CWE-614", confidence=0.7
        ))

        # ============================================
        # SSRF (2 rules)
        # ============================================
        self._register(JSSecurityRule(
            id="JS-045", name="SSRF via HTTP Client",
            description="HTTP request with user-controlled URL enabling SSRF",
            category=JSRuleCategory.SSRF, severity=JSSeverity.HIGH,
            pattern=r"(axios|http|https)\.(get|post)\s*\(.*(req\.body|req\.query|url).*\)",
            remediation="Validate URLs against an allowlist. Block internal IP ranges",
            cwe_id="CWE-918", owasp_category="A10:2021-SSRF", confidence=0.7
        ))
        self._register(JSSecurityRule(
            id="JS-046", name="SSRF via fetch()",
            description="fetch() with user-controlled URL can access internal services",
            category=JSRuleCategory.SSRF, severity=JSSeverity.HIGH,
            pattern=r"fetch\s*\(.*(req\.body|req\.query|url).*\)",
            remediation="Validate and whitelist URLs before passing to fetch()",
            cwe_id="CWE-918", owasp_category="A10:2021-SSRF", confidence=0.7
        ))

        # ============================================
        # JWT SECURITY (1 rule)
        # ============================================
        self._register(JSSecurityRule(
            id="JS-047", name="JWT None Algorithm",
            description="JWT signed with 'none' algorithm disabling signature verification",
            category=JSRuleCategory.JWT_SECURITY, severity=JSSeverity.CRITICAL,
            pattern=r"jwt\.sign\s*\(.*['\"]none['\"]",
            remediation="Always use strong algorithms: jwt.sign(payload, secret, { algorithm: 'HS256' })",
            cwe_id="CWE-345", owasp_category="A02:2021-Cryptographic Failures"
        ))

        # ============================================
        # IDOR (2 rules)
        # ============================================
        self._register(JSSecurityRule(
            id="JS-048", name="IDOR via Direct Database Lookup",
            description="Database query with user-provided ID without authorization check",
            category=JSRuleCategory.IDOR, severity=JSSeverity.HIGH,
            pattern=r"(Model|db|collection)\.(find|findOne|findById|deleteOne|updateOne)\s*\(.*req\.(params|query|body)",
            remediation="Verify requesting user has authorization to access the object",
            cwe_id="CWE-639", owasp_category="A01:2021-Broken Access Control", confidence=0.7
        ))
        self._register(JSSecurityRule(
            id="JS-049", name="IDOR via Unsanitized Params",
            description="Request parameter used for object lookup without ownership verification",
            category=JSRuleCategory.IDOR, severity=JSSeverity.MEDIUM,
            pattern=r"req\.params\.(id|userId|studentId)\s*(?!.*===.*req\.user)",
            remediation="Always check req.user.id === resource.ownerId before access",
            cwe_id="CWE-639", confidence=0.6
        ))

        # ============================================
        # MASS ASSIGNMENT (3 rules)
        # ============================================
        self._register(JSSecurityRule(
            id="JS-050", name="Mass Assignment via Object.assign",
            description="Object.assign merges all request body properties into object",
            category=JSRuleCategory.MASS_ASSIGNMENT, severity=JSSeverity.HIGH,
            pattern=r"Object\.assign\s*\(.*,\s*req\.body\s*\)",
            remediation="Destructure only allowed fields: const { name, email } = req.body",
            cwe_id="CWE-915", owasp_category="A04:2021-Insecure Design"
        ))
        self._register(JSSecurityRule(
            id="JS-051", name="Mass Assignment via Spread Operator",
            description="Spread operator copies all request body properties",
            category=JSRuleCategory.MASS_ASSIGNMENT, severity=JSSeverity.HIGH,
            pattern=r"\{\s*\.\.\.req\.body\s*\}",
            remediation="Pick specific fields: { name: req.body.name, email: req.body.email }",
            cwe_id="CWE-915"
        ))
        self._register(JSSecurityRule(
            id="JS-052", name="Mass Assignment via Constructor",
            description="Model constructor receives entire request body",
            category=JSRuleCategory.MASS_ASSIGNMENT, severity=JSSeverity.HIGH,
            pattern=r"new\s+\w+\(\s*req\.body\s*\)",
            remediation="Explicitly pick allowed fields before passing to constructor",
            cwe_id="CWE-915", confidence=0.7
        ))

        # ============================================
        # OPEN REDIRECT (2 rules)
        # ============================================
        self._register(JSSecurityRule(
            id="JS-053", name="Open Redirect via res.redirect",
            description="Express redirect with user-controlled URL from request",
            category=JSRuleCategory.OPEN_REDIRECT, severity=JSSeverity.HIGH,
            pattern=r"res\.redirect\s*\(\s*req\.(query|body|params)",
            remediation="Validate redirect URL against an allowlist of domains",
            cwe_id="CWE-601", owasp_category="A01:2021-Broken Access Control"
        ))
        self._register(JSSecurityRule(
            id="JS-054", name="Open Redirect via window.location",
            description="Client-side redirect with user-controlled URL",
            category=JSRuleCategory.OPEN_REDIRECT, severity=JSSeverity.HIGH,
            pattern=r"window\.location\s*=\s*.*req\.(query|body|params)",
            remediation="Validate redirect targets and use relative URLs",
            cwe_id="CWE-601"
        ))

        # ============================================
        # SSTI (3 rules)
        # ============================================
        self._register(JSSecurityRule(
            id="JS-055", name="SSTI via EJS render",
            description="EJS template rendered with user input enables template injection",
            category=JSRuleCategory.SSTI, severity=JSSeverity.CRITICAL,
            pattern=r"ejs\.render\s*\(.*req\.(body|query)",
            remediation="Use ejs.renderFile() with template files, never render user strings",
            cwe_id="CWE-1336", owasp_category="A03:2021-Injection"
        ))
        self._register(JSSecurityRule(
            id="JS-056", name="SSTI via Pug render",
            description="Pug template compiled from user input",
            category=JSRuleCategory.SSTI, severity=JSSeverity.HIGH,
            pattern=r"pug\.render\s*\(.*req\.(body|query)",
            remediation="Use pug.renderFile() with precompiled templates only",
            cwe_id="CWE-1336"
        ))
        self._register(JSSecurityRule(
            id="JS-057", name="SSTI via Handlebars compile",
            description="Handlebars template compiled from user input",
            category=JSRuleCategory.SSTI, severity=JSSeverity.HIGH,
            pattern=r"handlebars\.compile\s*\(.*req\.(body|query)",
            remediation="Precompile templates at build time, never from user input",
            cwe_id="CWE-1336"
        ))

        # ============================================
        # XXE (2 rules)
        # ============================================
        self._register(JSSecurityRule(
            id="JS-058", name="XXE via XML Parser",
            description="XML parsing with user input without disabling external entities",
            category=JSRuleCategory.XXE, severity=JSSeverity.HIGH,
            pattern=r"(parseString|parseXML|xml2js)\s*\(.*req\.(body|query)",
            remediation="Disable external entities: parser.parseString(xml, { explicitRoot: false })",
            cwe_id="CWE-611", owasp_category="A05:2021-Security Misconfiguration", confidence=0.7
        ))
        self._register(JSSecurityRule(
            id="JS-059", name="XXE via DOMParser",
            description="DOMParser.parseFromString can process external entities",
            category=JSRuleCategory.XXE, severity=JSSeverity.MEDIUM,
            pattern=r"DOMParser.*parseFromString",
            remediation="Validate and sanitize XML input before parsing",
            cwe_id="CWE-611", confidence=0.5
        ))

        # ============================================
        # FILE UPLOAD (2 rules)
        # ============================================
        self._register(JSSecurityRule(
            id="JS-060", name="Multer Without File Filter",
            description="Multer file upload without fileFilter allows any file type",
            category=JSRuleCategory.FILE_UPLOAD, severity=JSSeverity.MEDIUM,
            pattern=r"multer\s*\(\s*\{(?!.*fileFilter)",
            remediation="Add fileFilter to multer config to restrict file types",
            cwe_id="CWE-434", confidence=0.6
        ))
        self._register(JSSecurityRule(
            id="JS-061", name="Unvalidated File Upload",
            description="File upload handler without type validation",
            category=JSRuleCategory.FILE_UPLOAD, severity=JSSeverity.MEDIUM,
            pattern=r"upload\.(single|array|any)\s*\(",
            remediation="Validate file type, size, and content after upload",
            cwe_id="CWE-434", confidence=0.5
        ))

        # ============================================
        # RATE LIMITING (1 rule)
        # ============================================
        self._register(JSSecurityRule(
            id="JS-062", name="Missing Rate Limiting on Auth Endpoints",
            description="Authentication endpoints without rate limiting enable brute force",
            category=JSRuleCategory.RATE_LIMITING, severity=JSSeverity.MEDIUM,
            pattern=r"app\.(post|get)\s*\(['\"].*(login|auth|register|password)['\"](?!.*rateLimit|.*limiter)",
            remediation="Add express-rate-limit: app.use('/login', rateLimit({ windowMs: 15*60*1000, max: 5 }))",
            cwe_id="CWE-307", confidence=0.5
        ))

        # ============================================
        # TIMING ATTACK (2 rules)
        # ============================================
        self._register(JSSecurityRule(
            id="JS-063", name="Timing Attack on Password",
            description="String equality used for password comparison leaks timing info",
            category=JSRuleCategory.TIMING_ATTACK, severity=JSSeverity.MEDIUM,
            pattern=r"===?\s*.*password|password.*===?",
            remediation="Use crypto.timingSafeEqual() for constant-time comparison",
            cwe_id="CWE-208", confidence=0.5
        ))
        self._register(JSSecurityRule(
            id="JS-064", name="Timing Attack on Token",
            description="String equality used for token comparison leaks timing info",
            category=JSRuleCategory.TIMING_ATTACK, severity=JSSeverity.MEDIUM,
            pattern=r"if\s*\(.*token\s*===?\s*",
            remediation="Use crypto.timingSafeEqual() for constant-time token comparison",
            cwe_id="CWE-208", confidence=0.5
        ))

        # ============================================
        # DEBUG CONFIGURATION (1 rule)
        # ============================================
        self._register(JSSecurityRule(
            id="JS-065", name="Node.js Development Mode Check",
            description="Checking for development mode may enable debug features in production",
            category=JSRuleCategory.DEBUG_CONFIG, severity=JSSeverity.LOW,
            pattern=r"process\.env\.NODE_ENV\s*===\s*['\"]development['\"]",
            remediation="Ensure debug features are properly gated and not accidentally enabled",
            cwe_id="CWE-215", confidence=0.5
        ))

    def _register(self, rule: JSSecurityRule):
        self.rules[rule.id] = rule

    def get_rules_for_category(self, category: JSRuleCategory) -> List[JSSecurityRule]:
        return [r for r in self.rules.values() if r.category == category]

    def scan_code(self, code: str, filename: str = "") -> List[Dict]:
        """Scan JavaScript/TypeScript code against all structured rules"""
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
                            'scanner': 'javascript_security_rules'
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
