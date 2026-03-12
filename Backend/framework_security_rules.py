"""
Framework & Mobile Security Rules - Comprehensive Structured Ruleset

Structured security rules for:
- Web Frameworks: React, Vue, Angular, Flask, Django, Express, Next.js
- Mobile: Swift/iOS, Kotlin/Android, Dart/Flutter
"""

from dataclasses import dataclass, field
from typing import List, Dict, Optional
from enum import Enum
import re


class FrameworkSeverity(Enum):
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    INFO = "Info"


class FrameworkCategory(Enum):
    # Web Frameworks
    REACT = "react_security"
    VUE = "vue_security"
    ANGULAR = "angular_security"
    FLASK = "flask_security"
    DJANGO = "django_security"
    EXPRESS = "express_security"
    NEXTJS = "nextjs_security"
    # Mobile
    SWIFT_IOS = "swift_ios_security"
    KOTLIN_ANDROID = "kotlin_android_security"
    DART_FLUTTER = "dart_flutter_security"


@dataclass
class FrameworkSecurityRule:
    """A single framework/mobile security rule"""
    id: str
    name: str
    description: str
    category: FrameworkCategory
    severity: FrameworkSeverity
    pattern: str
    languages: List[str]
    remediation: str
    cwe_id: Optional[str] = None
    owasp_category: Optional[str] = None
    confidence: float = 0.8


class FrameworkRuleEngine:
    """Comprehensive Framework & Mobile Security Rule Engine"""

    def __init__(self):
        self.rules: Dict[str, FrameworkSecurityRule] = {}
        self._register_all_rules()

    def _register_all_rules(self):
        # ============================================
        # REACT (5 rules)
        # ============================================
        self._register(FrameworkSecurityRule(
            id="FW-001", name="React dangerouslySetInnerHTML",
            description="dangerouslySetInnerHTML bypasses React's XSS protection",
            category=FrameworkCategory.REACT, severity=FrameworkSeverity.HIGH,
            pattern=r"dangerouslySetInnerHTML",
            languages=["javascript", "typescript"],
            remediation="Sanitize HTML with DOMPurify before using dangerouslySetInnerHTML",
            cwe_id="CWE-79", owasp_category="A03:2021-Injection"
        ))
        self._register(FrameworkSecurityRule(
            id="FW-002", name="React Unsafe Component Methods",
            description="Deprecated unsafe lifecycle methods may introduce vulnerabilities",
            category=FrameworkCategory.REACT, severity=FrameworkSeverity.MEDIUM,
            pattern=r"(UNSAFE_componentWillMount|UNSAFE_componentWillReceiveProps|UNSAFE_componentWillUpdate)",
            languages=["javascript", "typescript"],
            remediation="Migrate to safe alternatives: getDerivedStateFromProps, componentDidMount",
            cwe_id="CWE-477", confidence=0.6
        ))
        self._register(FrameworkSecurityRule(
            id="FW-003", name="React href JavaScript Protocol",
            description="href='javascript:...' enables XSS in React components",
            category=FrameworkCategory.REACT, severity=FrameworkSeverity.HIGH,
            pattern=r"href\s*=\s*[{\"']javascript:",
            languages=["javascript", "typescript"],
            remediation="Validate URLs and block javascript: protocol in href attributes",
            cwe_id="CWE-79"
        ))
        self._register(FrameworkSecurityRule(
            id="FW-004", name="React Unescaped User Data in JSX",
            description="User input rendered directly in JSX without escaping",
            category=FrameworkCategory.REACT, severity=FrameworkSeverity.MEDIUM,
            pattern=r"<\w+[^>]*>\s*\{.*?(user|input|query|param|data).*?\}\s*</\w+>",
            languages=["javascript", "typescript"],
            remediation="React auto-escapes by default, but verify no dangerouslySetInnerHTML is used",
            cwe_id="CWE-79", confidence=0.4
        ))
        self._register(FrameworkSecurityRule(
            id="FW-005", name="React createRef for DOM Manipulation",
            description="Direct DOM manipulation via refs can bypass React's virtual DOM security",
            category=FrameworkCategory.REACT, severity=FrameworkSeverity.LOW,
            pattern=r"(createRef|useRef)\s*\(",
            languages=["javascript", "typescript"],
            remediation="Avoid direct DOM manipulation. Use React state and props instead",
            confidence=0.3
        ))

        # ============================================
        # VUE (5 rules)
        # ============================================
        self._register(FrameworkSecurityRule(
            id="FW-006", name="Vue v-html Directive",
            description="v-html renders raw HTML bypassing Vue's XSS protection",
            category=FrameworkCategory.VUE, severity=FrameworkSeverity.HIGH,
            pattern=r"v-html\s*=",
            languages=["javascript", "typescript"],
            remediation="Use v-text for safe text rendering, or sanitize with DOMPurify before v-html",
            cwe_id="CWE-79", owasp_category="A03:2021-Injection"
        ))
        self._register(FrameworkSecurityRule(
            id="FW-007", name="Vue Unsafe Template Compilation",
            description="Vue.compile() with user input enables template injection",
            category=FrameworkCategory.VUE, severity=FrameworkSeverity.CRITICAL,
            pattern=r"Vue\.compile\s*\(|compileToFunctions\s*\(",
            languages=["javascript", "typescript"],
            remediation="Never compile templates from user input. Use pre-compiled templates",
            cwe_id="CWE-1336"
        ))
        self._register(FrameworkSecurityRule(
            id="FW-008", name="Vue Unvalidated Props",
            description="Vue props without type validation can receive unexpected data",
            category=FrameworkCategory.VUE, severity=FrameworkSeverity.LOW,
            pattern=r"props\s*:\s*\[",
            languages=["javascript", "typescript"],
            remediation="Use object syntax with type validation: props: { name: { type: String, required: true } }",
            confidence=0.3
        ))
        self._register(FrameworkSecurityRule(
            id="FW-009", name="Vue Runtime Template Compilation",
            description="Full build with runtime template compilation increases attack surface",
            category=FrameworkCategory.VUE, severity=FrameworkSeverity.MEDIUM,
            pattern=r"template\s*:\s*[\"'`].*?\{.*?\}",
            languages=["javascript", "typescript"],
            remediation="Use pre-compiled .vue SFC files instead of runtime template strings",
            confidence=0.4
        ))
        self._register(FrameworkSecurityRule(
            id="FW-010", name="Vue Server-Side XSS",
            description="Vue SSR with unescaped user data can cause server-side XSS",
            category=FrameworkCategory.VUE, severity=FrameworkSeverity.HIGH,
            pattern=r"renderToString\s*\(.*?(user|input|query|param).*?\)",
            languages=["javascript", "typescript"],
            remediation="Ensure all user data is properly escaped in SSR context",
            cwe_id="CWE-79", confidence=0.6
        ))

        # ============================================
        # ANGULAR (5 rules)
        # ============================================
        self._register(FrameworkSecurityRule(
            id="FW-011", name="Angular bypassSecurityTrust",
            description="bypassSecurityTrust* methods bypass Angular's built-in XSS protection",
            category=FrameworkCategory.ANGULAR, severity=FrameworkSeverity.HIGH,
            pattern=r"bypassSecurityTrust(Html|Script|Style|Url|ResourceUrl)",
            languages=["typescript"],
            remediation="Avoid bypassing Angular sanitization. Use DomSanitizer properly",
            cwe_id="CWE-79", owasp_category="A03:2021-Injection"
        ))
        self._register(FrameworkSecurityRule(
            id="FW-012", name="Angular innerHTML Binding",
            description="[innerHTML] binding renders raw HTML in Angular templates",
            category=FrameworkCategory.ANGULAR, severity=FrameworkSeverity.MEDIUM,
            pattern=r"\[innerHTML\]\s*=",
            languages=["typescript"],
            remediation="Angular sanitizes innerHTML by default, but verify no bypass is used",
            cwe_id="CWE-79", confidence=0.6
        ))
        self._register(FrameworkSecurityRule(
            id="FW-013", name="Angular Disabled Route Guards",
            description="Routes without proper guards allow unauthorized access",
            category=FrameworkCategory.ANGULAR, severity=FrameworkSeverity.HIGH,
            pattern=r"path\s*:\s*['\"].*?['\"](?!.*canActivate|.*canLoad|.*guard)",
            languages=["typescript"],
            remediation="Add CanActivate or CanLoad guards to protect routes",
            cwe_id="CWE-862", confidence=0.4
        ))
        self._register(FrameworkSecurityRule(
            id="FW-014", name="Angular ElementRef nativeElement",
            description="Direct DOM access via nativeElement bypasses Angular's security",
            category=FrameworkCategory.ANGULAR, severity=FrameworkSeverity.MEDIUM,
            pattern=r"\.nativeElement\.(innerHTML|outerHTML|insertAdjacentHTML)",
            languages=["typescript"],
            remediation="Use Angular Renderer2 for DOM manipulation instead of nativeElement",
            cwe_id="CWE-79"
        ))
        self._register(FrameworkSecurityRule(
            id="FW-015", name="Angular HTTP Without Interceptors",
            description="Direct HttpClient usage without interceptors for auth/logging",
            category=FrameworkCategory.ANGULAR, severity=FrameworkSeverity.LOW,
            pattern=r"HttpClient\s*\.\s*(get|post|put|delete)\s*\(",
            languages=["typescript"],
            remediation="Use HTTP interceptors for consistent auth headers and error handling",
            confidence=0.3
        ))

        # ============================================
        # FLASK (5 rules)
        # ============================================
        self._register(FrameworkSecurityRule(
            id="FW-016", name="Flask Debug Mode in Production",
            description="Flask debug mode exposes interactive debugger and stack traces",
            category=FrameworkCategory.FLASK, severity=FrameworkSeverity.HIGH,
            pattern=r"app\.run\s*\(.*debug\s*=\s*True",
            languages=["python"],
            remediation="Set debug=False in production: app.run(debug=False)",
            cwe_id="CWE-215"
        ))
        self._register(FrameworkSecurityRule(
            id="FW-017", name="Flask Hardcoded Secret Key",
            description="Flask secret key hardcoded instead of loaded from environment",
            category=FrameworkCategory.FLASK, severity=FrameworkSeverity.HIGH,
            pattern=r"app\.secret_key\s*=\s*[\"'][^\"']+[\"']",
            languages=["python"],
            remediation="Load from environment: app.secret_key = os.environ['SECRET_KEY']",
            cwe_id="CWE-798"
        ))
        self._register(FrameworkSecurityRule(
            id="FW-018", name="Flask CSRF Protection Missing",
            description="Flask-WTF CSRF protection disabled",
            category=FrameworkCategory.FLASK, severity=FrameworkSeverity.HIGH,
            pattern=r"WTF_CSRF_ENABLED\s*=\s*False|CSRF_ENABLED\s*=\s*False",
            languages=["python"],
            remediation="Enable CSRF protection: WTF_CSRF_ENABLED = True",
            cwe_id="CWE-352", owasp_category="A01:2021-Broken Access Control"
        ))
        self._register(FrameworkSecurityRule(
            id="FW-019", name="Flask send_file Path Traversal",
            description="Flask send_file with user-controlled path enables file download",
            category=FrameworkCategory.FLASK, severity=FrameworkSeverity.HIGH,
            pattern=r"send_file\s*\(.*request\.",
            languages=["python"],
            remediation="Use send_from_directory() with validated filenames",
            cwe_id="CWE-22"
        ))
        self._register(FrameworkSecurityRule(
            id="FW-020", name="Flask Jinja2 autoescape Disabled",
            description="Jinja2 autoescape disabled, enabling XSS",
            category=FrameworkCategory.FLASK, severity=FrameworkSeverity.HIGH,
            pattern=r"autoescape\s*=\s*False|Markup\s*\(",
            languages=["python"],
            remediation="Keep autoescape=True (default in Flask). Avoid Markup() with user input",
            cwe_id="CWE-79"
        ))

        # ============================================
        # DJANGO (5 rules)
        # ============================================
        self._register(FrameworkSecurityRule(
            id="FW-021", name="Django mark_safe with User Input",
            description="Django mark_safe() disables auto-escaping, enabling XSS",
            category=FrameworkCategory.DJANGO, severity=FrameworkSeverity.HIGH,
            pattern=r"mark_safe\s*\(.*?(request|user_input|form|data)",
            languages=["python"],
            remediation="Never use mark_safe() with user-controlled content",
            cwe_id="CWE-79", owasp_category="A03:2021-Injection"
        ))
        self._register(FrameworkSecurityRule(
            id="FW-022", name="Django Raw SQL Query",
            description="Django raw() or extra() SQL with string formatting",
            category=FrameworkCategory.DJANGO, severity=FrameworkSeverity.HIGH,
            pattern=r"\.(raw|extra)\s*\(.*?(%s|%d|\{|\.format|\+)",
            languages=["python"],
            remediation="Use Django ORM or parameterized raw queries: Model.objects.raw('SELECT * WHERE id=%s', [id])",
            cwe_id="CWE-89"
        ))
        self._register(FrameworkSecurityRule(
            id="FW-023", name="Django DEBUG True in Settings",
            description="Django DEBUG=True in production exposes sensitive information",
            category=FrameworkCategory.DJANGO, severity=FrameworkSeverity.HIGH,
            pattern=r"DEBUG\s*=\s*True",
            languages=["python"],
            remediation="Set DEBUG = False in production settings",
            cwe_id="CWE-215", confidence=0.6
        ))
        self._register(FrameworkSecurityRule(
            id="FW-024", name="Django ALLOWED_HOSTS Empty",
            description="Empty ALLOWED_HOSTS allows host header attacks",
            category=FrameworkCategory.DJANGO, severity=FrameworkSeverity.MEDIUM,
            pattern=r"ALLOWED_HOSTS\s*=\s*\[\s*\]|ALLOWED_HOSTS\s*=\s*\[\s*'\*'\s*\]",
            languages=["python"],
            remediation="Set specific allowed hosts: ALLOWED_HOSTS = ['example.com']",
            cwe_id="CWE-20"
        ))
        self._register(FrameworkSecurityRule(
            id="FW-025", name="Django |safe Template Filter",
            description="Django |safe filter in templates disables auto-escaping",
            category=FrameworkCategory.DJANGO, severity=FrameworkSeverity.MEDIUM,
            pattern=r"\|\s*safe\s*\}",
            languages=["python"],
            remediation="Remove |safe filter or sanitize content before passing to template",
            cwe_id="CWE-79", confidence=0.6
        ))

        # ============================================
        # EXPRESS (5 rules)
        # ============================================
        self._register(FrameworkSecurityRule(
            id="FW-026", name="Express Missing Helmet Security Headers",
            description="Express app without Helmet security middleware",
            category=FrameworkCategory.EXPRESS, severity=FrameworkSeverity.MEDIUM,
            pattern=r"express\s*\(\s*\)(?!.*helmet)",
            languages=["javascript", "typescript"],
            remediation="Add Helmet: const helmet = require('helmet'); app.use(helmet())",
            cwe_id="CWE-693", confidence=0.4
        ))
        self._register(FrameworkSecurityRule(
            id="FW-027", name="Express Body Parser Size Limit Missing",
            description="Express body parser without size limit enables DoS via large payloads",
            category=FrameworkCategory.EXPRESS, severity=FrameworkSeverity.MEDIUM,
            pattern=r"bodyParser\.json\s*\(\s*\)|express\.json\s*\(\s*\)",
            languages=["javascript", "typescript"],
            remediation="Set size limit: express.json({ limit: '100kb' })",
            cwe_id="CWE-400", confidence=0.5
        ))
        self._register(FrameworkSecurityRule(
            id="FW-028", name="Express Hardcoded Session Secret",
            description="Express session secret hardcoded in source code",
            category=FrameworkCategory.EXPRESS, severity=FrameworkSeverity.HIGH,
            pattern=r"session\s*\(\s*\{.*secret\s*:\s*[\"'][^\"']+[\"']",
            languages=["javascript", "typescript"],
            remediation="Load from environment: session({ secret: process.env.SESSION_SECRET })",
            cwe_id="CWE-798"
        ))
        self._register(FrameworkSecurityRule(
            id="FW-029", name="Express CORS Allow All Origins",
            description="Express CORS configured to allow all origins",
            category=FrameworkCategory.EXPRESS, severity=FrameworkSeverity.MEDIUM,
            pattern=r"cors\s*\(\s*\{?\s*origin\s*:\s*['\"]?\*['\"]?",
            languages=["javascript", "typescript"],
            remediation="Specify allowed origins: cors({ origin: ['https://trusted.com'] })",
            cwe_id="CWE-942"
        ))
        self._register(FrameworkSecurityRule(
            id="FW-030", name="Express Static Files Dot Files",
            description="Express static middleware serving dot files (e.g., .env, .git)",
            category=FrameworkCategory.EXPRESS, severity=FrameworkSeverity.HIGH,
            pattern=r"express\.static\s*\(.*dotfiles\s*:\s*['\"]allow['\"]",
            languages=["javascript", "typescript"],
            remediation="Set dotfiles: 'deny' in express.static options",
            cwe_id="CWE-538"
        ))

        # ============================================
        # NEXT.JS (3 rules)
        # ============================================
        self._register(FrameworkSecurityRule(
            id="FW-031", name="Next.js API Route Without Auth",
            description="Next.js API route handler without authentication check",
            category=FrameworkCategory.NEXTJS, severity=FrameworkSeverity.MEDIUM,
            pattern=r"export\s+default\s+(async\s+)?function\s+handler\s*\(req.*res\)(?!.*auth|.*session|.*token|.*jwt)",
            languages=["javascript", "typescript"],
            remediation="Add authentication middleware or checks to API routes",
            cwe_id="CWE-306", confidence=0.4
        ))
        self._register(FrameworkSecurityRule(
            id="FW-032", name="Next.js Environment Variable Exposure",
            description="Non-NEXT_PUBLIC_ env vars may be exposed to client-side code",
            category=FrameworkCategory.NEXTJS, severity=FrameworkSeverity.HIGH,
            pattern=r"process\.env\.((?!NEXT_PUBLIC_)\w+)",
            languages=["javascript", "typescript"],
            remediation="Only expose env vars with NEXT_PUBLIC_ prefix to client-side code",
            cwe_id="CWE-200", confidence=0.4
        ))
        self._register(FrameworkSecurityRule(
            id="FW-033", name="Next.js getServerSideProps Data Leak",
            description="getServerSideProps returning sensitive data to client",
            category=FrameworkCategory.NEXTJS, severity=FrameworkSeverity.MEDIUM,
            pattern=r"getServerSideProps.*return\s*\{.*props\s*:.*\b(password|secret|token|key)\b",
            languages=["javascript", "typescript"],
            remediation="Filter sensitive fields before returning props from getServerSideProps",
            cwe_id="CWE-200", confidence=0.5
        ))

        # ============================================
        # SWIFT / iOS (10 rules)
        # ============================================
        self._register(FrameworkSecurityRule(
            id="FW-034", name="iOS Insecure UserDefaults Storage",
            description="Sensitive data stored in UserDefaults which is not encrypted",
            category=FrameworkCategory.SWIFT_IOS, severity=FrameworkSeverity.HIGH,
            pattern=r"UserDefaults\.(standard|suiteName)\.set\s*\(.*?(password|token|secret|key|credential|ssn|credit)",
            languages=["swift"],
            remediation="Use Keychain Services for sensitive data: SecItemAdd()",
            cwe_id="CWE-922", owasp_category="M2-Insecure Data Storage"
        ))
        self._register(FrameworkSecurityRule(
            id="FW-035", name="iOS ATS Disabled",
            description="App Transport Security disabled allowing insecure HTTP connections",
            category=FrameworkCategory.SWIFT_IOS, severity=FrameworkSeverity.HIGH,
            pattern=r"NSAllowsArbitraryLoads.*true|allowsArbitraryLoads\s*=\s*true",
            languages=["swift"],
            remediation="Enable ATS and use HTTPS for all connections",
            cwe_id="CWE-319", owasp_category="M3-Insecure Communication"
        ))
        self._register(FrameworkSecurityRule(
            id="FW-036", name="iOS WebView JavaScript Enabled",
            description="WKWebView with javaScriptEnabled allows XSS attacks",
            category=FrameworkCategory.SWIFT_IOS, severity=FrameworkSeverity.MEDIUM,
            pattern=r"javaScriptEnabled\s*=\s*true|WKWebViewConfiguration",
            languages=["swift"],
            remediation="Disable JavaScript in WebView if not needed, or validate loaded content",
            cwe_id="CWE-79", confidence=0.5
        ))
        self._register(FrameworkSecurityRule(
            id="FW-037", name="iOS Biometric Auth Bypass",
            description="Biometric authentication without server validation can be bypassed",
            category=FrameworkCategory.SWIFT_IOS, severity=FrameworkSeverity.HIGH,
            pattern=r"LAContext\s*\(\s*\)|canEvaluatePolicy|evaluatePolicy",
            languages=["swift"],
            remediation="Always validate biometric auth result with server-side verification",
            cwe_id="CWE-287", confidence=0.5
        ))
        self._register(FrameworkSecurityRule(
            id="FW-038", name="iOS Clipboard Data Exposure",
            description="Sensitive data copied to pasteboard is accessible by other apps",
            category=FrameworkCategory.SWIFT_IOS, severity=FrameworkSeverity.MEDIUM,
            pattern=r"UIPasteboard\.general\.string\s*=|UIPasteboard\.general\.setItems",
            languages=["swift"],
            remediation="Use UIPasteboard.withUniqueName() and set expiration for sensitive data",
            cwe_id="CWE-200"
        ))
        self._register(FrameworkSecurityRule(
            id="FW-039", name="iOS Hardcoded URL Scheme",
            description="Custom URL scheme without validation enables deep link attacks",
            category=FrameworkCategory.SWIFT_IOS, severity=FrameworkSeverity.MEDIUM,
            pattern=r"UIApplication\.shared\.open\s*\(|canOpenURL",
            languages=["swift"],
            remediation="Validate URL scheme and parameters before processing deep links",
            cwe_id="CWE-939", confidence=0.5
        ))
        self._register(FrameworkSecurityRule(
            id="FW-040", name="iOS Weak Cryptography (MD5/SHA1)",
            description="MD5 or SHA1 used for hashing which are cryptographically broken",
            category=FrameworkCategory.SWIFT_IOS, severity=FrameworkSeverity.MEDIUM,
            pattern=r"CC_MD5\s*\(|CC_SHA1\s*\(|Insecure\.MD5|Insecure\.SHA1",
            languages=["swift"],
            remediation="Use SHA256 or SHA512: CC_SHA256() or CryptoKit.SHA256",
            cwe_id="CWE-328"
        ))
        self._register(FrameworkSecurityRule(
            id="FW-041", name="iOS Certificate Pinning Missing",
            description="No SSL certificate pinning allows man-in-the-middle attacks",
            category=FrameworkCategory.SWIFT_IOS, severity=FrameworkSeverity.HIGH,
            pattern=r"URLSession\.(shared|default)(?!.*pinnedCertificates|.*serverTrust)",
            languages=["swift"],
            remediation="Implement SSL pinning using URLSessionDelegate and server trust evaluation",
            cwe_id="CWE-295", confidence=0.4
        ))
        self._register(FrameworkSecurityRule(
            id="FW-042", name="iOS Keychain Without Access Control",
            description="Keychain item stored without access control restrictions",
            category=FrameworkCategory.SWIFT_IOS, severity=FrameworkSeverity.MEDIUM,
            pattern=r"SecItemAdd\s*\((?!.*kSecAttrAccessible|.*SecAccessControl)",
            languages=["swift"],
            remediation="Set kSecAttrAccessible to appropriate level (e.g., kSecAttrAccessibleWhenUnlocked)",
            cwe_id="CWE-922", confidence=0.5
        ))
        self._register(FrameworkSecurityRule(
            id="FW-043", name="iOS Screen Recording/Screenshot Not Blocked",
            description="Sensitive screens not protected from screenshots or screen recording",
            category=FrameworkCategory.SWIFT_IOS, severity=FrameworkSeverity.LOW,
            pattern=r"class\s+\w*(Payment|Bank|Card|Password|Pin|OTP)\w*.*ViewController",
            languages=["swift"],
            remediation="Add UIScreen.main.isCaptured checks and UITextField.isSecureTextEntry",
            cwe_id="CWE-200", confidence=0.3
        ))

        # ============================================
        # KOTLIN / ANDROID (10 rules)
        # ============================================
        self._register(FrameworkSecurityRule(
            id="FW-044", name="Android SharedPreferences for Secrets",
            description="Sensitive data stored in SharedPreferences which is plaintext",
            category=FrameworkCategory.KOTLIN_ANDROID, severity=FrameworkSeverity.HIGH,
            pattern=r"getSharedPreferences|SharedPreferences.*edit\(\).*put.*?(password|token|secret|key|credential)",
            languages=["kotlin"],
            remediation="Use EncryptedSharedPreferences or Android Keystore for sensitive data",
            cwe_id="CWE-922", owasp_category="M2-Insecure Data Storage"
        ))
        self._register(FrameworkSecurityRule(
            id="FW-045", name="Android WebView JavaScript Injection",
            description="WebView with JavaScript enabled and addJavascriptInterface",
            category=FrameworkCategory.KOTLIN_ANDROID, severity=FrameworkSeverity.HIGH,
            pattern=r"addJavascriptInterface\s*\(|setJavaScriptEnabled\s*\(\s*true\s*\)",
            languages=["kotlin"],
            remediation="Use @JavascriptInterface annotations and validate all JS bridge calls",
            cwe_id="CWE-79", owasp_category="M1-Improper Platform Usage"
        ))
        self._register(FrameworkSecurityRule(
            id="FW-046", name="Android Exported Component Without Permission",
            description="Activity/Service exported without permission requirement",
            category=FrameworkCategory.KOTLIN_ANDROID, severity=FrameworkSeverity.HIGH,
            pattern=r"android:exported\s*=\s*[\"']true[\"'](?!.*permission)",
            languages=["kotlin"],
            remediation="Add android:permission attribute or set exported=false for internal components",
            cwe_id="CWE-926"
        ))
        self._register(FrameworkSecurityRule(
            id="FW-047", name="Android SQL Injection via rawQuery",
            description="rawQuery with string interpolation enables SQL injection",
            category=FrameworkCategory.KOTLIN_ANDROID, severity=FrameworkSeverity.CRITICAL,
            pattern=r"rawQuery\s*\([^)]*\$|rawQuery\s*\([^)]*\+",
            languages=["kotlin"],
            remediation="Use parameterized queries: rawQuery('SELECT * WHERE id=?', arrayOf(id))",
            cwe_id="CWE-89"
        ))
        self._register(FrameworkSecurityRule(
            id="FW-048", name="Android Intent Data Without Validation",
            description="Intent extras used without validation from external sources",
            category=FrameworkCategory.KOTLIN_ANDROID, severity=FrameworkSeverity.MEDIUM,
            pattern=r"intent\.(getStringExtra|getIntExtra|getSerializableExtra|data)\s*(?!.*validate|.*sanitize|.*check)",
            languages=["kotlin"],
            remediation="Validate all data received from intents before use",
            cwe_id="CWE-20", confidence=0.5
        ))
        self._register(FrameworkSecurityRule(
            id="FW-049", name="Android Cleartext Network Traffic",
            description="Android app allows cleartext (HTTP) network traffic",
            category=FrameworkCategory.KOTLIN_ANDROID, severity=FrameworkSeverity.HIGH,
            pattern=r"android:usesCleartextTraffic\s*=\s*[\"']true[\"']|cleartextTrafficPermitted",
            languages=["kotlin"],
            remediation="Set android:usesCleartextTraffic=false and use HTTPS for all connections",
            cwe_id="CWE-319"
        ))
        self._register(FrameworkSecurityRule(
            id="FW-050", name="Android Root Detection Bypass",
            description="Root detection that can be easily bypassed",
            category=FrameworkCategory.KOTLIN_ANDROID, severity=FrameworkSeverity.MEDIUM,
            pattern=r"Build\.TAGS.*test-keys|isRooted|RootBeer|RootCheck",
            languages=["kotlin"],
            remediation="Use multiple root detection methods and server-side verification",
            cwe_id="CWE-693", confidence=0.5
        ))
        self._register(FrameworkSecurityRule(
            id="FW-051", name="Android Weak Crypto (MD5/SHA1)",
            description="MD5 or SHA1 used for hashing which are cryptographically broken",
            category=FrameworkCategory.KOTLIN_ANDROID, severity=FrameworkSeverity.MEDIUM,
            pattern=r"MessageDigest\.getInstance\s*\(\s*[\"'](MD5|SHA-?1)[\"']\s*\)",
            languages=["kotlin"],
            remediation="Use SHA-256 or SHA-512: MessageDigest.getInstance('SHA-256')",
            cwe_id="CWE-328"
        ))
        self._register(FrameworkSecurityRule(
            id="FW-052", name="Android Insecure Random",
            description="java.util.Random is not cryptographically secure",
            category=FrameworkCategory.KOTLIN_ANDROID, severity=FrameworkSeverity.MEDIUM,
            pattern=r"java\.util\.Random\s*\(|Random\(\)|Random\(\d+\)",
            languages=["kotlin"],
            remediation="Use java.security.SecureRandom for security-sensitive operations",
            cwe_id="CWE-330"
        ))
        self._register(FrameworkSecurityRule(
            id="FW-053", name="Android WebView File Access",
            description="WebView with file access enabled allows reading local files",
            category=FrameworkCategory.KOTLIN_ANDROID, severity=FrameworkSeverity.HIGH,
            pattern=r"setAllowFileAccess\s*\(\s*true\s*\)|setAllowUniversalAccessFromFileURLs\s*\(\s*true",
            languages=["kotlin"],
            remediation="Disable file access in WebView: setAllowFileAccess(false)",
            cwe_id="CWE-200"
        ))

        # ============================================
        # DART / FLUTTER (10 rules)
        # ============================================
        self._register(FrameworkSecurityRule(
            id="FW-054", name="Flutter SharedPreferences for Secrets",
            description="Sensitive data stored in SharedPreferences which is plaintext on device",
            category=FrameworkCategory.DART_FLUTTER, severity=FrameworkSeverity.HIGH,
            pattern=r"SharedPreferences.*set.*?(password|token|secret|key|credential|pin)",
            languages=["dart"],
            remediation="Use flutter_secure_storage for sensitive data, backed by Keychain/Keystore",
            cwe_id="CWE-922"
        ))
        self._register(FrameworkSecurityRule(
            id="FW-055", name="Flutter Hardcoded API Key",
            description="API key hardcoded in Dart source code",
            category=FrameworkCategory.DART_FLUTTER, severity=FrameworkSeverity.HIGH,
            pattern=r"(apiKey|api_key|API_KEY)\s*[=:]\s*[\"'][A-Za-z0-9_\-]{20,}[\"']",
            languages=["dart"],
            remediation="Use --dart-define or .env files with flutter_dotenv package",
            cwe_id="CWE-798"
        ))
        self._register(FrameworkSecurityRule(
            id="FW-056", name="Flutter SQL Injection",
            description="rawQuery with string interpolation in sqflite database",
            category=FrameworkCategory.DART_FLUTTER, severity=FrameworkSeverity.CRITICAL,
            pattern=r"rawQuery\s*\([^)]*\$|rawQuery\s*\([^)]*\+",
            languages=["dart"],
            remediation="Use parameterized queries: rawQuery('SELECT * WHERE id=?', [id])",
            cwe_id="CWE-89"
        ))
        self._register(FrameworkSecurityRule(
            id="FW-057", name="Flutter WebView JavaScript Enabled",
            description="WebView with JavaScript enabled increases attack surface",
            category=FrameworkCategory.DART_FLUTTER, severity=FrameworkSeverity.MEDIUM,
            pattern=r"javascriptMode\s*:\s*JavascriptMode\.unrestricted|WebView\s*\(.*javascript",
            languages=["dart"],
            remediation="Only enable JavaScript when necessary, validate loaded URLs",
            cwe_id="CWE-79", confidence=0.5
        ))
        self._register(FrameworkSecurityRule(
            id="FW-058", name="Flutter Certificate Pinning Missing",
            description="HTTP client without certificate pinning allows MITM attacks",
            category=FrameworkCategory.DART_FLUTTER, severity=FrameworkSeverity.HIGH,
            pattern=r"HttpClient\s*\(\)|http\.Client\s*\(\)|Dio\s*\(\s*\)(?!.*certificate|.*badCertificateCallback)",
            languages=["dart"],
            remediation="Implement certificate pinning with SecurityContext or dio_pinning",
            cwe_id="CWE-295", confidence=0.4
        ))
        self._register(FrameworkSecurityRule(
            id="FW-059", name="Flutter Debug Mode Detection",
            description="App behavior differs in debug mode which may expose functionality",
            category=FrameworkCategory.DART_FLUTTER, severity=FrameworkSeverity.LOW,
            pattern=r"kDebugMode|kReleaseMode|assert\s*\(",
            languages=["dart"],
            remediation="Ensure debug-only features are properly stripped in release builds",
            cwe_id="CWE-215", confidence=0.3
        ))
        self._register(FrameworkSecurityRule(
            id="FW-060", name="Flutter Platform Channel Without Validation",
            description="Platform channel messages not validated before processing",
            category=FrameworkCategory.DART_FLUTTER, severity=FrameworkSeverity.MEDIUM,
            pattern=r"MethodChannel\s*\(|EventChannel\s*\(",
            languages=["dart"],
            remediation="Validate all data received through platform channels",
            cwe_id="CWE-20", confidence=0.4
        ))
        self._register(FrameworkSecurityRule(
            id="FW-061", name="Flutter Insecure HTTP Connection",
            description="HTTP connection without TLS in Flutter app",
            category=FrameworkCategory.DART_FLUTTER, severity=FrameworkSeverity.HIGH,
            pattern=r"Uri\.parse\s*\(\s*[\"']http://(?!localhost|127\.0\.0\.1|10\.)",
            languages=["dart"],
            remediation="Use HTTPS for all connections: Uri.parse('https://...')",
            cwe_id="CWE-319"
        ))
        self._register(FrameworkSecurityRule(
            id="FW-062", name="Flutter Weak Random Number",
            description="Using Random() instead of SecureRandom for security operations",
            category=FrameworkCategory.DART_FLUTTER, severity=FrameworkSeverity.MEDIUM,
            pattern=r"Random\s*\(\s*\)|Random\s*\(\s*\d+\s*\)",
            languages=["dart"],
            remediation="Use Random.secure() for security-sensitive random numbers",
            cwe_id="CWE-330"
        ))
        self._register(FrameworkSecurityRule(
            id="FW-063", name="Flutter Deep Link Without Validation",
            description="Deep link URL handled without proper validation",
            category=FrameworkCategory.DART_FLUTTER, severity=FrameworkSeverity.MEDIUM,
            pattern=r"getInitialLink|linkStream|uni_links|app_links(?!.*validate|.*sanitize|.*check)",
            languages=["dart"],
            remediation="Validate deep link parameters before processing",
            cwe_id="CWE-939", confidence=0.5
        ))

    def _register(self, rule: FrameworkSecurityRule):
        self.rules[rule.id] = rule

    def get_rules_for_language(self, language: str) -> List[FrameworkSecurityRule]:
        return [r for r in self.rules.values() if language in r.languages]

    def get_rules_for_category(self, category: FrameworkCategory) -> List[FrameworkSecurityRule]:
        return [r for r in self.rules.values() if r.category == category]

    def scan_code(self, code: str, language: str, filename: str = "") -> List[Dict]:
        """Scan code against all applicable framework/mobile rules"""
        issues = []
        applicable_rules = self.get_rules_for_language(language)
        lines = code.split('\n')
        total_lines = len(lines)

        for rule in applicable_rules:
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
                            'scanner': 'framework_security_rules'
                        })
            except re.error:
                pass

        return issues

    def get_statistics(self) -> Dict:
        stats = {'total_rules': len(self.rules), 'by_category': {}, 'by_severity': {}, 'by_language': {}}
        for rule in self.rules.values():
            cat = rule.category.value
            sev = rule.severity.value
            stats['by_category'][cat] = stats['by_category'].get(cat, 0) + 1
            stats['by_severity'][sev] = stats['by_severity'].get(sev, 0) + 1
            for lang in rule.languages:
                stats['by_language'][lang] = stats['by_language'].get(lang, 0) + 1
        return stats
