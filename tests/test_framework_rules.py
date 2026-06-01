"""
Framework-specific security rule tests.

Tests FrameworkRuleEngine.scan_code() against rules for:
React, Django, Flask, Express, Angular, Swift/iOS, Kotlin/Android, Dart/Flutter.
"""
import sys
import pytest

sys.path.insert(0, 'Backend')

from framework_security_rules import (
    FrameworkRuleEngine,
    FrameworkCategory,
    FrameworkSeverity,
)


# ===================================================================
# React (FW-001 … FW-005)
# ===================================================================

class TestReactRules:
    """React framework security rules."""

    def test_detects_dangerously_set_inner_html(self, framework_scanner):
        """dangerouslySetInnerHTML should trigger FW-001."""
        code = '''\
function App() {
  return <div dangerouslySetInnerHTML={{__html: userInput}} />;
}
'''
        issues = framework_scanner.scan_code(code, 'javascript')
        matching = [i for i in issues if i['rule_id'] == 'FW-001']
        assert matching, "Expected FW-001 for dangerouslySetInnerHTML"
        assert matching[0]['severity'] == 'High'

    def test_detects_href_javascript_protocol(self, framework_scanner):
        """href='javascript:...' should trigger FW-003."""
        code = '''\
<a href="javascript:alert(1)">Click</a>
'''
        issues = framework_scanner.scan_code(code, 'javascript')
        matching = [i for i in issues if i['rule_id'] == 'FW-003']
        assert matching, "Expected FW-003 for javascript: href"

    def test_detects_unsafe_lifecycle_methods(self, framework_scanner):
        """UNSAFE_componentWillMount should trigger FW-002."""
        code = '''\
class MyComponent extends React.Component {
  UNSAFE_componentWillMount() {
    this.fetchData();
  }
}
'''
        issues = framework_scanner.scan_code(code, 'javascript')
        matching = [i for i in issues if i['rule_id'] == 'FW-002']
        assert matching, "Expected FW-002 for UNSAFE_ lifecycle method"

    def test_no_false_positive_safe_href(self, framework_scanner):
        """Normal href should NOT trigger FW-003."""
        code = '''\
<a href="https://example.com">Safe link</a>
'''
        issues = framework_scanner.scan_code(code, 'javascript')
        fw003 = [i for i in issues if i['rule_id'] == 'FW-003']
        assert not fw003, "Normal https href should not trigger FW-003"


# ===================================================================
# Django (FW-021 … FW-025)
# ===================================================================

class TestDjangoRules:
    """Django framework security rules."""

    def test_detects_mark_safe_with_user_input(self, framework_scanner):
        """mark_safe(request.POST['html']) should trigger FW-021."""
        code = '''\
from django.utils.safestring import mark_safe
html = mark_safe(request.POST['html'])
'''
        issues = framework_scanner.scan_code(code, 'python')
        matching = [i for i in issues if i['rule_id'] == 'FW-021']
        assert matching, "Expected FW-021 for mark_safe with user input"

    def test_detects_raw_sql_with_format(self, framework_scanner):
        """Model.objects.raw() with .format should trigger FW-022."""
        code = '''\
User.objects.raw("SELECT * FROM users WHERE name = '%s'" .format(name))
'''
        issues = framework_scanner.scan_code(code, 'python')
        matching = [i for i in issues if i['rule_id'] == 'FW-022']
        assert matching, "Expected FW-022 for raw SQL with format"

    def test_detects_debug_true(self, framework_scanner):
        """DEBUG = True should trigger FW-023."""
        code = "DEBUG = True"
        issues = framework_scanner.scan_code(code, 'python')
        matching = [i for i in issues if i['rule_id'] == 'FW-023']
        assert matching, "Expected FW-023 for DEBUG = True"

    def test_detects_allowed_hosts_wildcard(self, framework_scanner):
        """ALLOWED_HOSTS = ['*'] should trigger FW-024."""
        code = "ALLOWED_HOSTS = ['*']"
        issues = framework_scanner.scan_code(code, 'python')
        matching = [i for i in issues if i['rule_id'] == 'FW-024']
        assert matching, "Expected FW-024 for wildcard ALLOWED_HOSTS"

    def test_detects_safe_template_filter(self, framework_scanner):
        """{{ content |safe }} should trigger FW-025."""
        code = "{{ user_content |safe }}"
        issues = framework_scanner.scan_code(code, 'python')
        matching = [i for i in issues if i['rule_id'] == 'FW-025']
        assert matching, "Expected FW-025 for |safe template filter"


# ===================================================================
# Flask (FW-016 … FW-020)
# ===================================================================

class TestFlaskRules:
    """Flask framework security rules."""

    def test_detects_flask_debug_true(self, framework_scanner):
        """app.run(debug=True) should trigger FW-016."""
        code = "app.run(debug=True, host='0.0.0.0')"
        issues = framework_scanner.scan_code(code, 'python')
        matching = [i for i in issues if i['rule_id'] == 'FW-016']
        assert matching, "Expected FW-016 for Flask debug=True"

    def test_detects_flask_hardcoded_secret_key(self, framework_scanner):
        """app.secret_key = 'hardcoded' should trigger FW-017."""
        code = "app.secret_key = 'my-super-secret-key-1234'"
        issues = framework_scanner.scan_code(code, 'python')
        matching = [i for i in issues if i['rule_id'] == 'FW-017']
        assert matching, "Expected FW-017 for hardcoded secret_key"

    def test_detects_flask_csrf_disabled(self, framework_scanner):
        """WTF_CSRF_ENABLED = False should trigger FW-018."""
        code = "WTF_CSRF_ENABLED = False"
        issues = framework_scanner.scan_code(code, 'python')
        matching = [i for i in issues if i['rule_id'] == 'FW-018']
        assert matching, "Expected FW-018 for CSRF disabled"

    def test_detects_autoescape_false(self, framework_scanner):
        """autoescape = False should trigger FW-020."""
        code = "env = Environment(autoescape = False)"
        issues = framework_scanner.scan_code(code, 'python')
        matching = [i for i in issues if i['rule_id'] == 'FW-020']
        assert matching, "Expected FW-020 for autoescape disabled"

    def test_no_false_positive_flask_debug_false(self, framework_scanner):
        """app.run(debug=False) should NOT trigger FW-016."""
        code = "app.run(debug=False)"
        issues = framework_scanner.scan_code(code, 'python')
        fw016 = [i for i in issues if i['rule_id'] == 'FW-016']
        assert not fw016, "debug=False should not trigger FW-016"


# ===================================================================
# Express (FW-026 … FW-030)
# ===================================================================

class TestExpressRules:
    """Express framework security rules."""

    def test_detects_missing_helmet(self, framework_scanner):
        """express() without helmet should trigger FW-026."""
        code = '''\
const app = express();
app.use(bodyParser.json());
'''
        issues = framework_scanner.scan_code(code, 'javascript')
        matching = [i for i in issues if i['rule_id'] == 'FW-026']
        assert matching, "Expected FW-026 for missing helmet"

    def test_detects_cors_wildcard(self, framework_scanner):
        """cors({ origin: '*' should trigger FW-029."""
        code = "app.use(cors({ origin: '*' }));"
        issues = framework_scanner.scan_code(code, 'javascript')
        matching = [i for i in issues if i['rule_id'] == 'FW-029']
        assert matching, "Expected FW-029 for CORS allow-all"

    def test_detects_hardcoded_session_secret(self, framework_scanner):
        """session({ secret: 'hardcoded' }) should trigger FW-028."""
        code = "app.use(session({ secret: 'mySessionSecret123' }));"
        issues = framework_scanner.scan_code(code, 'javascript')
        matching = [i for i in issues if i['rule_id'] == 'FW-028']
        assert matching, "Expected FW-028 for hardcoded session secret"

    def test_detects_body_parser_no_limit(self, framework_scanner):
        """express.json() without limit should trigger FW-027."""
        code = "app.use(express.json());"
        issues = framework_scanner.scan_code(code, 'javascript')
        matching = [i for i in issues if i['rule_id'] == 'FW-027']
        assert matching, "Expected FW-027 for missing body size limit"

    def test_detects_dotfiles_allow(self, framework_scanner):
        """express.static with dotfiles: 'allow' should trigger FW-030."""
        code = "app.use(express.static('public', { dotfiles: 'allow' }));"
        issues = framework_scanner.scan_code(code, 'javascript')
        matching = [i for i in issues if i['rule_id'] == 'FW-030']
        assert matching, "Expected FW-030 for dotfiles allow"


# ===================================================================
# Angular (FW-011 … FW-015)
# ===================================================================

class TestAngularRules:
    """Angular framework security rules."""

    def test_detects_bypass_security_trust_html(self, framework_scanner):
        """bypassSecurityTrustHtml should trigger FW-011."""
        code = "this.sanitizer.bypassSecurityTrustHtml(userInput);"
        issues = framework_scanner.scan_code(code, 'typescript')
        matching = [i for i in issues if i['rule_id'] == 'FW-011']
        assert matching, "Expected FW-011 for bypassSecurityTrustHtml"

    def test_detects_bypass_security_trust_url(self, framework_scanner):
        """bypassSecurityTrustUrl should trigger FW-011."""
        code = "this.sanitizer.bypassSecurityTrustUrl(url);"
        issues = framework_scanner.scan_code(code, 'typescript')
        matching = [i for i in issues if i['rule_id'] == 'FW-011']
        assert matching, "Expected FW-011 for bypassSecurityTrustUrl"

    def test_detects_bypass_security_trust_script(self, framework_scanner):
        """bypassSecurityTrustScript should trigger FW-011."""
        code = "this.sanitizer.bypassSecurityTrustScript(script);"
        issues = framework_scanner.scan_code(code, 'typescript')
        matching = [i for i in issues if i['rule_id'] == 'FW-011']
        assert matching

    def test_detects_native_element_innerhtml(self, framework_scanner):
        """.nativeElement.innerHTML should trigger FW-014."""
        code = "this.el.nativeElement.innerHTML = data;"
        issues = framework_scanner.scan_code(code, 'typescript')
        matching = [i for i in issues if i['rule_id'] == 'FW-014']
        assert matching, "Expected FW-014 for nativeElement.innerHTML"


# ===================================================================
# Swift / iOS (FW-034 … FW-043)
# ===================================================================

class TestSwiftRules:
    """Swift/iOS framework security rules."""

    def test_detects_userdefaults_sensitive_data(self, framework_scanner):
        """UserDefaults.standard.set with password should trigger FW-034."""
        code = 'UserDefaults.standard.set(password, forKey: "user_password")'
        issues = framework_scanner.scan_code(code, 'swift')
        matching = [i for i in issues if i['rule_id'] == 'FW-034']
        assert matching, "Expected FW-034 for sensitive data in UserDefaults"

    def test_detects_ats_disabled(self, framework_scanner):
        """NSAllowsArbitraryLoads true should trigger FW-035."""
        code = '<key>NSAllowsArbitraryLoads</key><true/>'
        # The pattern also matches swift-side code
        code_swift = 'allowsArbitraryLoads = true'
        issues = framework_scanner.scan_code(code_swift, 'swift')
        matching = [i for i in issues if i['rule_id'] == 'FW-035']
        assert matching, "Expected FW-035 for ATS disabled"

    def test_detects_weak_crypto_md5(self, framework_scanner):
        """CC_MD5() should trigger FW-040."""
        code = "let hash = CC_MD5(data)"
        issues = framework_scanner.scan_code(code, 'swift')
        matching = [i for i in issues if i['rule_id'] == 'FW-040']
        assert matching, "Expected FW-040 for CC_MD5"

    def test_detects_clipboard_exposure(self, framework_scanner):
        """UIPasteboard.general.string = should trigger FW-038."""
        code = 'UIPasteboard.general.string = secretToken'
        issues = framework_scanner.scan_code(code, 'swift')
        matching = [i for i in issues if i['rule_id'] == 'FW-038']
        assert matching, "Expected FW-038 for clipboard data exposure"


# ===================================================================
# Kotlin / Android (FW-044 … FW-053)
# ===================================================================

class TestKotlinRules:
    """Kotlin/Android framework security rules."""

    def test_detects_shared_preferences_secrets(self, framework_scanner):
        """getSharedPreferences should trigger FW-044."""
        code = 'val prefs = getSharedPreferences("app", MODE_PRIVATE)'
        issues = framework_scanner.scan_code(code, 'kotlin')
        matching = [i for i in issues if i['rule_id'] == 'FW-044']
        assert matching, "Expected FW-044 for SharedPreferences"

    def test_detects_webview_js_injection(self, framework_scanner):
        """setJavaScriptEnabled(true) should trigger FW-045."""
        code = "webView.settings.setJavaScriptEnabled(true)"
        issues = framework_scanner.scan_code(code, 'kotlin')
        matching = [i for i in issues if i['rule_id'] == 'FW-045']
        assert matching, "Expected FW-045 for WebView JS enabled"

    def test_detects_raw_query_injection(self, framework_scanner):
        """rawQuery with string interpolation should trigger FW-047."""
        code = 'db.rawQuery("SELECT * FROM users WHERE id = $userId", null)'
        issues = framework_scanner.scan_code(code, 'kotlin')
        matching = [i for i in issues if i['rule_id'] == 'FW-047']
        assert matching, "Expected FW-047 for rawQuery SQL injection"

    def test_detects_cleartext_traffic(self, framework_scanner):
        """usesCleartextTraffic=true should trigger FW-049."""
        code = 'android:usesCleartextTraffic="true"'
        issues = framework_scanner.scan_code(code, 'kotlin')
        matching = [i for i in issues if i['rule_id'] == 'FW-049']
        assert matching, "Expected FW-049 for cleartext traffic"

    def test_detects_weak_crypto_md5_kotlin(self, framework_scanner):
        """MessageDigest.getInstance('MD5') should trigger FW-051."""
        code = 'val md = MessageDigest.getInstance("MD5")'
        issues = framework_scanner.scan_code(code, 'kotlin')
        matching = [i for i in issues if i['rule_id'] == 'FW-051']
        assert matching, "Expected FW-051 for MD5 in Kotlin"


# ===================================================================
# Dart / Flutter (FW-054 … FW-063)
# ===================================================================

class TestDartFlutterRules:
    """Dart/Flutter framework security rules."""

    def test_detects_shared_preferences_password(self, framework_scanner):
        """SharedPreferences.setString with password should trigger FW-054."""
        code = 'await SharedPreferences.getInstance().then((p) => p.setString("password", pw));'
        issues = framework_scanner.scan_code(code, 'dart')
        matching = [i for i in issues if i['rule_id'] == 'FW-054']
        assert matching, "Expected FW-054 for SharedPreferences with password"

    def test_detects_hardcoded_api_key_dart(self, framework_scanner):
        """Hardcoded apiKey with long value should trigger FW-055."""
        code = 'const apiKey = "abcdefghijklmnopqrstuvwxyz1234567890abcd";'
        issues = framework_scanner.scan_code(code, 'dart')
        matching = [i for i in issues if i['rule_id'] == 'FW-055']
        assert matching, "Expected FW-055 for hardcoded API key in Dart"

    def test_detects_raw_query_sql_injection_dart(self, framework_scanner):
        """rawQuery with string interpolation should trigger FW-056."""
        code = 'db.rawQuery("SELECT * FROM items WHERE id = $id");'
        issues = framework_scanner.scan_code(code, 'dart')
        matching = [i for i in issues if i['rule_id'] == 'FW-056']
        assert matching, "Expected FW-056 for SQL injection in Dart"

    def test_detects_insecure_http_dart(self, framework_scanner):
        """Uri.parse('http://...') should trigger FW-061."""
        code = 'final uri = Uri.parse("http://api.example.com/data");'
        issues = framework_scanner.scan_code(code, 'dart')
        matching = [i for i in issues if i['rule_id'] == 'FW-061']
        assert matching, "Expected FW-061 for insecure HTTP in Dart"

    def test_no_flag_localhost_http(self, framework_scanner):
        """http://localhost should NOT trigger FW-061."""
        code = 'final uri = Uri.parse("http://localhost:3000/api");'
        issues = framework_scanner.scan_code(code, 'dart')
        fw061 = [i for i in issues if i['rule_id'] == 'FW-061']
        assert not fw061, "localhost HTTP should not trigger FW-061"

    def test_detects_weak_random_dart(self, framework_scanner):
        """Random() should trigger FW-062."""
        code = 'final rng = Random();'
        issues = framework_scanner.scan_code(code, 'dart')
        matching = [i for i in issues if i['rule_id'] == 'FW-062']
        assert matching, "Expected FW-062 for weak Random"


# ===================================================================
# Engine metadata / utilities
# ===================================================================

class TestFrameworkEngineUtils:
    """Tests for FrameworkRuleEngine utility methods."""

    def test_get_rules_for_language_python(self, framework_scanner):
        """get_rules_for_language('python') should return Flask + Django rules."""
        rules = framework_scanner.get_rules_for_language('python')
        ids = {r.id for r in rules}
        assert 'FW-016' in ids  # Flask debug
        assert 'FW-021' in ids  # Django mark_safe

    def test_get_rules_for_language_swift(self, framework_scanner):
        """get_rules_for_language('swift') should return iOS rules."""
        rules = framework_scanner.get_rules_for_language('swift')
        ids = {r.id for r in rules}
        assert 'FW-034' in ids  # UserDefaults
        assert 'FW-040' in ids  # Weak crypto

    def test_get_rules_for_category_react(self, framework_scanner):
        """get_rules_for_category(REACT) should return React rules."""
        rules = framework_scanner.get_rules_for_category(FrameworkCategory.REACT)
        assert len(rules) == 5, f"Expected 5 React rules, got {len(rules)}"

    def test_get_statistics(self, framework_scanner):
        """get_statistics should return total rule count and breakdowns."""
        stats = framework_scanner.get_statistics()
        assert stats['total_rules'] > 0
        assert 'by_category' in stats
        assert 'by_severity' in stats
        assert 'by_language' in stats

    def test_scan_code_returns_list(self, framework_scanner):
        """scan_code should always return a list, even for safe code."""
        issues = framework_scanner.scan_code("x = 1", 'python')
        assert isinstance(issues, list)

    def test_issue_has_expected_keys(self, framework_scanner):
        """Each issue dict should have rule_id, type, severity, line, etc."""
        code = "DEBUG = True"
        issues = framework_scanner.scan_code(code, 'python')
        assert issues
        issue = issues[0]
        expected_keys = {
            'rule_id', 'type', 'description', 'category', 'severity',
            'line', 'snippet', 'remediation', 'confidence', 'scanner',
        }
        assert expected_keys.issubset(issue.keys()), (
            f"Missing keys: {expected_keys - issue.keys()}"
        )
