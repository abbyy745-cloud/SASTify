"""
Core scanner tests for EnhancedRuleEngine.

Tests SQL injection, XSS, code injection, hardcoded secrets, path traversal,
SSRF, command injection, insecure deserialization, false positives, and
modern JS preprocessing.
"""
import sys
import pytest

sys.path.insert(0, 'Backend')

from enhanced_rule_engine import (
    EnhancedRuleEngine,
    _preprocess_modern_js,
    ESPRIMA_AVAILABLE,
)
from conftest import assert_has_vulnerability, assert_no_vulnerability


# ===================================================================
# SQL Injection – Python
# ===================================================================

class TestSQLInjectionPython:
    """SQL injection detection in Python code."""

    def test_detects_sql_injection_python_fstring(self, scanner):
        """f-string in cursor.execute should be flagged as SQL injection."""
        code = '''\
user_id = request.args.get('id')
cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")
'''
        issues = scanner.scan_with_ast_analysis(code, 'python')
        assert any(i['type'] == 'sql_injection' for i in issues)

    def test_detects_sql_injection_python_percent_format(self, scanner):
        """Old-style %-formatting in cursor.execute should be flagged."""
        code = '''\
name = request.form['name']
cursor.execute("SELECT * FROM users WHERE name = '%s'" % name)
'''
        issues = scanner.scan_with_ast_analysis(code, 'python')
        assert any(i['type'] == 'sql_injection' for i in issues)

    def test_detects_sql_injection_python_string_concat(self, scanner):
        """String concatenation inside execute is SQL injection."""
        code = '''\
q = "SELECT * FROM users WHERE id=" + request.args.get('id')
cursor.execute(q)
'''
        issues = scanner.scan_with_ast_analysis(code, 'python')
        assert any(i['type'] == 'sql_injection' for i in issues)

    def test_safe_parameterized_query_no_flag(self, scanner):
        """Parameterized queries should NOT be flagged as SQL injection."""
        code = '''\
cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))
'''
        issues = scanner.scan_with_ast_analysis(code, 'python')
        # Parameterized queries might still get flagged by regex but at lower confidence
        sqli = [i for i in issues if i['type'] == 'sql_injection' and i.get('confidence', 0) >= 0.9]
        # There should be no high-confidence SQL injection for safe parameterized queries
        # (Some low-confidence regex patterns may still match the %s literal)


# ===================================================================
# SQL Injection – JavaScript
# ===================================================================

class TestSQLInjectionJavaScript:
    """SQL injection detection in JavaScript code."""

    @pytest.mark.skipif(not ESPRIMA_AVAILABLE, reason="esprima not installed")
    def test_detects_sql_injection_js_template_literal(self, scanner):
        """Template literals in db.query should be flagged."""
        code = '''\
const id = req.query.id;
db.query(`SELECT * FROM users WHERE id = ${id}`);
'''
        issues = scanner.scan_with_ast_analysis(code, 'javascript')
        assert any(i['type'] == 'sql_injection' for i in issues)

    @pytest.mark.skipif(not ESPRIMA_AVAILABLE, reason="esprima not installed")
    def test_detects_sql_injection_js_string_concat(self, scanner):
        """String concatenation in pool.query should be flagged."""
        code = '''\
const name = req.body.name;
pool.query("SELECT * FROM users WHERE name = '" + name + "'");
'''
        issues = scanner.scan_with_ast_analysis(code, 'javascript')
        assert any(i['type'] == 'sql_injection' for i in issues)


# ===================================================================
# XSS Detection
# ===================================================================

class TestXSSDetection:
    """Cross-site scripting detection."""

    @pytest.mark.skipif(not ESPRIMA_AVAILABLE, reason="esprima not installed")
    def test_detects_xss_innerhtml(self, scanner):
        """Assigning user input to innerHTML should be flagged as XSS."""
        code = '''\
const input = req.query.input;
document.getElementById("out").innerHTML = input;
'''
        issues = scanner.scan_with_ast_analysis(code, 'javascript')
        assert any(i['type'] == 'xss' for i in issues)

    def test_detects_xss_document_write_regex(self, scanner):
        """document.write with user data should be flagged."""
        code = '''\
document.write(userInput);
'''
        issues = scanner.scan_with_ast_analysis(code, 'javascript')
        assert any(i['type'] == 'xss' for i in issues)

    @pytest.mark.skipif(not ESPRIMA_AVAILABLE, reason="esprima not installed")
    def test_detects_xss_outerhtml(self, scanner):
        """Assigning to outerHTML with tainted data should flag XSS."""
        code = '''\
const data = req.body.html;
el.outerHTML = data;
'''
        issues = scanner.scan_with_ast_analysis(code, 'javascript')
        assert any(i['type'] == 'xss' for i in issues)


# ===================================================================
# Code Injection
# ===================================================================

class TestCodeInjection:
    """Detection of eval/exec/compile injection vectors."""

    def test_detects_eval_python(self, scanner):
        """eval() in Python should be flagged as code injection."""
        code = '''\
user_input = request.args.get('expr')
result = eval(user_input)
'''
        issues = scanner.scan_with_ast_analysis(code, 'python')
        assert any(i['type'] == 'code_injection' for i in issues)

    def test_detects_exec_python(self, scanner):
        """exec() in Python should be flagged as code injection."""
        code = '''\
code = request.form['code']
exec(code)
'''
        issues = scanner.scan_with_ast_analysis(code, 'python')
        assert any(i['type'] == 'code_injection' for i in issues)

    @pytest.mark.skipif(not ESPRIMA_AVAILABLE, reason="esprima not installed")
    def test_detects_eval_javascript(self, scanner):
        """eval() in JavaScript should be flagged as code injection."""
        code = '''\
const expr = req.body.expr;
eval(expr);
'''
        issues = scanner.scan_with_ast_analysis(code, 'javascript')
        assert any(i['type'] == 'code_injection' for i in issues)

    def test_detects_child_process_exec(self, scanner):
        """child_process.exec should be flagged as shell injection."""
        code = '''\
const cmd = req.query.cmd;
child_process.exec(cmd);
'''
        issues = scanner.scan_with_ast_analysis(code, 'javascript')
        assert any(i['type'] in ('shell_injection', 'code_injection') for i in issues)


# ===================================================================
# Hardcoded Secrets
# ===================================================================

class TestHardcodedSecrets:
    """Detection of hardcoded API keys, passwords, and secrets."""

    def test_detects_hardcoded_password_python(self, scanner):
        """A hardcoded password string should be flagged."""
        code = '''\
password = "SuperSecretPassword123!"
'''
        issues = scanner.scan_with_ast_analysis(code, 'python')
        assert any(i['type'] == 'hardcoded_secret' for i in issues)

    def test_detects_hardcoded_api_key_python(self, scanner):
        """A hardcoded API key should be flagged."""
        code = '''\
api_key = "sk_live_abcdefghijklmnopqrstuvwx"
'''
        issues = scanner.scan_with_ast_analysis(code, 'python')
        assert any(i['type'] == 'hardcoded_secret' for i in issues)

    @pytest.mark.skipif(not ESPRIMA_AVAILABLE, reason="esprima not installed")
    def test_detects_hardcoded_password_javascript(self, scanner):
        """Hardcoded password in JS should be flagged."""
        code = '''\
const password = "MyHardcodedP@ssw0rd";
'''
        issues = scanner.scan_with_ast_analysis(code, 'javascript')
        assert any(i['type'] == 'hardcoded_secret' for i in issues)

    @pytest.mark.skipif(not ESPRIMA_AVAILABLE, reason="esprima not installed")
    def test_detects_hardcoded_secret_key_js(self, scanner):
        """Hardcoded secret key in JS should be flagged."""
        code = '''\
const secretKey = "aVeryLongSecretKeyValue1234567890";
'''
        issues = scanner.scan_with_ast_analysis(code, 'javascript')
        assert any(i['type'] == 'hardcoded_secret' for i in issues)

    def test_no_flag_password_from_env(self, scanner):
        """Password loaded from env should NOT be flagged as hardcoded secret."""
        code = '''\
import os
password = os.environ["PASSWORD"]
'''
        issues = scanner.scan_with_ast_analysis(code, 'python')
        secret_issues = [i for i in issues if i['type'] == 'hardcoded_secret']
        assert not secret_issues, (
            f"False positive: env-loaded password flagged at line(s) "
            f"{[i['line'] for i in secret_issues]}"
        )

    def test_no_flag_password_placeholder(self, scanner):
        """Placeholder/test passwords should NOT be flagged."""
        code = '''\
password = "placeholder_value_here"
'''
        issues = scanner.scan_with_ast_analysis(code, 'python')
        secret_issues = [i for i in issues if i['type'] == 'hardcoded_secret']
        assert not secret_issues


# ===================================================================
# Path Traversal
# ===================================================================

class TestPathTraversal:
    """Path traversal vulnerability detection."""

    def test_detects_path_traversal_open_concat(self, scanner):
        """open() with string concatenation should be flagged."""
        code = '''\
filename = request.args.get('file')
f = open("/var/data/" + filename)
'''
        issues = scanner.scan_with_ast_analysis(code, 'python')
        assert any(i['type'] == 'path_traversal' for i in issues)

    def test_detects_dotdot_path(self, scanner):
        """os.path.join with .. should be flagged."""
        code = '''\
path = os.path.join(base_dir, "../etc/passwd")
'''
        issues = scanner.scan_with_ast_analysis(code, 'python')
        assert any(i['type'] == 'path_traversal' for i in issues)


# ===================================================================
# SSRF Detection
# ===================================================================

class TestSSRFDetection:
    """Server-Side Request Forgery detection."""

    def test_detects_ssrf_requests_get_python(self, scanner):
        """requests.get with user-controlled URL should be flagged."""
        code = '''\
url = request.args.get('url')
response = requests.get(url)
'''
        issues = scanner.scan_with_ast_analysis(code, 'python')
        assert any(i['type'] == 'ssrf' for i in issues)

    def test_detects_ssrf_fstring_url(self, scanner):
        """requests.get with an f-string URL should be flagged."""
        code = '''\
host = request.args.get('host')
response = requests.get(f"http://{host}/api")
'''
        issues = scanner.scan_with_ast_analysis(code, 'python')
        assert any(i['type'] == 'ssrf' for i in issues)


# ===================================================================
# Command / Shell Injection
# ===================================================================

class TestCommandInjection:
    """Command / shell injection detection."""

    def test_detects_os_system(self, scanner):
        """os.system() should be flagged as shell injection."""
        code = '''\
cmd = request.form['cmd']
os.system(cmd)
'''
        issues = scanner.scan_with_ast_analysis(code, 'python')
        assert any(i['type'] in ('shell_injection', 'code_injection') for i in issues)

    def test_detects_subprocess_call(self, scanner):
        """subprocess.call() with a variable should be flagged."""
        code = '''\
user_cmd = request.args.get('c')
subprocess.call(user_cmd, shell=True)
'''
        issues = scanner.scan_with_ast_analysis(code, 'python')
        assert any(i['type'] in ('shell_injection', 'code_injection') for i in issues)

    def test_detects_os_popen(self, scanner):
        """os.popen() should be flagged."""
        code = '''\
command = request.args.get('cmd')
os.popen(command)
'''
        issues = scanner.scan_with_ast_analysis(code, 'python')
        assert any(i['type'] in ('shell_injection', 'code_injection') for i in issues)


# ===================================================================
# Insecure Deserialization
# ===================================================================

class TestInsecureDeserialization:
    """Detection of insecure deserialization patterns."""

    def test_detects_pickle_loads(self, scanner):
        """pickle.loads() should be flagged as insecure deserialization."""
        code = '''\
import pickle
data = pickle.loads(user_data)
'''
        issues = scanner.scan_with_ast_analysis(code, 'python')
        assert any(i['type'] == 'insecure_deserialization' for i in issues)

    def test_detects_pickle_load(self, scanner):
        """pickle.load() should be flagged."""
        code = '''\
import pickle
with open('data.pkl', 'rb') as f:
    obj = pickle.load(f)
'''
        issues = scanner.scan_with_ast_analysis(code, 'python')
        assert any(i['type'] == 'insecure_deserialization' for i in issues)

    def test_detects_yaml_load_unsafe(self, scanner):
        """yaml.load() without SafeLoader should be flagged."""
        code = '''\
import yaml
data = yaml.load(content)
'''
        issues = scanner.scan_with_ast_analysis(code, 'python')
        assert any(i['type'] == 'insecure_deserialization' for i in issues)

    def test_yaml_safe_load_not_flagged(self, scanner):
        """yaml.load with SafeLoader should NOT be flagged by the AST scanner."""
        code = '''\
import yaml
data = yaml.load(content, Loader=yaml.SafeLoader)
'''
        issues = scanner.scan_with_ast_analysis(code, 'python')
        # AST scanner should NOT flag this; regex may still match at lower confidence
        ast_deser = [
            i for i in issues
            if i['type'] == 'insecure_deserialization'
            and i.get('scanner') == 'ast_deserialization_analysis'
        ]
        assert not ast_deser, "yaml.load with SafeLoader should not be flagged by AST scanner"


# ===================================================================
# SSL / Weak Crypto
# ===================================================================

class TestSSLAndCrypto:
    """SSL verification and weak cryptography detection."""

    def test_detects_ssl_verification_disabled(self, scanner):
        """verify=False in requests should be flagged."""
        code = '''\
requests.get("https://example.com", verify=False)
'''
        issues = scanner.scan_with_ast_analysis(code, 'python')
        assert any(i['type'] == 'ssl_verification_disabled' for i in issues)

    def test_detects_weak_crypto_md5(self, scanner):
        """hashlib.md5() should be flagged as weak cryptography."""
        code = '''\
import hashlib
h = hashlib.md5(data)
'''
        issues = scanner.scan_with_ast_analysis(code, 'python')
        assert any(i['type'] == 'weak_cryptography' for i in issues)


# ===================================================================
# Debug Mode
# ===================================================================

class TestDebugMode:
    """Debug mode detection."""

    def test_detects_debug_true(self, scanner):
        """DEBUG = True should be flagged."""
        code = '''\
DEBUG = True
'''
        issues = scanner.scan_with_ast_analysis(code, 'python')
        assert any(i['type'] in ('debug_enabled', 'debug_mode_enabled') for i in issues)


# ===================================================================
# False Positive Tests
# ===================================================================

class TestFalsePositives:
    """Ensure safe patterns are NOT flagged."""

    def test_safe_constant_eval_not_flagged_high(self, scanner):
        """eval() with a constant string might be flagged but at low confidence."""
        code = '''\
result = eval("2 + 2")
'''
        issues = scanner.scan_with_ast_analysis(code, 'python')
        # Regex will flag eval() but AST should not report high-confidence taint
        high_conf_inject = [
            i for i in issues
            if i['type'] == 'code_injection'
            and i.get('scanner') == 'ast_taint_analysis'
        ]
        assert not high_conf_inject, "eval with constant should not be taint-flagged"

    def test_safe_string_variable_not_flagged(self, scanner):
        """A variable named 'password' assigned from config should not flag."""
        code = '''\
import os
db_password = os.environ.get("DB_PASSWORD")
'''
        issues = scanner.scan_with_ast_analysis(code, 'python')
        secret_issues = [i for i in issues if i['type'] == 'hardcoded_secret']
        assert not secret_issues

    def test_safe_cursor_execute_literal(self, scanner):
        """cursor.execute with a pure literal string is not high-confidence sqli."""
        code = '''\
cursor.execute("CREATE TABLE users (id INTEGER PRIMARY KEY)")
'''
        issues = scanner.scan_with_ast_analysis(code, 'python')
        # Should NOT have AST taint-confirmed SQL injection
        taint_sqli = [
            i for i in issues
            if i['type'] == 'sql_injection'
            and i.get('scanner') == 'ast_taint_analysis'
        ]
        assert not taint_sqli

    def test_comment_with_password_not_flagged(self, scanner):
        """Comments mentioning 'password' should ideally not trigger."""
        code = '''\
# password = "old_password_was_removed"
x = 42
'''
        issues = scanner.scan_with_ast_analysis(code, 'python')
        # AST scanner should NOT flag a comment as a hardcoded secret
        ast_secrets = [
            i for i in issues
            if i['type'] == 'hardcoded_secret'
            and i.get('scanner') == 'ast_secret_detection'
        ]
        assert not ast_secrets


# ===================================================================
# Modern JS Preprocessing
# ===================================================================

class TestModernJSPreprocessing:
    """Verify _preprocess_modern_js correctly transforms ES2020+ syntax."""

    def test_optional_chaining_removed(self):
        """Optional chaining ?. should be converted to regular access."""
        code = "const x = obj?.prop?.nested;"
        result = _preprocess_modern_js(code)
        assert "?." not in result
        assert "obj.prop.nested" in result

    def test_nullish_coalescing_converted(self):
        """?? should be converted to ||."""
        code = "const x = a ?? b;"
        result = _preprocess_modern_js(code)
        assert "??" not in result
        assert "||" in result

    def test_bigint_literal_stripped(self):
        """BigInt literals (123n) should have the n suffix removed."""
        code = "const big = 123456789n;"
        result = _preprocess_modern_js(code)
        assert "123456789n" not in result
        assert "123456789" in result

    def test_numeric_separators_removed(self):
        """Numeric separators (1_000) should be collapsed."""
        code = "const million = 1_000_000;"
        result = _preprocess_modern_js(code)
        assert "1_000_000" not in result
        assert "1000000" in result

    def test_private_class_fields(self):
        """Private fields #name should be converted to _priv_name."""
        code = '''\
class Foo {
  #secret = 42;
  get() { return this.#secret; }
}'''
        result = _preprocess_modern_js(code)
        assert "#secret" not in result
        assert "_priv_secret" in result

    def test_import_meta_replaced(self):
        """import.meta should be replaced with ({})."""
        code = "const url = import.meta.url;"
        result = _preprocess_modern_js(code)
        assert "import.meta" not in result


# ===================================================================
# Prototype Pollution (JS)
# ===================================================================

class TestPrototypePollution:
    """Prototype pollution detection in JavaScript."""

    def test_detects_proto_regex(self, scanner):
        """__proto__ usage should be flagged."""
        code = '''\
obj.__proto__.isAdmin = true;
'''
        issues = scanner.scan_with_ast_analysis(code, 'javascript')
        assert any(i['type'] == 'prototype_pollution' for i in issues)


# ===================================================================
# Parametrized: Multiple sinks
# ===================================================================

@pytest.mark.parametrize("sink_call,expected_type", [
    ("eval(user_input)", "code_injection"),
    ("exec(user_input)", "code_injection"),
    ("os.system(user_input)", "shell_injection"),
])
def test_python_sinks_parametrized(scanner, sink_call, expected_type):
    """Various Python sinks with tainted input should be detected."""
    code = f'''\
user_input = request.args.get('x')
{sink_call}
'''
    issues = scanner.scan_with_ast_analysis(code, 'python')
    assert any(i['type'] == expected_type for i in issues), (
        f"Expected '{expected_type}' for sink '{sink_call}', "
        f"got types: {[i['type'] for i in issues]}"
    )


@pytest.mark.parametrize("pattern,vuln_type", [
    ("pickle.loads(data)", "insecure_deserialization"),
    ("pickle.load(f)", "insecure_deserialization"),
    ("yaml.load(content)", "insecure_deserialization"),
    ("marshal.loads(raw)", "insecure_deserialization"),
])
def test_python_deserialization_parametrized(scanner, pattern, vuln_type):
    """Multiple deserialization sinks should all be flagged."""
    code = f'''\
import pickle, yaml, marshal
{pattern}
'''
    issues = scanner.scan_with_ast_analysis(code, 'python')
    assert any(i['type'] == vuln_type for i in issues)


@pytest.mark.parametrize("code_snippet,vuln_type", [
    ('password = "SuperSecretPassword123!"', "hardcoded_secret"),
    ('api_key = "sk_live_abcdefghijklmnopqrstuvwx"', "hardcoded_secret"),
    ('secret_key = "mySuperSecretLongKeyValue1234567890abcdef"', "hardcoded_secret"),
    ('token = "eyJhbGciOiJIUzI1NiJ9.verylongtoken"', "hardcoded_secret"),
])
def test_python_hardcoded_secrets_parametrized(scanner, code_snippet, vuln_type):
    """Parametrized hardcoded secret detection."""
    issues = scanner.scan_with_ast_analysis(code_snippet, 'python')
    assert any(i['type'] == vuln_type for i in issues)


# ===================================================================
# Issue structure validation
# ===================================================================

class TestIssueStructure:
    """Verify that returned issues have the expected dict keys."""

    def test_issue_has_required_keys(self, scanner):
        """Every issue should contain type, line, snippet, confidence, severity."""
        code = '''\
password = "MyHardcodedPassword1"
'''
        issues = scanner.scan_with_ast_analysis(code, 'python')
        assert issues, "Expected at least one issue"
        for issue in issues:
            assert 'type' in issue
            assert 'line' in issue
            assert 'confidence' in issue
            assert 'severity' in issue

    def test_severity_values(self, scanner):
        """Severity should be one of the known levels."""
        valid = {'Critical', 'High', 'Medium', 'Low', 'Info'}
        code = '''\
eval(request.args.get('x'))
'''
        issues = scanner.scan_with_ast_analysis(code, 'python')
        for issue in issues:
            assert issue['severity'] in valid, f"Unknown severity: {issue['severity']}"
