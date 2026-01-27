"""
PHP Security Analyzer - Enterprise Edition

25+ Vulnerability Classes with Deep Detection:
- Injection (SQL, Command, XSS, LDAP, XPath, Template)
- File Security (LFI/RFI, Path Traversal, Upload)
- Deserialization
- XXE
- Authentication & Session
- Cryptographic Failures
- Framework-specific (Laravel, WordPress, Symfony)
- Information Disclosure
- Security Misconfiguration
"""

import re
from typing import List, Dict, Optional
from dataclasses import dataclass
from enum import Enum


class PHPVulnCategory(Enum):
    INJECTION = "A03:2021-Injection"
    BROKEN_AUTH = "A07:2021-Authentication Failures"
    SENSITIVE_DATA = "A02:2021-Cryptographic Failures"
    XXE = "A05:2021-Security Misconfiguration"
    BROKEN_ACCESS = "A01:2021-Broken Access Control"
    MISCONFIG = "A05:2021-Security Misconfiguration"
    XSS = "A03:2021-Injection"
    DESER = "A08:2021-Software and Data Integrity"
    COMPONENTS = "A06:2021-Vulnerable Components"
    LOGGING = "A09:2021-Security Logging Failures"
    SSRF = "A10:2021-SSRF"
    FILE_SECURITY = "CWE-22"


@dataclass
class PHPVuln:
    vuln_type: str
    category: str
    severity: str
    line: int
    snippet: str
    description: str
    remediation: str
    cwe_id: str
    owasp: str
    confidence: float = 0.8


class PHPAnalyzer:
    """Enterprise PHP Security Analyzer with 25+ vulnerability classes"""
    
    # ============================================================
    # 1. SQL INJECTION
    # ============================================================
    SQL_INJECTION = [
        (r'mysql_query\s*\(', 'mysql_query (deprecated)', 'Critical'),
        (r'mysqli_query\s*\([^,]+,\s*["\'].*\$', 'mysqli_query variable', 'Critical'),
        (r'mysqli_query\s*\([^,]+,\s*["\'].*\.', 'mysqli_query concat', 'Critical'),
        (r'\$\w+->query\s*\(["\'].*\$', 'PDO query variable', 'Critical'),
        (r'\$\w+->query\s*\(["\'].*\.', 'PDO query concat', 'Critical'),
        (r'pg_query\s*\([^,]*,\s*["\'].*\$', 'PostgreSQL query', 'Critical'),
        (r'pg_query_params\s*\([^,]*,\s*["\'].*\$', 'PostgreSQL params', 'High'),
        (r'sqlite_query\s*\(', 'SQLite query (deprecated)', 'Critical'),
        (r'\$pdo->exec\s*\(["\'].*\$', 'PDO exec variable', 'Critical'),
        (r'->whereRaw\s*\(["\'].*\$', 'Laravel whereRaw', 'High'),
        (r'->selectRaw\s*\(["\'].*\$', 'Laravel selectRaw', 'High'),
        (r'->orderByRaw\s*\(["\'].*\$', 'Laravel orderByRaw', 'High'),
        (r'->havingRaw\s*\(["\'].*\$', 'Laravel havingRaw', 'High'),
        (r'->groupByRaw\s*\(["\'].*\$', 'Laravel groupByRaw', 'High'),
        (r'DB::raw\s*\(["\'].*\$', 'Laravel DB::raw', 'High'),
        (r'DB::select\s*\(["\'].*\$', 'Laravel DB::select', 'High'),
        (r'DB::statement\s*\(["\'].*\$', 'Laravel DB::statement', 'High'),
        (r'\$wpdb->query\s*\(["\'].*\$', 'WordPress wpdb', 'Critical'),
        (r'\$wpdb->prepare\s*\(["\'].*\$(?!\d)', 'WordPress prepare', 'High'),
        (r'\$wpdb->get_results\s*\(["\'].*\$', 'WordPress get_results', 'High'),
    ]
    
    # ============================================================
    # 2. COMMAND INJECTION
    # ============================================================
    COMMAND_INJECTION = [
        (r'exec\s*\([^)]*\$', 'exec variable', 'Critical'),
        (r'shell_exec\s*\([^)]*\$', 'shell_exec variable', 'Critical'),
        (r'system\s*\([^)]*\$', 'system variable', 'Critical'),
        (r'passthru\s*\([^)]*\$', 'passthru variable', 'Critical'),
        (r'popen\s*\([^)]*\$', 'popen variable', 'Critical'),
        (r'proc_open\s*\(', 'proc_open', 'High'),
        (r'pcntl_exec\s*\([^)]*\$', 'pcntl_exec variable', 'Critical'),
        (r'`[^`]*\$[^`]*`', 'Backtick variable', 'Critical'),
        (r'Artisan::call\s*\([^)]*\$', 'Laravel artisan', 'High'),
        (r'Symfony\\Component\\Process', 'Symfony Process', 'Medium'),
    ]
    
    # ============================================================
    # 3. XSS
    # ============================================================
    XSS = [
        (r'echo\s+\$', 'echo variable', 'High'),
        (r'print\s+\$', 'print variable', 'High'),
        (r'printf\s*\([^)]*\$', 'printf variable', 'High'),
        (r'\?>\s*<.*\$.*>', 'PHP in HTML', 'High'),
        (r'\{!!\s*\$', 'Blade unescaped', 'High'),
        (r'@php\s+echo\s+\$', 'Blade @php echo', 'High'),
        (r'<?=\s*\$(?!.*htmlspecialchars)', 'Short echo', 'High'),
        (r'print_r\s*\([^)]*\$', 'print_r output', 'Medium'),
        (r'var_dump\s*\([^)]*\$', 'var_dump output', 'Medium'),
        (r'document\.write\s*\([^)]*\$', 'document.write', 'High'),
        (r'innerHTML\s*=.*\$', 'innerHTML assignment', 'High'),
    ]
    
    # ============================================================
    # 4. FILE INCLUSION (LFI/RFI)
    # ============================================================
    FILE_INCLUSION = [
        (r'include\s*\(?[^)]*\$', 'include variable', 'Critical'),
        (r'include_once\s*\(?[^)]*\$', 'include_once variable', 'Critical'),
        (r'require\s*\(?[^)]*\$', 'require variable', 'Critical'),
        (r'require_once\s*\(?[^)]*\$', 'require_once variable', 'Critical'),
        (r'include\s+\$_(?:GET|POST|REQUEST)', 'include from request', 'Critical'),
        (r'require\s+\$_(?:GET|POST|REQUEST)', 'require from request', 'Critical'),
    ]
    
    # ============================================================
    # 5. PATH TRAVERSAL
    # ============================================================
    PATH_TRAVERSAL = [
        (r'file_get_contents\s*\([^)]*\$', 'file_get_contents variable', 'High'),
        (r'file_put_contents\s*\([^)]*\$', 'file_put_contents variable', 'High'),
        (r'fopen\s*\([^)]*\$', 'fopen variable', 'High'),
        (r'readfile\s*\([^)]*\$', 'readfile variable', 'High'),
        (r'unlink\s*\([^)]*\$', 'unlink variable', 'High'),
        (r'copy\s*\([^)]*\$', 'copy variable', 'High'),
        (r'rename\s*\([^)]*\$', 'rename variable', 'High'),
        (r'rmdir\s*\([^)]*\$', 'rmdir variable', 'High'),
        (r'mkdir\s*\([^)]*\$', 'mkdir variable', 'Medium'),
        (r'file_exists\s*\([^)]*\$', 'file_exists variable', 'Medium'),
        (r'is_file\s*\([^)]*\$', 'is_file variable', 'Low'),
        (r'Storage::get\s*\([^)]*\$', 'Laravel Storage get', 'High'),
        (r'Storage::put\s*\([^)]*\$', 'Laravel Storage put', 'High'),
        (r'Storage::delete\s*\([^)]*\$', 'Laravel Storage delete', 'High'),
    ]
    
    # ============================================================
    # 6. FILE UPLOAD
    # ============================================================
    FILE_UPLOAD = [
        (r'move_uploaded_file\s*\(', 'File upload', 'Medium'),
        (r'\$_FILES\s*\[', 'Files access', 'Low'),
        (r'getClientOriginalName\s*\(\s*\)', 'Original filename', 'Medium'),
        (r'getClientOriginalExtension\s*\(\s*\)', 'Original extension', 'Medium'),
        (r'getMimeType\s*\(\s*\)', 'MIME type check', 'Low'),
        (r'guessExtension\s*\(\s*\)', 'Guessed extension', 'Low'),
        (r'storeAs\s*\([^)]*\$', 'Laravel storeAs variable', 'High'),
        (r'putFileAs\s*\([^)]*\$', 'Laravel putFileAs variable', 'High'),
    ]
    
    # ============================================================
    # 7. DESERIALIZATION
    # ============================================================
    DESERIALIZATION = [
        (r'unserialize\s*\([^)]*\$', 'unserialize variable', 'Critical'),
        (r'unserialize\s*\(\s*\$_(?:GET|POST|REQUEST|COOKIE)', 'unserialize from request', 'Critical'),
        (r'maybe_unserialize\s*\([^)]*\$', 'WordPress unserialize', 'Critical'),
        (r'wakeup\s*\(\s*\)', '__wakeup (verify)', 'Medium'),
        (r'__destruct\s*\(\s*\)', '__destruct (verify)', 'Low'),
        (r'json_decode\s*\([^)]*\$', 'JSON decode (safer)', 'Low'),
    ]
    
    # ============================================================
    # 8. XXE
    # ============================================================
    XXE = [
        (r'simplexml_load_string\s*\([^)]*LIBXML_NOENT', 'SimpleXML XXE', 'Critical'),
        (r'simplexml_load_file\s*\([^)]*LIBXML_NOENT', 'SimpleXML file XXE', 'Critical'),
        (r'DOMDocument.*loadXML\s*\(', 'DOMDocument loadXML', 'High'),
        (r'libxml_disable_entity_loader\s*\(\s*false', 'Entity loader enabled', 'Critical'),
        (r'XMLReader::open', 'XMLReader open', 'Medium'),
        (r'SimpleXMLElement\s*\([^)]*\$', 'SimpleXMLElement variable', 'High'),
        (r'xml_parse\s*\([^)]*\$', 'xml_parse variable', 'High'),
    ]
    
    # ============================================================
    # 9. SSRF
    # ============================================================
    SSRF = [
        (r'file_get_contents\s*\([^)]*\$', 'file_get_contents URL', 'High'),
        (r'curl_setopt.*CURLOPT_URL.*\$', 'cURL URL variable', 'High'),
        (r'fopen\s*\([^)]*http.*\$', 'fopen HTTP', 'High'),
        (r'get_headers\s*\([^)]*\$', 'get_headers variable', 'High'),
        (r'Http::get\s*\([^)]*\$', 'Laravel HTTP get', 'High'),
        (r'Http::post\s*\([^)]*\$', 'Laravel HTTP post', 'High'),
        (r'Guzzle.*request\s*\([^)]*\$', 'Guzzle request', 'High'),
        (r'fsockopen\s*\([^)]*\$', 'fsockopen variable', 'High'),
    ]
    
    # ============================================================
    # 10. CRYPTOGRAPHIC ISSUES
    # ============================================================
    CRYPTO = [
        (r'md5\s*\(', 'MD5 hash', 'Medium'),
        (r'sha1\s*\(', 'SHA1 hash', 'Medium'),
        (r'crypt\s*\(', 'crypt()', 'Low'),
        (r'password\s*=\s*md5\s*\(', 'MD5 password', 'Critical'),
        (r'password\s*=\s*sha1\s*\(', 'SHA1 password', 'High'),
        (r'mcrypt_', 'mcrypt (deprecated)', 'High'),
        (r'MCRYPT_DES', 'DES encryption', 'Critical'),
        (r'MCRYPT_RIJNDAEL_256', 'Rijndael-256', 'Medium'),
        (r'openssl_encrypt\s*\([^)]*ECB', 'ECB mode', 'High'),
        (r'openssl_encrypt\s*\([^)]*DES', 'DES openssl', 'Critical'),
        (r'rand\s*\(\s*\)', 'rand() insecure', 'High'),
        (r'mt_rand\s*\(\s*\)', 'mt_rand() insecure', 'High'),
        (r'srand\s*\(\s*time', 'Seeded with time', 'High'),
        (r'uniqid\s*\(\s*\)', 'uniqid (predictable)', 'Medium'),
    ]
    
    # ============================================================
    # 11. AUTHENTICATION ISSUES
    # ============================================================
    AUTH = [
        (r'session_start\s*\(\s*\)(?!.*session_regenerate)', 'Session no regenerate', 'Medium'),
        (r'password\s*===?\s*[\'"]', 'Hardcoded password', 'Critical'),
        (r'==\s*\$password', 'Loose password comparison', 'High'),
        (r'strcmp\s*\([^)]*password', 'strcmp password', 'High'),
        (r'md5\s*\(\s*\$password', 'MD5 password', 'Critical'),
        (r'sha1\s*\(\s*\$password', 'SHA1 password', 'High'),
        (r'password_verify\s*\(', 'password_verify (good)', 'Info'),
        (r'password_hash\s*\(', 'password_hash (good)', 'Info'),
        (r'bcrypt\s*\(', 'bcrypt (good)', 'Info'),
    ]
    
    # ============================================================
    # 12. SESSION ISSUES
    # ============================================================
    SESSION = [
        (r'session\.cookie_secure.*false', 'Insecure session cookie', 'High'),
        (r'session\.cookie_httponly.*false', 'Non-HttpOnly session', 'Medium'),
        (r'session_set_cookie_params.*secure.*false', 'Insecure cookie params', 'High'),
        (r'setcookie\s*\([^)]*\)(?!.*true.*true)', 'Cookie no flags', 'Medium'),
        (r'\$_SESSION\s*\[\s*[\'"](?:user|admin|logged)', 'Direct session auth', 'Low'),
        (r'session_id\s*\(\s*\$', 'Session ID from variable', 'High'),
    ]
    
    # ============================================================
    # 13. HARDCODED SECRETS
    # ============================================================
    SECRETS = [
        (r'(?:password|passwd|pwd)\s*[=:]\s*[\'"][^\'"]{8,}[\'"]', 'Hardcoded password'),
        (r'(?:api_key|apikey)\s*[=:]\s*[\'"][A-Za-z0-9_\-]{20,}[\'"]', 'Hardcoded API key'),
        (r'(?:secret|secret_key)\s*[=:]\s*[\'"][^\'"]{16,}[\'"]', 'Hardcoded secret'),
        (r'(?:access_token|auth_token)\s*[=:]\s*[\'"][^\'"]{20,}[\'"]', 'Hardcoded token'),
        (r'mysql://[^:]+:[^@]+@', 'MySQL credentials'),
        (r'pgsql://[^:]+:[^@]+@', 'PostgreSQL credentials'),
        (r'mongodb://[^:]+:[^@]+@', 'MongoDB credentials'),
        (r'-----BEGIN\s+(?:RSA\s+)?PRIVATE\s+KEY-----', 'Private key'),
        (r"define\s*\(\s*['\"]DB_PASSWORD['\"].*['\"][^'\"]+['\"]", 'WordPress DB password'),
        (r'AWS_SECRET_ACCESS_KEY.*=.*[\'"][A-Za-z0-9+/=]{40}[\'"]', 'AWS secret'),
        (r'STRIPE_SECRET.*=.*[\'"]sk_live_[^\'"]+[\'"]', 'Stripe secret'),
    ]
    
    # ============================================================
    # 14. LARAVEL SPECIFIC
    # ============================================================
    LARAVEL = [
        (r'\$guarded\s*=\s*\[\s*\]', 'Empty $guarded', 'High'),
        (r'\$fillable\s*=\s*\[\s*\'\*\'\s*\]', 'Fillable all', 'High'),
        (r'->validate\s*\(\s*\[\s*\]', 'Empty validation', 'Medium'),
        (r'Route::any\s*\(', 'Route::any', 'Medium'),
        (r'withoutMiddleware.*csrf', 'CSRF disabled', 'High'),
        (r'->withoutGlobalScope', 'Scope bypassed', 'Medium'),
        (r'storage_path\s*\([^)]*\$', 'storage_path variable', 'High'),
        (r'public_path\s*\([^)]*\$', 'public_path variable', 'Medium'),
        (r'config\s*\(\s*[\'"]app\.debug[\'"].*true', 'Debug enabled', 'High'),
        (r'APP_DEBUG\s*=\s*true', '.env debug', 'High'),
        (r'APP_ENV\s*=\s*local', '.env local', 'Medium'),
        (r'->download\s*\([^)]*\$', 'Download variable', 'High'),
        (r'Crypt::decrypt\s*\([^)]*\$_', 'Decrypt from request', 'High'),
    ]
    
    # ============================================================
    # 15. WORDPRESS SPECIFIC
    # ============================================================
    WORDPRESS = [
        (r'current_user_can\s*\(\s*\)', 'Empty capability', 'High'),
        (r'check_admin_referer\s*\(\s*\)', 'Empty nonce', 'High'),
        (r'wp_nonce_field', 'Nonce field (good)', 'Info'),
        (r'wp_verify_nonce', 'Nonce verify (good)', 'Info'),
        (r'update_option\s*\([^)]*\$', 'update_option variable', 'High'),
        (r'add_option\s*\([^)]*\$', 'add_option variable', 'Medium'),
        (r'wp_redirect\s*\([^)]*\$', 'Redirect variable', 'High'),
        (r'wp_safe_redirect', 'Safe redirect (good)', 'Info'),
        (r'register_rest_route.*permission_callback.*__return_true', 'REST no auth', 'High'),
        (r'register_rest_route(?!.*permission_callback)', 'REST no permission', 'High'),
        (r'DISALLOW_FILE_EDIT.*false', 'File edit enabled', 'High'),
        (r"define\s*\(\s*['\"]WP_DEBUG['\"].*true", 'WP debug enabled', 'High'),
        (r'wpdb->prepare\s*\(\s*["\'].*%s.*%s.*\$', 'Improper prepare', 'High'),
    ]
    
    # ============================================================
    # 16. HEADER INJECTION
    # ============================================================
    HEADER_INJECTION = [
        (r'header\s*\([^)]*\$', 'header variable', 'High'),
        (r'setcookie\s*\([^)]*\$', 'setcookie variable', 'Medium'),
        (r'header\s*\(\s*[\'"]Location:.*\$', 'Redirect variable', 'High'),
        (r'header\s*\(\s*[\'"]Content-Type:.*\$', 'Content-Type variable', 'Medium'),
        (r'mail\s*\([^)]*\$', 'mail function', 'High'),
    ]
    
    # ============================================================
    # 17. EVAL INJECTION
    # ============================================================
    EVAL_INJECTION = [
        (r'eval\s*\([^)]*\$', 'eval variable', 'Critical'),
        (r'assert\s*\([^)]*\$', 'assert variable', 'Critical'),
        (r'create_function\s*\(', 'create_function', 'Critical'),
        (r'preg_replace\s*\([^)]*[\'"].*\/e[\'"]', 'preg_replace /e', 'Critical'),
        (r'call_user_func\s*\([^)]*\$', 'call_user_func variable', 'High'),
        (r'call_user_func_array\s*\([^)]*\$', 'call_user_func_array', 'High'),
    ]
    
    # ============================================================
    # 18. LDAP INJECTION
    # ============================================================
    LDAP = [
        (r'ldap_search\s*\([^)]*\$', 'ldap_search variable', 'High'),
        (r'ldap_bind\s*\([^)]*\$', 'ldap_bind variable', 'High'),
        (r'ldap_read\s*\([^)]*\$', 'ldap_read variable', 'High'),
        (r'ldap_modify\s*\([^)]*\$', 'ldap_modify variable', 'High'),
    ]
    
    # ============================================================
    # 19. LOG INJECTION
    # ============================================================
    LOG_INJECTION = [
        (r'error_log\s*\([^)]*\$', 'error_log variable', 'Medium'),
        (r'Log::\w+\s*\([^)]*\$', 'Laravel Log', 'Medium'),
        (r'->log\s*\([^)]*\$', 'Logger variable', 'Medium'),
        (r'syslog\s*\([^)]*\$', 'syslog variable', 'Medium'),
        (r'openlog\s*\([^)]*\$', 'openlog variable', 'Medium'),
    ]
    
    # ============================================================
    # 20. INFORMATION DISCLOSURE
    # ============================================================
    INFO_DISCLOSURE = [
        (r'display_errors\s*=\s*On', 'Display errors on', 'High'),
        (r'error_reporting\s*\(\s*E_ALL', 'Full error reporting', 'Medium'),
        (r'ini_set\s*\([\'"]display_errors[\'"].*1', 'Display errors ini', 'High'),
        (r'phpinfo\s*\(\s*\)', 'phpinfo exposed', 'High'),
        (r'var_dump\s*\(', 'var_dump (debug)', 'Medium'),
        (r'print_r\s*\(', 'print_r (debug)', 'Medium'),
        (r'debug_backtrace\s*\(', 'debug_backtrace', 'Medium'),
    ]
    
    # ============================================================
    # 21. MISCONFIGURATION
    # ============================================================
    MISCONFIG = [
        (r'allow_url_include\s*=\s*On', 'URL include on', 'Critical'),
        (r'allow_url_fopen\s*=\s*On', 'URL fopen on', 'Medium'),
        (r'register_globals\s*=\s*On', 'Register globals', 'Critical'),
        (r'expose_php\s*=\s*On', 'PHP exposed', 'Low'),
        (r'upload_max_filesize.*[0-9]+G', 'Large upload', 'Low'),
        (r'max_execution_time.*0', 'No execution limit', 'Medium'),
        (r'disable_functions\s*=\s*$', 'No disabled functions', 'Medium'),
    ]
    
    # ============================================================
    # 22. RACE CONDITIONS
    # ============================================================
    RACE_CONDITIONS = [
        (r'file_exists\s*\([^)]*\).*fopen', 'TOCTOU file check', 'Medium'),
        (r'is_writable\s*\([^)]*\).*fwrite', 'TOCTOU writable', 'Medium'),
        (r'flock\s*\([^)]*LOCK_EX', 'File locking (good)', 'Info'),
    ]
    
    # ============================================================
    # 23. OPEN REDIRECT
    # ============================================================
    OPEN_REDIRECT = [
        (r'header\s*\(\s*[\'"]Location:.*\$_(?:GET|POST|REQUEST)', 'Redirect from request', 'High'),
        (r'redirect\s*\([^)]*\$', 'redirect variable', 'High'),
        (r'Redirect::to\s*\([^)]*\$', 'Laravel redirect', 'High'),
        (r'return\s+redirect\s*\([^)]*\$', 'Return redirect', 'High'),
    ]
    
    # ============================================================
    # 24. TEMPLATE INJECTION
    # ============================================================
    TEMPLATE_INJECTION = [
        (r'Twig.*render.*\$', 'Twig render variable', 'High'),
        (r'Blade::render.*\$', 'Blade render variable', 'High'),
        (r'Smarty.*display.*\$', 'Smarty display variable', 'High'),
    ]
    
    # ============================================================
    # 25. REGEX DOS
    # ============================================================
    REGEX_DOS = [
        (r'preg_match\s*\(\s*[\'"].*\+\+', 'Greedy regex', 'Medium'),
        (r'preg_match\s*\(\s*\$', 'Regex from variable', 'High'),
        (r'preg_replace\s*\(\s*\$', 'Replace regex variable', 'High'),
        (r'preg_match_all\s*\(\s*\$', 'Match all variable', 'High'),
    ]
    
    def __init__(self):
        self.issues: List[PHPVuln] = []
        self.is_laravel = False
        self.is_wordpress = False
    
    def scan(self, code: str, filename: str = "") -> List[Dict]:
        self.issues = []
        lines = code.split('\n')
        
        # Detect framework
        self._detect_framework(code)
        
        # Run all checks
        self._check(lines, self.SQL_INJECTION, 'sql_injection', 'SQL Injection', 'CWE-89')
        self._check(lines, self.COMMAND_INJECTION, 'command_injection', 'Command Injection', 'CWE-78')
        self._check(lines, self.XSS, 'xss', 'Cross-Site Scripting', 'CWE-79')
        self._check(lines, self.FILE_INCLUSION, 'file_inclusion', 'File Inclusion', 'CWE-98')
        self._check(lines, self.PATH_TRAVERSAL, 'path_traversal', 'Path Traversal', 'CWE-22')
        self._check(lines, self.FILE_UPLOAD, 'file_upload', 'File Upload', 'CWE-434')
        self._check(lines, self.DESERIALIZATION, 'deserialization', 'Insecure Deserialization', 'CWE-502')
        self._check(lines, self.XXE, 'xxe', 'XML External Entity', 'CWE-611')
        self._check(lines, self.SSRF, 'ssrf', 'Server-Side Request Forgery', 'CWE-918')
        self._check(lines, self.CRYPTO, 'weak_crypto', 'Weak Cryptography', 'CWE-327')
        self._check(lines, self.AUTH, 'auth_issue', 'Authentication Issue', 'CWE-287')
        self._check(lines, self.SESSION, 'session_issue', 'Session Issue', 'CWE-384')
        self._check(lines, self.HEADER_INJECTION, 'header_injection', 'Header Injection', 'CWE-113')
        self._check(lines, self.EVAL_INJECTION, 'eval_injection', 'Eval Injection', 'CWE-95')
        self._check(lines, self.LDAP, 'ldap_injection', 'LDAP Injection', 'CWE-90')
        self._check(lines, self.LOG_INJECTION, 'log_injection', 'Log Injection', 'CWE-117')
        self._check(lines, self.INFO_DISCLOSURE, 'info_disclosure', 'Information Disclosure', 'CWE-200')
        self._check(lines, self.MISCONFIG, 'misconfiguration', 'Security Misconfiguration', 'CWE-16')
        self._check(lines, self.RACE_CONDITIONS, 'race_condition', 'Race Condition', 'CWE-362')
        self._check(lines, self.OPEN_REDIRECT, 'open_redirect', 'Open Redirect', 'CWE-601')
        self._check(lines, self.TEMPLATE_INJECTION, 'template_injection', 'Template Injection', 'CWE-94')
        self._check(lines, self.REGEX_DOS, 'regex_dos', 'Regex DoS', 'CWE-1333')
        
        if self.is_laravel:
            self._check(lines, self.LARAVEL, 'laravel_security', 'Laravel Security', 'CWE-20')
        if self.is_wordpress:
            self._check(lines, self.WORDPRESS, 'wordpress_security', 'WordPress Security', 'CWE-20')
        
        self._check_secrets(lines)
        
        return [self._to_dict(v, filename) for v in self.issues]
    
    def _detect_framework(self, code: str):
        self.is_laravel = any(x in code for x in ['namespace App\\', 'use Illuminate\\', 'extends Controller', 'Route::'])
        self.is_wordpress = any(x in code for x in ['add_action', 'add_filter', '$wpdb', 'WP_', 'get_option'])
    
    def _check(self, lines: List[str], patterns: list, vuln_type: str, desc: str, cwe: str):
        for i, line in enumerate(lines):
            for pattern, msg, severity in patterns:
                if severity == 'Info':
                    continue
                if re.search(pattern, line, re.IGNORECASE):
                    self.issues.append(PHPVuln(
                        vuln_type=vuln_type,
                        category=PHPVulnCategory.INJECTION.value,
                        severity=severity,
                        line=i+1,
                        snippet=line.strip()[:120],
                        description=f"{desc}: {msg}",
                        remediation=self._get_remediation(vuln_type),
                        cwe_id=cwe,
                        owasp=PHPVulnCategory.INJECTION.value,
                        confidence=0.85
                    ))
    
    def _check_secrets(self, lines: List[str]):
        for i, line in enumerate(lines):
            if line.strip().startswith('//') or line.strip().startswith('#'):
                continue
            if re.search(r'(YOUR_|REPLACE_|TODO|example|placeholder)', line, re.IGNORECASE):
                continue
            for pattern, msg in self.SECRETS:
                if re.search(pattern, line, re.IGNORECASE):
                    self.issues.append(PHPVuln(
                        vuln_type='hardcoded_secret',
                        category=PHPVulnCategory.SENSITIVE_DATA.value,
                        severity='High',
                        line=i+1,
                        snippet=re.sub(r'[=:]\s*[\'""]([^\'"]{4})[^\'"]*[\'""]', r'="\1****"', line.strip()[:100]),
                        description=f"Hardcoded Secret: {msg}",
                        remediation='Use environment variables or secure config management.',
                        cwe_id='CWE-798',
                        owasp=PHPVulnCategory.SENSITIVE_DATA.value
                    ))
    
    def _get_remediation(self, vuln_type: str) -> str:
        return {
            'sql_injection': 'Use prepared statements with PDO or mysqli.',
            'command_injection': 'Use escapeshellarg/escapeshellcmd. Avoid shell commands.',
            'xss': 'Use htmlspecialchars() with ENT_QUOTES.',
            'file_inclusion': 'Never include files based on user input.',
            'path_traversal': 'Use basename() and realpath(). Validate paths.',
            'file_upload': 'Validate MIME type and extension. Use random filenames.',
            'deserialization': 'Never unserialize() untrusted data. Use JSON.',
            'xxe': 'Disable external entities with libxml_disable_entity_loader.',
            'ssrf': 'Validate URLs against allowlist. Block internal IPs.',
            'weak_crypto': 'Use password_hash(). Use random_bytes().',
            'auth_issue': 'Use password_verify(). Regenerate session IDs.',
            'session_issue': 'Use secure cookie flags. Set SameSite.',
            'header_injection': 'Validate headers. Strip newlines.',
            'eval_injection': 'Never use eval() with user input.',
            'open_redirect': 'Validate redirect URLs against allowlist.',
            'laravel_security': 'Define $fillable/$guarded. Enable CSRF.',
            'wordpress_security': 'Use nonces. Check capabilities.',
        }.get(vuln_type, 'Review and fix security issue.')
    
    def _to_dict(self, v: PHPVuln, filename: str) -> Dict:
        return {
            'type': v.vuln_type, 'category': v.category, 'severity': v.severity, 'line': v.line,
            'snippet': v.snippet, 'description': v.description, 'remediation': v.remediation,
            'cwe_id': v.cwe_id, 'owasp': v.owasp, 'confidence': v.confidence, 'file': filename,
            'language': 'php', 'scanner': 'php_analyzer_v3'
        }


def scan_php(code: str, filename: str = "") -> List[Dict]:
    return PHPAnalyzer().scan(code, filename)
