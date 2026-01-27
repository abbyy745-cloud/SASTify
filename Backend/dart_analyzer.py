"""
Dart/Flutter Security Analyzer - Enterprise Edition

25+ Vulnerability Classes with Deep Detection:
- Injection (SQL, Command, WebView, Deep Link)
- Insecure Data Storage (SharedPreferences, Hive, Secure Storage)
- Network Security (SSL/TLS, Certificate Pinning)
- Cryptographic Failures
- State Management Security (Provider, Riverpod, GetX, BLoC)
- Platform Channel Security
- Widget Security
- Information Disclosure
- Authentication Issues
"""

import re
from typing import List, Dict
from dataclasses import dataclass
from enum import Enum


class FlutterVulnCategory(Enum):
    PLATFORM_USAGE = "M1-Improper Platform Usage"
    DATA_STORAGE = "M2-Insecure Data Storage"
    COMMUNICATION = "M3-Insecure Communication"
    AUTHENTICATION = "M4-Insecure Authentication"
    CRYPTO = "M5-Insufficient Cryptography"
    AUTHORIZATION = "M6-Insecure Authorization"
    CODE_QUALITY = "M7-Client Code Quality"
    CODE_TAMPERING = "M8-Code Tampering"
    REVERSE_ENG = "M9-Reverse Engineering"
    SIDE_CHANNEL = "M10-Extraneous Functionality"


@dataclass
class DartVuln:
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


class DartAnalyzer:
    """Enterprise Dart/Flutter Security Analyzer with 25+ vulnerability classes"""
    
    # ============================================================
    # 1. SQL INJECTION
    # ============================================================
    SQL_INJECTION = [
        (r'rawQuery\s*\([^)]*\$', 'rawQuery interpolation', 'Critical'),
        (r'rawQuery\s*\([^)]*\+', 'rawQuery concatenation', 'Critical'),
        (r'execute\s*\([^)]*\$', 'execute interpolation', 'Critical'),
        (r'rawInsert\s*\([^)]*\$', 'rawInsert interpolation', 'High'),
        (r'rawUpdate\s*\([^)]*\$', 'rawUpdate interpolation', 'High'),
        (r'rawDelete\s*\([^)]*\$', 'rawDelete interpolation', 'High'),
        (r'Sqflite.*query.*\$', 'Sqflite query interpolation', 'High'),
        (r'database\.execute\s*\([^)]*\$', 'Database execute interpolation', 'Critical'),
    ]
    
    # ============================================================
    # 2. COMMAND INJECTION
    # ============================================================
    COMMAND_INJECTION = [
        (r'Process\.run\s*\([^)]*\$', 'Process.run interpolation', 'Critical'),
        (r'Process\.start\s*\([^)]*\$', 'Process.start interpolation', 'Critical'),
        (r'Process\.runSync\s*\([^)]*\$', 'Process.runSync interpolation', 'Critical'),
        (r'shell\s*:\s*true', 'Shell execution enabled', 'High'),
        (r'ProcessResult.*\$', 'ProcessResult with interpolation', 'High'),
    ]
    
    # ============================================================
    # 3. INSECURE DATA STORAGE
    # ============================================================
    DATA_STORAGE = [
        (r'SharedPreferences.*setString\s*\([^)]*password', 'Password in SharedPreferences', 'High'),
        (r'SharedPreferences.*setString\s*\([^)]*token', 'Token in SharedPreferences', 'High'),
        (r'SharedPreferences.*setString\s*\([^)]*secret', 'Secret in SharedPreferences', 'High'),
        (r'SharedPreferences.*setString\s*\([^)]*apiKey', 'API key in SharedPreferences', 'High'),
        (r'prefs\.setString\s*\([^)]*password', 'Password in prefs', 'High'),
        (r'Hive\.box.*put\s*\([^)]*password', 'Password in Hive', 'High'),
        (r'Hive\.box.*put\s*\([^)]*token', 'Token in Hive', 'High'),
        (r'Hive\.openBox(?!.*encryptionKey)', 'Unencrypted Hive box', 'Medium'),
        (r'GetStorage\(\)\.write\s*\([^)]*password', 'Password in GetStorage', 'High'),
        (r'GetStorage\(\)\.write\s*\([^)]*token', 'Token in GetStorage', 'High'),
        (r'File\s*\(.*\)\.writeAsString.*password', 'Password written to file', 'High'),
        (r'getExternalStorageDirectory', 'External storage (public)', 'Medium'),
        (r'getTemporaryDirectory', 'Temp directory', 'Low'),
        (r'Clipboard\.setData.*password', 'Password to clipboard', 'High'),
        (r'Clipboard\.setData.*token', 'Token to clipboard', 'High'),
    ]
    
    # ============================================================
    # 4. NETWORK SECURITY
    # ============================================================
    NETWORK_SECURITY = [
        (r"'http://", 'Cleartext HTTP URL', 'High'),
        (r'"http://', 'Cleartext HTTP URL', 'High'),
        (r'http://\$', 'Dynamic HTTP URL', 'High'),
        (r'badCertificateCallback.*=>\s*true', 'Certificate bypass', 'Critical'),
        (r'badCertificateCallback.*return\s+true', 'Certificate validation bypassed', 'Critical'),
        (r'onBadCertificate:\s*\([^)]*\)\s*=>\s*true', 'Dio certificate bypass', 'Critical'),
        (r'validateCertificate.*false', 'Certificate validation disabled', 'Critical'),
        (r'acceptBadCertificates.*true', 'Bad certificates accepted', 'Critical'),
        (r'HttpClient\(\).*badCertificateCallback', 'Custom certificate callback', 'Medium'),
        (r'SecurityContext.*setTrustedCertificates', 'Certificate pinning (good)', 'Info'),
        (r'baseUrl.*=\s*[\'"]http://', 'Cleartext base URL', 'High'),
        (r'Dio\(\).*options.*baseUrl.*http://', 'Dio HTTP baseUrl', 'High'),
    ]
    
    # ============================================================
    # 5. WEBVIEW SECURITY
    # ============================================================
    WEBVIEW = [
        (r'WebView\s*\(', 'WebView usage', 'Low'),
        (r'javascriptMode:\s*JavascriptMode\.unrestricted', 'Unrestricted JavaScript', 'Medium'),
        (r'WebViewController.*runJavaScript', 'JavaScript execution', 'Medium'),
        (r'addJavaScriptChannel', 'JS channel exposed', 'Medium'),
        (r'evaluateJavascript', 'JavaScript evaluation', 'Medium'),
        (r'setJavaScriptMode.*unrestricted', 'Unrestricted JS mode', 'Medium'),
        (r'loadUrl\s*\([^)]*\$', 'loadUrl interpolation', 'High'),
        (r'loadHtmlString\s*\([^)]*\$', 'loadHtmlString interpolation', 'High'),
        (r'runJavaScript\s*\([^)]*\$', 'runJavaScript interpolation', 'Critical'),
        (r'InAppWebView.*javaScriptEnabled:\s*true', 'InAppWebView JS enabled', 'Medium'),
        (r'InAppWebView.*allowFileAccessFromFileURLs:\s*true', 'File URL access', 'High'),
    ]
    
    # ============================================================
    # 6. CRYPTOGRAPHIC ISSUES
    # ============================================================
    CRYPTO = [
        (r'md5\.convert', 'MD5 hashing', 'Medium'),
        (r'sha1\.convert', 'SHA1 hashing', 'Medium'),
        (r"import 'package:crypto/crypto.dart'.*md5", 'MD5 import', 'Medium'),
        (r'AESMode\.ecb', 'ECB mode encryption', 'High'),
        (r"AES\(.*mode:\s*'ecb'", 'AES ECB mode', 'High'),
        (r'encryptionKey.*=\s*[\'"][^\'"]{16,}[\'"]', 'Hardcoded encryption key', 'Critical'),
        (r'IV\.fromUtf8\s*\([\'"][^\'"]+[\'"]', 'Hardcoded IV', 'High'),
        (r'Key\.fromUtf8\s*\([\'"][^\'"]+[\'"]', 'Hardcoded key', 'Critical'),
        (r'Random\s*\(\s*\)', 'Insecure Random', 'High'),
        (r'Random\s*\(\s*\d+\s*\)', 'Seeded Random', 'High'),
        (r'math\.Random', 'Math.Random (insecure)', 'High'),
        (r'SecureRandom', 'SecureRandom (good)', 'Info'),
    ]
    
    # ============================================================
    # 7. AUTHENTICATION ISSUES
    # ============================================================
    AUTH = [
        (r'LocalAuthentication\(\)', 'Local authentication', 'Low'),
        (r'authenticateWithBiometrics', 'Biometric auth', 'Low'),
        (r'biometricOnly:\s*true', 'Biometric only auth', 'Low'),
        (r'useErrorDialogs:\s*false', 'Error dialogs disabled', 'Low'),
        (r'password\s*==\s*[\'"]', 'Hardcoded password check', 'Critical'),
        (r'\.compareTo\s*\(\s*password\s*\)', 'String password comparison', 'Medium'),
        (r'token\s*=\s*[\'"][A-Za-z0-9_\-]{20,}[\'"]', 'Hardcoded token', 'Critical'),
        (r'Bearer\s+[A-Za-z0-9\-_=]+\.[A-Za-z0-9\-_=]+', 'Hardcoded JWT', 'Critical'),
        (r'FirebaseAuth.*signInAnonymously', 'Anonymous sign in', 'Low'),
    ]
    
    # ============================================================
    # 8. HARDCODED SECRETS
    # ============================================================
    SECRETS = [
        (r'(?:apiKey|api_key|API_KEY)\s*=\s*[\'"][A-Za-z0-9_\-]{20,}[\'"]', 'Hardcoded API key'),
        (r'(?:password|PASSWORD)\s*=\s*[\'"](?!\s*$)[^\'"]{8,}[\'"]', 'Hardcoded password'),
        (r'(?:secret|SECRET|secretKey)\s*=\s*[\'"][^\'"]{16,}[\'"]', 'Hardcoded secret'),
        (r'(?:accessToken|access_token)\s*=\s*[\'"][^\'"]{20,}[\'"]', 'Hardcoded access token'),
        (r'AIza[0-9A-Za-z\-_]{35}', 'Google API key'),
        (r'sk_live_[0-9a-zA-Z]{24}', 'Stripe live key'),
        (r'pk_live_[0-9a-zA-Z]{24}', 'Stripe publishable key'),
        (r'AKIA[0-9A-Z]{16}', 'AWS access key'),
        (r'-----BEGIN\s+(?:RSA\s+)?PRIVATE\s+KEY-----', 'Embedded private key'),
        (r'firebase.*[\'"][A-Za-z0-9\-_]{30,}[\'"]', 'Firebase key'),
        (r'mongodb\+srv://[^:]+:[^@]+@', 'MongoDB connection string'),
        (r'ghp_[A-Za-z0-9]{36}', 'GitHub token'),
    ]
    
    # ============================================================
    # 9. PLATFORM CHANNEL SECURITY
    # ============================================================
    PLATFORM_CHANNEL = [
        (r'MethodChannel\s*\([\'"][^\'"]+[\'"]', 'Method channel', 'Low'),
        (r'invokeMethod\s*\([\'"][^\'"]+[\'"],\s*\{', 'Method invocation with args', 'Low'),
        (r'setMethodCallHandler', 'Method call handler', 'Low'),
        (r'receiveBroadcastStream', 'Event stream listening', 'Low'),
        (r'PlatformViewLink', 'Platform view integration', 'Low'),
        (r'invokeMethod.*password', 'Password in platform channel', 'High'),
        (r'invokeMethod.*token', 'Token in platform channel', 'Medium'),
        (r'EventChannel\s*\(.*password', 'Password in EventChannel', 'High'),
    ]
    
    # ============================================================
    # 10. STATE MANAGEMENT SECURITY
    # ============================================================
    STATE_MANAGEMENT = [
        (r'ChangeNotifierProvider.*password', 'Password in Provider', 'High'),
        (r'Provider\.of<.*>.*password', 'Password from Provider', 'High'),
        (r'StateProvider.*password', 'Password in StateProvider', 'High'),
        (r'ref\.watch.*password', 'Password watched from Riverpod', 'High'),
        (r'Get\.put.*password', 'Password in GetX controller', 'High'),
        (r'Obx\s*\(.*password', 'Password in Obx', 'High'),
        (r'BlocProvider.*password', 'Password in BLoC', 'High'),
        (r'state\.copyWith\s*\([^)]*password', 'Password in BLoC state', 'High'),
        (r'\.value\s*=.*password', 'Password in observable', 'High'),
        (r'StateNotifier.*password', 'Password in StateNotifier', 'High'),
        (r'StreamController.*password', 'Password in StreamController', 'High'),
    ]
    
    # ============================================================
    # 11. DEEP LINK SECURITY
    # ============================================================
    DEEP_LINK = [
        (r'uni_links', 'Deep link handling', 'Low'),
        (r'getInitialLink\(\)', 'Initial link handler', 'Low'),
        (r'linkStream\.listen', 'Link stream listener', 'Medium'),
        (r'Uri\.parse\s*\([^)]*\)\.queryParameters', 'Query param parsing', 'Medium'),
        (r'app_links', 'App links package', 'Low'),
        (r'onGenerateRoute.*Uri\.parse', 'Dynamic routing with URI', 'Medium'),
        (r'go_router.*path.*:', 'GoRouter path parameter', 'Low'),
        (r'Navigator\.pushNamed.*\$', 'Navigator interpolation', 'Medium'),
    ]
    
    # ============================================================
    # 12. DEBUG/RELEASE ISSUES
    # ============================================================
    DEBUG = [
        (r'kDebugMode', 'Debug mode check', 'Low'),
        (r'kReleaseMode', 'Release mode check', 'Low'),
        (r'assert\s*\(', 'Assert statement', 'Low'),
        (r'debugPrint', 'Debug print', 'Low'),
        (r'debugShowCheckedModeBanner:\s*true', 'Debug banner visible', 'Low'),
        (r'showPerformanceOverlay:\s*true', 'Performance overlay', 'Low'),
        (r'checkerboardRasterCacheImages:\s*true', 'Debug checkerboard', 'Low'),
        (r'print\s*\([^)]*password', 'Password printed', 'High'),
        (r'print\s*\([^)]*token', 'Token printed', 'High'),
        (r'debugPrint\s*\([^)]*password', 'Password debug printed', 'High'),
    ]
    
    # ============================================================
    # 13. CODE QUALITY
    # ============================================================
    CODE_QUALITY = [
        (r'catch\s*\([^)]*\)\s*\{[\s\n]*\}', 'Empty catch block', 'Low'),
        (r'catch\s*\([^)]*\)\s*\{[\s\n]*print\s*\(', 'Error only printed', 'Low'),
        (r'TODO.*(?:security|auth|password|encrypt)', 'Security TODO', 'Medium'),
        (r'FIXME.*(?:security|auth|password|encrypt)', 'Security FIXME', 'Medium'),
        (r'\/\/\s*HACK', 'HACK comment', 'Low'),
        (r'throw\s+Exception\s*\([^)]*\)', 'Generic exception', 'Low'),
        (r'dynamic\s+\w+', 'Dynamic type usage', 'Low'),
        (r'!\s*$', 'Null assertion (bang)', 'Low'),
    ]
    
    # ============================================================
    # 14. PATH TRAVERSAL
    # ============================================================
    PATH_TRAVERSAL = [
        (r'File\s*\([^)]*\$', 'File with interpolation', 'High'),
        (r'Directory\s*\([^)]*\$', 'Directory with interpolation', 'High'),
        (r'FileSystemEntity.*path.*\$', 'FileSystem with interpolation', 'High'),
        (r'File\.fromUri\s*\([^)]*\$', 'File.fromUri interpolation', 'High'),
        (r'path\.join\s*\([^)]*\$', 'path.join interpolation', 'Medium'),
    ]
    
    # ============================================================
    # 15. URL LAUNCH SECURITY
    # ============================================================
    URL_LAUNCH = [
        (r'launchUrl\s*\([^)]*\$', 'launchUrl interpolation', 'High'),
        (r'launch\s*\([^)]*\$', 'launch interpolation', 'High'),
        (r'openUrl\s*\([^)]*\$', 'openUrl interpolation', 'Medium'),
        (r'canLaunchUrl.*\$', 'canLaunchUrl interpolation', 'Low'),
        (r'LaunchMode\.externalApplication', 'External app launch', 'Low'),
    ]
    
    # ============================================================
    # 16. FIREBASE SECURITY
    # ============================================================
    FIREBASE = [
        (r'FirebaseFirestore.*collection.*\$', 'Firestore collection interpolation', 'Medium'),
        (r'FirebaseStorage.*ref.*\$', 'Storage ref interpolation', 'Medium'),
        (r'FirebaseDatabase.*ref.*\$', 'Database ref interpolation', 'Medium'),
        (r'SecurityRules.*allow\s+read', 'Security rules read', 'Info'),
        (r'SecurityRules.*allow\s+write', 'Security rules write', 'Info'),
        (r'\.enablePersistence\s*\(\s*\)', 'Firestore persistence', 'Low'),
    ]
    
    # ============================================================
    # 17. HTTP CLIENT SECURITY
    # ============================================================
    HTTP_CLIENT = [
        (r'http\.get\s*\([^)]*\$', 'HTTP GET interpolation', 'Medium'),
        (r'http\.post\s*\([^)]*\$', 'HTTP POST interpolation', 'Medium'),
        (r'Dio\(\)\.get\s*\([^)]*\$', 'Dio GET interpolation', 'Medium'),
        (r'Dio\(\)\.post\s*\([^)]*\$', 'Dio POST interpolation', 'Medium'),
        (r'headers.*Authorization.*\$', 'Auth header interpolation', 'Medium'),
        (r'headers.*Bearer.*\$', 'Bearer token interpolation', 'Medium'),
    ]
    
    # ============================================================
    # 18. LOGGING
    # ============================================================
    LOGGING = [
        (r'print\s*\([^)]*(?:password|token|secret|key|api)', 'Sensitive data printed', 'High'),
        (r'debugPrint\s*\([^)]*(?:password|token|secret)', 'Sensitive debug print', 'High'),
        (r'log\s*\([^)]*(?:password|token|secret)', 'Sensitive data logged', 'High'),
        (r'Logger.*(?:password|token|secret)', 'Sensitive in Logger', 'High'),
        (r'Crashlytics.*(?:password|token)', 'Sensitive in Crashlytics', 'High'),
        (r'FirebaseAnalytics.*(?:password|token)', 'Sensitive in Analytics', 'High'),
    ]
    
    # ============================================================
    # 19. WIDGET SECURITY
    # ============================================================
    WIDGET = [
        (r'TextField.*obscureText:\s*false.*password', 'Password not obscured', 'High'),
        (r'TextFormField.*password(?!.*obscureText:\s*true)', 'Password field not obscured', 'High'),
        (r'Text\s*\(.*password', 'Password in Text widget', 'High'),
        (r'SelectableText\s*\(.*password', 'Password selectable', 'High'),
        (r'Image\.network\s*\([^)]*\$', 'Image.network interpolation', 'Low'),
    ]
    
    # ============================================================
    # 20. PERMISSION SECURITY
    # ============================================================
    PERMISSIONS = [
        (r'Permission\.camera', 'Camera permission', 'Info'),
        (r'Permission\.location', 'Location permission', 'Info'),
        (r'Permission\.microphone', 'Microphone permission', 'Info'),
        (r'Permission\.storage', 'Storage permission', 'Info'),
        (r'Permission\.contacts', 'Contacts permission', 'Info'),
        (r'openAppSettings', 'Open app settings', 'Info'),
    ]
    
    # ============================================================
    # 21. BIOMETRIC SECURITY
    # ============================================================
    BIOMETRIC = [
        (r'FlutterBiometric', 'Flutter biometric', 'Low'),
        (r'local_auth', 'Local auth package', 'Low'),
        (r'canCheckBiometrics', 'Biometric check', 'Low'),
        (r'BiometricType\.fingerprint', 'Fingerprint type', 'Low'),
        (r'BiometricType\.face', 'Face type', 'Low'),
        (r'stickyAuth:\s*false', 'Sticky auth disabled', 'Medium'),
    ]
    
    # ============================================================
    # 22. SECURE STORAGE
    # ============================================================
    SECURE_STORAGE = [
        (r'FlutterSecureStorage\(\)', 'Secure storage usage', 'Info'),
        (r'FlutterSecureStorage\(\)\.write', 'Secure storage write', 'Info'),
        (r'FlutterSecureStorage\(\)\.read', 'Secure storage read', 'Info'),
        (r'Hive\.openEncryptedBox', 'Encrypted Hive box', 'Info'),
        (r'EncryptedSharedPreferences', 'Encrypted prefs', 'Info'),
    ]
    
    # ============================================================
    # 23. MEMORY SAFETY
    # ============================================================
    MEMORY = [
        (r'Pointer<', 'FFI Pointer usage', 'Medium'),
        (r'ffi\.allocate', 'FFI allocate', 'Medium'),
        (r'ffi\.free', 'FFI free', 'Low'),
        (r'Uint8List\.fromList', 'Uint8List creation', 'Low'),
        (r'ByteData\.view', 'ByteData view', 'Low'),
    ]
    
    # ============================================================
    # 24. ASYNC SAFETY
    # ============================================================
    ASYNC = [
        (r'Future\.wait\s*\([^)]*\)(?!.*try)', 'Future.wait without try', 'Low'),
        (r'\.then\s*\([^)]*\)(?!.*catchError)', 'then without catchError', 'Low'),
        (r'async\s*\{(?![\s\S]*try)', 'async without try', 'Low'),
        (r'StreamController(?!.*close)', 'StreamController not closed', 'Low'),
        (r'Timer\.periodic(?!.*cancel)', 'Timer not cancelled', 'Low'),
    ]
    
    # ============================================================
    # 25. THIRD PARTY SECURITY
    # ============================================================
    THIRD_PARTY = [
        (r'import.*firebase', 'Firebase import', 'Info'),
        (r'import.*google_sign_in', 'Google Sign In', 'Info'),
        (r'import.*facebook_auth', 'Facebook Auth', 'Info'),
        (r'import.*apple_sign_in', 'Apple Sign In', 'Info'),
        (r'import.*stripe', 'Stripe import', 'Info'),
        (r'import.*sentry', 'Sentry import', 'Info'),
    ]
    
    def __init__(self):
        self.issues: List[DartVuln] = []
    
    def scan(self, code: str, filename: str = "") -> List[Dict]:
        self.issues = []
        lines = code.split('\n')
        
        # Run all checks
        self._check(lines, self.SQL_INJECTION, 'sql_injection', 'SQL Injection', 'CWE-89')
        self._check(lines, self.COMMAND_INJECTION, 'command_injection', 'Command Injection', 'CWE-78')
        self._check(lines, self.DATA_STORAGE, 'insecure_storage', 'Insecure Data Storage', 'CWE-312')
        self._check(lines, self.NETWORK_SECURITY, 'insecure_network', 'Network Security', 'CWE-295')
        self._check(lines, self.WEBVIEW, 'webview_security', 'WebView Security', 'CWE-749')
        self._check(lines, self.CRYPTO, 'weak_crypto', 'Weak Cryptography', 'CWE-327')
        self._check(lines, self.AUTH, 'auth_issue', 'Authentication Issue', 'CWE-287')
        self._check(lines, self.PLATFORM_CHANNEL, 'platform_channel', 'Platform Channel Security', 'CWE-200')
        self._check(lines, self.STATE_MANAGEMENT, 'state_security', 'State Management Security', 'CWE-312')
        self._check(lines, self.DEEP_LINK, 'deep_link', 'Deep Link Security', 'CWE-939')
        self._check(lines, self.DEBUG, 'debug_issue', 'Debug Issue', 'CWE-489')
        self._check(lines, self.CODE_QUALITY, 'code_quality', 'Code Quality', 'CWE-710')
        self._check(lines, self.PATH_TRAVERSAL, 'path_traversal', 'Path Traversal', 'CWE-22')
        self._check(lines, self.URL_LAUNCH, 'url_launch', 'URL Launch Security', 'CWE-601')
        self._check(lines, self.FIREBASE, 'firebase_security', 'Firebase Security', 'CWE-284')
        self._check(lines, self.HTTP_CLIENT, 'http_security', 'HTTP Client Security', 'CWE-319')
        self._check(lines, self.LOGGING, 'info_disclosure', 'Information Disclosure', 'CWE-532')
        self._check(lines, self.WIDGET, 'widget_security', 'Widget Security', 'CWE-200')
        self._check(lines, self.BIOMETRIC, 'biometric_security', 'Biometric Security', 'CWE-287')
        self._check(lines, self.MEMORY, 'memory_safety', 'Memory Safety', 'CWE-119')
        self._check(lines, self.ASYNC, 'async_safety', 'Async Safety', 'CWE-755')
        self._check_secrets(lines)
        
        return [self._to_dict(v, filename) for v in self.issues]
    
    def _check(self, lines: List[str], patterns: list, vuln_type: str, desc: str, cwe: str):
        for i, line in enumerate(lines):
            for pattern, msg, severity in patterns:
                if severity == 'Info':
                    continue
                if re.search(pattern, line, re.IGNORECASE):
                    self.issues.append(DartVuln(
                        vuln_type=vuln_type,
                        category=FlutterVulnCategory.CODE_QUALITY.value,
                        severity=severity,
                        line=i+1,
                        snippet=line.strip()[:120],
                        description=f"{desc}: {msg}",
                        remediation=self._get_remediation(vuln_type),
                        cwe_id=cwe,
                        owasp=FlutterVulnCategory.CODE_QUALITY.value,
                        confidence=0.85
                    ))
    
    def _check_secrets(self, lines: List[str]):
        for i, line in enumerate(lines):
            if re.search(r'(test|example|placeholder|YOUR_)', line, re.IGNORECASE):
                continue
            for pattern, msg in self.SECRETS:
                if re.search(pattern, line, re.IGNORECASE):
                    self.issues.append(DartVuln(
                        vuln_type='hardcoded_secret',
                        category=FlutterVulnCategory.CRYPTO.value,
                        severity='High',
                        line=i+1,
                        snippet=re.sub(r'[\'"][^\'"]{4}([^\'"]*)[\'"]', r'"****\1"', line.strip()[:100]),
                        description=f"Hardcoded Secret: {msg}",
                        remediation='Use flutter_secure_storage or dart-define for secrets.',
                        cwe_id='CWE-798',
                        owasp=FlutterVulnCategory.CRYPTO.value
                    ))
    
    def _get_remediation(self, vuln_type: str) -> str:
        return {
            'sql_injection': 'Use parameterized queries with sqflite.',
            'command_injection': 'Avoid Process.run with user input.',
            'insecure_storage': 'Use flutter_secure_storage for sensitive data.',
            'insecure_network': 'Use HTTPS. Implement certificate pinning.',
            'webview_security': 'Disable JS when not needed. Validate URLs.',
            'weak_crypto': 'Use AES-GCM. Use SecureRandom.',
            'auth_issue': 'Use secure auth packages. Store tokens securely.',
            'platform_channel': 'Validate data from platform channels.',
            'state_security': 'Avoid passwords in observable state.',
            'deep_link': 'Validate all deep link parameters.',
            'debug_issue': 'Remove debug code in production.',
            'path_traversal': 'Validate paths. Use path package.',
            'url_launch': 'Validate URLs before launching.',
            'http_security': 'Use HTTPS. Avoid interpolation in URLs.',
            'widget_security': 'Use obscureText for password fields.',
        }.get(vuln_type, 'Review and fix security issue.')
    
    def _to_dict(self, v: DartVuln, filename: str) -> Dict:
        return {
            'type': v.vuln_type, 'category': v.category, 'severity': v.severity, 'line': v.line,
            'snippet': v.snippet, 'description': v.description, 'remediation': v.remediation,
            'cwe_id': v.cwe_id, 'owasp': v.owasp, 'confidence': v.confidence, 'file': filename,
            'language': 'dart', 'scanner': 'dart_analyzer_v3'
        }


def scan_dart(code: str, filename: str = "") -> List[Dict]:
    return DartAnalyzer().scan(code, filename)
