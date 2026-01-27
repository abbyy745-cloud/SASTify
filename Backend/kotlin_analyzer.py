"""
Kotlin/Android Security Analyzer - Enterprise Edition

25+ Vulnerability Classes with Deep Detection:
- Injection (SQL, Command, Intent, WebView, Deep Link)
- Insecure Data Storage (SharedPreferences, Room, DataStore)
- Network Security (SSL/TLS, Certificate Pinning)
- Cryptographic Failures
- Memory Safety (Null Safety, Type Casting)
- Race Conditions (Coroutine Safety)
- Resource Leaks
- Authentication & Authorization
- Information Disclosure
- Jetpack Compose Security
- Android Component Security
"""

import re
from typing import List, Dict, Optional
from dataclasses import dataclass
from enum import Enum


class KotlinVulnCategory(Enum):
    INJECTION = "M7-Client Code Quality"
    DATA_STORAGE = "M2-Insecure Data Storage"
    COMMUNICATION = "M3-Insecure Communication"
    AUTHENTICATION = "M4-Insecure Authentication"
    CRYPTO = "M5-Insufficient Cryptography"
    PLATFORM_USAGE = "M1-Improper Platform Usage"
    CODE_QUALITY = "M7-Client Code Quality"
    REVERSE_ENG = "M9-Reverse Engineering"
    SIDE_CHANNEL = "M10-Extraneous Functionality"


@dataclass
class KotlinVuln:
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


class KotlinAnalyzer:
    """Enterprise Kotlin/Android Security Analyzer with 25+ vulnerability classes"""
    
    # ============================================================
    # 1. SQL INJECTION
    # ============================================================
    SQL_INJECTION = [
        (r'rawQuery\s*\([^)]*\$', 'rawQuery interpolation', 'Critical'),
        (r'rawQuery\s*\([^)]*\+', 'rawQuery concatenation', 'Critical'),
        (r'execSQL\s*\([^)]*\$', 'execSQL interpolation', 'Critical'),
        (r'execSQL\s*\([^)]*\+', 'execSQL concatenation', 'Critical'),
        (r'query\s*\([^)]*\$', 'query interpolation', 'High'),
        (r'compileStatement\s*\([^)]*\$', 'compileStatement interpolation', 'Critical'),
        (r'@Query\s*\([^)]*\$', 'Room @Query interpolation', 'High'),
        (r'SimpleSQLiteQuery\s*\([^)]*\$', 'SimpleSQLiteQuery interpolation', 'High'),
        (r'RawQuery.*\+', 'RawQuery concatenation', 'High'),
        (r'SupportSQLiteQuery.*\$', 'SupportSQLiteQuery interpolation', 'High'),
    ]
    
    # ============================================================
    # 2. COMMAND INJECTION
    # ============================================================
    COMMAND_INJECTION = [
        (r'Runtime\.getRuntime\(\)\.exec\s*\([^)]*\$', 'Runtime.exec interpolation', 'Critical'),
        (r'ProcessBuilder\s*\([^)]*\$', 'ProcessBuilder interpolation', 'Critical'),
        (r'\.command\s*\([^)]*\$', 'command() interpolation', 'Critical'),
        (r'Process.*\$', 'Process with interpolation', 'High'),
    ]
    
    # ============================================================
    # 3. INTENT INJECTION
    # ============================================================
    INTENT_INJECTION = [
        (r'startActivity\s*\([^)]*\$', 'startActivity interpolation', 'High'),
        (r'startActivityForResult\s*\([^)]*\$', 'startActivityForResult interpolation', 'High'),
        (r'sendBroadcast\s*\([^)]*\$', 'sendBroadcast interpolation', 'High'),
        (r'startService\s*\([^)]*\$', 'startService interpolation', 'High'),
        (r'Intent\s*\([^)]*\$', 'Intent with interpolation', 'Medium'),
        (r'Intent\.parseUri\s*\(', 'Intent.parseUri (dangerous)', 'High'),
        (r'intent\.setComponent\s*\([^)]*\$', 'setComponent interpolation', 'High'),
        (r'intent\.setClassName\s*\([^)]*\$', 'setClassName interpolation', 'High'),
        (r'intent\.setClass\s*\([^)]*\$', 'setClass interpolation', 'Medium'),
        (r'ComponentName\s*\([^)]*\$', 'ComponentName interpolation', 'High'),
    ]
    
    # ============================================================
    # 4. INSECURE DATA STORAGE
    # ============================================================
    DATA_STORAGE = [
        (r'getSharedPreferences\s*\([^)]*MODE_WORLD_READABLE', 'World readable prefs', 'Critical'),
        (r'getSharedPreferences\s*\([^)]*MODE_WORLD_WRITEABLE', 'World writeable prefs', 'Critical'),
        (r'SharedPreferences.*putString\s*\([^)]*password', 'Password in SharedPrefs', 'High'),
        (r'SharedPreferences.*putString\s*\([^)]*token', 'Token in SharedPrefs', 'High'),
        (r'SharedPreferences.*putString\s*\([^)]*secret', 'Secret in SharedPrefs', 'High'),
        (r'SharedPreferences.*putString\s*\([^)]*key', 'Key in SharedPrefs', 'High'),
        (r'SharedPreferences.*putString\s*\([^)]*api', 'API key in SharedPrefs', 'High'),
        (r'DataStore.*password', 'Password in DataStore', 'High'),
        (r'DataStore.*token', 'Token in DataStore', 'High'),
        (r'Room.*Entity.*password', 'Password in Room entity', 'High'),
        (r'openOrCreateDatabase\s*\([^)]*null\s*\)', 'Unencrypted database', 'Medium'),
        (r'SQLiteDatabase.*openOrCreateDatabase(?!.*password)', 'Unencrypted SQLite', 'Medium'),
        (r'File\s*\([^)]*getExternalStorage', 'External storage file', 'Medium'),
        (r'getExternalFilesDir.*password', 'Password in external storage', 'High'),
        (r'context\.openFileOutput\s*\([^)]*Context\.MODE_PRIVATE', 'Private file (verify content)', 'Low'),
        (r'\.writeText\s*\([^)]*password', 'Password written to file', 'High'),
    ]
    
    # ============================================================
    # 5. NETWORK SECURITY
    # ============================================================
    NETWORK_SECURITY = [
        (r'TrustManager.*checkServerTrusted\s*\([^)]*\)\s*\{[\s\n]*\}', 'Empty TrustManager', 'Critical'),
        (r'checkServerTrusted.*\{[\s\n]*\}', 'Empty certificate check', 'Critical'),
        (r'HostnameVerifier.*verify.*return\s+true', 'Hostname bypass', 'Critical'),
        (r'HostnameVerifier.*\{.*true.*\}', 'Hostname verifier bypass', 'Critical'),
        (r'SSLSocketFactory\.ALLOW_ALL', 'SSL bypass', 'Critical'),
        (r'setHostnameVerifier\s*\(\s*SSLSocketFactory\.ALLOW_ALL', 'All hostnames allowed', 'Critical'),
        (r'\.sslSocketFactory\s*\(\s*null', 'Null SSL factory', 'Critical'),
        (r'\.hostnameVerifier\s*\(\s*null', 'Null hostname verifier', 'Critical'),
        (r'android:usesCleartextTraffic\s*=\s*"true"', 'Cleartext traffic allowed', 'High'),
        (r'http://', 'Cleartext HTTP URL', 'High'),
        (r'CertificatePinner', 'Certificate pinning (good)', 'Info'),
        (r'\.connectionSpecs.*CLEARTEXT', 'Cleartext connection', 'High'),
        (r'OkHttpClient.*Builder\(\)(?!.*certificatePinner)', 'OkHttp without pinning', 'Medium'),
        (r'Retrofit\.Builder.*baseUrl.*http://', 'Retrofit HTTP base', 'High'),
    ]
    
    # ============================================================
    # 6. WEBVIEW SECURITY
    # ============================================================
    WEBVIEW_SECURITY = [
        (r'setJavaScriptEnabled\s*\(\s*true', 'JavaScript enabled', 'Medium'),
        (r'addJavascriptInterface\s*\(', 'JS interface exposed', 'High'),
        (r'setAllowFileAccess\s*\(\s*true', 'File access enabled', 'High'),
        (r'setAllowUniversalAccessFromFileURLs\s*\(\s*true', 'Universal file access', 'Critical'),
        (r'setAllowFileAccessFromFileURLs\s*\(\s*true', 'File URL access', 'High'),
        (r'setAllowContentAccess\s*\(\s*true', 'Content access enabled', 'Medium'),
        (r'setSavePassword\s*\(\s*true', 'Save password enabled', 'High'),
        (r'setMixedContentMode.*MIXED_CONTENT_ALWAYS_ALLOW', 'Mixed content allowed', 'High'),
        (r'loadUrl\s*\([^)]*\$', 'loadUrl interpolation', 'High'),
        (r'loadData\s*\([^)]*\$', 'loadData interpolation', 'High'),
        (r'evaluateJavascript\s*\([^)]*\$', 'evaluateJavascript interpolation', 'Critical'),
        (r'WebViewClient.*onReceivedSslError.*proceed', 'SSL error ignored', 'Critical'),
        (r'WebView.*settings\.domStorageEnabled\s*=\s*true', 'DOM storage enabled', 'Low'),
    ]
    
    # ============================================================
    # 7. CRYPTOGRAPHIC ISSUES
    # ============================================================
    CRYPTO = [
        (r'Cipher\.getInstance\s*\(\s*"DES"', 'DES encryption', 'Critical'),
        (r'Cipher\.getInstance\s*\(\s*"DESede"', '3DES encryption', 'High'),
        (r'Cipher\.getInstance\s*\(\s*"RC2"', 'RC2 encryption', 'Critical'),
        (r'Cipher\.getInstance\s*\(\s*"RC4"', 'RC4 encryption', 'Critical'),
        (r'Cipher\.getInstance\s*\(\s*"AES"\s*\)', 'AES default ECB', 'High'),
        (r'Cipher\.getInstance\s*\(\s*"[^"]*ECB[^"]*"', 'ECB mode', 'High'),
        (r'MessageDigest\.getInstance\s*\(\s*"MD5"', 'MD5 hash', 'Medium'),
        (r'MessageDigest\.getInstance\s*\(\s*"SHA-?1"', 'SHA1 hash', 'Medium'),
        (r'SecretKeySpec\s*\(.*".*".*\.toByteArray', 'Hardcoded key', 'Critical'),
        (r'IvParameterSpec\s*\(.*".*".*\.toByteArray', 'Hardcoded IV', 'High'),
        (r'Random\s*\(\s*\)', 'Insecure Random', 'High'),
        (r'kotlin\.random\.Random', 'kotlin.random (not crypto)', 'High'),
        (r'Math\.random\s*\(\s*\)', 'Math.random', 'High'),
        (r'SecureRandom\s*\(\s*\d+', 'Seeded SecureRandom', 'High'),
        (r'\.setSeed\s*\(\s*\d+', 'Static seed', 'High'),
        (r'KeyGenerator.*init\s*\(\s*\d{1,2}\s*\)', 'Small key size', 'High'),
    ]
    
    # ============================================================
    # 8. AUTHENTICATION ISSUES
    # ============================================================
    AUTH = [
        (r'\.equals\s*\(\s*password', 'Password equals()', 'High'),
        (r'password\s*==\s*"', 'Hardcoded password check', 'Critical'),
        (r'BiometricPrompt.*setDeviceCredentialAllowed.*false', 'Biometric only', 'Low'),
        (r'BiometricPrompt.*setNegativeButtonText\s*\(\s*""', 'Empty negative button', 'Medium'),
        (r'KeychainManager.*password', 'Password in Keychain', 'Medium'),
        (r'AccountManager.*getPassword', 'AccountManager password', 'Medium'),
        (r'KeyStore.*getKey\s*\([^)]*null\s*\)', 'Null key protection', 'High'),
        (r'setUserAuthenticationRequired\s*\(\s*false', 'No user auth required', 'Medium'),
    ]
    
    # ============================================================
    # 9. HARDCODED SECRETS
    # ============================================================
    SECRETS = [
        (r'val\s+\w*[pP]assword\w*\s*=\s*"(?!["\s])[^"]{8,}"', 'Hardcoded password'),
        (r'val\s+\w*[aA]pi[Kk]ey\w*\s*=\s*"[A-Za-z0-9_\-]{20,}"', 'Hardcoded API key'),
        (r'val\s+\w*[sS]ecret\w*\s*=\s*"[^"]{16,}"', 'Hardcoded secret'),
        (r'val\s+\w*[tT]oken\w*\s*=\s*"[^"]{20,}"', 'Hardcoded token'),
        (r'-----BEGIN\s+(?:RSA\s+)?PRIVATE\s+KEY-----', 'Embedded private key'),
        (r'AIza[0-9A-Za-z\-_]{35}', 'Google API key'),
        (r'sk_live_[0-9a-zA-Z]{24}', 'Stripe live key'),
        (r'AKIA[0-9A-Z]{16}', 'AWS access key'),
        (r'ghp_[A-Za-z0-9]{36}', 'GitHub token'),
        (r'firebase.*"[A-Za-z0-9\-_]{30,}"', 'Firebase key'),
        (r'"mongodb://[^:]+:[^@]+@', 'MongoDB credentials'),
    ]
    
    # ============================================================
    # 10. LOGGING SENSITIVE DATA
    # ============================================================
    LOGGING = [
        (r'Log\.[dievw]\s*\([^)]*password', 'Password logged', 'High'),
        (r'Log\.[dievw]\s*\([^)]*token', 'Token logged', 'High'),
        (r'Log\.[dievw]\s*\([^)]*secret', 'Secret logged', 'High'),
        (r'Log\.[dievw]\s*\([^)]*key', 'Key logged', 'Medium'),
        (r'Log\.[dievw]\s*\([^)]*credential', 'Credential logged', 'High'),
        (r'println\s*\([^)]*password', 'Password printed', 'High'),
        (r'Timber\.\w+\s*\([^)]*password', 'Password in Timber', 'High'),
        (r'Log\.wtf', 'Log.wtf (what a terrible failure)', 'Low'),
        (r'Crashlytics.*password', 'Password in Crashlytics', 'High'),
        (r'FirebaseAnalytics.*password', 'Password in Analytics', 'High'),
    ]
    
    # ============================================================
    # 11. EXPORTED COMPONENTS
    # ============================================================
    COMPONENTS = [
        (r'android:exported\s*=\s*"true"', 'Exported component', 'Medium'),
        (r'android:permission\s*=\s*""', 'Empty permission', 'High'),
        (r'registerReceiver\s*\([^)]*null', 'Receiver no permission', 'Medium'),
        (r'sendBroadcast\s*\([^)]*\)(?!.*permission)', 'Broadcast no permission', 'Medium'),
        (r'PendingIntent\.get\w+\s*\([^)]*0\s*\)', 'Mutable PendingIntent', 'High'),
        (r'PendingIntent\.get\w+\s*\([^)]*FLAG_MUTABLE', 'Mutable PendingIntent flag', 'High'),
        (r'taskAffinity\s*=\s*""', 'Empty task affinity', 'Medium'),
        (r'android:launchMode\s*=\s*"singleTask"', 'SingleTask (task hijacking)', 'Low'),
    ]
    
    # ============================================================
    # 12. DEEP LINK SECURITY
    # ============================================================
    DEEP_LINK = [
        (r'intent\.data\?\.', 'Deep link data access', 'Medium'),
        (r'intent\.getStringExtra\s*\([^)]*url', 'URL from intent', 'High'),
        (r'intent\.data\?\.getQueryParameter', 'Query param from deep link', 'High'),
        (r'NavDeepLinkBuilder', 'Nav deep link', 'Low'),
        (r'AppLinks', 'App links', 'Low'),
        (r'handleDeepLink', 'Deep link handler', 'Medium'),
        (r'<data\s+android:scheme', 'Custom scheme', 'Low'),
        (r'android:autoVerify\s*=\s*"false"', 'Auto-verify disabled', 'Medium'),
    ]
    
    # ============================================================
    # 13. JETPACK COMPOSE SECURITY
    # ============================================================
    COMPOSE = [
        (r'remember\s*\{.*password', 'Password in remember', 'High'),
        (r'rememberSaveable\s*\{.*password', 'Password in saveable', 'High'),
        (r'@State.*password', 'Password in State', 'Medium'),
        (r'mutableStateOf.*password', 'Password in mutableState', 'High'),
        (r'ViewModel.*password.*LiveData', 'Password in LiveData', 'Medium'),
        (r'SharedFlow.*password', 'Password in SharedFlow', 'Medium'),
        (r'StateFlow.*password', 'Password in StateFlow', 'Medium'),
        (r'TextField.*value.*password(?!.*visualTransformation)', 'Password without mask', 'Medium'),
        (r'BasicTextField.*password', 'BasicTextField password', 'Medium'),
    ]
    
    # ============================================================
    # 14. NULL SAFETY ISSUES
    # ============================================================
    NULL_SAFETY = [
        (r'!!\s*\.', 'Non-null assertion', 'Low'),
        (r'as\s+\w+(?!\?)', 'Unsafe cast', 'Low'),
        (r'lateinit\s+var', 'lateinit variable', 'Low'),
        (r'\.getOrNull\s*\(\s*\)!!', 'getOrNull with !!', 'Medium'),
        (r'\.firstOrNull\s*\(\s*\)!!', 'firstOrNull with !!', 'Medium'),
        (r'\?\.\w+!!', 'Safe call then !!', 'Medium'),
        (r'intent\.extras!!', 'Extras !!', 'Medium'),
        (r'intent\.getStringExtra.*!!', 'getStringExtra !!', 'Medium'),
    ]
    
    # ============================================================
    # 15. COROUTINE SAFETY
    # ============================================================
    COROUTINE = [
        (r'GlobalScope\.launch', 'GlobalScope usage', 'Medium'),
        (r'GlobalScope\.async', 'GlobalScope async', 'Medium'),
        (r'runBlocking\s*\{', 'runBlocking (may block)', 'Low'),
        (r'Dispatchers\.IO(?!.*withContext)', 'IO without withContext', 'Low'),
        (r'launch\s*\{(?!.*try)', 'launch without error handling', 'Low'),
        (r'async\s*\{(?!.*try)', 'async without error handling', 'Low'),
        (r'SupervisorJob\s*\(\s*\)(?!.*CoroutineExceptionHandler)', 'Supervisor without handler', 'Low'),
    ]
    
    # ============================================================
    # 16. RESOURCE LEAKS
    # ============================================================
    RESOURCE_LEAKS = [
        (r'FileInputStream\s*\([^)]*\)(?!.*use\s*\{)', 'FileInputStream leak', 'Medium'),
        (r'FileOutputStream\s*\([^)]*\)(?!.*use\s*\{)', 'FileOutputStream leak', 'Medium'),
        (r'Cursor(?!.*use)', 'Cursor without use', 'Medium'),
        (r'SQLiteDatabase\.openDatabase(?!.*use)', 'DB without use', 'Medium'),
        (r'ContentResolver.*query(?!.*use)', 'ContentResolver leak', 'Medium'),
        (r'HttpURLConnection(?!.*disconnect)', 'URLConnection leak', 'Low'),
        (r'Socket\s*\((?!.*use)', 'Socket without use', 'Medium'),
        (r'BroadcastReceiver(?!.*unregister)', 'Receiver not unregistered', 'Low'),
        (r'registerReceiver(?!.*unregister)', 'Receiver not unregistered', 'Low'),
    ]
    
    # ============================================================
    # 17. INFORMATION DISCLOSURE
    # ============================================================
    INFO_DISCLOSURE = [
        (r'\.printStackTrace\s*\(\s*\)', 'Stack trace printed', 'Medium'),
        (r'android:debuggable\s*=\s*"true"', 'Debuggable app', 'High'),
        (r'android:allowBackup\s*=\s*"true"', 'Backup enabled', 'Medium'),
        (r'Toast\.makeText\s*\([^)]*exception', 'Exception in Toast', 'Medium'),
        (r'Toast\.makeText\s*\([^)]*error', 'Error in Toast', 'Low'),
        (r'BuildConfig\.DEBUG.*if', 'Debug check', 'Low'),
        (r'StrictMode\.setThreadPolicy', 'StrictMode usage', 'Info'),
    ]
    
    # ============================================================
    # 18. INSECURE RANDOM
    # ============================================================
    INSECURE_RANDOM = [
        (r'Random\s*\(\s*\)', 'java.util.Random', 'High'),
        (r'kotlin\.random\.Random\.Default', 'kotlin Random.Default', 'High'),
        (r'Random\.nextInt', 'Random.nextInt', 'Medium'),
        (r'Random\.nextLong', 'Random.nextLong', 'Medium'),
        (r'Math\.random', 'Math.random', 'High'),
        (r'ThreadLocalRandom', 'ThreadLocalRandom (not crypto)', 'Medium'),
    ]
    
    # ============================================================
    # 19. PATH TRAVERSAL
    # ============================================================
    PATH_TRAVERSAL = [
        (r'File\s*\([^)]*\$', 'File with interpolation', 'High'),
        (r'FileInputStream\s*\([^)]*\$', 'FileInputStream interpolation', 'High'),
        (r'FileOutputStream\s*\([^)]*\$', 'FileOutputStream interpolation', 'High'),
        (r'openFileInput\s*\([^)]*\$', 'openFileInput interpolation', 'High'),
        (r'openFileOutput\s*\([^)]*\$', 'openFileOutput interpolation', 'High'),
        (r'getAssets\(\)\.open\s*\([^)]*\$', 'Asset open interpolation', 'Medium'),
        (r'ZipEntry.*\$', 'ZipEntry with interpolation', 'High'),
    ]
    
    # ============================================================
    # 20. CLIPBOARD SECURITY
    # ============================================================
    CLIPBOARD = [
        (r'ClipboardManager.*setPrimaryClip.*password', 'Password to clipboard', 'High'),
        (r'ClipboardManager.*setPrimaryClip.*token', 'Token to clipboard', 'High'),
        (r'ClipboardManager.*setPrimaryClip.*secret', 'Secret to clipboard', 'High'),
        (r'ClipData\.newPlainText.*password', 'Password ClipData', 'High'),
        (r'getPrimaryClip\s*\(\s*\)', 'Reading clipboard', 'Low'),
    ]
    
    # ============================================================
    # 21. BACKUP SECURITY
    # ============================================================
    BACKUP = [
        (r'android:allowBackup\s*=\s*"true"', 'Backup enabled', 'Medium'),
        (r'android:fullBackupContent\s*=\s*"true"', 'Full backup enabled', 'Medium'),
        (r'android:dataExtractionRules', 'Data extraction rules', 'Low'),
        (r'BackupAgentHelper', 'Backup agent', 'Low'),
        (r'onBackup\s*\(', 'onBackup method', 'Low'),
    ]
    
    # ============================================================
    # 22. TAPJACKING
    # ============================================================
    TAPJACKING = [
        (r'setFilterTouchesWhenObscured\s*\(\s*false', 'Touch filter disabled', 'High'),
        (r'android:filterTouchesWhenObscured\s*=\s*"false"', 'Touch filter disabled', 'High'),
        (r'FLAG_WINDOW_IS_OBSCURED', 'Obscured flag check', 'Info'),
        (r'onFilterTouchEventForSecurity', 'Touch filter override', 'Low'),
    ]
    
    # ============================================================
    # 23. CONTENT PROVIDER SECURITY
    # ============================================================
    CONTENT_PROVIDER = [
        (r'android:grantUriPermissions\s*=\s*"true"', 'Grant URI permissions', 'Medium'),
        (r'android:readPermission\s*=\s*""', 'Empty read permission', 'High'),
        (r'android:writePermission\s*=\s*""', 'Empty write permission', 'High'),
        (r'openFile\s*\([^)]*\$', 'openFile interpolation', 'High'),
        (r'query\s*\([^)]*\$', 'Provider query interpolation', 'High'),
    ]
    
    # ============================================================
    # 24. ROOTING/EMULATOR DETECTION
    # ============================================================
    ROOT_DETECTION = [
        (r'RootBeer', 'RootBeer (check)', 'Info'),
        (r'isDeviceRooted', 'Root detection', 'Info'),
        (r'isEmulator', 'Emulator detection', 'Info'),
        (r'Build\.FINGERPRINT.*generic', 'Emulator fingerprint', 'Info'),
        (r'Build\.BRAND.*generic', 'Emulator brand', 'Info'),
        (r'checkForSuBinary', 'SU binary check', 'Info'),
    ]
    
    # ============================================================
    # 25. MISCONFIGURATION
    # ============================================================
    MISCONFIG = [
        (r'android:testOnly\s*=\s*"true"', 'Test only enabled', 'High'),
        (r'android:process\s*=\s*":"', 'Private process', 'Low'),
        (r'ProGuard', 'ProGuard usage', 'Info'),
        (r'minifyEnabled\s*=\s*false', 'Minification disabled', 'Low'),
        (r'shrinkResources\s*=\s*false', 'Shrink resources disabled', 'Low'),
        (r'debuggable\s*true', 'Debuggable true', 'High'),
    ]
    
    # ============================================================
    # 26. WORKMANAGER SECURITY
    # ============================================================
    WORKMANAGER = [
        (r'OneTimeWorkRequest.*password', 'Password in WorkRequest', 'High'),
        (r'PeriodicWorkRequest.*password', 'Password in PeriodicWork', 'High'),
        (r'Data\.Builder.*putString.*password', 'Password in Work Data', 'High'),
        (r'inputData\[.*password', 'Password in inputData', 'High'),
        (r'WorkManager.*enqueue.*Constraints.*networkType.*UNMETERED', 'Work on WiFi only', 'Info'),
    ]
    
    # ============================================================
    # 27. FIREBASE SECURITY
    # ============================================================
    FIREBASE = [
        (r'FirebaseDatabase.*getReference.*password', 'Password in Firebase ref', 'High'),
        (r'setValue.*password', 'Password to Firebase', 'High'),
        (r'FirebaseFirestore.*password', 'Password in Firestore', 'High'),
        (r'FirebaseAuth.*signInWithEmailAndPassword', 'Email/password auth', 'Low'),
        (r'RemoteConfig.*password', 'Password in RemoteConfig', 'Critical'),
        (r'FirebaseMessaging.*token.*log', 'FCM token logged', 'Medium'),
        (r'google-services\.json', 'Firebase config file', 'Info'),
    ]
    
    # ============================================================
    # 28. PLAY INTEGRITY API
    # ============================================================
    PLAY_INTEGRITY = [
        (r'IntegrityManager', 'Play Integrity API', 'Info'),
        (r'IntegrityTokenRequest', 'Integrity token request', 'Info'),
        (r'SafetyNet\.getClient', 'SafetyNet API (deprecated)', 'Medium'),
        (r'AttestationResponse', 'Attestation response', 'Info'),
        (r'nonce.*static', 'Static nonce (replay attack)', 'High'),
    ]
    
    # ============================================================
    # 29. SCOPED STORAGE
    # ============================================================
    SCOPED_STORAGE = [
        (r'MANAGE_EXTERNAL_STORAGE', 'All files access permission', 'High'),
        (r'requestLegacyExternalStorage\s*=\s*true', 'Legacy storage', 'Medium'),
        (r'getExternalStorageDirectory', 'Legacy external storage', 'Medium'),
        (r'MediaStore.*IS_PENDING', 'Pending media files', 'Low'),
        (r'ContentResolver.*openOutputStream', 'SAF output stream', 'Low'),
    ]
    
    # ============================================================
    # 30. NOTIFICATION SECURITY
    # ============================================================
    NOTIFICATIONS = [
        (r'NotificationCompat.*setContentText.*password', 'Password in notification', 'High'),
        (r'NotificationChannel.*IMPORTANCE_HIGH.*password', 'Password in heads-up', 'Critical'),
        (r'setVisibility.*VISIBILITY_PUBLIC.*password', 'Password visible on lock', 'Critical'),
        (r'setShowWhen.*timestamp.*password', 'Timestamp with password', 'Medium'),
        (r'MessagingStyle.*password', 'Password in message notification', 'High'),
    ]
    
    # ============================================================
    # 31. BIOMETRIC LIBRARY
    # ============================================================
    BIOMETRIC_LIB = [
        (r'BiometricPrompt\.PromptInfo.*setDeviceCredentialAllowed', 'Device credential fallback', 'Low'),
        (r'BiometricManager\.BIOMETRIC_STRONG', 'Strong biometric requirement', 'Info'),
        (r'setAllowedAuthenticators.*DEVICE_CREDENTIAL', 'Device credential allowed', 'Low'),
        (r'KeyGenParameterSpec.*setUserAuthenticationRequired', 'Key requires auth', 'Info'),
        (r'setUserAuthenticationValidityDurationSeconds.*-1', 'Infinite auth validity', 'High'),
    ]
    
    # ============================================================
    # 32. ANDROID KEYSTORE
    # ============================================================
    KEYSTORE = [
        (r'KeyStore\.getInstance.*"AndroidKeyStore"', 'Android Keystore usage', 'Info'),
        (r'setUserAuthenticationRequired\s*\(\s*false', 'No user auth for key', 'Medium'),
        (r'setUnlockedDeviceRequired\s*\(\s*false', 'Locked device key access', 'Medium'),
        (r'setInvalidatedByBiometricEnrollment\s*\(\s*false', 'Biometric not invalidating', 'Low'),
        (r'setRandomizedEncryptionRequired\s*\(\s*false', 'Deterministic encryption', 'High'),
        (r'setIsStrongBoxBacked', 'StrongBox backed key', 'Info'),
    ]
    
    # ============================================================
    # 33. ROOM / SQLCIPHER
    # ============================================================
    ROOM_DB = [
        (r'Room\.databaseBuilder(?!.*SupportFactory)', 'Room without encryption', 'Medium'),
        (r'RoomDatabase.*fallbackToDestructiveMigration', 'Destructive migration', 'Low'),
        (r'SupportFactory.*password.*String', 'SQLCipher with hardcoded key', 'High'),
        (r'@Query.*\$\{', 'Query with interpolation', 'Critical'),
        (r'allowMainThreadQueries', 'Main thread queries allowed', 'Low'),
    ]
    
    # ============================================================
    # 34. NAVIGATION SECURITY
    # ============================================================
    NAVIGATION = [
        (r'NavDeepLinkBuilder(?!.*validate)', 'Deep link without validation', 'High'),
        (r'findNavController.*navigate.*Bundle', 'Nav with bundle', 'Low'),
        (r'popBackStack.*inclusive.*true', 'Inclusive pop back', 'Low'),
        (r'navArgs.*password', 'Password in nav args', 'High'),
        (r'SavedStateHandle.*password', 'Password in SavedState', 'High'),
    ]
    
    # ============================================================
    # 35. ENCRYPTED SHARED PREFERENCES
    # ============================================================
    ENCRYPTED_PREFS = [
        (r'EncryptedSharedPreferences', 'Encrypted prefs usage', 'Info'),
        (r'MasterKey.*AES256_GCM', 'MasterKey with AES256', 'Info'),
        (r'MasterKey.*userAuthenticationRequired', 'MasterKey with auth', 'Info'),
        (r'EncryptedFile', 'Encrypted file usage', 'Info'),
        (r'MasterKeys\.getOrCreate\s*\(\s*MasterKeys\.AES256_GCM_SPEC', 'Legacy MasterKeys', 'Low'),
    ]
    
    def __init__(self):
        self.issues: List[KotlinVuln] = []
    
    def scan(self, code: str, filename: str = "") -> List[Dict]:
        self.issues = []
        lines = code.split('\n')
        
        # Run all checks
        self._check(lines, self.SQL_INJECTION, 'sql_injection', 'SQL Injection', 'CWE-89')
        self._check(lines, self.COMMAND_INJECTION, 'command_injection', 'Command Injection', 'CWE-78')
        self._check(lines, self.INTENT_INJECTION, 'intent_injection', 'Intent Injection', 'CWE-926')
        self._check(lines, self.DATA_STORAGE, 'insecure_storage', 'Insecure Data Storage', 'CWE-312')
        self._check(lines, self.NETWORK_SECURITY, 'insecure_network', 'Insecure Network', 'CWE-295')
        self._check(lines, self.WEBVIEW_SECURITY, 'webview_security', 'WebView Security', 'CWE-749')
        self._check(lines, self.CRYPTO, 'weak_crypto', 'Weak Cryptography', 'CWE-327')
        self._check(lines, self.AUTH, 'auth_issue', 'Authentication Issue', 'CWE-287')
        self._check(lines, self.LOGGING, 'info_disclosure', 'Information Disclosure', 'CWE-532')
        self._check(lines, self.COMPONENTS, 'component_security', 'Component Security', 'CWE-926')
        self._check(lines, self.DEEP_LINK, 'deep_link', 'Deep Link Security', 'CWE-939')
        self._check(lines, self.COMPOSE, 'compose_security', 'Jetpack Compose Security', 'CWE-312')
        self._check(lines, self.NULL_SAFETY, 'null_safety', 'Null Safety', 'CWE-476')
        self._check(lines, self.COROUTINE, 'coroutine_safety', 'Coroutine Safety', 'CWE-362')
        self._check(lines, self.RESOURCE_LEAKS, 'resource_leak', 'Resource Leak', 'CWE-404')
        self._check(lines, self.INFO_DISCLOSURE, 'info_disclosure', 'Information Disclosure', 'CWE-200')
        self._check(lines, self.INSECURE_RANDOM, 'insecure_random', 'Insecure Randomness', 'CWE-338')
        self._check(lines, self.PATH_TRAVERSAL, 'path_traversal', 'Path Traversal', 'CWE-22')
        self._check(lines, self.CLIPBOARD, 'clipboard_security', 'Clipboard Security', 'CWE-200')
        self._check(lines, self.BACKUP, 'backup_security', 'Backup Security', 'CWE-530')
        self._check(lines, self.TAPJACKING, 'tapjacking', 'Tapjacking', 'CWE-1021')
        self._check(lines, self.CONTENT_PROVIDER, 'content_provider', 'Content Provider Security', 'CWE-926')
        self._check(lines, self.MISCONFIG, 'misconfiguration', 'Security Misconfiguration', 'CWE-16')
        # New advanced Android rules
        self._check(lines, self.WORKMANAGER, 'workmanager_security', 'WorkManager Security', 'CWE-312')
        self._check(lines, self.FIREBASE, 'firebase_security', 'Firebase Security', 'CWE-312')
        self._check(lines, self.PLAY_INTEGRITY, 'play_integrity', 'Play Integrity API', 'CWE-347')
        self._check(lines, self.SCOPED_STORAGE, 'scoped_storage', 'Scoped Storage Security', 'CWE-276')
        self._check(lines, self.NOTIFICATIONS, 'notification_security', 'Notification Security', 'CWE-312')
        self._check(lines, self.BIOMETRIC_LIB, 'biometric_security', 'Biometric Security', 'CWE-287')
        self._check(lines, self.KEYSTORE, 'keystore_security', 'Android Keystore Security', 'CWE-321')
        self._check(lines, self.ROOM_DB, 'room_security', 'Room Database Security', 'CWE-89')
        self._check(lines, self.NAVIGATION, 'navigation_security', 'Navigation Security', 'CWE-601')
        self._check(lines, self.ENCRYPTED_PREFS, 'encrypted_prefs', 'Encrypted Preferences', 'CWE-311')
        self._check_secrets(lines)
        
        return [self._to_dict(v, filename) for v in self.issues]
    
    def _check(self, lines: List[str], patterns: list, vuln_type: str, desc: str, cwe: str):
        for i, line in enumerate(lines):
            for pattern, msg, severity in patterns:
                if severity == 'Info':
                    continue
                if re.search(pattern, line, re.IGNORECASE):
                    self.issues.append(KotlinVuln(
                        vuln_type=vuln_type,
                        category=KotlinVulnCategory.CODE_QUALITY.value,
                        severity=severity,
                        line=i+1,
                        snippet=line.strip()[:120],
                        description=f"{desc}: {msg}",
                        remediation=self._get_remediation(vuln_type),
                        cwe_id=cwe,
                        owasp=KotlinVulnCategory.CODE_QUALITY.value,
                        confidence=0.85
                    ))
    
    def _check_secrets(self, lines: List[str]):
        for i, line in enumerate(lines):
            if re.search(r'(test|example|placeholder)', line, re.IGNORECASE):
                continue
            for pattern, msg in self.SECRETS:
                if re.search(pattern, line, re.IGNORECASE):
                    self.issues.append(KotlinVuln(
                        vuln_type='hardcoded_secret',
                        category=KotlinVulnCategory.CRYPTO.value,
                        severity='High',
                        line=i+1,
                        snippet=re.sub(r'"[^"]{4}([^"]*)"', r'"****\1"', line.strip()[:100]),
                        description=f"Hardcoded Secret: {msg}",
                        remediation='Use EncryptedSharedPreferences or Android Keystore.',
                        cwe_id='CWE-798',
                        owasp=KotlinVulnCategory.CRYPTO.value
                    ))
    
    def _get_remediation(self, vuln_type: str) -> str:
        return {
            'sql_injection': 'Use Room DAOs with parameterized queries.',
            'command_injection': 'Avoid exec(). Validate all input.',
            'intent_injection': 'Validate intent data. Use explicit intents.',
            'insecure_storage': 'Use EncryptedSharedPreferences or Keystore.',
            'insecure_network': 'Implement certificate pinning. Use HTTPS.',
            'webview_security': 'Disable JS when not needed. Validate URLs.',
            'weak_crypto': 'Use AES-256-GCM. Use SecureRandom.',
            'auth_issue': 'Use BiometricManager. Secure key storage.',
            'component_security': 'Set exported=false. Add permissions.',
            'deep_link': 'Validate deep link parameters.',
            'compose_security': 'Avoid passwords in state. Use encryptedPrefs.',
            'null_safety': 'Use safe calls (?.) instead of !!.',
            'coroutine_safety': 'Use viewModelScope. Handle exceptions.',
            'resource_leak': 'Use .use {} or try-with-resources.',
            'path_traversal': 'Validate paths. Use canonical paths.',
            'clipboard_security': 'Never copy secrets to clipboard.',
            'tapjacking': 'Set filterTouchesWhenObscured=true.',
            'content_provider': 'Add read/write permissions.',
        }.get(vuln_type, 'Review and fix security issue.')
    
    def _to_dict(self, v: KotlinVuln, filename: str) -> Dict:
        return {
            'type': v.vuln_type, 'category': v.category, 'severity': v.severity, 'line': v.line,
            'snippet': v.snippet, 'description': v.description, 'remediation': v.remediation,
            'cwe_id': v.cwe_id, 'owasp': v.owasp, 'confidence': v.confidence, 'file': filename,
            'language': 'kotlin', 'scanner': 'kotlin_analyzer_v3'
        }


def scan_kotlin(code: str, filename: str = "") -> List[Dict]:
    return KotlinAnalyzer().scan(code, filename)
