"""
Swift/iOS Security Analyzer - Enterprise Edition

25+ Vulnerability Classes with Deep Detection:
- Injection (SQL, Command, XSS, URL Scheme)
- Insecure Data Storage (Keychain, UserDefaults, CoreData)
- Network Security (ATS, SSL/TLS, Certificate Pinning)
- Cryptographic Failures
- Memory Safety (Force Unwrap, Type Casting)
- Authentication & Biometrics
- Information Disclosure
- SwiftUI Security
- iOS SDK Security
- WebView Security
"""

import re
from typing import List, Dict
from dataclasses import dataclass
from enum import Enum


class iOSVulnCategory(Enum):
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
class SwiftVuln:
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


class SwiftAnalyzer:
    """Enterprise Swift/iOS Security Analyzer with 25+ vulnerability classes"""
    
    # ============================================================
    # 1. SQL INJECTION
    # ============================================================
    SQL_INJECTION = [
        (r'sqlite3_exec\s*\([^)]*\+', 'sqlite3_exec interpolation', 'Critical'),
        (r'sqlite3_prepare\s*\([^)]*\+', 'sqlite3_prepare interpolation', 'Critical'),
        (r'\.execute\s*\([^)]*\+', 'Execute interpolation', 'High'),
        (r'GRDB.*execute\s*\([^)]*\+', 'GRDB execute concat', 'High'),
        (r'raw\s*\([^)]*\+', 'Raw SQL interpolation', 'High'),
        (r'prepareStatement\s*\([^)]*\+', 'PrepareStatement interpolation', 'High'),
        (r'FMDatabase.*executeUpdate.*\+', 'FMDB interpolation', 'High'),
        (r'FMDatabase.*executeQuery.*\+', 'FMDB query interpolation', 'High'),
    ]

    
    # ============================================================
    # 2. COMMAND INJECTION
    # ============================================================
    COMMAND_INJECTION = [
        (r'Process\(\).*arguments.*+', 'Process interpolation', 'Critical'),
        (r'NSTask.*arguments.*+', 'NSTask interpolation', 'Critical'),
        (r'shell\s*\([^)]*+', 'Shell interpolation', 'Critical'),
        (r'/bin/sh.*-c.*+', 'Shell command interpolation', 'Critical'),
        (r'CommandLine.*arguments.*+', 'CommandLine interpolation', 'High'),
    ]
    
    # ============================================================
    # 3. INSECURE DATA STORAGE
    # ============================================================
    DATA_STORAGE = [
        (r'UserDefaults.*set\s*\([^)]*password', 'Password in UserDefaults', 'High'),
        (r'UserDefaults.*set\s*\([^)]*token', 'Token in UserDefaults', 'High'),
        (r'UserDefaults.*set\s*\([^)]*secret', 'Secret in UserDefaults', 'High'),
        (r'UserDefaults.*set\s*\([^)]*key', 'Key in UserDefaults', 'High'),
        (r'UserDefaults.*set\s*\([^)]*apiKey', 'API Key in UserDefaults', 'High'),
        (r'@AppStorage\s*\([^)]*password', 'Password in @AppStorage', 'High'),
        (r'@AppStorage\s*\([^)]*token', 'Token in @AppStorage', 'High'),
        (r'@AppStorage\s*\([^)]*secret', 'Secret in @AppStorage', 'High'),
        (r'@SceneStorage\s*\([^)]*password', 'Password in @SceneStorage', 'High'),
        (r'NSFileProtection.*none', 'No file protection', 'High'),
        (r'NSFileProtectionNone', 'No file protection', 'High'),
        (r'write\s*\(toFile:.*atomically.*password', 'Password to file', 'High'),
        (r'NSCoder.*encode.*password', 'Password encoded', 'High'),
        (r'CoreData.*password', 'Password in CoreData', 'High'),
        (r'Realm.*password', 'Password in Realm', 'High'),
    ]
    
    # ============================================================
    # 4. KEYCHAIN SECURITY
    # ============================================================
    KEYCHAIN = [
        (r'kSecAttrAccessible.*kSecAttrAccessibleAlways(?!ThisDeviceOnly)', 'Keychain always accessible', 'High'),
        (r'kSecAttrAccessible.*kSecAttrAccessibleAfterFirstUnlock(?!ThisDeviceOnly)', 'Keychain after unlock', 'Medium'),
        (r'kSecAttrSynchronizable.*true', 'Keychain sync enabled', 'Medium'),
        (r'SecItemAdd.*kSecClassGenericPassword', 'Keychain generic password', 'Low'),
        (r'SecItemAdd.*password.*kSecAttrAccessibleWhenUnlocked(?!ThisDeviceOnly)', 'Password accessible', 'Medium'),
        (r'KeychainAccess', 'KeychainAccess usage', 'Info'),
    ]
    
    # ============================================================
    # 5. NETWORK SECURITY
    # ============================================================
    NETWORK_SECURITY = [
        (r'NSAllowsArbitraryLoads.*true', 'ATS disabled', 'Critical'),
        (r'NSExceptionAllowsInsecureHTTPLoads.*true', 'Insecure HTTP allowed', 'High'),
        (r'NSTemporaryExceptionAllowsInsecureHTTPLoads.*true', 'Temp insecure HTTP', 'High'),
        (r'http://', 'Cleartext HTTP URL', 'High'),
        (r'URLSession.*didReceive.*challenge.*completionHandler\s*\([^)]*\.useCredential', 'Custom SSL handling', 'Medium'),
        (r'SecTrustEvaluate.*passing.*true', 'Trust always passing', 'Critical'),
        (r'ServerTrustPolicy.*disableEvaluation', 'SSL evaluation disabled', 'Critical'),
        (r'\.serverTrustManager\s*=\s*nil', 'Nil trust manager', 'Critical'),
        (r'Alamofire.*ServerTrustPolicy.*none', 'Alamofire no trust', 'Critical'),
        (r'trustsAllCertificates', 'Trusts all certificates', 'Critical'),
        (r'validateCertificates.*false', 'Certificate validation off', 'Critical'),
        (r'certificatePinning', 'Certificate pinning (good)', 'Info'),
        (r'NSPinnedDomains', 'Pinned domains (good)', 'Info'),
    ]
    
    # ============================================================
    # 6. WEBVIEW SECURITY
    # ============================================================
    WEBVIEW = [
        (r'WKWebViewConfiguration\(\)', 'WKWebView config', 'Low'),
        (r'javaScriptEnabled\s*=\s*true', 'JavaScript enabled', 'Medium'),
        (r'javaScriptCanOpenWindowsAutomatically\s*=\s*true', 'JS can open windows', 'Medium'),
        (r'allowsBackForwardNavigationGestures\s*=\s*true', 'Navigation gestures', 'Low'),
        (r'loadFileURL\s*\([^)]*,\s*allowingReadAccessTo', 'File URL loading', 'Medium'),
        (r'addUserScript', 'User script injection', 'Medium'),
        (r'evaluateJavaScript\s*\([^)]*+', 'JS evaluation interpolation', 'Critical'),
        (r'loadHTMLString\s*\([^)]*+', 'HTML string interpolation', 'High'),
        (r'loadRequest\s*\([^)]*+', 'Request interpolation', 'High'),
        (r'WKScriptMessageHandler', 'Script message handler', 'Low'),
        (r'UIWebView', 'Deprecated UIWebView', 'High'),
    ]
    
    # ============================================================
    # 7. CRYPTOGRAPHIC ISSUES
    # ============================================================
    CRYPTO = [
        (r'CC_MD5\s*\(', 'MD5 hashing', 'Medium'),
        (r'CC_SHA1\s*\(', 'SHA1 hashing', 'Medium'),
        (r'Insecure\.MD5', 'CryptoKit MD5', 'Medium'),
        (r'Insecure\.SHA1', 'CryptoKit SHA1', 'Medium'),
        (r'kCCAlgorithmDES', 'DES encryption', 'Critical'),
        (r'kCCAlgorithm3DES', '3DES encryption', 'High'),
        (r'kCCOptionECBMode', 'ECB mode', 'High'),
        (r'CCCrypt.*kCCEncrypt.*kCCModeECB', 'ECB encryption', 'High'),
        (r'let\s+\w*[kK]ey\w*\s*=\s*"[^"]{16,}"', 'Hardcoded key', 'Critical'),
        (r'let\s+iv\s*=\s*"[^"]+"', 'Hardcoded IV', 'High'),
        (r'SymmetricKey\s*\(data:\s*"', 'Hardcoded symmetric key', 'Critical'),
        (r'arc4random\s*\(\s*\)', 'arc4random (weak)', 'Low'),
        (r'drand48\s*\(\s*\)', 'drand48 (weak)', 'High'),
        (r'srand\s*\(', 'srand seeding', 'High'),
        (r'rand\s*\(\s*\)', 'C rand (weak)', 'High'),
        (r'SecKeyGeneratePair.*\d{1,3}[^0-9]', 'Small key size', 'High'),
    ]
    
    # ============================================================
    # 8. AUTHENTICATION
    # ============================================================
    AUTH = [
        (r'LAContext\(\)', 'Local authentication', 'Low'),
        (r'evaluatePolicy.*deviceOwnerAuthentication(?!WithBiometrics)', 'Device auth only', 'Low'),
        (r'localizedFallbackTitle\s*=\s*""', 'Empty fallback', 'Medium'),
        (r'\.isEqual\s*\(.*password', 'Password isEqual', 'High'),
        (r'password\s*==\s*"', 'Hardcoded password check', 'Critical'),
        (r'if\s+password\s*==', 'Password string comparison', 'Medium'),
        (r'let\s+\w*[tT]oken\w*\s*=\s*"[^"]{20,}"', 'Hardcoded token', 'Critical'),
        (r'"Bearer\s+eyJ', 'Hardcoded JWT', 'Critical'),
        (r'canEvaluatePolicy.*biometryNone', 'Biometry check', 'Low'),
    ]
    
    # ============================================================
    # 9. HARDCODED SECRETS
    # ============================================================
    SECRETS = [
        (r'let\s+\w*[pP]assword\w*\s*=\s*"(?!["\s])[^"]{8,}"', 'Hardcoded password'),
        (r'let\s+\w*[aA]pi[Kk]ey\w*\s*=\s*"[A-Za-z0-9_\-]{20,}"', 'Hardcoded API key'),
        (r'let\s+\w*[sS]ecret\w*\s*=\s*"[^"]{16,}"', 'Hardcoded secret'),
        (r'let\s+\w*[tT]oken\w*\s*=\s*"[^"]{20,}"', 'Hardcoded token'),
        (r'-----BEGIN\s+(?:RSA\s+)?PRIVATE\s+KEY-----', 'Embedded private key'),
        (r'AIza[0-9A-Za-z\-_]{35}', 'Google API key'),
        (r'sk_live_[0-9a-zA-Z]{24}', 'Stripe live key'),
        (r'AKIA[0-9A-Z]{16}', 'AWS access key'),
        (r'ghp_[A-Za-z0-9]{36}', 'GitHub token'),
        (r'firebase.*"[A-Za-z0-9\-_]{30,}"', 'Firebase key'),
        (r'xox[baprs]-[0-9]{10,13}-[A-Za-z0-9-]{24}', 'Slack token'),
    ]
    
    # ============================================================
    # 10. LOGGING SENSITIVE DATA
    # ============================================================
    LOGGING = [
        (r'print\s*\([^)]*password', 'Password printed', 'High'),
        (r'print\s*\([^)]*token', 'Token printed', 'High'),
        (r'print\s*\([^)]*secret', 'Secret printed', 'High'),
        (r'NSLog\s*\([^)]*password', 'Password logged', 'High'),
        (r'NSLog\s*\([^)]*token', 'Token logged', 'High'),
        (r'os_log\s*\([^)]*%\{public\}.*password', 'Public password log', 'High'),
        (r'os_log\s*\([^)]*%\{public\}.*token', 'Public token log', 'High'),
        (r'debugPrint\s*\([^)]*password', 'Debug password', 'High'),
        (r'Logger.*password', 'Logger password', 'High'),
    ]
    
    # ============================================================
    # 11. URL SCHEME SECURITY
    # ============================================================
    URL_SCHEME = [
        (r'CFBundleURLSchemes', 'Custom URL scheme', 'Low'),
        (r'application.*open.*url.*options', 'URL handler', 'Medium'),
        (r'handleOpenURL', 'Legacy URL handler', 'Medium'),
        (r'\.host\s*==', 'Host check (verify)', 'Low'),
        (r'\.scheme\s*==', 'Scheme check (verify)', 'Low'),
        (r'UIApplication\.shared\.open\s*\([^)]*+', 'Open URL interpolation', 'High'),
        (r'canOpenURL\s*\([^)]*+', 'canOpenURL interpolation', 'Low'),
    ]
    
    # ============================================================
    # 12. SWIFTUI SECURITY
    # ============================================================
    SWIFTUI = [
        (r'@State\s+(?:private\s+)?var\s+\w*password', 'Password in @State', 'Medium'),
        (r'@State\s+(?:private\s+)?var\s+\w*token', 'Token in @State', 'Medium'),
        (r'@AppStorage\s*\([^)]*(?:password|token|secret)', 'Secret in @AppStorage', 'High'),
        (r'@SceneStorage\s*\([^)]*password', 'Password in @SceneStorage', 'High'),
        (r'\.onOpenURL\s*\{', 'Deep link handler', 'Medium'),
        (r'WKWebView.*@State', 'WebView in SwiftUI', 'Low'),
        (r'SecureField(?!.*\.textContentType)', 'SecureField without type', 'Low'),
        (r'TextField.*password', 'Password in TextField', 'High'),
    ]
    
    # ============================================================
    # 13. MEMORY SAFETY
    # ============================================================
    MEMORY_SAFETY = [
        (r'!\s*\.', 'Force unwrap', 'Low'),
        (r'as!', 'Force cast', 'Low'),
        (r'try!', 'Force try', 'Low'),
        (r'fatalError\s*\(', 'fatalError', 'Low'),
        (r'preconditionFailure', 'preconditionFailure', 'Low'),
        (r'UnsafeMutablePointer', 'Unsafe pointer', 'Medium'),
        (r'UnsafeRawPointer', 'Unsafe raw pointer', 'Medium'),
        (r'UnsafeBufferPointer', 'Unsafe buffer', 'Medium'),
        (r'withUnsafePointer', 'Unsafe pointer', 'Medium'),
        (r'Unmanaged', 'Unmanaged memory', 'Medium'),
    ]
    
    # ============================================================
    # 14. INFORMATION DISCLOSURE
    # ============================================================
    INFO_DISCLOSURE = [
        (r'\.localizedDescription', 'Error description', 'Low'),
        (r'print\s*\(error', 'Error printed', 'Low'),
        (r'#if\s+DEBUG.*print', 'Debug print', 'Low'),
        (r'UIDevice\.current', 'Device info', 'Low'),
        (r'ProcessInfo\.processInfo', 'Process info', 'Low'),
        (r'Bundle\.main\.infoDictionary', 'Bundle info', 'Low'),
        (r'FileManager.*attributesOfItem', 'File attributes', 'Low'),
    ]
    
    # ============================================================
    # 15. JAILBREAK DETECTION
    # ============================================================
    JAILBREAK = [
        (r'canOpenURL.*cydia', 'Jailbreak detection', 'Info'),
        (r'fileExists.*MobileSubstrate', 'Jailbreak detection', 'Info'),
        (r'fileExists.*apt', 'Jailbreak detection', 'Info'),
        (r'fileExists.*/Applications/Cydia', 'Jailbreak detection', 'Info'),
        (r'fileExists.*/bin/bash', 'Jailbreak detection', 'Info'),
        (r'JAILBREAK', 'Jailbreak constant', 'Info'),
        (r'isJailbroken', 'Jailbreak check', 'Info'),
    ]
    
    # ============================================================
    # 16. ANTI-TAMPERING
    # ============================================================
    ANTI_TAMPER = [
        (r'__builtin_trap', 'Anti-debug trap', 'Info'),
        (r'ptrace.*PT_DENY_ATTACH', 'ptrace anti-debug', 'Info'),
        (r'isDebuggerAttached', 'Debugger detection', 'Info'),
        (r'sysctl.*P_TRACED', 'Process traced check', 'Info'),
        (r'getppid\(\)', 'Parent PID check', 'Info'),
    ]
    
    # ============================================================
    # 17. PASTEBOARD SECURITY
    # ============================================================
    PASTEBOARD = [
        (r'UIPasteboard\.general\.string\s*=.*password', 'Password to pasteboard', 'High'),
        (r'UIPasteboard\.general\.string\s*=.*token', 'Token to pasteboard', 'High'),
        (r'UIPasteboard\.general\.string\s*=.*secret', 'Secret to pasteboard', 'High'),
        (r'UIPasteboard.*expiration.*never', 'Pasteboard no expiration', 'Medium'),
        (r'UIPasteboard\.general\.string', 'Reading pasteboard', 'Low'),
    ]
    
    # ============================================================
    # 18. CODE QUALITY
    # ============================================================
    CODE_QUALITY = [
        (r'catch\s*\{[\s\n]*\}', 'Empty catch', 'Low'),
        (r'catch\s*\{[\s\n]*print\s*\(error', 'Error only printed', 'Low'),
        (r'TODO.*(?:security|auth|password|encrypt)', 'Security TODO', 'Medium'),
        (r'FIXME.*(?:security|auth|password|encrypt)', 'Security FIXME', 'Medium'),
        (r'HACK', 'HACK comment', 'Low'),
    ]
    
    # ============================================================
    # 19. RESOURCE LEAKS
    # ============================================================
    RESOURCE_LEAKS = [
        (r'FileHandle\s*\((?!.*closeFile)', 'FileHandle leak', 'Low'),
        (r'InputStream(?!.*close)', 'InputStream leak', 'Low'),
        (r'OutputStream(?!.*close)', 'OutputStream leak', 'Low'),
        (r'URLSession\s*\((?!.*invalidateAndCancel)', 'URLSession leak', 'Low'),
        (r'Timer\.scheduledTimer(?!.*invalidate)', 'Timer not invalidated', 'Low'),
        (r'NotificationCenter\.default\.addObserver(?!.*removeObserver)', 'Observer leak', 'Low'),
    ]
    
    # ============================================================
    # 20. BIOMETRIC AUTHENTICATION
    # ============================================================
    BIOMETRIC = [
        (r'evaluateAccessControl.*kSecAccessControlBiometryAny', 'Any biometry', 'Low'),
        (r'evaluateAccessControl.*kSecAccessControlBiometryCurrentSet', 'Current biometry', 'Info'),
        (r'LAError.*biometryLockout', 'Lockout handling', 'Info'),
        (r'LAError.*biometryNotEnrolled', 'Not enrolled handling', 'Info'),
        (r'LAPolicy.*deviceOwnerAuthenticationWithBiometrics', 'Biometric only', 'Low'),
    ]
    
    # ============================================================
    # 21. INTER-APP COMMUNICATION
    # ============================================================
    IPC = [
        (r'UIPasteboard.*name', 'Named pasteboard', 'Low'),
        (r'NSExtensionContext', 'Extension context', 'Low'),
        (r'sharedContainerIdentifier', 'Shared container', 'Low'),
        (r'appGroupIdentifier', 'App group', 'Low'),
        (r'UserDefaults\s*\(\s*suiteName', 'Suite UserDefaults', 'Low'),
        (r'openURL\s*\([^)]*+', 'openURL interpolation', 'High'),
    ]
    
    # ============================================================
    # 22. NETWORK CONFIGURATION
    # ============================================================
    NETWORK_CONFIG = [
        (r'NSAllowsLocalNetworking.*true', 'Local networking', 'Low'),
        (r'NSExceptionDomains', 'Exception domains', 'Low'),
        (r'NSExceptionMinimumTLSVersion.*1\.[01]', 'Old TLS version', 'High'),
        (r'NSExceptionRequiresForwardSecrecy.*false', 'No forward secrecy', 'Medium'),
        (r'NSIncludesSubdomains.*false', 'Subdomains excluded', 'Low'),
    ]
    
    # ============================================================
    # 23. PATH TRAVERSAL
    # ============================================================
    PATH_TRAVERSAL = [
        (r'FileManager.*createFile\s*\(atPath:.*+', 'File create interpolation', 'High'),
        (r'String\s*\(contentsOfFile:.*+', 'File read interpolation', 'High'),
        (r'Data\s*\(contentsOf:.*+', 'Data read interpolation', 'High'),
        (r'URL\s*\(fileURLWithPath:.*+', 'File URL interpolation', 'Medium'),
        (r'writeToURL\s*\([^)]*+', 'Write URL interpolation', 'High'),
    ]
    
    # ============================================================
    # 24. THIRD PARTY SECURITY
    # ============================================================
    THIRD_PARTY = [
        (r'import\s+AlamofireImage', 'Alamofire Image', 'Info'),
        (r'import\s+Kingfisher', 'Kingfisher', 'Info'),
        (r'import\s+SDWebImage', 'SDWebImage', 'Info'),
        (r'import\s+Firebase', 'Firebase', 'Info'),
        (r'import\s+Crashlytics', 'Crashlytics', 'Info'),
        (r'import\s+Analytics', 'Analytics', 'Info'),
    ]
    
    # ============================================================
    # 25. BACKGROUND TASK SECURITY
    # ============================================================
    BACKGROUND = [
        (r'beginBackgroundTask', 'Background task', 'Low'),
        (r'BGAppRefreshTaskRequest', 'App refresh', 'Low'),
        (r'BGProcessingTaskRequest', 'Processing task', 'Low'),
        (r'applicationDidEnterBackground.*password', 'Password in background', 'High'),
        (r'UserDefaults.*background.*password', 'Password saved in background', 'High'),
    ]
    
    # ============================================================
    # 26. UNIVERSAL LINKS / ASSOCIATED DOMAINS
    # ============================================================
    UNIVERSAL_LINKS = [
        (r'applinks:', 'Universal Links config', 'Low'),
        (r'webcredentials:', 'Web credentials', 'Low'),
        (r'userActivity.*webpageURL', 'Universal link URL', 'Medium'),
        (r'continue.*userActivity(?!.*validate)', 'Universal link without validation', 'High'),
        (r'NSUserActivity.*webpageURL.*open', 'Direct URL open', 'High'),
        (r'\.universalLinksOnly', 'Universal links only mode', 'Info'),
    ]
    
    # ============================================================
    # 27. APP CLIPS SECURITY
    # ============================================================
    APP_CLIPS = [
        (r'AppClip', 'App Clip usage', 'Low'),
        (r'SKOverlay', 'App Clip overlay', 'Low'),
        (r'appStoreOverlayPresentCondition', 'Overlay condition', 'Low'),
        (r'NSAppClip', 'App Clip entitlement', 'Info'),
        (r'SKOverlayAppClipConfiguration', 'App Clip config', 'Low'),
    ]
    
    # ============================================================
    # 28. CLOUDKIT SECURITY
    # ============================================================
    CLOUDKIT = [
        (r'CKContainer.*publicCloudDatabase.*password', 'Password in public CloudKit', 'Critical'),
        (r'CKRecord.*setValue.*password', 'Password in CKRecord', 'High'),
        (r'CKRecord.*setValue.*token', 'Token in CKRecord', 'High'),
        (r'CKRecord.*setValue.*secret', 'Secret in CKRecord', 'High'),
        (r'CKQuerySubscription.*publicDatabase', 'Public DB subscription', 'Medium'),
        (r'CKShare.*publicPermission', 'Public share permission', 'Medium'),
        (r'CKFetchRecordsOperation.*desiredKeys', 'CloudKit fetch', 'Low'),
    ]
    
    # ============================================================
    # 29. HEALTHKIT SECURITY
    # ============================================================
    HEALTHKIT = [
        (r'HKHealthStore', 'HealthKit usage', 'Low'),
        (r'HKObjectType.*characteristicType', 'Health characteristics', 'Medium'),
        (r'HKSampleType.*quantityType', 'Health quantities', 'Medium'),
        (r'requestAuthorization.*toShare.*password', 'Password with HealthKit', 'Critical'),
        (r'HKQuery.*predicateForSamples', 'Health query', 'Low'),
        (r'HKWorkout', 'Workout data', 'Low'),
        (r'HKClinicalType', 'Clinical records', 'High'),
    ]
    
    # ============================================================
    # 30. SCENE DELEGATE SECURITY
    # ============================================================
    SCENE_DELEGATE = [
        (r'scene.*willConnectTo.*options', 'Scene connection', 'Low'),
        (r'scene.*openURLContexts(?!.*validate)', 'URL context without validation', 'High'),
        (r'sceneDidBecomeActive.*password', 'Password on activate', 'Medium'),
        (r'sceneDidEnterBackground.*save.*password', 'Password saved on background', 'High'),
        (r'UISceneConfiguration', 'Scene configuration', 'Low'),
    ]
    
    # ============================================================
    # 31. WIDGET EXTENSION SECURITY
    # ============================================================
    WIDGET_EXT = [
        (r'WidgetConfiguration', 'Widget config', 'Low'),
        (r'IntentConfiguration.*password', 'Password in widget intent', 'High'),
        (r'TimelineProvider.*password', 'Password in timeline', 'High'),
        (r'WidgetFamily.*accessoryCircular', 'Lock screen widget', 'Medium'),
        (r'@Environment.*\\.widgetFamily', 'Widget environment', 'Low'),
    ]
    
    # ============================================================
    # 32. CORE ML SECURITY
    # ============================================================
    COREML = [
        (r'MLModel.*compileModel', 'ML model compilation', 'Low'),
        (r'MLModelConfiguration', 'ML config', 'Low'),
        (r'MLModel.*contentsOf.*http://', 'Insecure ML model download', 'High'),
        (r'MLModel.*prediction.*userInput', 'User input to ML prediction', 'Medium'),
        (r'VNCoreMLRequest', 'Vision ML request', 'Low'),
    ]
    
    # ============================================================
    # 33. PUSH NOTIFICATION SECURITY
    # ============================================================
    PUSH_NOTIFICATIONS = [
        (r'UNUserNotificationCenter.*add.*password', 'Password in notification', 'High'),
        (r'UNMutableNotificationContent.*body.*password', 'Password in notification body', 'High'),
        (r'didReceiveRemoteNotification.*userInfo.*password', 'Password in push payload', 'High'),
        (r'UNNotificationServiceExtension', 'Notification service ext', 'Low'),
        (r'bestAttemptContent', 'Notification content modification', 'Low'),
    ]
    
    # ============================================================
    # 34. SIRI / INTENTS SECURITY
    # ============================================================
    SIRI_INTENTS = [
        (r'INInteraction', 'Siri interaction', 'Low'),
        (r'INVoiceShortcut', 'Voice shortcut', 'Low'),
        (r'INIntent.*password', 'Password in intent', 'High'),
        (r'donate.*interaction.*password', 'Password in donated interaction', 'High'),
        (r'SiriKit', 'SiriKit usage', 'Low'),
    ]
    
    # ============================================================
    # 35. APP TRACKING TRANSPARENCY
    # ============================================================
    APP_TRACKING = [
        (r'ATTrackingManager', 'Tracking manager', 'Low'),
        (r'requestTrackingAuthorization', 'Tracking authorization', 'Low'),
        (r'advertisingIdentifier', 'IDFA access', 'Medium'),
        (r'ASIdentifierManager', 'Ad identifier', 'Medium'),
        (r'identifierForVendor', 'Vendor identifier', 'Low'),
    ]
    
    def __init__(self):
        self.issues: List[SwiftVuln] = []
    
    def scan(self, code: str, filename: str = "") -> List[Dict]:
        self.issues = []
        lines = code.split('\n')
        
        # Run all checks
        self._check(lines, self.SQL_INJECTION, 'sql_injection', 'SQL Injection', 'CWE-89')
        self._check(lines, self.COMMAND_INJECTION, 'command_injection', 'Command Injection', 'CWE-78')
        self._check(lines, self.DATA_STORAGE, 'insecure_storage', 'Insecure Data Storage', 'CWE-312')
        self._check(lines, self.KEYCHAIN, 'keychain_security', 'Keychain Security', 'CWE-311')
        self._check(lines, self.NETWORK_SECURITY, 'insecure_network', 'Network Security', 'CWE-295')
        self._check(lines, self.WEBVIEW, 'webview_security', 'WebView Security', 'CWE-749')
        self._check(lines, self.CRYPTO, 'weak_crypto', 'Weak Cryptography', 'CWE-327')
        self._check(lines, self.AUTH, 'auth_issue', 'Authentication Issue', 'CWE-287')
        self._check(lines, self.LOGGING, 'info_disclosure', 'Information Disclosure', 'CWE-532')
        self._check(lines, self.URL_SCHEME, 'url_scheme', 'URL Scheme Security', 'CWE-939')
        self._check(lines, self.SWIFTUI, 'swiftui_security', 'SwiftUI Security', 'CWE-312')
        self._check(lines, self.MEMORY_SAFETY, 'memory_safety', 'Memory Safety', 'CWE-476')
        self._check(lines, self.INFO_DISCLOSURE, 'info_disclosure', 'Information Disclosure', 'CWE-200')
        self._check(lines, self.PASTEBOARD, 'pasteboard_security', 'Pasteboard Security', 'CWE-200')
        self._check(lines, self.CODE_QUALITY, 'code_quality', 'Code Quality', 'CWE-710')
        self._check(lines, self.RESOURCE_LEAKS, 'resource_leak', 'Resource Leak', 'CWE-404')
        self._check(lines, self.BIOMETRIC, 'biometric_security', 'Biometric Security', 'CWE-287')
        self._check(lines, self.IPC, 'ipc_security', 'IPC Security', 'CWE-200')
        self._check(lines, self.NETWORK_CONFIG, 'network_config', 'Network Configuration', 'CWE-16')
        self._check(lines, self.PATH_TRAVERSAL, 'path_traversal', 'Path Traversal', 'CWE-22')
        self._check(lines, self.BACKGROUND, 'background_security', 'Background Security', 'CWE-312')
        # New iOS advanced rules
        self._check(lines, self.UNIVERSAL_LINKS, 'universal_links', 'Universal Links Security', 'CWE-601')
        self._check(lines, self.APP_CLIPS, 'app_clips', 'App Clips Security', 'CWE-16')
        self._check(lines, self.CLOUDKIT, 'cloudkit_security', 'CloudKit Security', 'CWE-312')
        self._check(lines, self.HEALTHKIT, 'healthkit_security', 'HealthKit Security', 'CWE-359')
        self._check(lines, self.SCENE_DELEGATE, 'scene_delegate', 'Scene Delegate Security', 'CWE-200')
        self._check(lines, self.WIDGET_EXT, 'widget_security', 'Widget Extension Security', 'CWE-312')
        self._check(lines, self.COREML, 'coreml_security', 'Core ML Security', 'CWE-494')
        self._check(lines, self.PUSH_NOTIFICATIONS, 'push_notification', 'Push Notification Security', 'CWE-312')
        self._check(lines, self.SIRI_INTENTS, 'siri_intents', 'Siri Intents Security', 'CWE-200')
        self._check(lines, self.APP_TRACKING, 'app_tracking', 'App Tracking Transparency', 'CWE-359')
        self._check_secrets(lines)
        
        return [self._to_dict(v, filename) for v in self.issues]
    
    def _check(self, lines: List[str], patterns: list, vuln_type: str, desc: str, cwe: str):
        for i, line in enumerate(lines):
            for pattern, msg, severity in patterns:
                if severity == 'Info':
                    continue
                if re.search(pattern, line, re.IGNORECASE):
                    self.issues.append(SwiftVuln(
                        vuln_type=vuln_type,
                        category=iOSVulnCategory.CODE_QUALITY.value,
                        severity=severity,
                        line=i+1,
                        snippet=line.strip()[:120],
                        description=f"{desc}: {msg}",
                        remediation=self._get_remediation(vuln_type),
                        cwe_id=cwe,
                        owasp=iOSVulnCategory.CODE_QUALITY.value,
                        confidence=0.85
                    ))
    
    def _check_secrets(self, lines: List[str]):
        for i, line in enumerate(lines):
            if re.search(r'(test|example|placeholder)', line, re.IGNORECASE):
                continue
            for pattern, msg in self.SECRETS:
                if re.search(pattern, line, re.IGNORECASE):
                    self.issues.append(SwiftVuln(
                        vuln_type='hardcoded_secret',
                        category=iOSVulnCategory.CRYPTO.value,
                        severity='High',
                        line=i+1,
                        snippet=re.sub(r'"[^"]{4}([^"]*)"', r'"****\1"', line.strip()[:100]),
                        description=f"Hardcoded Secret: {msg}",
                        remediation='Store secrets in Keychain with kSecAttrAccessibleWhenUnlockedThisDeviceOnly.',
                        cwe_id='CWE-798',
                        owasp=iOSVulnCategory.CRYPTO.value
                    ))
    
    def _get_remediation(self, vuln_type: str) -> str:
        return {
            'sql_injection': 'Use parameterized queries with sqlite3_bind_*.',
            'command_injection': 'Avoid Process with user input. Validate arguments.',
            'insecure_storage': 'Use Keychain for sensitive data. Not UserDefaults.',
            'keychain_security': 'Use kSecAttrAccessibleWhenUnlockedThisDeviceOnly.',
            'insecure_network': 'Enable ATS. Implement certificate pinning.',
            'webview_security': 'Disable JS when not needed. Validate URLs.',
            'weak_crypto': 'Use AES-256-GCM. Use SecRandomCopyBytes.',
            'auth_issue': 'Use LAContext properly. Secure password storage.',
            'url_scheme': 'Validate URL scheme input. Use allowlists.',
            'swiftui_security': 'Avoid secrets in @AppStorage. Use Keychain.',
            'memory_safety': 'Use optional binding instead of force unwrap.',
            'path_traversal': 'Validate paths. Use canonicalPath.',
            'pasteboard_security': 'Never copy secrets to pasteboard.',
            'code_quality': 'Handle errors properly. Remove debug code.',
            'resource_leak': 'Use defer for cleanup. Close resources.',
        }.get(vuln_type, 'Review and fix security issue.')
    
    def _to_dict(self, v: SwiftVuln, filename: str) -> Dict:
        return {
            'type': v.vuln_type, 'category': v.category, 'severity': v.severity, 'line': v.line,
            'snippet': v.snippet, 'description': v.description, 'remediation': v.remediation,
            'cwe_id': v.cwe_id, 'owasp': v.owasp, 'confidence': v.confidence, 'file': filename,
            'language': 'swift', 'scanner': 'swift_analyzer_v3'
        }


def scan_swift(code: str, filename: str = "") -> List[Dict]:
    return SwiftAnalyzer().scan(code, filename)
