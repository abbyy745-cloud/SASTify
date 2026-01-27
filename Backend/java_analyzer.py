"""
Java Security Analyzer - Enterprise Edition

25+ Vulnerability Classes with Deep Detection:
- Injection (SQL, Command, LDAP, XPath, Template, Expression, OGNL)
- Authentication & Session Management
- Cryptographic Failures
- Server-Side Request Forgery (SSRF)
- Deserialization Attacks
- Race Conditions (TOCTOU)
- Null Pointer Dereference
- Integer Overflow/Underflow
- Resource Leaks
- Improper Input Validation
- Business Logic Flaws
- Information Disclosure
- Security Misconfiguration
- Framework-specific (Spring, Android, Hibernate, Struts)
"""

import re
from typing import List, Dict, Set, Optional, Tuple
from dataclasses import dataclass, field
from enum import Enum


class VulnCategory(Enum):
    INJECTION = "A03:2021-Injection"
    BROKEN_AUTH = "A07:2021-Authentication Failures"
    SENSITIVE_DATA = "A02:2021-Cryptographic Failures"
    XXE = "A05:2021-Security Misconfiguration"
    BROKEN_ACCESS = "A01:2021-Broken Access Control"
    MISCONFIG = "A05:2021-Security Misconfiguration"
    XSS = "A03:2021-Injection"
    DESER = "A08:2021-Software and Data Integrity"
    VULN_COMP = "A06:2021-Vulnerable Components"
    LOGGING = "A09:2021-Security Logging Failures"
    SSRF = "A10:2021-SSRF"
    CRYPTO = "A02:2021-Cryptographic Failures"
    RACE_CONDITION = "CWE-362"
    RESOURCE_LEAK = "CWE-404"
    NULL_DEREF = "CWE-476"
    INTEGER_ISSUES = "CWE-190"
    BUSINESS_LOGIC = "CWE-840"


@dataclass
class TaintedVar:
    name: str
    source: str
    line: int
    source_type: str
    sanitized: bool = False


@dataclass
class Vulnerability:
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


class JavaAnalyzer:
    """Enterprise Java Security Analyzer with 25+ vulnerability classes"""
    
    # ============================================================
    # 1. SQL INJECTION
    # ============================================================
    SQL_INJECTION = [
        (r'Statement.*execute\w*\s*\([^)]*\+', 'Statement concatenation', 'Critical'),
        (r'createStatement\s*\(\s*\).*execute', 'Raw Statement', 'Critical'),
        (r'prepareStatement\s*\([^?]*\+', 'PreparedStatement with concat', 'Critical'),
        (r'\.executeQuery\s*\([^)]*\+', 'executeQuery with concat', 'Critical'),
        (r'\.executeUpdate\s*\([^)]*\+', 'executeUpdate with concat', 'Critical'),
        (r'createNativeQuery\s*\([^)]*\+', 'JPA native query concat', 'Critical'),
        (r'createQuery\s*\([^)]*\+', 'JPA/Hibernate query concat', 'High'),
        (r'Session\.createSQLQuery\s*\([^)]*\+', 'Hibernate SQL concat', 'Critical'),
        (r'jdbcTemplate\.query\s*\([^)]*\+', 'Spring JDBC concat', 'Critical'),
        (r'entityManager\.createNativeQuery\s*\([^)]*\+', 'EntityManager concat', 'Critical'),
        (r'@Query.*nativeQuery.*\+', 'Spring @Query native concat', 'High'),
        (r'em\.createQuery.*String\.format', 'JPA with String.format', 'High'),
        (r'\.queryForObject.*\+', 'Spring queryForObject', 'High'),
        (r'NamedParameterJdbcTemplate.*\+', 'NamedParameter with concat', 'High'),
    ]
    
    # ============================================================
    # 2. COMMAND INJECTION
    # ============================================================
    COMMAND_INJECTION = [
        (r'Runtime\.getRuntime\(\)\.exec\s*\(', 'Runtime.exec()', 'Critical'),
        (r'ProcessBuilder\s*\([^)]*\+', 'ProcessBuilder concat', 'Critical'),
        (r'ProcessBuilder.*command\s*\([^)]*\+', 'ProcessBuilder.command concat', 'Critical'),
        (r'new\s+ProcessBuilder\s*\(\s*Arrays\.asList.*\+', 'ProcessBuilder list concat', 'High'),
        (r'Runtime.*exec.*request\.get', 'Runtime with request input', 'Critical'),
        (r'ScriptEngine.*eval\s*\([^)]*\+', 'ScriptEngine eval', 'Critical'),
        (r'GroovyShell.*evaluate', 'Groovy shell', 'Critical'),
        (r'ApplicationRuntime.*exec', 'ApplicationRuntime exec', 'High'),
    ]
    
    # ============================================================
    # 3. PATH TRAVERSAL
    # ============================================================
    PATH_TRAVERSAL = [
        (r'new\s+File\s*\([^)]*\+', 'File path concat', 'High'),
        (r'new\s+FileInputStream\s*\([^)]*\+', 'FileInputStream concat', 'High'),
        (r'new\s+FileOutputStream\s*\([^)]*\+', 'FileOutputStream concat', 'High'),
        (r'new\s+FileReader\s*\([^)]*\+', 'FileReader concat', 'High'),
        (r'new\s+FileWriter\s*\([^)]*\+', 'FileWriter concat', 'High'),
        (r'Paths\.get\s*\([^)]*\+', 'Paths.get concat', 'High'),
        (r'Files\.\w+\s*\(.*request', 'Files API with request', 'High'),
        (r'new\s+RandomAccessFile\s*\([^)]*\+', 'RandomAccessFile concat', 'High'),
        (r'ClassLoader.*getResource.*\+', 'ClassLoader resource', 'Medium'),
        (r'getServletContext\(\)\.getResource.*\+', 'Servlet resource', 'Medium'),
        (r'FileUtils\.readFileToString.*\+', 'Commons FileUtils', 'High'),
        (r'IOUtils\.copy.*new\s+File.*\+', 'IOUtils with path', 'High'),
    ]
    
    # ============================================================
    # 4. XSS (Cross-Site Scripting)
    # ============================================================
    XSS = [
        (r'PrintWriter.*print\w*\s*\([^)]*\+', 'PrintWriter output', 'High'),
        (r'response\.getWriter\(\)\.print', 'Response writer', 'High'),
        (r'out\.print\w*\s*\([^)]*\+', 'JSP out concat', 'High'),
        (r'response\.setContentType.*text/html', 'HTML response', 'Low'),
        (r'\.sendRedirect\s*\([^)]*\+', 'Redirect concat', 'High'),
        (r'RequestDispatcher.*forward', 'Forward dispatch', 'Medium'),
        (r'model\.addAttribute.*request\.get', 'Model with request', 'High'),
        (r'ModelAndView.*addObject.*request', 'ModelAndView request', 'High'),
        (r'ScriptEngineManager.*JavaScript', 'Server JS execution', 'High'),
        (r'JspWriter.*print.*\+', 'JspWriter concat', 'High'),
        (r'@ResponseBody.*\+', 'ResponseBody concat', 'Medium'),
    ]
    
    # ============================================================
    # 5. XXE (XML External Entity)
    # ============================================================
    XXE = [
        (r'DocumentBuilderFactory\.newInstance\s*\(\)', 'Unsafe DocumentBuilder', 'High'),
        (r'SAXParserFactory\.newInstance\s*\(\)', 'Unsafe SAXParser', 'High'),
        (r'XMLInputFactory\.newInstance\s*\(\)', 'Unsafe XMLInput', 'High'),
        (r'TransformerFactory\.newInstance\s*\(\)', 'Unsafe Transformer', 'High'),
        (r'SchemaFactory\.newInstance\s*\(\)', 'Unsafe Schema', 'High'),
        (r'Unmarshaller.*unmarshal\s*\(', 'JAXB unmarshal', 'Medium'),
        (r'SAXReader\s*\(\)', 'Dom4j SAXReader', 'High'),
        (r'SAXBuilder\s*\(\)', 'JDOM SAXBuilder', 'High'),
        (r'XmlSlurper\s*\(\)', 'Groovy XmlSlurper', 'High'),
        (r'XmlParser\s*\(\)', 'Groovy XmlParser', 'High'),
        (r'XMLReader.*parse\s*\(', 'XMLReader parse', 'Medium'),
        (r'Digester\s*\(\)', 'Commons Digester', 'High'),
    ]
    
    # ============================================================
    # 6. SSRF (Server-Side Request Forgery)
    # ============================================================
    SSRF = [
        (r'new\s+URL\s*\([^)]*\+', 'URL with input', 'High'),
        (r'HttpURLConnection.*openConnection', 'HTTP connection', 'Medium'),
        (r'HttpClient.*execute\s*\(', 'HttpClient request', 'Medium'),
        (r'RestTemplate\.\w+\s*\([^)]*\+', 'RestTemplate concat', 'High'),
        (r'WebClient\.\w+\s*\([^)]*\+', 'WebClient concat', 'High'),
        (r'OkHttpClient.*newCall', 'OkHttp call', 'Medium'),
        (r'Jsoup\.connect\s*\([^)]*\+', 'Jsoup connect', 'High'),
        (r'URI\.create\s*\([^)]*\+', 'URI create concat', 'High'),
        (r'HttpRequest\.newBuilder.*uri.*\+', 'HttpRequest uri', 'High'),
        (r'AsyncHttpClient.*prepare.*\+', 'Async HTTP', 'High'),
        (r'socket\.connect\s*\([^)]*\+', 'Socket connect', 'High'),
        (r'InetAddress\.getByName\s*\([^)]*\+', 'InetAddress lookup', 'Medium'),
    ]
    
    # ============================================================
    # 7. DESERIALIZATION
    # ============================================================
    DESERIALIZATION = [
        (r'ObjectInputStream\s*\(', 'ObjectInputStream', 'Critical'),
        (r'\.readObject\s*\(\s*\)', 'readObject()', 'Critical'),
        (r'XMLDecoder\s*\(', 'XMLDecoder', 'Critical'),
        (r'Yaml\.load\s*\([^)]*\)', 'SnakeYAML load', 'Critical'),
        (r'Yaml\s*\(\)\.load\s*\(', 'SnakeYAML load', 'Critical'),
        (r'ObjectMapper\.readValue.*Object\.class', 'Jackson to Object', 'High'),
        (r'JsonParser.*readValueAs\s*\(', 'Jackson parsing', 'Medium'),
        (r'Kryo\.readObject\s*\(', 'Kryo deser', 'High'),
        (r'XStream\s*\(\)\.fromXML', 'XStream deser', 'Critical'),
        (r'SerializationUtils\.deserialize', 'Commons deser', 'Critical'),
        (r'BurlapInput.*readObject', 'Burlap deser', 'High'),
        (r'HessianInput.*readObject', 'Hessian deser', 'High'),
        (r'\.readUnshared\s*\(\)', 'readUnshared()', 'Critical'),
    ]
    
    # ============================================================
    # 8. LDAP INJECTION
    # ============================================================
    LDAP_INJECTION = [
        (r'DirContext.*search\s*\([^)]*\+', 'LDAP search concat', 'High'),
        (r'LdapTemplate\.search\s*\([^)]*\+', 'Spring LDAP concat', 'High'),
        (r'\.filter\s*\([^)]*\+.*ldap', 'LDAP filter concat', 'High'),
        (r'new\s+SearchControls', 'SearchControls - verify filter', 'Low'),
        (r'InitialDirContext.*search', 'InitialDirContext search', 'Medium'),
        (r'NamingEnumeration.*search', 'LDAP enumeration', 'Low'),
    ]
    
    # ============================================================
    # 9. XPATH INJECTION
    # ============================================================
    XPATH_INJECTION = [
        (r'XPath.*evaluate\s*\([^)]*\+', 'XPath eval concat', 'High'),
        (r'XPathExpression.*evaluate\s*\([^)]*\+', 'XPathExpr eval', 'High'),
        (r'XPathFactory.*newXPath', 'XPath factory', 'Low'),
        (r'document\.selectNodes\s*\([^)]*\+', 'Dom4j XPath', 'High'),
        (r'XPathSelectElement\s*\([^)]*\+', 'XPath select', 'High'),
    ]
    
    # ============================================================
    # 10. TEMPLATE INJECTION
    # ============================================================
    TEMPLATE_INJECTION = [
        (r'VelocityContext.*put\s*\([^)]*request', 'Velocity user input', 'High'),
        (r'Velocity\.evaluate\s*\([^)]*\+', 'Velocity eval', 'Critical'),
        (r'freemarker\.Template.*process', 'Freemarker template', 'Medium'),
        (r'Configuration\.getTemplate\s*\([^)]*\+', 'Freemarker getTemplate', 'High'),
        (r'Thymeleaf.*process.*request', 'Thymeleaf process', 'High'),
        (r'TemplateEngine.*process\s*\([^)]*\+', 'Template engine concat', 'High'),
        (r'JtwigTemplate.*render', 'Jtwig render', 'Medium'),
        (r'PebbleEngine.*getTemplate.*\+', 'Pebble template', 'High'),
        (r'HandlebarsTemplateEngine', 'Handlebars engine', 'Medium'),
    ]
    
    # ============================================================
    # 11. EXPRESSION INJECTION (SpEL, OGNL, MVEL)
    # ============================================================
    EXPRESSION_INJECTION = [
        (r'SpelExpressionParser\s*\(', 'SpEL parser', 'High'),
        (r'\.parseExpression\s*\([^)]*\+', 'SpEL parse concat', 'Critical'),
        (r'ExpressionParser.*parseExpression.*request', 'SpEL request input', 'Critical'),
        (r'OgnlContext', 'OGNL context', 'High'),
        (r'Ognl\.getValue\s*\([^)]*\+', 'OGNL eval', 'Critical'),
        (r'Ognl\.setValue\s*\([^)]*\+', 'OGNL set', 'Critical'),
        (r'OgnlUtil.*getValue', 'OGNL util', 'High'),
        (r'MVEL\.eval\s*\([^)]*\+', 'MVEL eval', 'Critical'),
        (r'MVEL\.executeExpression', 'MVEL execute', 'High'),
        (r'JexlEngine.*createExpression', 'JEXL expression', 'High'),
        (r'ScriptEngine.*eval\s*\([^)]*\+', 'Script eval', 'Critical'),
    ]
    
    # ============================================================
    # 12. RACE CONDITIONS (TOCTOU)
    # ============================================================
    RACE_CONDITIONS = [
        (r'\.exists\s*\(\s*\).*\{[\s\S]*?new\s+File', 'File exists TOCTOU', 'Medium'),
        (r'\.isFile\s*\(\s*\).*new\s+FileInputStream', 'isFile TOCTOU', 'Medium'),
        (r'\.canRead\s*\(\s*\).*read', 'canRead TOCTOU', 'Medium'),
        (r'\.canWrite\s*\(\s*\).*write', 'canWrite TOCTOU', 'Medium'),
        (r'synchronized\s*\(\s*this\s*\)', 'Sync on this', 'Medium'),
        (r'synchronized\s*\(\s*getClass\(\)\s*\)', 'Sync on class', 'Medium'),
        (r'\.wait\s*\(\s*\)(?!.*while)', 'wait without loop', 'Medium'),
        (r'lazyInit.*==\s*null', 'Lazy init race', 'Low'),
        (r'if\s*\(\s*\w+\s*==\s*null\s*\)\s*\w+\s*=', 'Null check race', 'Low'),
        (r'singleton\s*==\s*null', 'Singleton race', 'Medium'),
        (r'@PostConstruct.*static', 'Static in PostConstruct', 'Low'),
    ]
    
    # ============================================================
    # 13. NULL POINTER DEREFERENCE
    # ============================================================
    NULL_DEREFERENCE = [
        (r'\.get\s*\([^)]*\)\s*\.', 'Unchecked get() dereference', 'Medium'),
        (r'find\w+\s*\([^)]*\)\s*\.', 'Unchecked find dereference', 'Medium'),
        (r'@RequestParam\s+\w+\s+\w+\s*[^@]*\.\w+\s*\(', 'Nullable param dereference', 'Low'),
        (r'request\.getParameter\s*\([^)]*\)\s*\.', 'Request param dereference', 'Medium'),
        (r'request\.getHeader\s*\([^)]*\)\s*\.', 'Header dereference', 'Medium'),
        (r'System\.getProperty\s*\([^)]*\)\s*\.', 'Property dereference', 'Low'),
        (r'System\.getenv\s*\([^)]*\)\s*\.', 'Env var dereference', 'Low'),
        (r'map\.get\s*\([^)]*\)\s*\.', 'Map get dereference', 'Medium'),
        (r'Optional\.get\s*\(\s*\)', 'Optional.get() without check', 'Medium'),
    ]
    
    # ============================================================
    # 14. INTEGER OVERFLOW/UNDERFLOW
    # ============================================================
    INTEGER_OVERFLOW = [
        (r'int\s+\w+\s*=.*\*.*\*', 'Integer multiplication overflow', 'Medium'),
        (r'\+\+\w+\s*[);]', 'Unchecked increment', 'Low'),
        (r'Integer\.MAX_VALUE\s*\+', 'MAX_VALUE overflow', 'High'),
        (r'Integer\.parseInt\s*\([^)]*\)\s*\*', 'Parse then multiply', 'Medium'),
        (r'\(int\)\s*\w+\.\w+\s*\*', 'Cast then multiply', 'Medium'),
        (r'length\s*\*\s*\d{4,}', 'Length multiplier', 'Medium'),
        (r'size\s*\*\s*\d{4,}', 'Size multiplier', 'Medium'),
        (r'byte\[\]\s*=\s*new\s*byte\[.*\+', 'Dynamic array size', 'Medium'),
        (r'int\s+\w+\s*=\s*.*<<', 'Shift overflow', 'Low'),
    ]
    
    # ============================================================
    # 15. RESOURCE LEAKS
    # ============================================================
    RESOURCE_LEAKS = [
        (r'new\s+FileInputStream\s*\([^)]*\)(?!.*try-with)', 'FileInputStream leak', 'Medium'),
        (r'new\s+FileOutputStream\s*\([^)]*\)(?!.*try-with)', 'FileOutputStream leak', 'Medium'),
        (r'new\s+BufferedReader\s*\([^)]*\)(?!.*try-with)', 'BufferedReader leak', 'Medium'),
        (r'new\s+Connection\s*\([^)]*\)(?!.*try-with)', 'Connection leak', 'High'),
        (r'DriverManager\.getConnection(?!.*try-with)', 'DB connection leak', 'High'),
        (r'\.prepareStatement\s*\([^)]*\)(?!.*try-with)', 'Statement leak', 'Medium'),
        (r'new\s+Socket\s*\([^)]*\)(?!.*try-with)', 'Socket leak', 'Medium'),
        (r'\.getInputStream\s*\(\s*\)(?!.*close)', 'InputStream not closed', 'Low'),
        (r'\.getOutputStream\s*\(\s*\)(?!.*close)', 'OutputStream not closed', 'Low'),
        (r'newChannel\s*\(\s*\)(?!.*close)', 'Channel not closed', 'Low'),
        (r'ExecutorService.*new(?!.*shutdown)', 'ExecutorService leak', 'Medium'),
        (r'Cipher\.getInstance(?!.*finally)', 'Cipher resource', 'Low'),
    ]
    
    # ============================================================
    # 16. IMPROPER INPUT VALIDATION
    # ============================================================
    INPUT_VALIDATION = [
        (r'@RequestParam\s+String\s+\w+(?!.*@Valid)', 'Unvalidated string param', 'Low'),
        (r'@PathVariable\s+Long\s+\w+.*findById.*\.get\(\)', 'ID without existence check', 'Medium'),
        (r'Integer\.parseInt(?!.*catch)', 'Uncaught parseInt', 'Low'),
        (r'Long\.parseLong(?!.*catch)', 'Uncaught parseLong', 'Low'),
        (r'Double\.parseDouble(?!.*catch)', 'Uncaught parseDouble', 'Low'),
        (r'@RequestBody\s+\w+\s+\w+(?!.*@Valid)', 'Unvalidated request body', 'Medium'),
        (r'@Email(?!.*@NotBlank)', 'Email without NotBlank', 'Low'),
        (r'@Min\s*\(\s*0\s*\)(?!.*@Max)', 'Min without Max', 'Low'),
        (r'request\.getParameter.*\.length\(\)', 'Null length check', 'Low'),
        (r'replaceAll\s*\(\s*"\\\\w"', 'Weak regex validation', 'Low'),
        (r'matches\s*\(\s*"\.?\*"', 'Greedy regex', 'Medium'),
    ]
    
    # ============================================================
    # 17. CRYPTOGRAPHIC ISSUES
    # ============================================================
    CRYPTO_ISSUES = [
        (r'Cipher\.getInstance\s*\(\s*"DES"', 'DES encryption', 'Critical'),
        (r'Cipher\.getInstance\s*\(\s*"DESede"', '3DES encryption', 'High'),
        (r'Cipher\.getInstance\s*\(\s*"RC2"', 'RC2 encryption', 'Critical'),
        (r'Cipher\.getInstance\s*\(\s*"RC4"', 'RC4 encryption', 'Critical'),
        (r'Cipher\.getInstance\s*\(\s*"Blowfish"', 'Blowfish', 'Medium'),
        (r'Cipher\.getInstance\s*\(\s*"[^"]*ECB[^"]*"', 'ECB mode', 'High'),
        (r'Cipher\.getInstance\s*\(\s*"AES"\s*\)', 'AES default ECB', 'High'),
        (r'MessageDigest\.getInstance\s*\(\s*"MD5"', 'MD5 hash', 'Medium'),
        (r'MessageDigest\.getInstance\s*\(\s*"SHA-?1"', 'SHA1 hash', 'Medium'),
        (r'SecretKeySpec\s*\(.*".*".*\.getBytes', 'Hardcoded key', 'Critical'),
        (r'IvParameterSpec\s*\(.*".*".*\.getBytes', 'Hardcoded IV', 'High'),
        (r'Random\s*\(\s*\)', 'Insecure Random', 'High'),
        (r'Math\.random\s*\(\s*\)', 'Math.random', 'High'),
        (r'\.setSeed\s*\(\s*\d+\s*\)', 'Static seed', 'High'),
        (r'KeyPairGenerator.*initialize\s*\(\s*\d{1,3}\s*\)', 'Small key size', 'High'),
        (r'KeyGenerator.*init\s*\(\s*\d{1,2}\s*\)', 'Small symmetric key', 'High'),
        (r'NullCipher', 'NullCipher usage', 'Critical'),
        (r'password\.toCharArray\s*\(\s*\)', 'Password in memory', 'Low'),
    ]
    
    # ============================================================
    # 18. AUTHENTICATION ISSUES
    # ============================================================
    AUTH_ISSUES = [
        (r'\.equals\s*\(\s*password', 'Password equals()', 'High'),
        (r'password\s*==\s*"', 'Hardcoded password', 'Critical'),
        (r'password\.equals\s*\("', 'Hardcoded password check', 'Critical'),
        (r'UsernamePasswordAuthenticationToken\s*\([^)]*null', 'Null credentials', 'High'),
        (r'@PreAuthorize\s*\(\s*"permitAll', 'Permit all', 'Medium'),
        (r'http\.csrf\(\)\.disable', 'CSRF disabled', 'High'),
        (r'@CrossOrigin\s*\(\s*origins\s*=\s*"\*"', 'CORS *', 'Medium'),
        (r'setAllowedOrigins\s*\(\s*Arrays\.asList\s*\(\s*"\*"', 'CORS * list', 'Medium'),
        (r'BCrypt\.checkpw.*equals', 'BCrypt with equals', 'Low'),
        (r'session\.getId\(\).*log', 'Session ID logged', 'Medium'),
        (r'remember-?me.*alwaysRemember.*true', 'Always remember', 'Medium'),
        (r'session\.setMaxInactiveInterval\s*\(\s*-1', 'Infinite session', 'Medium'),
        (r'Security\.addProvider.*Bouncy', 'BouncyCastle - verify usage', 'Info'),
    ]
    
    # ============================================================
    # 19. SESSION ISSUES
    # ============================================================
    SESSION_ISSUES = [
        (r'Cookie.*setSecure\s*\(\s*false', 'Insecure cookie', 'High'),
        (r'Cookie.*setHttpOnly\s*\(\s*false', 'Non-HttpOnly cookie', 'Medium'),
        (r'new\s+Cookie\s*\([^)]+\)(?!.*setSecure)', 'Cookie no Secure', 'Medium'),
        (r'session\.setAttribute\s*\([^)]*password', 'Password in session', 'High'),
        (r'JSESSIONID.*SameSite=None', 'SameSite None', 'Medium'),
        (r'\.setMaxAge\s*\(\s*-1\s*\)', 'Session-only cookie', 'Info'),
        (r'response\.addCookie.*\.getValue\(\)', 'Cookie reflection', 'Medium'),
        (r'setDomain\s*\(\s*"\."', 'Wide cookie domain', 'Medium'),
    ]
    
    # ============================================================
    # 20. INFORMATION DISCLOSURE
    # ============================================================
    INFO_DISCLOSURE = [
        (r'e\.printStackTrace\s*\(\s*\)', 'Stack trace exposure', 'Medium'),
        (r'throw\s+new\s+\w*Exception\s*\([^)]*\+', 'Exception with data', 'Low'),
        (r'System\.getProperty\s*\([^)]*\)', 'System property', 'Low'),
        (r'System\.getenv\s*\([^)]*\)', 'Env variable', 'Low'),
        (r'\.getMessage\s*\(\s*\).*response', 'Error message in response', 'Medium'),
        (r'\.getCause\s*\(\s*\).*response', 'Cause in response', 'Medium'),
        (r'@ExceptionHandler.*return.*e\.', 'Handler exposes error', 'Medium'),
        (r'database.*version.*query', 'DB version query', 'Low'),
        (r'server\.error\.include-stacktrace=always', 'Include stacktrace', 'High'),
        (r'server\.error\.include-message=always', 'Include message', 'Medium'),
    ]
    
    # ============================================================
    # 21. HARDCODED SECRETS
    # ============================================================
    SECRETS = [
        (r'(?:password|passwd|pwd)\s*=\s*"(?!["\s])[^"]{8,}"', 'Hardcoded password'),
        (r'(?:api[_-]?key|apikey)\s*=\s*"[A-Za-z0-9_\-]{20,}"', 'Hardcoded API key'),
        (r'(?:secret|secret[_-]?key)\s*=\s*"[^"]{16,}"', 'Hardcoded secret'),
        (r'(?:access[_-]?token|auth[_-]?token)\s*=\s*"[^"]{20,}"', 'Hardcoded token'),
        (r'-----BEGIN\s+(?:RSA\s+)?PRIVATE\s+KEY-----', 'Private key embedded'),
        (r'jdbc:[^"]*password=[^&\s"]+', 'Password in JDBC'),
        (r'mongodb://[^:]+:[^@]+@', 'MongoDB credentials'),
        (r'redis://:[^@]+@', 'Redis credentials'),
        (r'amqp://[^:]+:[^@]+@', 'AMQP credentials'),
        (r'AKIA[0-9A-Z]{16}', 'AWS access key'),
        (r'sk_live_[0-9a-zA-Z]{24}', 'Stripe live key'),
        (r'ghp_[A-Za-z0-9]{36}', 'GitHub token'),
        (r'eyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*', 'JWT token'),
    ]
    
    # ============================================================
    # 22. ANDROID SPECIFIC
    # ============================================================
    ANDROID = [
        (r'android:exported\s*=\s*"true"', 'Exported component', 'Medium'),
        (r'android:debuggable\s*=\s*"true"', 'Debuggable', 'High'),
        (r'android:allowBackup\s*=\s*"true"', 'Backup enabled', 'Medium'),
        (r'android:usesCleartextTraffic\s*=\s*"true"', 'Cleartext traffic', 'High'),
        (r'setJavaScriptEnabled\s*\(\s*true', 'WebView JS', 'Medium'),
        (r'addJavascriptInterface\s*\(', 'JS interface', 'High'),
        (r'setAllowFileAccess\s*\(\s*true', 'WebView file access', 'High'),
        (r'setAllowUniversalAccessFromFileURLs\s*\(\s*true', 'Universal access', 'Critical'),
        (r'MODE_WORLD_READABLE|MODE_WORLD_WRITEABLE', 'World accessible', 'Critical'),
        (r'TrustManager.*checkServerTrusted\s*\([^)]*\)\s*\{[\s\n]*\}', 'Empty TrustManager', 'Critical'),
        (r'HostnameVerifier.*verify.*return\s+true', 'Hostname bypass', 'Critical'),
        (r'Log\.[dievw]\s*\([^)]*(?:password|token|secret)', 'Sensitive logging', 'High'),
        (r'sendBroadcast\s*\([^)]*\)(?!.*permission)', 'Broadcast no permission', 'Medium'),
        (r'PendingIntent\.get\w+\s*\([^)]*0\s*\)', 'Mutable PendingIntent', 'High'),
        (r'WebSettings.*setSavePassword\s*\(\s*true', 'WebView save password', 'High'),
        (r'\.setMixedContentMode.*MIXED_CONTENT_ALWAYS_ALLOW', 'Mixed content', 'High'),
        (r'getSharedPreferences.*MODE_PRIVATE\)(?!.*encrypt)', 'Unencrypted prefs', 'Medium'),
        (r'SQLiteDatabase\.openOrCreateDatabase(?!.*password)', 'Unencrypted DB', 'Medium'),
    ]
    
    # ============================================================
    # 23. SPRING SPECIFIC
    # ============================================================
    SPRING = [
        (r'@GetMapping.*\+', 'Dynamic endpoint', 'Low'),
        (r'@Value\s*\(\s*"\$\{[^}]*\+', 'Dynamic @Value', 'Medium'),
        (r'RedirectView\s*\([^)]*\+', 'Open redirect', 'High'),
        (r'redirect:[^"]*\+', 'Open redirect', 'High'),
        (r'BeanUtils\.copyProperties.*request', 'Mass assignment', 'High'),
        (r'ModelMapper.*map\s*\([^)]*request', 'Mass assignment ModelMapper', 'Medium'),
        (r'@Async\s+public\s+void', 'Async void - exceptions lost', 'Low'),
        (r'@Transactional.*propagation.*NEVER', 'Transaction NEVER', 'Low'),
        (r'@Query.*SpEL', 'SpEL in @Query', 'High'),
        (r'@Cacheable.*key.*\#', 'Cache key SpEL', 'Medium'),
        (r'\.antMatchers\s*\(\s*"\*\*"', 'Wide antMatcher', 'Medium'),
        (r'authorizeRequests\(\)\.anyRequest\(\)\.permitAll', 'All permit', 'High'),
        (r'MethodSecurityExpressionHandler', 'Custom security handler', 'Info'),
        (r'httpBasic\(\)', 'Basic auth', 'Medium'),
        (r'formLogin\(\)\.loginPage\(\s*null', 'Null login page', 'Medium'),
    ]
    
    # ============================================================
    # 24. BUSINESS LOGIC
    # ============================================================
    BUSINESS_LOGIC = [
        (r'price\s*=.*request\.get', 'Price from input', 'High'),
        (r'amount\s*=.*request\.get', 'Amount from input', 'High'),
        (r'discount\s*=.*request\.get', 'Discount from input', 'High'),
        (r'quantity\s*<\s*0', 'Negative quantity check (verify)', 'Medium'),
        (r'\.setPrice\s*\([^)]*request', 'Price set from request', 'High'),
        (r'\.setAmount\s*\([^)]*request', 'Amount set from request', 'High'),
        (r'admin\s*=\s*"true".*request', 'Admin flag from input', 'Critical'),
        (r'role\s*=.*request\.get', 'Role from input', 'Critical'),
        (r'isAdmin\s*=.*request', 'Admin check from input', 'Critical'),
        (r'bypass.*=.*request', 'Bypass from input', 'High'),
        (r'skip.*validation.*=.*true', 'Skip validation', 'High'),
    ]
    
    # ============================================================
    # 25. LOG INJECTION
    # ============================================================
    LOG_INJECTION = [
        (r'logger\.\w+\s*\([^)]*\+.*request', 'Logger with request', 'Medium'),
        (r'log\.\w+\s*\([^)]*\+.*request', 'Log with request', 'Medium'),
        (r'System\.out\.print.*request', 'Stdout with request', 'Low'),
        (r'System\.err\.print.*request', 'Stderr with request', 'Low'),
        (r'Logger\.getLogger.*log.*\n.*request', 'Logger with request', 'Medium'),
        (r'@Slf4j.*log.*\$\{', 'Slf4j interpolation', 'Low'),
    ]
    
    # ============================================================
    # 26. DENIAL OF SERVICE
    # ============================================================
    DOS = [
        (r'Pattern\.compile\s*\([^)]*\+', 'Regex from input', 'High'),
        (r'Pattern\.compile\s*\([^)]*\*\+', 'Greedy regex', 'High'),
        (r'matches\s*\([^)]*\*\+\*', 'ReDoS pattern', 'High'),
        (r'\.split\s*\([^)]*\)', 'Split (ReDoS risk)', 'Low'),
        (r'new\s+byte\s*\[\s*\w+\s*\]', 'Dynamic allocation', 'Low'),
        (r'StringBuilder\s*\(\s*\d{6,}', 'Large StringBuilder', 'Low'),
        (r'while\s*\(\s*true\s*\)', 'Infinite loop', 'Low'),
        (r'recursion.*\+\+depth', 'Unbounded recursion', 'Medium'),
        (r'zip\.getNextEntry\s*\(', 'Zip bomb risk', 'Medium'),
        (r'XMLParser.*setEntityResolver', 'Billion laughs risk', 'Medium'),
    ]
    
    def __init__(self):
        self.issues: List[Vulnerability] = []
        self.tainted: Dict[str, TaintedVar] = {}
        self.is_android = False
        self.is_spring = False
    
    def scan(self, code: str, filename: str = "") -> List[Dict]:
        self.issues = []
        self.tainted = {}
        lines = code.split('\n')
        
        # Detect framework
        self._detect_framework(code)
        
        # All checks
        self._check_patterns(lines, self.SQL_INJECTION, 'sql_injection', 'SQL Injection', 'CWE-89')
        self._check_patterns(lines, self.COMMAND_INJECTION, 'command_injection', 'Command Injection', 'CWE-78')
        self._check_patterns(lines, self.PATH_TRAVERSAL, 'path_traversal', 'Path Traversal', 'CWE-22')
        self._check_patterns(lines, self.XSS, 'xss', 'Cross-Site Scripting', 'CWE-79')
        self._check_patterns(lines, self.XXE, 'xxe', 'XML External Entity', 'CWE-611')
        self._check_patterns(lines, self.SSRF, 'ssrf', 'Server-Side Request Forgery', 'CWE-918')
        self._check_patterns(lines, self.DESERIALIZATION, 'deserialization', 'Insecure Deserialization', 'CWE-502')
        self._check_patterns(lines, self.LDAP_INJECTION, 'ldap_injection', 'LDAP Injection', 'CWE-90')
        self._check_patterns(lines, self.XPATH_INJECTION, 'xpath_injection', 'XPath Injection', 'CWE-643')
        self._check_patterns(lines, self.TEMPLATE_INJECTION, 'template_injection', 'Template Injection', 'CWE-94')
        self._check_patterns(lines, self.EXPRESSION_INJECTION, 'expression_injection', 'Expression Injection', 'CWE-917')
        self._check_patterns(lines, self.RACE_CONDITIONS, 'race_condition', 'Race Condition', 'CWE-362')
        self._check_patterns(lines, self.NULL_DEREFERENCE, 'null_dereference', 'Null Dereference', 'CWE-476')
        self._check_patterns(lines, self.INTEGER_OVERFLOW, 'integer_overflow', 'Integer Overflow', 'CWE-190')
        self._check_patterns(lines, self.RESOURCE_LEAKS, 'resource_leak', 'Resource Leak', 'CWE-404')
        self._check_patterns(lines, self.INPUT_VALIDATION, 'input_validation', 'Improper Input Validation', 'CWE-20')
        self._check_crypto(lines)
        self._check_auth(lines)
        self._check_session(lines)
        self._check_info_disclosure(lines)
        self._check_secrets(lines)
        self._check_log_injection(lines)
        self._check_dos(lines)
        self._check_business_logic(lines)
        
        if self.is_android:
            self._check_android(lines)
        if self.is_spring:
            self._check_spring(lines)
        
        return [self._to_dict(v, filename) for v in self.issues]
    
    def _detect_framework(self, code: str):
        self.is_spring = any(x in code for x in ['org.springframework', '@SpringBootApplication', '@RestController', '@Service'])
        self.is_android = any(x in code for x in ['import android.', 'import androidx.', 'Activity', 'Fragment'])
    
    def _check_patterns(self, lines: List[str], patterns: list, vuln_type: str, desc: str, cwe: str):
        for i, line in enumerate(lines):
            for pattern, msg, severity in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    self.issues.append(Vulnerability(
                        vuln_type=vuln_type,
                        category=VulnCategory.INJECTION.value if 'injection' in vuln_type else VulnCategory.MISCONFIG.value,
                        severity=severity,
                        line=i+1,
                        snippet=line.strip()[:120],
                        description=f"{desc}: {msg}",
                        remediation=self._get_remediation(vuln_type),
                        cwe_id=cwe,
                        owasp=VulnCategory.INJECTION.value,
                        confidence=0.85
                    ))
    
    def _check_crypto(self, lines: List[str]):
        for i, line in enumerate(lines):
            for pattern, msg, severity in self.CRYPTO_ISSUES:
                if re.search(pattern, line, re.IGNORECASE):
                    self.issues.append(Vulnerability(
                        vuln_type='weak_crypto', category=VulnCategory.CRYPTO.value, severity=severity,
                        line=i+1, snippet=line.strip()[:120], description=f"Weak Cryptography: {msg}",
                        remediation=self._get_crypto_rem(msg), cwe_id='CWE-327', owasp=VulnCategory.CRYPTO.value
                    ))

    
    def _check_auth(self, lines: List[str]):
        for i, line in enumerate(lines):
            for pattern, msg, severity in self.AUTH_ISSUES:
                if severity == 'Info':
                    continue
                if re.search(pattern, line, re.IGNORECASE):
                    self.issues.append(Vulnerability(
                        vuln_type='auth_issue', category=VulnCategory.BROKEN_AUTH.value, severity=severity,
                        line=i+1, snippet=line.strip()[:120], description=f"Authentication: {msg}",
                        remediation='Use secure authentication mechanisms.', cwe_id='CWE-287', owasp=VulnCategory.BROKEN_AUTH.value
                    ))
    
    def _check_session(self, lines: List[str]):
        for i, line in enumerate(lines):
            for pattern, msg, severity in self.SESSION_ISSUES:
                if severity == 'Info':
                    continue
                if re.search(pattern, line, re.IGNORECASE):
                    self.issues.append(Vulnerability(
                        vuln_type='session_issue', category=VulnCategory.BROKEN_AUTH.value, severity=severity,
                        line=i+1, snippet=line.strip()[:120], description=f"Session: {msg}",
                        remediation='Use secure cookie flags.', cwe_id='CWE-384', owasp=VulnCategory.BROKEN_AUTH.value
                    ))
    
    def _check_info_disclosure(self, lines: List[str]):
        for i, line in enumerate(lines):
            for pattern, msg, severity in self.INFO_DISCLOSURE:
                if re.search(pattern, line, re.IGNORECASE):
                    self.issues.append(Vulnerability(
                        vuln_type='info_disclosure', category=VulnCategory.SENSITIVE_DATA.value, severity=severity,
                        line=i+1, snippet=line.strip()[:120], description=f"Information Disclosure: {msg}",
                        remediation='Handle errors gracefully.', cwe_id='CWE-200', owasp=VulnCategory.SENSITIVE_DATA.value
                    ))
    
    def _check_secrets(self, lines: List[str]):
        for i, line in enumerate(lines):
            if re.search(r'(test|example|placeholder|YOUR_)', line, re.IGNORECASE):
                continue
            for pattern, msg in self.SECRETS:
                if re.search(pattern, line, re.IGNORECASE):
                    self.issues.append(Vulnerability(
                        vuln_type='hardcoded_secret', category=VulnCategory.CRYPTO.value, severity='High',
                        line=i+1, snippet=re.sub(r'"[^"]{4}([^"]*)"', r'"****\1"', line.strip()[:100]),
                        description=f"Hardcoded Secret: {msg}", remediation='Use environment variables or vault.',
                        cwe_id='CWE-798', owasp=VulnCategory.CRYPTO.value
                    ))
    
    def _check_log_injection(self, lines: List[str]):
        for i, line in enumerate(lines):
            for pattern, msg, severity in self.LOG_INJECTION:
                if re.search(pattern, line, re.IGNORECASE):
                    self.issues.append(Vulnerability(
                        vuln_type='log_injection', category=VulnCategory.LOGGING.value, severity=severity,
                        line=i+1, snippet=line.strip()[:120], description=f"Log Injection: {msg}",
                        remediation='Sanitize log messages.', cwe_id='CWE-117', owasp=VulnCategory.LOGGING.value
                    ))
    
    def _check_dos(self, lines: List[str]):
        for i, line in enumerate(lines):
            for pattern, msg, severity in self.DOS:
                if re.search(pattern, line, re.IGNORECASE):
                    self.issues.append(Vulnerability(
                        vuln_type='denial_of_service', category=VulnCategory.MISCONFIG.value, severity=severity,
                        line=i+1, snippet=line.strip()[:120], description=f"DoS Risk: {msg}",
                        remediation='Implement resource limits.', cwe_id='CWE-400', owasp=VulnCategory.MISCONFIG.value
                    ))
    
    def _check_business_logic(self, lines: List[str]):
        for i, line in enumerate(lines):
            for pattern, msg, severity in self.BUSINESS_LOGIC:
                if re.search(pattern, line, re.IGNORECASE):
                    self.issues.append(Vulnerability(
                        vuln_type='business_logic', category=VulnCategory.BUSINESS_LOGIC.value, severity=severity,
                        line=i+1, snippet=line.strip()[:120], description=f"Business Logic: {msg}",
                        remediation='Validate business rules server-side.', cwe_id='CWE-840', owasp=VulnCategory.BROKEN_ACCESS.value
                    ))
    
    def _check_android(self, lines: List[str]):
        for i, line in enumerate(lines):
            for pattern, msg, severity, cwe in self.ANDROID:
                if cwe and re.search(pattern, line, re.IGNORECASE):
                    self.issues.append(Vulnerability(
                        vuln_type='android_security', category=VulnCategory.MISCONFIG.value, severity=severity,
                        line=i+1, snippet=line.strip()[:120], description=f"Android: {msg}",
                        remediation='Follow Android security best practices.', cwe_id=cwe, owasp=VulnCategory.MISCONFIG.value
                    ))
    
    def _check_spring(self, lines: List[str]):
        for i, line in enumerate(lines):
            for pattern, msg, severity, cwe in self.SPRING:
                if cwe and re.search(pattern, line, re.IGNORECASE):
                    self.issues.append(Vulnerability(
                        vuln_type='spring_security', category=VulnCategory.MISCONFIG.value, severity=severity,
                        line=i+1, snippet=line.strip()[:120], description=f"Spring: {msg}",
                        remediation='Follow Spring Security best practices.', cwe_id=cwe, owasp=VulnCategory.MISCONFIG.value
                    ))
    
    def _get_remediation(self, vuln_type: str) -> str:
        return {
            'sql_injection': 'Use PreparedStatement with parameterized queries.',
            'command_injection': 'Avoid Runtime.exec(). Use ProcessBuilder with fixed args.',
            'path_traversal': 'Validate paths. Use getCanonicalPath().',
            'xss': 'Use OWASP Encoder. Set Content-Security-Policy.',
            'xxe': 'Disable DTD and external entities.',
            'ssrf': 'Whitelist allowed URLs. Block internal IPs.',
            'ldap_injection': 'Use LDAP parameterized queries.',
            'xpath_injection': 'Use parameterized XPath.',
            'template_injection': 'Sandbox template engines. Validate input.',
            'expression_injection': 'Never evaluate user input in expressions.',
            'race_condition': 'Use proper synchronization.',
            'null_dereference': 'Use Optional or null checks.',
            'integer_overflow': 'Use Math.addExact/multiplyExact.',
            'resource_leak': 'Use try-with-resources.',
            'deserialization': 'Never deserialize untrusted data.',
            'input_validation': 'Add @Valid and validation annotations.',
        }.get(vuln_type, 'Review and fix security issue.')
    
    def _get_crypto_rem(self, msg: str) -> str:
        if 'DES' in msg or 'RC' in msg: return 'Use AES-256-GCM.'
        if 'ECB' in msg: return 'Use GCM or CBC with random IV.'
        if 'MD5' in msg or 'SHA1' in msg: return 'Use SHA-256+. Use bcrypt for passwords.'
        if 'Random' in msg: return 'Use SecureRandom.'
        return 'Use modern cryptography.'
    
    def _to_dict(self, v: Vulnerability, filename: str) -> Dict:
        return {
            'type': v.vuln_type, 'category': v.category, 'severity': v.severity, 'line': v.line,
            'snippet': v.snippet, 'description': v.description, 'remediation': v.remediation,
            'cwe_id': v.cwe_id, 'owasp': v.owasp, 'confidence': v.confidence, 'file': filename,
            'language': 'java', 'scanner': 'java_analyzer_v3'
        }


def scan_java(code: str, filename: str = "") -> List[Dict]:
    return JavaAnalyzer().scan(code, filename)
