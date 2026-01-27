# SASTify - Complete Product Documentation

## Executive Summary

**SASTify** is an enterprise-grade Static Application Security Testing (SAST) tool designed for modern development workflows. It combines traditional pattern matching with advanced AST-based analysis and cross-file taint tracking to provide comprehensive vulnerability detection across 8+ programming languages.

---

## Table of Contents

1. [Product Overview](#product-overview)
2. [Architecture](#architecture)
3. [Supported Languages](#supported-languages)
4. [Detection Capabilities](#detection-capabilities)
5. [Analysis Engines](#analysis-engines)
6. [API Reference](#api-reference)
7. [CLI Reference](#cli-reference)
8. [Output Formats](#output-formats)
9. [CI/CD Integration](#cicd-integration)
10. [Configuration](#configuration)
11. [Vulnerability Categories](#vulnerability-categories)
12. [Technical Specifications](#technical-specifications)

---

## Product Overview

### What is SASTify?

SASTify is a security-focused static code analyzer that identifies vulnerabilities before code reaches production. Unlike simple pattern-matching tools, SASTify performs:

- **AST-Based Analysis** - Parses actual code syntax trees for accurate detection
- **Taint Tracking** - Follows user input through data flows to find injection vulnerabilities
- **Cross-File Analysis** - Detects vulnerabilities that span multiple files
- **Semantic Understanding** - Understands code context, not just text patterns

### Key Differentiators

| Feature | SASTify | Basic SAST Tools |
|---------|---------|------------------|
| AST Parsing | ✅ Real syntax trees | ❌ Regex only |
| Taint Tracking | ✅ Multi-file | ❌ None |
| False Positive Reduction | ✅ Context-aware | ❌ High FP rate |
| Mobile Security | ✅ Swift, Kotlin, Dart | ❌ Limited |
| CI/CD Ready | ✅ SARIF, JSON, GitHub Actions | Partial |

---

## Architecture

### High-Level Architecture

```
┌───────────────────────────────────────────────────────────────────┐
│                         SASTify Pipeline                           │
├───────────────────────────────────────────────────────────────────┤
│                                                                    │
│  ┌──────────┐   ┌──────────────┐   ┌──────────────┐              │
│  │  Source  │──▶│   Parsing    │──▶│  AST/Taint   │              │
│  │  Code    │   │  (per-lang)  │   │   Analysis   │              │
│  └──────────┘   └──────────────┘   └──────────────┘              │
│                                           │                        │
│                   ┌───────────────────────┼───────────────────┐   │
│                   ▼                       ▼                    ▼   │
│            ┌─────────────┐    ┌─────────────────┐    ┌──────────┐ │
│            │ Single-File │    │  Cross-File     │    │ Pattern  │ │
│            │ AST Scan    │    │  Taint Engine   │    │ Matching │ │
│            └─────────────┘    └─────────────────┘    └──────────┘ │
│                   │                       │                    │   │
│                   └───────────────────────┼───────────────────┘   │
│                                           ▼                        │
│                                 ┌──────────────────┐              │
│                                 │   Aggregation &   │              │
│                                 │   Deduplication   │              │
│                                 └──────────────────┘              │
│                                           │                        │
│                   ┌───────────────────────┼───────────────────┐   │
│                   ▼                       ▼                    ▼   │
│            ┌─────────────┐    ┌─────────────────┐    ┌──────────┐ │
│            │    JSON     │    │     SARIF       │    │   HTML   │ │
│            │   Output    │    │    Output       │    │  Report  │ │
│            └─────────────┘    └─────────────────┘    └──────────┘ │
│                                                                    │
└───────────────────────────────────────────────────────────────────┘
```

### Component Structure

```
Backend/
├── main.py                    # FastAPI REST API server
├── cli.py                     # Command-line interface
├── enhanced_rule_engine.py    # Core scanning engine (84KB)
│
├── AST Scanners (Language-Specific)
│   ├── swift_ast_scanner.py   # Swift/iOS with tree-sitter
│   ├── kotlin_ast_scanner.py  # Kotlin/Android with tree-sitter
│   ├── dart_ast_scanner.py    # Dart/Flutter with tree-sitter
│   ├── java_analyzer.py       # Java analyzer
│   ├── php_analyzer.py        # PHP analyzer
│   └── typescript_analyzer.py # TypeScript analyzer
│
├── Cross-File Analysis
│   ├── project_analyzer.py    # Project indexing
│   ├── call_graph.py          # Inter-procedural call graph
│   ├── function_summary.py    # Function taint summaries
│   ├── cross_file_taint.py    # Cross-file taint propagation
│   └── dataflow_graph.py      # Control/Data flow graphs
│
├── Output Formatters
│   ├── sarif_formatter.py     # SARIF 2.1.0 output
│   └── (HTML, JSON, Table built into CLI)
│
└── Supporting Modules
    ├── auth.py                # API authentication
    ├── database.py            # Scan result storage
    ├── deepseek_api.py        # AI-powered analysis
    └── false_positive_detector.py
```

---

## Supported Languages

### Full AST Analysis (Deep Detection)

| Language | Parser | AST Scanner | Taint Tracking |
|----------|--------|-------------|----------------|
| **Python** | `ast` module | `PythonASTScanner` | ✅ Full |
| **JavaScript** | `esprima` | `JavascriptASTScanner` | ✅ Full |
| **Swift** | `tree-sitter` | `SwiftASTScanner` | ✅ Full |
| **Kotlin** | `tree-sitter` | `KotlinASTScanner` | ✅ Full |
| **Dart** | `tree-sitter` | `DartASTScanner` | ✅ Full |

### Pattern-Based Analysis

| Language | Analyzer | Rule Count |
|----------|----------|------------|
| **Java** | `JavaAnalyzer` | 200+ rules |
| **PHP** | `PHPAnalyzer` | 150+ rules |
| **TypeScript** | `TypeScriptAnalyzer` | 100+ rules |

### File Extension Mapping

```python
{
    '.py': 'python',
    '.js': 'javascript',
    '.jsx': 'javascript',
    '.ts': 'typescript',
    '.tsx': 'typescript',
    '.swift': 'swift',
    '.kt': 'kotlin',
    '.dart': 'dart',
    '.java': 'java',
    '.php': 'php'
}
```

---

## Detection Capabilities

### Vulnerability Categories

SASTify detects **50+ vulnerability types** across these categories:

#### Injection Vulnerabilities
| Type | CWE | Description |
|------|-----|-------------|
| SQL Injection | CWE-89 | Unparameterized database queries |
| Command Injection | CWE-78 | OS command execution with user input |
| Code Injection | CWE-94 | Dynamic code evaluation (eval, exec) |
| XSS | CWE-79 | Cross-site scripting |
| LDAP Injection | CWE-90 | LDAP query manipulation |
| XPath Injection | CWE-91 | XPath query manipulation |
| Template Injection | CWE-1336 | Server-side template injection |

#### Cryptographic Issues
| Type | CWE | Description |
|------|-----|-------------|
| Weak Hash | CWE-328 | MD5, SHA1 for passwords |
| Weak Cipher | CWE-327 | DES, 3DES, RC4 usage |
| ECB Mode | CWE-327 | Electronic Codebook mode |
| Hardcoded Key | CWE-321 | Static encryption keys |
| Insecure Random | CWE-338 | Predictable random numbers |

#### Authentication & Authorization
| Type | CWE | Description |
|------|-----|-------------|
| Hardcoded Credentials | CWE-798 | Passwords in source code |
| Missing Auth | CWE-306 | Unprotected endpoints |
| Weak Password | CWE-521 | Insufficient password requirements |
| Session Fixation | CWE-384 | Session management issues |

#### Data Exposure
| Type | CWE | Description |
|------|-----|-------------|
| Information Disclosure | CWE-200 | Sensitive data in logs/errors |
| Insecure Storage | CWE-312 | Unencrypted sensitive data |
| Path Traversal | CWE-22 | Directory traversal attacks |
| SSRF | CWE-918 | Server-side request forgery |

#### Mobile-Specific (iOS/Android/Flutter)
| Type | CWE | Platform |
|------|-----|----------|
| Insecure Keychain | CWE-311 | iOS |
| ATS Disabled | CWE-319 | iOS |
| Exported Components | CWE-926 | Android |
| WebView JavaScript | CWE-749 | All |
| Clipboard Secrets | CWE-200 | All |
| Platform Channel Injection | CWE-78 | Flutter |

---

## Analysis Engines

### 1. TaintTracker

The core taint tracking engine that identifies:
- **Sources** - Where untrusted data enters (user input, network, files)
- **Sinks** - Where dangerous operations occur (SQL, exec, eval)
- **Sanitizers** - Functions that clean data

```python
# Example: TaintTracker configuration
taint_tracker = TaintTracker()

# Python sources
sources = taint_tracker.get_all_sources('python')
# -> {'request': ['request.args', 'request.form', 'request.json'],
#     'file': ['open', 'read', 'readline'], ...}

# Python sinks
sinks = taint_tracker.get_all_sinks('python')
# -> {'sql_injection': ['cursor.execute', 'db.execute'],
#     'command_injection': ['os.system', 'subprocess.call'], ...}
```

### 2. PythonASTScanner

Full AST analysis for Python code:

```python
scanner = PythonASTScanner(taint_tracker)
issues = scanner.scan(code)

# Detects:
# - SQL injection via f-strings, %, +
# - Command injection via os.system, subprocess
# - Code injection via eval, exec
# - Hardcoded secrets in assignments
# - Insecure deserialization (pickle.loads)
# - Weak cryptography (MD5, SHA1, DES)
# - SSRF via requests library
# - Disabled SSL verification
```

### 3. JavascriptASTScanner

Full AST analysis for JavaScript/Node.js:

```python
scanner = JavascriptASTScanner(taint_tracker)
issues = scanner.scan(code)

# Detects:
# - DOM XSS (innerHTML, document.write)
# - SQL injection (template literals, concatenation)
# - Command injection (child_process.exec)
# - Prototype pollution (Object.assign, _.merge)
# - eval() and Function() usage
# - Express route vulnerabilities
```

### 4. Mobile AST Scanners (Tree-Sitter)

Real AST parsing for mobile languages:

```python
# Swift/iOS
swift_scanner = SwiftASTScanner()
issues = swift_scanner.scan(swift_code)
# -> Keychain, ATS, WebView, biometrics, hardcoded secrets

# Kotlin/Android
kotlin_scanner = KotlinASTScanner()
issues = kotlin_scanner.scan(kotlin_code)
# -> Intent injection, PendingIntent, WebView, Room SQL, coroutines

# Dart/Flutter
dart_scanner = DartASTScanner()
issues = dart_scanner.scan(dart_code)
# -> Platform channels, sqflite, WebView, deep links
```

### 5. Cross-File Taint Engine

Detects vulnerabilities spanning multiple files:

```
               ┌─────────────────────────────────────────────────────┐
               │              Cross-File Analysis Pipeline            │
               └─────────────────────────────────────────────────────┘
                                        │
          ┌─────────────────────────────┼─────────────────────────────┐
          ▼                             ▼                             ▼
   ┌─────────────┐            ┌─────────────────┐            ┌─────────────┐
   │   Project   │            │   Call Graph    │            │  Function   │
   │   Indexer   │            │    Builder      │            │  Summaries  │
   └─────────────┘            └─────────────────┘            └─────────────┘
          │                             │                             │
          │  Files, functions,          │  Who calls whom             │ Taint flows
          │  imports, exports           │  across files               │ per function
          │                             │                             │
          └─────────────────────────────┼─────────────────────────────┘
                                        ▼
                              ┌─────────────────────┐
                              │  Worklist Algorithm  │
                              │  (Taint Propagation) │
                              └─────────────────────┘
                                        │
                                        ▼
                              ┌─────────────────────┐
                              │  Cross-File Vulns   │
                              │  (source→sink path) │
                              └─────────────────────┘
```

Example detection:
```
routes.py:15 → services/user.py:42 → database.py:88
   ▲                    │                    ▲
   │                    │                    │
   request.form['id']   │                    cursor.execute(query)
   (TAINT SOURCE)       │                    (TAINT SINK)
                        │
                 id = get_user_id(data)
                 (TAINT PROPAGATION)
```

### 6. DataflowEnhancedScanner

Control Flow Graph (CFG) and Data Flow Graph (DFG) analysis:

```python
scanner = DataflowEnhancedScanner()
issues = scanner.scan_file(code, filename)

# Provides:
# - Basic block construction
# - Reaching definitions analysis
# - Definition-use chains
# - Alias tracking
# - Interprocedural taint flow
```

---

## API Reference

### REST API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/scan` | POST | Scan single file |
| `/scan/project` | POST | Scan entire project |
| `/scan/batch` | POST | Scan multiple files |
| `/results/{scan_id}` | GET | Get scan results |
| `/analyze-issue` | POST | AI analysis of issue |
| `/report-false-positive` | POST | Report false positive |
| `/analytics` | GET | Get analytics data |
| `/health` | GET | Health check |

### Scan Request

```json
POST /scan
{
    "code": "cursor.execute('SELECT * FROM users WHERE id=' + user_id)",
    "language": "python",
    "filename": "app.py",
    "user_id": "user123"
}
```

### Scan Response

```json
{
    "scan_id": "abc123",
    "total_issues": 1,
    "critical": 1,
    "high": 0,
    "medium": 0,
    "low": 0,
    "vulnerabilities": [
        {
            "type": "sql_injection",
            "severity": "Critical",
            "line": 1,
            "column": 0,
            "snippet": "cursor.execute('SELECT * FROM users WHERE id=' + user_id)",
            "description": "SQL Injection: Tainted data 'user_id' flows to 'cursor.execute'",
            "cwe_id": "CWE-89",
            "confidence": 0.95,
            "remediation": "Use parameterized queries with placeholders",
            "taint_source": "user_input",
            "taint_sink": "cursor.execute"
        }
    ]
}
```

### Project Scan Request

```json
POST /scan/project
{
    "project_path": "/path/to/project",
    "user_id": "user123"
}
```

---

## CLI Reference

### Installation

```bash
cd Backend
pip install -r requirements.txt
```

### Basic Usage

```bash
# Scan single file
python cli.py path/to/file.py

# Scan directory
python cli.py path/to/project/

# Scan with specific language
python cli.py path/to/project/ --languages python,javascript

# Filter by severity
python cli.py path/to/project/ --severity high,critical

# Output formats
python cli.py path/to/project/ --format json --output results.json
python cli.py path/to/project/ --format sarif --output results.sarif
python cli.py path/to/project/ --format html --output report.html
python cli.py path/to/project/ --format table  # Pretty console output

# Verbose mode
python cli.py path/to/project/ --verbose

# With AI analysis
python cli.py path/to/project/ --ai-analysis --ai-issues 5

# Use config file
python cli.py path/to/project/ --config .sastifyrc.json

# Exclude patterns
python cli.py path/to/project/ --exclude "**/test/**,**/node_modules/**"
```

### Exit Codes

| Code | Meaning |
|------|---------|
| 0 | No vulnerabilities found |
| 1 | Vulnerabilities found (≥1 issue) |
| 2 | Error during scanning |

### Configuration File (.sastifyrc.json)

```json
{
    "severity_threshold": "medium",
    "exclude_patterns": [
        "**/test/**",
        "**/node_modules/**",
        "**/__pycache__/**"
    ],
    "languages": ["python", "javascript", "swift", "kotlin"],
    "output_format": "sarif",
    "output_file": "security-results.sarif",
    "ai_analysis": false
}
```

---

## Output Formats

### 1. JSON

```json
{
    "scan_id": "uuid",
    "timestamp": "2026-01-26T06:00:00Z",
    "files_scanned": 42,
    "total_issues": 15,
    "severity_counts": {
        "critical": 2,
        "high": 5,
        "medium": 6,
        "low": 2
    },
    "vulnerabilities": [...]
}
```

### 2. SARIF 2.1.0

```json
{
    "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
    "version": "2.1.0",
    "runs": [{
        "tool": {
            "driver": {
                "name": "SASTify",
                "version": "1.0.0",
                "rules": [...]
            }
        },
        "results": [...]
    }]
}
```

### 3. HTML Report

Interactive HTML report with:
- Summary dashboard
- Severity breakdown charts
- Filterable vulnerability table
- Code snippets with highlighting
- Remediation guidance

### 4. Table (Console)

```
┌──────────────────────────────────────────────────────────────────────────────┐
│                            SASTify Security Report                            │
├─────────────────┬──────────┬──────┬────────────────────────────────────────────┤
│ Vulnerability   │ Severity │ Line │ File                                       │
├─────────────────┼──────────┼──────┼────────────────────────────────────────────┤
│ sql_injection   │ CRITICAL │   15 │ app/database.py                            │
│ hardcoded_secret│ HIGH     │   42 │ config/settings.py                         │
│ weak_crypto     │ MEDIUM   │   88 │ utils/crypto.py                            │
└─────────────────┴──────────┴──────┴────────────────────────────────────────────┘

Summary: 3 issues found (1 Critical, 1 High, 1 Medium)
```

---

## CI/CD Integration

### GitHub Actions

```yaml
# .github/workflows/security.yml
name: Security Scan

on: [push, pull_request]

jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      
      - name: SASTify Security Scan
        uses: ./
        with:
          path: '.'
          severity: 'high,critical'
          format: 'sarif'
          output: 'results.sarif'
          fail-on-findings: true
      
      - name: Upload SARIF
        uses: github/codeql-action/upload-sarif@v2
        with:
          sarif_file: results.sarif
```

### Docker

```dockerfile
FROM python:3.11-slim

WORKDIR /app
COPY Backend/ ./Backend/
RUN pip install -r Backend/requirements.txt

ENTRYPOINT ["python", "Backend/cli.py"]
```

```bash
# Docker usage
docker build -t sastify .
docker run -v $(pwd):/code sastify /code --format sarif --output /code/results.sarif
```

### GitLab CI

```yaml
security_scan:
  image: python:3.11
  script:
    - pip install -r Backend/requirements.txt
    - python Backend/cli.py . --format json --output gl-sast-report.json
  artifacts:
    reports:
      sast: gl-sast-report.json
```

---

## Vulnerability Categories (Complete List)

### Injection (15 types)
- SQL Injection (CWE-89)
- Command Injection (CWE-78)
- Code Injection (CWE-94)
- XSS - Reflected/Stored/DOM (CWE-79)
- LDAP Injection (CWE-90)
- XPath Injection (CWE-91)
- XML Injection (CWE-91)
- Template Injection (CWE-1336)
- Header Injection (CWE-113)
- Log Injection (CWE-117)
- Intent Injection (CWE-926) [Android]
- WebView Injection (CWE-749) [Mobile]
- Platform Channel Injection [Flutter]
- URL Scheme Injection [iOS]
- Deep Link Injection [Mobile]

### Cryptography (8 types)
- Weak Hash Algorithm (CWE-328)
- Weak Cipher Algorithm (CWE-327)
- ECB Mode Usage (CWE-327)
- Hardcoded Encryption Key (CWE-321)
- Hardcoded IV (CWE-329)
- Insecure Random (CWE-338)
- Small Key Size (CWE-326)
- Deprecated Crypto API (CWE-327)

### Authentication (6 types)
- Hardcoded Password (CWE-798)
- Hardcoded API Key (CWE-798)
- Missing Authentication (CWE-306)
- Weak Password Policy (CWE-521)
- Plaintext Credentials (CWE-256)
- Biometric Bypass [Mobile]

### Data Exposure (8 types)
- Sensitive Data Logging (CWE-532)
- Stack Trace Exposure (CWE-209)
- Debug Mode Enabled (CWE-215)
- Insecure Data Storage (CWE-312)
- Clipboard Secrets (CWE-200)
- Backup Enabled [Android]
- Pasteboard Secrets [iOS]
- Notification Secrets [Mobile]

### Network Security (7 types)
- Cleartext HTTP (CWE-319)
- SSL/TLS Bypass (CWE-295)
- Certificate Pinning Missing
- ATS Disabled [iOS]
- Cleartext Traffic [Android]
- Custom TrustManager [Android]
- HostnameVerifier Bypass

### Mobile-Specific (15 types)
- Exported Component [Android]
- PendingIntent Mutable [Android]
- WebView JavaScript Enabled
- WebView File Access
- Keychain Insecure [iOS]
- UserDefaults Secrets [iOS]
- SharedPreferences Secrets [Android]
- Tapjacking [Android]
- Jailbreak/Root Detection Bypass
- Debuggable Build
- Universal Links Injection [iOS]
- App Clips Security [iOS]
- HealthKit Data Exposure [iOS]
- Platform Channel Security [Flutter]
- sqflite SQL Injection [Flutter]

### Code Quality (5 types)
- Resource Leak (CWE-404)
- Null Dereference (CWE-476)
- Force Unwrap [Swift]
- Null Assertion [Kotlin]
- GlobalScope Usage [Kotlin]

---

## Technical Specifications

### Performance

| Metric | Value |
|--------|-------|
| Lines/second (Python) | ~50,000 |
| Lines/second (JavaScript) | ~45,000 |
| Memory usage (avg) | 200-400 MB |
| Startup time | < 2 seconds |

### Accuracy Metrics

| Metric | Target |
|--------|--------|
| Precision | > 85% |
| Recall | > 90% |
| F1 Score | > 87% |

### Dependencies

```
fastapi==0.109.0       # REST API
uvicorn==0.27.0        # ASGI server
esprima==4.0.1         # JavaScript parser
tree-sitter>=0.20.0    # Mobile language parsing
astroid==2.15.5        # Python AST utilities
requests==2.31.0       # HTTP client
redis==5.0.1           # Caching (optional)
colorama==0.4.6        # CLI colors
jsonschema==4.19.0     # Config validation
```

### System Requirements

- Python 3.9+
- 512 MB RAM minimum
- Linux/macOS/Windows

---

## Roadmap

### Planned Features

- [ ] C/C++ support via tree-sitter
- [ ] Go language support
- [ ] Rust language support
- [ ] SBOM (Software Bill of Materials) generation
- [ ] IDE plugins (VS Code, IntelliJ)
- [ ] Incremental scanning
- [ ] Custom rule authoring UI

---

## License & Support

- **Version**: 1.0.0
- **Documentation**: This document
- **Repository**: SASTify

---

*Generated on 2026-01-26 | SASTify Enterprise SAST Tool*
