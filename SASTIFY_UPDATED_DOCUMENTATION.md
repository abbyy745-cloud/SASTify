# SASTify - Complete Product Documentation (Updated)

> **Version:** 2.0.0  
> **Last Updated:** April 2026  
> **Repository:** [github.com/abbyy745-cloud/SASTify](https://github.com/abbyy745-cloud/SASTify)

---

## 1. Executive Summary

**SASTify** is an enterprise-grade Static Application Security Testing (SAST) tool designed for modern development workflows. It combines traditional pattern matching with advanced AST-based analysis, cross-file taint tracking, and **AI-powered vulnerability analysis** to provide comprehensive vulnerability detection across **8+ programming languages** and **7+ web/mobile frameworks**.

### What's New Since v1.0

| Feature Area | Enhancement |
|---|---|
| **Structured Rule Engines** | 197 new structured security rules across Python (69), JavaScript/TypeScript (65), and Frameworks/Mobile (63) |
| **AI-Powered Analysis** | DeepSeek API integration with concurrent batch processing, fast/full analysis modes |
| **Dual Report Generation** | Premium HTML security report + dedicated AI test case report |
| **Cross-Ruleset Deduplication** | Smart fingerprinting with scanner priority to eliminate duplicate findings |
| **CI/CD Integration** | GitHub Actions workflows with SARIF upload to GitHub Security tab |
| **Library Models** | Taint models for AI, Database, Django, Express, and Flask libraries |
| **Performance Optimization** | Workflow runtime reduced from ~30 minutes to ~5 minutes |
| **Enhanced Reporting** | Precise vulnerability locations, code snippet context, risk scoring/grading |

---

## 2. Product Overview

### What is SASTify?

SASTify is a security-focused static code analyzer that identifies vulnerabilities before code reaches production.

### Key Features

- **AST-Based Analysis:** Parses code syntax trees for accurate detection
- **Taint Tracking:** Follows user input through data flows
- **Cross-File Analysis:** Detects vulnerabilities spanning multiple files
- **Semantic Understanding:** Understands code context
- **Structured Rule Engines:** 197 language-specific security rules with CWE/OWASP mapping
- **AI-Powered Analysis:** DeepSeek API integration for vulnerability confirmation, fix suggestions, and test case generation
- **Dual Report Generation:** Premium interactive HTML security reports + AI-generated test case reports
- **Cross-Ruleset Deduplication:** Smart fingerprinting eliminates duplicate findings across scanners

### Key Differentiators

- Real syntax trees vs. Regex-only tools
- Multi-file taint tracking
- Context-aware false positive reduction
- Comprehensive mobile security (Swift, Kotlin, Dart)
- **197 structured security rules** with CWE IDs and OWASP categories
- **AI-powered vulnerability verification** (DeepSeek integration)
- **Concurrent batch AI analysis** with fast/full modes
- **Dedicated test case report** generation from AI analysis
- CI/CD ready (SARIF, JSON, GitHub Actions)

---

## 3. Architecture

### High-Level Pipeline

```
Source Code → Parsing → Analysis Engines → Aggregation & Deduplication → Output
```

1. **Source Code:** Entry point for analysis
2. **Parsing:** Language-specific parsing to AST
3. **Analysis Engines:**
   - **Structured Rule Engines** (Python, JS/TS, Framework/Mobile) — *NEW*
   - **Single-File AST Scan** (Python AST, Esprima JS AST)
   - **Cross-File Taint Engine** (Worklist algorithm)
   - **Pattern Matching** (Regex-based fallback)
   - **EdTech Domain Rules**
4. **Cross-Ruleset Deduplication** — *NEW*: Smart fingerprinting with ±2 line tolerance and scanner priority
5. **AI Analysis (Optional)** — *NEW*: DeepSeek API with concurrent batch processing
6. **Output Formats:** JSON, SARIF 2.1.0, HTML Report, Table, Test Case Report

### Component Structure

```
SASTify/
├── Backend/
│   ├── cli.py                          # CLI with AI analysis, deduplication, HTML reports
│   ├── main.py                         # FastAPI server
│   ├── enhanced_rule_engine.py         # Core rule engine with AST scanners
│   ├── python_security_rules.py        # 69 Python security rules        [NEW]
│   ├── javascript_security_rules.py    # 65 JS/TS security rules         [NEW]
│   ├── framework_security_rules.py     # 63 Framework/Mobile rules       [NEW]
│   ├── edtech_rules.py                 # EdTech-specific security rules
│   ├── deepseek_api.py                 # AI analysis with batch processing [ENHANCED]
│   ├── test_report_generator.py        # AI test case report              [NEW]
│   ├── sarif_formatter.py              # SARIF 2.1.0 output
│   ├── cross_file_taint.py             # Cross-file taint analysis
│   ├── enhanced_cross_file.py          # Enhanced cross-file analysis
│   ├── false_positive_detector.py      # False positive detection
│   ├── swift_analyzer.py               # Swift/iOS AST scanner
│   ├── kotlin_analyzer.py              # Kotlin/Android AST scanner
│   ├── dart_analyzer.py                # Dart/Flutter AST scanner
│   ├── java_analyzer.py                # Java AST scanner
│   ├── php_analyzer.py                 # PHP AST scanner
│   ├── typescript_analyzer.py          # TypeScript AST scanner
│   ├── dataflow_graph.py               # CFG/DFG analysis
│   ├── call_graph.py                   # Call graph builder
│   ├── function_summary.py             # Function summary analysis
│   ├── tree_sitter_scanner.py          # Tree-sitter based scanning
│   ├── core/
│   │   ├── cache.py                    # Scan result caching
│   │   ├── scanners.py                 # Core scanner infrastructure
│   │   ├── severity.py                 # Severity classification
│   │   ├── taint_graph.py              # Taint flow graph
│   │   ├── rule_loader.py              # YAML rule loader
│   │   └── project_analyzer.py         # Project-level analysis
│   ├── rules/
│   │   └── default_rules.yaml          # YAML-based taint rules
│   ├── library_models/                                                    [NEW]
│   │   ├── ai_model.py                 # AI library taint models
│   │   ├── database_model.py           # Database library taint models
│   │   ├── django_model.py             # Django framework taint models
│   │   ├── express_model.py            # Express.js taint models
│   │   └── flask_model.py              # Flask framework taint models
│   └── parsers/
│       └── parse_frontend.js           # Frontend framework parser
├── .github/workflows/                                                     [NEW]
│   ├── sastify-scan.yml                # GitHub Actions scan workflow
│   └── self-scan.yml                   # Self-scanning workflow
├── action.yml                          # GitHub Action definition          [NEW]
├── Dockerfile                          # Docker containerization
└── Frontend/                           # Web UI
```

### Scanning Pipeline (Detailed)

```
┌─────────────────────────────────────────────────────────────────┐
│                         CLI Entry Point                          │
│  (cli.py → collect files → determine language per file)         │
└──────────────────────────┬──────────────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────────────┐
│                    Per-File Scanning                             │
│  enhanced_rule_engine.scan_with_ast_analysis(code, lang, file)  │
│                                                                  │
│  ┌──────────────────────────────────────────────────────┐       │
│  │ 1. Structured Rule Engines (run FIRST)        [NEW]  │       │
│  │    ├── PythonRuleEngine      (69 rules, .py)         │       │
│  │    ├── JavaScriptRuleEngine  (65 rules, .js/.ts)     │       │
│  │    └── FrameworkRuleEngine   (63 rules, all langs)   │       │
│  ├──────────────────────────────────────────────────────┤       │
│  │ 2. AST-Based Taint Analysis                          │       │
│  │    ├── PythonASTScanner  (ast module)                │       │
│  │    └── JavascriptASTScanner  (esprima)               │       │
│  ├──────────────────────────────────────────────────────┤       │
│  │ 3. EdTech Domain Rules                               │       │
│  │    └── EdTechRuleEngine (education-specific)         │       │
│  ├──────────────────────────────────────────────────────┤       │
│  │ 4. Pattern Matching (fallback)                       │       │
│  └──────────────────────────────────────────────────────┘       │
└──────────────────────────┬──────────────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────────────┐
│              Cross-Ruleset Deduplication              [NEW]      │
│                                                                  │
│  • Groups findings by (file, normalized_category, line ±2)      │
│  • Keeps highest-priority scanner's detection                   │
│  • Merges metadata (rule_ids, scanners, confidence)             │
│  • Scanner priority: edtech(100) > structured(95) > AST(90)    │
│    > pattern(50)                                                │
└──────────────────────────┬──────────────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────────────┐
│              AI Analysis (Optional)                  [NEW]      │
│                                                                  │
│  • DeepSeek API with concurrent batch processing (5 workers)    │
│  • Fast mode: concise prompts, 600 max tokens                  │
│  • Full mode: comprehensive prompts, 1200 max tokens            │
│  • Retry logic with exponential backoff (3 retries, 45s timeout)│
│  • Response sanitization (removes eval/exec from AI output)     │
│  • AI enriches each finding with:                               │
│    - Confirmation (is_confirmed_vulnerability)                  │
│    - Detailed explanation & vulnerability summary               │
│    - Attack scenarios with example payloads                     │
│    - Impact analysis (CIA triad + compliance)                   │
│    - Fix suggestions (production-ready code)                    │
│    - Test case suggestions (unit, security, integration)        │
│    - Security references (CWE, OWASP)                          │
└──────────────────────────┬──────────────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────────────┐
│                     Output Generation                           │
│                                                                  │
│  ├── JSON (machine-readable)                                    │
│  ├── SARIF 2.1.0 (GitHub Security tab upload)                   │
│  ├── HTML Report (premium interactive dashboard)                │
│  ├── Table (colored console output)                             │
│  └── Test Case Report (dedicated AI test case HTML)    [NEW]    │
└─────────────────────────────────────────────────────────────────┘
```

---

## 4. Supported Languages & Frameworks

### Languages

| Language | Analysis Type | File Extensions | Structured Rules |
|---|---|---|---|
| Python | Full AST + Structured Rules | `.py` | 69 rules (PY-001 to PY-069) |
| JavaScript | Full AST + Structured Rules | `.js`, `.jsx` | 65 rules (JS-001 to JS-065) |
| TypeScript | AST + Structured Rules | `.ts`, `.tsx` | 65 rules (shared with JS) |
| Swift | Tree-sitter AST | `.swift` | 10 framework rules (FW-034 to FW-043) |
| Kotlin | Tree-sitter AST | `.kt`, `.kts` | 10 framework rules (FW-044 to FW-053) |
| Dart | Tree-sitter AST | `.dart` | 10 framework rules (FW-054 to FW-063) |
| Java | Pattern-Based | `.java` | — |
| PHP | Pattern-Based | `.php` | — |

### Frameworks (NEW)

| Framework | Rules | Rule IDs |
|---|---|---|
| React | 5 rules | FW-001 to FW-005 |
| Vue.js | 5 rules | FW-006 to FW-010 |
| Angular | 5 rules | FW-011 to FW-015 |
| Flask | 5 rules | FW-016 to FW-020 |
| Django | 5 rules | FW-021 to FW-025 |
| Express.js | 5 rules | FW-026 to FW-030 |
| Next.js | 3 rules | FW-031 to FW-033 |

---

## 5. Detection Capabilities

### Total Rule Count: 197+ Structured Rules + AST + Pattern Rules

### Python Security Rules (69 Rules — NEW)

| Category | Rule IDs | Count | Example |
|---|---|---|---|
| SQL Injection | PY-001 to PY-004 | 4 | Format string, concatenation, % formatting, SQLite |
| Code Injection | PY-005 to PY-009 | 5 | eval(), exec(), compile(), __import__, getattr |
| Hardcoded Secrets | PY-010 to PY-013 | 4 | Passwords, API keys, secret keys, AWS credentials |
| Insecure Deserialization | PY-014 to PY-018 | 5 | pickle, YAML, marshal, JSON object_hook |
| Path Traversal | PY-019 to PY-022 | 4 | open() concat, os.path.join, ../ sequences |
| Shell Injection | PY-023 to PY-027 | 5 | os.system, os.popen, subprocess, commands |
| XSS & Templates | PY-028 to PY-030 | 3 | render_template_string, Django Template, mark_safe |
| Insecure Randomness | PY-031 to PY-033 | 3 | random.randint, random.choice, random.random |
| SSL/TLS | PY-034 to PY-035 | 2 | verify=False, unverified context |
| Information Exposure | PY-036 to PY-038 | 3 | Password in print/log, debug mode |
| File Permissions | PY-039 to PY-040 | 2 | 0o777, 0o666 |
| Weak Cryptography | PY-041 to PY-043 | 3 | MD5, SHA1, crypt |
| SSRF | PY-044 to PY-045 | 2 | requests, urllib |
| JWT Security | PY-046 to PY-047 | 2 | None algorithm, Flask debug |
| Session Security | PY-048 to PY-049 | 2 | HttpOnly, Secure flags |
| IDOR | PY-050 to PY-051 | 2 | Direct object query, get_object_or_404 |
| Mass Assignment | PY-052 to PY-053 | 2 | Dict unpacking, update(**) |
| Open Redirect | PY-054 to PY-055 | 2 | Request args, url_for |
| SSTI | PY-056 to PY-058 | 3 | render_template_string, Template(), from_string |
| LDAP Injection | PY-059 to PY-060 | 2 | LDAP operations, filter concatenation |
| XXE | PY-061 to PY-064 | 4 | lxml, etree, minidom, SAX |
| File Upload | PY-065 to PY-066 | 2 | Insecure save, unrestricted extensions |
| Rate Limiting | PY-067 | 1 | Missing on auth endpoints |
| Timing Attack | PY-068 to PY-069 | 2 | Password/token comparison |

### JavaScript/TypeScript Security Rules (65 Rules — NEW)

| Category | Rule IDs | Count | Example |
|---|---|---|---|
| SQL Injection | JS-001 to JS-004 | 4 | Template literal, concatenation, executeSql, MySQL |
| NoSQL Injection | JS-005 to JS-006 | 2 | $where, $regex with user input |
| XSS | JS-007 to JS-014 | 8 | innerHTML, outerHTML, document.write, eval, setTimeout/setInterval strings, Function constructor |
| Hardcoded Secrets | JS-015 to JS-017 | 3 | Password/secret vars, long secret strings, JWT secrets |
| Insecure Deserialization | JS-018 to JS-019 | 2 | JSON.parse, eval deserialization |
| Path Traversal | JS-020 to JS-023 | 4 | fs.readFile, fs.writeFile, dynamic require, ../ |
| Shell/Code Injection | JS-024 to JS-028 | 5 | child_process exec/spawn/execFile, vm contexts |
| Prototype Pollution | JS-029 to JS-031 | 3 | __proto__, constructor.prototype, Object.assign |
| Insecure Communication | JS-032 to JS-035 | 4 | HTTP without TLS, insecure WebSocket, SSL disabled |
| Information Exposure | JS-036 to JS-038 | 3 | Password in console, secret in error, stack trace in response |
| Regex DoS | JS-039 to JS-040 | 2 | Repeated groups (+/*) |
| CORS | JS-041 to JS-042 | 2 | Wildcard origin, Express CORS wildcard |
| Cookie Security | JS-043 to JS-044 | 2 | Missing HttpOnly, missing Secure flag |
| SSRF | JS-045 to JS-046 | 2 | HTTP client, fetch() |
| JWT Security | JS-047 | 1 | None algorithm |
| IDOR | JS-048 to JS-049 | 2 | Direct DB lookup, unsanitized params |
| Mass Assignment | JS-050 to JS-052 | 3 | Object.assign, spread operator, constructor |
| Open Redirect | JS-053 to JS-054 | 2 | res.redirect, window.location |
| SSTI | JS-055 to JS-057 | 3 | EJS render, Pug render, Handlebars compile |
| XXE | JS-058 to JS-059 | 2 | XML parser, DOMParser |
| File Upload | JS-060 to JS-061 | 2 | Multer without filter, unvalidated upload |
| Rate Limiting | JS-062 | 1 | Missing on auth endpoints |
| Timing Attack | JS-063 to JS-064 | 2 | Password/token comparison |
| Debug Config | JS-065 | 1 | NODE_ENV development check |

### Framework & Mobile Security Rules (63 Rules — NEW)

| Framework | Rule IDs | Count | Key Detections |
|---|---|---|---|
| **React** | FW-001 to FW-005 | 5 | dangerouslySetInnerHTML, unsafe lifecycle methods, javascript: href, unescaped JSX, createRef DOM manipulation |
| **Vue.js** | FW-006 to FW-010 | 5 | v-html directive, Vue.compile(), unvalidated props, runtime template compilation, SSR XSS |
| **Angular** | FW-011 to FW-015 | 5 | bypassSecurityTrust, innerHTML binding, disabled route guards, nativeElement access, missing interceptors |
| **Flask** | FW-016 to FW-020 | 5 | Debug mode, hardcoded secret key, CSRF disabled, send_file traversal, autoescape disabled |
| **Django** | FW-021 to FW-025 | 5 | mark_safe XSS, raw SQL, DEBUG=True, empty ALLOWED_HOSTS, \|safe filter |
| **Express.js** | FW-026 to FW-030 | 5 | Missing Helmet, body parser size limit, hardcoded session secret, CORS wildcard, static dotfiles |
| **Next.js** | FW-031 to FW-033 | 3 | API route without auth, env var exposure, getServerSideProps data leak |
| **Swift/iOS** | FW-034 to FW-043 | 10 | UserDefaults secrets, ATS disabled, WebView JS, biometric bypass, clipboard exposure, URL scheme, weak crypto, missing cert pinning, Keychain access control, screenshot protection |
| **Kotlin/Android** | FW-044 to FW-053 | 10 | SharedPreferences secrets, WebView JS injection, exported components, rawQuery SQL injection, intent data validation, cleartext traffic, root detection, weak crypto, insecure random, WebView file access |
| **Dart/Flutter** | FW-054 to FW-063 | 10 | SharedPreferences secrets, hardcoded API key, rawQuery SQL injection, WebView JS, missing cert pinning, debug mode, platform channel validation, insecure HTTP, weak random, deep link validation |

### Rule Structure

Each structured rule includes:

```python
@dataclass
class SecurityRule:
    id: str                    # e.g., "PY-001", "JS-015", "FW-034"
    name: str                  # Human-readable rule name
    description: str           # Detailed description
    category: RuleCategory     # Categorization enum
    severity: Severity         # Critical / High / Medium / Low / Info
    pattern: str               # Regex detection pattern
    remediation: str           # How to fix the issue
    cwe_id: Optional[str]      # CWE identifier (e.g., "CWE-89")
    owasp_category: Optional[str]  # OWASP Top 10 mapping
    confidence: float          # Detection confidence (0.0 - 1.0)
    languages: List[str]       # Applicable languages (Framework rules only)
```

---

## 6. Analysis Engines

### 6.1 Structured Rule Engines (NEW)

Three dedicated rule engines run **before** the pattern-based fallback:

- **PythonRuleEngine** (`python_security_rules.py`): 69 rules covering 24 vulnerability categories
- **JavaScriptRuleEngine** (`javascript_security_rules.py`): 65 rules covering 24 vulnerability categories
- **FrameworkRuleEngine** (`framework_security_rules.py`): 63 rules for 7 web frameworks + 3 mobile platforms

Each engine:
- Scans code line-by-line against compiled regex patterns
- Provides **snippet context** (±3 lines around the finding)
- Includes CWE and OWASP mappings for every rule
- Returns structured findings with confidence scores

### 6.2 TaintTracker

Manages sources (user input), sinks (dangerous functions), and sanitizers. Loads rules from YAML configuration (`rules/default_rules.yaml`) with fallback to embedded defaults.

**Sources tracked:**
- Python: Flask, Django, FastAPI, stdlib inputs
- JavaScript: Express, browser DOM, Node.js inputs
- EdTech: Student data, exam data, AI data

### 6.3 Python/JS AST Scanners

- **PythonASTScanner**: Uses Python `ast` module for full syntax analysis including:
  - Taint propagation through assignments
  - Hardcoded secret detection in AST assignments
  - Debug mode detection
  - Insecure deserialization (pickle, yaml, marshal, shelve, jsonpickle)
  - Weak cryptography (MD5, SHA1, crypt)
  - SSRF with dynamic URL detection
  - SSL verification bypass
  - Unprotected route detection

- **JavascriptASTScanner**: Uses `esprima` for full syntax analysis including:
  - ES6 module support (parseModule with parseScript fallback)
  - Hardcoded secret detection in variable declarations and assignments
  - Prototype pollution (Object.assign, _.merge, direct __proto__ assignment)
  - NoSQL injection (MongoDB query operators)
  - JWT weaknesses (none algorithm)
  - Proctoring evasion detection (EdTech)

### 6.4 Mobile Scanners (Tree-Sitter)

Real AST parsing for native mobile and Flutter apps:
- **Swift Analyzer**: iOS security (Keychain, ATS, WebView, biometric auth)
- **Kotlin Analyzer**: Android security (SharedPreferences, WebView, intents)
- **Dart Analyzer**: Flutter security (platform channels, storage, HTTP)

### 6.5 Cross-File Taint Engine

Uses a **Worklist Algorithm** to propagate taint across file boundaries (e.g., from a route in `app.py` to a database call in `db.py`).

### 6.6 DataflowEnhancedScanner

Control Flow Graph (CFG) and Data Flow Graph (DFG) analysis for advanced data flow tracking.

### 6.7 Library Models (NEW)

Pre-built taint models for popular libraries in `library_models/`:

| Model | File | Purpose |
|---|---|---|
| AI Libraries | `ai_model.py` | Taint models for OpenAI, LangChain, and other AI/ML libraries |
| Database | `database_model.py` | Taint models for SQLAlchemy, psycopg2, PyMongo, etc. |
| Django | `django_model.py` | Django ORM, views, forms, middleware sources/sinks |
| Express | `express_model.py` | Express.js middleware, routing, response handling |
| Flask | `flask_model.py` | Flask routing, templates, session handling |

---

## 7. Cross-Ruleset Deduplication (NEW)

SASTify implements a sophisticated deduplication system to eliminate redundant findings across multiple scanners:

### How It Works

1. **Normalization**: Vulnerability types are mapped to broader categories via `VULN_CATEGORY_MAP` (e.g., `pii_leakage_log`, `pii_leakage_log_node`, `Student PII in Logs` → `pii_exposure`)
2. **Grouping**: Findings are grouped by `(file, normalized_category, line ±2)`
3. **Priority Selection**: Within each group, the highest-priority scanner's detection is kept
4. **Metadata Merging**: Rule IDs, scanners, confidence scores, and snippet contexts are merged from all duplicates

### Scanner Priority Order

| Scanner | Priority | Description |
|---|---|---|
| `edtech_rules` | 100 | EdTech-specific domain rules |
| `python_security_rules` | 95 | Python structured rule engine |
| `javascript_security_rules` | 95 | JS/TS structured rule engine |
| `framework_security_rules` | 92 | Framework/Mobile rule engine |
| `ast_taint_analysis` | 90 | AST-based taint tracking |
| `ast_logic_analysis` | 85 | AST logic analysis |
| `ast_sink_detection` | 80 | AST sink detection |
| `typescript_analyzer` | 75 | TypeScript analyzer |
| `frontend_ast` | 70 | Frontend AST parser |
| `pattern_matching` | 50 | Regex pattern fallback |

---

## 8. AI-Powered Analysis (NEW/ENHANCED)

### DeepSeek API Integration

SASTify integrates with the DeepSeek API for AI-powered vulnerability analysis:

- **Model**: `deepseek-coder`
- **Two Analysis Modes**:
  - **Fast Mode**: Concise prompts, 600 max tokens — optimized for CI/CD pipelines
  - **Full Mode**: Comprehensive prompts, 1200 max tokens — detailed security auditing
- **Concurrent Processing**: `ThreadPoolExecutor` with 5 workers for batch analysis
- **Rate Limiting**: 100ms minimum between requests
- **Retry Logic**: Exponential backoff (3 retries, base delay 2s, timeout 45s)
- **Code Sanitization**: Removes hardcoded secrets before sending to AI
- **Response Sanitization**: Removes eval/exec from AI-generated responses

### AI Analysis Output

For each analyzed vulnerability, the AI provides:

| Field | Description |
|---|---|
| `is_confirmed_vulnerability` | Whether AI confirms the finding |
| `confidence` | AI confidence score (0.0 - 1.0) |
| `risk_level` | Low / Medium / High / Critical |
| `vulnerability_summary` | One-line summary |
| `detailed_explanation` | Multi-paragraph root cause analysis |
| `attack_scenario` | Attack description, example payloads, attacker goal |
| `impact_analysis` | Confidentiality, Integrity, Availability, Compliance impact |
| `suggested_fix` | Production-ready code fix |
| `remediation_steps` | Step-by-step remediation actions |
| `suggested_test_cases` | Unit, security, and integration test cases |
| `security_references` | CWE IDs, OWASP references |
| `false_positive_reason` | Explanation if marked as false positive |

---

## 9. API & CLI Reference

### CLI Commands

```bash
# Basic scan
python cli.py path/to/project/

# Scan with HTML report
python cli.py path/to/project/ --format html --output report.html

# Scan with AI analysis (fast mode)
python cli.py path/to/project/ --format html --output report.html \
  --ai-analysis --api-key $DEEPSEEK_API_KEY --ai-mode fast --max-ai-issues 10

# Scan with AI analysis (full mode) + test case report
python cli.py path/to/project/ --format html --output report.html \
  --ai-analysis --api-key $DEEPSEEK_API_KEY --ai-mode full --max-ai-issues 20 \
  --test-report test-cases.html

# Scan with severity filter and CI gate
python cli.py path/to/project/ --format sarif --output results.sarif \
  --severity critical,high --fail-on critical,high

# Scan specific languages
python cli.py path/to/project/ --languages python,javascript

# Scan with verbose output
python cli.py path/to/project/ --verbose
```

### CLI Options

| Option | Description |
|---|---|
| `path` | File or directory to scan |
| `--format` | Output format: `json`, `sarif`, `html`, `table`, `summary` |
| `--output` | Output file path |
| `--severity` | Filter by severity (comma-separated) |
| `--fail-on` | CI gate: exit code 1 if severity found |
| `--languages` | Filter by language (comma-separated) |
| `--exclude` | Exclude patterns (comma-separated globs) |
| `--config` | Config file path (`.sastifyrc.json`) |
| `--verbose` | Verbose output |
| `--ai-analysis` | Enable AI analysis |
| `--api-key` | DeepSeek API key (or `DEEPSEEK_API_KEY` env var) |
| `--ai-mode` | AI mode: `fast` or `full` |
| `--max-ai-issues` | Max issues to analyze with AI (default: 10) |
| `--test-report` | Path for AI test case report HTML |

### API Endpoints

| Endpoint | Method | Description |
|---|---|---|
| `/scan` | POST | Scan a single file |
| `/scan/project` | POST | Scan an entire project |
| `/results/{scan_id}` | GET | Get scan results |
| `/analyze-issue` | POST | AI-powered analysis of a specific issue |

---

## 10. Output Formats

### JSON
Machine-readable scan summaries with severity counts and vulnerability details.

### SARIF 2.1.0
Industry-standard security results format. Compatible with:
- **GitHub Security tab** (via `github/codeql-action/upload-sarif`)
- VS Code SARIF Viewer extension
- Other SARIF-compatible tools

### HTML Report (ENHANCED)
Premium interactive dashboard with:
- **Risk Score & Grade** (A-F based on severity-weighted scoring)
- Severity breakdown charts
- AI analysis integration (detailed explanations, fix suggestions)
- Attack scenarios and impact analysis per vulnerability
- Code snippet context with syntax highlighting
- Light theme with modern Inter/JetBrains Mono typography
- Responsive design

### Test Case Report (NEW)
Dedicated AI-generated test case HTML report with:
- Test cases grouped by vulnerability type
- Three test categories: Unit, Security, Integration
- Attack payloads and expected behaviors
- AI deep analysis sections (explanation, attack scenario, impact)
- Copy-to-clipboard functionality for test code
- Expand/collapse groups with auto-expand first group

### Table
Formatted console output with colorama-powered severity coloring.

### Summary
One-line summary for CI/CD pipeline status lines.

---

## 11. CI/CD Integration (NEW)

### GitHub Actions

SASTify includes two GitHub Actions workflows:

#### `sastify-scan.yml` — Standard Scan Workflow
- Triggered on push/PR to main
- Installs dependencies
- Runs SASTify scan
- Outputs SARIF for GitHub Security tab
- Generates HTML report as artifact

#### `self-scan.yml` — Self-Scanning Workflow
- SASTify scans its own codebase
- Generates both security report and test case report
- Includes AI analysis with DeepSeek integration
- Uploads SARIF to GitHub Security tab

#### GitHub Action (`action.yml`)
SASTify can be used as a reusable GitHub Action:

```yaml
- name: Run SASTify
  uses: abbyy745-cloud/SASTify@main
  with:
    path: '.'
    format: 'sarif'
    output: 'results.sarif'
    severity: 'critical,high,medium'
    ai-analysis: 'true'
    api-key: ${{ secrets.DEEPSEEK_API_KEY }}
    ai-mode: 'fast'
    max-ai-issues: '10'
    test-report: 'test-cases.html'
```

### Docker Support

```bash
# Build
docker build -t sastify .

# Run scan
docker run -v $(pwd):/code sastify python Backend/cli.py /code --format html --output /code/report.html
```

---

## 12. Technical Specifications

| Specification | Value |
|---|---|
| **Performance** | ~50,000 lines/sec (Python), optimized with concurrent AI |
| **Target Accuracy** | Precision > 85%, Recall > 90% |
| **Requirements** | Python 3.9+, 512MB RAM minimum |
| **Rule Count** | 197 structured + AST + pattern rules |
| **Languages** | 8+ programming languages |
| **Frameworks** | 7 web + 3 mobile frameworks |
| **AI Integration** | DeepSeek API (fast/full modes) |
| **CI/CD** | GitHub Actions, Docker, SARIF 2.1.0 |
| **Workflow Runtime** | ~5 minutes (optimized from ~30 min) |

### Key Dependencies

| Package | Purpose |
|---|---|
| `esprima` | JavaScript AST parsing |
| `tree-sitter` | Mobile language AST parsing |
| `pyyaml` | YAML rule configuration |
| `requests` | HTTP client (API, AI) |
| `colorama` | Colored terminal output |
| `concurrent.futures` | Parallel AI processing |
| `fastapi` | Web API server |

---

## 13. Appendix

### Roadmap (Updated)

**Completed:**
- ✅ Structured rule engines (Python, JS/TS, Framework/Mobile)
- ✅ AI-powered vulnerability analysis (DeepSeek integration)
- ✅ Premium HTML reports with risk scoring
- ✅ Test case report generation
- ✅ GitHub Actions CI/CD workflows
- ✅ Cross-ruleset deduplication
- ✅ Concurrent AI batch processing
- ✅ Library taint models

**Planned:**
- ⬜ C/C++ language support
- ⬜ Go language support
- ⬜ Rust language support
- ⬜ SBOM generation
- ⬜ IDE plugins (VS Code / IntelliJ)
- ⬜ Custom rule authoring UI
- ⬜ Multi-LLM support (OpenAI, Anthropic, Gemini)

### Version History

| Version | Date | Key Changes |
|---|---|---|
| 1.0.0 | Jan 2026 | Initial release: AST analysis, pattern matching, SARIF, EdTech rules |
| 1.1.0 | Jan 2026 | GitHub Actions CI/CD, SARIF validation, CodeQL integration |
| 1.2.0 | Feb 2026 | Premium HTML reports with AI analysis, test case generation |
| 1.3.0 | Feb 2026 | Workflow optimization (30 min → 5 min), concurrent AI |
| 1.4.0 | Feb 2026 | Enhanced security reports, dual AI modes (fast/full) |
| 1.5.0 | Mar 2026 | Vulnerability deduplication, snippet contexts, rule expansion |
| 2.0.0 | Mar 2026 | Structured rule engines (197 rules), library models, framework/mobile rules |
