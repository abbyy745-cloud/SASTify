import re
import ast
import esprima
import hashlib
import yaml
from typing import List, Dict, Tuple, Any, Set, Optional
import json
import subprocess
import os
from pathlib import Path


class TaintTracker:
    """
    Tracks taint sources, sinks, and sanitizers for AST-based vulnerability detection.
    Loads rules from YAML configuration file with fallback to embedded defaults.
    """
    
    def __init__(self, rules_file: Optional[str] = None):
        # Default rules path
        if rules_file is None:
            rules_file = os.path.join(os.path.dirname(__file__), 'rules', 'default_rules.yaml')
        
        # Load from YAML or use defaults
        self.rules_loaded_from_yaml = False
        self.sources = {}
        self.sinks = {}
        self.sanitizers = {}
        self.ast_rules = {}
        self.edtech_ast_rules = []
        
        if os.path.exists(rules_file):
            self._load_from_yaml(rules_file)
        else:
            self._load_defaults()
    
    def _load_from_yaml(self, rules_file: str):
        """Load rules from YAML configuration file"""
        try:
            with open(rules_file, 'r', encoding='utf-8') as f:
                rules = yaml.safe_load(f)
            
            # Load sources - flatten nested structure
            if 'sources' in rules:
                self.sources = {}
                for lang, categories in rules['sources'].items():
                    if isinstance(categories, dict):
                        self.sources[lang] = categories
                    else:
                        self.sources[lang] = {'default': categories}
            
            # Load sinks - keep vulnerability type structure
            if 'sinks' in rules:
                self.sinks = rules['sinks']
            
            # Load sanitizers - flatten if nested
            if 'sanitizers' in rules:
                self.sanitizers = {}
                for lang, categories in rules['sanitizers'].items():
                    if isinstance(categories, dict):
                        # Flatten all categories into a single list
                        all_sanitizers = []
                        for cat_items in categories.values():
                            if isinstance(cat_items, list):
                                all_sanitizers.extend(cat_items)
                        self.sanitizers[lang] = all_sanitizers
                    else:
                        self.sanitizers[lang] = categories
            
            # Load AST-specific rules
            if 'ast_rules' in rules:
                self.ast_rules = rules['ast_rules']
            
            # Load EdTech AST rules
            if 'edtech_ast_rules' in rules:
                self.edtech_ast_rules = rules['edtech_ast_rules']
            
            self.rules_loaded_from_yaml = True
            
        except Exception as e:
            print(f"Warning: Failed to load rules from YAML ({e}), using defaults")
            self._load_defaults()
    
    def _load_defaults(self):
        """Load default hardcoded rules as fallback"""
        self.sources = {
            'python': {
                'flask': ['request.args', 'request.form', 'request.values', 'request.cookies', 'request.headers', 'request.json', 'request.data', 'request.url'],
                'django': ['request.GET', 'request.POST', 'request.COOKIES', 'request.META', 'request.body', 'request.path'],
                'stdlib': ['input', 'sys.argv', 'os.environ', 'argparse.ArgumentParser', 'click.argument', 'click.option'],
                'fastapi': ['Query', 'Body', 'Form', 'Header', 'Cookie', 'Path']
            },
            'javascript': {
                'express': ['req.body', 'req.query', 'req.params', 'req.cookies', 'req.headers', 'req.url'],
                'browser': ['document.location', 'location.search', 'location.hash', 'document.cookie', 'localStorage', 'sessionStorage', 'window.name'],
                'node': ['process.env', 'process.argv', 'fs.readFileSync']
            },
            'edtech': {
                'student_data': ['student_id', 'student_name', 'roll_number', 'cnic', 'dob', 'parent_contact', 'address', 'grade', 'marks', 'score'],
                'exam_data': ['exam_token', 'submission_id', 'answer_key', 'question_id'],
                'ai_data': ['prompt', 'user_input', 'model_output', 'generated_text']
            }
        }
        
        self.sinks = {
            'python': {
                'sql_injection': ['cursor.execute', 'connection.execute', 'db.execute', 'Model.objects.raw', 'sqlalchemy.text'],
                'code_injection': ['eval', 'exec', 'compile', 'os.system', 'os.popen', 'subprocess.call', 'subprocess.Popen', 'subprocess.run'],
                'xss': ['render_template_string', 'Markup', 'flask.Response', 'django.utils.safestring.mark_safe'],
                'path_traversal': ['open', 'os.path.join', 'send_file', 'send_from_directory', 'shutil.copy', 'shutil.move'],
                'shell_injection': ['os.system', 'os.popen', 'subprocess.call', 'subprocess.Popen', 'subprocess.run', 'commands.getoutput'],
                'deserialization': ['pickle.load', 'pickle.loads', 'yaml.load', 'marshal.load', 'marshal.loads'],
                'ssrf': ['requests.get', 'requests.post', 'urllib.request.urlopen']
            },
            'javascript': {
                'sql_injection': ['db.query', 'pool.query', 'connection.query', 'sequelize.query', 'knex.raw'],
                'code_injection': ['eval', 'setTimeout', 'setInterval', 'new Function', 'child_process.exec', 'child_process.spawn', 'vm.runInContext'],
                'xss': ['innerHTML', 'outerHTML', 'document.write', 'document.writeln', 'insertAdjacentHTML'],
                'prototype_pollution': ['__proto__', 'prototype', 'constructor', 'Object.assign', '_.merge', '_.extend'],
                'ssrf': ['fetch', 'axios.get', 'axios.post', 'http.get', 'http.request']
            },
            'edtech': {
                'pii_leakage': ['console.log', 'console.error', 'logger.debug', 'print', 'logging.info'],
                'exam_integrity': ['submit_grade', 'update_score', 'calculate_marks'],
                'ai_security': ['llm.generate', 'openai.Completion.create', 'model.predict']
            },
            'universal': {
                'ssrf': ['requests.get', 'requests.post', 'urllib.request.urlopen', 'axios.get', 'fetch', 'http.get'],
                'csrf': [],
                'auth': ['jwt.encode', 'itsdangerous.Signer']
            }
        }
        
        self.sanitizers = {
            'python': ['html.escape', 'markupsafe.escape', 'bleach.clean', 'werkzeug.utils.secure_filename', 'shlex.quote'],
            'javascript': ['DOMPurify.sanitize', 'escape', 'encodeURIComponent', 'encodeURI', 'xss']
        }
    
    def get_all_sources(self, language: str) -> List[str]:
        """Get all sources for a language, flattened from all categories"""
        sources = []
        lang_sources = self.sources.get(language, {})
        if isinstance(lang_sources, dict):
            for category_sources in lang_sources.values():
                if isinstance(category_sources, list):
                    sources.extend(category_sources)
        return sources
    
    def get_all_sinks(self, language: str) -> Dict[str, List[str]]:
        """Get all sinks for a language, organized by vulnerability type"""
        return self.sinks.get(language, {})
    
    def get_all_sanitizers(self, language: str) -> List[str]:
        """Get all sanitizers for a language"""
        sanitizers = self.sanitizers.get(language, [])
        if isinstance(sanitizers, list):
            return sanitizers
        return []
    
    def is_source(self, identifier: str, language: str) -> bool:
        """Check if an identifier is a taint source"""
        return identifier in self.get_all_sources(language)
    
    def is_sink(self, func_name: str, language: str) -> Optional[str]:
        """Check if a function is a sink, returns vulnerability type or None"""
        for vuln_type, sinks in self.get_all_sinks(language).items():
            if func_name in sinks:
                return vuln_type
        return None
    
    def is_sanitizer(self, func_name: str, language: str) -> bool:
        """Check if a function is a sanitizer"""
        return func_name in self.get_all_sanitizers(language)

class PythonASTScanner:
    def __init__(self, taint_tracker: TaintTracker):
        self.taint_tracker = taint_tracker
        self.tainted_variables: Set[str] = set()
        self.issues: List[Dict] = []

    def scan(self, code: str) -> List[Dict]:
        self.issues = []
        self.tainted_variables = set()
        try:
            tree = ast.parse(code)
            self._visit(tree, code)
        except SyntaxError as e:
            print(f"Python syntax error: {e}")
        except Exception as e:
            print(f"Python AST scan error: {e}")
        return self.issues

    def _visit(self, node: ast.AST, code: str):
        # Track assignments (Propagation)
        if isinstance(node, ast.Assign):
            self._handle_assignment(node)
            self._check_hardcoded_secret(node, code)
            self._check_debug_mode(node, code)
        
        # Check for sinks (Vulnerability Detection)
        if isinstance(node, ast.Call):
            self._check_call(node, code)
            self._check_deserialization(node, code)
            self._check_weak_crypto(node, code)
            self._check_ssrf(node, code)
            self._check_ssl_verification(node, code)
            
        # Check for unprotected routes (EdTech)
        if isinstance(node, ast.FunctionDef):
            self._check_function_def(node, code)

        # Recursively visit children
        for child in ast.iter_child_nodes(node):
            self._visit(child, code)
    
    def _check_hardcoded_secret(self, node: ast.Assign, code: str):
        """AST-based detection of hardcoded secrets in assignments"""
        secret_patterns = ['password', 'passwd', 'pwd', 'secret', 'api_key', 'apikey', 
                          'token', 'auth', 'private_key', 'access_key', 'secret_key']
        
        for target in node.targets:
            if isinstance(target, ast.Name):
                var_name = target.id.lower()
                # Check if variable name suggests a secret
                if any(pattern in var_name for pattern in secret_patterns):
                    # Check if value is a hardcoded string
                    if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
                        value = node.value.value
                        # Ignore empty strings, env var patterns, and obvious placeholders
                        if len(value) >= 8 and not value.startswith('${') and \
                           not any(x in value.lower() for x in ['env', 'config', 'xxx', 'test', 'example', 'placeholder']):
                            self.issues.append({
                                'type': 'hardcoded_secret',
                                'line': node.lineno,
                                'snippet': code.split('\n')[node.lineno - 1].strip(),
                                'confidence': 0.9,
                                'severity': 'High',
                                'scanner': 'ast_secret_detection',
                                'description': f'Hardcoded secret detected in variable "{target.id}"'
                            })
    
    def _check_debug_mode(self, node: ast.Assign, code: str):
        """AST-based detection of debug mode enabled"""
        debug_patterns = ['debug', 'DEBUG']
        
        for target in node.targets:
            if isinstance(target, ast.Name) and target.id.upper() == 'DEBUG':
                if isinstance(node.value, ast.Constant) and node.value.value is True:
                    self.issues.append({
                        'type': 'debug_enabled',
                        'line': node.lineno,
                        'snippet': code.split('\n')[node.lineno - 1].strip(),
                        'confidence': 0.85,
                        'severity': 'Medium',
                        'scanner': 'ast_config_analysis',
                        'description': 'Debug mode is enabled, which may expose sensitive information'
                    })
    
    def _check_deserialization(self, node: ast.Call, code: str):
        """AST-based detection of insecure deserialization"""
        dangerous_deserializers = {
            'pickle.load': 'Insecure deserialization with pickle.load',
            'pickle.loads': 'Insecure deserialization with pickle.loads',
            'cPickle.load': 'Insecure deserialization with cPickle.load',
            'cPickle.loads': 'Insecure deserialization with cPickle.loads',
            'yaml.load': 'Insecure YAML deserialization (use yaml.safe_load instead)',
            'yaml.unsafe_load': 'Explicitly unsafe YAML deserialization',
            'marshal.load': 'Insecure deserialization with marshal.load',
            'marshal.loads': 'Insecure deserialization with marshal.loads',
            'shelve.open': 'Insecure deserialization with shelve.open',
            'jsonpickle.decode': 'Insecure deserialization with jsonpickle.decode'
        }
        
        func_name = self._get_func_name(node)
        if func_name in dangerous_deserializers:
            # For yaml.load, check if Loader is specified as SafeLoader
            is_safe_yaml = False
            if func_name == 'yaml.load':
                for kw in node.keywords:
                    if kw.arg == 'Loader':
                        if isinstance(kw.value, ast.Attribute) and 'Safe' in kw.value.attr:
                            is_safe_yaml = True
                        elif isinstance(kw.value, ast.Name) and 'Safe' in kw.value.id:
                            is_safe_yaml = True
            
            if not is_safe_yaml:
                self.issues.append({
                    'type': 'insecure_deserialization',
                    'line': node.lineno,
                    'snippet': code.split('\n')[node.lineno - 1].strip(),
                    'confidence': 0.95,
                    'severity': 'Critical',
                    'scanner': 'ast_deserialization_analysis',
                    'description': dangerous_deserializers[func_name]
                })
    
    def _check_weak_crypto(self, node: ast.Call, code: str):
        """AST-based detection of weak cryptography usage"""
        weak_crypto_functions = {
            'hashlib.md5': 'MD5 is cryptographically weak, use SHA-256 or stronger',
            'hashlib.sha1': 'SHA-1 is cryptographically weak, use SHA-256 or stronger',
            'Crypto.Hash.MD5': 'MD5 is cryptographically weak',
            'Crypto.Hash.SHA': 'SHA-1 is cryptographically weak',
            'crypt.crypt': 'crypt() uses weak encryption'
        }
        
        func_name = self._get_func_name(node)
        if func_name in weak_crypto_functions:
            self.issues.append({
                'type': 'weak_cryptography',
                'line': node.lineno,
                'snippet': code.split('\n')[node.lineno - 1].strip(),
                'confidence': 0.85,
                'severity': 'Medium',
                'scanner': 'ast_crypto_analysis',
                'description': weak_crypto_functions[func_name]
            })
    
    def _check_ssrf(self, node: ast.Call, code: str):
        """AST-based detection of potential SSRF vulnerabilities"""
        ssrf_functions = ['requests.get', 'requests.post', 'requests.put', 'requests.delete',
                         'urllib.request.urlopen', 'urllib2.urlopen', 'http.client.HTTPConnection']
        
        func_name = self._get_func_name(node)
        if func_name in ssrf_functions and node.args:
            # Check if first argument (URL) is from user input
            first_arg = node.args[0]
            arg_source = self._get_source_segment(first_arg)
            
            # Check if URL comes from a source or tainted variable
            is_tainted = any(source in arg_source for source in self._get_all_sources())
            is_tainted = is_tainted or any(var in arg_source for var in self.tainted_variables)
            
            # Also check for f-strings or concatenation with variables
            if isinstance(first_arg, (ast.JoinedStr, ast.BinOp)):
                is_tainted = True
            
            if is_tainted:
                self.issues.append({
                    'type': 'ssrf',
                    'line': node.lineno,
                    'snippet': code.split('\n')[node.lineno - 1].strip(),
                    'confidence': 0.9,
                    'severity': 'High',
                    'scanner': 'ast_ssrf_analysis',
                    'description': f'Potential SSRF: {func_name} with dynamic URL'
                })
    
    def _check_ssl_verification(self, node: ast.Call, code: str):
        """AST-based detection of disabled SSL verification"""
        ssl_functions = ['requests.get', 'requests.post', 'requests.put', 'requests.delete',
                        'requests.patch', 'requests.head', 'requests.options']
        
        func_name = self._get_func_name(node)
        if func_name in ssl_functions:
            for kw in node.keywords:
                if kw.arg == 'verify':
                    if isinstance(kw.value, ast.Constant) and kw.value.value is False:
                        self.issues.append({
                            'type': 'ssl_verification_disabled',
                            'line': node.lineno,
                            'snippet': code.split('\n')[node.lineno - 1].strip(),
                            'confidence': 0.95,
                            'severity': 'High',
                            'scanner': 'ast_ssl_analysis',
                            'description': 'SSL certificate verification is disabled'
                        })

    def _check_function_def(self, node: ast.FunctionDef, code: str):
        # EdTech Rule: Unprotected Exam Endpoint
        # Check if function is a route (has @app.route or similar)
        is_route = False
        has_auth = False
        route_path = ""
        
        for decorator in node.decorator_list:
            if isinstance(decorator, ast.Call):
                func_name = self._get_func_name(decorator)
                if 'route' in func_name:
                    is_route = True
                    # Extract route path if possible
                    if decorator.args and isinstance(decorator.args[0], ast.Constant): # Python 3.8+
                         route_path = decorator.args[0].value
                    elif decorator.args and isinstance(decorator.args[0], ast.Str): # Python < 3.8
                         route_path = decorator.args[0].s
            elif isinstance(decorator, ast.Name):
                if decorator.id in ['login_required', 'admin_required', 'jwt_required']:
                    has_auth = True
        
        if is_route:
            # Check for sensitive keywords in function name or route path
            sensitive_keywords = ['exam', 'grade', 'score', 'submit']
            is_sensitive = any(k in node.name.lower() for k in sensitive_keywords) or \
                           any(k in route_path.lower() for k in sensitive_keywords)
            
            if is_sensitive and not has_auth:
                 self.issues.append({
                    'type': 'unprotected_exam_endpoint',
                    'line': node.lineno,
                    'snippet': self._get_node_source(code, node).split('\n')[0], # Just the def line
                    'confidence': 0.9,
                    'severity': 'High',
                    'scanner': 'ast_logic_analysis',
                    'description': f'Sensitive exam/grading route "{node.name}" is missing authentication decorators.'
                })
        
        # Universal Rule: CSRF Protection Check (Flask)
        # Heuristic: If it's a state-changing route (POST/PUT/DELETE) and NO csrf protection is visible
        if is_route and any(m in route_path.upper() or m in str(node.decorator_list) for m in ['POST', 'PUT', 'DELETE']):
            has_csrf = False
            for decorator in node.decorator_list:
                func_name = self._get_func_name(decorator)
                if 'csrf' in func_name.lower(): # e.g. @csrf.exempt or @csrf_protect
                    has_csrf = True
            
            # This is a weak heuristic, assuming global CSRF is ON unless exempted. 
            # But we can check for MISSING csrf decorators if the project seems to use them.
            pass # Placeholder for more complex CSRF logic

    def _handle_assignment(self, node: ast.Assign):
        # Check if right side is a source or tainted variable
        is_tainted = False
        
        # Check if value comes from a known source
        source_code = self._get_source_segment(node.value)
        if any(source in source_code for source in self._get_all_sources()):
            is_tainted = True
        
        # Check if value involves existing tainted variables
        if not is_tainted:
            for var in self.tainted_variables:
                if var in source_code:
                    is_tainted = True
                    break
        
        # Check for sanitization (if sanitized, remove taint)
        if isinstance(node.value, ast.Call):
            func_name = self._get_func_name(node.value)
            if func_name in self.taint_tracker.sanitizers['python']:
                is_tainted = False

        # Update tainted variables
        if is_tainted:
            for target in node.targets:
                if isinstance(target, ast.Name):
                    self.tainted_variables.add(target.id)

    def _check_call(self, node: ast.Call, code: str):
        func_name = self._get_func_name(node)
        
        for vuln_type, sinks in self.taint_tracker.sinks['python'].items():
            if func_name in sinks:
                # Check arguments for tainted variables
                tainted_arg = False
                has_dynamic_arg = False  # Any non-literal argument
                
                for arg in node.args:
                    arg_source = self._get_source_segment(arg)
                    
                    # Check if argument is not a simple literal (has dynamic component)
                    # Note: ast.Constant covers strings, numbers, booleans, None in Python 3.8+
                    if not isinstance(arg, ast.Constant):
                        has_dynamic_arg = True
                    
                    # Direct source usage
                    if any(source in arg_source for source in self._get_all_sources()):
                        tainted_arg = True
                    
                    # Tainted variable usage
                    for var in self.tainted_variables:
                        if isinstance(arg, ast.Name) and arg.id == var:
                            tainted_arg = True
                        elif var in arg_source:
                            tainted_arg = True
                
                # Report if tainted OR if has dynamic args (dangerous functions with any variable input)
                if tainted_arg or has_dynamic_arg:
                    description = f'Dangerous function call: {func_name}'
                    confidence = 0.95 if tainted_arg else 0.7  # Higher confidence for confirmed taint
                    
                    if tainted_arg:
                        description = f'Tainted data flows into dangerous sink: {func_name}'
                    else:
                        description = f'Dangerous function {func_name} called with dynamic input'
                    
                    # Refine description for EdTech rules
                    if 'edtech' in self.taint_tracker.sinks:
                        if func_name in self.taint_tracker.sinks['edtech'].get('pii_leakage', []):
                            vuln_type = 'pii_leakage_log'
                            description = f'Potential PII leakage: {func_name} called with data'
                        elif func_name in self.taint_tracker.sinks['edtech'].get('ai_security', []):
                            vuln_type = 'prompt_injection'
                            description = f'Potential AI Prompt Injection: {func_name}'
                    if func_name in self.taint_tracker.sinks.get('universal', {}).get('ssrf', []):
                        vuln_type = 'ssrf'
                        description = f'Potential SSRF: {func_name} with dynamic URL'

                    self.issues.append({
                        'type': vuln_type,
                        'line': node.lineno,
                        'snippet': code.split('\n')[node.lineno - 1].strip(),
                        'confidence': confidence,
                        'severity': 'Critical' if vuln_type in ['code_injection', 'sql_injection', 'prompt_injection'] else 'High',
                        'scanner': 'ast_taint_analysis' if tainted_arg else 'ast_sink_detection',
                        'description': description
                    })

    def _get_all_sources(self):
        sources = []
        for cat in self.taint_tracker.sources['python'].values():
            sources.extend(cat)
        # Add EdTech sources
        if 'edtech' in self.taint_tracker.sources:
            for cat in self.taint_tracker.sources['edtech'].values():
                sources.extend(cat)
        return sources

    def _get_func_name(self, node: ast.Call) -> str:
        if isinstance(node.func, ast.Name):
            return node.func.id
        elif isinstance(node.func, ast.Attribute):
            # Handle cases like cursor.execute or os.path.join
            parts = []
            curr = node.func
            while isinstance(curr, ast.Attribute):
                parts.append(curr.attr)
                curr = curr.value
            if isinstance(curr, ast.Name):
                parts.append(curr.id)
            return ".".join(reversed(parts))
        return ""

    def _get_source_segment(self, node: ast.AST) -> str:
        # Improved source segment extraction
        if isinstance(node, ast.Name):
            return node.id
        if isinstance(node, ast.Attribute):
             return f"{self._get_source_segment(node.value)}.{node.attr}"
        if isinstance(node, ast.Call):
            args = [self._get_source_segment(arg) for arg in node.args]
            return f"{self._get_func_name(node)}({', '.join(args)})"
        if isinstance(node, ast.JoinedStr):
            # Handle f-strings: concatenate all parts
            parts = []
            for value in node.values:
                if isinstance(value, ast.FormattedValue):
                    parts.append(self._get_source_segment(value.value))
                elif isinstance(value, ast.Constant): # Python 3.8+
                    parts.append(str(value.value))
                elif isinstance(value, ast.Str): # Python < 3.8
                    parts.append(value.s)
            return "".join(parts)
        if isinstance(node, ast.BinOp):
            return f"{self._get_source_segment(node.left)} {self._get_source_segment(node.right)}"
        return "" # Fallback

    def _get_node_source(self, code: str, node: ast.AST) -> str:
        if hasattr(node, 'lineno') and hasattr(node, 'end_lineno'):
            lines = code.split('\n')
            start_line = node.lineno - 1
            end_line = node.end_lineno
            return '\n'.join(lines[start_line:end_line])
        return ''

class JavascriptASTScanner:
    def __init__(self, taint_tracker: TaintTracker):
        self.taint_tracker = taint_tracker
        self.tainted_variables: Set[str] = set()
        self.issues: List[Dict] = []

    def scan(self, code: str) -> List[Dict]:
        self.issues = []
        self.tainted_variables = set()
        try:
            # Try parsing as ES6 module first (supports import/export)
            try:
                parsed = esprima.parseModule(code, {'loc': True})
            except Exception:
                # Fall back to script parsing for non-module code
                parsed = esprima.parseScript(code, {'loc': True})
            self._traverse(parsed, code)
        except Exception as e:
            print(f"JavaScript AST scan error: {e}")
        return self.issues

    def _traverse(self, node, code):
        if not node or not hasattr(node, 'type'):
            return

        # Track assignments
        if node.type == 'VariableDeclarator' and node.init:
            self._handle_assignment(node.id, node.init, code)
            self._check_hardcoded_secret_js(node, code)
        elif node.type == 'AssignmentExpression':
            self._handle_assignment(node.left, node.right, code)
            self._check_hardcoded_secret_assignment(node, code)

        # Check for sinks
        if node.type == 'CallExpression':
            self._check_call(node, code)
            self._check_prototype_pollution(node, code)
            self._check_nosql_injection(node, code)
            self._check_jwt_weaknesses(node, code)
        
        # Check for innerHTML assignment
        if node.type == 'AssignmentExpression' and hasattr(node.left, 'type') and node.left.type == 'MemberExpression':
             if hasattr(node.left, 'property') and hasattr(node.left.property, 'name'):
                 if node.left.property.name in ['innerHTML', 'outerHTML']:
                     self._check_sink_assignment(node, code, 'xss')
                 # Check for prototype pollution via assignment
                 if node.left.property.name in ['__proto__', 'prototype', 'constructor']:
                     self._report_prototype_pollution_assignment(node, code)

        # Check for Express Routes (EdTech: Unprotected Exam Endpoint)
        if node.type == 'CallExpression':
            self._check_express_route(node, code)

        # Check for MemberExpressions (Deep EdTech: Proctoring Evasion)
        if node.type == 'MemberExpression':
            self._check_proctoring_evasion(node, code)

        # Recursion
        for key, value in node.__dict__.items():
            if key == 'loc': continue
            if isinstance(value, list):
                for item in value:
                    self._traverse(item, code)
            else:
                self._traverse(value, code)
    
    def _check_hardcoded_secret_js(self, node, code: str):
        """AST-based detection of hardcoded secrets in variable declarations"""
        if not hasattr(node, 'id') or not hasattr(node.id, 'name'):
            return
        
        secret_patterns = ['password', 'apikey', 'api_key', 'secret', 'token', 
                          'auth', 'private', 'access_key', 'secretkey']
        var_name = (node.id.name or "").lower()
        
        if not var_name:
            return
            
        if any(pattern in var_name for pattern in secret_patterns):
            if hasattr(node, 'init') and node.init and hasattr(node.init, 'type'):
                if node.init.type == 'Literal' and isinstance(node.init.value, str):
                    value = node.init.value
                    if len(value) >= 8 and not value.startswith('${') and \
                       not any(x in value.lower() for x in ['env', 'process', 'config', 'test', 'example']):
                        line = node.loc.start.line if hasattr(node, 'loc') else 0
                        self.issues.append({
                            'type': 'hardcoded_secret',
                            'line': line,
                            'snippet': code.split('\n')[line - 1].strip() if line > 0 else '',
                            'confidence': 0.9,
                            'severity': 'High',
                            'scanner': 'ast_secret_detection',
                            'description': f'Hardcoded secret in variable "{node.id.name}"'
                        })
    
    def _check_hardcoded_secret_assignment(self, node, code: str):
        """Check for secrets in assignment expressions"""
        if not hasattr(node.left, 'type'):
            return
            
        secret_patterns = ['password', 'apikey', 'api_key', 'secret', 'token', 'auth']
        var_name = ''
        
        if node.left.type == 'Identifier' and hasattr(node.left, 'name'):
            var_name = node.left.name.lower()
        elif node.left.type == 'MemberExpression' and hasattr(node.left, 'property'):
            if hasattr(node.left.property, 'name'):
                var_name = node.left.property.name.lower()
        
        if any(pattern in var_name for pattern in secret_patterns):
            if hasattr(node.right, 'type') and node.right.type == 'Literal':
                if isinstance(node.right.value, str) and len(node.right.value) >= 8:
                    line = node.loc.start.line if hasattr(node, 'loc') else 0
                    self.issues.append({
                        'type': 'hardcoded_secret',
                        'line': line,
                        'snippet': code.split('\n')[line - 1].strip() if line > 0 else '',
                        'confidence': 0.85,
                        'severity': 'High',
                        'scanner': 'ast_secret_detection',
                        'description': f'Hardcoded secret assigned to "{var_name}"'
                    })
    
    def _check_prototype_pollution(self, node, code: str):
        """AST-based detection of prototype pollution via function calls"""
        dangerous_functions = ['Object.assign', '_.merge', '_.extend', '_.defaults', 
                              '_.defaultsDeep', 'jQuery.extend', '$.extend']
        
        func_name = self._get_func_name(node)
        if func_name in dangerous_functions:
            # Check if first argument could be user-controlled
            if hasattr(node, 'arguments') and len(node.arguments) > 1:
                line = node.loc.start.line if hasattr(node, 'loc') else 0
                self.issues.append({
                    'type': 'prototype_pollution',
                    'line': line,
                    'snippet': code.split('\n')[line - 1].strip() if line > 0 else '',
                    'confidence': 0.75,
                    'severity': 'High',
                    'scanner': 'ast_prototype_analysis',
                    'description': f'{func_name} can lead to prototype pollution if source is user-controlled'
                })
    
    def _report_prototype_pollution_assignment(self, node, code: str):
        """Report direct prototype pollution via assignment"""
        line = node.loc.start.line if hasattr(node, 'loc') else 0
        self.issues.append({
            'type': 'prototype_pollution',
            'line': line,
            'snippet': code.split('\n')[line - 1].strip() if line > 0 else '',
            'confidence': 0.9,
            'severity': 'Critical',
            'scanner': 'ast_prototype_analysis',
            'description': 'Direct prototype pollution via __proto__/prototype assignment'
        })
    
    def _check_nosql_injection(self, node, code: str):
        """AST-based detection of NoSQL injection"""
        nosql_functions = ['find', 'findOne', 'findOneAndUpdate', 'findOneAndDelete',
                          'updateOne', 'updateMany', 'deleteOne', 'deleteMany', 'aggregate']
        
        func_name = self._get_func_name(node)
        if any(func_name.endswith(f'.{fn}') for fn in nosql_functions):
            # Check if query argument contains user input
            if hasattr(node, 'arguments') and node.arguments:
                arg_source = self._get_source_from_node(node.arguments[0], code)
                is_tainted = any(source in arg_source for source in self._get_all_sources())
                is_tainted = is_tainted or any(var in arg_source for var in self.tainted_variables)
                
                if is_tainted:
                    line = node.loc.start.line if hasattr(node, 'loc') else 0
                    self.issues.append({
                        'type': 'nosql_injection',
                        'line': line,
                        'snippet': code.split('\n')[line - 1].strip() if line > 0 else '',
                        'confidence': 0.85,
                        'severity': 'High',
                        'scanner': 'ast_nosql_analysis',
                        'description': f'Potential NoSQL injection in {func_name}'
                    })
    
    def _check_jwt_weaknesses(self, node, code: str):
        """AST-based detection of JWT security issues"""
        jwt_functions = ['jwt.sign', 'jwt.verify', 'jsonwebtoken.sign', 'jsonwebtoken.verify']
        
        func_name = self._get_func_name(node)
        if func_name in jwt_functions:
            if hasattr(node, 'arguments'):
                for arg in node.arguments:
                    arg_str = self._get_source_from_node(arg, code).lower()
                    # Check for 'none' algorithm
                    if "'none'" in arg_str or '"none"' in arg_str or 'algorithm' in arg_str and 'none' in arg_str:
                        line = node.loc.start.line if hasattr(node, 'loc') else 0
                        self.issues.append({
                            'type': 'jwt_none_algorithm',
                            'line': line,
                            'snippet': code.split('\n')[line - 1].strip() if line > 0 else '',
                            'confidence': 0.95,
                            'severity': 'Critical',
                            'scanner': 'ast_jwt_analysis',
                            'description': 'JWT with "none" algorithm allows signature bypass'
                        })

    def _handle_assignment(self, target, value, code):
        is_tainted = False
        value_source = self._get_source_from_node(value, code)
        
        # Check sources
        if any(source in value_source for source in self._get_all_sources()):
            is_tainted = True
            
        # Check existing tainted vars
        if not is_tainted:
            for var in self.tainted_variables:
                if var in value_source: # Simple substring check for now
                    is_tainted = True
                    break
        
        # Check sanitizers
        if value.type == 'CallExpression':
            func_name = self._get_func_name(value)
            if func_name in self.taint_tracker.sanitizers['javascript']:
                is_tainted = False

        if is_tainted:
            if target.type == 'Identifier':
                self.tainted_variables.add(target.name)

    def _check_call(self, node, code):
        func_name = self._get_func_name(node)
        
        for vuln_type, sinks in self.taint_tracker.sinks['javascript'].items():
            if func_name in sinks:
                tainted_arg = False
                has_dynamic_arg = False
                
                for arg in node.arguments:
                    # Skip literals - they're safe
                    if arg.type == 'Literal':
                        continue
                    
                    # Any non-literal is a dynamic argument
                    has_dynamic_arg = True
                        
                    arg_source = self._get_source_from_node(arg, code)
                    if any(source in arg_source for source in self._get_all_sources()):
                        tainted_arg = True
                    for var in self.tainted_variables:
                        if var in arg_source:
                            tainted_arg = True
                
                # Report if tainted OR has dynamic args
                if tainted_arg or has_dynamic_arg:
                    confidence = 0.95 if tainted_arg else 0.7
                    
                    if tainted_arg:
                        description = f'Tainted data flows into dangerous sink: {func_name}'
                    else:
                        description = f'Dangerous function {func_name} called with dynamic input'
                    
                    # Refine for EdTech/Universal rules
                    if func_name in self.taint_tracker.sinks.get('edtech', {}).get('pii_leakage', []):
                        vuln_type = 'pii_leakage_log_node'
                        description = f'Potential PII leakage: {func_name}'
                    elif func_name in self.taint_tracker.sinks.get('edtech', {}).get('ai_security', []):
                        vuln_type = 'prompt_injection_node'
                        description = f'Potential AI Prompt Injection: {func_name}'
                    elif func_name in self.taint_tracker.sinks.get('universal', {}).get('ssrf', []):
                        vuln_type = 'ssrf_node'
                        description = f'Potential SSRF: {func_name} with dynamic URL'

                    self.issues.append({
                        'type': vuln_type,
                        'line': node.loc.start.line,
                        'snippet': code.split('\n')[node.loc.start.line - 1].strip(),
                        'confidence': confidence,
                        'severity': 'Critical' if vuln_type in ['code_injection', 'sql_injection', 'prompt_injection_node'] else 'High',
                        'scanner': 'ast_taint_analysis' if tainted_arg else 'ast_sink_detection',
                        'description': description
                    })

    def _check_sink_assignment(self, node, code, vuln_type):
        # For things like element.innerHTML = tainted
        value_source = self._get_source_from_node(node.right, code)
        tainted = False
        if any(source in value_source for source in self._get_all_sources()):
            tainted = True
        for var in self.tainted_variables:
            if var in value_source:
                tainted = True
        
        if tainted:
             self.issues.append({
                'type': vuln_type,
                'line': node.loc.start.line,
                'snippet': code.split('\n')[node.loc.start.line - 1].strip(),  # Full line for AI context
                'confidence': 0.9,
                'severity': 'High',
                'scanner': 'ast_taint_analysis',
                'description': f'Tainted data assigned to dangerous property: {node.left.property.name}'
            })

    def _check_express_route(self, node, code):
        # Heuristic: Check for app.get/post/etc. calls
        func_name = self._get_func_name(node)
        if func_name.startswith('app.') and func_name.split('.')[1] in ['get', 'post', 'put', 'delete']:
            # Check arguments
            if len(node.arguments) >= 2:
                route_path = self._get_source_from_node(node.arguments[0], code)
                
                # Check if route is sensitive
                sensitive_keywords = ['exam', 'grade', 'score', 'submit']
                is_sensitive = any(k in route_path.lower() for k in sensitive_keywords)
                
                if is_sensitive:
                    # Check for middleware (auth checks)
                    # If only 2 args (path, callback), likely missing auth middleware
                    # If 3+ args, middle ones might be middleware
                    has_auth = False
                    if len(node.arguments) > 2:
                        for arg in node.arguments[1:-1]: # Check middle args
                            arg_source = self._get_source_from_node(arg, code)
                            if 'auth' in arg_source.lower() or 'login' in arg_source.lower() or 'admin' in arg_source.lower():
                                has_auth = True
                    
                    if not has_auth:
                         self.issues.append({
                            'type': 'unprotected_exam_endpoint_node',
                            'line': node.loc.start.line,
                            'snippet': code.split('\n')[node.loc.start.line - 1].strip(),  # Full line
                            'confidence': 0.8,
                            'severity': 'High',
                            'scanner': 'ast_logic_analysis',
                            'description': f'Sensitive exam/grading route "{route_path}" appears to be missing authentication middleware.'
                        })
                
                # Universal Rule: CSRF Check (Express)
                # Check if 'csurf' or similar middleware is used in the route
                has_csrf = False
                if len(node.arguments) > 2:
                    for arg in node.arguments[1:-1]:
                        arg_source = self._get_source_from_node(arg, code)
                        if 'csrf' in arg_source.lower():
                            has_csrf = True
                # Heuristic: If it's a POST/PUT/DELETE and NO csrf middleware is found locally
                # (This is prone to FP if global middleware is used, but good for awareness)
                if func_name.split('.')[1] in ['post', 'put', 'delete'] and not has_csrf:
                     # We don't flag it as a bug immediately to avoid noise, but could be a warning
                     pass

    def _check_proctoring_evasion(self, node, code):
        # Check for document.hidden, navigator.webdriver
        source = self._get_source_from_node(node, code)
        
        if 'document.hidden' in source:
             self.issues.append({
                'type': 'proctoring_evasion',
                'line': node.loc.start.line,
                'snippet': code.split('\n')[node.loc.start.line - 1].strip(),
                'confidence': 0.9,
                'severity': 'Medium',
                'scanner': 'ast_logic_analysis',
                'description': 'Potential Proctoring Evasion: Accessing document.hidden to detect tab switching.'
            })
        elif 'navigator.webdriver' in source:
             self.issues.append({
                'type': 'proctoring_evasion',
                'line': node.loc.start.line,
                'snippet': code.split('\n')[node.loc.start.line - 1].strip(),
                'confidence': 0.9,
                'severity': 'Medium',
                'scanner': 'ast_logic_analysis',
                'description': 'Potential Proctoring Evasion: Checking navigator.webdriver to detect automation.'
            })

    def _get_all_sources(self):
        sources = []
        for cat in self.taint_tracker.sources['javascript'].values():
            sources.extend(cat)
        # Add EdTech sources
        if 'edtech' in self.taint_tracker.sources:
            for cat in self.taint_tracker.sources['edtech'].values():
                sources.extend(cat)
        return sources

    def _get_func_name(self, node):
        try:
            if node.type == 'CallExpression':
                if node.callee.type == 'Identifier':
                    return node.callee.name or ""
                elif node.callee.type == 'MemberExpression':
                    obj = self._get_source_from_node(node.callee.object, "") # Simplified
                    prop = getattr(node.callee.property, 'name', None) or ""
                    return f"{obj}.{prop}" if obj else prop
        except (AttributeError, TypeError):
            pass
        return ""

    def _get_source_from_node(self, node, code):
        # Improved source extraction for JS
        if node.type == 'Identifier':
            return node.name
        if node.type == 'Literal':
            return str(node.value)
        if node.type == 'MemberExpression':
            obj = self._get_source_from_node(node.object, code)
            prop = node.property.name if node.property.type == 'Identifier' else ''
            return f"{obj}.{prop}" if obj else prop
        if node.type == 'BinaryExpression': # Concatenation
            return self._get_source_from_node(node.left, code) + " " + self._get_source_from_node(node.right, code)
        if node.type == 'TemplateLiteral':
            return " ".join([self._get_source_from_node(e, code) for e in node.expressions])
        return ""

class FrontendASTScanner:
    def __init__(self, taint_tracker: TaintTracker):
        self.taint_tracker = taint_tracker
        self.issues = []
        # Path to the node parser script
        self.parser_script = os.path.join(os.path.dirname(__file__), 'parsers', 'parse_frontend.js')

    def scan(self, code: str, file_path: str) -> List[Dict]:
        self.issues = []
        if not os.path.exists(self.parser_script):
            print(f"Warning: Parser script not found at {self.parser_script}")
            return []

        file_type = None
        if file_path.endswith(('.jsx', '.tsx')):
            file_type = 'react'
        elif file_path.endswith('.vue'):
            file_type = 'vue'
        elif file_path.endswith('.html'):
            # Heuristic: Check if it's an Angular template (look for angular specific syntax or file location)
            # For now, we assume .html files passed to this scanner are Angular templates
            file_type = 'angular'
        
        if not file_type:
            return []

        ast_json = self._parse_file(file_path, file_type)
        if not ast_json:
            return []

        if file_type == 'react':
            self._scan_react(ast_json, code)
        elif file_type == 'vue':
            self._scan_vue(ast_json, code)
        elif file_type == 'angular':
            self._scan_angular(ast_json, code)
            
        return self.issues

    def _parse_file(self, file_path: str, file_type: str) -> Optional[Dict]:
        try:
            # Call node script
            result = subprocess.run(
                ['node', self.parser_script, file_path, file_type],
                capture_output=True,
                text=True,
                check=True
            )
            return json.loads(result.stdout)
        except subprocess.CalledProcessError as e:
            print(f"Error parsing frontend file {file_path}: {e.stderr}")
            return None
        except json.JSONDecodeError:
            print(f"Error decoding AST JSON for {file_path}")
            return None

    def _scan_react(self, ast_node, code):
        # Recursive traversal for React AST (Babel ESTree)
        if isinstance(ast_node, dict):
            # Check for JSXAttribute (dangerouslySetInnerHTML)
            if ast_node.get('type') == 'JSXAttribute':
                if ast_node.get('name', {}).get('name') == 'dangerouslySetInnerHTML':
                    self.issues.append({
                        'type': 'react_xss',
                        'line': ast_node.get('loc', {}).get('start', {}).get('line', 0),
                        'snippet': 'dangerouslySetInnerHTML={...}',
                        'confidence': 0.9,
                        'severity': 'High',
                        'scanner': 'frontend_ast',
                        'description': 'Direct DOM manipulation with dangerouslySetInnerHTML is risky.'
                    })
            
            # Check for Prop Drilling (Tainted Props) - Simplified
            # Look for props named 'user_input', 'html', etc.
            if ast_node.get('type') == 'JSXAttribute':
                prop_name = ast_node.get('name', {}).get('name')
                if prop_name in ['userInput', 'htmlContent', 'raw']:
                     self.issues.append({
                        'type': 'prop_drilling_risk',
                        'line': ast_node.get('loc', {}).get('start', {}).get('line', 0),
                        'snippet': f'{prop_name}={{...}}',
                        'confidence': 0.6,
                        'severity': 'Medium',
                        'scanner': 'frontend_ast',
                        'description': f'Potentially unsafe prop "{prop_name}" passed to component.'
                    })

            for key, value in ast_node.items():
                self._scan_react(value, code)
        elif isinstance(ast_node, list):
            for item in ast_node:
                self._scan_react(item, code)

    def _scan_vue(self, ast_node, code):
        # Recursive traversal for Vue AST
        if isinstance(ast_node, dict):
            # Check for VAttribute (v-html)
            if ast_node.get('type') == 'VAttribute':
                key = ast_node.get('key', {})
                # key.name is a VIdentifier node, not a string
                name_node = key.get('name', {})
                if isinstance(name_node, dict) and name_node.get('name') == 'html' and key.get('argument') is None: # v-html
                     self.issues.append({
                        'type': 'vue_xss',
                        'line': ast_node.get('loc', {}).get('start', {}).get('line', 0),
                        'snippet': 'v-html="..."',
                        'confidence': 0.9,
                        'severity': 'High',
                        'scanner': 'frontend_ast',
                        'description': 'v-html directive used. Ensure content is sanitized.'
                    })

            for key, value in ast_node.items():
                self._scan_vue(value, code)
        elif isinstance(ast_node, list):
            for item in ast_node:
                self._scan_vue(item, code)

    def _scan_angular(self, ast_node, code):
        # Recursive traversal for Angular AST
        if isinstance(ast_node, dict):
            # Check for BoundAttribute (innerHTML)
            # Structure: inputs: [{ name: 'innerHTML', type: 'BoundAttribute', ... }]
            if 'inputs' in ast_node and isinstance(ast_node['inputs'], list):
                for input_node in ast_node['inputs']:
                    if input_node.get('type') == 'BoundAttribute' and input_node.get('name') == 'innerHTML':
                         self.issues.append({
                            'type': 'angular_xss',
                            'line': input_node.get('loc', {}).get('start', {}).get('line', 0),
                            'snippet': '[innerHTML]="..."',
                            'confidence': 0.9,
                            'severity': 'High',
                            'scanner': 'frontend_ast',
                            'description': '[innerHTML] binding used. Ensure content is sanitized.'
                        })

            for key, value in ast_node.items():
                self._scan_angular(value, code)
        elif isinstance(ast_node, list):
            for item in ast_node:
                self._scan_angular(item, code)

class EnhancedRuleEngine:
    def __init__(self):
        self.taint_tracker = TaintTracker()
        self.python_scanner = PythonASTScanner(self.taint_tracker)
        self.js_scanner = JavascriptASTScanner(self.taint_tracker)
        self.frontend_scanner = FrontendASTScanner(self.taint_tracker)
        self.vulnerability_patterns = self._build_comprehensive_patterns()
        
        # Initialize new EdTech rule engine
        try:
            from edtech_rules import EdTechRuleEngine
            self.edtech_engine = EdTechRuleEngine()
            self.edtech_available = True
        except ImportError:
            self.edtech_engine = None
            self.edtech_available = False
            print("Warning: EdTech rules not available")
        
        # Initialize TypeScript analyzer
        try:
            from typescript_analyzer import TypeScriptParser
            self.typescript_available = True
        except ImportError:
            self.typescript_available = False
            print("Warning: TypeScript analyzer not available")
        
        # Initialize Java analyzer
        try:
            from java_analyzer import JavaAnalyzer
            self.java_analyzer = JavaAnalyzer()
            self.java_available = True
        except ImportError:
            self.java_analyzer = None
            self.java_available = False
        
        # Initialize PHP analyzer
        try:
            from php_analyzer import PHPAnalyzer
            self.php_analyzer = PHPAnalyzer()
            self.php_available = True
        except ImportError:
            self.php_analyzer = None
            self.php_available = False
        
        # Initialize Swift analyzer - prefer AST scanner if tree-sitter available
        try:
            from swift_ast_scanner import SwiftASTScanner
            self.swift_analyzer = SwiftASTScanner()
            self.swift_available = True
            self.swift_is_ast = True
        except ImportError:
            try:
                from swift_analyzer import SwiftAnalyzer
                self.swift_analyzer = SwiftAnalyzer()
                self.swift_available = True
                self.swift_is_ast = False
            except ImportError:
                self.swift_analyzer = None
                self.swift_available = False
                self.swift_is_ast = False
        
        # Initialize Kotlin analyzer - prefer AST scanner if tree-sitter available
        try:
            from kotlin_ast_scanner import KotlinASTScanner
            self.kotlin_analyzer = KotlinASTScanner()
            self.kotlin_available = True
            self.kotlin_is_ast = True
        except ImportError:
            try:
                from kotlin_analyzer import KotlinAnalyzer
                self.kotlin_analyzer = KotlinAnalyzer()
                self.kotlin_available = True
                self.kotlin_is_ast = False
            except ImportError:
                self.kotlin_analyzer = None
                self.kotlin_available = False
                self.kotlin_is_ast = False
        
        # Initialize Dart/Flutter analyzer - prefer AST scanner if tree-sitter available
        try:
            from dart_ast_scanner import DartASTScanner
            self.dart_analyzer = DartASTScanner()
            self.dart_available = True
            self.dart_is_ast = True
        except ImportError:
            try:
                from dart_analyzer import DartAnalyzer
                self.dart_analyzer = DartAnalyzer()
                self.dart_available = True
                self.dart_is_ast = False
            except ImportError:
                self.dart_analyzer = None
                self.dart_available = False
                self.dart_is_ast = False



    
    def _build_comprehensive_patterns(self) -> Dict[str, List[Tuple]]:
        """Build comprehensive vulnerability patterns for Python and JavaScript"""
        return {
            'python': [
                # SQL Injection
                (r"cursor\.execute\s*\(\s*[\"'].*?%s.*?[\"']", 'sql_injection', 0.9, 'High'),
                (r"cursor\.execute\s*\(\s*f\".*?\{.*\}.*?\"", 'sql_injection', 0.8, 'High'),
                (r"execute\s*\(\s*[\"'].*?\+.*?[\"']", 'sql_injection', 0.7, 'Medium'),
                (r"sqlite3\.connect.*execute.*%", 'sql_injection', 0.9, 'High'),
                
                # Code Injection
                (r"eval\s*\(", 'code_injection', 0.9, 'Critical'),
                (r"exec\s*\(", 'code_injection', 0.9, 'Critical'),
                (r"compile\s*\(", 'code_injection', 0.7, 'High'),
                (r"__import__\s*\(", 'code_injection', 0.8, 'High'),
                (r"getattr\s*\(\s*__builtins__", 'code_injection', 0.6, 'Medium'),
                
                # Hardcoded Secrets - Improved patterns to reduce false positives
                # Only match if value is NOT: empty, placeholder, env var, or common test values
                (r"(password|pwd|passwd)\s*=\s*[\"'](?!\s*$|.*\{|.*env|.*ENV|.*config|.*CONFIG|test|demo|example|placeholder|xxx|\*+)[A-Za-z0-9!@#$%^&*()_+\-=\[\]{};':,.<>?/~`]{8,}[\"']", 'hardcoded_secret', 0.8, 'High'),
                (r"(api_key|apiKey|apikey)\s*=\s*[\"'](?!\s*$|.*\{|.*env|.*ENV|.*config|.*CONFIG|test|demo|example|placeholder|xxx|your_|my_)[A-Za-z0-9_\-]{20,}[\"']", 'hardcoded_secret', 0.9, 'High'),
                (r"(secret|secret_key|private_key)\s*=\s*[\"'](?!\s*$|.*\{|.*env|.*ENV|.*config|.*CONFIG|test|demo|example|placeholder|xxx)[A-Za-z0-9!@#$%^&*()_+\-=\[\]{};':,.<>?/~`]{16,}[\"']", 'hardcoded_secret', 0.9, 'High'),
                (r"(aws_key|aws_secret|access_key|access_token)\s*=\s*[\"'](?!\s*$|.*\{|.*env|.*ENV|.*config|.*CONFIG|test|demo|example|AKIA)[A-Za-z0-9+/=]{20,}[\"']", 'hardcoded_secret', 0.9, 'High'),
                # Long random-looking strings (but not UUIDs or common patterns)
                (r"=\s*[\"'](?!.*-.*-.*-.*-)[A-Za-z0-9]{40,}[\"']", 'hardcoded_secret', 0.6, 'Medium'),
                
                # Insecure Deserialization
                (r"pickle\.loads\s*\(", 'insecure_deserialization', 0.8, 'High'),
                (r"pickle\.load\s*\(", 'insecure_deserialization', 0.8, 'High'),
                (r"yaml\.load\s*\(", 'insecure_deserialization', 0.7, 'Medium'),
                (r"marshal\.loads\s*\(", 'insecure_deserialization', 0.6, 'Medium'),
                (r"json\.loads\s*\(.*?object_hook", 'insecure_deserialization', 0.5, 'Low'),
                
                # Path Traversal
                (r"open\s*\(.*?\+.*?\)", 'path_traversal', 0.6, 'Medium'),
                (r"file\s*\(.*?\+.*?\)", 'path_traversal', 0.6, 'Medium'),
                (r"os\.path\.join.*\.\.", 'path_traversal', 0.7, 'High'),
                (r"\.\./", 'path_traversal', 0.5, 'Medium'),
                
                # Shell Injection
                (r"os\.system\s*\(", 'shell_injection', 0.8, 'High'),
                (r"os\.popen\s*\(", 'shell_injection', 0.8, 'High'),
                (r"subprocess\.call\s*\(", 'shell_injection', 0.7, 'Medium'),
                (r"subprocess\.Popen\s*\(", 'shell_injection', 0.7, 'Medium'),
                (r"commands\.getstatusoutput", 'shell_injection', 0.6, 'Medium'),
                
                # XSS (for web frameworks)
                (r"flask\.render_template_string", 'xss', 0.7, 'Medium'),
                (r"django\.template\.Template", 'xss', 0.7, 'Medium'),
                (r"mark_safe", 'xss', 0.6, 'Medium'),
                
                # Insecure Randomness
                (r"random\.randint", 'insecure_randomness', 0.3, 'Low'),
                (r"random\.choice", 'insecure_randomness', 0.3, 'Low'),
                (r"random\.random", 'insecure_randomness', 0.3, 'Low'),
                
                # SSL/TLS Issues
                (r"verify\s*=\s*False", 'ssl_verification_disabled', 0.8, 'High'),
                (r"ssl\._create_unverified_context", 'ssl_verification_disabled', 0.8, 'High'),
                
                # Information Exposure
                (r"print\s*\(.*password.*\)", 'information_exposure', 0.6, 'Medium'),
                (r"logging\.info.*password", 'information_exposure', 0.6, 'Medium'),
                (r"debug.*=.*True", 'information_exposure', 0.5, 'Low'),
                
                # File Permissions
                (r"0o777", 'insecure_file_permission', 0.6, 'Medium'),
                (r"0o666", 'insecure_file_permission', 0.5, 'Low'),
                
                # Weak Cryptography
                (r"md5\s*\(", 'weak_cryptography', 0.7, 'Medium'),
                (r"sha1\s*\(", 'weak_cryptography', 0.7, 'Medium'),
                (r"crypt\.crypt", 'weak_cryptography', 0.6, 'Medium'),

                # --- EdTech: Student Data & PII Exposure ---
                (r"(student_name|roll_no|cnic|dob|parent_contact|address)\s*=\s*[\"'][^\"']+[\"']", 'hardcoded_pii', 0.8, 'High'),
                (r"(print|logging\.info|logger\.debug)\s*\(.*(student|cnic|dob|parent|address).*\)", 'pii_leakage_log', 0.7, 'High'),
                (r"traceback\.print_exc\s*\(", 'pii_leakage_stacktrace', 0.6, 'Medium'),
                (r"/student/(\d+|<[^>]+>)", 'unsafe_identifier_exposure', 0.7, 'Medium', True),
                (r"autocomplete\s*=\s*[\"']on[\"']", 'sensitive_autocomplete_enabled', 0.6, 'Low', True),

                # --- EdTech: Exam & Assessment Integrity ---
                (r"@app\.route.*(start|stop)_exam", 'unprotected_exam_endpoint', 0.5, 'High'), # Needs manual check for decorators
                (r"request\.args\.get\('marks'\)", 'submission_tampering', 0.8, 'Critical'),
                (r"score\s*=\s*request\..*?\.get\('score'\)", 'submission_tampering', 0.8, 'Critical'),
                (r"safe\s*=\s*False", 'unsafe_file_upload', 0.6, 'High'), # Context dependent
                (r"safe\s*=\s*False", 'unsafe_file_upload', 0.6, 'High'), # Context dependent
                (r"MathJax\.Hub\.Config", 'inline_mathjax_exploit', 0.4, 'Medium', True), # Potential vector
                (r"window\.(setTimeout|setInterval)", 'client_side_timer', 0.6, 'High', True), # Embedded JS
                (r"dangerouslySetInnerHTML", 'cheating_html_injection', 0.8, 'High', True), # Embedded JS/React

                # --- EdTech: AI-Powered Learning Platform ---
                (r"prompt\s*=\s*f\".*?\{.*?user_input.*?\}.*?\"", 'prompt_injection', 0.8, 'High'),
                (r"prompt\s*\+=\s*user_input", 'prompt_injection', 0.8, 'High'),
                (r"(openai|deepseek)\.api_key\s*=\s*[\"'][a-zA-Z0-9\-_]+[\"']", 'hardcoded_ai_key', 0.9, 'Critical'),
                (r"/api/v1/llm/generate", 'exposed_model_endpoint', 0.7, 'High', True),
                (r"def\s+grade_submission", 'ai_grading_security', 0.5, 'Medium'), # Heuristic - check function body in AST if possible, but regex catches definition
                
                # --- Universal: OWASP Top 10 ---
                (r"requests\.(get|post|put|delete)\s*\(.*(request|input|url|site).*\)", 'ssrf', 0.7, 'High'),
                (r"urllib\.request\.urlopen\s*\(.*(request|input|url|site).*\)", 'ssrf', 0.7, 'High'),
                (r"jwt\.encode\s*\(.*algorithm\s*=\s*['\"]none['\"]", 'weak_jwt_alg', 0.9, 'Critical'),
                (r"DEBUG\s*=\s*True", 'debug_mode_enabled', 0.6, 'Medium'),
                (r"app\.config\['DEBUG'\]\s*=\s*True", 'debug_mode_enabled', 0.8, 'Medium'),
                (r"SESSION_COOKIE_HTTPONLY\s*=\s*False", 'insecure_session_cookie', 0.8, 'High'),
                (r"SESSION_COOKIE_SECURE\s*=\s*False", 'insecure_session_cookie', 0.8, 'High'),
                
                # --- Deep EdTech: LTI & Proctoring ---
                (r"oauth_consumer_key", 'lti_launch_handling', 0.4, 'Medium'), # Just flagging LTI presence for AST to check
                (r"lis_outcome_service_url", 'lti_launch_handling', 0.4, 'Medium'),
            ],
            'javascript': [
                # SQL Injection
                (r"\.query\s*\(\s*[`\"'].*?\$\{.*\}.*?[`\"']", 'sql_injection', 0.9, 'High'),
                (r"\.query\s*\(\s*[`\"'].*?\+\s*.*?[`\"']", 'sql_injection', 0.8, 'High'),
                (r"executeSql\s*\(.*?\+.*?\)", 'sql_injection', 0.9, 'High'),
                (r"mysql\.query.*\+", 'sql_injection', 0.8, 'High'),
                
                # XSS
                (r"\.innerHTML\s*=\s*.*?\+?.*?;", 'xss', 0.8, 'High'),
                (r"\.outerHTML\s*=\s*.*?\+?.*?;", 'xss', 0.8, 'High'),
                (r"document\.write\s*\(.*?\)", 'xss', 0.7, 'Medium'),
                (r"document\.writeln\s*\(.*?\)", 'xss', 0.7, 'Medium'),
                (r"eval\s*\(.*?\)", 'xss', 0.9, 'Critical'),
                (r"setTimeout\s*\(.*?\)", 'xss', 0.6, 'Medium'),
                (r"setInterval\s*\(.*?\)", 'xss', 0.6, 'Medium'),
                (r"Function\s*\(.*?\)", 'xss', 0.7, 'High'),
                
                # Hardcoded Secrets - Improved patterns to reduce false positives
                (r"(const|let|var)\s+.*?(password|pwd|apiKey|secretKey)\s*=\s*[\"'](?!\s*$|.*\{|.*env|.*ENV|.*process\.env|.*config|test|demo|example|placeholder|xxx|your_|my_)[A-Za-z0-9!@#$%^&*()_+\-=\[\]{};':,.<>?/~`]{8,}[\"']", 'hardcoded_secret', 0.8, 'High'),
                # Long random-looking strings (but not UUIDs or common patterns)
                (r"=\s*[\"'](?!.*-.*-.*-.*-|http|https|www\.|localhost)[A-Za-z0-9]{40,}[\"']", 'hardcoded_secret', 0.6, 'Medium'),
                # JWT signing with hardcoded secret
                (r"JWT\.sign\([^,]+,\s*[\"'](?!.*\{|.*env|.*ENV|.*process\.env|.*config)[A-Za-z0-9!@#$%^&*()_+\-=]{16,}[\"']", 'hardcoded_secret', 0.9, 'High'),
                
                # Insecure Deserialization
                (r"JSON\.parse\s*\(.*?\)", 'insecure_deserialization', 0.5, 'Low'),
                (r"eval\s*\(.*?\)", 'insecure_deserialization', 0.9, 'Critical'),
                
                # Path Traversal
                (r"fs\.readFile\s*\(.*?\+.*?\)", 'path_traversal', 0.6, 'Medium'),
                (r"fs\.writeFile\s*\(.*?\+.*?\)", 'path_traversal', 0.6, 'Medium'),
                (r"require\s*\(.*?\+.*?\)", 'path_traversal', 0.5, 'Medium'),
                (r"\.\./", 'path_traversal', 0.5, 'Medium'),
                
                # Server-Side JS Injection
                (r"child_process\.exec\s*\(", 'shell_injection', 0.8, 'High'),
                (r"child_process\.spawn\s*\(", 'shell_injection', 0.8, 'High'),
                (r"child_process\.execFile\s*\(", 'shell_injection', 0.7, 'Medium'),
                (r"vm\.runInThisContext", 'code_injection', 0.8, 'High'),
                (r"vm\.runInNewContext", 'code_injection', 0.8, 'High'),
                
                # Prototype Pollution
                (r"__proto__", 'prototype_pollution', 0.7, 'High'),
                (r"constructor\.prototype", 'prototype_pollution', 0.7, 'High'),
                (r"Object\.assign.*__proto__", 'prototype_pollution', 0.8, 'High'),
                
                # Insecure Communication
                (r"http:\/\/", 'insecure_communication', 0.6, 'Medium'),
                (r"ws:\/\/", 'insecure_communication', 0.6, 'Medium'),
                (r"rejectUnauthorized\s*:\s*false", 'ssl_verification_disabled', 0.8, 'High'),
                (r"strictSSL\s*:\s*false", 'ssl_verification_disabled', 0.8, 'High'),
                
                # Information Exposure
                (r"console\.log.*password", 'information_exposure', 0.6, 'Medium'),
                (r"console\.error.*secret", 'information_exposure', 0.6, 'Medium'),
                (r"res\.send.*error.*stack", 'information_exposure', 0.7, 'Medium'),
                
                # Regex DoS
                (r"\/\([^\)]*\)\+\/", 'regex_dos', 0.5, 'Low'),
                (r"\/\([^\)]*\)\*\/", 'regex_dos', 0.5, 'Low'),
                
                # CORS Misconfiguration
                (r"Access-Control-Allow-Origin\s*:\s*\"\\*\"", 'cors_misconfiguration', 0.7, 'Medium'),
                (r"origin:\s*[\"']\\*[\"']", 'cors_misconfiguration', 0.7, 'Medium'),
                
                # Cookie Security
                (r"httpOnly\s*:\s*false", 'insecure_cookie', 0.6, 'Medium'),
                (r"secure\s*:\s*false", 'insecure_cookie', 0.7, 'Medium'),

                # --- EdTech: Student Data & PII Exposure ---
                (r"console\.(log|debug|info)\s*\(.*(student|cnic|dob|parent|address).*\)", 'pii_leakage_log', 0.7, 'High'),
                (r"\/student\/(\d+|<[^>]+>)", 'unsafe_identifier_exposure', 0.7, 'Medium', True),
                (r"autocomplete\s*=\s*[\"']on[\"']", 'sensitive_autocomplete_enabled', 0.6, 'Low', True),

                # --- EdTech: Exam & Assessment Integrity ---
                (r"window\.(setTimeout|setInterval)", 'client_side_timer', 0.6, 'High', True),
                (r"\?marks=\d+", 'submission_tampering_url', 0.7, 'Critical', True),
                (r"dangerouslySetInnerHTML", 'cheating_html_injection', 0.8, 'High', True),

                # --- EdTech: AI-Powered Learning Platform ---
                (r"prompt\s*=\s*`.*?${.*?user_input.*?}.*?`", 'prompt_injection', 0.8, 'High'),
                (r"prompt\s*\+=\s*user_input", 'prompt_injection', 0.8, 'High'),
                (r"(openai|deepseek)Key\s*=\s*[\"'][a-zA-Z0-9\-_]+[\"']", 'hardcoded_ai_key', 0.9, 'Critical'),

                # --- EdTech: Node.js Backend Specific ---
                (r"console\.(log|info|error)\s*\(.*(req\.body|req\.query|req\.params).*\)", 'pii_leakage_log_node', 0.7, 'High'),
                (r"app\.(get|post|put|delete)\s*\(\s*['\"]\/student\/.*['\"]\s*,\s*\(", 'unsafe_route_node', 0.6, 'Medium'), # Heuristic: missing middleware
                (r"res\.json\s*\(.*(student|user).*\)", 'pii_exposure_node', 0.5, 'Medium'), # Potential over-exposure
                
                (r"app\.post\s*\(\s*['\"].*submit_grade.*['\"]", 'unprotected_exam_endpoint_node', 0.6, 'High'),
                (r"const\s+score\s*=\s*req\.body\.score", 'submission_tampering_node', 0.8, 'Critical'),
                
                (r"const\s+score\s*=\s*req\.body\.score", 'submission_tampering_node', 0.8, 'Critical'),
                
                (r"const\s+score\s*=\s*req\.body\.score", 'submission_tampering_node', 0.8, 'Critical'),
                
                (r"const\s+prompt\s*=\s*.*?\+.*?(req\.body|req\.query|req\.params|userInput)", 'prompt_injection_node', 0.8, 'High', True),
                (r"openai\.createCompletion", 'ai_api_call_node', 0.5, 'Low'), # Just flagging usage

                # --- Universal: OWASP Top 10 ---
                (r"(axios|http|https)\.(get|post)\s*\(.*(req\.body|req\.query|url).*\)", 'ssrf_node', 0.7, 'High'),
                (r"fetch\s*\(.*(req\.body|req\.query|url).*\)", 'ssrf_node', 0.7, 'High'),
                (r"jwt\.sign\s*\(.*['\"]none['\"]", 'weak_jwt_alg', 0.9, 'Critical'),
                (r"process\.env\.NODE_ENV\s*===\s*['\"]development['\"]", 'debug_mode_enabled', 0.5, 'Low'),
                (r"app\.use\s*\(\s*cors\s*\(\s*\{.*origin\s*:\s*'\*'", 'cors_misconfiguration', 0.8, 'Medium'),

                # --- Deep EdTech: Proctoring Evasion ---
                (r"document\.hidden", 'proctoring_evasion', 0.6, 'Medium'), # Checking visibility state
                (r"navigator\.webdriver", 'proctoring_evasion', 0.6, 'Medium'), # Checking for automation
                (r"window\.open\s*\(", 'proctoring_evasion', 0.4, 'Low'), # Opening new tabs
            ]
        }

    def scan_with_ast_analysis(self, code: str, language: str, filename: Optional[str] = None) -> List[Dict]:
        """Perform deep AST-based security analysis with EdTech and TypeScript support"""
        issues = []
        
        # AST Analysis based on language
        if language == 'python':
            issues.extend(self.python_scanner.scan(code))
        elif language == 'javascript':
            issues.extend(self.js_scanner.scan(code))
        elif language == 'typescript' and self.typescript_available:
            # TypeScript-specific analysis
            from typescript_analyzer import TypeScriptParser
            parser = TypeScriptParser(filename or 'code.ts', code)
            ts_issues = parser.get_type_safety_issues()
            for issue in ts_issues:
                issues.append({
                    'type': issue['type'].lower().replace(' ', '_'),
                    'line': issue['line'],
                    'snippet': issue.get('snippet', ''),
                    'confidence': 0.8,
                    'severity': issue.get('severity', 'Medium'),
                    'scanner': 'typescript_analyzer',
                    'description': issue.get('message', issue['type'])
                })
            # Also run JS scanner for TypeScript
            issues.extend(self.js_scanner.scan(code))
        elif language == 'java' and self.java_available:
            # Java analysis
            issues.extend(self.java_analyzer.scan(code, filename or ''))
        elif language == 'php' and self.php_available:
            # PHP analysis
            issues.extend(self.php_analyzer.scan(code, filename or ''))
        elif language == 'swift' and self.swift_available:
            # Swift/iOS analysis
            issues.extend(self.swift_analyzer.scan(code, filename or ''))
        elif language == 'kotlin' and self.kotlin_available:
            # Kotlin/Android analysis
            issues.extend(self.kotlin_analyzer.scan(code, filename or ''))
        elif language == 'dart' and self.dart_available:
            # Dart/Flutter analysis
            issues.extend(self.dart_analyzer.scan(code, filename or ''))
            
        # Frontend Analysis (React, Vue, Angular)
        if filename and filename.endswith(('.jsx', '.tsx', '.vue', '.html')):
             issues.extend(self.frontend_scanner.scan(code, filename))
        
        # EdTech-specific rule scanning (57 comprehensive rules)
        if self.edtech_available:
            edtech_lang = 'typescript' if language == 'typescript' else language
            edtech_issues = self.edtech_engine.scan_code(code, edtech_lang, filename or '')
            issues.extend(edtech_issues)

        
        # Regex-based pattern matching (Fallback & Supplementary)
        pattern_lang = 'javascript' if language == 'typescript' else language
        pattern_issues = self._scan_with_patterns(code, pattern_lang)
        
        # Deduplicate: Only add pattern issues if they don't overlap with AST issues
        # Overlap defined as: Same line AND Same type
        ast_issue_signatures = {(issue['line'], issue['type']) for issue in issues}

        
        for issue in pattern_issues:
            if (issue['line'], issue['type']) not in ast_issue_signatures:
                # If it's a regex match but not found by AST, we keep it but mark it
                # This ensures we don't miss things AST misses, but we don't double report
                issues.append(issue)
        
        return issues
    
    def _scan_with_patterns(self, code: str, language: str) -> List[Dict]:
        """Scan code using re patterns, ignoring matches inside string literals"""
        issues = []
        
        if language not in self.vulnerability_patterns:
            return issues
            
        # Get ranges of string literals to ignore
        string_ranges = self._get_string_ranges(code, language)
        
        for pattern_tuple in self.vulnerability_patterns[language]:
            # Unpack tuple with optional 5th element
            if len(pattern_tuple) == 5:
                pattern, vuln_type, confidence, severity, check_inside_strings = pattern_tuple
            else:
                pattern, vuln_type, confidence, severity = pattern_tuple
                check_inside_strings = False

            matches = re.finditer(pattern, code, re.IGNORECASE | re.MULTILINE)
            for match in matches:
                # Calculate line and column
                start_index = match.start()
                line_number = code[:start_index].count('\n') + 1
                last_newline = code.rfind('\n', 0, start_index)
                column = start_index - last_newline - 1 if last_newline != -1 else start_index
                
                # Check if match is inside a string literal
                if not check_inside_strings:
                    is_inside_string = False
                    for start_line, start_col, end_line, end_col in string_ranges:
                        # Check if match start is within the range
                        # Case 1: Single line string
                        if start_line == end_line == line_number:
                            if start_col <= column < end_col:
                                is_inside_string = True
                                break
                        # Case 2: Multi-line string
                        elif start_line <= line_number <= end_line:
                            # If it's the start line, col must be >= start_col
                            if line_number == start_line and column < start_col:
                                continue
                            # If it's the end line, col must be < end_col
                            if line_number == end_line and column >= end_col:
                                continue
                            is_inside_string = True
                            break
                    
                    if is_inside_string:
                        continue

                issues.append({
                    'type': vuln_type,
                    'line': line_number,
                    'snippet': code.split('\n')[line_number - 1].strip(),  # Full line for better AI context
                    'confidence': confidence,
                    'severity': severity,
                    'scanner': 'pattern_matching',
                    'description': f'Pattern matched: {vuln_type}'
                })
        
        return issues

    def _get_string_ranges(self, code: str, language: str) -> List[Tuple[int, int, int, int]]:
        """Get start/end (line, col) for all string literals"""
        ranges = []
        try:
            if language == 'python':
                tree = ast.parse(code)
                for node in ast.walk(tree):
                    if isinstance(node, ast.Constant):
                        # In Py3.8+, ast.Constant handles strings. Check if it's a string.
                        if not isinstance(node.value, str):
                            continue
                        
                        # node.lineno is 1-based
                        # node.col_offset is 0-based
                        if hasattr(node, 'end_lineno') and hasattr(node, 'end_col_offset'):
                            ranges.append((node.lineno, node.col_offset, node.end_lineno, node.end_col_offset))
                            
            elif language == 'javascript':
                parsed = esprima.parseScript(code, {'loc': True, 'range': True})
                
                def traverse(node):
                    if not node or not hasattr(node, 'type'):
                        return
                    
                    if node.type == 'Literal' and isinstance(node.value, str):
                        ranges.append((node.loc.start.line, node.loc.start.column, 
                                     node.loc.end.line, node.loc.end.column))
                    elif node.type == 'TemplateLiteral':
                        ranges.append((node.loc.start.line, node.loc.start.column, 
                                     node.loc.end.line, node.loc.end.column))
                    
                    for key, value in node.__dict__.items():
                        if key == 'loc': continue
                        if isinstance(value, list):
                            for item in value:
                                traverse(item)
                        else:
                            traverse(value)
                
                traverse(parsed)
                
        except Exception as e:
            # If parsing fails, we fallback to no filtering (safer to have FP than FN)
            print(f"Error parsing for string ranges: {e}")
            pass
            
        return ranges
