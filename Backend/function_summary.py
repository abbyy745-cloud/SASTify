"""
Function Summary Generator - Inter-Procedural Taint Analysis

This module generates summaries for each function describing:
- Which parameters can carry taint
- Which parameters flow to return values
- Which parameters flow to dangerous sinks
"""

import ast
from dataclasses import dataclass, field
from typing import Dict, List, Set, Optional, Any, Tuple
from enum import Enum
import esprima

from project_analyzer import (
    ProjectIndex, FunctionInfo, FileInfo, Language, 
    ParameterInfo, ProjectAnalyzer
)
from call_graph import CallGraph, CallGraphBuilder


class TaintState(Enum):
    """Taint state of a value"""
    CLEAN = "clean"
    TAINTED = "tainted"
    UNKNOWN = "unknown"
    SANITIZED = "sanitized"


@dataclass
class TaintFlow:
    """Represents a flow of tainted data"""
    source_param: int  # Parameter index that is tainted
    sink_type: str     # Type of sink reached (sql_injection, xss, etc.)
    sink_name: str     # Name of the sink function
    path: List[str] = field(default_factory=list)  # Call path to sink
    line_number: int = 0
    confidence: float = 0.9


@dataclass
class FunctionSummary:
    """
    Summary of a function's taint behavior.
    
    This is the key data structure for inter-procedural analysis.
    It describes how taint flows through a function without needing
    to re-analyze the function body each time.
    """
    name: str
    file_path: str
    fully_qualified_name: str
    
    # Parameters
    parameters: List[str] = field(default_factory=list)
    
    # Taint propagation: which params flow to return value
    param_to_return: Set[int] = field(default_factory=set)
    
    # Taint sinks: which params flow to dangerous sinks
    param_to_sink: Dict[int, List[TaintFlow]] = field(default_factory=dict)
    
    # Calls made with tainted params: {callee: [(caller_param_idx, callee_param_idx)]}
    tainted_calls: Dict[str, List[Tuple[int, int]]] = field(default_factory=dict)
    
    # Is this function itself a source? (e.g., request.args.get)
    is_source: bool = False
    source_type: Optional[str] = None
    
    # Is this function a sanitizer?
    is_sanitizer: bool = False
    sanitizes: List[str] = field(default_factory=list)
    
    # Is this an entry point (route handler)?
    is_entry_point: bool = False
    entry_params: List[int] = field(default_factory=list)  # Which params receive user input


class PythonSummaryGenerator:
    """Generate function summaries for Python code"""
    
    # Known sources - functions that return tainted data
    SOURCES = {
        'request.args.get': 'user_input',
        'request.form.get': 'user_input', 
        'request.json.get': 'user_input',
        'request.data': 'user_input',
        'request.cookies.get': 'user_input',
        'request.headers.get': 'user_input',
        'input': 'user_input',
        'os.environ.get': 'environment',
        'sys.argv': 'command_line',
        # Django
        'request.GET.get': 'user_input',
        'request.POST.get': 'user_input',
        # EdTech specific
        'Student.query.get': 'pii_data',
        'User.query.get': 'pii_data',
    }
    
    # Known sinks - dangerous functions
    SINKS = {
        # SQL Injection
        'cursor.execute': ('sql_injection', 0),  # (vuln_type, dangerous_param_index)
        'db.execute': ('sql_injection', 0),
        'session.execute': ('sql_injection', 0),
        'connection.execute': ('sql_injection', 0),
        'Model.objects.raw': ('sql_injection', 0),
        # Code Injection
        'eval': ('code_injection', 0),
        'exec': ('code_injection', 0),
        'compile': ('code_injection', 0),
        'os.system': ('shell_injection', 0),
        'os.popen': ('shell_injection', 0),
        'subprocess.call': ('shell_injection', 0),
        'subprocess.run': ('shell_injection', 0),
        'subprocess.Popen': ('shell_injection', 0),
        # XSS
        'render_template_string': ('xss', 0),
        'Markup': ('xss', 0),
        # Path Traversal
        'open': ('path_traversal', 0),
        'send_file': ('path_traversal', 0),
        # SSRF
        'requests.get': ('ssrf', 0),
        'requests.post': ('ssrf', 0),
        'urllib.request.urlopen': ('ssrf', 0),
        # AI/LLM - EdTech specific
        'openai.ChatCompletion.create': ('prompt_injection', -1),  # messages param
        'openai.Completion.create': ('prompt_injection', -1),
        'llm.generate': ('prompt_injection', 0),
        # Logging PII
        'print': ('pii_leakage', 0),
        'logging.info': ('pii_leakage', 0),
        'logging.debug': ('pii_leakage', 0),
        'logger.info': ('pii_leakage', 0),
    }
    
    # Known sanitizers
    SANITIZERS = {
        'html.escape': ['xss'],
        'markupsafe.escape': ['xss'],
        'bleach.clean': ['xss'],
        'werkzeug.utils.secure_filename': ['path_traversal'],
        'shlex.quote': ['shell_injection'],
        'psycopg2.sql.SQL': ['sql_injection'],
        'sqlalchemy.text': ['sql_injection'],
    }
    
    def __init__(self, file_path: str, code: str, func_info: FunctionInfo):
        self.file_path = file_path
        self.code = code
        self.func_info = func_info
        self.tainted_vars: Dict[str, int] = {}  # var_name -> param_index that taints it
        
    def generate(self) -> FunctionSummary:
        """Generate summary for the function"""
        summary = FunctionSummary(
            name=self.func_info.name,
            file_path=self.file_path,
            fully_qualified_name=f"{self.file_path}::{self.func_info.name}",
            parameters=[p.name for p in self.func_info.parameters],
            is_entry_point=self.func_info.is_route,
        )
        
        # Mark entry point parameters as tainted
        if self.func_info.is_route:
            # In Flask/FastAPI, params after 'self' are from URL or decorated with Query/Body
            for i, param in enumerate(self.func_info.parameters):
                if param.name not in ['self', 'cls']:
                    summary.entry_params.append(i)
        
        # Parse function body and analyze
        try:
            tree = ast.parse(self.code)
            func_node = self._find_function_node(tree, self.func_info.name)
            if func_node:
                self._analyze_function(func_node, summary)
        except SyntaxError:
            pass
        
        return summary
    
    def _find_function_node(self, tree: ast.AST, name: str) -> Optional[ast.FunctionDef]:
        """Find the function definition node"""
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                if node.name == name:
                    return node
        return None
    
    def _analyze_function(self, node: ast.FunctionDef, summary: FunctionSummary):
        """Analyze function body for taint flows"""
        # Initialize tainted vars with parameters
        for i, param in enumerate(self.func_info.parameters):
            # Mark as potentially tainted (will be confirmed by caller)
            self.tainted_vars[param.name] = i
        
        # Analyze each statement
        for stmt in ast.walk(node):
            if isinstance(stmt, ast.Assign):
                self._analyze_assignment(stmt, summary)
            elif isinstance(stmt, ast.Call):
                self._analyze_call(stmt, summary)
            elif isinstance(stmt, ast.Return):
                self._analyze_return(stmt, summary)
    
    def _analyze_assignment(self, node: ast.Assign, summary: FunctionSummary):
        """Analyze assignment for taint propagation"""
        # Get source taint
        source_taint = self._get_expression_taint(node.value)
        
        if source_taint is not None:
            # Propagate taint to targets
            for target in node.targets:
                if isinstance(target, ast.Name):
                    self.tainted_vars[target.id] = source_taint
                elif isinstance(target, ast.Tuple):
                    for elt in target.elts:
                        if isinstance(elt, ast.Name):
                            self.tainted_vars[elt.id] = source_taint
    
    def _analyze_call(self, node: ast.Call, summary: FunctionSummary):
        """Analyze function call for sink detection"""
        func_name = self._get_call_name(node)
        
        if not func_name:
            return
        
        # Check if it's a known sink
        for sink_pattern, (vuln_type, dangerous_param) in self.SINKS.items():
            if sink_pattern in func_name or func_name.endswith(sink_pattern.split('.')[-1]):
                # Check if any argument is tainted
                for i, arg in enumerate(node.args):
                    taint_source = self._get_expression_taint(arg)
                    if taint_source is not None:
                        # Found taint flowing to sink!
                        if taint_source not in summary.param_to_sink:
                            summary.param_to_sink[taint_source] = []
                        
                        summary.param_to_sink[taint_source].append(TaintFlow(
                            source_param=taint_source,
                            sink_type=vuln_type,
                            sink_name=func_name,
                            line_number=node.lineno if hasattr(node, 'lineno') else 0,
                            confidence=0.9
                        ))
        
        # Track calls with tainted arguments for inter-procedural analysis
        for i, arg in enumerate(node.args):
            taint_source = self._get_expression_taint(arg)
            if taint_source is not None:
                if func_name not in summary.tainted_calls:
                    summary.tainted_calls[func_name] = []
                summary.tainted_calls[func_name].append((taint_source, i))
    
    def _analyze_return(self, node: ast.Return, summary: FunctionSummary):
        """Analyze return statement for taint in return value"""
        if node.value:
            taint_source = self._get_expression_taint(node.value)
            if taint_source is not None:
                summary.param_to_return.add(taint_source)
    
    def _get_expression_taint(self, node: ast.AST) -> Optional[int]:
        """Get the parameter index that taints this expression, if any"""
        if isinstance(node, ast.Name):
            return self.tainted_vars.get(node.id)
        
        elif isinstance(node, ast.BinOp):
            # String concatenation or arithmetic - taint propagates
            left_taint = self._get_expression_taint(node.left)
            right_taint = self._get_expression_taint(node.right)
            return left_taint if left_taint is not None else right_taint
        
        elif isinstance(node, ast.JoinedStr):  # f-string
            for value in node.values:
                if isinstance(value, ast.FormattedValue):
                    taint = self._get_expression_taint(value.value)
                    if taint is not None:
                        return taint
        
        elif isinstance(node, ast.Call):
            # Check if it's a source
            func_name = self._get_call_name(node)
            if func_name:
                for source_pattern in self.SOURCES:
                    if source_pattern in func_name:
                        return -1  # Special marker for direct source
            
            # Check if it's a sanitizer
            for sanitizer in self.SANITIZERS:
                if sanitizer in (func_name or ''):
                    return None  # Sanitized = not tainted
            
            # Otherwise, check if any argument is tainted
            for arg in node.args:
                taint = self._get_expression_taint(arg)
                if taint is not None:
                    return taint
        
        elif isinstance(node, ast.Subscript):
            return self._get_expression_taint(node.value)
        
        elif isinstance(node, ast.Attribute):
            return self._get_expression_taint(node.value)
        
        return None
    
    def _get_call_name(self, node: ast.Call) -> Optional[str]:
        """Get the name of a function call"""
        if isinstance(node.func, ast.Name):
            return node.func.id
        elif isinstance(node.func, ast.Attribute):
            parts = []
            curr = node.func
            while isinstance(curr, ast.Attribute):
                parts.append(curr.attr)
                curr = curr.value
            if isinstance(curr, ast.Name):
                parts.append(curr.id)
            return ".".join(reversed(parts))
        return None


class JavaScriptSummaryGenerator:
    """Generate function summaries for JavaScript code"""
    
    # Known sources
    SOURCES = {
        'req.body': 'user_input',
        'req.query': 'user_input',
        'req.params': 'user_input',
        'req.cookies': 'user_input',
        'document.location': 'user_input',
        'location.search': 'user_input',
        'location.hash': 'user_input',
        'localStorage.getItem': 'storage',
        'sessionStorage.getItem': 'storage',
    }
    
    # Known sinks
    SINKS = {
        'eval': ('code_injection', 0),
        'setTimeout': ('code_injection', 0),
        'setInterval': ('code_injection', 0),
        'Function': ('code_injection', 0),
        'innerHTML': ('xss', 0),
        'outerHTML': ('xss', 0),
        'document.write': ('xss', 0),
        'insertAdjacentHTML': ('xss', 1),
        'db.query': ('sql_injection', 0),
        'pool.query': ('sql_injection', 0),
        'connection.query': ('sql_injection', 0),
        'exec': ('shell_injection', 0),
        'spawn': ('shell_injection', 0),
        'execSync': ('shell_injection', 0),
        'fetch': ('ssrf', 0),
        'axios.get': ('ssrf', 0),
        'axios.post': ('ssrf', 0),
        'http.get': ('ssrf', 0),
        # AI/LLM
        'openai.createCompletion': ('prompt_injection', -1),
        'openai.createChatCompletion': ('prompt_injection', -1),
    }
    
    SANITIZERS = {
        'DOMPurify.sanitize': ['xss'],
        'escape': ['xss'],
        'encodeURIComponent': ['xss', 'ssrf'],
        'encodeURI': ['xss', 'ssrf'],
    }
    
    def __init__(self, file_path: str, code: str, func_info: FunctionInfo):
        self.file_path = file_path
        self.code = code
        self.func_info = func_info
        self.tainted_vars: Dict[str, int] = {}
        
    def generate(self) -> FunctionSummary:
        """Generate summary for JavaScript function"""
        summary = FunctionSummary(
            name=self.func_info.name,
            file_path=self.file_path,
            fully_qualified_name=f"{self.file_path}::{self.func_info.name}",
            parameters=[p.name for p in self.func_info.parameters],
            is_entry_point=self.func_info.is_route,
        )
        
        # Mark Express req/res params as tainted
        if self.func_info.is_route:
            for i, param in enumerate(self.func_info.parameters):
                if param.name in ['req', 'request']:
                    summary.entry_params.append(i)
                    
        # Initialize tainted vars
        for i, param in enumerate(self.func_info.parameters):
            if param.is_taint_source or param.name in ['req', 'request']:
                self.tainted_vars[param.name] = i
        
        # Parse and analyze
        try:
            tree = esprima.parseScript(self.code, {'loc': True, 'tolerant': True})
            self._analyze_node(tree, summary)
        except:
            pass
        
        return summary
    
    def _analyze_node(self, node, summary: FunctionSummary):
        """Recursively analyze JavaScript AST"""
        if not node or not hasattr(node, 'type'):
            return
        
        if node.type == 'CallExpression':
            self._analyze_call(node, summary)
        elif node.type == 'AssignmentExpression':
            self._analyze_assignment(node, summary)
        elif node.type == 'VariableDeclarator' and node.init:
            self._analyze_var_decl(node, summary)
        elif node.type == 'ReturnStatement' and node.argument:
            self._analyze_return(node, summary)
        
        # Recurse
        for key, value in node.__dict__.items():
            if key == 'loc':
                continue
            if isinstance(value, list):
                for item in value:
                    self._analyze_node(item, summary)
            elif hasattr(value, 'type'):
                self._analyze_node(value, summary)
    
    def _analyze_call(self, node, summary: FunctionSummary):
        """Analyze function call"""
        func_name = self._get_call_name(node)
        if not func_name:
            return
        
        # Check sinks
        for sink_pattern, (vuln_type, dangerous_param) in self.SINKS.items():
            if sink_pattern in func_name:
                for i, arg in enumerate(node.arguments):
                    taint = self._get_expression_taint(arg)
                    if taint is not None:
                        if taint not in summary.param_to_sink:
                            summary.param_to_sink[taint] = []
                        summary.param_to_sink[taint].append(TaintFlow(
                            source_param=taint,
                            sink_type=vuln_type,
                            sink_name=func_name,
                            line_number=node.loc.start.line if node.loc else 0
                        ))
        
        # Track tainted calls
        for i, arg in enumerate(node.arguments):
            taint = self._get_expression_taint(arg)
            if taint is not None:
                if func_name not in summary.tainted_calls:
                    summary.tainted_calls[func_name] = []
                summary.tainted_calls[func_name].append((taint, i))
    
    def _analyze_assignment(self, node, summary):
        """Analyze assignment"""
        taint = self._get_expression_taint(node.right)
        if taint is not None and hasattr(node.left, 'name'):
            self.tainted_vars[node.left.name] = taint
    
    def _analyze_var_decl(self, node, summary):
        """Analyze variable declaration"""
        taint = self._get_expression_taint(node.init)
        if taint is not None and hasattr(node.id, 'name'):
            self.tainted_vars[node.id.name] = taint
    
    def _analyze_return(self, node, summary: FunctionSummary):
        """Analyze return statement"""
        taint = self._get_expression_taint(node.argument)
        if taint is not None:
            summary.param_to_return.add(taint)
    
    def _get_expression_taint(self, node) -> Optional[int]:
        """Get taint source for expression"""
        if not node or not hasattr(node, 'type'):
            return None
        
        if node.type == 'Identifier':
            return self.tainted_vars.get(node.name)
        
        elif node.type == 'MemberExpression':
            # Check if it's a known source
            source_str = self._get_member_string(node)
            for source_pattern in self.SOURCES:
                if source_pattern in source_str:
                    return -1  # Direct source
            return self._get_expression_taint(node.object)
        
        elif node.type == 'BinaryExpression':
            left = self._get_expression_taint(node.left)
            right = self._get_expression_taint(node.right)
            return left if left is not None else right
        
        elif node.type == 'TemplateLiteral':
            for expr in node.expressions:
                taint = self._get_expression_taint(expr)
                if taint is not None:
                    return taint
        
        elif node.type == 'CallExpression':
            func_name = self._get_call_name(node)
            # Check sanitizers
            for sanitizer in self.SANITIZERS:
                if sanitizer in (func_name or ''):
                    return None
            # Check sources
            for source in self.SOURCES:
                if source in (func_name or ''):
                    return -1
            # Propagate from args
            for arg in node.arguments:
                taint = self._get_expression_taint(arg)
                if taint is not None:
                    return taint
        
        return None
    
    def _get_call_name(self, node) -> Optional[str]:
        """Get function call name"""
        if node.callee.type == 'Identifier':
            return node.callee.name
        elif node.callee.type == 'MemberExpression':
            return self._get_member_string(node.callee)
        return None
    
    def _get_member_string(self, node) -> str:
        """Convert member expression to string"""
        parts = []
        curr = node
        while curr.type == 'MemberExpression':
            if hasattr(curr.property, 'name'):
                parts.append(curr.property.name)
            curr = curr.object
        if hasattr(curr, 'name'):
            parts.append(curr.name)
        return '.'.join(reversed(parts))


class FunctionSummaryStore:
    """Store and manage function summaries for a project"""
    
    def __init__(self):
        self.summaries: Dict[str, FunctionSummary] = {}
    
    def add(self, summary: FunctionSummary):
        """Add a summary"""
        self.summaries[summary.fully_qualified_name] = summary
    
    def get(self, fqn: str) -> Optional[FunctionSummary]:
        """Get summary by fully qualified name"""
        return self.summaries.get(fqn)
    
    def get_by_name(self, name: str) -> List[FunctionSummary]:
        """Get all summaries matching a function name"""
        return [s for s in self.summaries.values() if s.name == name]
    
    def get_vulnerabilities(self) -> List[Tuple[FunctionSummary, TaintFlow]]:
        """Get all detected vulnerabilities"""
        vulns = []
        for summary in self.summaries.values():
            for param_idx, flows in summary.param_to_sink.items():
                for flow in flows:
                    vulns.append((summary, flow))
        return vulns
    
    def to_dict(self) -> Dict[str, Any]:
        """Serialize to dictionary"""
        return {
            fqn: {
                'name': s.name,
                'file': s.file_path,
                'params': s.parameters,
                'param_to_return': list(s.param_to_return),
                'vulnerabilities': [
                    {
                        'param': flow.source_param,
                        'type': flow.sink_type,
                        'sink': flow.sink_name,
                        'line': flow.line_number
                    }
                    for flows in s.param_to_sink.values()
                    for flow in flows
                ],
                'is_entry': s.is_entry_point
            }
            for fqn, s in self.summaries.items()
        }


def generate_project_summaries(project_index: ProjectIndex) -> FunctionSummaryStore:
    """Generate summaries for all functions in a project"""
    store = FunctionSummaryStore()
    
    for file_path, file_info in project_index.files.items():
        try:
            code = open(file_path, 'r', encoding='utf-8').read()
        except:
            continue
        
        for func_name, func_info in file_info.functions.items():
            if file_info.language == Language.PYTHON:
                generator = PythonSummaryGenerator(file_path, code, func_info)
            else:
                generator = JavaScriptSummaryGenerator(file_path, code, func_info)
            
            summary = generator.generate()
            store.add(summary)
    
    return store
