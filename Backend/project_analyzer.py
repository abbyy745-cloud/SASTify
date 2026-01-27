"""
Project Analyzer - Core Infrastructure for Cross-File Analysis

This module provides project-wide indexing, symbol table management,
and import resolution for both Python and JavaScript projects.
"""

import os
import ast
import json
from pathlib import Path
from dataclasses import dataclass, field
from typing import Dict, List, Set, Optional, Any, Tuple
from enum import Enum
import esprima


class Language(Enum):
    PYTHON = "python"
    JAVASCRIPT = "javascript"


@dataclass
class ParameterInfo:
    """Information about a function parameter"""
    name: str
    index: int
    type_hint: Optional[str] = None
    default_value: Optional[str] = None
    is_taint_source: bool = False  # True if param receives user input


@dataclass
class FunctionInfo:
    """Information about a function extracted from AST"""
    name: str
    file_path: str
    line_number: int
    parameters: List[ParameterInfo] = field(default_factory=list)
    return_type: Optional[str] = None
    decorators: List[str] = field(default_factory=list)
    is_route: bool = False  # Flask/Express route
    route_path: Optional[str] = None
    http_methods: List[str] = field(default_factory=list)
    calls: List[str] = field(default_factory=list)  # Functions this function calls
    class_name: Optional[str] = None  # If method of a class


@dataclass
class ClassInfo:
    """Information about a class"""
    name: str
    file_path: str
    line_number: int
    methods: List[str] = field(default_factory=list)
    base_classes: List[str] = field(default_factory=list)


@dataclass
class ImportInfo:
    """Information about an import statement"""
    module: str
    names: List[str]  # Specific names imported (empty for 'import x')
    alias: Optional[str] = None
    is_from_import: bool = False
    resolved_path: Optional[str] = None  # Resolved file path


@dataclass
class FileInfo:
    """Complete information about a single source file"""
    path: str
    language: Language
    functions: Dict[str, FunctionInfo] = field(default_factory=dict)
    classes: Dict[str, ClassInfo] = field(default_factory=dict)
    imports: List[ImportInfo] = field(default_factory=list)
    global_variables: Dict[str, str] = field(default_factory=dict)  # name -> type hint
    exports: Set[str] = field(default_factory=set)  # Exported names (JS)


@dataclass
class ProjectIndex:
    """Complete index of a project"""
    root_path: str
    files: Dict[str, FileInfo] = field(default_factory=dict)
    symbol_table: Dict[str, List[str]] = field(default_factory=dict)  # symbol -> [file paths]
    import_graph: Dict[str, Set[str]] = field(default_factory=dict)  # file -> files it imports
    reverse_import_graph: Dict[str, Set[str]] = field(default_factory=dict)  # file -> files that import it


class PythonExtractor:
    """Extract information from Python AST"""
    
    def __init__(self, file_path: str, code: str):
        self.file_path = file_path
        self.code = code
        self.functions: Dict[str, FunctionInfo] = {}
        self.classes: Dict[str, ClassInfo] = {}
        self.imports: List[ImportInfo] = []
        self.current_class: Optional[str] = None
        
    def extract(self) -> FileInfo:
        """Extract all information from the file"""
        try:
            tree = ast.parse(self.code)
            self._visit(tree)
        except SyntaxError as e:
            print(f"Syntax error in {self.file_path}: {e}")
        
        return FileInfo(
            path=self.file_path,
            language=Language.PYTHON,
            functions=self.functions,
            classes=self.classes,
            imports=self.imports
        )
    
    def _visit(self, node: ast.AST, parent_class: Optional[str] = None):
        """Visit AST nodes recursively"""
        if isinstance(node, ast.FunctionDef) or isinstance(node, ast.AsyncFunctionDef):
            self._extract_function(node, parent_class)
        elif isinstance(node, ast.ClassDef):
            self._extract_class(node)
        elif isinstance(node, ast.Import):
            self._extract_import(node)
        elif isinstance(node, ast.ImportFrom):
            self._extract_import_from(node)
        
        for child in ast.iter_child_nodes(node):
            if isinstance(node, ast.ClassDef):
                self._visit(child, node.name)
            else:
                self._visit(child, parent_class)
    
    def _extract_function(self, node: ast.FunctionDef, parent_class: Optional[str]):
        """Extract function information"""
        # Extract parameters
        params = []
        for i, arg in enumerate(node.args.args):
            param = ParameterInfo(
                name=arg.arg,
                index=i,
                type_hint=ast.unparse(arg.annotation) if arg.annotation else None
            )
            params.append(param)
        
        # Extract decorators
        decorators = []
        is_route = False
        route_path = None
        http_methods = []
        
        for dec in node.decorator_list:
            dec_name = self._get_decorator_name(dec)
            decorators.append(dec_name)
            
            # Check for Flask/FastAPI routes
            if 'route' in dec_name.lower() or dec_name in ['get', 'post', 'put', 'delete', 'patch']:
                is_route = True
                if isinstance(dec, ast.Call) and dec.args:
                    if isinstance(dec.args[0], ast.Constant):
                        route_path = dec.args[0].value
                    # Extract methods from keywords
                    for kw in dec.keywords:
                        if kw.arg == 'methods' and isinstance(kw.value, ast.List):
                            http_methods = [elt.value for elt in kw.value.elts if isinstance(elt, ast.Constant)]
        
        # Extract function calls
        calls = self._extract_calls(node)
        
        # Build function name
        full_name = f"{parent_class}.{node.name}" if parent_class else node.name
        
        func_info = FunctionInfo(
            name=node.name,
            file_path=self.file_path,
            line_number=node.lineno,
            parameters=params,
            return_type=ast.unparse(node.returns) if node.returns else None,
            decorators=decorators,
            is_route=is_route,
            route_path=route_path,
            http_methods=http_methods,
            calls=calls,
            class_name=parent_class
        )
        
        self.functions[full_name] = func_info
    
    def _extract_calls(self, node: ast.FunctionDef) -> List[str]:
        """Extract all function calls within a function"""
        calls = []
        for child in ast.walk(node):
            if isinstance(child, ast.Call):
                call_name = self._get_call_name(child)
                if call_name:
                    calls.append(call_name)
        return calls
    
    def _get_call_name(self, node: ast.Call) -> Optional[str]:
        """Get the name of a function being called"""
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
    
    def _get_decorator_name(self, dec) -> str:
        """Get decorator name as string"""
        if isinstance(dec, ast.Name):
            return dec.id
        elif isinstance(dec, ast.Attribute):
            return f"{self._get_decorator_name(dec.value)}.{dec.attr}"
        elif isinstance(dec, ast.Call):
            return self._get_decorator_name(dec.func)
        return ""
    
    def _extract_class(self, node: ast.ClassDef):
        """Extract class information"""
        base_classes = []
        for base in node.bases:
            if isinstance(base, ast.Name):
                base_classes.append(base.id)
            elif isinstance(base, ast.Attribute):
                base_classes.append(ast.unparse(base))
        
        methods = []
        for item in node.body:
            if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
                methods.append(item.name)
        
        self.classes[node.name] = ClassInfo(
            name=node.name,
            file_path=self.file_path,
            line_number=node.lineno,
            methods=methods,
            base_classes=base_classes
        )
    
    def _extract_import(self, node: ast.Import):
        """Extract import statement"""
        for alias in node.names:
            self.imports.append(ImportInfo(
                module=alias.name,
                names=[],
                alias=alias.asname,
                is_from_import=False
            ))
    
    def _extract_import_from(self, node: ast.ImportFrom):
        """Extract from ... import statement"""
        module = node.module or ""
        names = [alias.name for alias in node.names]
        
        self.imports.append(ImportInfo(
            module=module,
            names=names,
            is_from_import=True
        ))


class JavaScriptExtractor:
    """Extract information from JavaScript AST using esprima"""
    
    def __init__(self, file_path: str, code: str):
        self.file_path = file_path
        self.code = code
        self.functions: Dict[str, FunctionInfo] = {}
        self.classes: Dict[str, ClassInfo] = {}
        self.imports: List[ImportInfo] = []
        self.exports: Set[str] = set()
        
    def extract(self) -> FileInfo:
        """Extract all information from the file"""
        try:
            # Handle JSX/TSX by stripping types (simplified)
            tree = esprima.parseScript(self.code, {'loc': True, 'tolerant': True})
            self._traverse(tree)
        except Exception as e:
            # Try parsing as module (for import/export)
            try:
                tree = esprima.parseModule(self.code, {'loc': True, 'tolerant': True})
                self._traverse(tree)
            except Exception as e2:
                print(f"JavaScript parse error in {self.file_path}: {e2}")
        
        return FileInfo(
            path=self.file_path,
            language=Language.JAVASCRIPT,
            functions=self.functions,
            classes=self.classes,
            imports=self.imports,
            exports=self.exports
        )
    
    def _traverse(self, node, parent_class: Optional[str] = None):
        """Traverse JavaScript AST"""
        if not node or not hasattr(node, 'type'):
            return
        
        if node.type == 'FunctionDeclaration':
            self._extract_function(node, parent_class)
        elif node.type == 'VariableDeclaration':
            self._extract_variable_functions(node)
        elif node.type == 'ClassDeclaration':
            self._extract_class(node)
        elif node.type == 'MethodDefinition':
            self._extract_method(node, parent_class)
        elif node.type == 'ImportDeclaration':
            self._extract_import(node)
        elif node.type == 'ExportNamedDeclaration':
            self._extract_export(node)
        elif node.type == 'CallExpression':
            self._check_express_route(node)
        
        # Recurse
        for key, value in node.__dict__.items():
            if key == 'loc':
                continue
            if isinstance(value, list):
                for item in value:
                    if hasattr(item, 'type'):
                        self._traverse(item, parent_class)
            elif hasattr(value, 'type'):
                self._traverse(value, parent_class)
    
    def _extract_function(self, node, parent_class: Optional[str]):
        """Extract function declaration"""
        name = node.id.name if node.id else "anonymous"
        
        params = []
        for i, param in enumerate(node.params):
            param_name = param.name if hasattr(param, 'name') else str(i)
            params.append(ParameterInfo(name=param_name, index=i))
        
        calls = self._extract_calls(node.body)
        
        self.functions[name] = FunctionInfo(
            name=name,
            file_path=self.file_path,
            line_number=node.loc.start.line if node.loc else 0,
            parameters=params,
            calls=calls,
            class_name=parent_class
        )
    
    def _extract_variable_functions(self, node):
        """Extract arrow functions and function expressions assigned to variables"""
        for decl in node.declarations:
            if decl.init and decl.init.type in ['ArrowFunctionExpression', 'FunctionExpression']:
                name = decl.id.name if hasattr(decl.id, 'name') else "anonymous"
                
                params = []
                for i, param in enumerate(decl.init.params):
                    param_name = param.name if hasattr(param, 'name') else str(i)
                    params.append(ParameterInfo(name=param_name, index=i))
                
                calls = self._extract_calls(decl.init.body) if decl.init.body else []
                
                self.functions[name] = FunctionInfo(
                    name=name,
                    file_path=self.file_path,
                    line_number=node.loc.start.line if node.loc else 0,
                    parameters=params,
                    calls=calls
                )
    
    def _extract_calls(self, node) -> List[str]:
        """Extract function calls from a node"""
        calls = []
        self._find_calls(node, calls)
        return calls
    
    def _find_calls(self, node, calls: List[str]):
        """Recursively find all call expressions"""
        if not node or not hasattr(node, 'type'):
            return
        
        if node.type == 'CallExpression':
            call_name = self._get_call_name(node)
            if call_name:
                calls.append(call_name)
        
        for key, value in node.__dict__.items():
            if key == 'loc':
                continue
            if isinstance(value, list):
                for item in value:
                    self._find_calls(item, calls)
            elif hasattr(value, 'type'):
                self._find_calls(value, calls)
    
    def _get_call_name(self, node) -> Optional[str]:
        """Get name of function being called"""
        if node.callee.type == 'Identifier':
            return node.callee.name
        elif node.callee.type == 'MemberExpression':
            parts = []
            curr = node.callee
            while curr.type == 'MemberExpression':
                if hasattr(curr.property, 'name'):
                    parts.append(curr.property.name)
                curr = curr.object
            if hasattr(curr, 'name'):
                parts.append(curr.name)
            return ".".join(reversed(parts))
        return None
    
    def _extract_class(self, node):
        """Extract class declaration"""
        name = node.id.name if node.id else "AnonymousClass"
        
        methods = []
        if node.body and node.body.body:
            for item in node.body.body:
                if item.type == 'MethodDefinition' and item.key:
                    methods.append(item.key.name)
        
        base_classes = []
        if node.superClass:
            if hasattr(node.superClass, 'name'):
                base_classes.append(node.superClass.name)
        
        self.classes[name] = ClassInfo(
            name=name,
            file_path=self.file_path,
            line_number=node.loc.start.line if node.loc else 0,
            methods=methods,
            base_classes=base_classes
        )
        
        # Extract methods
        if node.body and node.body.body:
            for item in node.body.body:
                if item.type == 'MethodDefinition':
                    self._extract_method(item, name)
    
    def _extract_method(self, node, class_name: str):
        """Extract class method"""
        name = node.key.name if hasattr(node.key, 'name') else "method"
        full_name = f"{class_name}.{name}"
        
        params = []
        if node.value and node.value.params:
            for i, param in enumerate(node.value.params):
                param_name = param.name if hasattr(param, 'name') else str(i)
                params.append(ParameterInfo(name=param_name, index=i))
        
        calls = self._extract_calls(node.value.body) if node.value and node.value.body else []
        
        self.functions[full_name] = FunctionInfo(
            name=name,
            file_path=self.file_path,
            line_number=node.loc.start.line if node.loc else 0,
            parameters=params,
            calls=calls,
            class_name=class_name
        )
    
    def _extract_import(self, node):
        """Extract ES6 import"""
        source = node.source.value if node.source else ""
        names = []
        
        for spec in node.specifiers:
            if spec.type == 'ImportDefaultSpecifier':
                names.append(spec.local.name)
            elif spec.type == 'ImportSpecifier':
                names.append(spec.imported.name if hasattr(spec.imported, 'name') else spec.local.name)
            elif spec.type == 'ImportNamespaceSpecifier':
                names.append(f"* as {spec.local.name}")
        
        self.imports.append(ImportInfo(
            module=source,
            names=names,
            is_from_import=True
        ))
    
    def _extract_export(self, node):
        """Extract exports"""
        if node.declaration:
            if node.declaration.type == 'FunctionDeclaration' and node.declaration.id:
                self.exports.add(node.declaration.id.name)
            elif node.declaration.type == 'VariableDeclaration':
                for decl in node.declaration.declarations:
                    if hasattr(decl.id, 'name'):
                        self.exports.add(decl.id.name)
    
    def _check_express_route(self, node):
        """Check if this is an Express route definition"""
        call_name = self._get_call_name(node)
        if call_name and call_name.startswith('app.') or call_name and call_name.startswith('router.'):
            method = call_name.split('.')[-1]
            if method in ['get', 'post', 'put', 'delete', 'patch', 'all']:
                # This is a route definition
                if node.arguments and len(node.arguments) >= 2:
                    route_path = None
                    if node.arguments[0].type == 'Literal':
                        route_path = node.arguments[0].value
                    
                    # The handler is usually the last argument
                    handler = node.arguments[-1]
                    handler_name = f"route_{method}_{route_path}" if route_path else f"route_{method}"
                    
                    if handler.type in ['ArrowFunctionExpression', 'FunctionExpression']:
                        params = []
                        for i, param in enumerate(handler.params):
                            param_name = param.name if hasattr(param, 'name') else str(i)
                            # Mark req as taint source
                            is_source = param_name in ['req', 'request']
                            params.append(ParameterInfo(name=param_name, index=i, is_taint_source=is_source))
                        
                        self.functions[handler_name] = FunctionInfo(
                            name=handler_name,
                            file_path=self.file_path,
                            line_number=node.loc.start.line if node.loc else 0,
                            parameters=params,
                            is_route=True,
                            route_path=route_path,
                            http_methods=[method.upper()],
                            calls=self._extract_calls(handler.body) if handler.body else []
                        )


class ProjectAnalyzer:
    """Analyze entire project and build index"""
    
    PYTHON_EXTENSIONS = {'.py'}
    JS_EXTENSIONS = {'.js', '.jsx', '.ts', '.tsx', '.mjs'}
    IGNORED_DIRS = {'node_modules', '__pycache__', '.git', '.venv', 'venv', 'env', 'dist', 'build'}
    
    def __init__(self, project_root: str):
        self.project_root = Path(project_root).resolve()
        self.index = ProjectIndex(root_path=str(self.project_root))
        
    def analyze(self) -> ProjectIndex:
        """Analyze the entire project"""
        print(f"Analyzing project: {self.project_root}")
        
        # Phase 1: Index all files
        self._index_files()
        
        # Phase 2: Build symbol table
        self._build_symbol_table()
        
        # Phase 3: Resolve imports
        self._resolve_imports()
        
        # Phase 4: Build import graph
        self._build_import_graph()
        
        print(f"Indexed {len(self.index.files)} files, {len(self.index.symbol_table)} symbols")
        return self.index
    
    def _index_files(self):
        """Index all source files in the project"""
        for root, dirs, files in os.walk(self.project_root):
            # Skip ignored directories
            dirs[:] = [d for d in dirs if d not in self.IGNORED_DIRS]
            
            for file in files:
                file_path = Path(root) / file
                ext = file_path.suffix.lower()
                
                if ext in self.PYTHON_EXTENSIONS:
                    self._index_python_file(file_path)
                elif ext in self.JS_EXTENSIONS:
                    self._index_javascript_file(file_path)
    
    def _index_python_file(self, file_path: Path):
        """Index a Python file"""
        try:
            code = file_path.read_text(encoding='utf-8')
            extractor = PythonExtractor(str(file_path), code)
            file_info = extractor.extract()
            self.index.files[str(file_path)] = file_info
        except Exception as e:
            print(f"Error indexing {file_path}: {e}")
    
    def _index_javascript_file(self, file_path: Path):
        """Index a JavaScript file"""
        try:
            code = file_path.read_text(encoding='utf-8')
            extractor = JavaScriptExtractor(str(file_path), code)
            file_info = extractor.extract()
            self.index.files[str(file_path)] = file_info
        except Exception as e:
            print(f"Error indexing {file_path}: {e}")
    
    def _build_symbol_table(self):
        """Build global symbol table mapping symbols to files"""
        for file_path, file_info in self.index.files.items():
            # Add functions
            for func_name in file_info.functions.keys():
                if func_name not in self.index.symbol_table:
                    self.index.symbol_table[func_name] = []
                self.index.symbol_table[func_name].append(file_path)
            
            # Add classes
            for class_name in file_info.classes.keys():
                if class_name not in self.index.symbol_table:
                    self.index.symbol_table[class_name] = []
                self.index.symbol_table[class_name].append(file_path)
    
    def _resolve_imports(self):
        """Resolve import statements to actual file paths"""
        for file_path, file_info in self.index.files.items():
            file_dir = Path(file_path).parent
            
            for imp in file_info.imports:
                resolved = self._resolve_import(imp, file_dir, file_info.language)
                imp.resolved_path = resolved
    
    def _resolve_import(self, imp: ImportInfo, file_dir: Path, language: Language) -> Optional[str]:
        """Resolve a single import to a file path"""
        if language == Language.PYTHON:
            return self._resolve_python_import(imp, file_dir)
        else:
            return self._resolve_js_import(imp, file_dir)
    
    def _resolve_python_import(self, imp: ImportInfo, file_dir: Path) -> Optional[str]:
        """Resolve Python import"""
        module_parts = imp.module.split('.')
        
        # Try relative import first
        relative_path = file_dir
        for part in module_parts:
            relative_path = relative_path / part
        
        # Check for .py file
        py_file = relative_path.with_suffix('.py')
        if py_file.exists():
            return str(py_file)
        
        # Check for package __init__.py
        init_file = relative_path / '__init__.py'
        if init_file.exists():
            return str(init_file)
        
        # Try from project root
        root_path = self.project_root
        for part in module_parts:
            root_path = root_path / part
        
        py_file = root_path.with_suffix('.py')
        if py_file.exists():
            return str(py_file)
        
        return None  # External module
    
    def _resolve_js_import(self, imp: ImportInfo, file_dir: Path) -> Optional[str]:
        """Resolve JavaScript import"""
        module = imp.module
        
        # Skip package imports (don't start with . or /)
        if not module.startswith('.') and not module.startswith('/'):
            return None  # External package
        
        # Resolve relative path
        if module.startswith('.'):
            resolved = (file_dir / module).resolve()
        else:
            resolved = Path(module).resolve()
        
        # Try various extensions
        for ext in ['', '.js', '.jsx', '.ts', '.tsx', '/index.js', '/index.ts']:
            candidate = Path(str(resolved) + ext)
            if candidate.exists():
                return str(candidate)
        
        return None
    
    def _build_import_graph(self):
        """Build the import dependency graph"""
        for file_path, file_info in self.index.files.items():
            self.index.import_graph[file_path] = set()
            
            for imp in file_info.imports:
                if imp.resolved_path:
                    self.index.import_graph[file_path].add(imp.resolved_path)
                    
                    # Build reverse graph
                    if imp.resolved_path not in self.index.reverse_import_graph:
                        self.index.reverse_import_graph[imp.resolved_path] = set()
                    self.index.reverse_import_graph[imp.resolved_path].add(file_path)
    
    def get_file_info(self, file_path: str) -> Optional[FileInfo]:
        """Get file info by path"""
        return self.index.files.get(file_path)
    
    def find_function(self, name: str) -> List[Tuple[str, FunctionInfo]]:
        """Find a function by name across all files"""
        results = []
        file_paths = self.index.symbol_table.get(name, [])
        for file_path in file_paths:
            file_info = self.index.files.get(file_path)
            if file_info and name in file_info.functions:
                results.append((file_path, file_info.functions[name]))
        return results
    
    def get_callers(self, function_name: str) -> List[Tuple[str, FunctionInfo]]:
        """Find all functions that call a given function"""
        callers = []
        for file_path, file_info in self.index.files.items():
            for func_name, func_info in file_info.functions.items():
                if function_name in func_info.calls:
                    callers.append((file_path, func_info))
        return callers
    
    def get_entry_points(self) -> List[Tuple[str, FunctionInfo]]:
        """Find all entry points (routes, main functions)"""
        entry_points = []
        for file_path, file_info in self.index.files.items():
            for func_name, func_info in file_info.functions.items():
                if func_info.is_route:
                    entry_points.append((file_path, func_info))
                elif func_name == 'main' or func_name == '__main__':
                    entry_points.append((file_path, func_info))
        return entry_points
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert index to dictionary for serialization"""
        return {
            'root_path': self.index.root_path,
            'files': {
                path: {
                    'language': info.language.value,
                    'functions': {
                        name: {
                            'name': f.name,
                            'line': f.line_number,
                            'params': [p.name for p in f.parameters],
                            'calls': f.calls,
                            'is_route': f.is_route,
                            'route_path': f.route_path
                        }
                        for name, f in info.functions.items()
                    },
                    'classes': list(info.classes.keys()),
                    'imports': [
                        {'module': i.module, 'names': i.names, 'resolved': i.resolved_path}
                        for i in info.imports
                    ]
                }
                for path, info in self.index.files.items()
            },
            'symbol_count': len(self.index.symbol_table),
            'entry_points': [
                {'file': fp, 'function': fi.name, 'route': fi.route_path}
                for fp, fi in self.get_entry_points()
            ]
        }
