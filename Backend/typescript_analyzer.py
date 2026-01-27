"""
TypeScript Analyzer - Full TypeScript/TSX Support

Provides complete TypeScript parsing and analysis including:
- Type annotations for better taint tracking
- Interface and type alias handling
- Generic type support
- TSX/JSX component analysis
"""

import os
import re
import json
import subprocess
from dataclasses import dataclass, field
from typing import Dict, List, Set, Optional, Any, Tuple
from pathlib import Path


@dataclass
class TypeInfo:
    """TypeScript type information"""
    name: str
    is_nullable: bool = False
    is_array: bool = False
    is_promise: bool = False
    generic_params: List[str] = field(default_factory=list)
    is_any: bool = False  # Any type is automatically suspicious


@dataclass
class TypeScriptParameter:
    """TypeScript function parameter with type info"""
    name: str
    index: int
    type_info: Optional[TypeInfo] = None
    is_optional: bool = False
    default_value: Optional[str] = None
    is_rest: bool = False  # ...args


@dataclass
class TypeScriptFunction:
    """TypeScript function information"""
    name: str
    file_path: str
    line_number: int
    parameters: List[TypeScriptParameter] = field(default_factory=list)
    return_type: Optional[TypeInfo] = None
    is_async: bool = False
    is_exported: bool = False
    is_arrow: bool = False
    decorators: List[str] = field(default_factory=list)
    calls: List[str] = field(default_factory=list)
    class_name: Optional[str] = None


@dataclass
class TypeScriptClass:
    """TypeScript class information"""
    name: str
    file_path: str
    line_number: int
    extends: Optional[str] = None
    implements: List[str] = field(default_factory=list)
    methods: List[str] = field(default_factory=list)
    properties: Dict[str, TypeInfo] = field(default_factory=dict)
    is_abstract: bool = False
    is_exported: bool = False
    decorators: List[str] = field(default_factory=list)


@dataclass
class TypeScriptInterface:
    """TypeScript interface information"""
    name: str
    file_path: str
    line_number: int
    properties: Dict[str, TypeInfo] = field(default_factory=dict)
    methods: List[str] = field(default_factory=list)
    extends: List[str] = field(default_factory=list)
    is_exported: bool = False


@dataclass
class TypeScriptFile:
    """Complete TypeScript file analysis"""
    path: str
    functions: Dict[str, TypeScriptFunction] = field(default_factory=dict)
    classes: Dict[str, TypeScriptClass] = field(default_factory=dict)
    interfaces: Dict[str, TypeScriptInterface] = field(default_factory=dict)
    imports: List[Dict[str, Any]] = field(default_factory=list)
    exports: Set[str] = field(default_factory=set)
    type_aliases: Dict[str, str] = field(default_factory=dict)


class TypeScriptParser:
    """
    Parse TypeScript/TSX files without requiring TypeScript compiler.
    Uses regex-based parsing for speed and portability.
    """
    
    # Patterns for TypeScript-specific constructs
    PATTERNS = {
        'import': re.compile(
            r"import\s+(?:{([^}]+)}|\*\s+as\s+(\w+)|(\w+))\s+from\s+['\"]([^'\"]+)['\"]"
        ),
        'function': re.compile(
            r"(?:export\s+)?(?:async\s+)?function\s+(\w+)\s*(?:<[^>]+>)?\s*\(([^)]*)\)(?:\s*:\s*([^{]+))?\s*{"
        ),
        'arrow_function': re.compile(
            r"(?:export\s+)?(?:const|let|var)\s+(\w+)\s*(?::\s*[^=]+)?\s*=\s*(?:async\s+)?(?:<[^>]+>)?\s*\(([^)]*)\)(?:\s*:\s*([^=]+))?\s*=>"
        ),
        'class': re.compile(
            r"(?:export\s+)?(?:abstract\s+)?class\s+(\w+)(?:<[^>]+>)?(?:\s+extends\s+(\w+)(?:<[^>]+>)?)?(?:\s+implements\s+([^{]+))?\s*{"
        ),
        'interface': re.compile(
            r"(?:export\s+)?interface\s+(\w+)(?:<[^>]+>)?(?:\s+extends\s+([^{]+))?\s*{"
        ),
        'method': re.compile(
            r"(?:public|private|protected)?\s*(?:async\s+)?(\w+)\s*(?:<[^>]+>)?\s*\(([^)]*)\)(?:\s*:\s*([^{]+))?\s*{"
        ),
        'type_alias': re.compile(
            r"(?:export\s+)?type\s+(\w+)(?:<[^>]+>)?\s*=\s*([^;]+)"
        ),
        'decorator': re.compile(
            r"@(\w+)(?:\([^)]*\))?"
        ),
        'call': re.compile(
            r"(\w+(?:\.\w+)*)\s*\("
        ),
        'type_annotation': re.compile(
            r":\s*([^,)=;]+)"
        ),
    }
    
    # Dangerous type patterns (taint-relevant)
    DANGEROUS_TYPES = {
        'any', 'unknown', 'never', 'object', 'Function',
        'Request', 'Response', 'Express.Request', 'NextApiRequest',
    }
    
    # Types that indicate user input
    USER_INPUT_TYPES = {
        'Request', 'NextApiRequest', 'KoaContext', 'HonoContext',
        'FormData', 'URLSearchParams',
    }
    
    def __init__(self, file_path: str, code: str):
        self.file_path = file_path
        self.code = code
        self.lines = code.split('\n')
        
    def parse(self) -> TypeScriptFile:
        """Parse the TypeScript file"""
        result = TypeScriptFile(path=self.file_path)
        
        # Parse imports
        result.imports = self._parse_imports()
        
        # Parse type aliases
        result.type_aliases = self._parse_type_aliases()
        
        # Parse interfaces
        result.interfaces = self._parse_interfaces()
        
        # Parse classes
        result.classes = self._parse_classes()
        
        # Parse functions
        result.functions = self._parse_functions()
        
        # Parse exports
        result.exports = self._parse_exports()
        
        return result
    
    def _parse_imports(self) -> List[Dict[str, Any]]:
        """Parse import statements"""
        imports = []
        for match in self.PATTERNS['import'].finditer(self.code):
            named = match.group(1)
            namespace = match.group(2)
            default = match.group(3)
            source = match.group(4)
            
            imported_names = []
            if named:
                imported_names = [n.strip().split(' as ')[0] for n in named.split(',')]
            if namespace:
                imported_names = [f"* as {namespace}"]
            if default:
                imported_names = [default]
            
            imports.append({
                'module': source,
                'names': imported_names,
                'is_relative': source.startswith('.'),
                'is_type_import': 'type ' in match.group(0)
            })
        
        return imports
    
    def _parse_type_aliases(self) -> Dict[str, str]:
        """Parse type aliases"""
        aliases = {}
        for match in self.PATTERNS['type_alias'].finditer(self.code):
            aliases[match.group(1)] = match.group(2).strip()
        return aliases
    
    def _parse_interfaces(self) -> Dict[str, TypeScriptInterface]:
        """Parse interface declarations"""
        interfaces = {}
        for match in self.PATTERNS['interface'].finditer(self.code):
            name = match.group(1)
            extends = match.group(2)
            line_num = self.code[:match.start()].count('\n') + 1
            
            interfaces[name] = TypeScriptInterface(
                name=name,
                file_path=self.file_path,
                line_number=line_num,
                extends=extends.split(',') if extends else [],
                is_exported='export' in self.code[max(0, match.start()-20):match.start()]
            )
        
        return interfaces
    
    def _parse_classes(self) -> Dict[str, TypeScriptClass]:
        """Parse class declarations"""
        classes = {}
        for match in self.PATTERNS['class'].finditer(self.code):
            name = match.group(1)
            extends = match.group(2)
            implements = match.group(3)
            line_num = self.code[:match.start()].count('\n') + 1
            
            # Find decorators above this class
            decorators = self._find_decorators(match.start())
            
            # Find class body and extract methods
            class_start = match.end()
            class_body = self._extract_block(class_start)
            methods = self._extract_methods(class_body, name)
            
            classes[name] = TypeScriptClass(
                name=name,
                file_path=self.file_path,
                line_number=line_num,
                extends=extends,
                implements=implements.split(',') if implements else [],
                methods=[m.name for m in methods.values()],
                decorators=decorators,
                is_exported='export' in self.code[max(0, match.start()-20):match.start()],
                is_abstract='abstract' in self.code[max(0, match.start()-20):match.start()]
            )
            
            # Add methods to the class scope
            for method_name, method in methods.items():
                method.class_name = name
                # Store with class prefix
                full_name = f"{name}.{method_name}"
        
        return classes
    
    def _parse_functions(self) -> Dict[str, TypeScriptFunction]:
        """Parse function declarations"""
        functions = {}
        
        # Regular functions
        for match in self.PATTERNS['function'].finditer(self.code):
            name = match.group(1)
            params_str = match.group(2)
            return_type = match.group(3)
            line_num = self.code[:match.start()].count('\n') + 1
            
            params = self._parse_parameters(params_str)
            calls = self._extract_function_calls(match.end())
            
            functions[name] = TypeScriptFunction(
                name=name,
                file_path=self.file_path,
                line_number=line_num,
                parameters=params,
                return_type=self._parse_type(return_type) if return_type else None,
                is_async='async' in self.code[max(0, match.start()-10):match.start()],
                is_exported='export' in self.code[max(0, match.start()-20):match.start()],
                is_arrow=False,
                calls=calls
            )
        
        # Arrow functions
        for match in self.PATTERNS['arrow_function'].finditer(self.code):
            name = match.group(1)
            params_str = match.group(2)
            return_type = match.group(3)
            line_num = self.code[:match.start()].count('\n') + 1
            
            params = self._parse_parameters(params_str)
            calls = self._extract_function_calls(match.end())
            
            functions[name] = TypeScriptFunction(
                name=name,
                file_path=self.file_path,
                line_number=line_num,
                parameters=params,
                return_type=self._parse_type(return_type) if return_type else None,
                is_async='async' in self.code[max(0, match.start()-10):match.start()],
                is_exported='export' in self.code[max(0, match.start()-20):match.start()],
                is_arrow=True,
                calls=calls
            )
        
        return functions
    
    def _parse_exports(self) -> Set[str]:
        """Parse exports"""
        exports = set()
        
        # Named exports
        for match in re.finditer(r'export\s+{([^}]+)}', self.code):
            for name in match.group(1).split(','):
                exports.add(name.strip().split(' as ')[0].strip())
        
        # Inline exports (from function/class parsing)
        for match in re.finditer(r'export\s+(?:async\s+)?(?:function|const|class|interface|type)\s+(\w+)', self.code):
            exports.add(match.group(1))
        
        # Default export
        if re.search(r'export\s+default', self.code):
            exports.add('default')
        
        return exports
    
    def _parse_parameters(self, params_str: str) -> List[TypeScriptParameter]:
        """Parse function parameters"""
        params = []
        if not params_str.strip():
            return params
        
        # Split by comma, but handle nested generics
        param_parts = self._split_params(params_str)
        
        for idx, param in enumerate(param_parts):
            param = param.strip()
            if not param:
                continue
            
            # Handle rest parameters
            is_rest = param.startswith('...')
            if is_rest:
                param = param[3:]
            
            # Parse name and type
            is_optional = '?' in param
            param = param.replace('?', '')
            
            if ':' in param:
                parts = param.split(':', 1)
                name = parts[0].strip()
                type_str = parts[1].strip()
                
                # Handle default values
                default_value = None
                if '=' in type_str:
                    type_parts = type_str.split('=', 1)
                    type_str = type_parts[0].strip()
                    default_value = type_parts[1].strip()
                
                type_info = self._parse_type(type_str)
            else:
                name = param.split('=')[0].strip()
                type_info = None
                default_value = param.split('=')[1].strip() if '=' in param else None
            
            params.append(TypeScriptParameter(
                name=name,
                index=idx,
                type_info=type_info,
                is_optional=is_optional,
                default_value=default_value,
                is_rest=is_rest
            ))
        
        return params
    
    def _split_params(self, params_str: str) -> List[str]:
        """Split parameters handling nested generics"""
        result = []
        current = ""
        depth = 0
        
        for char in params_str:
            if char in '<([{':
                depth += 1
            elif char in '>)]}':
                depth -= 1
            
            if char == ',' and depth == 0:
                result.append(current)
                current = ""
            else:
                current += char
        
        if current.strip():
            result.append(current)
        
        return result
    
    def _parse_type(self, type_str: str) -> TypeInfo:
        """Parse a type annotation"""
        if not type_str:
            return TypeInfo(name='unknown')
        
        type_str = type_str.strip()
        
        # Check for nullable
        is_nullable = '| null' in type_str or '| undefined' in type_str or type_str.endswith('?')
        type_str = type_str.replace('| null', '').replace('| undefined', '').rstrip('?').strip()
        
        # Check for array
        is_array = type_str.endswith('[]') or type_str.startswith('Array<')
        if is_array:
            type_str = type_str.rstrip('[]')
            if type_str.startswith('Array<'):
                type_str = type_str[6:-1]
        
        # Check for Promise
        is_promise = type_str.startswith('Promise<')
        if is_promise:
            type_str = type_str[8:-1]
        
        # Extract generic params
        generic_params = []
        if '<' in type_str:
            base = type_str[:type_str.index('<')]
            generics = type_str[type_str.index('<')+1:-1]
            generic_params = [g.strip() for g in self._split_params(generics)]
            type_str = base
        
        return TypeInfo(
            name=type_str,
            is_nullable=is_nullable,
            is_array=is_array,
            is_promise=is_promise,
            generic_params=generic_params,
            is_any=type_str in ('any', 'unknown')
        )
    
    def _find_decorators(self, position: int) -> List[str]:
        """Find decorators above a position"""
        decorators = []
        # Look backwards for decorators
        preceding = self.code[max(0, position-500):position]
        for match in self.PATTERNS['decorator'].finditer(preceding):
            decorators.append(match.group(1))
        return decorators
    
    def _extract_block(self, start: int) -> str:
        """Extract a code block starting at position"""
        depth = 1
        pos = start
        while pos < len(self.code) and depth > 0:
            if self.code[pos] == '{':
                depth += 1
            elif self.code[pos] == '}':
                depth -= 1
            pos += 1
        return self.code[start:pos]
    
    def _extract_methods(self, class_body: str, class_name: str) -> Dict[str, TypeScriptFunction]:
        """Extract methods from class body"""
        methods = {}
        for match in self.PATTERNS['method'].finditer(class_body):
            name = match.group(1)
            params_str = match.group(2)
            return_type = match.group(3)
            line_num = class_body[:match.start()].count('\n') + 1
            
            params = self._parse_parameters(params_str)
            
            methods[name] = TypeScriptFunction(
                name=name,
                file_path=self.file_path,
                line_number=line_num,
                parameters=params,
                return_type=self._parse_type(return_type) if return_type else None,
                is_async='async' in class_body[max(0, match.start()-10):match.start()],
                class_name=class_name
            )
        
        return methods
    
    def _extract_function_calls(self, start: int) -> List[str]:
        """Extract function calls from function body"""
        body = self._extract_block(start)
        calls = []
        for match in self.PATTERNS['call'].finditer(body):
            call_name = match.group(1)
            if call_name not in ('if', 'for', 'while', 'switch', 'catch', 'function'):
                calls.append(call_name)
        return list(set(calls))
    
    def get_taint_sources(self) -> List[Tuple[str, int, str]]:
        """Get potential taint sources based on types"""
        sources = []
        
        for func in self.parse().functions.values():
            for param in func.parameters:
                if param.type_info:
                    if param.type_info.name in self.USER_INPUT_TYPES:
                        sources.append((
                            func.name, 
                            param.index,
                            f"Parameter '{param.name}' is of type '{param.type_info.name}' (user input)"
                        ))
                    elif param.type_info.is_any:
                        sources.append((
                            func.name,
                            param.index,
                            f"Parameter '{param.name}' uses dangerous 'any' type"
                        ))
        
        return sources
    
    def get_type_safety_issues(self) -> List[Dict]:
        """Get type-safety related security issues"""
        issues = []
        file_info = self.parse()
        
        # Check for 'any' type usage
        for func_name, func in file_info.functions.items():
            for param in func.parameters:
                if param.type_info and param.type_info.is_any:
                    issues.append({
                        'type': 'Dangerous Any Type',
                        'severity': 'Medium',
                        'line': func.line_number,
                        'message': f"Function '{func_name}' uses 'any' type for parameter '{param.name}'",
                        'remediation': 'Replace with specific type for better static analysis'
                    })
            
            if func.return_type and func.return_type.is_any:
                issues.append({
                    'type': 'Dangerous Any Return Type',
                    'severity': 'Medium',
                    'line': func.line_number,
                    'message': f"Function '{func_name}' returns 'any' type",
                    'remediation': 'Specify concrete return type'
                })
        
        # Check for type assertions (potential bypass)
        for i, line in enumerate(self.lines, 1):
            if ' as any' in line or '<any>' in line:
                issues.append({
                    'type': 'Type Safety Bypass',
                    'severity': 'High',
                    'line': i,
                    'message': 'Casting to any bypasses type safety',
                    'snippet': line.strip()
                })
            
            if '!' in line and not '//' in line:
                # Non-null assertion
                if re.search(r'\w+!\.', line):
                    issues.append({
                        'type': 'Non-null Assertion Risk',
                        'severity': 'Low',
                        'line': i,
                        'message': 'Non-null assertion may cause runtime errors',
                        'snippet': line.strip()
                    })
        
        return issues


def parse_typescript_file(file_path: str) -> TypeScriptFile:
    """Parse a TypeScript file"""
    with open(file_path, 'r', encoding='utf-8') as f:
        code = f.read()
    parser = TypeScriptParser(file_path, code)
    return parser.parse()


def get_typescript_taint_info(file_path: str) -> Dict[str, Any]:
    """Get taint analysis information from TypeScript file"""
    with open(file_path, 'r', encoding='utf-8') as f:
        code = f.read()
    parser = TypeScriptParser(file_path, code)
    
    return {
        'file': file_path,
        'taint_sources': parser.get_taint_sources(),
        'type_safety_issues': parser.get_type_safety_issues()
    }
