"""
Tree-Sitter Scanner Base Module

Provides universal AST parsing for Swift, Kotlin, and Dart using tree-sitter.
This enables real semantic analysis instead of regex pattern matching.

Supported languages:
- Swift (iOS/macOS)
- Kotlin (Android)
- Dart (Flutter)
"""

import os
from typing import List, Dict, Set, Optional, Any, Tuple, Iterator
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path

# Try to import tree-sitter (graceful fallback if not installed)
try:
    import tree_sitter
    from tree_sitter import Language, Parser, Node, Tree
    TREE_SITTER_AVAILABLE = True
except ImportError:
    TREE_SITTER_AVAILABLE = False
    Language = None
    Parser = None
    Node = None
    Tree = None


class MobileLanguage(Enum):
    """Supported mobile languages"""
    SWIFT = "swift"
    KOTLIN = "kotlin"
    DART = "dart"


@dataclass
class ASTNode:
    """Wrapper for tree-sitter node with additional metadata"""
    type: str
    text: str
    start_line: int
    end_line: int
    start_col: int
    end_col: int
    children: List['ASTNode'] = field(default_factory=list)
    parent_type: Optional[str] = None
    
    @classmethod
    def from_ts_node(cls, node: 'Node', code_bytes: bytes) -> 'ASTNode':
        """Create ASTNode from tree-sitter node"""
        if not TREE_SITTER_AVAILABLE or node is None:
            return None
        
        text = code_bytes[node.start_byte:node.end_byte].decode('utf-8', errors='ignore')
        
        return cls(
            type=node.type,
            text=text[:500],  # Limit text size
            start_line=node.start_point[0] + 1,  # 1-indexed
            end_line=node.end_point[0] + 1,
            start_col=node.start_point[1],
            end_col=node.end_point[1],
            parent_type=node.parent.type if node.parent else None
        )


@dataclass
class TaintInfo:
    """Information about a tainted variable or expression"""
    variable: str
    source: str
    source_line: int
    taint_type: str  # 'user_input', 'network', 'file', etc.
    is_sanitized: bool = False
    sanitizer: Optional[str] = None


@dataclass
class Vulnerability:
    """Detected vulnerability"""
    vuln_type: str
    severity: str
    line: int
    column: int
    snippet: str
    description: str
    cwe_id: str
    confidence: float
    ast_node_type: str
    taint_source: Optional[str] = None
    taint_sink: Optional[str] = None
    remediation: str = ""


class TreeSitterScanner:
    """
    Base class for tree-sitter based AST scanning.
    Provides common utilities for Swift, Kotlin, and Dart scanners.
    """
    
    # Language-specific grammars (loaded lazily)
    _languages: Dict[str, Any] = {}
    _parsers: Dict[str, Any] = {}
    
    def __init__(self, language: MobileLanguage):
        self.language = language
        self.issues: List[Vulnerability] = []
        self.tainted_vars: Dict[str, TaintInfo] = {}
        self.current_scope: List[str] = []
        self.code_bytes: bytes = b""
        
        # Initialize parser for this language
        if TREE_SITTER_AVAILABLE:
            self._init_parser()
    
    def _init_parser(self):
        """Initialize tree-sitter parser for the language"""
        lang_name = self.language.value
        
        if lang_name in self._parsers:
            return
        
        try:
            # Try to load language grammar
            if lang_name == 'swift':
                try:
                    import tree_sitter_swift
                    self._languages[lang_name] = Language(tree_sitter_swift.language())
                except ImportError:
                    # Fallback: try to load from compiled .so file
                    self._load_language_from_so(lang_name)
                    
            elif lang_name == 'kotlin':
                try:
                    import tree_sitter_kotlin
                    self._languages[lang_name] = Language(tree_sitter_kotlin.language())
                except ImportError:
                    self._load_language_from_so(lang_name)
                    
            elif lang_name == 'dart':
                try:
                    import tree_sitter_dart
                    self._languages[lang_name] = Language(tree_sitter_dart.language())
                except ImportError:
                    self._load_language_from_so(lang_name)
            
            if lang_name in self._languages:
                parser = Parser()
                parser.language = self._languages[lang_name]
                self._parsers[lang_name] = parser
                
        except Exception as e:
            print(f"Warning: Could not initialize tree-sitter for {lang_name}: {e}")
    
    def _load_language_from_so(self, lang_name: str):
        """Try to load language from compiled .so file"""
        # Look for pre-built .so files in common locations
        so_paths = [
            Path(__file__).parent / 'grammars' / f'{lang_name}.so',
            Path(__file__).parent / f'tree-sitter-{lang_name}.so',
            Path.home() / '.tree-sitter' / f'{lang_name}.so',
        ]
        
        for path in so_paths:
            if path.exists():
                self._languages[lang_name] = Language(str(path), lang_name)
                return
    
    @property
    def parser(self) -> Optional['Parser']:
        """Get the parser for this language"""
        return self._parsers.get(self.language.value)
    
    def parse(self, code: str) -> Optional['Tree']:
        """Parse code and return AST tree"""
        if not TREE_SITTER_AVAILABLE or not self.parser:
            return None
        
        self.code_bytes = code.encode('utf-8')
        return self.parser.parse(self.code_bytes)
    
    def traverse(self, node: 'Node', visitor_func) -> None:
        """
        Traverse AST tree depth-first, calling visitor_func for each node.
        visitor_func(node, depth) -> bool: return False to skip children
        """
        if node is None:
            return
        
        def _visit(n: 'Node', depth: int = 0):
            if visitor_func(n, depth):
                for child in n.children:
                    _visit(child, depth + 1)
        
        _visit(node)
    
    def find_nodes_by_type(self, tree: 'Tree', node_types: List[str]) -> Iterator['Node']:
        """Find all nodes of specified types"""
        if tree is None:
            return
        
        def _find(node: 'Node'):
            if node.type in node_types:
                yield node
            for child in node.children:
                yield from _find(child)
        
        yield from _find(tree.root_node)
    
    def get_node_text(self, node: 'Node') -> str:
        """Get the source text for a node"""
        if node is None:
            return ""
        return self.code_bytes[node.start_byte:node.end_byte].decode('utf-8', errors='ignore')
    
    def get_children_by_type(self, node: 'Node', child_type: str) -> List['Node']:
        """Get all direct children of a specific type"""
        if node is None:
            return []
        return [c for c in node.children if c.type == child_type]
    
    def get_child_by_field(self, node: 'Node', field_name: str) -> Optional['Node']:
        """Get child node by field name"""
        if node is None:
            return None
        return node.child_by_field_name(field_name)
    
    def is_inside_comment(self, node: 'Node') -> bool:
        """Check if node is inside a comment"""
        parent = node.parent
        while parent:
            if 'comment' in parent.type.lower():
                return True
            parent = parent.parent
        return False
    
    def is_inside_string(self, node: 'Node') -> bool:
        """Check if node is inside a string literal"""
        parent = node.parent
        while parent:
            if 'string' in parent.type.lower() and 'interpolation' not in parent.type.lower():
                return True
            parent = parent.parent
        return False
    
    def mark_tainted(self, variable: str, source: str, line: int, taint_type: str = 'user_input'):
        """Mark a variable as tainted"""
        scoped_var = '.'.join(self.current_scope + [variable])
        self.tainted_vars[scoped_var] = TaintInfo(
            variable=variable,
            source=source,
            source_line=line,
            taint_type=taint_type
        )
        # Also store without scope for simpler lookups
        self.tainted_vars[variable] = self.tainted_vars[scoped_var]
    
    def is_tainted(self, variable: str) -> bool:
        """Check if a variable is tainted"""
        if variable in self.tainted_vars:
            return not self.tainted_vars[variable].is_sanitized
        
        scoped_var = '.'.join(self.current_scope + [variable])
        if scoped_var in self.tainted_vars:
            return not self.tainted_vars[scoped_var].is_sanitized
        
        return False
    
    def mark_sanitized(self, variable: str, sanitizer: str):
        """Mark a variable as sanitized"""
        if variable in self.tainted_vars:
            self.tainted_vars[variable].is_sanitized = True
            self.tainted_vars[variable].sanitizer = sanitizer
    
    def add_issue(self, vuln_type: str, severity: str, node: 'Node', 
                  description: str, cwe_id: str, confidence: float = 0.85,
                  taint_source: str = None, taint_sink: str = None,
                  remediation: str = ""):
        """Add a vulnerability finding"""
        if node is None:
            return
        
        # Skip if inside comment
        if self.is_inside_comment(node):
            return
        
        snippet = self.get_node_text(node)[:120]
        
        self.issues.append(Vulnerability(
            vuln_type=vuln_type,
            severity=severity,
            line=node.start_point[0] + 1,
            column=node.start_point[1],
            snippet=snippet,
            description=description,
            cwe_id=cwe_id,
            confidence=confidence,
            ast_node_type=node.type,
            taint_source=taint_source,
            taint_sink=taint_sink,
            remediation=remediation
        ))
    
    def scan(self, code: str, filename: str = "") -> List[Dict]:
        """
        Main scanning entry point.
        Override in subclasses to implement language-specific scanning.
        """
        self.issues = []
        self.tainted_vars = {}
        
        tree = self.parse(code)
        if tree is None:
            # Fallback: return empty if parsing failed
            return []
        
        # Call language-specific analysis
        self._analyze(tree, code, filename)
        
        return self._to_dict_list(filename)
    
    def _analyze(self, tree: 'Tree', code: str, filename: str):
        """Override in subclasses for language-specific analysis"""
        pass
    
    def _to_dict_list(self, filename: str) -> List[Dict]:
        """Convert issues to dict format"""
        return [
            {
                'type': v.vuln_type,
                'severity': v.severity,
                'line': v.line,
                'column': v.column,
                'snippet': v.snippet,
                'description': v.description,
                'cwe_id': v.cwe_id,
                'confidence': v.confidence,
                'ast_node_type': v.ast_node_type,
                'taint_source': v.taint_source,
                'taint_sink': v.taint_sink,
                'remediation': v.remediation,
                'file': filename,
                'language': self.language.value,
                'scanner': f'{self.language.value}_ast_scanner'
            }
            for v in self.issues
        ]


def is_tree_sitter_available() -> bool:
    """Check if tree-sitter is available"""
    return TREE_SITTER_AVAILABLE


def get_available_languages() -> List[str]:
    """Get list of languages with available parsers"""
    available = []
    
    if not TREE_SITTER_AVAILABLE:
        return available
    
    for lang in MobileLanguage:
        try:
            scanner = TreeSitterScanner(lang)
            if scanner.parser is not None:
                available.append(lang.value)
        except:
            pass
    
    return available
