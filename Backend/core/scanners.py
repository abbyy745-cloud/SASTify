import ast
from typing import List, Dict, Any
from .taint_graph import TaintGraph, TaintSourceType

class BaseScanner:
    def __init__(self, taint_graph: TaintGraph, rules: Dict):
        self.taint_graph = taint_graph
        self.rules = rules
        self.issues = []

    def scan(self, code: str, file_path: str):
        raise NotImplementedError

class GraphPythonScanner(BaseScanner):
    def scan(self, code: str, file_path: str):
        try:
            tree = ast.parse(code)
            self._visit(tree, file_path, code)
        except Exception as e:
            print(f"Error scanning {file_path}: {e}")
        return self.issues

    def _visit(self, node: ast.AST, file_path: str, code: str):
        # Check suppression
        if self._is_suppressed(node, code):
            return

        # 1. Assignments (Flow)
        if isinstance(node, ast.Assign):
            self._handle_assign(node, file_path, code)
        
        # 2. Calls (Sinks & Sanitizers)
        if isinstance(node, ast.Call):
            self._handle_call(node, file_path, code)

        # 3. Custom Patterns
        self._check_custom_patterns(node, file_path, code)

        for child in ast.iter_child_nodes(node):
            self._visit(child, file_path, code)

    def _is_suppressed(self, node: ast.AST, code: str) -> bool:
        if hasattr(node, 'lineno'):
            line = code.splitlines()[node.lineno - 1]
            if '# sastify:ignore' in line or '# nosec' in line:
                return True
        return False

    def _check_custom_patterns(self, node: ast.AST, file_path: str, code: str):
        for pattern in self.rules.get('patterns', []):
            if pattern.get('language') == 'python':
                # Regex match on node source
                if 'regex' in pattern:
                    import re
                    node_source = self._get_node_source(code, node)
                    if re.search(pattern['regex'], node_source):
                        self.issues.append({
                            'type': pattern.get('type', 'custom_pattern'),
                            'file': file_path,
                            'line': node.lineno if hasattr(node, 'lineno') else 0,
                            'description': pattern.get('name', 'Custom Pattern Match'),
                            'severity': pattern.get('severity', 'Medium')
                        })

    def _get_node_source(self, code: str, node: ast.AST) -> str:
        if hasattr(node, 'lineno') and hasattr(node, 'end_lineno'):
            lines = code.splitlines()
            return "\n".join(lines[node.lineno-1:node.end_lineno])
        return ""


    def _handle_assign(self, node: ast.Assign, file_path: str, code: str):
        # source = value
        # target = targets
        
        value_source_str = self._get_source_segment(node.value)
        
        # Check if value is a known source
        is_source = False
        for src in self.rules['sources'].get('python', []):
            if src in value_source_str:
                is_source = True
                break
        
        for target in node.targets:
            if isinstance(target, ast.Name):
                target_name = target.id
                if is_source:
                    # Create a source node
                    self.taint_graph.get_or_create_node(target_name, file_path, node.lineno, TaintSourceType.USER_INPUT)
                else:
                    # Check if value comes from another variable (Flow)
                    if isinstance(node.value, ast.Name):
                        self.taint_graph.add_flow(node.value.id, target_name, file_path, node.lineno)
                    elif isinstance(node.value, ast.Call):
                        # Check if it's a sanitizer call
                        func_name = self._get_func_name(node.value)
                        if func_name in self.rules['sanitizers'].get('python', []):
                            # It's a sanitizer!
                            # We need to flow taint BUT add sanitizer tag
                            # Assuming single arg sanitizer for now: clean = sanitize(dirty)
                            if node.value.args:
                                arg0 = node.value.args[0]
                                if isinstance(arg0, ast.Name):
                                    self.taint_graph.add_flow(arg0.id, target_name, file_path, node.lineno)
                                    self.taint_graph.apply_sanitizer(target_name, func_name, file_path, node.lineno)
                    elif isinstance(node.value, ast.BinOp):
                        # Handle concatenation: left -> target, right -> target
                        self._handle_binop_flow(node.value, target_name, file_path, node.lineno)

    def _handle_binop_flow(self, node: ast.BinOp, target_name: str, file_path: str, line: int):
        if isinstance(node.left, ast.Name):
            self.taint_graph.add_flow(node.left.id, target_name, file_path, line)
        elif isinstance(node.left, ast.BinOp):
            self._handle_binop_flow(node.left, target_name, file_path, line)
            
        if isinstance(node.right, ast.Name):
            self.taint_graph.add_flow(node.right.id, target_name, file_path, line)

    def _handle_call(self, node: ast.Call, file_path: str, code: str):
        func_name = self._get_func_name(node)
        
        # Check Sinks
        for vuln_type, sinks in self.rules['sinks'].get('python', {}).items():
            if func_name in sinks:
                # Check if any arg is tainted
                for arg in node.args:
                    arg_name = self._get_source_segment(arg)
                    # We need to check if this arg corresponds to a tainted node in the graph
                    # Since we are building the graph, we might need to look it up
                    # But for now, let's just check if the node exists and is tainted
                    
                    # If arg is a variable
                    if isinstance(arg, ast.Name):
                        taint_node = self.taint_graph.get_or_create_node(arg.id, file_path, node.lineno)
                        if taint_node.tainted:
                            # Check if sanitized
                            if taint_node.sanitizers:
                                # For now, assume any sanitizer fixes it. 
                                # In future, check if sanitizer matches sink type (e.g. sql escape for sql sink)
                                continue
                                
                            self.issues.append({
                                'type': vuln_type,
                                'file': file_path,
                                'line': node.lineno,
                                'description': f"Tainted data reaches sink {func_name}",
                                'severity': 'High',
                                'trace': self.taint_graph.get_trace(taint_node)
                            })

        # Check Sanitizers
        if func_name in self.rules['sanitizers'].get('python', []):
            # If this call is part of an assignment, the target will be sanitized
            # But here we are just visiting the call. 
            # We need to handle this in Assignment if the value is a Call.
            pass

    def _get_func_name(self, node: ast.Call) -> str:
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
        return ""

    def _get_source_segment(self, node: ast.AST) -> str:
        if isinstance(node, ast.Name):
            return node.id
        if isinstance(node, ast.Attribute):
             return f"{self._get_source_segment(node.value)}.{node.attr}"
        if isinstance(node, ast.Call):
            return self._get_source_segment(node.func)
        return ""
