"""
Call Graph Builder - Constructs and analyzes function call relationships

This module builds a call graph from the project index and provides
utilities for traversing the graph for taint analysis.
"""

from dataclasses import dataclass, field
from typing import Dict, List, Set, Optional, Tuple, Any
from collections import defaultdict, deque
from enum import Enum

from project_analyzer import ProjectIndex, FunctionInfo, FileInfo, Language


class EdgeType(Enum):
    """Type of edge in call graph"""
    DIRECT_CALL = "direct"      # foo() calls bar()
    METHOD_CALL = "method"       # obj.method()
    CALLBACK = "callback"        # passed as argument
    IMPORT = "import"           # imported function


@dataclass
class CallEdge:
    """An edge in the call graph representing a function call"""
    caller: str           # Fully qualified caller name
    callee: str           # Fully qualified callee name
    caller_file: str
    callee_file: Optional[str]
    line_number: int
    edge_type: EdgeType
    argument_mapping: Dict[int, int] = field(default_factory=dict)  # caller_arg_idx -> callee_param_idx


@dataclass 
class CallGraphNode:
    """A node in the call graph representing a function"""
    name: str
    file_path: str
    function_info: FunctionInfo
    outgoing_edges: List[CallEdge] = field(default_factory=list)  # Calls FROM this function
    incoming_edges: List[CallEdge] = field(default_factory=list)  # Calls TO this function
    is_entry_point: bool = False
    is_sink: bool = False
    is_source: bool = False


class CallGraph:
    """
    Complete call graph for a project.
    
    Supports:
    - Forward traversal (what does function X call?)
    - Backward traversal (what calls function X?)
    - Path finding (is there a path from A to B?)
    """
    
    def __init__(self):
        self.nodes: Dict[str, CallGraphNode] = {}
        self.edges: List[CallEdge] = []
        self.entry_points: Set[str] = set()
        self.sinks: Set[str] = set()
        self.sources: Set[str] = set()
        
        # Known dangerous sinks
        self.known_sinks = {
            # SQL Injection
            'cursor.execute', 'connection.execute', 'db.execute',
            'Model.objects.raw', 'session.execute',
            # Code Injection
            'eval', 'exec', 'compile', 'os.system', 'subprocess.call',
            'subprocess.run', 'subprocess.Popen',
            # XSS
            'innerHTML', 'document.write', 'render_template_string',
            # Path Traversal
            'open', 'send_file',
            # SSRF
            'requests.get', 'requests.post', 'fetch', 'axios.get', 'axios.post',
            # AI/LLM
            'openai.ChatCompletion.create', 'openai.Completion.create',
            'langchain.LLMChain.run', 'llm.generate',
        }
        
        # Known sources (user input)
        self.known_sources = {
            # Flask
            'request.args.get', 'request.form.get', 'request.json.get',
            'request.data', 'request.cookies.get',
            # Django
            'request.GET.get', 'request.POST.get', 'request.body',
            # Express
            'req.body', 'req.query', 'req.params', 'req.cookies',
            # FastAPI
            'Query', 'Body', 'Form', 'Path', 'Header',
        }
    
    def add_node(self, name: str, file_path: str, func_info: FunctionInfo) -> CallGraphNode:
        """Add a node to the graph"""
        fqn = self._get_fqn(name, file_path)
        
        if fqn not in self.nodes:
            node = CallGraphNode(
                name=name,
                file_path=file_path,
                function_info=func_info,
                is_entry_point=func_info.is_route,
                is_sink=self._is_sink(name),
                is_source=any(src in name for src in self.known_sources)
            )
            self.nodes[fqn] = node
            
            if node.is_entry_point:
                self.entry_points.add(fqn)
            if node.is_sink:
                self.sinks.add(fqn)
            if node.is_source:
                self.sources.add(fqn)
        
        return self.nodes[fqn]
    
    def add_edge(self, caller: str, callee: str, caller_file: str, 
                 callee_file: Optional[str], line_number: int,
                 edge_type: EdgeType = EdgeType.DIRECT_CALL,
                 arg_mapping: Optional[Dict[int, int]] = None):
        """Add an edge to the graph"""
        caller_fqn = self._get_fqn(caller, caller_file)
        callee_fqn = self._get_fqn(callee, callee_file) if callee_file else callee
        
        edge = CallEdge(
            caller=caller_fqn,
            callee=callee_fqn,
            caller_file=caller_file,
            callee_file=callee_file,
            line_number=line_number,
            edge_type=edge_type,
            argument_mapping=arg_mapping or {}
        )
        
        self.edges.append(edge)
        
        # Update nodes
        if caller_fqn in self.nodes:
            self.nodes[caller_fqn].outgoing_edges.append(edge)
        if callee_fqn in self.nodes:
            self.nodes[callee_fqn].incoming_edges.append(edge)
    
    def _get_fqn(self, name: str, file_path: str) -> str:
        """Get fully qualified name for a function"""
        return f"{file_path}::{name}"
    
    def _is_sink(self, name: str) -> bool:
        """Check if a function name is a known sink"""
        return any(sink in name for sink in self.known_sinks)
    
    def get_callees(self, function_fqn: str) -> List[str]:
        """Get all functions called by a function"""
        if function_fqn not in self.nodes:
            return []
        return [edge.callee for edge in self.nodes[function_fqn].outgoing_edges]
    
    def get_callers(self, function_fqn: str) -> List[str]:
        """Get all functions that call a function"""
        if function_fqn not in self.nodes:
            return []
        return [edge.caller for edge in self.nodes[function_fqn].incoming_edges]
    
    def find_paths_to_sinks(self, start_fqn: str, max_depth: int = 10) -> List[List[str]]:
        """Find all paths from a function to any sink"""
        paths = []
        self._dfs_to_sink(start_fqn, [], set(), paths, max_depth)
        return paths
    
    def _dfs_to_sink(self, current: str, path: List[str], visited: Set[str], 
                     paths: List[List[str]], max_depth: int):
        """DFS to find paths to sinks"""
        if len(path) > max_depth:
            return
        
        if current in visited:
            return
        
        visited.add(current)
        path.append(current)
        
        # Check if current is a sink
        if current in self.nodes and self.nodes[current].is_sink:
            paths.append(path.copy())
        elif self._is_sink(current.split('::')[-1] if '::' in current else current):
            paths.append(path.copy())
        
        # Continue DFS
        for callee in self.get_callees(current):
            self._dfs_to_sink(callee, path, visited, paths, max_depth)
        
        path.pop()
        visited.remove(current)
    
    def find_paths_from_sources(self, max_depth: int = 10) -> List[List[str]]:
        """Find all paths from entry points to sinks"""
        all_paths = []
        for entry in self.entry_points:
            paths = self.find_paths_to_sinks(entry, max_depth)
            all_paths.extend(paths)
        return all_paths
    
    def get_reachable(self, start_fqn: str, direction: str = 'forward') -> Set[str]:
        """Get all reachable nodes from a starting point"""
        reachable = set()
        queue = deque([start_fqn])
        
        while queue:
            current = queue.popleft()
            if current in reachable:
                continue
            reachable.add(current)
            
            if direction == 'forward':
                neighbors = self.get_callees(current)
            else:
                neighbors = self.get_callers(current)
            
            for neighbor in neighbors:
                if neighbor not in reachable:
                    queue.append(neighbor)
        
        return reachable
    
    def topological_sort(self) -> List[str]:
        """
        Topological sort of the call graph.
        Useful for bottom-up analysis (callees before callers).
        """
        in_degree = defaultdict(int)
        for node in self.nodes:
            in_degree[node] = len(self.get_callers(node))
        
        # Start with nodes that have no incoming edges
        queue = deque([node for node in self.nodes if in_degree[node] == 0])
        result = []
        
        while queue:
            node = queue.popleft()
            result.append(node)
            
            for callee in self.get_callees(node):
                in_degree[callee] -= 1
                if in_degree[callee] == 0:
                    queue.append(callee)
        
        # Handle cycles by adding remaining nodes
        remaining = [n for n in self.nodes if n not in result]
        result.extend(remaining)
        
        return result
    
    def reverse_topological_sort(self) -> List[str]:
        """Reverse topological sort (callers before callees)"""
        return list(reversed(self.topological_sort()))
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization"""
        return {
            'nodes': [
                {
                    'name': node.name,
                    'file': node.file_path,
                    'is_entry': node.is_entry_point,
                    'is_sink': node.is_sink,
                    'outgoing': [e.callee for e in node.outgoing_edges],
                    'incoming': [e.caller for e in node.incoming_edges]
                }
                for node in self.nodes.values()
            ],
            'edges': [
                {
                    'from': e.caller,
                    'to': e.callee,
                    'line': e.line_number,
                    'type': e.edge_type.value
                }
                for e in self.edges
            ],
            'entry_points': list(self.entry_points),
            'sinks': list(self.sinks),
            'statistics': {
                'total_nodes': len(self.nodes),
                'total_edges': len(self.edges),
                'entry_points': len(self.entry_points),
                'sinks': len(self.sinks)
            }
        }


class CallGraphBuilder:
    """Builds call graph from project index"""
    
    def __init__(self, project_index: ProjectIndex):
        self.index = project_index
        self.graph = CallGraph()
        
    def build(self) -> CallGraph:
        """Build the complete call graph"""
        # Phase 1: Add all functions as nodes
        self._add_all_nodes()
        
        # Phase 2: Add edges for function calls
        self._add_all_edges()
        
        print(f"Built call graph: {len(self.graph.nodes)} nodes, {len(self.graph.edges)} edges")
        print(f"Entry points: {len(self.graph.entry_points)}, Sinks: {len(self.graph.sinks)}")
        
        return self.graph
    
    def _add_all_nodes(self):
        """Add all functions as nodes"""
        for file_path, file_info in self.index.files.items():
            for func_name, func_info in file_info.functions.items():
                self.graph.add_node(func_name, file_path, func_info)
    
    def _add_all_edges(self):
        """Add edges for all function calls"""
        for file_path, file_info in self.index.files.items():
            for func_name, func_info in file_info.functions.items():
                caller_fqn = f"{file_path}::{func_name}"
                
                for call in func_info.calls:
                    # Try to resolve the callee
                    callee_file = self._resolve_callee(call, file_info, file_path)
                    
                    self.graph.add_edge(
                        caller=func_name,
                        callee=call,
                        caller_file=file_path,
                        callee_file=callee_file,
                        line_number=func_info.line_number,
                        edge_type=EdgeType.DIRECT_CALL
                    )
    
    def _resolve_callee(self, call_name: str, file_info: FileInfo, 
                        current_file: str) -> Optional[str]:
        """Resolve a function call to its definition file"""
        # Check if it's defined in current file
        if call_name in file_info.functions:
            return current_file
        
        # Check if it's imported
        parts = call_name.split('.')
        first_part = parts[0]
        
        for imp in file_info.imports:
            if first_part in imp.names or (not imp.names and imp.module.endswith(first_part)):
                if imp.resolved_path:
                    return imp.resolved_path
        
        # Check symbol table
        if call_name in self.index.symbol_table:
            # Return first match (could be ambiguous)
            return self.index.symbol_table[call_name][0]
        
        return None  # External or unresolved
    
    def get_paths_to_vulnerability(self, sink_name: str) -> List[List[str]]:
        """Get all paths from entry points to a specific sink"""
        paths = []
        
        for entry in self.graph.entry_points:
            entry_paths = self.graph.find_paths_to_sinks(entry)
            for path in entry_paths:
                if any(sink_name in node for node in path):
                    paths.append(path)
        
        return paths


def build_call_graph(project_index: ProjectIndex) -> CallGraph:
    """Convenience function to build call graph from project index"""
    builder = CallGraphBuilder(project_index)
    return builder.build()
