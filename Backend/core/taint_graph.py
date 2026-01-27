from enum import Enum
from typing import List, Set, Dict, Optional
import uuid

class TaintSourceType(Enum):
    USER_INPUT = "user_input"
    FILE_READ = "file_read"
    NETWORK_READ = "network_read"
    DATABASE_READ = "database_read"
    ENVIRONMENT = "environment"
    OTHER = "other"

class TaintNode:
    def __init__(self, name: str, source_type: Optional[TaintSourceType] = None, file_path: str = "", line_number: int = 0):
        self.id = str(uuid.uuid4())
        self.name = name
        self.source_type = source_type
        self.file_path = file_path
        self.line_number = line_number
        self.sanitizers: Set[str] = set()
        self.tainted = False
        self.parents: List['TaintNode'] = []
        self.children: List['TaintNode'] = []

    def add_sanitizer(self, sanitizer_name: str):
        self.sanitizers.add(sanitizer_name)
        # Logic: Some sanitizers might clear taint, others might just tag it
        # For now, we keep the node tainted but mark it as sanitized for specific contexts

    def is_sanitized_for(self, vulnerability_type: str) -> bool:
        # Check if any applied sanitizer covers the vulnerability type
        # This requires a mapping of sanitizers to vuln types
        return False # Placeholder

class TaintGraph:
    def __init__(self):
        self.nodes: Dict[str, TaintNode] = {} # Map node ID to Node
        self.variable_map: Dict[str, TaintNode] = {} # Map "file:var_name" to Node

    def get_or_create_node(self, name: str, file_path: str, line: int, source_type: Optional[TaintSourceType] = None) -> TaintNode:
        key = f"{file_path}:{name}"
        if key in self.variable_map:
            return self.variable_map[key]
        
        node = TaintNode(name, source_type, file_path, line)
        if source_type:
            node.tainted = True
            
        self.nodes[node.id] = node
        self.variable_map[key] = node
        return node

    def add_flow(self, source_name: str, target_name: str, file_path: str, line: int):
        """Record a data flow from source_var to target_var"""
        source_node = self.get_or_create_node(source_name, file_path, line) # Line might be approx for source
        target_node = self.get_or_create_node(target_name, file_path, line)
        
        # Link
        source_node.children.append(target_node)
        target_node.parents.append(source_node)
        
        # Propagate taint
        if source_node.tainted:
            target_node.tainted = True
            # Propagate sanitizers? Maybe not, sanitizers usually apply to the value *at that point*
            # But if source was sanitized, target is also sanitized copy.
            target_node.sanitizers.update(source_node.sanitizers)

    def apply_sanitizer(self, var_name: str, sanitizer: str, file_path: str, line: int):
        node = self.get_or_create_node(var_name, file_path, line)
        node.add_sanitizer(sanitizer)

    def get_trace(self, sink_node: TaintNode) -> List[str]:
        """Backtrack to find the source of taint"""
        trace = []
        visited = set()
        
        def dfs(node: TaintNode):
            if node.id in visited:
                return
            visited.add(node.id)
            trace.append(f"{node.file_path}:{node.line_number} - {node.name}")
            for parent in node.parents:
                dfs(parent)
        
        dfs(sink_node)
        return list(reversed(trace))
