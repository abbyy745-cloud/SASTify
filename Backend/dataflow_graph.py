"""
Dataflow Graph Engine for SASTify

Provides Control Flow Graph (CFG) and Data Flow Graph (DFG) construction
for improved inter-procedural taint analysis.

Features:
- Basic block construction from AST
- Variable definition-use chains  
- Reaching definitions analysis
- Alias tracking
- SSA-like phi node support
"""

import ast
from typing import Dict, List, Set, Optional, Tuple, Any
from dataclasses import dataclass, field
from collections import defaultdict
from enum import Enum


class NodeType(Enum):
    """Types of CFG nodes"""
    ENTRY = "entry"
    EXIT = "exit"
    BASIC_BLOCK = "basic_block"
    CONDITIONAL = "conditional"
    LOOP_HEADER = "loop_header"
    CALL_SITE = "call_site"
    RETURN = "return"
    EXCEPTION = "exception"


@dataclass
class Definition:
    """A variable definition point"""
    variable: str
    line: int
    node_id: int
    is_tainted: bool = False
    taint_source: Optional[str] = None
    aliases: Set[str] = field(default_factory=set)


@dataclass
class Use:
    """A variable use point"""
    variable: str
    line: int
    node_id: int
    reaching_defs: List[Definition] = field(default_factory=list)


@dataclass
class BasicBlock:
    """A basic block in the CFG"""
    id: int
    node_type: NodeType
    statements: List[ast.AST] = field(default_factory=list)
    definitions: List[Definition] = field(default_factory=list)
    uses: List[Use] = field(default_factory=list)
    predecessors: Set[int] = field(default_factory=set)
    successors: Set[int] = field(default_factory=set)
    
    # Dataflow sets
    gen: Set[str] = field(default_factory=set)  # Variables defined here
    kill: Set[str] = field(default_factory=set)  # Variables killed (redefined)
    in_set: Set[Tuple[str, int]] = field(default_factory=set)  # Reaching defs in
    out_set: Set[Tuple[str, int]] = field(default_factory=set)  # Reaching defs out
    
    start_line: int = 0
    end_line: int = 0


@dataclass
class ControlFlowGraph:
    """Control Flow Graph representation"""
    function_name: str
    file_path: str
    entry_block: int = 0
    exit_block: int = -1
    blocks: Dict[int, BasicBlock] = field(default_factory=dict)
    
    def add_edge(self, from_id: int, to_id: int):
        """Add an edge between blocks"""
        if from_id in self.blocks and to_id in self.blocks:
            self.blocks[from_id].successors.add(to_id)
            self.blocks[to_id].predecessors.add(from_id)
    
    def get_all_definitions(self) -> List[Definition]:
        """Get all variable definitions in the CFG"""
        defs = []
        for block in self.blocks.values():
            defs.extend(block.definitions)
        return defs
    
    def get_all_uses(self) -> List[Use]:
        """Get all variable uses in the CFG"""
        uses = []
        for block in self.blocks.values():
            uses.extend(block.uses)
        return uses


class CFGBuilder(ast.NodeVisitor):
    """Builds Control Flow Graph from Python AST"""
    
    def __init__(self, function_name: str, file_path: str):
        self.cfg = ControlFlowGraph(function_name=function_name, file_path=file_path)
        self.current_block_id = 0
        self.block_counter = 0
        self.loop_stack: List[int] = []  # For break/continue
        self.exception_handlers: List[int] = []
        
        # Taint tracking
        self.taint_sources = {
            'request.args', 'request.form', 'request.json', 'request.data',
            'request.values', 'request.cookies', 'request.headers',
            'input', 'sys.argv', 'os.environ', 'os.getenv',
            'Query', 'Body', 'Form', 'Header', 'Cookie', 'Path',
            'req.body', 'req.query', 'req.params'
        }
    
    def build(self, func_node: ast.FunctionDef) -> ControlFlowGraph:
        """Build CFG from a function AST node"""
        # Create entry block
        entry = self._create_block(NodeType.ENTRY)
        self.cfg.entry_block = entry.id
        self.current_block_id = entry.id
        
        # Process function body
        for stmt in func_node.body:
            self.visit(stmt)
        
        # Create exit block
        exit_block = self._create_block(NodeType.EXIT)
        self.cfg.exit_block = exit_block.id
        
        # Connect last block to exit
        if self.current_block_id != exit_block.id:
            self.cfg.add_edge(self.current_block_id, exit_block.id)
        
        return self.cfg
    
    def _create_block(self, node_type: NodeType = NodeType.BASIC_BLOCK) -> BasicBlock:
        """Create a new basic block"""
        block = BasicBlock(id=self.block_counter, node_type=node_type)
        self.cfg.blocks[self.block_counter] = block
        self.block_counter += 1
        return block
    
    def _add_statement(self, stmt: ast.AST):
        """Add statement to current block"""
        block = self.cfg.blocks[self.current_block_id]
        block.statements.append(stmt)
        
        if hasattr(stmt, 'lineno'):
            if block.start_line == 0:
                block.start_line = stmt.lineno
            block.end_line = stmt.lineno
    
    def visit_Assign(self, node: ast.Assign):
        """Handle assignment - creates definition"""
        self._add_statement(node)
        block = self.cfg.blocks[self.current_block_id]
        
        # Check if value is tainted
        value_str = self._get_source_string(node.value)
        is_tainted = any(src in value_str for src in self.taint_sources)
        
        for target in node.targets:
            if isinstance(target, ast.Name):
                var_name = target.id
                definition = Definition(
                    variable=var_name,
                    line=node.lineno,
                    node_id=self.current_block_id,
                    is_tainted=is_tainted,
                    taint_source=value_str if is_tainted else None
                )
                block.definitions.append(definition)
                block.gen.add(var_name)
                
                # Track aliases (x = y means x aliases y)
                if isinstance(node.value, ast.Name):
                    definition.aliases.add(node.value.id)
    
    def visit_AugAssign(self, node: ast.AugAssign):
        """Handle augmented assignment (+=, etc.)"""
        self._add_statement(node)
        block = self.cfg.blocks[self.current_block_id]
        
        if isinstance(node.target, ast.Name):
            var_name = node.target.id
            # This is both a use and a definition
            block.uses.append(Use(variable=var_name, line=node.lineno, node_id=self.current_block_id))
            block.definitions.append(Definition(variable=var_name, line=node.lineno, node_id=self.current_block_id))
            block.gen.add(var_name)
    
    def visit_If(self, node: ast.If):
        """Handle if statement - creates branches"""
        # Condition block
        cond_block = self._create_block(NodeType.CONDITIONAL)
        self.cfg.add_edge(self.current_block_id, cond_block.id)
        self.current_block_id = cond_block.id
        self._add_statement(node.test)
        
        # True branch
        true_block = self._create_block()
        self.cfg.add_edge(cond_block.id, true_block.id)
        self.current_block_id = true_block.id
        for stmt in node.body:
            self.visit(stmt)
        true_end = self.current_block_id
        
        # False branch (else/elif)
        if node.orelse:
            false_block = self._create_block()
            self.cfg.add_edge(cond_block.id, false_block.id)
            self.current_block_id = false_block.id
            for stmt in node.orelse:
                self.visit(stmt)
            false_end = self.current_block_id
        else:
            false_end = cond_block.id
        
        # Merge block
        merge_block = self._create_block()
        self.cfg.add_edge(true_end, merge_block.id)
        if node.orelse:
            self.cfg.add_edge(false_end, merge_block.id)
        else:
            self.cfg.add_edge(cond_block.id, merge_block.id)
        self.current_block_id = merge_block.id
    
    def visit_For(self, node: ast.For):
        """Handle for loop"""
        # Loop header
        header = self._create_block(NodeType.LOOP_HEADER)
        self.cfg.add_edge(self.current_block_id, header.id)
        self.current_block_id = header.id
        self.loop_stack.append(header.id)
        
        # Loop variable is defined
        block = self.cfg.blocks[self.current_block_id]
        if isinstance(node.target, ast.Name):
            block.definitions.append(Definition(
                variable=node.target.id,
                line=node.lineno,
                node_id=self.current_block_id
            ))
            block.gen.add(node.target.id)
        
        # Loop body
        body_block = self._create_block()
        self.cfg.add_edge(header.id, body_block.id)
        self.current_block_id = body_block.id
        for stmt in node.body:
            self.visit(stmt)
        body_end = self.current_block_id
        
        # Back edge
        self.cfg.add_edge(body_end, header.id)
        
        # Exit block
        exit_block = self._create_block()
        self.cfg.add_edge(header.id, exit_block.id)
        self.current_block_id = exit_block.id
        
        # Handle else clause
        if node.orelse:
            for stmt in node.orelse:
                self.visit(stmt)
        
        self.loop_stack.pop()
    
    def visit_While(self, node: ast.While):
        """Handle while loop"""
        header = self._create_block(NodeType.LOOP_HEADER)
        self.cfg.add_edge(self.current_block_id, header.id)
        self.current_block_id = header.id
        self._add_statement(node.test)
        self.loop_stack.append(header.id)
        
        # Loop body
        body_block = self._create_block()
        self.cfg.add_edge(header.id, body_block.id)
        self.current_block_id = body_block.id
        for stmt in node.body:
            self.visit(stmt)
        body_end = self.current_block_id
        
        # Back edge
        self.cfg.add_edge(body_end, header.id)
        
        # Exit block
        exit_block = self._create_block()
        self.cfg.add_edge(header.id, exit_block.id)
        self.current_block_id = exit_block.id
        
        self.loop_stack.pop()
    
    def visit_Return(self, node: ast.Return):
        """Handle return statement"""
        return_block = self._create_block(NodeType.RETURN)
        self.cfg.add_edge(self.current_block_id, return_block.id)
        self.current_block_id = return_block.id
        self._add_statement(node)
        
        # Connect to exit
        if self.cfg.exit_block >= 0:
            self.cfg.add_edge(return_block.id, self.cfg.exit_block)
    
    def visit_Call(self, node: ast.Call):
        """Handle function call"""
        call_block = self._create_block(NodeType.CALL_SITE)
        self.cfg.add_edge(self.current_block_id, call_block.id)
        self.current_block_id = call_block.id
        self._add_statement(node)
        
        # Track uses in call arguments
        block = self.cfg.blocks[self.current_block_id]
        for arg in node.args:
            if isinstance(arg, ast.Name):
                block.uses.append(Use(variable=arg.id, line=node.lineno, node_id=self.current_block_id))
    
    def visit_Try(self, node: ast.Try):
        """Handle try/except"""
        # Try block
        try_block = self._create_block()
        self.cfg.add_edge(self.current_block_id, try_block.id)
        self.current_block_id = try_block.id
        
        for stmt in node.body:
            self.visit(stmt)
        try_end = self.current_block_id
        
        # Exception handlers
        handler_ends = []
        for handler in node.handlers:
            handler_block = self._create_block(NodeType.EXCEPTION)
            self.cfg.add_edge(try_block.id, handler_block.id)
            self.current_block_id = handler_block.id
            for stmt in handler.body:
                self.visit(stmt)
            handler_ends.append(self.current_block_id)
        
        # Merge point
        merge_block = self._create_block()
        self.cfg.add_edge(try_end, merge_block.id)
        for end in handler_ends:
            self.cfg.add_edge(end, merge_block.id)
        self.current_block_id = merge_block.id
        
        # Finally
        if node.finalbody:
            for stmt in node.finalbody:
                self.visit(stmt)
    
    def visit_Name(self, node: ast.Name):
        """Track variable uses"""
        if isinstance(node.ctx, ast.Load):
            block = self.cfg.blocks[self.current_block_id]
            block.uses.append(Use(
                variable=node.id,
                line=node.lineno if hasattr(node, 'lineno') else 0,
                node_id=self.current_block_id
            ))
    
    def _get_source_string(self, node: ast.AST) -> str:
        """Get string representation of AST node"""
        if isinstance(node, ast.Name):
            return node.id
        elif isinstance(node, ast.Attribute):
            return f"{self._get_source_string(node.value)}.{node.attr}"
        elif isinstance(node, ast.Call):
            return f"{self._get_source_string(node.func)}()"
        elif isinstance(node, ast.Subscript):
            return f"{self._get_source_string(node.value)}[]"
        return ""
    
    def generic_visit(self, node: ast.AST):
        """Default visitor"""
        self._add_statement(node)
        for child in ast.iter_child_nodes(node):
            self.visit(child)


class ReachingDefinitionsAnalysis:
    """Compute reaching definitions for taint analysis"""
    
    def __init__(self, cfg: ControlFlowGraph):
        self.cfg = cfg
        self.changed = True
    
    def analyze(self) -> Dict[int, Set[Tuple[str, int]]]:
        """Run reaching definitions analysis"""
        # Initialize
        for block in self.cfg.blocks.values():
            block.in_set = set()
            block.out_set = set()
            # Gen set: (variable, definition_line)
            for defn in block.definitions:
                block.gen.add(defn.variable)
                block.out_set.add((defn.variable, defn.line))
        
        # Iterate until fixpoint
        self.changed = True
        iterations = 0
        max_iterations = 100
        
        while self.changed and iterations < max_iterations:
            self.changed = False
            iterations += 1
            
            for block_id in self._get_traversal_order():
                block = self.cfg.blocks[block_id]
                
                # IN = union of OUT of predecessors
                new_in = set()
                for pred_id in block.predecessors:
                    pred = self.cfg.blocks[pred_id]
                    new_in |= pred.out_set
                
                if new_in != block.in_set:
                    self.changed = True
                    block.in_set = new_in
                
                # OUT = GEN ∪ (IN - KILL)
                killed = {(v, l) for (v, l) in block.in_set if v in block.gen}
                new_out = block.out_set | (block.in_set - killed)
                
                if new_out != block.out_set:
                    self.changed = True
                    block.out_set = new_out
        
        # Connect reaching definitions to uses
        self._connect_defs_to_uses()
        
        return {b.id: b.in_set for b in self.cfg.blocks.values()}
    
    def _get_traversal_order(self) -> List[int]:
        """Get blocks in reverse postorder for faster convergence"""
        visited = set()
        order = []
        
        def dfs(block_id: int):
            if block_id in visited:
                return
            visited.add(block_id)
            for succ in self.cfg.blocks[block_id].successors:
                dfs(succ)
            order.append(block_id)
        
        dfs(self.cfg.entry_block)
        return list(reversed(order))
    
    def _connect_defs_to_uses(self):
        """Connect each use to its reaching definitions"""
        all_defs = {(d.variable, d.line): d for b in self.cfg.blocks.values() for d in b.definitions}
        
        for block in self.cfg.blocks.values():
            for use in block.uses:
                # Find reaching definitions for this variable
                for (var, line) in block.in_set:
                    if var == use.variable and (var, line) in all_defs:
                        use.reaching_defs.append(all_defs[(var, line)])


class TaintedDataflowAnalysis:
    """Analyze taint flow using the dataflow graph"""
    
    def __init__(self, cfg: ControlFlowGraph):
        self.cfg = cfg
        self.tainted_vars: Set[str] = set()
        self.taint_flows: List[Dict] = []
    
    def analyze(self) -> List[Dict]:
        """Find all tainted data flows to sinks"""
        # First, compute reaching definitions
        rd = ReachingDefinitionsAnalysis(self.cfg)
        rd.analyze()
        
        # Find initially tainted definitions
        for block in self.cfg.blocks.values():
            for defn in block.definitions:
                if defn.is_tainted:
                    self.tainted_vars.add(defn.variable)
                    # Propagate through aliases
                    self.tainted_vars |= defn.aliases
        
        # Propagate taint through reaching definitions
        self._propagate_taint()
        
        # Check for sinks with tainted input
        self._check_sinks()
        
        return self.taint_flows
    
    def _propagate_taint(self):
        """Propagate taint through variable assignments"""
        changed = True
        iterations = 0
        
        while changed and iterations < 50:
            changed = False
            iterations += 1
            
            for block in self.cfg.blocks.values():
                for defn in block.definitions:
                    if defn.variable in self.tainted_vars:
                        continue
                    
                    # Check if any reaching definition is tainted
                    for use in block.uses:
                        if use.variable in self.tainted_vars:
                            # If this use flows to this definition (same statement)
                            if any(d.line == defn.line for d in use.reaching_defs if d.is_tainted):
                                self.tainted_vars.add(defn.variable)
                                defn.is_tainted = True
                                changed = True
    
    def _check_sinks(self):
        """Check if tainted data reaches dangerous sinks"""
        sinks = {
            'execute': 'sql_injection',
            'query': 'sql_injection',
            'eval': 'code_injection',
            'exec': 'code_injection',
            'system': 'command_injection',
            'popen': 'command_injection',
            'innerHTML': 'xss',
            'write': 'xss',
            'load': 'deserialization',
            'loads': 'deserialization',
        }
        
        for block in self.cfg.blocks.values():
            if block.node_type == NodeType.CALL_SITE:
                for stmt in block.statements:
                    if isinstance(stmt, ast.Call):
                        func_name = self._get_func_name(stmt)
                        for sink_pattern, vuln_type in sinks.items():
                            if sink_pattern in func_name.lower():
                                # Check if any argument is tainted
                                for use in block.uses:
                                    if use.variable in self.tainted_vars:
                                        self.taint_flows.append({
                                            'type': vuln_type,
                                            'sink': func_name,
                                            'tainted_var': use.variable,
                                            'line': block.start_line,
                                            'block_id': block.id,
                                            'confidence': 0.95,
                                            'severity': 'Critical' if vuln_type in ['sql_injection', 'code_injection'] else 'High'
                                        })
    
    def _get_func_name(self, node: ast.Call) -> str:
        """Extract function name from call node"""
        if isinstance(node.func, ast.Name):
            return node.func.id
        elif isinstance(node.func, ast.Attribute):
            return f"{self._get_attr_chain(node.func)}"
        return ""
    
    def _get_attr_chain(self, node: ast.Attribute) -> str:
        """Get full attribute chain like a.b.c"""
        if isinstance(node.value, ast.Attribute):
            return f"{self._get_attr_chain(node.value)}.{node.attr}"
        elif isinstance(node.value, ast.Name):
            return f"{node.value.id}.{node.attr}"
        return node.attr


def build_function_cfg(code: str, function_name: str = "", file_path: str = "") -> Optional[ControlFlowGraph]:
    """Build CFG for a specific function or the first function in code"""
    try:
        tree = ast.parse(code)
        
        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef):
                if not function_name or node.name == function_name:
                    builder = CFGBuilder(node.name, file_path)
                    return builder.build(node)
        return None
    except SyntaxError:
        return None


def analyze_function_taint(code: str, function_name: str = "", file_path: str = "") -> List[Dict]:
    """Analyze taint flow in a function using dataflow analysis"""
    cfg = build_function_cfg(code, function_name, file_path)
    if not cfg:
        return []
    
    analyzer = TaintedDataflowAnalysis(cfg)
    return analyzer.analyze()


# Integration with existing scanner
class DataflowEnhancedScanner:
    """Scanner that uses dataflow analysis for improved accuracy"""
    
    def __init__(self):
        self.taint_sources = set()
        self.sinks = {}
    
    def scan_file(self, code: str, file_path: str) -> List[Dict]:
        """Scan a file using dataflow-enhanced analysis"""
        issues = []
        
        try:
            tree = ast.parse(code)
            
            for node in ast.walk(tree):
                if isinstance(node, ast.FunctionDef):
                    # Build CFG and analyze each function
                    cfg = build_function_cfg(code, node.name, file_path)
                    if cfg:
                        flows = analyze_function_taint(code, node.name, file_path)
                        for flow in flows:
                            flow['file'] = file_path
                            flow['function'] = node.name
                            flow['scanner'] = 'dataflow_analysis'
                            issues.append(flow)
        except:
            pass
        
        return issues
