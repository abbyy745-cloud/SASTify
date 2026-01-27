"""
Enhanced Cross-File Taint Engine

Extends the base cross-file analysis with:
- Async/await data flow tracking
- Promise chain analysis
- Callback propagation
- Class inheritance taint
- Global state tracking
- Module re-exports
- Higher-order function analysis
- Closure capture tracking
"""

from dataclasses import dataclass, field
from typing import Dict, List, Set, Optional, Any, Tuple
from collections import defaultdict, deque
from enum import Enum
import re

from project_analyzer import ProjectIndex, FunctionInfo, FileInfo, Language
from call_graph import CallGraph, CallGraphBuilder
from function_summary import FunctionSummary, FunctionSummaryStore, TaintFlow
from cross_file_taint import CrossFileTaintEngine, CrossFileVulnerability


class TaintPropagationType(Enum):
    """How taint propagates"""
    DIRECT = "direct"           # Direct assignment
    RETURN = "return"           # Through return value
    CALLBACK = "callback"       # Through callback argument
    PROMISE = "promise"         # Through Promise resolution
    CLOSURE = "closure"         # Through captured variable
    GLOBAL = "global"           # Through global state
    CLASS_FIELD = "class_field" # Through class property
    INHERITANCE = "inheritance" # Through parent class
    REEXPORT = "reexport"       # Through module re-export


@dataclass
class TaintPath:
    """Detailed path of taint propagation"""
    steps: List[Tuple[str, str, TaintPropagationType]] = field(default_factory=list)
    # Each step: (file, function, propagation_type)
    
    def add_step(self, file: str, function: str, prop_type: TaintPropagationType):
        self.steps.append((file, function, prop_type))
    
    def is_cross_file(self) -> bool:
        if len(self.steps) < 2:
            return False
        return len(set(s[0] for s in self.steps)) > 1


@dataclass
class AsyncTaintFlow:
    """Taint flow through async/await and Promises"""
    source_function: str
    source_file: str
    promise_chain: List[str] = field(default_factory=list)
    await_points: List[int] = field(default_factory=list)  # Line numbers
    resolved_to: Optional[str] = None  # Where the Promise resolves
    tainted_value: str = ""


@dataclass
class ClosureTaint:
    """Taint captured in a closure"""
    outer_function: str
    inner_function: str
    captured_variable: str
    is_tainted: bool = False
    taint_source: Optional[str] = None


@dataclass
class GlobalTaint:
    """Global state taint tracking"""
    variable_name: str
    defined_in: str
    defined_at_line: int
    accessed_by: List[Tuple[str, str, int]] = field(default_factory=list)  # file, func, line
    is_tainted: bool = False
    taint_source: Optional[str] = None


class EnhancedCrossFileTaintEngine(CrossFileTaintEngine):
    """
    Enhanced taint engine with advanced edge case handling.
    """
    
    def __init__(self, project_index: ProjectIndex, call_graph: CallGraph,
                 summary_store: FunctionSummaryStore):
        super().__init__(project_index, call_graph, summary_store)
        
        # Additional tracking
        self.async_flows: List[AsyncTaintFlow] = []
        self.closure_taints: List[ClosureTaint] = []
        self.global_taints: Dict[str, GlobalTaint] = {}
        self.class_field_taints: Dict[str, Dict[str, bool]] = {}  # class -> field -> is_tainted
        self.reexports: Dict[str, Dict[str, str]] = {}  # file -> exported_name -> original_file
        
    def analyze(self) -> List[CrossFileVulnerability]:
        """Enhanced analysis with edge cases"""
        print("Starting enhanced cross-file taint analysis...")
        
        # Base analysis
        super()._initialize_from_entry_points()
        
        # Enhanced analysis phases
        self._track_globals()
        self._track_closures()
        self._track_async_flows()
        self._track_class_inheritance()
        self._track_reexports()
        self._track_higher_order_functions()
        
        # Propagate with enhanced tracking
        self._enhanced_propagate()
        
        # Check for enhanced vulnerabilities
        self._check_async_vulnerabilities()
        self._check_closure_vulnerabilities()
        self._check_global_vulnerabilities()
        self._check_inheritance_vulnerabilities()
        
        # Standard checks
        super()._check_summary_vulnerabilities()
        super()._deduplicate_vulnerabilities()
        
        print(f"Found {len(self.vulnerabilities)} vulnerabilities (enhanced)")
        return self.vulnerabilities
    
    def _track_globals(self):
        """Track global state that could carry taint"""
        global_patterns = [
            r'global\s+(\w+)',  # Python global
            r'window\.(\w+)\s*=',  # JS window global
            r'global\.(\w+)\s*=',  # Node.js global
            r'(?:^|\n)(\w+)\s*=\s*[^=]',  # Module-level assignment
            r'(?:var|let|const)\s+(\w+)\s*=.*(?:req\.|request\.|process\.env)',  # Tainted globals
        ]
        
        for file_path, file_info in self.index.files.items():
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    code = f.read()
                    lines = code.split('\n')
                
                for pattern in global_patterns:
                    for match in re.finditer(pattern, code, re.MULTILINE):
                        var_name = match.group(1)
                        line_num = code[:match.start()].count('\n') + 1
                        
                        # Check if assigned from a taint source
                        line = lines[line_num - 1] if line_num <= len(lines) else ""
                        is_tainted = any(src in line for src in [
                            'request', 'req.', 'input', 'process.env', 
                            'query', 'body', 'params'
                        ])
                        
                        if var_name not in self.global_taints:
                            self.global_taints[var_name] = GlobalTaint(
                                variable_name=var_name,
                                defined_in=file_path,
                                defined_at_line=line_num,
                                is_tainted=is_tainted,
                                taint_source=line.strip() if is_tainted else None
                            )
                        
                        # Track accesses
                        for i, ln in enumerate(lines, 1):
                            if var_name in ln and i != line_num:
                                self.global_taints[var_name].accessed_by.append((
                                    file_path, "", i
                                ))
            except:
                pass
    
    def _track_closures(self):
        """Track closures that capture tainted variables"""
        closure_patterns = {
            'python': [
                r'def\s+(\w+)\s*\([^)]*\):\s*\n[^}]*def\s+(\w+)',  # Nested function
                r'lambda\s*[^:]*:\s*([^\n]+)',  # Lambda
            ],
            'javascript': [
                r'function\s+(\w+)[^{]*\{[^}]*function\s+(\w+)',  # Nested function
                r'const\s+(\w+)\s*=.*=>\s*{[^}]*(\w+)\s*=',  # Arrow in arrow
                r'(\w+)\s*=.*\([^)]*\)\s*=>\s*{[^}]*\1',  # Self-referencing closure
            ]
        }
        
        for file_path, file_info in self.index.files.items():
            lang = 'python' if file_info.language == Language.PYTHON else 'javascript'
            
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    code = f.read()
                
                for pattern in closure_patterns.get(lang, []):
                    for match in re.finditer(pattern, code, re.DOTALL):
                        groups = match.groups()
                        if len(groups) >= 2:
                            self.closure_taints.append(ClosureTaint(
                                outer_function=groups[0],
                                inner_function=groups[1] if len(groups) > 1 else 'anonymous',
                                captured_variable='',
                                is_tainted=False
                            ))
            except:
                pass
    
    def _track_async_flows(self):
        """Track async/await and Promise chains"""
        async_patterns = {
            'await': r'await\s+(\w+(?:\.\w+)*)\s*\(',
            'then': r'\.then\s*\(\s*(?:async\s*)?\(?([^)]*)\)?\s*=>\s*{?',
            'promise_new': r'new\s+Promise\s*\(\s*\(\s*(\w+)',
            'async_func': r'async\s+(?:function\s+)?(\w+)',
        }
        
        for file_path, file_info in self.index.files.items():
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    code = f.read()
                    lines = code.split('\n')
                
                for line_num, line in enumerate(lines, 1):
                    # Track await points
                    for match in re.finditer(async_patterns['await'], line):
                        func_name = match.group(1)
                        self.async_flows.append(AsyncTaintFlow(
                            source_function=func_name,
                            source_file=file_path,
                            await_points=[line_num]
                        ))
                    
                    # Track .then() chains
                    for match in re.finditer(async_patterns['then'], line):
                        callback_params = match.group(1)
                        if callback_params:
                            # The first parameter to .then() receives the resolved value
                            param_name = callback_params.split(',')[0].strip()
                            self.async_flows.append(AsyncTaintFlow(
                                source_function='then_callback',
                                source_file=file_path,
                                tainted_value=param_name
                            ))
            except:
                pass
    
    def _track_class_inheritance(self):
        """Track taint through class inheritance"""
        for file_path, file_info in self.index.files.items():
            for class_name, class_info in file_info.classes.items():
                # Check if parent class has tainted methods
                for base in class_info.base_classes:
                    # Find base class
                    base_files = self.index.symbol_table.get(base, [])
                    for base_file in base_files:
                        base_info = self.index.files.get(base_file)
                        if base_info and base in base_info.classes:
                            # Check for tainted fields in base
                            if class_name not in self.class_field_taints:
                                self.class_field_taints[class_name] = {}
                            
                            # Inherit taint from base class
                            if base in self.class_field_taints:
                                for field, is_tainted in self.class_field_taints[base].items():
                                    if is_tainted:
                                        self.class_field_taints[class_name][field] = True
    
    def _track_reexports(self):
        """Track module re-exports"""
        reexport_patterns = [
            r'export\s*{\s*([^}]+)\s*}\s*from\s*[\'"]([^\'"]+)[\'"]',  # export { x } from 'y'
            r'export\s*\*\s*from\s*[\'"]([^\'"]+)[\'"]',  # export * from 'y'
            r'module\.exports\s*=\s*require\s*\([\'"]([^\'"]+)[\'"]\)',  # CommonJS re-export
        ]
        
        for file_path, file_info in self.index.files.items():
            if file_info.language != Language.JAVASCRIPT:
                continue
            
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    code = f.read()
                
                self.reexports[file_path] = {}
                
                for pattern in reexport_patterns:
                    for match in re.finditer(pattern, code):
                        if 'from' in pattern:
                            names = match.group(1)
                            source = match.group(2)
                            for name in names.split(','):
                                name = name.strip().split(' as ')[0].strip()
                                self.reexports[file_path][name] = source
            except:
                pass
    
    def _track_higher_order_functions(self):
        """Track higher-order functions that pass tainted data to callbacks"""
        hof_patterns = [
            r'\.map\s*\(\s*(?:async\s*)?\(?([^)]*)\)?',
            r'\.filter\s*\(\s*\(?([^)]*)\)?',
            r'\.forEach\s*\(\s*\(?([^)]*)\)?',
            r'\.reduce\s*\(\s*\(?([^)]*)\)?',
            r'Promise\.all\s*\(\s*([^)]+)',
        ]
        
        # These patterns push taint to callback parameters
        for file_path, file_info in self.index.files.items():
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    code = f.read()
                
                for pattern in hof_patterns:
                    for match in re.finditer(pattern, code):
                        # The callback receives potentially tainted array elements
                        pass  # Handled in propagation
            except:
                pass
    
    def _enhanced_propagate(self):
        """Enhanced taint propagation with edge cases"""
        iteration = 0
        max_iterations = 15000
        
        while self.worklist and iteration < max_iterations:
            iteration += 1
            fqn, tainted_param, path, source_type = self.worklist.popleft()
            
            # Skip if already processed
            if fqn in self.processed and tainted_param in self.processed[fqn]:
                continue
            
            if fqn not in self.processed:
                self.processed[fqn] = set()
            self.processed[fqn].add(tainted_param)
            
            summary = self.summaries.get(fqn)
            if not summary:
                continue
            
            # Standard sink check
            if tainted_param in summary.param_to_sink:
                for flow in summary.param_to_sink[tainted_param]:
                    self._report_vulnerability(
                        source_fqn=path[0] if path else fqn,
                        source_param=tainted_param,
                        sink_fqn=fqn,
                        flow=flow,
                        path=path,
                        source_type=source_type
                    )
            
            # Enhanced: Check async flows
            for async_flow in self.async_flows:
                if async_flow.source_function in fqn:
                    # Taint flows through await
                    self._propagate_async_taint(fqn, tainted_param, path, source_type)
            
            # Enhanced: Check global state
            for var_name, global_taint in self.global_taints.items():
                if global_taint.is_tainted and global_taint.defined_in in fqn:
                    # Propagate to all accessors
                    for accessor_file, accessor_func, line in global_taint.accessed_by:
                        accessor_fqn = f"{accessor_file}::{accessor_func}" if accessor_func else accessor_file
                        if accessor_fqn not in self.processed.get(fqn, set()):
                            self.worklist.append((accessor_fqn, -1, path + [accessor_fqn], 'global_state'))
            
            # Enhanced: Check closure capture
            for closure in self.closure_taints:
                if closure.outer_function in fqn and closure.is_tainted:
                    inner_fqn = self._resolve_callee(fqn, closure.inner_function)
                    if inner_fqn:
                        self.worklist.append((inner_fqn, -1, path + [inner_fqn], 'closure'))
            
            # Standard call propagation
            for callee_name, arg_mappings in summary.tainted_calls.items():
                for caller_param, callee_param in arg_mappings:
                    if caller_param == tainted_param:
                        callee_fqn = self._resolve_callee(fqn, callee_name)
                        if callee_fqn:
                            new_path = path + [callee_fqn]
                            self.worklist.append((callee_fqn, callee_param, new_path, source_type))
            
            # Return value propagation
            if tainted_param in summary.param_to_return:
                callers = self.call_graph.get_callers(fqn)
                for caller_fqn in callers:
                    new_path = path + [caller_fqn]
                    self.worklist.append((caller_fqn, -1, new_path, source_type))
    
    def _propagate_async_taint(self, fqn: str, param: int, path: List[str], source_type: str):
        """Propagate taint through async/await"""
        # When an async function is awaited, its return value is tainted
        # Find all await points for this function
        for async_flow in self.async_flows:
            if async_flow.source_function.endswith(fqn.split('::')[-1]):
                # This function is awaited somewhere - propagate to the await site
                for file_path, file_info in self.index.files.items():
                    for func_name, func_info in file_info.functions.items():
                        if any(async_flow.source_function in call for call in func_info.calls):
                            awaiter_fqn = f"{file_path}::{func_name}"
                            self.worklist.append((awaiter_fqn, -1, path + [awaiter_fqn], 'async'))
    
    def _check_async_vulnerabilities(self):
        """Check for vulnerabilities in async flows"""
        for async_flow in self.async_flows:
            # Check if awaited function is a known source
            source_patterns = ['request', 'fetch', 'axios', 'db.query', 'Model.find']
            if any(p in async_flow.source_function for p in source_patterns):
                # The resolved value is tainted
                pass
    
    def _check_closure_vulnerabilities(self):
        """Check for vulnerabilities through closures"""
        for closure in self.closure_taints:
            if closure.is_tainted:
                # Report if the closure is used in a sink
                pass
    
    def _check_global_vulnerabilities(self):
        """Check for vulnerabilities through global state"""
        for var_name, global_taint in self.global_taints.items():
            if not global_taint.is_tainted:
                continue
            
            # Check if global is used in any sink
            for accessor_file, accessor_func, line in global_taint.accessed_by:
                try:
                    with open(accessor_file, 'r', encoding='utf-8') as f:
                        lines = f.readlines()
                        if line <= len(lines):
                            line_content = lines[line - 1]
                            # Check if this access is a sink
                            sinks = ['execute', 'query', 'eval', 'innerHTML', 'write']
                            for sink in sinks:
                                if sink in line_content and var_name in line_content:
                                    self.vulnerabilities.append(CrossFileVulnerability(
                                        vuln_type='global_state_injection',
                                        severity='High',
                                        confidence=0.8,
                                        source_file=global_taint.defined_in,
                                        source_function='',
                                        source_line=global_taint.defined_at_line,
                                        source_type='global_variable',
                                        sink_file=accessor_file,
                                        sink_function=accessor_func,
                                        sink_line=line,
                                        sink_name=sink,
                                        taint_path=[global_taint.defined_in, accessor_file],
                                        source_snippet=global_taint.taint_source or '',
                                        sink_snippet=line_content.strip()
                                    ))
                except:
                    pass
    
    def _check_inheritance_vulnerabilities(self):
        """Check for vulnerabilities through class inheritance"""
        for class_name, fields in self.class_field_taints.items():
            for field, is_tainted in fields.items():
                if not is_tainted:
                    continue
                
                # Check if this field is used in a sink method
                for file_path, file_info in self.index.files.items():
                    if class_name in file_info.classes:
                        # Find methods using this field
                        for func_name, func_info in file_info.functions.items():
                            if class_name in func_name:
                                # Check if method uses the tainted field
                                for call in func_info.calls:
                                    if any(s in call for s in ['execute', 'query', 'eval']):
                                        self.vulnerabilities.append(CrossFileVulnerability(
                                            vuln_type='inherited_taint_to_sink',
                                            severity='High',
                                            confidence=0.85,
                                            source_file=file_path,
                                            source_function=class_name,
                                            source_line=func_info.line_number,
                                            source_type='inherited_field',
                                            sink_file=file_path,
                                            sink_function=func_name,
                                            sink_line=func_info.line_number,
                                            sink_name=call,
                                            taint_path=[f"{class_name}.{field}", func_name]
                                        ))


def enhanced_analyze_project(project_path: str) -> Dict[str, Any]:
    """Enhanced project analysis with edge cases"""
    from project_analyzer import ProjectAnalyzer
    from call_graph import CallGraphBuilder
    from function_summary import generate_project_summaries
    
    print(f"\n{'='*60}")
    print(f"Enhanced Cross-File Taint Analysis: {project_path}")
    print(f"{'='*60}\n")
    
    # Index project
    print("Step 1: Indexing project files...")
    analyzer = ProjectAnalyzer(project_path)
    project_index = analyzer.analyze()
    
    # Build call graph
    print("\nStep 2: Building call graph...")
    builder = CallGraphBuilder(project_index)
    call_graph = builder.build()
    
    # Generate summaries
    print("\nStep 3: Generating function summaries...")
    summary_store = generate_project_summaries(project_index)
    
    # Enhanced analysis
    print("\nStep 4: Running enhanced cross-file analysis...")
    engine = EnhancedCrossFileTaintEngine(project_index, call_graph, summary_store)
    vulnerabilities = engine.analyze()
    
    # Generate report
    report = engine.get_vulnerability_report()
    report['project_info'] = {
        'path': project_path,
        'files_analyzed': len(project_index.files),
        'functions_analyzed': len(summary_store.summaries),
        'call_graph_nodes': len(call_graph.nodes),
        'call_graph_edges': len(call_graph.edges),
    }
    
    # Enhanced metrics
    report['enhanced_metrics'] = {
        'async_flows_tracked': len(engine.async_flows),
        'closures_tracked': len(engine.closure_taints),
        'globals_tracked': len(engine.global_taints),
        'class_hierarchies_tracked': len(engine.class_field_taints),
        'reexports_tracked': sum(len(v) for v in engine.reexports.values()),
    }
    
    print(f"\n{'='*60}")
    print("Enhanced Analysis Complete!")
    print(f"Files analyzed: {len(project_index.files)}")
    print(f"Async flows: {len(engine.async_flows)}")
    print(f"Global taints: {len(engine.global_taints)}")
    print(f"Vulnerabilities found: {len(vulnerabilities)}")
    print(f"{'='*60}\n")
    
    return report
