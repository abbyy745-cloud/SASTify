"""
Cross-File Taint Engine - The Core of Advanced Analysis

This module propagates taint across file boundaries using function summaries
and the call graph to find vulnerabilities that span multiple files.
"""

from dataclasses import dataclass, field
from typing import Dict, List, Set, Optional, Any, Tuple
from collections import deque
from enum import Enum

from project_analyzer import ProjectIndex, ProjectAnalyzer, Language
from call_graph import CallGraph, CallGraphBuilder, CallGraphNode
from function_summary import (
    FunctionSummary, FunctionSummaryStore, TaintFlow, TaintState,
    generate_project_summaries, PythonSummaryGenerator, JavaScriptSummaryGenerator
)


@dataclass
class CrossFileVulnerability:
    """A vulnerability that spans multiple files"""
    vuln_type: str
    severity: str
    confidence: float
    
    # Source information
    source_file: str
    source_function: str
    source_line: int
    source_type: str  # 'user_input', 'pii_data', etc.
    
    # Sink information
    sink_file: str
    sink_function: str
    sink_line: int
    sink_name: str
    
    # The path taint takes through the codebase
    taint_path: List[str] = field(default_factory=list)
    
    # Code snippets for context
    source_snippet: str = ""
    sink_snippet: str = ""
    
    # EdTech-specific metadata
    involves_pii: bool = False
    involves_exam_data: bool = False
    involves_ai: bool = False
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'type': self.vuln_type,
            'severity': self.severity,
            'confidence': self.confidence,
            'source': {
                'file': self.source_file,
                'function': self.source_function,
                'line': self.source_line,
                'type': self.source_type
            },
            'sink': {
                'file': self.sink_file,
                'function': self.sink_function,
                'line': self.sink_line,
                'name': self.sink_name
            },
            'path': self.taint_path,
            'snippets': {
                'source': self.source_snippet,
                'sink': self.sink_snippet
            },
            'edtech': {
                'pii': self.involves_pii,
                'exam': self.involves_exam_data,
                'ai': self.involves_ai
            }
        }


@dataclass
class TaintedValue:
    """Represents a tainted value being tracked"""
    origin_file: str
    origin_function: str
    origin_param: int
    source_type: str
    current_file: str
    current_function: str
    current_var: str
    path: List[str] = field(default_factory=list)


class CrossFileTaintEngine:
    """
    Main engine for cross-file taint analysis.
    
    Uses a worklist algorithm to propagate taint through the call graph
    until a fixpoint is reached or vulnerabilities are found.
    """
    
    SEVERITY_MAP = {
        'sql_injection': 'Critical',
        'code_injection': 'Critical', 
        'shell_injection': 'Critical',
        'prompt_injection': 'Critical',
        'xss': 'High',
        'ssrf': 'High',
        'path_traversal': 'High',
        'pii_leakage': 'High',
        'insecure_deserialization': 'High',
    }
    
    # EdTech-specific patterns
    PII_PATTERNS = ['student', 'user', 'cnic', 'dob', 'grade', 'score', 'parent', 'contact']
    EXAM_PATTERNS = ['exam', 'test', 'quiz', 'submission', 'answer', 'grade', 'score', 'marks']
    AI_PATTERNS = ['openai', 'llm', 'gpt', 'prompt', 'completion', 'langchain', 'ai']
    
    def __init__(self, project_index: ProjectIndex, call_graph: CallGraph, 
                 summary_store: FunctionSummaryStore):
        self.index = project_index
        self.call_graph = call_graph
        self.summaries = summary_store
        self.vulnerabilities: List[CrossFileVulnerability] = []
        
        # Worklist for fixpoint iteration
        self.worklist: deque = deque()
        
        # Track which functions have been processed with which taint
        self.processed: Dict[str, Set[int]] = {}  # fqn -> set of tainted param indices
    
    def analyze(self) -> List[CrossFileVulnerability]:
        """Run the cross-file taint analysis"""
        print("Starting cross-file taint analysis...")
        
        # Phase 1: Find all entry points and initialize taint
        self._initialize_from_entry_points()
        
        # Phase 2: Propagate taint through call graph
        self._propagate_taint()
        
        # Phase 3: Check for indirect vulnerabilities via summaries
        self._check_summary_vulnerabilities()
        
        # Phase 4: Deduplicate and rank vulnerabilities
        self._deduplicate_vulnerabilities()
        
        print(f"Found {len(self.vulnerabilities)} cross-file vulnerabilities")
        return self.vulnerabilities
    
    def _initialize_from_entry_points(self):
        """Initialize taint from entry points (routes, main functions)"""
        for fqn in self.call_graph.entry_points:
            summary = self.summaries.get(fqn)
            if not summary:
                continue
            
            # Mark entry point parameters as tainted
            for param_idx in summary.entry_params:
                self.worklist.append((fqn, param_idx, [fqn], 'user_input'))
                
            # Also check for direct vulnerabilities in entry points
            for param_idx, flows in summary.param_to_sink.items():
                for flow in flows:
                    self._report_vulnerability(
                        source_fqn=fqn,
                        source_param=param_idx,
                        sink_fqn=fqn,
                        flow=flow,
                        path=[fqn],
                        source_type='user_input'
                    )
    
    def _propagate_taint(self):
        """Propagate taint through the call graph using worklist algorithm"""
        iteration = 0
        max_iterations = 10000  # Prevent infinite loops
        
        while self.worklist and iteration < max_iterations:
            iteration += 1
            fqn, tainted_param, path, source_type = self.worklist.popleft()
            
            # Skip if already processed with this taint
            if fqn in self.processed and tainted_param in self.processed[fqn]:
                continue
            
            if fqn not in self.processed:
                self.processed[fqn] = set()
            self.processed[fqn].add(tainted_param)
            
            summary = self.summaries.get(fqn)
            if not summary:
                continue
            
            # Check if this tainted param flows to any sinks
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
            
            # Propagate through function calls
            for callee_name, arg_mappings in summary.tainted_calls.items():
                for caller_param, callee_param in arg_mappings:
                    if caller_param == tainted_param:
                        # Find the callee's FQN
                        callee_fqn = self._resolve_callee(fqn, callee_name)
                        if callee_fqn:
                            new_path = path + [callee_fqn]
                            self.worklist.append((callee_fqn, callee_param, new_path, source_type))
            
            # If taint flows to return value, propagate to callers
            if tainted_param in summary.param_to_return:
                callers = self.call_graph.get_callers(fqn)
                for caller_fqn in callers:
                    caller_summary = self.summaries.get(caller_fqn)
                    if caller_summary:
                        # Find which variable receives the return value
                        # This is simplified - real implementation would track assignments
                        new_path = path + [caller_fqn]
                        # Propagate as special "return taint"
                        self.worklist.append((caller_fqn, -1, new_path, source_type))
    
    def _check_summary_vulnerabilities(self):
        """Check for vulnerabilities recorded in function summaries"""
        for fqn, summary in self.summaries.summaries.items():
            # Check direct vulnerabilities (param -1 means direct source)
            if -1 in summary.param_to_sink:
                for flow in summary.param_to_sink[-1]:
                    self._report_vulnerability(
                        source_fqn=fqn,
                        source_param=-1,
                        sink_fqn=fqn,
                        flow=flow,
                        path=[fqn],
                        source_type='direct_source'
                    )
    
    def _resolve_callee(self, caller_fqn: str, callee_name: str) -> Optional[str]:
        """Resolve a callee name to its FQN"""
        # Try direct match
        for fqn in self.summaries.summaries:
            if fqn.endswith(f"::{callee_name}"):
                return fqn
        
        # Try matching just the function name
        caller_file = caller_fqn.split('::')[0] if '::' in caller_fqn else ''
        candidate = f"{caller_file}::{callee_name}"
        if candidate in self.summaries.summaries:
            return candidate
        
        return None
    
    def _report_vulnerability(self, source_fqn: str, source_param: int,
                             sink_fqn: str, flow: TaintFlow, path: List[str],
                             source_type: str):
        """Report a detected vulnerability"""
        source_file, source_func = self._parse_fqn(source_fqn)
        sink_file, sink_func = self._parse_fqn(sink_fqn)
        
        # Determine EdTech relevance
        involves_pii = any(p in sink_fqn.lower() or p in source_fqn.lower() 
                         for p in self.PII_PATTERNS)
        involves_exam = any(p in sink_fqn.lower() or p in source_fqn.lower() 
                          for p in self.EXAM_PATTERNS)
        involves_ai = any(p in flow.sink_name.lower() for p in self.AI_PATTERNS)
        
        # Adjust confidence based on cross-file nature
        confidence = flow.confidence
        if source_file != sink_file:
            confidence *= 0.95  # Slightly lower for cross-file (more complex)
        
        # Get code snippets
        source_snippet = self._get_code_snippet(source_file, flow.line_number) or ""
        sink_snippet = self._get_code_snippet(sink_file, flow.line_number) or ""
        
        vuln = CrossFileVulnerability(
            vuln_type=flow.sink_type,
            severity=self.SEVERITY_MAP.get(flow.sink_type, 'Medium'),
            confidence=confidence,
            source_file=source_file,
            source_function=source_func,
            source_line=flow.line_number,
            source_type=source_type,
            sink_file=sink_file,
            sink_function=sink_func,
            sink_line=flow.line_number,
            sink_name=flow.sink_name,
            taint_path=path,
            source_snippet=source_snippet,
            sink_snippet=sink_snippet,
            involves_pii=involves_pii,
            involves_exam_data=involves_exam,
            involves_ai=involves_ai
        )
        
        self.vulnerabilities.append(vuln)
    
    def _parse_fqn(self, fqn: str) -> Tuple[str, str]:
        """Parse fully qualified name into file and function"""
        if '::' in fqn:
            parts = fqn.split('::')
            return parts[0], parts[1]
        return '', fqn
    
    def _get_code_snippet(self, file_path: str, line_number: int) -> Optional[str]:
        """Get a code snippet from a file"""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                lines = f.readlines()
                if 0 < line_number <= len(lines):
                    return lines[line_number - 1].strip()
        except:
            pass
        return None
    
    def _deduplicate_vulnerabilities(self):
        """Remove duplicate vulnerabilities and sort by severity"""
        seen = set()
        unique = []
        
        for v in self.vulnerabilities:
            key = (v.vuln_type, v.sink_file, v.sink_line, v.sink_name)
            if key not in seen:
                seen.add(key)
                unique.append(v)
        
        # Sort by severity
        severity_order = {'Critical': 0, 'High': 1, 'Medium': 2, 'Low': 3}
        unique.sort(key=lambda v: severity_order.get(v.severity, 4))
        
        self.vulnerabilities = unique
    
    def get_vulnerability_report(self) -> Dict[str, Any]:
        """Generate a comprehensive vulnerability report"""
        return {
            'total_vulnerabilities': len(self.vulnerabilities),
            'by_severity': {
                'critical': len([v for v in self.vulnerabilities if v.severity == 'Critical']),
                'high': len([v for v in self.vulnerabilities if v.severity == 'High']),
                'medium': len([v for v in self.vulnerabilities if v.severity == 'Medium']),
                'low': len([v for v in self.vulnerabilities if v.severity == 'Low']),
            },
            'by_type': self._group_by_type(),
            'edtech_specific': {
                'pii_issues': len([v for v in self.vulnerabilities if v.involves_pii]),
                'exam_issues': len([v for v in self.vulnerabilities if v.involves_exam_data]),
                'ai_issues': len([v for v in self.vulnerabilities if v.involves_ai]),
            },
            'cross_file_count': len([v for v in self.vulnerabilities 
                                    if v.source_file != v.sink_file]),
            'vulnerabilities': [v.to_dict() for v in self.vulnerabilities]
        }
    
    def _group_by_type(self) -> Dict[str, int]:
        """Group vulnerabilities by type"""
        counts = {}
        for v in self.vulnerabilities:
            counts[v.vuln_type] = counts.get(v.vuln_type, 0) + 1
        return counts


def analyze_project(project_path: str) -> Dict[str, Any]:
    """
    Main entry point for cross-file analysis.
    
    Performs complete analysis pipeline:
    1. Index project files
    2. Build call graph
    3. Generate function summaries
    4. Run cross-file taint analysis
    """
    print(f"\n{'='*60}")
    print(f"Cross-File Taint Analysis: {project_path}")
    print(f"{'='*60}\n")
    
    # Step 1: Index project
    print("Step 1: Indexing project files...")
    analyzer = ProjectAnalyzer(project_path)
    project_index = analyzer.analyze()
    
    # Step 2: Build call graph
    print("\nStep 2: Building call graph...")
    builder = CallGraphBuilder(project_index)
    call_graph = builder.build()
    
    # Step 3: Generate function summaries
    print("\nStep 3: Generating function summaries...")
    summary_store = generate_project_summaries(project_index)
    print(f"Generated {len(summary_store.summaries)} function summaries")
    
    # Step 4: Run cross-file taint analysis
    print("\nStep 4: Running cross-file taint analysis...")
    taint_engine = CrossFileTaintEngine(project_index, call_graph, summary_store)
    vulnerabilities = taint_engine.analyze()
    
    # Generate report
    report = taint_engine.get_vulnerability_report()
    report['project_info'] = {
        'path': project_path,
        'files_analyzed': len(project_index.files),
        'functions_analyzed': len(summary_store.summaries),
        'call_graph_nodes': len(call_graph.nodes),
        'call_graph_edges': len(call_graph.edges),
    }
    
    print(f"\n{'='*60}")
    print("Analysis Complete!")
    print(f"Files analyzed: {len(project_index.files)}")
    print(f"Functions analyzed: {len(summary_store.summaries)}")
    print(f"Vulnerabilities found: {len(vulnerabilities)}")
    print(f"  - Critical: {report['by_severity']['critical']}")
    print(f"  - High: {report['by_severity']['high']}")
    print(f"  - Medium: {report['by_severity']['medium']}")
    print(f"{'='*60}\n")
    
    return report
