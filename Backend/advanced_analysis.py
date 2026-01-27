try:
    from core.project_analyzer import ProjectAnalyzer
except ImportError:
    from .core.project_analyzer import ProjectAnalyzer
from typing import Dict, Any

def analyze_project(project_path: str) -> Dict[str, Any]:
    """
    Run the advanced project-level analysis.
    """
    analyzer = ProjectAnalyzer(project_path)
    return analyzer.analyze()

def analyze_snippet(code: str, language: str = 'python') -> Dict[str, Any]:
    """
    Run advanced analysis on a single snippet using the new engine.
    """
    # For snippet analysis, we can instantiate the scanner directly
    try:
        from core.taint_graph import TaintGraph
        from core.rule_loader import RuleLoader
        from core.scanners import GraphPythonScanner
    except ImportError:
        from .core.taint_graph import TaintGraph
        from .core.rule_loader import RuleLoader
        from .core.scanners import GraphPythonScanner
    
    rule_loader = RuleLoader()
    rules = rule_loader.load_rules()
    taint_graph = TaintGraph()
    
    if language == 'python':
        scanner = GraphPythonScanner(taint_graph, rules)
        issues = scanner.scan(code, "snippet.py")
        return {'issues': issues}
    
    return {'issues': []}
