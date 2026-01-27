import os
import concurrent.futures
from typing import List, Dict, Any
from .taint_graph import TaintGraph
from .rule_loader import RuleLoader
from .scanners import GraphPythonScanner
from .cache import CacheManager

class ProjectAnalyzer:
    def __init__(self, project_path: str):
        self.project_path = project_path
        self.taint_graph = TaintGraph()
        self.rule_loader = RuleLoader()
        self.rules = self.rule_loader.load_rules()
        self.cache_manager = CacheManager()
        self.scanners = {
            'python': GraphPythonScanner(self.taint_graph, self.rules)
            # Add JS scanner here
        }

    def analyze(self, use_cache: bool = True) -> Dict[str, Any]:
        files = self._discover_files()
        results = []
        
        # Parallel Scanning
        with concurrent.futures.ThreadPoolExecutor() as executor:
            future_to_file = {executor.submit(self._scan_file, f, use_cache): f for f in files}
            for future in concurrent.futures.as_completed(future_to_file):
                file_path = future_to_file[future]
                try:
                    issues = future.result()
                    results.extend(issues)
                except Exception as e:
                    print(f"File {file_path} generated an exception: {e}")
                    
        return {
            'issues': results,
            'metrics': {
                'files_scanned': len(files),
                'total_issues': len(results)
            }
        }

    def _discover_files(self) -> List[str]:
        file_list = []
        for root, dirs, files in os.walk(self.project_path):
            if 'node_modules' in dirs:
                dirs.remove('node_modules')
            if '__pycache__' in dirs:
                dirs.remove('__pycache__')
            if '.git' in dirs:
                dirs.remove('.git')
                
            for file in files:
                if file.endswith(('.py', '.js', '.jsx', '.ts', '.tsx')):
                    file_list.append(os.path.join(root, file))
        return file_list

    def _scan_file(self, file_path: str, use_cache: bool) -> List[Dict]:
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                code = f.read()
        except UnicodeDecodeError:
            return []

        # Check Cache
        if use_cache:
            cached = self.cache_manager.get_cached_result(file_path, code)
            if cached:
                return cached['issues']

        issues = []
        if file_path.endswith('.py'):
            issues = self.scanners['python'].scan(code, file_path)
        # Add JS support
        
        # Cache results
        if use_cache:
            self.cache_manager.cache_result(file_path, code, {'issues': issues})
            
        return issues
