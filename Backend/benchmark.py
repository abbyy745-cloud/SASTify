"""
Performance Benchmark Suite for SASTify

Measures and reports performance metrics for:
- File indexing speed
- Call graph construction time
- Taint analysis throughput
- Memory usage
- Scalability with project size
"""

import os
import sys
import time
import tempfile
import shutil
import random
import string
import tracemalloc
from dataclasses import dataclass
from typing import List, Dict, Any
from functools import wraps

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))


@dataclass
class BenchmarkResult:
    """Result of a benchmark run"""
    name: str
    duration_seconds: float
    memory_peak_mb: float
    throughput: float  # items/second
    details: Dict[str, Any]


class BenchmarkTimer:
    """Context manager for timing operations"""
    
    def __init__(self, name: str):
        self.name = name
        self.start_time = 0
        self.end_time = 0
        self.memory_start = 0
        self.memory_peak = 0
    
    def __enter__(self):
        tracemalloc.start()
        self.start_time = time.perf_counter()
        return self
    
    def __exit__(self, *args):
        self.end_time = time.perf_counter()
        current, peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()
        self.memory_peak = peak / 1024 / 1024  # Convert to MB
    
    @property
    def duration(self) -> float:
        return self.end_time - self.start_time


def generate_python_file(num_functions: int = 10, num_classes: int = 2) -> str:
    """Generate a random Python file for benchmarking"""
    lines = [
        "from flask import Flask, request, jsonify",
        "import sqlite3",
        "import os",
        "",
        "app = Flask(__name__)",
        "",
    ]
    
    # Generate classes
    for c in range(num_classes):
        class_name = f"Service{c}"
        lines.append(f"class {class_name}:")
        lines.append(f"    def __init__(self):")
        lines.append(f"        self.db = sqlite3.connect('db.sqlite')")
        lines.append("")
        
        for m in range(num_functions // num_classes):
            method_name = f"method_{c}_{m}"
            lines.append(f"    def {method_name}(self, param_{m}):")
            lines.append(f"        cursor = self.db.cursor()")
            if random.random() > 0.7:
                # SQL injection vulnerability
                lines.append(f"        cursor.execute(f'SELECT * FROM table{m} WHERE id = {{param_{m}}}')")
            else:
                # Safe query
                lines.append(f"        cursor.execute('SELECT * FROM table{m} WHERE id = ?', (param_{m},))")
            lines.append(f"        return cursor.fetchall()")
            lines.append("")
    
    # Generate functions
    for f in range(num_functions):
        func_name = f"function_{f}"
        lines.append(f"@app.route('/api/{func_name}')")
        lines.append(f"def {func_name}():")
        lines.append(f"    user_input = request.args.get('param{f}')")
        
        if random.random() > 0.5:
            # Call another function
            target = random.randint(0, max(0, f-1)) if f > 0 else 0
            lines.append(f"    result = function_{target}()")
        
        if random.random() > 0.7:
            # Potential vulnerability
            lines.append(f"    os.system(f'echo {{user_input}}')")
        
        lines.append(f"    return jsonify({{'result': 'ok'}})")
        lines.append("")
    
    return "\n".join(lines)


def generate_javascript_file(num_functions: int = 10) -> str:
    """Generate a random JavaScript file for benchmarking"""
    lines = [
        "const express = require('express');",
        "const mysql = require('mysql');",
        "",
        "const app = express();",
        "const pool = mysql.createPool({ host: 'localhost', database: 'test' });",
        "",
    ]
    
    for f in range(num_functions):
        func_name = f"handler{f}"
        lines.append(f"app.get('/api/{func_name}', async (req, res) => {{")
        lines.append(f"    const userInput = req.query.param{f};")
        
        if random.random() > 0.6:
            # SQL injection
            lines.append(f"    const query = `SELECT * FROM users WHERE id = ${{userInput}}`;")
            lines.append(f"    pool.query(query, (err, results) => {{")
            lines.append(f"        res.json(results);")
            lines.append(f"    }});")
        else:
            lines.append(f"    res.json({{ status: 'ok' }});")
        
        lines.append(f"}});")
        lines.append("")
    
    return "\n".join(lines)


def create_test_project(num_files: int, functions_per_file: int, temp_dir: str) -> str:
    """Create a test project with specified size"""
    for i in range(num_files):
        if random.random() > 0.5:
            ext = '.py'
            content = generate_python_file(functions_per_file)
        else:
            ext = '.js'
            content = generate_javascript_file(functions_per_file)
        
        filename = f"module_{i}{ext}"
        filepath = os.path.join(temp_dir, filename)
        
        with open(filepath, 'w') as f:
            f.write(content)
    
    return temp_dir


class SastifyBenchmark:
    """Benchmark suite for SASTify"""
    
    def __init__(self):
        self.results: List[BenchmarkResult] = []
    
    def run_all(self, quick: bool = False):
        """Run all benchmarks"""
        print("\n" + "="*60)
        print("SASTify Performance Benchmark Suite")
        print("="*60)
        
        # Project sizes to test
        if quick:
            sizes = [(10, 5), (50, 10)]  # (files, functions_per_file)
        else:
            sizes = [(10, 5), (50, 10), (100, 20), (200, 30)]
        
        for num_files, funcs_per_file in sizes:
            total_funcs = num_files * funcs_per_file
            print(f"\n--- Testing with {num_files} files, ~{total_funcs} functions ---")
            
            # Create test project
            temp_dir = tempfile.mkdtemp()
            try:
                create_test_project(num_files, funcs_per_file, temp_dir)
                
                # Run benchmarks
                self.benchmark_indexing(temp_dir, num_files, total_funcs)
                self.benchmark_call_graph(temp_dir, num_files, total_funcs)
                self.benchmark_summaries(temp_dir, num_files, total_funcs)
                self.benchmark_taint_analysis(temp_dir, num_files, total_funcs)
                
            finally:
                shutil.rmtree(temp_dir)
        
        # Print summary
        self.print_summary()
    
    def benchmark_indexing(self, project_path: str, num_files: int, num_funcs: int):
        """Benchmark project indexing"""
        from project_analyzer import ProjectAnalyzer
        
        with BenchmarkTimer("Indexing") as timer:
            analyzer = ProjectAnalyzer(project_path)
            index = analyzer.analyze()
        
        self.results.append(BenchmarkResult(
            name=f"Indexing ({num_files} files)",
            duration_seconds=timer.duration,
            memory_peak_mb=timer.memory_peak,
            throughput=num_files / timer.duration,
            details={
                'files_indexed': len(index.files),
                'symbols_found': len(index.symbol_table),
            }
        ))
        
        print(f"  Indexing: {timer.duration:.3f}s, {timer.memory_peak:.1f}MB peak")
    
    def benchmark_call_graph(self, project_path: str, num_files: int, num_funcs: int):
        """Benchmark call graph construction"""
        from project_analyzer import ProjectAnalyzer
        from call_graph import CallGraphBuilder
        
        analyzer = ProjectAnalyzer(project_path)
        index = analyzer.analyze()
        
        with BenchmarkTimer("CallGraph") as timer:
            builder = CallGraphBuilder(index)
            graph = builder.build()
        
        self.results.append(BenchmarkResult(
            name=f"Call Graph ({num_files} files)",
            duration_seconds=timer.duration,
            memory_peak_mb=timer.memory_peak,
            throughput=num_funcs / timer.duration,
            details={
                'nodes': len(graph.nodes),
                'edges': len(graph.edges),
            }
        ))
        
        print(f"  Call Graph: {timer.duration:.3f}s, {len(graph.nodes)} nodes, {len(graph.edges)} edges")
    
    def benchmark_summaries(self, project_path: str, num_files: int, num_funcs: int):
        """Benchmark function summary generation"""
        from project_analyzer import ProjectAnalyzer
        from function_summary import generate_project_summaries
        
        analyzer = ProjectAnalyzer(project_path)
        index = analyzer.analyze()
        
        with BenchmarkTimer("Summaries") as timer:
            summaries = generate_project_summaries(index)
        
        self.results.append(BenchmarkResult(
            name=f"Summaries ({num_files} files)",
            duration_seconds=timer.duration,
            memory_peak_mb=timer.memory_peak,
            throughput=len(summaries.summaries) / timer.duration,
            details={
                'summaries_generated': len(summaries.summaries),
            }
        ))
        
        print(f"  Summaries: {timer.duration:.3f}s, {len(summaries.summaries)} generated")
    
    def benchmark_taint_analysis(self, project_path: str, num_files: int, num_funcs: int):
        """Benchmark full taint analysis"""
        from cross_file_taint import analyze_project
        
        with BenchmarkTimer("TaintAnalysis") as timer:
            report = analyze_project(project_path)
        
        self.results.append(BenchmarkResult(
            name=f"Taint Analysis ({num_files} files)",
            duration_seconds=timer.duration,
            memory_peak_mb=timer.memory_peak,
            throughput=num_funcs / timer.duration,
            details={
                'vulnerabilities_found': report['total_vulnerabilities'],
            }
        ))
        
        print(f"  Taint Analysis: {timer.duration:.3f}s, {report['total_vulnerabilities']} vulns found")
    
    def print_summary(self):
        """Print benchmark summary"""
        print("\n" + "="*60)
        print("BENCHMARK SUMMARY")
        print("="*60)
        
        print(f"\n{'Benchmark':<40} {'Time (s)':<12} {'Memory (MB)':<12} {'Throughput':<15}")
        print("-"*80)
        
        for result in self.results:
            print(f"{result.name:<40} {result.duration_seconds:<12.3f} "
                  f"{result.memory_peak_mb:<12.1f} {result.throughput:<15.1f}/s")
        
        # Calculate averages by category
        indexing_results = [r for r in self.results if 'Indexing' in r.name]
        callgraph_results = [r for r in self.results if 'Call Graph' in r.name]
        summary_results = [r for r in self.results if 'Summaries' in r.name]
        taint_results = [r for r in self.results if 'Taint Analysis' in r.name]
        
        print("\n" + "="*60)
        print("PERFORMANCE METRICS")
        print("="*60)
        
        if indexing_results:
            avg_throughput = sum(r.throughput for r in indexing_results) / len(indexing_results)
            print(f"Average indexing throughput: {avg_throughput:.1f} files/second")
        
        if taint_results:
            avg_throughput = sum(r.throughput for r in taint_results) / len(taint_results)
            print(f"Average analysis throughput: {avg_throughput:.1f} functions/second")
        
        # Memory efficiency
        if self.results:
            max_memory = max(r.memory_peak_mb for r in self.results)
            print(f"Peak memory usage: {max_memory:.1f} MB")
        
        # Scalability analysis
        print("\n" + "="*60)
        print("SCALABILITY ANALYSIS")
        print("="*60)
        
        if len(taint_results) >= 2:
            # Compare first and last
            small = taint_results[0]
            large = taint_results[-1]
            
            size_ratio = float(large.name.split('(')[1].split()[0]) / float(small.name.split('(')[1].split()[0])
            time_ratio = large.duration_seconds / small.duration_seconds
            
            print(f"Project size increased by: {size_ratio:.1f}x")
            print(f"Analysis time increased by: {time_ratio:.1f}x")
            
            if time_ratio <= size_ratio * 1.5:
                print("Scalability: GOOD (near-linear)")
            elif time_ratio <= size_ratio * 2:
                print("Scalability: ACCEPTABLE (sub-quadratic)")
            else:
                print("Scalability: NEEDS IMPROVEMENT (super-linear)")
        
        # Recommendations
        print("\n" + "="*60)
        print("RECOMMENDATIONS")
        print("="*60)
        
        if self.results:
            slowest = max(self.results, key=lambda r: r.duration_seconds)
            print(f"Bottleneck: {slowest.name} ({slowest.duration_seconds:.3f}s)")
            
            highest_memory = max(self.results, key=lambda r: r.memory_peak_mb)
            if highest_memory.memory_peak_mb > 500:
                print(f"[!] High memory usage in {highest_memory.name}: {highest_memory.memory_peak_mb:.1f}MB")
                print("    Consider incremental processing for large projects")


class EdgeCaseBenchmark:
    """Benchmark edge cases that might cause performance issues"""
    
    def run_all(self):
        print("\n" + "="*60)
        print("Edge Case Performance Tests")
        print("="*60)
        
        self.test_deeply_nested_calls()
        self.test_large_file()
        self.test_many_imports()
        self.test_circular_dependencies()
    
    def test_deeply_nested_calls(self):
        """Test performance with deeply nested function calls"""
        print("\n--- Deeply Nested Calls ---")
        
        temp_dir = tempfile.mkdtemp()
        try:
            # Create a file with deeply nested calls
            lines = ["def func_0(x): return x"]
            for i in range(1, 100):
                lines.append(f"def func_{i}(x): return func_{i-1}(x)")
            lines.append("result = func_99(user_input)")
            
            with open(os.path.join(temp_dir, 'nested.py'), 'w') as f:
                f.write("\n".join(lines))
            
            from cross_file_taint import analyze_project
            
            start = time.perf_counter()
            report = analyze_project(temp_dir)
            duration = time.perf_counter() - start
            
            print(f"  100 nested calls: {duration:.3f}s")
            
        finally:
            shutil.rmtree(temp_dir)
    
    def test_large_file(self):
        """Test performance with a very large file"""
        print("\n--- Large File (1000+ functions) ---")
        
        temp_dir = tempfile.mkdtemp()
        try:
            content = generate_python_file(1000, 10)
            
            with open(os.path.join(temp_dir, 'large.py'), 'w') as f:
                f.write(content)
            
            from cross_file_taint import analyze_project
            
            start = time.perf_counter()
            report = analyze_project(temp_dir)
            duration = time.perf_counter() - start
            
            print(f"  1000 functions in single file: {duration:.3f}s")
            
        finally:
            shutil.rmtree(temp_dir)
    
    def test_many_imports(self):
        """Test performance with many cross-file imports"""
        print("\n--- Many Cross-File Imports ---")
        
        temp_dir = tempfile.mkdtemp()
        try:
            # Create 20 files that all import each other
            for i in range(20):
                imports = [f"from module_{j} import func_{j}" for j in range(20) if j != i]
                content = "\n".join(imports) + f"\n\ndef func_{i}(x):\n    return x\n"
                
                with open(os.path.join(temp_dir, f'module_{i}.py'), 'w') as f:
                    f.write(content)
            
            from cross_file_taint import analyze_project
            
            start = time.perf_counter()
            report = analyze_project(temp_dir)
            duration = time.perf_counter() - start
            
            print(f"  20 files with circular imports: {duration:.3f}s")
            
        finally:
            shutil.rmtree(temp_dir)
    
    def test_circular_dependencies(self):
        """Test handling of circular dependencies"""
        print("\n--- Circular Dependencies ---")
        
        temp_dir = tempfile.mkdtemp()
        try:
            # A imports B, B imports C, C imports A
            with open(os.path.join(temp_dir, 'a.py'), 'w') as f:
                f.write("from b import func_b\ndef func_a(x): return func_b(x)\n")
            
            with open(os.path.join(temp_dir, 'b.py'), 'w') as f:
                f.write("from c import func_c\ndef func_b(x): return func_c(x)\n")
            
            with open(os.path.join(temp_dir, 'c.py'), 'w') as f:
                f.write("from a import func_a\ndef func_c(x): return func_a(x)\n")
            
            from cross_file_taint import analyze_project
            
            start = time.perf_counter()
            report = analyze_project(temp_dir)
            duration = time.perf_counter() - start
            
            print(f"  Circular dependency chain: {duration:.3f}s")
            print(f"  (Should not hang or crash)")
            
        finally:
            shutil.rmtree(temp_dir)


def main():
    """Run all benchmarks"""
    import argparse
    
    parser = argparse.ArgumentParser(description='SASTify Performance Benchmarks')
    parser.add_argument('--quick', action='store_true', help='Run quick benchmarks only')
    parser.add_argument('--edge-cases', action='store_true', help='Run edge case tests')
    args = parser.parse_args()
    
    if args.edge_cases:
        edge_benchmark = EdgeCaseBenchmark()
        edge_benchmark.run_all()
    else:
        benchmark = SastifyBenchmark()
        benchmark.run_all(quick=args.quick)
    
    print("\n[OK] Benchmarks complete!")


if __name__ == '__main__':
    main()
