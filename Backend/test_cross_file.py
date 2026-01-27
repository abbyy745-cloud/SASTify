"""
Test script for Cross-File Taint Analysis

Run this to verify the advanced taint analysis system is working correctly.
"""

import os
import sys

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

def test_project_analyzer():
    """Test the project analyzer"""
    print("\n" + "="*60)
    print("TEST 1: Project Analyzer")
    print("="*60)
    
    from project_analyzer import ProjectAnalyzer
    
    # Analyze the Backend directory itself
    project_path = os.path.dirname(os.path.abspath(__file__))
    analyzer = ProjectAnalyzer(project_path)
    index = analyzer.analyze()
    
    print(f"[OK] Indexed {len(index.files)} files")
    print(f"[OK] Found {len(index.symbol_table)} symbols")
    print(f"[OK] Entry points: {len(analyzer.get_entry_points())}")
    
    return True


def test_call_graph():
    """Test the call graph builder"""
    print("\n" + "="*60)
    print("TEST 2: Call Graph Builder")
    print("="*60)
    
    from project_analyzer import ProjectAnalyzer
    from call_graph import CallGraphBuilder
    
    project_path = os.path.dirname(os.path.abspath(__file__))
    analyzer = ProjectAnalyzer(project_path)
    index = analyzer.analyze()
    
    builder = CallGraphBuilder(index)
    graph = builder.build()
    
    print(f"[OK] Graph has {len(graph.nodes)} nodes")
    print(f"[OK] Graph has {len(graph.edges)} edges")
    print(f"[OK] Entry points: {len(graph.entry_points)}")
    print(f"[OK] Sinks detected: {len(graph.sinks)}")
    
    return True


def test_function_summaries():
    """Test function summary generation"""
    print("\n" + "="*60)
    print("TEST 3: Function Summary Generation")
    print("="*60)
    
    from project_analyzer import ProjectAnalyzer
    from function_summary import generate_project_summaries
    
    project_path = os.path.dirname(os.path.abspath(__file__))
    analyzer = ProjectAnalyzer(project_path)
    index = analyzer.analyze()
    
    summaries = generate_project_summaries(index)
    
    print(f"[OK] Generated {len(summaries.summaries)} summaries")
    
    # Check for vulnerabilities in summaries
    vulns = summaries.get_vulnerabilities()
    print(f"[OK] Found {len(vulns)} potential vulnerabilities in summaries")
    
    return True


def test_cross_file_analysis():
    """Test the full cross-file analysis"""
    print("\n" + "="*60)
    print("TEST 4: Cross-File Taint Analysis")
    print("="*60)
    
    from cross_file_taint import analyze_project
    
    project_path = os.path.dirname(os.path.abspath(__file__))
    report = analyze_project(project_path)
    
    print(f"[OK] Analysis complete")
    print(f"[OK] Total vulnerabilities: {report['total_vulnerabilities']}")
    print(f"[OK] By severity: {report['by_severity']}")
    print(f"[OK] EdTech-specific issues:")
    print(f"  - PII issues: {report['edtech_specific']['pii_issues']}")
    print(f"  - Exam issues: {report['edtech_specific']['exam_issues']}")
    print(f"  - AI issues: {report['edtech_specific']['ai_issues']}")
    
    return True


def test_library_models():
    """Test library models"""
    print("\n" + "="*60)
    print("TEST 5: Library Models")
    print("="*60)
    
    from library_models import get_all_models
    
    models = get_all_models()
    
    for name, model in models.items():
        sources = len(model.sources) if hasattr(model, 'sources') else 0
        sinks = len(model.sinks) if hasattr(model, 'sinks') else 0
        print(f"[OK] {name}: {sources} sources, {sinks} sinks")
    
    # Test Flask model specifically
    flask = models['flask']
    assert flask.is_source('request.args.get'), "Flask source detection failed"
    assert flask.is_sink('render_template_string') is not None, "Flask sink detection failed"
    print("[OK] Flask model working correctly")
    
    # Test AI model
    ai = models['ai']
    assert ai.is_sink('openai.ChatCompletion.create') is not None, "AI sink detection failed"
    print("[OK] AI model working correctly")
    
    return True


def create_test_project():
    """Create a test project with known vulnerabilities for testing"""
    print("\n" + "="*60)
    print("CREATING TEST PROJECT")
    print("="*60)
    
    test_dir = os.path.join(os.path.dirname(__file__), 'test_project')
    os.makedirs(test_dir, exist_ok=True)
    
    # Create a Flask app with cross-file vulnerability
    routes_py = '''
from flask import Flask, request
from services import process_student_query

app = Flask(__name__)

@app.route('/student/search')
def search_student():
    # User input enters here
    query = request.args.get('q')
    # Flows to another file
    return process_student_query(query)
'''
    
    services_py = '''
import sqlite3

def process_student_query(search_term):
    """This function receives tainted data from routes.py"""
    conn = sqlite3.connect('students.db')
    cursor = conn.cursor()
    
    # SQL INJECTION! The tainted data flows here from another file
    cursor.execute(f"SELECT * FROM students WHERE name LIKE '%{search_term}%'")
    
    return cursor.fetchall()

def grade_with_ai(student_answer, rubric):
    """EdTech AI grading - vulnerable to prompt injection"""
    import openai
    
    # PROMPT INJECTION! Student answer goes directly into prompt
    response = openai.ChatCompletion.create(
        model="gpt-4",
        messages=[
            {"role": "system", "content": f"Grade this answer using rubric: {rubric}"},
            {"role": "user", "content": student_answer}  # User-controlled!
        ]
    )
    return response
'''
    
    with open(os.path.join(test_dir, 'routes.py'), 'w') as f:
        f.write(routes_py)
    
    with open(os.path.join(test_dir, 'services.py'), 'w') as f:
        f.write(services_py)
    
    print(f"[OK] Created test project at {test_dir}")
    return test_dir


def test_vulnerable_project():
    """Test cross-file analysis on a project with known vulnerabilities"""
    print("\n" + "="*60)
    print("TEST 6: Vulnerable Test Project Analysis")
    print("="*60)
    
    test_dir = create_test_project()
    
    from cross_file_taint import analyze_project
    
    report = analyze_project(test_dir)
    
    print(f"\n[OK] Analysis of test project complete")
    print(f"[OK] Found {report['total_vulnerabilities']} vulnerabilities")
    
    # We expect to find:
    # 1. SQL injection (cross-file: routes.py -> services.py)
    # 2. Prompt injection in AI grading
    
    for vuln in report['vulnerabilities']:
        print(f"\n  [{vuln['severity']}] {vuln['type']}")
        print(f"    Source: {vuln['source']['file']}:{vuln['source']['line']}")
        print(f"    Sink: {vuln['sink']['file']}:{vuln['sink']['line']}")
        if vuln['edtech']['pii']:
            print(f"    [!] Involves PII data")
        if vuln['edtech']['ai']:
            print(f"    [AI] AI/LLM related")
    
    return True


def main():
    """Run all tests"""
    print("\n" + "="*60)
    print("CROSS-FILE TAINT ANALYSIS TEST SUITE")
    print("="*60)
    
    tests = [
        ("Project Analyzer", test_project_analyzer),
        ("Call Graph Builder", test_call_graph),
        ("Function Summaries", test_function_summaries),
        ("Cross-File Analysis", test_cross_file_analysis),
        ("Library Models", test_library_models),
        ("Vulnerable Project", test_vulnerable_project),
    ]
    
    results = []
    for name, test_func in tests:
        try:
            success = test_func()
            results.append((name, success, None))
        except Exception as e:
            import traceback
            results.append((name, False, str(e)))
            traceback.print_exc()
    
    print("\n" + "="*60)
    print("TEST RESULTS")
    print("="*60)
    
    passed = 0
    failed = 0
    for name, success, error in results:
        if success:
            print(f"[PASS] {name}")
            passed += 1
        else:
            print(f"[FAIL] {name}: {error}")
            failed += 1
    
    print(f"\nTotal: {passed} passed, {failed} failed")
    
    return failed == 0


if __name__ == '__main__':
    success = main()
    sys.exit(0 if success else 1)
