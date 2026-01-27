"""
SASTify Benchmark Test Suite

OWASP-style test cases for measuring detection accuracy.
Includes true positives (vulnerable code) and true negatives (safe code).

Metrics:
- Precision = TP / (TP + FP)
- Recall = TP / (TP + FN)
- F1 Score = 2 * (Precision * Recall) / (Precision + Recall)
"""

import sys
import os
from dataclasses import dataclass, field
from typing import List, Dict, Tuple, Any
import json

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from enhanced_rule_engine import TaintTracker, PythonASTScanner, JavascriptASTScanner
from dataflow_graph import DataflowEnhancedScanner


@dataclass
class BenchmarkResult:
    """Results from running benchmark"""
    true_positives: int = 0
    false_positives: int = 0
    true_negatives: int = 0
    false_negatives: int = 0
    
    @property
    def precision(self) -> float:
        if self.true_positives + self.false_positives == 0:
            return 0.0
        return self.true_positives / (self.true_positives + self.false_positives)
    
    @property
    def recall(self) -> float:
        if self.true_positives + self.false_negatives == 0:
            return 0.0
        return self.true_positives / (self.true_positives + self.false_negatives)
    
    @property
    def f1_score(self) -> float:
        if self.precision + self.recall == 0:
            return 0.0
        return 2 * (self.precision * self.recall) / (self.precision + self.recall)


# =============================================================================
# TRUE POSITIVE TEST CASES (Known Vulnerabilities - Should Be Detected)
# =============================================================================

PYTHON_VULNERABLE_SAMPLES = {
    'sql_injection': [
        {
            'code': '''
def get_user(user_id):
    query = "SELECT * FROM users WHERE id = " + user_id
    cursor.execute(query)
    return cursor.fetchone()
''',
            'line': 3,
            'description': 'String concatenation SQL injection'
        },
        {
            'code': '''
def search_users(name):
    cursor.execute(f"SELECT * FROM users WHERE name = '{name}'")
    return cursor.fetchall()
''',
            'line': 3,
            'description': 'F-string SQL injection'
        },
        {
            'code': '''
def delete_user(user_id):
    query = "DELETE FROM users WHERE id = %s" % user_id
    db.execute(query)
''',
            'line': 3,
            'description': 'Percent-format SQL injection'
        },
    ],
    'command_injection': [
        {
            'code': '''
import os
def run_command(cmd):
    os.system(cmd)
''',
            'line': 4,
            'description': 'os.system with user input'
        },
        {
            'code': '''
import subprocess
def execute(command):
    subprocess.call(command, shell=True)
''',
            'line': 4,
            'description': 'subprocess.call with shell=True'
        },
    ],
    'code_injection': [
        {
            'code': '''
def calculate(expression):
    result = eval(expression)
    return result
''',
            'line': 3,
            'description': 'eval with user input'
        },
        {
            'code': '''
def run_code(code):
    exec(code)
''',
            'line': 3,
            'description': 'exec with user input'
        },
    ],
    'hardcoded_secret': [
        {
            'code': '''
API_KEY = "sk_live_1234567890abcdef1234567890"
PASSWORD = "SuperSecretPassword123!"
''',
            'line': 2,
            'description': 'Hardcoded API key and password'
        },
    ],
    'insecure_deserialization': [
        {
            'code': '''
import pickle
def load_data(data):
    return pickle.loads(data)
''',
            'line': 4,
            'description': 'pickle.loads with untrusted data'
        },
    ],
    'ssrf': [
        {
            'code': '''
import requests
def fetch_url(url):
    response = requests.get(url)
    return response.text
''',
            'line': 4,
            'description': 'SSRF via requests.get'
        },
    ],
}

JAVASCRIPT_VULNERABLE_SAMPLES = {
    'sql_injection': [
        {
            'code': '''
function getUser(userId) {
    const query = "SELECT * FROM users WHERE id = " + userId;
    return db.query(query);
}
''',
            'line': 3,
            'description': 'String concatenation SQL injection'
        },
        {
            'code': '''
function searchUsers(name) {
    return db.query(`SELECT * FROM users WHERE name = '${name}'`);
}
''',
            'line': 3,
            'description': 'Template literal SQL injection'
        },
    ],
    'xss': [
        {
            'code': '''
function display(userInput) {
    document.getElementById("output").innerHTML = userInput;
}
''',
            'line': 3,
            'description': 'innerHTML with user input'
        },
        {
            'code': '''
function showMessage(msg) {
    document.write(msg);
}
''',
            'line': 3,
            'description': 'document.write XSS'
        },
    ],
    'command_injection': [
        {
            'code': '''
function runCommand(cmd) {
    const exec = require('child_process').exec;
    exec(cmd, callback);
}
''',
            'line': 4,
            'description': 'child_process.exec with user input'
        },
    ],
    'prototype_pollution': [
        {
            'code': '''
function merge(target, source) {
    return Object.assign(target, source);
}
''',
            'line': 3,
            'description': 'Object.assign prototype pollution'
        },
        {
            'code': '''
const _ = require('lodash');
function extend(obj, data) {
    return _.merge(obj, data);
}
''',
            'line': 4,
            'description': '_.merge prototype pollution'
        },
    ],
    'hardcoded_secret': [
        {
            'code': '''
const apiKey = "AIzaSyDOCAbC123dEf456GhI789jKL01-MnsIqr";
const secretToken = "ghp_1234567890abcdefghijklmnopqrstuvwxyz";
''',
            'line': 2,
            'description': 'Hardcoded API keys'
        },
    ],
}


# =============================================================================
# TRUE NEGATIVE TEST CASES (Safe Code - Should NOT Be Flagged)
# =============================================================================

PYTHON_SAFE_SAMPLES = {
    'sql_parameterized': [
        {
            'code': '''
def get_user(user_id):
    cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
    return cursor.fetchone()
''',
            'should_not_detect': 'sql_injection',
            'description': 'Parameterized query - safe'
        },
    ],
    'subprocess_safe': [
        {
            'code': '''
import subprocess
def run_safe():
    subprocess.run(["ls", "-la"], shell=False)
''',
            'should_not_detect': 'command_injection',
            'description': 'subprocess with list args and shell=False'
        },
    ],
    'env_variable': [
        {
            'code': '''
import os
API_KEY = os.environ.get("API_KEY")
''',
            'should_not_detect': 'hardcoded_secret',
            'description': 'Secret from environment variable'
        },
    ],
}

JAVASCRIPT_SAFE_SAMPLES = {
    'sql_parameterized': [
        {
            'code': '''
function getUser(userId) {
    return db.query("SELECT * FROM users WHERE id = ?", [userId]);
}
''',
            'should_not_detect': 'sql_injection',
            'description': 'Parameterized query - safe'
        },
    ],
    'dom_safe': [
        {
            'code': '''
function display(userInput) {
    document.getElementById("output").textContent = userInput;
}
''',
            'should_not_detect': 'xss',
            'description': 'textContent is safe from XSS'
        },
    ],
    'sanitized_html': [
        {
            'code': '''
const DOMPurify = require('dompurify');
function display(html) {
    element.innerHTML = DOMPurify.sanitize(html);
}
''',
            'should_not_detect': 'xss',
            'description': 'DOMPurify sanitized - safe'
        },
    ],
}


class BenchmarkRunner:
    """Runs benchmark tests and calculates accuracy metrics"""
    
    def __init__(self):
        self.taint_tracker = TaintTracker()
        self.python_scanner = PythonASTScanner(self.taint_tracker)
        self.js_scanner = JavascriptASTScanner(self.taint_tracker)
        self.dataflow_scanner = DataflowEnhancedScanner()
        self.results: Dict[str, BenchmarkResult] = {}
    
    def run_all(self) -> Dict[str, Any]:
        """Run all benchmark tests"""
        print("=" * 60)
        print("SASTify Benchmark Suite")
        print("=" * 60)
        
        # Test Python vulnerabilities
        print("\n[*] Testing Python True Positives...")
        py_tp = self._test_true_positives(PYTHON_VULNERABLE_SAMPLES, 'python')
        
        # Test JavaScript vulnerabilities
        print("[*] Testing JavaScript True Positives...")
        js_tp = self._test_true_positives(JAVASCRIPT_VULNERABLE_SAMPLES, 'javascript')
        
        # Test Python safe code
        print("[*] Testing Python True Negatives...")
        py_tn = self._test_true_negatives(PYTHON_SAFE_SAMPLES, 'python')
        
        # Test JavaScript safe code
        print("[*] Testing JavaScript True Negatives...")
        js_tn = self._test_true_negatives(JAVASCRIPT_SAFE_SAMPLES, 'javascript')
        
        # Aggregate results
        total = BenchmarkResult(
            true_positives=py_tp.true_positives + js_tp.true_positives,
            false_negatives=py_tp.false_negatives + js_tp.false_negatives,
            true_negatives=py_tn.true_negatives + js_tn.true_negatives,
            false_positives=py_tn.false_positives + js_tn.false_positives
        )
        
        self.results['python'] = BenchmarkResult(
            true_positives=py_tp.true_positives,
            false_negatives=py_tp.false_negatives,
            true_negatives=py_tn.true_negatives,
            false_positives=py_tn.false_positives
        )
        
        self.results['javascript'] = BenchmarkResult(
            true_positives=js_tp.true_positives,
            false_negatives=js_tp.false_negatives,
            true_negatives=js_tn.true_negatives,
            false_positives=js_tn.false_positives
        )
        
        self.results['total'] = total
        
        return self._generate_report()
    
    def _test_true_positives(self, samples: Dict, language: str) -> BenchmarkResult:
        """Test that vulnerabilities are detected"""
        result = BenchmarkResult()
        
        for vuln_type, cases in samples.items():
            for case in cases:
                code = case['code']
                expected_line = case.get('line', 0)
                
                if language == 'python':
                    issues = self.python_scanner.scan(code)
                else:
                    issues = self.js_scanner.scan(code)
                
                # Check if vulnerability was detected
                detected = any(
                    vuln_type in str(issue.get('type', '')).lower() or
                    vuln_type.replace('_', '') in str(issue.get('type', '')).lower()
                    for issue in issues
                )
                
                if detected:
                    result.true_positives += 1
                    print(f"  ✓ {vuln_type}: {case['description']}")
                else:
                    result.false_negatives += 1
                    print(f"  ✗ MISSED {vuln_type}: {case['description']}")
        
        return result
    
    def _test_true_negatives(self, samples: Dict, language: str) -> BenchmarkResult:
        """Test that safe code is not flagged"""
        result = BenchmarkResult()
        
        for category, cases in samples.items():
            for case in cases:
                code = case['code']
                should_not_detect = case['should_not_detect']
                
                if language == 'python':
                    issues = self.python_scanner.scan(code)
                else:
                    issues = self.js_scanner.scan(code)
                
                # Check if safe code was incorrectly flagged
                false_alarm = any(
                    should_not_detect in str(issue.get('type', '')).lower()
                    for issue in issues
                )
                
                if not false_alarm:
                    result.true_negatives += 1
                    print(f"  ✓ {category}: {case['description']}")
                else:
                    result.false_positives += 1
                    print(f"  ✗ FALSE POSITIVE {category}: {case['description']}")
        
        return result
    
    def _generate_report(self) -> Dict[str, Any]:
        """Generate benchmark report"""
        report = {
            'summary': {},
            'languages': {},
            'recommendations': []
        }
        
        print("\n" + "=" * 60)
        print("BENCHMARK RESULTS")
        print("=" * 60)
        
        for lang, result in self.results.items():
            report['languages'][lang] = {
                'true_positives': result.true_positives,
                'false_positives': result.false_positives,
                'true_negatives': result.true_negatives,
                'false_negatives': result.false_negatives,
                'precision': round(result.precision, 4),
                'recall': round(result.recall, 4),
                'f1_score': round(result.f1_score, 4)
            }
            
            print(f"\n{lang.upper()}:")
            print(f"  True Positives:  {result.true_positives}")
            print(f"  False Positives: {result.false_positives}")
            print(f"  True Negatives:  {result.true_negatives}")
            print(f"  False Negatives: {result.false_negatives}")
            print(f"  Precision: {result.precision:.2%}")
            print(f"  Recall:    {result.recall:.2%}")
            print(f"  F1 Score:  {result.f1_score:.2%}")
        
        total = self.results['total']
        report['summary'] = {
            'precision': round(total.precision, 4),
            'recall': round(total.recall, 4),
            'f1_score': round(total.f1_score, 4),
            'total_tests': (total.true_positives + total.false_negatives + 
                          total.true_negatives + total.false_positives)
        }
        
        print("\n" + "=" * 60)
        print(f"OVERALL: Precision={total.precision:.2%}, Recall={total.recall:.2%}, F1={total.f1_score:.2%}")
        print("=" * 60)
        
        return report


def run_benchmark() -> Dict[str, Any]:
    """Run the full benchmark suite"""
    runner = BenchmarkRunner()
    return runner.run_all()


if __name__ == "__main__":
    report = run_benchmark()
    
    # Save report
    output_file = os.path.join(os.path.dirname(__file__), 'benchmark_results.json')
    with open(output_file, 'w') as f:
        json.dump(report, f, indent=2)
    print(f"\nResults saved to: {output_file}")
