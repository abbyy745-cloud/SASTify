import sys
import os

# Add Backend to path
sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'Backend'))

from enhanced_rule_engine import EnhancedRuleEngine

def debug_scan():
    engine = EnhancedRuleEngine()
    
    with open('tests/python/comprehensive_test.py', 'r') as f:
        code = f.read()
    
    print("Scanning comprehensive_test.py...")
    issues = engine.scan_with_ast_analysis(code, 'python')
    
    for i, issue in enumerate(issues, 1):
        print(f"\nIssue #{i}:")
        print(f"  Type: {issue['type']}")
        print(f"  Line: {issue['line']}")
        print(f"  Snippet: {issue['snippet'].strip()}")
        print(f"  Scanner: {issue['scanner']}")
        print(f"  Severity: {issue['severity']}")

if __name__ == "__main__":
    debug_scan()
