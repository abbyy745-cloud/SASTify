import sys
import os
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from enhanced_rule_engine import EnhancedRuleEngine

# Test code with eval inside a string
test_code = '''# [SAFE] 'eval' as a string, not a function call
instruction = "Do not use eval() in your code"
'''

engine = EnhancedRuleEngine()
issues = engine.scan_with_ast_analysis(test_code, 'python', 'test.py')

print(f"Found {len(issues)} issues:")
for issue in issues:
    print(f"  - Line {issue['line']}: {issue['type']} - {issue['snippet']}")
    print(f"    Scanner: {issue['scanner']}")
