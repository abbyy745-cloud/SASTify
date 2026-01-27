"""
Run SASTify scanner on tricky test files
"""
import sys
sys.path.insert(0, '.')

from enhanced_rule_engine import EnhancedRuleEngine

engine = EnhancedRuleEngine()

# Test Python file
print("=" * 70)
print("PYTHON TEST RESULTS")
print("=" * 70)

with open('../tests/tricky_python_test.py', 'r') as f:
    code = f.read()

issues = engine.scan_with_ast_analysis(code, 'python', 'tricky_python_test.py')

# Count by severity
severities = {'Critical': 0, 'High': 0, 'Medium': 0, 'Low': 0}
for v in issues:
    sev = v.get('severity', 'Medium')
    if sev in severities:
        severities[sev] += 1

print(f"Total Issues Found: {len(issues)}")
print(f"Critical: {severities['Critical']}, High: {severities['High']}, Medium: {severities['Medium']}, Low: {severities['Low']}")
print()

for i, v in enumerate(issues[:30], 1):
    snippet = v.get('snippet', '')[:65].replace('\n', ' ')
    vtype = v.get('type', 'unknown')
    sev = v.get('severity', 'Medium')
    line = v.get('line', 0)
    print(f"{i:2}. [{sev:8}] Line {line:3}: {vtype}")
    print(f"    {snippet}")
    print()

# Test JavaScript file
print("=" * 70)
print("JAVASCRIPT TEST RESULTS")
print("=" * 70)

with open('../tests/tricky_javascript_test.js', 'r') as f:
    code = f.read()

issues = engine.scan_with_ast_analysis(code, 'javascript', 'tricky_javascript_test.js')

# Count by severity
severities = {'Critical': 0, 'High': 0, 'Medium': 0, 'Low': 0}
for v in issues:
    sev = v.get('severity', 'Medium')
    if sev in severities:
        severities[sev] += 1

print(f"Total Issues Found: {len(issues)}")
print(f"Critical: {severities['Critical']}, High: {severities['High']}, Medium: {severities['Medium']}, Low: {severities['Low']}")
print()

for i, v in enumerate(issues[:30], 1):
    snippet = v.get('snippet', '')[:65].replace('\n', ' ')
    vtype = v.get('type', 'unknown')
    sev = v.get('severity', 'Medium')
    line = v.get('line', 0)
    print(f"{i:2}. [{sev:8}] Line {line:3}: {vtype}")
    print(f"    {snippet}")
    print()

print("=" * 70)
print("TEST COMPLETE")
print("=" * 70)
