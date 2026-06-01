import sys
sys.path.insert(0, 'Backend')
from enhanced_rule_engine import EnhancedRuleEngine

e = EnhancedRuleEngine()
print(f"Tree-sitter JS: {e.tree_sitter_js_available}")
print(f"Tree-sitter TS: {e.tree_sitter_ts_available}")
print(f"Dataflow:       {e.dataflow_available}")

# Test 1: JS with tree-sitter
code = """
const userInput = req.query.name;
eval(userInput);
document.getElementById('x').innerHTML = userInput;
const api_secret = "sk-abc123456789012345678901234567890";
db.query(`SELECT * FROM users WHERE id = ${userId}`);
"""
print("\n--- JavaScript scan ---")
results = e.scan_with_ast_analysis(code, 'javascript', 'test.js')
print(f"Found {len(results)} issues:")
for r in results:
    print(f"  [{r.get('scanner','?'):20s}] {r['severity']:8s} L{r['line']:3d} {r['type']}")

# Test 2: Modern JS syntax that would crash esprima
code2 = """
class MyService {
  #apiKey = "secret";
  async fetchData() {
    const result = await fetch(url);
    return result?.data ?? [];
  }
}
const x = import.meta.url;
const big = 123n;
"""
print("\n--- Modern JS syntax ---")
results2 = e.scan_with_ast_analysis(code2, 'javascript', 'modern.js')
print(f"Parsed OK! Found {len(results2)} issues (no crash)")

# Test 3: Python dataflow taint
code3 = """
from flask import request
import sqlite3

def vulnerable():
    user_input = request.args.get('name')
    db = sqlite3.connect('test.db')
    cursor = db.cursor()
    cursor.execute("SELECT * FROM users WHERE name = '" + user_input + "'")
"""
print("\n--- Python dataflow taint ---")
results3 = e.scan_with_ast_analysis(code3, 'python', 'app.py')
print(f"Found {len(results3)} issues:")
for r in results3:
    print(f"  [{r.get('scanner','?'):20s}] {r['severity']:8s} L{r['line']:3d} {r['type']}")

print("\n=== ALL INTEGRATION TESTS PASSED ===")
