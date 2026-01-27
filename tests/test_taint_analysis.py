import unittest
from Backend.enhanced_rule_engine import EnhancedRuleEngine

class TestTaintAnalysis(unittest.TestCase):
    def setUp(self):
        self.engine = EnhancedRuleEngine()

    def test_python_simple_taint(self):
        code = """
import flask
app = flask.Flask(__name__)

@app.route('/vuln')
def vuln():
    user_input = flask.request.args.get('id')
    cursor.execute(f"SELECT * FROM users WHERE id = {user_input}")
"""
        issues = self.engine.scan_with_ast_analysis(code, 'python')
        self.assertTrue(any(i['type'] == 'sql_injection' and i['scanner'] == 'ast_taint_analysis' for i in issues))

    def test_python_sanitized_input(self):
        code = """
import flask
import html
app = flask.Flask(__name__)

@app.route('/safe')
def safe():
    user_data = flask.request.args.get('id')
    safe_data = html.escape(user_data)
    cursor.execute(f"SELECT * FROM users WHERE id = {safe_data}")
"""
        issues = self.engine.scan_with_ast_analysis(code, 'python')
        print(f"DEBUG: Issues found: {issues}")
        # Should NOT have sql_injection from ast_taint_analysis
        self.assertFalse(any(i['type'] == 'sql_injection' and i['scanner'] == 'ast_taint_analysis' for i in issues))

    def test_javascript_simple_taint(self):
        code = """
const express = require('express');
const app = express();

app.post('/vuln', (req, res) => {
    const userInput = req.body.input;
    const query = `SELECT * FROM users WHERE name = '${userInput}'`;
    db.query(query);
});
"""
        issues = self.engine.scan_with_ast_analysis(code, 'javascript')
        self.assertTrue(any(i['type'] == 'sql_injection' and i['scanner'] == 'ast_taint_analysis' for i in issues))

    def test_javascript_xss_taint(self):
        code = """
function updateUI() {
    let badData = location.hash;
    document.getElementById('content').innerHTML = badData;
}
"""
        issues = self.engine.scan_with_ast_analysis(code, 'javascript')
        self.assertTrue(any(i['type'] == 'xss' and i['scanner'] == 'ast_taint_analysis' for i in issues))

    def test_javascript_sanitized(self):
        code = """
function updateUI() {
    let badData = location.hash;
    let cleanData = DOMPurify.sanitize(badData);
    document.getElementById('content').innerHTML = cleanData;
}
"""
        issues = self.engine.scan_with_ast_analysis(code, 'javascript')
        self.assertFalse(any(i['type'] == 'xss' and i['scanner'] == 'ast_taint_analysis' for i in issues))

if __name__ == '__main__':
    unittest.main()
