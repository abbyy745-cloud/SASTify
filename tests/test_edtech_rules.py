import unittest
import os
import sys

# Add Backend to path
sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'Backend'))

from enhanced_rule_engine import EnhancedRuleEngine

class TestEdTechRules(unittest.TestCase):
    def setUp(self):
        self.engine = EnhancedRuleEngine()
        self.test_files_dir = os.path.join(os.path.dirname(__file__), 'edtech_test_files')

    def test_pii_detection(self):
        with open(os.path.join(self.test_files_dir, 'pii_vulnerable.py'), 'r') as f:
            code = f.read()
        
        issues = self.engine.scan_with_ast_analysis(code, 'python')
        
        # Check for specific vulnerability types
        vuln_types = [issue['type'] for issue in issues]
        self.assertIn('hardcoded_pii', vuln_types)
        self.assertIn('pii_leakage_log', vuln_types)
        self.assertIn('unsafe_identifier_exposure', vuln_types)
        self.assertIn('sensitive_autocomplete_enabled', vuln_types)
        
        # Check specific lines (optional, but good for precision)
        # hardcoded_pii should be around line 8
        self.assertTrue(any(i['type'] == 'hardcoded_pii' and i['line'] == 8 for i in issues))

    def test_exam_integrity_detection(self):
        with open(os.path.join(self.test_files_dir, 'exam_vulnerable.py'), 'r') as f:
            code = f.read()
        
        issues = self.engine.scan_with_ast_analysis(code, 'python')
        vuln_types = [issue['type'] for issue in issues]
        
        self.assertIn('unprotected_exam_endpoint', vuln_types)
        self.assertIn('submission_tampering', vuln_types)
        self.assertIn('client_side_timer', vuln_types)
        self.assertIn('cheating_html_injection', vuln_types)

    def test_ai_vulnerability_detection(self):
        with open(os.path.join(self.test_files_dir, 'ai_vulnerable.py'), 'r') as f:
            code = f.read()
        
        issues = self.engine.scan_with_ast_analysis(code, 'python')
        vuln_types = [issue['type'] for issue in issues]
        
        self.assertIn('hardcoded_ai_key', vuln_types)
        self.assertIn('exposed_model_endpoint', vuln_types)
        self.assertIn('prompt_injection', vuln_types)
        self.assertIn('ai_grading_security', vuln_types)

    def test_node_backend_detection(self):
        with open(os.path.join(self.test_files_dir, 'node_backend_vulnerable.js'), 'r') as f:
            code = f.read()
        
        issues = self.engine.scan_with_ast_analysis(code, 'javascript')
        vuln_types = [issue['type'] for issue in issues]
        
        self.assertIn('pii_leakage_log_node', vuln_types)
        self.assertIn('unsafe_route_node', vuln_types)
        self.assertIn('unprotected_exam_endpoint_node', vuln_types)
        self.assertIn('submission_tampering_node', vuln_types)
        self.assertIn('prompt_injection_node', vuln_types)

    def test_false_positives(self):
        with open(os.path.join(self.test_files_dir, 'false_positives.py'), 'r') as f:
            code = f.read()
        
        issues = self.engine.scan_with_ast_analysis(code, 'python')
        # Filter for AST issues only
        ast_issues = [i for i in issues if i['scanner'] in ['ast_taint_analysis', 'ast_logic_analysis']]
        
        # AST should find 0 issues in this file
        self.assertEqual(len(ast_issues), 0, f"AST found false positives: {[i['type'] for i in ast_issues]}")

    def test_universal_detection(self):
        with open(os.path.join(self.test_files_dir.replace('edtech_test_files', 'universal_test_files'), 'universal_vulnerable.py'), 'r') as f:
            code = f.read()
        
        issues = self.engine.scan_with_ast_analysis(code, 'python')
        vuln_types = [issue['type'] for issue in issues]
        
        self.assertIn('ssrf', vuln_types)
        self.assertIn('weak_jwt_alg', vuln_types)
        self.assertIn('debug_mode_enabled', vuln_types)
        self.assertIn('insecure_session_cookie', vuln_types)

    def test_deep_edtech_detection(self):
        # Python: LTI
        with open(os.path.join(self.test_files_dir, 'deep_edtech_vulnerable.py'), 'r') as f:
            py_code = f.read()
        
        py_issues = self.engine.scan_with_ast_analysis(py_code, 'python')
        py_vulns = [issue['type'] for issue in py_issues]
        self.assertIn('lti_launch_handling', py_vulns)

        # JS: Proctoring
        with open(os.path.join(self.test_files_dir, 'deep_edtech_vulnerable.js'), 'r') as f:
            js_code = f.read()
        
        js_issues = self.engine.scan_with_ast_analysis(js_code, 'javascript')
        js_vulns = [issue['type'] for issue in js_issues]
        self.assertIn('proctoring_evasion', js_vulns)

    def test_frontend_analysis(self):
        # React
        react_path = os.path.join(self.test_files_dir.replace('edtech_test_files', 'frontend_test_files'), 'react_vulnerable.jsx')
        with open(react_path, 'r') as f:
            react_code = f.read()
        
        # We need to manually call the scanner or use scan_file if we had a proper integration test
        # But here we are unit testing the engine. The engine needs the file path for frontend files.
        # Let's use the new scan_file method if possible, or mock it.
        # Actually, scan_with_ast_analysis doesn't take file path yet in the test wrapper.
        # Let's call frontend_scanner directly for this unit test.
        
        react_issues = self.engine.frontend_scanner.scan(react_code, react_path)
        react_vulns = [issue['type'] for issue in react_issues]
        self.assertIn('react_xss', react_vulns)
        self.assertIn('prop_drilling_risk', react_vulns)

        # Vue
        vue_path = os.path.join(self.test_files_dir.replace('edtech_test_files', 'frontend_test_files'), 'vue_vulnerable.vue')
        with open(vue_path, 'r') as f:
            vue_code = f.read()
            
        vue_issues = self.engine.frontend_scanner.scan(vue_code, vue_path)
        vue_vulns = [issue['type'] for issue in vue_issues]
        self.assertIn('vue_xss', vue_vulns)

        # Angular
        angular_path = os.path.join(self.test_files_dir.replace('edtech_test_files', 'frontend_test_files'), 'angular_vulnerable.html')
        with open(angular_path, 'r') as f:
            angular_code = f.read()
            
        angular_issues = self.engine.frontend_scanner.scan(angular_code, angular_path)
        angular_vulns = [issue['type'] for issue in angular_issues]
        self.assertIn('angular_xss', angular_vulns)

if __name__ == '__main__':
    unittest.main()
