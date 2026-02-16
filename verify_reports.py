
import sys
import os
import json
from unittest.mock import MagicMock

# Add path to import Backend modules
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from Backend.cli import SASTifyCLI
from Backend.test_report_generator import TestReportGenerator

def test_report_generation():
    print("Testing report generation with rich AI data...")
    
    # 1. Mock Vulnerability Data with Rich AI Analysis
    mock_vuln = {
        'file': 'test_file.py',
        'line': 10,
        'severity': 'High',
        'type': 'sql_injection',
        'snippet': 'query = "SELECT * FROM users WHERE id = " + user_input',
        'ai_analyzed': True,
        'ai_confidence': 0.95,
        'ai_is_false_positive': False,
        'ai_explanation': 'Concise explanation.',
        'ai_detailed_explanation': 'Detailed explanation of SQL injection.',
        'ai_attack_scenario': {
            'description': 'Attacker injects SQL code.',
            'attacker_goal': 'Dump database',
            'example_payloads': ["' OR 1=1 --"]
        },
        'ai_impact_analysis': {
            'confidentiality': 'High - Data leak',
            'integrity': 'Medium - Data mod',
            'availability': 'Low'
        },
        'ai_fix_suggestion': 'query = "SELECT * FROM users WHERE id = %s", (user_input,)',
        'ai_remediation_steps': ['Use param queries'],
        'ai_security_references': ['CWE-89'],
        'ai_test_suggestions': [
            {
                'type': 'unit',
                'name': 'Test SQL Injection',
                'description': 'Tries to inject SQL',
                'code': 'assert check_vuln("\'")',
                'test_inputs': ["' OR 1=1 --"],
                'expected_behavior': 'Query blocked'
            }
        ]
    }
    
    vulnerabilities = [mock_vuln]
    
    # 2. Generate Security Report (Main HTML)
    print("Generating main security report...")
    cli = SASTifyCLI()
    # Mock some CLI internals if needed, but _format_html is mostly pure
    html_content = cli._format_html(vulnerabilities, file_count=1)
    
    # Check for presence of AI sections
    checks = {
        "AI Analysis Header": "AI Security Analysis",
        "Detailed Explanation": "Detailed explanation of SQL injection",
        "Attack Scenario": "Attacker injects SQL code",
        "Impact Analysis": "Impact Analysis",
        "Confidentiality Impact": "High - Data leak"
    }
    
    print("\nChecking Security Report Content:")
    failed = False
    for label, text in checks.items():
        if text in html_content:
            print(f"  [PASS] {label} present")
        else:
            print(f"  [FAIL] {label} MISSING")
            failed = True
            
    # 3. Generate Test Case Report
    print("\nGenerating test case report...")
    generator = TestReportGenerator()
    test_html = generator._generate_html(vulnerabilities)
    
    # Check for presence of AI sections in Test Report
    test_checks = {
        "Report Title": "Test Cases & Threat Analysis",
        "Analysis Section": "AI Analysis",
        "Detailed Explanation": "Detailed explanation of SQL injection",
        "Attack Scenario": "Attacker injects SQL code",
        "Impact Analysis": "Potential Impact",
        "Confidentiality": "confidentiality" 
    }
    
    print("\nChecking Test Report Content:")
    for label, text in test_checks.items():
        if text in test_html:
            print(f"  [PASS] {label} present")
        else:
            print(f"  [FAIL] {label} MISSING")
            failed = True

    if failed:
        print("\n❌ Verification Failed")
        exit(1)
    else:
        print("\n✅ Verification Passed: Both reports invoke AI logic correctly.")

if __name__ == "__main__":
    test_report_generation()
