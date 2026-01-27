import sys
import os
import json

# Add Backend to path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'Backend')))

from enhanced_rule_engine import EnhancedRuleEngine
from deepseek_api import SecureDeepSeekAPI
from false_positive_detector import FalsePositiveDetector

def reproduce():
    print("--- Starting Reproduction Script ---")
    
    # 1. Scan debug_deepseek.py
    target_file = os.path.join(os.path.dirname(__file__), 'debug_deepseek.py')
    with open(target_file, 'r') as f:
        code = f.read()
        
    print(f"Scanning {target_file}...")
    
    rule_engine = EnhancedRuleEngine()
    issues = rule_engine.scan_with_ast_analysis(code, 'python', target_file)
    
    print(f"Found {len(issues)} issues:")
    for i, issue in enumerate(issues):
        print(f"  {i+1}. {issue['type']} at line {issue['line']}: {issue['snippet']}")
        
    # 2. Check False Positives
    fp_detector = FalsePositiveDetector()
    print("\nChecking for False Positives...")
    for issue in issues:
        is_fp = fp_detector.is_likely_false_positive(issue, {}, target_file)
        print(f"  Issue {issue['type']} is likely FP? {is_fp}")

    # 3. Simulate AI Analysis (Crash Check)
    print("\nSimulating AI Analysis (Crash Check)...")
    api_key = os.getenv('DEEPSEEK_API_KEY')
    if not api_key:
        print("  WARNING: DEEPSEEK_API_KEY not set. Using dummy key for crash test (will fail auth but shouldn't crash).")
        api_key = "dummy_key"
        
    deepseek = SecureDeepSeekAPI(api_key)
    
    if issues:
        test_issue = issues[0]
        print(f"  Analyzing issue: {test_issue['type']}")
        try:
            # Mock context
            context = test_issue
            result = deepseek.analyze_vulnerability(
                code_snippet=test_issue['snippet'],
                language='python',
                vulnerability_type=test_issue['type'],
                context=context
            )
            print("  AI Analysis Result:", json.dumps(result, indent=2))
        except Exception as e:
            print(f"  CRASH DETECTED: {e}")
            import traceback
            traceback.print_exc()
    else:
        print("  No issues to analyze.")

if __name__ == "__main__":
    reproduce()
