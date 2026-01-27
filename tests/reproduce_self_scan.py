import sys
import os
import json

# Add project root to path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from Backend.enhanced_rule_engine import EnhancedRuleEngine
from Backend.false_positive_detector import FalsePositiveDetector

def test_self_scan():
    print("--- Scanning Backend/enhanced_rule_engine.py ---")
    
    rule_engine = EnhancedRuleEngine()
    fp_detector = FalsePositiveDetector()
    
    file_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'Backend', 'enhanced_rule_engine.py')
    
    with open(file_path, 'r', encoding='utf-8') as f:
        code = f.read()
        
    # Scan
    issues = rule_engine.scan_with_ast_analysis(code, 'python', 'Backend/enhanced_rule_engine.py')
    
    print(f"Found {len(issues)} issues.")
    
    for i, issue in enumerate(issues, 1):
        print(f"  {i}. {issue['type']} at line {issue['line']}: {issue['snippet'][:50]}...")
        
        # Check FP
        is_fp = fp_detector.is_likely_false_positive(issue, {}, 'Backend/enhanced_rule_engine.py')
        print(f"     Likely FP? {is_fp}")
        if is_fp:
            print("     (Correctly identified as FP)" if 'pattern' in issue.get('description', '').lower() else "     (Marked as FP)")

if __name__ == "__main__":
    test_self_scan()
