import sys
import os

# Add Backend to path
sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'Backend'))

from false_positive_detector import FalsePositiveDetector

def test_fp_detection():
    detector = FalsePositiveDetector()
    
    # Test case 1: Hardcoded secret in a regular file
    issue_regular = {
        'type': 'hardcoded_secret',
        'snippet': 'password = "secret"',
        'confidence': 0.8,
        'severity': 'High'
    }
    is_fp_regular = detector.is_likely_false_positive(issue_regular, {}, filename="src/auth.py")
    print(f"Regular file (auth.py) - Hardcoded Secret: Is FP? {is_fp_regular} (Expected: False)")
    
    # Test case 2: Hardcoded secret in a test file
    issue_test = {
        'type': 'hardcoded_secret',
        'snippet': 'password = "secret"',
        'confidence': 0.8,
        'severity': 'High'
    }
    is_fp_test = detector.is_likely_false_positive(issue_test, {}, filename="tests/test_auth.py")
    print(f"Test file (test_auth.py) - Hardcoded Secret: Is FP? {is_fp_test} (Expected: True)")

    # Test case 3: Insecure randomness in a test file
    issue_random = {
        'type': 'insecure_randomness',
        'snippet': 'random.randint(1, 100)',
        'confidence': 0.4, # Low confidence
        'severity': 'Low'
    }
    is_fp_random = detector.is_likely_false_positive(issue_random, {}, filename="tests/utils_test.py")
    print(f"Test file (utils_test.py) - Randomness: Is FP? {is_fp_random} (Expected: True)")

if __name__ == "__main__":
    test_fp_detection()
