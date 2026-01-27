import hashlib
import json
from typing import Dict, List, Any, Optional
from datetime import datetime

class FalsePositiveDetector:
    def __init__(self):
        self.false_positive_db = {}
        self.feedback_history = []
    
    def calculate_fingerprint(self, issue: Dict) -> str:
        """Create a unique fingerprint for an issue"""
        fingerprint_data = {
            'type': issue.get('type'),
            'line_content': issue.get('snippet', '').strip(),
            'pattern': issue.get('pattern', ''),
            'context_hash': self._get_context_hash(issue)
        }
        return hashlib.md5(json.dumps(fingerprint_data, sort_keys=True).encode()).hexdigest()
    
    def _get_context_hash(self, issue: Dict) -> str:
        """Create hash of code context around the issue"""
        context = issue.get('context', '')[:100]  # First 100 chars of context
        return hashlib.md5(context.encode()).hexdigest()
    
    def is_likely_false_positive(self, issue: Dict, historical_data: Dict, filename: Optional[str] = None) -> bool:
        """Determine if an issue is likely a false positive"""
        fingerprint = self.calculate_fingerprint(issue)
        
        # Check if we've seen this exact issue before as FP
        if fingerprint in self.false_positive_db:
            return self.false_positive_db[fingerprint]['is_false_positive']
        
        # Check if it's a test file
        if filename and self._is_test_file(filename):
            # In test files, we are more lenient with secrets and randomness
            issue_type = issue.get('type', '')
            if issue_type in ['hardcoded_secret', 'insecure_randomness', 'weak_cryptography', 'information_exposure', 'path_traversal']:
                return True
        
        # Apply heuristic rules
        confidence_score = issue.get('confidence', 0)
        
        # Low confidence issues are more likely to be FPs
        if confidence_score < 0.5:
            return True
        
        # Certain patterns are commonly false positives
        if self._is_common_false_positive_pattern(issue):
            return True
        
        # Check user's historical feedback
        user_fp_rate = historical_data.get('false_positive_rate', 0)
        if user_fp_rate > 0.7:  # User frequently marks similar issues as FP
            return True
        
        return False
    
    def _is_test_file(self, filename: str) -> bool:
        """Check if the file is likely a test file"""
        filename_lower = filename.lower()
        test_indicators = ['test_', '_test', '.test.', '.spec.', '/tests/', '\\tests\\', '/test/', '\\test\\', 'debug_']
        return any(indicator in filename_lower for indicator in test_indicators)

    def _is_common_false_positive_pattern(self, issue: Dict) -> bool:
        """Check for patterns that are commonly false positives"""
        issue_type = issue.get('type', '')
        snippet = issue.get('snippet', '').lower()
        
        common_fp_patterns = [
            # Test code patterns
            ('test' in snippet and 'password' in snippet),
            ('example' in snippet and 'api_key' in snippet),
            ('mock' in snippet and 'secret' in snippet),
            
            # Configuration patterns that are safe
            ('config' in snippet and 'default' in snippet),
            ('localhost' in snippet and 'password' in snippet),
            
            # Common development patterns
            ('debug' in snippet and issue_type == 'information_exposure'),
            ('todo' in snippet and 'fix' in snippet),
        ]
        
        return any(common_fp_patterns)
    
    def record_feedback(self, issue: Dict, is_false_positive: bool, user_comment: str = ""):
        """Record user feedback about an issue"""
        fingerprint = self.calculate_fingerprint(issue)
        
        feedback = {
            'fingerprint': fingerprint,
            'issue_type': issue.get('type'),
            'is_false_positive': is_false_positive,
            'user_comment': user_comment,
            'timestamp': self._get_current_timestamp()
        }
        
        self.feedback_history.append(feedback)
        self.false_positive_db[fingerprint] = feedback
        
        print(f"Recorded feedback for {fingerprint}: FP={is_false_positive}")
    
    def get_false_positive_stats(self) -> Dict:
        """Get statistics about false positives"""
        total_feedback = len(self.feedback_history)
        if total_feedback == 0:
            return {'total': 0, 'false_positive_rate': 0}
        
        false_positives = sum(1 for fb in self.feedback_history if fb['is_false_positive'])
        
        return {
            'total_feedback': total_feedback,
            'false_positives': false_positives,
            'false_positive_rate': false_positives / total_feedback,
            'common_fp_types': self._get_common_fp_types()
        }
    
    def _get_common_fp_types(self) -> List[Dict]:
        """Get most common false positive types"""
        type_counts = {}
        for fb in self.feedback_history:
            if fb['is_false_positive']:
                issue_type = fb['issue_type']
                type_counts[issue_type] = type_counts.get(issue_type, 0) + 1
        
        return [{'type': k, 'count': v} for k, v in sorted(type_counts.items(), key=lambda x: x[1], reverse=True)[:5]]
    
    def _get_current_timestamp(self) -> str:
        return datetime.now().isoformat()