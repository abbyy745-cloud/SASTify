import re
import requests
import json
import time
from typing import Dict, List, Optional

class SecureDeepSeekAPI:
    def __init__(self, api_key: str):
        self.api_key = api_key
        self.base_url = "https://api.deepseek.com/chat/completions"
        self.rate_limit_delay = 0.1  # 100ms between requests
        self.last_request_time = 0
        
    def analyze_vulnerability(self, code_snippet: str, language: str, vulnerability_type: str, context: Dict) -> Dict:
        """Analyze a specific vulnerability and provide fix suggestions"""
        
        # Rate limiting
        current_time = time.time()
        if current_time - self.last_request_time < self.rate_limit_delay:
            time.sleep(self.rate_limit_delay - (current_time - self.last_request_time))
        
        prompt = self._build_secure_prompt(code_snippet, language, vulnerability_type, context)
        
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {self.api_key}"
        }
        
        data = {
            "model": "deepseek-coder",
            "messages": [{"role": "user", "content": prompt}],
            "temperature": 0.1,
            "max_tokens": 2000,  # Reduced for faster responses
            "stream": False
        }
        
        # Retry logic with exponential backoff
        max_retries = 3
        base_delay = 2  # seconds
        
        for attempt in range(max_retries):
            try:
                response = requests.post(
                    self.base_url, 
                    headers=headers, 
                    json=data, 
                    timeout=90  # Increased timeout for CI environments
                )
                response.raise_for_status()
                
                result = response.json()
                self.last_request_time = time.time()
                
                # Extract and sanitize the response
                try:
                    if 'choices' in result and len(result['choices']) > 0:
                        ai_response = result['choices'][0]['message']['content']
                        return self._parse_and_sanitize_response(ai_response)
                    else:
                        print(f"Unexpected API response format: {result}")
                        return {
                            'error': 'Unexpected API response format',
                            'suggested_fix': 'Unable to generate fix',
                            'explanation': 'The AI service returned an unexpected response format.',
                            'confidence': 0.0
                        }
                except (KeyError, IndexError, TypeError) as e:
                    print(f"Error parsing API response: {e}")
                    return {
                        'error': 'Failed to parse AI response',
                        'suggested_fix': 'Unable to generate fix',
                        'explanation': 'Error parsing the AI service response.',
                        'confidence': 0.0
                    }
                
            except requests.exceptions.Timeout as e:
                wait_time = base_delay * (2 ** attempt)
                if attempt < max_retries - 1:
                    print(f"DeepSeek API timeout (attempt {attempt + 1}/{max_retries}), retrying in {wait_time}s...")
                    time.sleep(wait_time)
                else:
                    print(f"DeepSeek API timeout after {max_retries} attempts: {e}")
                    return {
                        'error': 'API request timed out',
                        'suggested_fix': 'Unable to generate fix - API timeout',
                        'explanation': 'The AI service timed out. Please review the code manually.',
                        'confidence': 0.0
                    }
                    
            except requests.exceptions.RequestException as e:
                print(f"DeepSeek API error: {e}")
                return {
                    'error': 'API request failed',
                    'suggested_fix': 'Unable to generate fix at this time',
                    'explanation': 'Please review the code manually',
                    'confidence': 0.0
                }
        
        # Should not reach here, but just in case
        return {
            'error': 'Unknown error',
            'suggested_fix': 'Unable to generate fix',
            'explanation': 'An unexpected error occurred.',
            'confidence': 0.0
        }
    
    def _build_secure_prompt(self, code_snippet: str, language: str, vulnerability_type: str, context: Dict) -> str:
        """Build a comprehensive prompt for detailed security analysis"""
        
        # Sanitize code snippet (remove potential secrets)
        sanitized_code = self._sanitize_code(code_snippet)
        
        return f"""You are an elite security researcher and code auditor. Perform a comprehensive security analysis of this {language} code for a potential {vulnerability_type} vulnerability.

CODE TO ANALYZE:
```{language}
{sanitized_code}
```

SCANNER DETECTION CONTEXT:
- Vulnerability Type: {vulnerability_type}
- Initial Confidence: {context.get('confidence', 'Unknown')}
- Reported Severity: {context.get('severity', 'Unknown')}
- Line Number: {context.get('line', 'Unknown')}

PROVIDE A COMPREHENSIVE ANALYSIS covering:

1. **VULNERABILITY CONFIRMATION**: Is this a real exploitable vulnerability or a false positive?

2. **DETAILED EXPLANATION**: If confirmed, explain IN DETAIL:
   - What makes this code vulnerable
   - The root cause of the security flaw
   - Why this pattern is dangerous
   - What an attacker could achieve by exploiting this

3. **ATTACK SCENARIO**: Describe a realistic attack scenario:
   - Step-by-step how an attacker would exploit this
   - Example malicious payloads they might use
   - What data/systems could be compromised

4. **IMPACT ANALYSIS**: Assess the business/security impact:
   - Confidentiality impact (data exposure)
   - Integrity impact (data modification)
   - Availability impact (service disruption)
   - Compliance implications (GDPR, PCI-DSS, etc.)

5. **REMEDIATION**: Provide a complete, secure code fix that:
   - Directly replaces the vulnerable code
   - Follows security best practices
   - Is production-ready

6. **TEST CASES**: Provide comprehensive test cases including:
   - Unit tests to verify the fix works
   - Security tests with actual attack payloads
   - Edge cases that should be handled

RESPONSE FORMAT (strict JSON):
{{
    "is_confirmed_vulnerability": true/false,
    "confidence": 0.0-1.0,
    "risk_level": "Low/Medium/High/Critical",
    "vulnerability_summary": "One-line summary of the issue",
    "detailed_explanation": "Comprehensive multi-paragraph explanation of why this code is vulnerable, what the root cause is, and the technical details of how the vulnerability works. Be thorough and educational.",
    "attack_scenario": {{
        "description": "Detailed narrative of how an attacker would exploit this vulnerability step by step",
        "example_payloads": ["payload1", "payload2", "payload3"],
        "attacker_goal": "What the attacker achieves"
    }},
    "impact_analysis": {{
        "confidentiality": "High/Medium/Low/None - explanation",
        "integrity": "High/Medium/Low/None - explanation",
        "availability": "High/Medium/Low/None - explanation",
        "compliance": "List of compliance frameworks this may violate"
    }},
    "suggested_fix": "Complete, production-ready code fix that replaces the vulnerable code",
    "remediation_steps": [
        "Step 1: Description of first remediation action",
        "Step 2: Description of second remediation action",
        "Step 3: etc."
    ],
    "false_positive_reason": "If this is a false positive, explain in detail why it's not actually exploitable",
    "suggested_test_cases": [
        {{
            "type": "unit",
            "name": "Descriptive test name",
            "description": "What this test verifies and why it's important",
            "code": "Complete runnable test code in {language}"
        }},
        {{
            "type": "security",
            "name": "Security test name",
            "description": "What attack vector this tests against",
            "test_inputs": ["malicious_input_1", "malicious_input_2"],
            "expected_behavior": "What should happen when these inputs are provided"
        }},
        {{
            "type": "integration",
            "name": "Integration test name",
            "description": "End-to-end test scenario",
            "code": "Complete test code"
        }}
    ],
    "security_references": [
        "CWE-XXX: Name",
        "OWASP Top 10 reference if applicable"
    ]
}}

IMPORTANT: Return ONLY the JSON object. No markdown, no explanatory text before or after."""
    
    def _sanitize_code(self, code: str) -> str:
        """Remove potential secrets from code before sending to AI"""
        # Remove obvious hardcoded secrets (basic sanitization)
        sanitized = re.sub(r'["\'][A-Za-z0-9]{20,}["\']', '"***SANITIZED***"', code)
        sanitized = re.sub(r'(?i)password\s*=\s*["\'][^"\']+["\']', 'password = "***SANITIZED***"', sanitized)
        sanitized = re.sub(r'(?i)api[_-]?key\s*=\s*["\'][^"\']+["\']', 'api_key = "***SANITIZED***"', sanitized)
        sanitized = re.sub(r'(?i)secret\s*=\s*["\'][^"\']+["\']', 'secret = "***SANITIZED***"', sanitized)
        
        return sanitized
    
    def _parse_and_sanitize_response(self, ai_response: str) -> Dict:
        """Parse AI response and sanitize any potentially dangerous content"""
        try:
            # Extract JSON from response
            json_match = re.search(r'\{.*\}', ai_response, re.DOTALL)
            if json_match:
                response_data = json.loads(json_match.group())
            else:
                response_data = {'error': 'Invalid response format'}
        except json.JSONDecodeError:
            response_data = {'error': 'Failed to parse AI response'}
        
        # Recursive sanitization function
        def sanitize_value(value):
            if isinstance(value, str):
                # Remove any code execution attempts
                value = re.sub(r'eval\s*\(', 'sanitized(', value)
                value = re.sub(r'exec\s*\(', 'sanitized(', value)
                value = re.sub(r'__import__', 'sanitized_import', value)
                return value
            elif isinstance(value, dict):
                return {k: sanitize_value(v) for k, v in value.items()}
            elif isinstance(value, list):
                return [sanitize_value(item) for item in value]
            return value
        
        # Sanitize all values recursively
        sanitized_data = sanitize_value(response_data)
        
        # Clean up suggested_fix if it contains markdown code blocks
        if 'suggested_fix' in sanitized_data and isinstance(sanitized_data['suggested_fix'], str):
            fix_value = sanitized_data['suggested_fix']
            code_block_match = re.search(r'```(?:\w+)?\s*(.*?)```', fix_value, re.DOTALL)
            if code_block_match:
                sanitized_data['suggested_fix'] = code_block_match.group(1).strip()
            else:
                # Remove "Replace with:" or similar prefixes
                sanitized_data['suggested_fix'] = re.sub(r'(?i)^replace.*?with:?\s*', '', fix_value).strip()
        
        # Map new field names to legacy names for backward compatibility
        if 'detailed_explanation' in sanitized_data and 'explanation' not in sanitized_data:
            sanitized_data['explanation'] = sanitized_data['detailed_explanation']
        
        # Ensure required fields with comprehensive defaults
        sanitized_data.setdefault('is_confirmed_vulnerability', False)
        sanitized_data.setdefault('suggested_fix', 'No fix suggested')
        sanitized_data.setdefault('explanation', sanitized_data.get('detailed_explanation', 'No explanation provided'))
        sanitized_data.setdefault('detailed_explanation', sanitized_data.get('explanation', 'No detailed explanation provided'))
        sanitized_data.setdefault('confidence', 0.5)
        sanitized_data.setdefault('risk_level', 'Medium')
        sanitized_data.setdefault('vulnerability_summary', '')
        sanitized_data.setdefault('attack_scenario', {})
        sanitized_data.setdefault('impact_analysis', {})
        sanitized_data.setdefault('remediation_steps', [])
        sanitized_data.setdefault('suggested_test_cases', [])
        sanitized_data.setdefault('security_references', [])
        
        return sanitized_data