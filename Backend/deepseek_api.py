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
            "max_tokens": 800,
            "stream": False
        }
        
        try:
            response = requests.post(self.base_url, headers=headers, json=data, timeout=30)
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
            
        except requests.exceptions.RequestException as e:
            print(f"DeepSeek API error: {e}")
            return {
                'error': 'API request failed',
                'suggested_fix': 'Unable to generate fix at this time',
                'explanation': 'Please review the code manually',
                'confidence': 0.0
            }
    
    def _build_secure_prompt(self, code_snippet: str, language: str, vulnerability_type: str, context: Dict) -> str:
        """Build a secure prompt that doesn't expose sensitive information"""
        
        # Sanitize code snippet (remove potential secrets)
        sanitized_code = self._sanitize_code(code_snippet)
        
        return f"""
        You are a security code reviewer and testing expert. Analyze this {language} code for a {vulnerability_type} vulnerability.
        
        CODE SNIPPET:
        ```{language}
        {sanitized_code}
        ```
        
        VULNERABILITY CONTEXT:
        - Type: {vulnerability_type}
        - Scanner Confidence: {context.get('confidence', 'Unknown')}
        - Severity: {context.get('severity', 'Unknown')}
        
        YOUR TASK:
        1. Confirm if this is a real vulnerability or false positive
        2. If real, provide a specific code fix
        3. Explain the security risk briefly
        4. Suggest secure coding alternatives
        5. Provide test cases the developer can implement to verify the fix
        
        RESPONSE FORMAT (JSON only):
        {{
            "is_confirmed_vulnerability": true/false,
            "confidence": 0.0-1.0,
            "suggested_fix": "specific code fix here",
            "explanation": "brief security explanation",
            "risk_level": "Low/Medium/High/Critical",
            "false_positive_reason": "if false positive, explain why",
            "suggested_test_cases": [
                {{
                    "type": "unit",
                    "name": "test name",
                    "description": "what this test verifies",
                    "code": "test code snippet in {language}"
                }},
                {{
                    "type": "security",
                    "name": "security test name",
                    "description": "what attack scenario this tests",
                    "test_inputs": ["malicious input 1", "malicious input 2"]
                }}
            ]
        }}
        
        Important: Only return the JSON object, no other text.
        """
    
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
        
        # Sanitize the response to prevent code injection
        sanitized_data = {}
        for key, value in response_data.items():
            if isinstance(value, str):
                # Remove any code execution attempts
                value = re.sub(r'eval\s*\(', 'sanitized(', value)
                value = re.sub(r'exec\s*\(', 'sanitized(', value)
                value = re.sub(r'__import__', 'sanitized_import', value)
                
                # Clean up suggested_fix if it contains markdown code blocks
                if key == 'suggested_fix':
                    # Check for markdown code blocks ```language ... ``` or just ``` ... ```
                    code_block_match = re.search(r'```(?:\w+)?\s*(.*?)```', value, re.DOTALL)
                    if code_block_match:
                        value = code_block_match.group(1).strip()
                    else:
                        # Also check for single backticks `...` if it's a one-liner
                        single_tick_match = re.search(r'`([^`]+)`', value)
                        if single_tick_match and '\n' not in value:
                             # Only use single tick match if it looks like a short snippet and not just mentioning a variable
                             # But for fixes, usually we want the whole content. 
                             # If the AI says "Use `secrets.token_hex()`", we want "secrets.token_hex()".
                             # However, if it says "Import `os`", we might want "import os".
                             # Let's stick to stripping surrounding text if it looks like a sentence.
                             pass
                    
                    # Remove "Replace with:" or similar prefixes if no code block found but text exists
                    if not code_block_match:
                         # Simple heuristic: if it starts with "Replace ... with", try to remove it
                         value = re.sub(r'(?i)^replace.*?with:?\s*', '', value).strip()

            sanitized_data[key] = value
        
        # Ensure required fields
        sanitized_data.setdefault('is_confirmed_vulnerability', False)
        sanitized_data.setdefault('suggested_fix', 'No fix suggested')
        sanitized_data.setdefault('explanation', 'No explanation provided')
        sanitized_data.setdefault('confidence', 0.5)
        sanitized_data.setdefault('risk_level', 'Medium')
        sanitized_data.setdefault('suggested_test_cases', [])
        
        return sanitized_data