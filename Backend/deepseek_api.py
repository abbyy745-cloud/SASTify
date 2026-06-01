import re
import requests
import json
import time
import concurrent.futures
from typing import Dict, List, Optional

class SecureDeepSeekAPI:
    def __init__(self, api_key: str):
        self.api_key = api_key
        self.base_url = "https://api.deepseek.com/chat/completions"
        # DeepSeek free tier allows ~3 RPM — enforce at least 20 s between calls
        # to stay well under the limit and avoid 429s.
        self.rate_limit_delay = 20.0
        self.last_request_time = 0
        self._lock = None  # will be created on first use (thread-safety)
        
    def analyze_vulnerability(self, code_snippet: str, language: str, vulnerability_type: str, context: Dict, ai_mode: str = 'fast') -> Dict:
        """Analyze a specific vulnerability and provide fix suggestions"""
        
        # Rate limiting
        current_time = time.time()
        if current_time - self.last_request_time < self.rate_limit_delay:
            time.sleep(self.rate_limit_delay - (current_time - self.last_request_time))
        
        if ai_mode == 'fast':
            prompt = self._build_fast_prompt(code_snippet, language, vulnerability_type, context)
            max_tokens = 2000
        else:
            prompt = self._build_secure_prompt(code_snippet, language, vulnerability_type, context)
            max_tokens = 4000
        
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {self.api_key}"
        }
        
        data = {
            "model": "deepseek-chat",
            "messages": [{"role": "user", "content": prompt}],
            "temperature": 0.1,
            "max_tokens": max_tokens,
            "stream": False
        }
        
        # Retry logic with exponential backoff — handles 429, timeouts, and
        # transient network errors gracefully.
        max_retries = 4
        base_delay = 5  # seconds — initial backoff

        for attempt in range(max_retries):
            try:
                response = requests.post(
                    self.base_url,
                    headers=headers,
                    json=data,
                    timeout=45
                )

                # ── Handle rate-limit explicitly before raise_for_status ────────
                if response.status_code == 429:
                    retry_after = int(response.headers.get('Retry-After', base_delay * (2 ** attempt)))
                    wait_time = max(retry_after, base_delay * (2 ** attempt))
                    if attempt < max_retries - 1:
                        print(f"DeepSeek 429 rate-limited (attempt {attempt + 1}/{max_retries}). "
                              f"Waiting {wait_time}s before retry…")
                        time.sleep(wait_time)
                        continue
                    else:
                        print(f"DeepSeek 429 rate-limit — exhausted {max_retries} retries.")
                        return self._error_response(
                            'DeepSeek API rate limit reached (429). '
                            'Please wait a moment and try again.'
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
                        return self._error_response('Unexpected API response format')
                except (KeyError, IndexError, TypeError) as e:
                    print(f"Error parsing API response: {e}")
                    return self._error_response('Failed to parse AI response')

            except requests.exceptions.Timeout:
                wait_time = base_delay * (2 ** attempt)
                if attempt < max_retries - 1:
                    print(f"DeepSeek timeout (attempt {attempt + 1}/{max_retries}), retrying in {wait_time}s…")
                    time.sleep(wait_time)
                else:
                    print(f"DeepSeek timeout after {max_retries} attempts.")
                    return self._error_response('AI request timed out — the model may be busy. Try again shortly.')

            except requests.exceptions.RequestException as e:
                status = getattr(e.response, 'status_code', None) if hasattr(e, 'response') else None
                if status == 429:
                    # Caught via raise_for_status path
                    wait_time = base_delay * (2 ** attempt)
                    if attempt < max_retries - 1:
                        print(f"DeepSeek 429 (via exception), waiting {wait_time}s…")
                        time.sleep(wait_time)
                        continue
                    return self._error_response('DeepSeek API rate limit reached (429). Please try again shortly.')
                print(f"DeepSeek API error: {e}")
                return self._error_response(f'API request failed: {str(e)}')

        return self._error_response('Unknown error after retries')
    
    def analyze_vulnerabilities_batch(self, vuln_items: List[Dict], ai_mode: str = 'fast', max_workers: int = 1, verbose: bool = False) -> List[Dict]:
        """Analyze multiple vulnerabilities SEQUENTIALLY to avoid rate-limit (429) errors.

        max_workers is kept at 1 by default — concurrent requests to DeepSeek's
        free-tier API reliably trigger 429s. The rate_limit_delay between calls
        is enforced by analyze_vulnerability() itself.

        Each item in vuln_items should have: code_snippet, language, vulnerability_type, context
        Returns list of AI result dicts in the same order.
        """
        results = [None] * len(vuln_items)

        for idx, item in enumerate(vuln_items):
            if verbose:
                print(f"  [{idx+1}/{len(vuln_items)}] Analyzing: {item.get('vulnerability_type', 'unknown')}")
            results[idx] = self.analyze_vulnerability(
                item['code_snippet'],
                item['language'],
                item['vulnerability_type'],
                item.get('context', {}),
                ai_mode=ai_mode
            )

        return results
    
    @staticmethod
    def _error_response(error_msg: str) -> Dict:
        """Return a standard error response dict"""
        return {
            'error': error_msg,
            'suggested_fix': 'Unable to generate fix',
            'explanation': 'Please review the code manually.',
            'confidence': 0.0
        }
    
    def _build_fast_prompt(self, code_snippet: str, language: str, vulnerability_type: str, context: Dict) -> str:
        """Build a concise prompt for fast AI analysis."""
        sanitized_code = self._sanitize_code(code_snippet)

        # Only embed fields that are truly scanner-agnostic.
        # Do NOT embed scanner descriptions, rule names, or edtech-specific
        # labels — they cause the AI to hallucinate domain-specific reasoning
        # unrelated to the actual code.
        severity  = context.get('severity', 'Unknown')
        line      = context.get('line', 'Unknown')
        filename  = context.get('filename', '')
        file_hint = f" (in file: {filename})" if filename else ""

        return f"""You are a security researcher performing code review. Analyse the following {language} code snippet for a potential **{vulnerability_type}** vulnerability.

Your analysis MUST be based SOLELY on the code below. Do NOT assume any application domain (e.g. education, finance, healthcare) unless it is explicitly visible in the code. Do NOT reference information that is not present in the snippet.

Code snippet{file_hint} — line {line} (severity flagged as: {severity}):
```{language}
{sanitized_code}
```

Return a STRICT JSON object with ALL of the following fields:

{{
    "is_confirmed_vulnerability": true/false,
    "confidence": 0.0-1.0,
    "risk_level": "Low/Medium/High/Critical",
    "vulnerability_summary": "One-line summary of what is wrong in THIS code",
    "detailed_explanation": "2–3 sentence explanation grounded in the code above",
    "attack_scenario": {{
        "description": "How an attacker would exploit THIS specific code pattern",
        "example_payloads": ["payload1"],
        "attacker_goal": "Goal"
    }},
    "impact_analysis": {{
        "confidentiality": "High/Medium/Low — reason",
        "integrity": "High/Medium/Low — reason",
        "availability": "High/Medium/Low — reason",
        "compliance": "Relevant standards if any"
    }},
    "suggested_fix": "Corrected code snippet that replaces the vulnerable lines",
    "remediation_steps": ["Step 1", "Step 2"],
    "false_positive_reason": "If NOT a real vulnerability, explain why based on the code only",
    "suggested_test_cases": [
        {{
            "type": "unit",
            "name": "Test name",
            "description": "What it tests",
            "code": "Test code"
        }},
        {{
            "type": "security",
            "name": "Security test",
            "description": "Attack vector tested",
            "test_inputs": ["input1"],
            "expected_behavior": "Expected result"
        }}
    ],
    "security_references": ["CWE-XXX"]
}}

Return ONLY the JSON. No markdown, no text before or after."""

    def _build_secure_prompt(self, code_snippet: str, language: str, vulnerability_type: str, context: Dict) -> str:
        """Build a comprehensive prompt for detailed security analysis (full mode)."""
        sanitized_code = self._sanitize_code(code_snippet)

        severity  = context.get('severity', 'Unknown')
        line      = context.get('line', 'Unknown')
        filename  = context.get('filename', '')
        file_hint = f" (in file: {filename})" if filename else ""

        return f"""You are an elite security researcher performing a comprehensive code audit. Analyse the following {language} code for a potential **{vulnerability_type}** vulnerability.

CRITICAL RULES:
- Base every conclusion SOLELY on the code provided below.
- Do NOT infer application domain (e.g. education, finance) unless the code explicitly shows it.
- Do NOT reference information that does not appear in the snippet.
- If the vulnerability type label seems unrelated to what the code actually does, say so in false_positive_reason.

Code snippet{file_hint} — line {line} (severity flagged as: {severity}):
```{language}
{sanitized_code}
```

Provide a COMPREHENSIVE analysis covering:
1. **VULNERABILITY CONFIRMATION**: Is this a real, exploitable vulnerability given the code above?
2. **DETAILED EXPLANATION**: Root cause, what makes it dangerous, what an attacker achieves.
3. **ATTACK SCENARIO**: Step-by-step exploitation of THIS specific code pattern with concrete payloads.
4. **IMPACT ANALYSIS**: Confidentiality / Integrity / Availability / Compliance implications.
5. **REMEDIATION**: Complete, production-ready secure code that replaces the vulnerable lines.
6. **TEST CASES**: Unit tests, security tests with attack payloads, edge cases.

RESPONSE FORMAT (strict JSON — return ONLY this, no markdown outside):
{{
    "is_confirmed_vulnerability": true/false,
    "confidence": 0.0-1.0,
    "risk_level": "Low/Medium/High/Critical",
    "vulnerability_summary": "One-line summary grounded in the code",
    "detailed_explanation": "Thorough explanation of why THIS code is vulnerable and how it works technically.",
    "attack_scenario": {{
        "description": "Step-by-step exploitation of this specific code pattern",
        "example_payloads": ["payload1", "payload2"],
        "attacker_goal": "What the attacker achieves"
    }},
    "impact_analysis": {{
        "confidentiality": "High/Medium/Low/None — explanation",
        "integrity": "High/Medium/Low/None — explanation",
        "availability": "High/Medium/Low/None — explanation",
        "compliance": "Compliance frameworks this may violate"
    }},
    "suggested_fix": "Complete, production-ready secure code that replaces the vulnerable code",
    "remediation_steps": [
        "Step 1: First remediation action",
        "Step 2: Second remediation action"
    ],
    "false_positive_reason": "If NOT a real vulnerability, explain why based strictly on the code — or if the vulnerability type label is unrelated to the code pattern, say that here",
    "suggested_test_cases": [
        {{
            "type": "unit",
            "name": "Descriptive test name",
            "description": "What this test verifies",
            "code": "Complete runnable test code in {language}"
        }},
        {{
            "type": "security",
            "name": "Security test name",
            "description": "Attack vector tested",
            "test_inputs": ["malicious_input_1", "malicious_input_2"],
            "expected_behavior": "Expected safe behaviour"
        }},
        {{
            "type": "integration",
            "name": "Integration test name",
            "description": "End-to-end scenario",
            "code": "Complete test code"
        }}
    ],
    "security_references": [
        "CWE-XXX: Name",
        "OWASP reference if applicable"
    ]
}}"""
    
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