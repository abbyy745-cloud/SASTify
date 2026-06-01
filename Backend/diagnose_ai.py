"""
SASTify AI Analysis Diagnostic Script
Tests the DeepSeek API integration end-to-end.
"""
import os
import sys
import json
import time

# Force UTF-8 output on Windows
if sys.platform == 'win32':
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')

sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from dotenv import load_dotenv
load_dotenv()

# ── Step 1: Check API key ────────────────────────────────────────────────────
api_key = os.getenv('DEEPSEEK_API_KEY')
print("=" * 60)
print("SASTify AI Analysis Diagnostic")
print("=" * 60)

print(f"\n[1/5] API Key Check")
if not api_key:
    print("  FAIL: DEEPSEEK_API_KEY is NOT set in .env")
    sys.exit(1)
print(f"  OK: API Key present (starts with: {api_key[:8]}...)")

# ── Step 2: Test raw API connectivity ────────────────────────────────────────
import requests

print(f"\n[2/5] Raw API Connectivity Test (model: deepseek-chat)")
headers = {
    "Content-Type": "application/json",
    "Authorization": f"Bearer {api_key}"
}
data = {
    "model": "deepseek-chat",
    "messages": [{"role": "user", "content": "Say 'hello' in one word."}],
    "temperature": 0.0,
    "max_tokens": 10,
    "stream": False
}

try:
    start = time.time()
    resp = requests.post(
        "https://api.deepseek.com/chat/completions",
        headers=headers,
        json=data,
        timeout=30
    )
    elapsed = time.time() - start
    print(f"  HTTP Status: {resp.status_code} (took {elapsed:.1f}s)")
    
    if resp.status_code == 200:
        result_raw = resp.json()
        content = result_raw.get('choices', [{}])[0].get('message', {}).get('content', '')
        print(f"  OK: API responded: {content!r}")
        model_used = result_raw.get('model', 'unknown')
        print(f"  Model used: {model_used}")
    elif resp.status_code == 401:
        print(f"  FAIL: Authentication failed - API key is INVALID or EXPIRED")
        print(f"  Response: {resp.text[:300]}")
        sys.exit(1)
    elif resp.status_code == 402:
        print(f"  FAIL: Insufficient balance - your DeepSeek account may need funds")
        print(f"  Response: {resp.text[:300]}")
        sys.exit(1)
    elif resp.status_code == 429:
        print(f"  WARN: Rate limited (429) - too many requests. Wait and try again.")
        print(f"  Response: {resp.text[:300]}")
    else:
        print(f"  FAIL: Unexpected status {resp.status_code}")
        print(f"  Response: {resp.text[:500]}")
        sys.exit(1)
except requests.exceptions.Timeout:
    print(f"  FAIL: Request TIMED OUT after 30s - network or API issue")
    sys.exit(1)
except requests.exceptions.ConnectionError as e:
    print(f"  FAIL: Connection FAILED: {e}")
    sys.exit(1)

# ── Step 3: Test the model name used in deepseek_api.py ──────────────────────
print(f"\n[3/5] Model Name Verification (testing 'deepseek-coder')")
print(f"  NOTE: deepseek_api.py currently uses model='deepseek-coder'")
data_model_check = {
    "model": "deepseek-coder",
    "messages": [{"role": "user", "content": "Reply with just the word OK"}],
    "temperature": 0.0,
    "max_tokens": 5,
    "stream": False
}

try:
    time.sleep(2)
    resp2 = requests.post(
        "https://api.deepseek.com/chat/completions",
        headers=headers,
        json=data_model_check,
        timeout=30
    )
    if resp2.status_code == 200:
        print(f"  OK: Model 'deepseek-coder' is accessible")
    else:
        print(f"  FAIL: Model 'deepseek-coder' returned status {resp2.status_code}")
        print(f"  Response: {resp2.text[:400]}")
        print(f"  >>> You likely need to switch to 'deepseek-chat' in deepseek_api.py")
except Exception as e:
    print(f"  FAIL: Error testing model: {e}")

# ── Step 4: Test SecureDeepSeekAPI class ─────────────────────────────────────
print(f"\n[4/5] SecureDeepSeekAPI Class Test")
from deepseek_api import SecureDeepSeekAPI

api = SecureDeepSeekAPI(api_key)

test_code = """const query = req.query.input;
db.query("SELECT * FROM users WHERE id=" + query);"""

test_context = {
    'confidence': 0.9,
    'severity': 'High',
    'line': 2,
    'filename': 'app.js',
}

print(f"  Sending test vulnerability (SQL Injection)...")
print(f"  Rate limit delay configured: {api.rate_limit_delay}s")
print(f"  (This may take up to {api.rate_limit_delay + 45}s due to rate limiting + timeout)")

start = time.time()
result = None
try:
    result = api.analyze_vulnerability(
        code_snippet=test_code,
        language="javascript",
        vulnerability_type="SQL Injection",
        context=test_context,
        ai_mode='fast'
    )
    elapsed = time.time() - start
    print(f"  Completed in {elapsed:.1f}s")
    
    if 'error' in result and result.get('confidence', 1) == 0.0:
        print(f"  FAIL: API returned ERROR: {result['error']}")
    else:
        print(f"  OK: AI analysis returned successfully!")
        print(f"  - is_confirmed_vulnerability: {result.get('is_confirmed_vulnerability')}")
        print(f"  - confidence: {result.get('confidence')}")
        print(f"  - risk_level: {result.get('risk_level')}")
        print(f"  - vulnerability_summary: {result.get('vulnerability_summary', '')[:100]}")
        print(f"  - has suggested_fix: {bool(result.get('suggested_fix'))}")
        print(f"  - has explanation: {bool(result.get('explanation'))}")
        print(f"  - has attack_scenario: {bool(result.get('attack_scenario'))}")
        print(f"  - has suggested_test_cases: {len(result.get('suggested_test_cases', []))} test(s)")
        print(f"  - security_references: {result.get('security_references', [])}")
        
except Exception as e:
    elapsed = time.time() - start
    print(f"  FAIL: EXCEPTION after {elapsed:.1f}s: {type(e).__name__}: {e}")
    import traceback
    traceback.print_exc()

# ── Step 5: Check JSON parsing quality ───────────────────────────────────────
print(f"\n[5/5] Response Parsing Quality Check")
if result is not None and isinstance(result, dict) and not ('error' in result and result.get('confidence', 1) == 0.0):
    expected_fields = [
        'is_confirmed_vulnerability', 'confidence', 'risk_level',
        'vulnerability_summary', 'detailed_explanation', 'explanation',
        'attack_scenario', 'impact_analysis', 'suggested_fix',
        'remediation_steps', 'suggested_test_cases', 'security_references'
    ]
    missing = [f for f in expected_fields if f not in result]
    present = [f for f in expected_fields if f in result]
    
    print(f"  Fields present: {len(present)}/{len(expected_fields)}")
    if missing:
        print(f"  WARN: Missing fields (filled with defaults): {missing}")
    else:
        print(f"  OK: All expected fields present")
    
    # Check for hallucination indicators
    explanation = str(result.get('explanation', '')) + str(result.get('detailed_explanation', ''))
    hallucination_keywords = ['student', 'education', 'school', 'grade', 'course', 
                              'enrollment', 'classroom', 'teacher', 'academic']
    found_hallucinations = [kw for kw in hallucination_keywords if kw.lower() in explanation.lower()]
    if found_hallucinations:
        print(f"  WARN: POTENTIAL HALLUCINATION: AI mentioned domain keywords not in code: {found_hallucinations}")
    else:
        print(f"  OK: No hallucination detected - AI stayed grounded in the code")
    
    print(f"\n  --- Full AI Response ---")
    print(json.dumps(result, indent=2, default=str, ensure_ascii=False)[:2000])
else:
    print(f"  SKIP: No valid result from step 4")

print("\n" + "=" * 60)
print("Diagnostic Complete")
print("=" * 60)
