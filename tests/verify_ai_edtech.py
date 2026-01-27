import os
import sys
from dotenv import load_dotenv

# Add Backend to path
sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'Backend'))

from deepseek_api import SecureDeepSeekAPI

# Load environment variables
load_dotenv(os.path.join(os.path.dirname(__file__), '..', 'Backend', '.env'))

api_key = os.getenv('DEEPSEEK_API_KEY')
if not api_key:
    print("Skipping AI test: DEEPSEEK_API_KEY not found")
    sys.exit(0)

api = SecureDeepSeekAPI(api_key)

# Read vulnerable code
with open(os.path.join(os.path.dirname(__file__), 'edtech_test_files', 'ai_vulnerable.py'), 'r') as f:
    code = f.read()

# Extract a snippet (Prompt Injection)
snippet = 'prompt = f"Translate the following to French: {user_input}"'
vuln_type = "Prompt Injection"
context = {
    "confidence": 0.8,
    "severity": "High",
    "description": "Potential prompt injection via f-string concatenation"
}

print("Sending request to AI...")
try:
    result = api.analyze_vulnerability(snippet, "python", vuln_type, context)
    print("AI Response:", result)
    
    # Verification logic
    if "injection" in result.lower() or "sanitize" in result.lower() or "user input" in result.lower():
        print("SUCCESS: AI correctly identified the risk.")
    else:
        print("FAILURE: AI response did not mention key terms.")
        sys.exit(1)

except Exception as e:
    print(f"AI Analysis Failed: {e}")
    sys.exit(1)
