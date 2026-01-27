import os
import sys
from dotenv import load_dotenv

# Add current directory to path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from deepseek_api import SecureDeepSeekAPI

# Load environment variables
load_dotenv()

api_key = os.getenv('DEEPSEEK_API_KEY')
print(f"API Key present: {bool(api_key)}")

if not api_key:
    print("Error: DEEPSEEK_API_KEY not found in .env")
    sys.exit(1)

api = SecureDeepSeekAPI(api_key)

code_snippet = "const password = 'hardcoded_password';"
language = "javascript"
vulnerability_type = "Hardcoded Credential"
context = {"confidence": 0.9, "severity": "High"}

print("Testing analyze_vulnerability...")
try:
    result = api.analyze_vulnerability(code_snippet, language, vulnerability_type, context)
    print("Result:", result)
except Exception as e:
    print(f"Exception: {e}")
