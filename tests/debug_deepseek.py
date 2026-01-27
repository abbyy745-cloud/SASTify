import requests
import os
import json
from dotenv import load_dotenv

# Load env from Backend/.env
load_dotenv(os.path.join(os.path.dirname(__file__), '..', 'Backend', '.env'))

api_key = os.getenv('DEEPSEEK_API_KEY')
print(f"API Key found: {bool(api_key)}")

def test_endpoint(url):
    print(f"\nTesting endpoint: {url}")
    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {api_key}"
    }
    
    data = {
        "model": "deepseek-coder",
        "messages": [{"role": "user", "content": "Hello, are you working?"}],
        "temperature": 0.1,
        "max_tokens": 10,
        "stream": False
    }
    
    try:
        response = requests.post(url, headers=headers, json=data, timeout=10)
        print(f"Status Code: {response.status_code}")
        print(f"Response: {response.text[:200]}...")
        if response.status_code == 200:
            print("SUCCESS!")
            return True
    except Exception as e:
        print(f"Error: {e}")
    return False

# Test 1: Current implementation
print("--- Test 1: Current Implementation ---")
test_endpoint("https://api.deepseek.com")

# Test 2: Standard Chat Completion Endpoint
print("\n--- Test 2: Standard Chat Completion Endpoint ---")
test_endpoint("https://api.deepseek.com/chat/completions")

# Test 3: v1 Chat Completion Endpoint
print("\n--- Test 3: v1 Chat Completion Endpoint ---")
test_endpoint("https://api.deepseek.com/v1/chat/completions")
