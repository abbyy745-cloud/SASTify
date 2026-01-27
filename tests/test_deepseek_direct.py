import requests
import os
from dotenv import load_dotenv

load_dotenv(dotenv_path='Backend/.env')

API_KEY = os.getenv('DEEPSEEK_API_KEY')
URL = "https://api.deepseek.com/chat/completions"

def test_key():
    print(f"Testing API Key: {API_KEY[:5]}...{API_KEY[-4:]}")
    
    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {API_KEY}"
    }
    
    data = {
        "model": "deepseek-coder",
        "messages": [{"role": "user", "content": "Hello"}],
        "max_tokens": 10
    }
    
    try:
        response = requests.post(URL, headers=headers, json=data, timeout=10)
        print(f"Status Code: {response.status_code}")
        print(f"Response: {response.text}")
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    test_key()
