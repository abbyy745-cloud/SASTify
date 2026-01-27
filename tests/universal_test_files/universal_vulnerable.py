import requests
import jwt
import os

# Vulnerability 1: SSRF (Server-Side Request Forgery)
def fetch_url():
    user_url = requests.args.get('url')
    # Unsafe: Fetching arbitrary URL provided by user
    response = requests.get(user_url)
    return response.content

# Vulnerability 2: Weak JWT Algorithm
def create_token(user_id):
    payload = {'user_id': user_id}
    # Unsafe: Algorithm 'none' allows signature bypass
    token = jwt.encode(payload, None, algorithm='none')
    return token

# Vulnerability 3: Misconfiguration (Debug Mode)
DEBUG = True # Unsafe in production

# Vulnerability 4: Insecure Cookies
SESSION_COOKIE_HTTPONLY = False
SESSION_COOKIE_SECURE = False
