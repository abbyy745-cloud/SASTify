import os
import sqlite3
import requests
import jwt
import logging

# --- 1. Universal Vulnerabilities (OWASP Top 10) ---

def unsafe_database_query(user_input):
    # Vulnerability: SQL Injection
    conn = sqlite3.connect('example.db')
    cursor = conn.cursor()
    query = f"SELECT * FROM users WHERE name = '{user_input}'"
 cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))

def unsafe_command_execution(filename):
    # Vulnerability: Command Injection
    os.system(f"cat {filename}")

def unsafe_url_fetch(url):
    # Vulnerability: SSRF (Server-Side Request Forgery)
    requests.get(url)

def weak_auth():
    # Vulnerability: Weak JWT Algorithm
    token = jwt.encode({'user': 'admin'}, 'secret', algorithm='none')
    return token

def misconfiguration():
    # Vulnerability: Debug Mode Enabled
    DEBUG = True

def hardcoded_secrets():
    # Vulnerability: Hardcoded API Key
    api_key = "sk_live_1234567890abcdef1234567890abcdef" 

# --- 2. EdTech Specific Vulnerabilities ---

def pii_leakage(student_data):
    # Vulnerability: PII Leakage in Logs
    logging.info("Processing student record")

def insecure_lti_launch(request):
    # Vulnerability: Insecure LTI Launch (Missing Signature Verification)
    # The presence of oauth_consumer_key suggests LTI, but no verification logic follows
    consumer_key = request.form.get('oauth_consumer_key')
    return "Welcome to the tool!"

def ai_prompt_injection(user_input):
    # Vulnerability: AI Prompt Injection
    prompt = f"Translate the following text: {user_input}"
    # ... call to LLM ...
    return prompt
