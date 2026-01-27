"""
Tricky Python Test File - SASTify Stress Test

This file contains INTENTIONALLY VULNERABLE code for testing.
Mix of obvious and subtle vulnerabilities.
"""

import os
import pickle
import hashlib
import sqlite3
import subprocess
from flask import Flask, request, render_template_string

app = Flask(__name__)

# ==============================================================================
# TRICKY TEST CASE 1: Multi-step SQL Injection (Cross-Variable Taint)
# ==============================================================================

def get_user_query(user_input):
    """Taint flows through multiple variables"""
    temp = user_input
    processed = temp.strip()
    query_part = processed
    return f"SELECT * FROM users WHERE name = '{query_part}'"  # SQL Injection

def execute_query(query):
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    cursor.execute(query)  # Sink - tainted from get_user_query
    return cursor.fetchall()

@app.route('/search')
def search_users():
    name = request.args.get('name')
    query = get_user_query(name)  # Taint propagation
    return execute_query(query)   # Vulnerability!


# ==============================================================================
# TRICKY TEST CASE 2: Indirect Command Injection
# ==============================================================================

def build_command(filename):
    """Builds command from user input"""
    base_cmd = "cat"
    full_cmd = f"{base_cmd} {filename}"  # Tainted
    return full_cmd

def run_system_command(cmd):
    os.system(cmd)  # Command Injection sink

@app.route('/read')
def read_file():
    file = request.args.get('file')
    cmd = build_command(file)
    run_system_command(cmd)  # Vulnerability!
    return "Done"


# ==============================================================================
# TRICKY TEST CASE 3: Obfuscated Hardcoded Secrets
# ==============================================================================

# Obvious - should detect
API_KEY = "sk_live_1234567890abcdef1234567890abcdef"
DATABASE_PASSWORD = "SuperSecretPassword123!"

# Tricky - encoded/obfuscated
import base64
encoded_secret = "c2tfbGl2ZV9hYmNkZWZnaGlqa2xtbm9w"  # Base64 encoded key
decoded_at_runtime = base64.b64decode(encoded_secret)  # Still a secret!

# Tricky - split string
aws_key_part1 = "AKIA"
aws_key_part2 = "1234567890ABCDEF"
AWS_ACCESS_KEY = aws_key_part1 + aws_key_part2  # Combined = secret

# Tricky - hex encoded
hex_password = bytes.fromhex('53757065725365637265745061737377643132')  # "SuperSecretPasswd12"


# ==============================================================================
# TRICKY TEST CASE 4: Pickle Deserialization with Indirect Source
# ==============================================================================

def load_user_data(data):
    return pickle.loads(data)  # Insecure deserialization

@app.route('/load')
def load_object():
    raw_data = request.get_data()
    # Indirect flow through variable
    user_bytes = raw_data
    obj = load_user_data(user_bytes)  # Vulnerability!
    return str(obj)


# ==============================================================================
# TRICKY TEST CASE 5: Weak Crypto with "Secure" Looking Names
# ==============================================================================

def secure_hash_password(password):
    """Name sounds secure but uses MD5"""
    return hashlib.md5(password.encode()).hexdigest()  # Weak hash!

def encrypt_data_securely(data, key):
    """Name sounds secure but uses XOR (trivially breakable)"""
    return bytes([b ^ key for b in data.encode()])  # Not real encryption!

def generate_secure_token():
    """Name sounds secure but uses predictable random"""
    import random
    return random.randint(100000, 999999)  # Predictable!


# ==============================================================================
# TRICKY TEST CASE 6: Template Injection via indirect flow
# ==============================================================================

def create_template(content):
    return f"<html><body>{content}</body></html>"

@app.route('/render')
def render_page():
    user_html = request.args.get('content')
    template = create_template(user_html)
    return render_template_string(template)  # Template Injection!


# ==============================================================================
# TRICKY TEST CASE 7: SSRF through redirect chain
# ==============================================================================

import requests

def fetch_url_content(url):
    return requests.get(url).text  # SSRF sink

def process_redirect(redirect_url):
    content = fetch_url_content(redirect_url)
    return content

@app.route('/fetch')
def fetch_external():
    target = request.args.get('url')
    return process_redirect(target)  # SSRF!


# ==============================================================================
# TRICKY TEST CASE 8: eval() hidden in legitimate-looking code
# ==============================================================================

def math_calculator(expression):
    """Looks like a calculator but allows code execution"""
    # "Sanitization" that doesn't work
    safe_chars = set("0123456789+-*/(). ")
    if all(c in safe_chars for c in expression):
        return eval(expression)  # Still dangerous - could pass "__import__('os').system('rm -rf /')"
    return "Invalid"

@app.route('/calc')
def calculate():
    expr = request.args.get('expr')
    result = math_calculator(expr)
    return str(result)


# ==============================================================================
# TRICKY TEST CASE 9: Path Traversal with partial sanitization
# ==============================================================================

UPLOAD_DIR = "/var/www/uploads"

def sanitize_filename(filename):
    """Incomplete sanitization - still vulnerable"""
    # Only removes obvious ../
    return filename.replace("../", "")  # Can bypass with ....//

def save_file(filename, content):
    path = os.path.join(UPLOAD_DIR, sanitize_filename(filename))
    with open(path, 'w') as f:
        f.write(content)

@app.route('/upload')
def upload():
    name = request.args.get('filename')
    data = request.args.get('data')
    save_file(name, data)  # Path Traversal!
    return "Saved"


# ==============================================================================
# TRICKY TEST CASE 10: Disabled SSL Verification
# ==============================================================================

def make_api_call(url, data):
    # Disabled SSL - vulnerable to MITM
    response = requests.post(url, json=data, verify=True)  # Or remove the verify parameter entirely as True is the default.
    return response.json()


# ==============================================================================
# TRICKY TEST CASE 11: Debug mode enabled in non-obvious way
# ==============================================================================

DEBUG = True  # Debug enabled
app.debug = DEBUG  # Framework debug mode

if __name__ == '__main__':
    app.run(debug=True)  # Running in debug mode!


# ==============================================================================
# TRICKY TEST CASE 12: Information Disclosure via Exceptions
# ==============================================================================

@app.route('/user/<int:user_id>')
def get_user(user_id):
    try:
        result = execute_query(f"SELECT * FROM users WHERE id = {user_id}")
        return str(result)
    except Exception as e:
        # Exposes internal info
        return f"Error: {str(e)}\nQuery: SELECT * FROM users WHERE id = {user_id}"


# ==============================================================================
# TRICKY TEST CASE 13: Subprocess with shell=True
# ==============================================================================

def run_script(script_name, args):
    # shell=True allows command injection
    cmd = f"python {script_name} {args}"
    subprocess.call(cmd, shell=True)  # Vulnerable!

@app.route('/run')
def run():
    script = request.args.get('script')
    arguments = request.args.get('args', '')
    run_script(script, arguments)
    return "Executed"
