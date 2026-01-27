# PYTHON VULNERABLE TEST FILE


def bad_eval(user_input):
    return eval(user_input)


def bad_exec(code):
    exec(code)

# 3. SQL Injection
import sqlite3
def login(username):
    conn = sqlite3.connect("users.db")
    query = "SELECT * FROM users WHERE username = '" + username + "';"
    return conn.execute(query)

# 4. Hardcoded password
PASSWORD = "mySuperSecretPassword123"

# 5. Hardcoded API key
API_KEY = "sk-193847123987123987918239"

# 6. Unsafe yaml load
import yaml
def unsafe_yaml(data):
    return yaml.load(data)   # should use safe_load

# 7. Path Traversal
import os
def read_file(filename):
    return open("/var/app/data/" + filename).read()

# 8. Command injection (os.system)
import os
def run_ping(ip):
    os.system("ping " + ip)

# 9. Command injection (subprocess)
import subprocess
def run_cmd(cmd):
    subprocess.Popen(cmd, shell=True)

# 10. Weak hashing
import hashlib
def weak_hash(password):
    return hashlib.md5(password.encode()).hexdigest()

# 11. Insecure Random for security tokens
import random
def insecure_token():
    return random.random()

# 12. Flask Debug Mode
from flask import Flask
app = Flask(__name__)
app.config["DEBUG"] = True  # Security issue

@app.route("/")
def index():
    return "Hello"
