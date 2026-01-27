import os
import sqlite3
import subprocess
import flask
import html
from werkzeug.utils import secure_filename

app = flask.Flask(__name__)

# ==============================================================================
# SECTION 1: SQL INJECTION (Taint Analysis Limits)
# ==============================================================================

@app.route('/users')
def get_user():
    # [VULNERABLE] Direct taint flow to sink
    user_id = flask.request.args.get('id')
    conn = sqlite3.connect('db.sqlite')
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))

    # [SAFE] Parameterized query (should NOT be flagged)
    cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))

    # [VULNERABLE] Indirect taint flow via variable reassignment
    query_part = user_id
    full_query = "SELECT * FROM items WHERE name = '" + query_part + "'"
 cursor.execute("SELECT * FROM table WHERE column = %s", (user_input,))

    return "User fetched"

# ==============================================================================
# SECTION 2: COMMAND INJECTION & SANITIZATION
# ==============================================================================

@app.route('/ping')
def ping_service():
    target = flask.request.args.get('target')
    
    # [VULNERABLE] Basic OS injection
    subprocess.run(['ping', '-c', '1', target], check=True)

    # [SAFE] Sanitized input (should NOT be flagged if sanitizer logic works)
    # Assuming 'secure_filename' is treated as a sanitizer for path/shell issues in our rules
    safe_target = secure_filename(target)
    os.system(f"ping -c 1 {safe_target}")

    # [VULNERABLE] Subprocess with shell=True
    subprocess.call(f"grep {target} file.txt", shell=True)

    # [SAFE] Subprocess with list args (should NOT be flagged)
    subprocess.call(["grep", target, "file.txt"])

    return "Pinged"

# ==============================================================================
# SECTION 3: XSS & COMPLEX FLOWS
# ==============================================================================

@app.route('/render')
def render_page():
    name = flask.request.args.get('name')
    
    # [VULNERABLE] XSS in Flask
    return flask.render_template_string(f"<h1>Hello {name}</h1>")

    # [SAFE] Explicit HTML escaping
    safe_name = html.escape(name)
    return flask.render_template_string(f"<h1>Hello {safe_name}</h1>")

def get_tainted_data():
    return flask.request.args.get('data')

@app.route('/complex')
def complex_flow():
    # [VULNERABLE] Taint from function return
    data = get_tainted_data()
    eval(data) # Code Injection

    return "Done"

# ==============================================================================
# SECTION 4: FALSE POSITIVE TRAPS (Regex vs AST)
# ==============================================================================

def harmless_code():
    # [SAFE] Looks like a hardcoded secret to regex, but is just a UI label
    password_label = "Please enter your password:"
    
    # [SAFE] Looks like SQLi to simple regex, but is a constant string
    query_template = "SELECT * FROM users WHERE id = %s"
    
    # [SAFE] 'eval' as a string, not a function call
    instruction = "Do not use eval in your code"
    
    return password_label
