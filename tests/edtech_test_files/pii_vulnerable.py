import logging
import traceback
from flask import Flask, request

app = Flask(__name__)

# Vulnerability 1: Hardcoded PII
student_name = "John Doe"
cnic = "12345-6789012-3"
dob = "2005-01-01"

def log_student_data(student_id):
    # Vulnerability 2: PII Leakage in Logs
    logging.info(f"Processing data for student: {student_name}, CNIC: {cnic}")
    print(f"Debug: Student address is 123 Main St")
    
    try:
        process_data(student_id)
    except Exception:
        # Vulnerability 3: PII in Stack Trace (if variables are in locals)
        traceback.print_exc()

@app.route('/student/<student_id>') # Vulnerability 4: Unsafe Identifier Exposure
def get_student(student_id):
    return f"Student ID: {student_id}"

@app.route('/register', methods=['GET', 'POST'])
def register():
    # Vulnerability 5: Sensitive Autocomplete Enabled
    return """
    <form action="/register" method="post">
        <input type="text" name="cnic" autocomplete="on">
        <input type="submit" value="Register">
    </form>
    """

def process_data(id):
    pass
