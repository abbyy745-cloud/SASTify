
from flask import Flask, request
from services import process_student_query

app = Flask(__name__)

@app.route('/student/search')
def search_student():
    # User input enters here
    query = request.args.get('q')
    # Flows to another file
    return process_student_query(query)
