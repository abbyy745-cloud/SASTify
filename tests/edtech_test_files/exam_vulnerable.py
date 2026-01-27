from flask import Flask, request

app = Flask(__name__)

# Vulnerability 1: Unprotected Exam Endpoints
@app.route('/api/start_exam')
def start_exam():
    return "Exam Started"

@app.route('/api/stop_exam')
def stop_exam():
    return "Exam Stopped"

@app.route('/submit_grade', methods=['POST'])
def submit_grade():
    # Vulnerability 2: Submission Tampering (Client-controlled marks)
    marks = request.args.get('marks')
    score = request.form.get('score')
    
    # Vulnerability 3: Unsafe File Upload (Cheating Vector)
    safe = False 
    
    return f"Grade submitted: {marks}"

def client_side_logic():
    # Vulnerability 4: Client-side Timer
    return """
    <script>
        window.setTimeout(function() {
            alert("Exam over!");
        }, 3600000);
        
        window.setInterval(function() {
            console.log("Time remaining...");
        }, 1000);
    </script>
    """

def render_question(question_text):
    # Vulnerability 5: Cheating Vector (HTML Injection)
    return f"""
    <div dangerouslySetInnerHTML={{__html: '{question_text}'}}></div>
    """
