import openai
from flask import Flask, request

app = Flask(__name__)

# Vulnerability 1: Hardcoded AI Keys
openai.api_key = "sk-1234567890abcdef1234567890abcdef"
deepseek_key = "sk-deepseek-12345"

@app.route('/api/v1/llm/generate', methods=['POST']) # Vulnerability 2: Exposed Model Endpoint
def generate_text():
    user_input = request.json.get('prompt')
    
    # Vulnerability 3: Prompt Injection (Concatenation)
    prompt = f"Translate the following to French: {user_input}"
    
    # Vulnerability 3: Prompt Injection (Concatenation - Variant)
    prompt2 = "Summarize this: " + user_input
    
    response = openai.Completion.create(
        engine="text-davinci-003",
        prompt=prompt,
        max_tokens=100
    )
    return response.choices[0].text

def grade_submission(user_input):
    # Vulnerability 4: AI Grading Security (Heuristic)
    # Using raw user input in grading logic without sanitization
    grading_prompt = f"Grade this student essay: {user_input}"
    return openai.Completion.create(prompt=grading_prompt)

def safe_grading(user_input):
    # Safe version (should not trigger if we had advanced taint tracking, but regex might still catch it)
    # Ideally, we want to see if the rule engine distinguishes this.
    # For now, our regex is simple: def grade_submission.*user_input
    pass
