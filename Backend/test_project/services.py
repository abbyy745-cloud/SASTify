
import sqlite3

def process_student_query(search_term):
    """This function receives tainted data from routes.py"""
    conn = sqlite3.connect('students.db')
    cursor = conn.cursor()
    
    # SQL INJECTION! The tainted data flows here from another file
    cursor.execute(f"SELECT * FROM students WHERE name LIKE '%{search_term}%'")
    
    return cursor.fetchall()

def grade_with_ai(student_answer, rubric):
    """EdTech AI grading - vulnerable to prompt injection"""
    import openai
    
    # PROMPT INJECTION! Student answer goes directly into prompt
    response = openai.ChatCompletion.create(
        model="gpt-4",
        messages=[
            {"role": "system", "content": f"Grade this answer using rubric: {rubric}"},
            {"role": "user", "content": student_answer}  # User-controlled!
        ]
    )
    return response
