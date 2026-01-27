import logging

def safe_logging():
    # These look like PII but are just strings
    logging.info("Student ID: 12345") 
    print("The variable name is student_id")
    
    # This looks like a route but has no decorator
    def start_exam():
        pass

    # This looks like an AI key but is a placeholder
    openai_key = "placeholder_key_for_testing"
    
    # Safe usage of variables
    student_id = "123" # Source
    # But not used in sink
    x = student_id
