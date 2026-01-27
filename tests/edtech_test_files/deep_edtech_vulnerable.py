# Python: Insecure LTI Launch
from flask import request

def lti_launch():
    # Vulnerability: Handling LTI launch without verifying OAuth signature
    # A real LTI launch MUST verify oauth_consumer_key and oauth_signature
    consumer_key = request.form.get('oauth_consumer_key')
    user_id = request.form.get('user_id')
    
    # Missing verification logic...
    login_user(user_id)

# JavaScript: Proctoring Evasion (Client-Side)
# This would typically be in a .js file, but putting it here for regex testing in Python context too
"""
function checkProctoring() {
    // Vulnerability: Checking if document is hidden (Proctoring Evasion)
    if (document.hidden) {
        alert("Please stay on the tab!");
    }
    
    // Vulnerability: Checking for WebDriver (Automation Detection Evasion)
    if (navigator.webdriver) {
        console.log("Bot detected");
    }
}
"""
