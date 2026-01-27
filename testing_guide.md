# SAST Tool Testing Guide

This guide will help you verify the functionality of your SAST tool using the provided demo files.

## 1. Setup
Ensure your VS Code extension is running.
1.  Open the project in VS Code.
2.  Press `F5` to launch the Extension Development Host (if debugging) or ensure the extension is installed.

## 2. Testing Python Analysis
1.  Open the file `tests/demo_vulnerable.py`.
2.  Trigger the scan (e.g., run the "Analyze File" command from the Command Palette or click the "Scan" button in your extension UI).
3.  **Verify Results**: You should see the following issues reported:
    *   **High/Critical**: SQL Injection (`cursor.execute`)
    *   **High**: Command Injection (`os.system`)
    *   **High**: SSRF (`requests.get`)
    *   **Critical**: Weak JWT Algorithm (`jwt.encode`)
    *   **Medium**: Debug Mode Enabled (`DEBUG = True`)
    *   **High**: Hardcoded Secret (`api_key = ...`)
    *   **High**: PII Leakage (`logging.info`)
    *   **Medium**: Insecure LTI Launch (`oauth_consumer_key`)
    *   **High**: AI Prompt Injection (`prompt = ...`)

## 3. Testing JavaScript/Frontend Analysis
1.  Open the file `tests/demo_vulnerable.js`.
2.  Trigger the scan.
3.  **Verify Results**: You should see the following issues reported:
    *   **High**: SQL Injection (`db.execute`)
    *   **High**: XSS (`innerHTML`)
    *   **High**: SSRF (`axios.get`)
    *   **High**: Hardcoded Secret (`AKIA...`)
    *   **Medium**: Proctoring Evasion (`document.hidden`)
    *   **High**: PII Leakage (`console.log`)

## 4. Testing Frontend Frameworks (React/Vue/Angular)
To test specific frontend framework capabilities, open the following files individually and run the scan:

*   **React**: `tests/frontend_test_files/react_vulnerable.jsx`
    *   Expect: XSS (`dangerouslySetInnerHTML`), Prop Drilling Risk.
*   **Vue**: `tests/frontend_test_files/vue_vulnerable.vue`
    *   Expect: XSS (`v-html`).
*   **Angular**: `tests/frontend_test_files/angular_vulnerable.html`
    *   Expect: XSS (`[innerHTML]`).
