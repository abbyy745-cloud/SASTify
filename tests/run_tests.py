import requests
import os
import time

API_URL = "http://127.0.0.1:8000/api/scan"   # change port if FastAPI uses 8000
USER_ID = "test_user_001"

# -----------------------------------------------------------------
# Utility: Read file contents
# -----------------------------------------------------------------
def read_file(path):
    with open(path, "r", encoding="utf-8") as f:
        return f.read()

# -----------------------------------------------------------------
# Utility: Split file into smaller chunks (per function)
# -----------------------------------------------------------------
def split_python_code(content):
    chunks = []
    current = []
    for line in content.split("\n"):
        if line.startswith("def ") or line.startswith("class "):
            if current:
                chunks.append("\n".join(current))
            current = [line]
        else:
            current.append(line)
    if current:
        chunks.append("\n".join(current))
    return chunks

def split_js_code(content):
    chunks = []
    current = []
    for line in content.split("\n"):
        if line.strip().startswith("function "):
            if current:
                chunks.append("\n".join(current))
            current = [line]
        else:
            current.append(line)
    if current:
        chunks.append("\n".join(current))
    return chunks

# -----------------------------------------------------------------
# Send snippet to backend
# -----------------------------------------------------------------
def send_for_scan(code, language):
    payload = {
        "code": code,
        "language": language,
        "user_id": USER_ID
    }

    try:
        response = requests.post(API_URL, json=payload, timeout=20)
        return response.json()
    except Exception as e:
        return {"error": str(e)}

# -----------------------------------------------------------------
# Print results cleanly
# -----------------------------------------------------------------
def print_result(snippet_id, result):
    print("=" * 60)
    print(f"SNIPPET #{snippet_id} — RESULT")
    print("=" * 60)

    if "error" in result:
        print("❌ Request Failed:", result["error"])
        return

    metrics = result.get("metrics", {})
    issues = result.get("issues", [])

    print(f"✔ Total Issues Found: {metrics.get('total_issues', 0)}")
    print(f"✔ After Filtering FP: {metrics.get('filtered_issues', 0)}")

    for i, issue in enumerate(issues):
        print(f"\n🔺 Issue #{i+1}")
        print(f"Type: {issue.get('type')}")
        print(f"Line: {issue.get('line')}")
        print(f"Severity: {issue.get('severity')}")
        print(f"Likely FP: {issue.get('is_likely_false_positive', False)}")

    print("\n")


# -----------------------------------------------------------------
# MAIN EXECUTION
# -----------------------------------------------------------------
def run_all_tests():

    # ---------------- Python ----------------
    py_path = "tests/python/test_samples.py"
    print("\n===== Running Python Tests =====\n")
    py_content = read_file(py_path)
    py_snippets = split_python_code(py_content)

    for idx, code in enumerate(py_snippets, 1):
        print(f"\n>>> Testing Python Snippet #{idx}")
        result = send_for_scan(code, "python")
        print_result(idx, result)
        time.sleep(0.5)



    # ---------------- JavaScript ----------------
    js_path = "tests/javascript/test_samples.js"
    print("\n===== Running JavaScript Tests =====\n")
    js_content = read_file(js_path)
    js_snippets = split_js_code(js_content)

    for idx, code in enumerate(js_snippets, 1):
        print(f"\n>>> Testing JavaScript Snippet #{idx}")
        result = send_for_scan(code, "javascript")
        print_result(idx, result)
        time.sleep(0.5)


if __name__ == "__main__":
    run_all_tests()
