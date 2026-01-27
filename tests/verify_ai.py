import requests
import time
import json

API_URL = "http://127.0.0.1:8000"

def verify_ai_integration():
    print("1. Sending vulnerable code for scanning...")
    
    # Vulnerable code snippet (Dangerous Eval)
    code = """
    def bad_eval(user_input):
        return eval(user_input)
    """
    
    scan_payload = {
        "code": code,
        "language": "python",
        "user_id": "test_verifier"
    }
    
    try:
        # 1. Scan
        scan_response = requests.post(f"{API_URL}/api/scan", json=scan_payload)
        scan_data = scan_response.json()
        
        if not scan_data.get('success'):
            print("[X] Scan failed:", scan_data.get('error'))
            return
            
        scan_id = scan_data['scan_id']
        issues = scan_data['issues']
        
        if not issues:
            print("[X] No issues found to analyze.")
            return
            
        print(f"[V] Scan successful. Scan ID: {scan_id}")
        print(f"[V] Found {len(issues)} issues. Analyzing the first one...")
        
        # 2. Analyze Issue with AI
        issue_index = 0
        analyze_payload = {
            "scan_id": scan_id,
            "issue_index": issue_index,
            "code_snippet": code,
            "user_id": "test_verifier"
        }
        
        print("2. Requesting AI analysis (this calls DeepSeek API)...")
        ai_response = requests.post(f"{API_URL}/api/analyze-issue", json=analyze_payload)
        ai_data = ai_response.json()
        
        if ai_data.get('success'):
            print("\n[V] AI API IS WORKING!")
            print("-" * 50)
            analysis = ai_data.get('ai_analysis', {})
            print(f"Explanation: {analysis.get('explanation')}")
            print(f"Risk Level: {analysis.get('risk_level')}")
            print(f"Suggested Fix: {analysis.get('suggested_fix')}")
            print("-" * 50)
        else:
            print("\n[X] AI Analysis Failed:")
            print(ai_data.get('error'))
            
    except Exception as e:
        print(f"\n[X] Error during verification: {str(e)}")

if __name__ == "__main__":
    verify_ai_integration()
