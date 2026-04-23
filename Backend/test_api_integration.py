"""Quick integration test for SASTify API v2.0"""
import requests
import json

BASE = "http://127.0.0.1:8000"

def test():
    # 1. Health check
    r = requests.get(f"{BASE}/api/health")
    health = r.json()
    print("=== Health Check ===")
    print(f"  status: {health['status']}")
    print(f"  database: {health['database']}")
    print(f"  db_path: {health['database_path']}")

    # 2. Scan as alice
    print("\n=== Scan as alice ===")
    r = requests.post(f"{BASE}/api/scan", json={
        "code": "eval(input())\nimport os\nos.system(user_input)",
        "language": "python",
        "filename": "test.py",
        "user_id": "alice"
    })
    alice_scan = r.json()
    alice_scan_id = alice_scan["scan_id"]
    print(f"  scan_id: {alice_scan_id}")
    print(f"  issues: {len(alice_scan['issues'])}")
    print(f"  user_id: {alice_scan['user_id']}")

    # 3. Scan as bob
    print("\n=== Scan as bob ===")
    r = requests.post(f"{BASE}/api/scan", json={
        "code": 'const q = req.query.input; db.query("SELECT * FROM users WHERE id=" + q);',
        "language": "javascript",
        "filename": "app.js",
        "user_id": "bob"
    })
    bob_scan = r.json()
    bob_scan_id = bob_scan["scan_id"]
    print(f"  scan_id: {bob_scan_id}")
    print(f"  issues: {len(bob_scan['issues'])}")

    # 4. Alice dashboard
    print("\n=== Alice Dashboard ===")
    r = requests.get(f"{BASE}/api/users/alice/dashboard")
    dash = r.json()
    print(f"  statistics: {dash['statistics']}")
    print(f"  recent_scans count: {len(dash['recent_scans']['scans'])}")

    # 5. Alice scans list
    print("\n=== Alice Scans List ===")
    r = requests.get(f"{BASE}/api/users/alice/scans")
    alice_scans = r.json()
    print(f"  pagination: {alice_scans['pagination']}")
    for s in alice_scans["scans"]:
        print(f"  scan: {s['scan_id']} user={s['user_id']}")

    # 6. Bob scans — should NOT contain alice's scans
    print("\n=== Bob Scans List ===")
    r = requests.get(f"{BASE}/api/users/bob/scans")
    bob_scans = r.json()
    print(f"  bob scan count: {bob_scans['pagination']['total']}")
    for s in bob_scans["scans"]:
        assert s["user_id"] == "bob", f"FAIL: bob got someone else's scan {s['user_id']}"
        print(f"  scan: {s['scan_id']} user={s['user_id']}")

    # 7. Ownership check — bob trying to access alice's scan
    print("\n=== Ownership Check (bob -> alice scan) ===")
    r = requests.get(f"{BASE}/api/users/bob/scans/{alice_scan_id}")
    print(f"  Status: {r.status_code} (expected 404)")
    assert r.status_code == 404, f"FAIL: expected 404, got {r.status_code}"

    # 8. Alice can access her own scan
    print("\n=== Alice Accesses Own Scan ===")
    r = requests.get(f"{BASE}/api/users/alice/scans/{alice_scan_id}")
    print(f"  Status: {r.status_code} (expected 200)")
    assert r.status_code == 200, f"FAIL: expected 200, got {r.status_code}"
    own_scan = r.json()
    print(f"  scan vulnerabilities: {len(own_scan['scan']['vulnerabilities'])}")

    # 9. User statistics
    print("\n=== Alice Statistics ===")
    r = requests.get(f"{BASE}/api/users/alice/statistics")
    stats = r.json()
    print(f"  {stats['statistics']}")

    # 10. User trends
    print("\n=== Alice Trends ===")
    r = requests.get(f"{BASE}/api/users/alice/trends?days=7")
    trends = r.json()
    print(f"  trends entries: {len(trends['trends']['trends'])}")

    # 11. Top vulnerabilities
    print("\n=== Alice Top Vulns ===")
    r = requests.get(f"{BASE}/api/users/alice/top-vulnerabilities")
    top = r.json()
    print(f"  top vuln types: {len(top['top_vulnerabilities'])}")

    # 12. Backward-compat analytics
    print("\n=== Analytics (backward compat) ===")
    r = requests.get(f"{BASE}/api/analytics?user_id=alice")
    analytics = r.json()
    print(f"  total_scans: {analytics['user_stats']['total_scans']}")
    print(f"  scan_history: {len(analytics['user_stats']['scan_history'])} scans")

    # 13. Public scan-results endpoint
    print("\n=== Public scan-results ===")
    r = requests.get(f"{BASE}/api/scan-results/{alice_scan_id}")
    print(f"  Status: {r.status_code}")
    assert r.status_code == 200

    print("\n" + "=" * 50)
    print("ALL TESTS PASSED!")
    print("=" * 50)

if __name__ == "__main__":
    test()
