"""Quick test for EdTech rules"""
from edtech_rules import EdTechRuleEngine

e = EdTechRuleEngine()
stats = e.get_statistics()

print("=" * 50)
print("EdTech Rules Statistics")
print("=" * 50)
print(f"Total rules: {stats['total_rules']}")
print(f"FERPA rules: {stats['ferpa_rules']}")
print(f"COPPA rules: {stats['coppa_rules']}")
print("")
print("By Category:")
for cat, count in stats['by_category'].items():
    print(f"  {cat}: {count}")
print("")
print("By Severity:")
for sev, count in stats['by_severity'].items():
    print(f"  {sev}: {count}")
print("")

# Test scanning
test_code = '''
def search_student():
    query = request.args.get('q')
    print(f"Searching for student: {query}, CNIC: {student.cnic}")
    cursor.execute(f"SELECT * FROM students WHERE name = '{query}'")
    return cursor.fetchall()
'''

issues = e.scan_code(test_code, 'python', 'test.py')
print(f"Found {len(issues)} issues in test code:")
for issue in issues:
    print(f"  [{issue['severity']}] {issue['type']} on line {issue['line']}")
