import sys
import os
sys.path.append(os.path.join(os.path.dirname(__file__), '..'))

from Backend.advanced_analysis import analyze_project

def test_analysis():
    project_path = os.path.join(os.path.dirname(__file__), '..', 'Backend')
    print(f"Scanning {project_path}...")
    
    results = analyze_project(project_path)
    
    print("Scan complete.")
    print(f"Files scanned: {results['metrics']['files_scanned']}")
    print(f"Issues found: {results['metrics']['total_issues']}")
    
    for issue in results['issues']:
        print(f"[{issue['type']}] {issue['file']}:{issue['line']} - {issue['description']}")

if __name__ == "__main__":
    test_analysis()
