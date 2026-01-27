from fastapi import FastAPI, HTTPException, Request, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from pydantic import BaseModel
from typing import List, Dict, Any, Optional
import os
import sys
import time
import json
from datetime import datetime
from dotenv import load_dotenv

# Add current directory to path to allow imports when running from root
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

# Import existing logic
from enhanced_rule_engine import EnhancedRuleEngine
from deepseek_api import SecureDeepSeekAPI
from false_positive_detector import FalsePositiveDetector

# Load environment variables
load_dotenv()

# Initialize Limiter
limiter = Limiter(key_func=get_remote_address)

app = FastAPI(
    title="SASTify API",
    description="AI-powered static application security testing API",
    version="1.0.0"
)

# Setup CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # In production, replace with specific origins
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Setup Rate Limiter
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# Initialize components
rule_engine = EnhancedRuleEngine()
deepseek_api = SecureDeepSeekAPI(api_key=os.getenv('DEEPSEEK_API_KEY'))
fp_detector = FalsePositiveDetector()

# Storage (In-memory for now, should be DB in production)
scan_results: Dict[str, Any] = {}
user_analytics: Dict[str, Any] = {}

# Pydantic Models
class ScanRequest(BaseModel):
    code: str
    language: str = 'javascript'
    filename: Optional[str] = None
    scan_id: Optional[str] = None
    user_id: str = 'anonymous'

class AnalyzeIssueRequest(BaseModel):
    scan_id: str
    issue_index: int
    code_snippet: str
    user_id: str = 'anonymous'

class FalsePositiveReportRequest(BaseModel):
    scan_id: str
    issue_index: int
    comment: str = ''
    user_id: str = 'anonymous'

class ProjectScanRequest(BaseModel):
    project_path: str
    user_id: str = 'anonymous'

class BatchFileItem(BaseModel):
    code: str
    language: str
    filename: str

class BatchScanRequest(BaseModel):
    files: List[BatchFileItem]
    user_id: str = 'anonymous'

# Import cross-file analysis engine
try:
    from cross_file_taint import analyze_project as cross_file_analyze
    CROSS_FILE_AVAILABLE = True
except ImportError:
    CROSS_FILE_AVAILABLE = False
    print("Warning: Cross-file analysis not available")

@app.post("/api/scan-project")
@limiter.limit("5/minute")
async def scan_project_endpoint(request: Request, data: ProjectScanRequest):
    """
    Advanced project-wide security analysis.
    
    Features:
    - Cross-file taint tracking
    - Inter-procedural analysis
    - Call graph construction
    - EdTech-specific vulnerability detection
    """
    try:
        if not os.path.exists(data.project_path):
            raise HTTPException(status_code=404, detail="Project path not found")
        
        if not CROSS_FILE_AVAILABLE:
            raise HTTPException(
                status_code=503, 
                detail="Cross-file analysis module not available"
            )
        
        print(f"Starting cross-file analysis for: {data.project_path}")
        start_time = time.time()
        
        # Run the cross-file analysis
        report = cross_file_analyze(data.project_path)
        
        scan_time = time.time() - start_time
        
        # Generate scan ID
        project_scan_id = f"project_{int(time.time())}"
        
        # Store results
        scan_results[project_scan_id] = {
            'scan_id': project_scan_id,
            'timestamp': datetime.now().isoformat(),
            'project_path': data.project_path,
            'issues': report['vulnerabilities'],
            'report': report
        }
        
        # Update user analytics
        if data.user_id not in user_analytics:
            user_analytics[data.user_id] = {
                'total_scans': 0,
                'total_issues_found': 0,
                'false_positive_history': {},
                'scan_history': []
            }
        
        user_analytics[data.user_id]['total_scans'] += 1
        user_analytics[data.user_id]['total_issues_found'] += report['total_vulnerabilities']
        user_analytics[data.user_id]['scan_history'].append(project_scan_id)
        
        return {
            'success': True,
            'scan_id': project_scan_id,
            'summary': {
                'files_analyzed': report['project_info']['files_analyzed'],
                'functions_analyzed': report['project_info']['functions_analyzed'],
                'total_vulnerabilities': report['total_vulnerabilities'],
                'by_severity': report['by_severity'],
                'by_type': report['by_type'],
                'edtech_specific': report['edtech_specific'],
                'cross_file_count': report['cross_file_count'],
                'scan_time': f"{scan_time:.2f}s"
            },
            'call_graph': {
                'nodes': report['project_info']['call_graph_nodes'],
                'edges': report['project_info']['call_graph_edges']
            },
            'vulnerabilities': report['vulnerabilities']
        }
        
    except HTTPException:
        raise
    except Exception as e:
        import traceback
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/scan-batch")
@limiter.limit("30/minute")
async def scan_batch(request: Request, data: BatchScanRequest):
    """Batch scan multiple files in a single request to avoid rate limiting"""
    try:
        batch_scan_id = f"batch_{int(time.time())}"
        start_time = time.time()
        
        print(f"Starting batch scan {batch_scan_id} for {len(data.files)} files")
        
        all_issues = []
        total_issues = 0
        total_filtered = 0
        total_likely_fps = 0
        
        user_history = user_analytics.get(data.user_id, {}).get('false_positive_history', {})
        
        for file_item in data.files:
            try:
                # Scan each file
                rule_issues = rule_engine.scan_with_ast_analysis(
                    file_item.code, 
                    file_item.language, 
                    file_item.filename
                )
                
                # Apply false positive detection and add metadata
                for issue in rule_issues:
                    is_likely_fp = fp_detector.is_likely_false_positive(issue, user_history, file_item.filename)
                    issue['is_likely_false_positive'] = is_likely_fp
                    issue['file'] = file_item.filename
                    issue['language'] = file_item.language  # Store language per issue for batch scans
                    all_issues.append(issue)
                
                total_issues += len(rule_issues)
                total_filtered += len(rule_issues)
                total_likely_fps += len([i for i in rule_issues if i.get('is_likely_false_positive', False)])
                
            except Exception as file_error:
                print(f"Error scanning file {file_item.filename}: {file_error}")
                continue
        
        scan_time = time.time() - start_time
        
        # Store batch results
        scan_results[batch_scan_id] = {
            'scan_id': batch_scan_id,
            'timestamp': datetime.now().isoformat(),
            'files_scanned': len(data.files),
            'issues': all_issues,
            'scan_time': scan_time
        }
        
        # Update user analytics
        if data.user_id not in user_analytics:
            user_analytics[data.user_id] = {
                'total_scans': 0,
                'total_issues_found': 0,
                'false_positive_history': {},
                'scan_history': []
            }
        
        user_analytics[data.user_id]['total_scans'] += 1
        user_analytics[data.user_id]['total_issues_found'] += len(all_issues)
        user_analytics[data.user_id]['scan_history'].append(batch_scan_id)
        
        return {
            'success': True,
            'scan_id': batch_scan_id,
            'issues': all_issues,
            'metrics': {
                'files_scanned': len(data.files),
                'total_issues': total_issues,
                'filtered_issues': total_filtered,
                'likely_false_positives': total_likely_fps,
                'scan_time': f"{scan_time:.2f}s"
            }
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/scan")
@limiter.limit("10/minute")
async def scan_code(request: Request, data: ScanRequest):
    """Main scanning endpoint with enhanced security analysis"""
    try:
        scan_id = data.scan_id or f"scan_{int(time.time())}"
        
        print(f"Starting enhanced scan {scan_id} for {data.language} (file: {data.filename})")
        
        # Step 1: Enhanced rule-based scanning
        start_time = time.time()
        rule_issues = rule_engine.scan_with_ast_analysis(data.code, data.language, data.filename)
        rule_scan_time = time.time() - start_time
        
        # Step 2: False positive detection
        user_history = user_analytics.get(data.user_id, {}).get('false_positive_history', {})
        filtered_issues = []
        
        for issue in rule_issues:
            is_likely_fp = fp_detector.is_likely_false_positive(issue, user_history, data.filename)
            if is_likely_fp:
                issue['is_likely_false_positive'] = True
            else:
                issue['is_likely_false_positive'] = False
            
            filtered_issues.append(issue)
        
        # Step 3: Prepare results
        scan_data = {
            'scan_id': scan_id,
            'timestamp': datetime.now().isoformat(),
            'language': data.language,
            'code_length': len(data.code),
            'total_issues_found': len(rule_issues),
            'issues_after_fp_filter': len([i for i in filtered_issues if not i['is_likely_false_positive']]),
            'scan_time': rule_scan_time,
            'issues': filtered_issues,
            'filtered_issues': [i for i in filtered_issues if not i['is_likely_false_positive']],
            'code_lines': data.code.split('\n')
        }
        
        scan_results[scan_id] = scan_data
        
        # Update user analytics
        if data.user_id not in user_analytics:
            user_analytics[data.user_id] = {
                'total_scans': 0,
                'total_issues_found': 0,
                'false_positive_history': {},
                'scan_history': []
            }
        
        user_analytics[data.user_id]['total_scans'] += 1
        user_analytics[data.user_id]['total_issues_found'] += len(filtered_issues)
        user_analytics[data.user_id]['scan_history'].append(scan_id)
        
        return {
            'success': True,
            'scan_id': scan_id,
            'issues': filtered_issues,
            'metrics': {
                'total_issues': len(rule_issues),
                'filtered_issues': len(filtered_issues),
                'likely_false_positives': len(rule_issues) - len(filtered_issues),
                'scan_time': f"{rule_scan_time:.2f}s"
            }
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/analyze-issue")
@limiter.limit("5/minute")
async def analyze_specific_issue(request: Request, data: AnalyzeIssueRequest):
    """Analyze a specific issue with AI"""
    try:
        if data.scan_id not in scan_results:
            raise HTTPException(status_code=404, detail='Scan not found')
        
        scan_data = scan_results[data.scan_id]
        issues = scan_data['issues']
        
        if data.issue_index >= len(issues):
            raise HTTPException(status_code=404, detail='Issue not found')
        
        issue = issues[data.issue_index]
        
        # Get language - from issue for batch scans, from scan_data for single file scans
        language = issue.get('language') or scan_data.get('language', 'python')
        
        # Use AI to analyze the specific issue
        ai_analysis = deepseek_api.analyze_vulnerability(
            code_snippet=data.code_snippet,
            language=language,
            vulnerability_type=issue['type'],
            context=issue
        )
        
        # Store AI analysis
        if 'ai_analysis' not in scan_data:
            scan_data['ai_analysis'] = {}
        scan_data['ai_analysis'][str(data.issue_index)] = ai_analysis
        
        # Return only the safe parts of AI analysis
        # Use false_positive_reason as explanation if explanation is empty (for false positives)
        explanation = ai_analysis.get('explanation', '')
        if not explanation:
            explanation = ai_analysis.get('false_positive_reason', 'No explanation provided')
        
        safe_response = {
            'suggested_fix': ai_analysis.get('suggested_fix', ''),
            'explanation': explanation,
            'confidence': ai_analysis.get('confidence', 0),
            'risk_level': ai_analysis.get('risk_level', 'Medium'),
            'is_confirmed': ai_analysis.get('is_confirmed_vulnerability', False),
            'false_positive_reason': ai_analysis.get('false_positive_reason', '')
        }
        
        return {
            'success': True,
            'ai_analysis': safe_response,
            'original_issue': {
                'type': issue['type'],
                'line': issue['line'],
                'severity': issue['severity']
            }
        }
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/report-false-positive")
async def report_false_positive(data: FalsePositiveReportRequest):
    """Allow users to report false positives"""
    try:
        if data.scan_id not in scan_results:
            raise HTTPException(status_code=404, detail='Scan not found')
        
        scan_data = scan_results[data.scan_id]
        issues = scan_data['issues']
        
        if data.issue_index >= len(issues):
            raise HTTPException(status_code=404, detail='Issue not found')
        
        issue = issues[data.issue_index]
        
        # Record false positive feedback
        fp_detector.record_feedback(issue, True, data.comment)
        
        # Update user analytics
        if data.user_id not in user_analytics:
            user_analytics[data.user_id] = {'false_positive_history': {}}
        
        fp_history = user_analytics[data.user_id].get('false_positive_history', {})
        issue_type = issue['type']
        fp_history[issue_type] = fp_history.get(issue_type, 0) + 1
        user_analytics[data.user_id]['false_positive_history'] = fp_history
        
        return {'success': True, 'message': 'False positive reported'}
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/analytics")
async def get_analytics(user_id: str = 'anonymous'):
    """Get comprehensive analytics"""
    user_stats = user_analytics.get(user_id, {})
    fp_stats = fp_detector.get_false_positive_stats()
    
    analytics = {
        'user_stats': user_stats,
        'false_positive_stats': fp_stats,
        'total_scans_in_system': len(scan_results),
        'most_common_vulnerabilities': get_most_common_vulnerabilities()
    }
    
    return analytics

@app.get("/api/scan-results/{scan_id}")
async def get_scan_results(scan_id: str):
    """Get detailed results for a specific scan"""
    if scan_id not in scan_results:
        raise HTTPException(status_code=404, detail='Scan not found')
    
    return scan_results[scan_id]

@app.get("/api/health")
async def health_check():
    """System health endpoint"""
    return {
        'status': 'healthy',
        'timestamp': datetime.now().isoformat(),
        'scans_processed': len(scan_results),
        'users_active': len(user_analytics)
    }

def get_most_common_vulnerabilities():
    """Calculate most common vulnerability types across all scans"""
    vuln_counts = {}
    
    for scan_id, scan_data in scan_results.items():
        for issue in scan_data.get('issues', []):
            vuln_type = issue['type']
            vuln_counts[vuln_type] = vuln_counts.get(vuln_type, 0) + 1
    
    return sorted([{'type': k, 'count': v} for k, v in vuln_counts.items()], 
                  key=lambda x: x['count'], reverse=True)[:10]

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
