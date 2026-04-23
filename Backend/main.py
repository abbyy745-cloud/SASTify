from fastapi import FastAPI, HTTPException, Request, Depends, Query
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
import hashlib
import uuid
from datetime import datetime
from dotenv import load_dotenv

# Add current directory to path to allow imports when running from root
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

# Import existing logic
from enhanced_rule_engine import EnhancedRuleEngine
from deepseek_api import SecureDeepSeekAPI
from false_positive_detector import FalsePositiveDetector
from database import get_database, ScanRecord, Database

# Load environment variables
load_dotenv()

# Initialize Limiter
limiter = Limiter(key_func=get_remote_address)

app = FastAPI(
    title="SASTify API",
    description="AI-powered static application security testing API",
    version="2.0.0"
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

# Initialize database (persistent storage - replaces in-memory dicts)
db = get_database()

# ==================== Pydantic Models ====================

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


# ==================== Helper Functions ====================

def _generate_scan_id(prefix: str = "scan") -> str:
    """Generate a unique scan ID"""
    return f"{prefix}_{int(time.time())}_{uuid.uuid4().hex[:8]}"


def _create_scan_record(
    scan_id: str, user_id: str, filename: str, language: str,
    issues: List[Dict], scan_type: str = 'file', code: str = ''
) -> ScanRecord:
    """Build a ScanRecord from scan results"""
    severity_counts = {'Critical': 0, 'High': 0, 'Medium': 0, 'Low': 0}
    for issue in issues:
        sev = issue.get('severity', 'Medium')
        if sev in severity_counts:
            severity_counts[sev] += 1

    return ScanRecord(
        scan_id=scan_id,
        user_id=user_id,
        filename=filename or 'unknown',
        language=language or 'unknown',
        total_vulnerabilities=len(issues),
        critical_count=severity_counts['Critical'],
        high_count=severity_counts['High'],
        medium_count=severity_counts['Medium'],
        low_count=severity_counts['Low'],
        scan_type=scan_type,
        created_at=datetime.utcnow().isoformat(),
        code_hash=hashlib.sha256(code.encode()).hexdigest() if code else ''
    )


# ==================== Import Cross-File Analysis ====================

try:
    from cross_file_taint import analyze_project as cross_file_analyze
    CROSS_FILE_AVAILABLE = True
except ImportError:
    CROSS_FILE_AVAILABLE = False
    print("Warning: Cross-file analysis not available")


# ==================== Scan Endpoints ====================

@app.post("/api/scan")
@limiter.limit("10/minute")
async def scan_code(request: Request, data: ScanRequest):
    """Main scanning endpoint with enhanced security analysis"""
    try:
        scan_id = data.scan_id or _generate_scan_id()

        print(f"Starting enhanced scan {scan_id} for {data.language} (file: {data.filename})")

        # Ensure user exists in DB
        db.ensure_user(data.user_id)

        # Step 1: Enhanced rule-based scanning
        start_time = time.time()
        rule_issues = rule_engine.scan_with_ast_analysis(data.code, data.language, data.filename)
        rule_scan_time = time.time() - start_time

        # Step 2: False positive detection
        # Load user's FP history from database
        user_fp_history = _get_user_fp_history(data.user_id)
        filtered_issues = []

        for issue in rule_issues:
            is_likely_fp = fp_detector.is_likely_false_positive(issue, user_fp_history, data.filename)
            issue['is_likely_false_positive'] = is_likely_fp
            filtered_issues.append(issue)

        # Step 3: Build scan record and persist to database
        scan_record = _create_scan_record(
            scan_id=scan_id,
            user_id=data.user_id,
            filename=data.filename,
            language=data.language,
            issues=filtered_issues,
            scan_type='file',
            code=data.code
        )

        raw_results = {
            'language': data.language,
            'code_length': len(data.code),
            'scan_time': rule_scan_time,
            'issues': filtered_issues,
            'code_lines': data.code.split('\n')
        }

        db.save_scan(scan_record, filtered_issues, raw_results)

        return {
            'success': True,
            'scan_id': scan_id,
            'user_id': data.user_id,
            'issues': filtered_issues,
            'metrics': {
                'total_issues': len(rule_issues),
                'filtered_issues': len(filtered_issues),
                'likely_false_positives': len([i for i in filtered_issues if i.get('is_likely_false_positive')]),
                'scan_time': f"{rule_scan_time:.2f}s"
            }
        }

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/scan-batch")
@limiter.limit("30/minute")
async def scan_batch(request: Request, data: BatchScanRequest):
    """Batch scan multiple files in a single request"""
    try:
        batch_scan_id = _generate_scan_id("batch")
        start_time = time.time()

        print(f"Starting batch scan {batch_scan_id} for {len(data.files)} files")

        # Ensure user exists
        db.ensure_user(data.user_id)

        all_issues = []
        total_issues = 0
        total_likely_fps = 0

        user_fp_history = _get_user_fp_history(data.user_id)

        for file_item in data.files:
            try:
                rule_issues = rule_engine.scan_with_ast_analysis(
                    file_item.code,
                    file_item.language,
                    file_item.filename
                )

                for issue in rule_issues:
                    is_likely_fp = fp_detector.is_likely_false_positive(issue, user_fp_history, file_item.filename)
                    issue['is_likely_false_positive'] = is_likely_fp
                    issue['file'] = file_item.filename
                    issue['language'] = file_item.language
                    all_issues.append(issue)

                total_issues += len(rule_issues)
                total_likely_fps += len([i for i in rule_issues if i.get('is_likely_false_positive', False)])

            except Exception as file_error:
                print(f"Error scanning file {file_item.filename}: {file_error}")
                continue

        scan_time = time.time() - start_time

        # Persist to database
        combined_code = "\n".join(f.code for f in data.files)
        scan_record = _create_scan_record(
            scan_id=batch_scan_id,
            user_id=data.user_id,
            filename=f"batch ({len(data.files)} files)",
            language="multi",
            issues=all_issues,
            scan_type='batch',
            code=combined_code
        )

        raw_results = {
            'files_scanned': len(data.files),
            'scan_time': scan_time,
            'issues': all_issues
        }

        db.save_scan(scan_record, all_issues, raw_results)

        return {
            'success': True,
            'scan_id': batch_scan_id,
            'user_id': data.user_id,
            'issues': all_issues,
            'metrics': {
                'files_scanned': len(data.files),
                'total_issues': total_issues,
                'filtered_issues': len(all_issues),
                'likely_false_positives': total_likely_fps,
                'scan_time': f"{scan_time:.2f}s"
            }
        }

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/scan-project")
@limiter.limit("5/minute")
async def scan_project_endpoint(request: Request, data: ProjectScanRequest):
    """Advanced project-wide security analysis with cross-file taint tracking"""
    try:
        if not os.path.exists(data.project_path):
            raise HTTPException(status_code=404, detail="Project path not found")

        if not CROSS_FILE_AVAILABLE:
            raise HTTPException(
                status_code=503,
                detail="Cross-file analysis module not available"
            )

        # Ensure user exists
        db.ensure_user(data.user_id)

        print(f"Starting cross-file analysis for: {data.project_path}")
        start_time = time.time()

        report = cross_file_analyze(data.project_path)
        scan_time = time.time() - start_time

        project_scan_id = _generate_scan_id("project")

        # Persist to database
        scan_record = _create_scan_record(
            scan_id=project_scan_id,
            user_id=data.user_id,
            filename=data.project_path,
            language="multi",
            issues=report.get('vulnerabilities', []),
            scan_type='project'
        )

        raw_results = {
            'project_path': data.project_path,
            'report': report,
            'scan_time': scan_time
        }

        db.save_scan(scan_record, report.get('vulnerabilities', []), raw_results)

        return {
            'success': True,
            'scan_id': project_scan_id,
            'user_id': data.user_id,
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


# ==================== Analysis & Feedback Endpoints ====================

@app.post("/api/analyze-issue")
@limiter.limit("5/minute")
async def analyze_specific_issue(request: Request, data: AnalyzeIssueRequest):
    """Analyze a specific issue with AI"""
    try:
        # Fetch scan from database
        scan_data = db.get_scan(data.scan_id)
        if not scan_data:
            raise HTTPException(status_code=404, detail='Scan not found')

        # Get full issues from raw_results
        raw = scan_data.get('raw_results')
        if isinstance(raw, str):
            try:
                raw = json.loads(raw)
            except (json.JSONDecodeError, TypeError):
                raw = {}

        issues = raw.get('issues', []) if raw else []

        # Fallback: use vulnerabilities from DB if raw_results has no issues
        if not issues:
            issues = scan_data.get('vulnerabilities', [])

        if data.issue_index >= len(issues):
            raise HTTPException(status_code=404, detail='Issue not found')

        issue = issues[data.issue_index]

        # Get language
        language = issue.get('language') or scan_data.get('language', 'python')

        # Use AI to analyze
        ai_analysis = deepseek_api.analyze_vulnerability(
            code_snippet=data.code_snippet,
            language=language,
            vulnerability_type=issue.get('type', 'unknown'),
            context=issue
        )

        # Store AI analysis in database
        db.update_scan_ai_analysis(data.scan_id, data.issue_index, json.dumps(ai_analysis))

        # Also update the specific vulnerability row if we can match it
        vulns = db.get_scan_vulnerabilities(data.scan_id)
        if data.issue_index < len(vulns):
            vuln_id = vulns[data.issue_index].get('id')
            if vuln_id:
                db.update_vulnerability_ai_analysis(vuln_id, json.dumps(ai_analysis))

        # Build safe response
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
                'type': issue.get('type', 'unknown'),
                'line': issue.get('line', 0),
                'severity': issue.get('severity', 'Medium')
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
        # Fetch scan from database
        scan_data = db.get_scan(data.scan_id)
        if not scan_data:
            raise HTTPException(status_code=404, detail='Scan not found')

        vulns = scan_data.get('vulnerabilities', [])
        if data.issue_index >= len(vulns):
            raise HTTPException(status_code=404, detail='Issue not found')

        issue = vulns[data.issue_index]

        # Record false positive feedback in detector
        fp_detector.record_feedback(issue, True, data.comment)

        # Also record in database
        vuln_id = issue.get('id')
        fingerprint = hashlib.sha256(
            f"{issue.get('vuln_type', '')}:{issue.get('line', 0)}:{issue.get('snippet', '')}".encode()
        ).hexdigest()

        db.record_false_positive(
            vuln_id=vuln_id,
            fingerprint=fingerprint,
            is_fp=True,
            comment=data.comment,
            user_id=data.user_id
        )

        return {'success': True, 'message': 'False positive reported and recorded'}

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ==================== Scan Results Endpoint (backward compatible) ====================

@app.get("/api/scan-results/{scan_id}")
async def get_scan_results(scan_id: str):
    """Get detailed results for a specific scan (public by scan_id)"""
    scan_data = db.get_scan(scan_id)
    if not scan_data:
        raise HTTPException(status_code=404, detail='Scan not found')

    # Parse raw_results if it's a JSON string
    if scan_data.get('raw_results') and isinstance(scan_data['raw_results'], str):
        try:
            scan_data['raw_results'] = json.loads(scan_data['raw_results'])
        except (json.JSONDecodeError, TypeError):
            pass

    return scan_data


# ==================== Analytics Endpoint (backward compatible) ====================

@app.get("/api/analytics")
async def get_analytics(user_id: str = 'anonymous'):
    """Get comprehensive analytics for a user"""
    stats = db.get_statistics(user_id)
    trends = db.get_vulnerability_trends(user_id, days=30)
    top_vulns = db.get_top_vulnerabilities(user_id, limit=10)
    fp_stats = fp_detector.get_false_positive_stats()

    # Get user's recent scan IDs for backward compatibility
    user_scans = db.get_user_scans(user_id, limit=50)
    scan_history = [s['scan_id'] for s in user_scans.get('scans', [])]

    return {
        'user_stats': {
            'total_scans': stats.get('total_scans', 0),
            'total_issues_found': stats.get('total_vulnerabilities', 0),
            'false_positive_history': {},  # Maintained for backward compat
            'scan_history': scan_history
        },
        'false_positive_stats': fp_stats,
        'total_scans_in_system': stats.get('total_scans', 0),
        'most_common_vulnerabilities': [
            {'type': v['vuln_type'], 'count': v['count']} for v in top_vulns
        ],
        'trends': trends
    }


# ==================== User-Scoped Dashboard Endpoints ====================

@app.get("/api/users/{user_id}/dashboard")
async def get_user_dashboard(user_id: str):
    """
    Get complete dashboard data for a user.
    Returns stats, trends, top vulnerabilities, and recent scans — 
    everything a web dashboard needs in a single call.
    """
    summary = db.get_user_summary(user_id)

    if not summary.get('user'):
        raise HTTPException(status_code=404, detail=f"User '{user_id}' not found")

    return {
        'success': True,
        'user_id': user_id,
        'user': summary['user'],
        'statistics': summary['statistics'],
        'trends': summary['trends'],
        'top_vulnerabilities': summary['top_vulnerabilities'],
        'recent_scans': summary['recent_scans']
    }


@app.get("/api/users/{user_id}/scans")
async def get_user_scans(
    user_id: str,
    page: int = Query(1, ge=1, description="Page number"),
    limit: int = Query(20, ge=1, le=100, description="Items per page")
):
    """List all scans for a user with pagination"""
    offset = (page - 1) * limit
    result = db.get_user_scans(user_id, limit=limit, offset=offset)

    scans = result.get('scans', [])
    total = result.get('total', 0)

    return {
        'success': True,
        'user_id': user_id,
        'scans': scans,
        'pagination': {
            'page': page,
            'limit': limit,
            'total': total,
            'total_pages': (total + limit - 1) // limit if total > 0 else 0
        }
    }


@app.get("/api/users/{user_id}/scans/{scan_id}")
async def get_user_scan(user_id: str, scan_id: str):
    """Get a specific scan with ownership check — only returns if it belongs to this user"""
    scan_data = db.get_user_scan(user_id, scan_id)
    if not scan_data:
        raise HTTPException(
            status_code=404,
            detail=f"Scan '{scan_id}' not found for user '{user_id}'"
        )

    # Parse raw_results JSON
    if scan_data.get('raw_results') and isinstance(scan_data['raw_results'], str):
        try:
            scan_data['raw_results'] = json.loads(scan_data['raw_results'])
        except (json.JSONDecodeError, TypeError):
            pass

    return {
        'success': True,
        'user_id': user_id,
        'scan': scan_data
    }


@app.get("/api/users/{user_id}/statistics")
async def get_user_statistics(user_id: str):
    """Get aggregate statistics for a user"""
    stats = db.get_statistics(user_id)
    return {
        'success': True,
        'user_id': user_id,
        'statistics': stats
    }


@app.get("/api/users/{user_id}/trends")
async def get_user_trends(
    user_id: str,
    days: int = Query(30, ge=1, le=365, description="Number of days to look back")
):
    """Get vulnerability trends over time for a user"""
    trends = db.get_vulnerability_trends(user_id, days=days)
    return {
        'success': True,
        'user_id': user_id,
        'trends': trends
    }


@app.get("/api/users/{user_id}/top-vulnerabilities")
async def get_user_top_vulnerabilities(
    user_id: str,
    limit: int = Query(10, ge=1, le=50, description="Number of top vulnerabilities")
):
    """Get most common vulnerability types for a user"""
    top_vulns = db.get_top_vulnerabilities(user_id, limit=limit)
    return {
        'success': True,
        'user_id': user_id,
        'top_vulnerabilities': top_vulns
    }


# ==================== System Endpoints ====================

@app.get("/api/health")
async def health_check():
    """System health endpoint"""
    stats = db.get_statistics()
    return {
        'status': 'healthy',
        'timestamp': datetime.now().isoformat(),
        'database': 'connected',
        'database_path': db.db_path,
        'scans_processed': stats.get('total_scans', 0),
        'total_vulnerabilities': stats.get('total_vulnerabilities', 0)
    }


# ==================== Internal Helpers ====================

def _get_user_fp_history(user_id: str) -> Dict:
    """Get false positive history for a user from the database"""
    try:
        with db.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT v.vuln_type, COUNT(*) as count
                FROM false_positive_feedback fpf
                JOIN vulnerabilities v ON fpf.vuln_id = v.id
                WHERE fpf.user_id = ? AND fpf.is_false_positive = 1
                GROUP BY v.vuln_type
            """, (user_id,))

            history = {}
            for row in cursor.fetchall():
                history[row['vuln_type']] = row['count']
            return history
    except Exception:
        return {}


if __name__ == "__main__":
    import uvicorn
    print(f"SASTify API v2.0 — Database: {db.db_path}")
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
