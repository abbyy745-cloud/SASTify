from fastapi import FastAPI, HTTPException, Request, Depends, Query, Header
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from pydantic import BaseModel, EmailStr
from typing import List, Dict, Any, Optional
import os
import sys
import time
import json
import hashlib
import uuid
import secrets
from datetime import datetime, timezone
from dotenv import load_dotenv

sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from enhanced_rule_engine import EnhancedRuleEngine
from deepseek_api import SecureDeepSeekAPI
from false_positive_detector import FalsePositiveDetector
from database import get_database, ScanRecord, Database

# Explicitly load .env from the Backend directory so it works regardless of the current working directory
env_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), '.env')
load_dotenv(dotenv_path=env_path)

limiter = Limiter(key_func=get_remote_address)

app = FastAPI(
    title="SASTify API",
    description="AI-powered static application security testing API",
    version="2.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # In production, replace with your frontend domain
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

rule_engine = EnhancedRuleEngine()
deepseek_api = SecureDeepSeekAPI(api_key=os.getenv('DEEPSEEK_API_KEY'))
fp_detector = FalsePositiveDetector()
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

# ── NEW: Auth models ──────────────────────────────────────────────────────────

class RegisterRequest(BaseModel):
    email: str
    password: str
    name: str = ''

class LoginRequest(BaseModel):
    email: str
    password: str


# ==================== Helper Functions ====================

def _generate_scan_id(prefix: str = "scan") -> str:
    return f"{prefix}_{int(time.time())}_{uuid.uuid4().hex[:8]}"


def _create_scan_record(
    scan_id, user_id, filename, language, issues, scan_type='file', code=''
) -> ScanRecord:
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
        created_at=datetime.now(timezone.utc).isoformat(),
        code_hash=hashlib.sha256(code.encode()).hexdigest() if code else ''
    )


def _hash_password(password: str) -> str:
    """Simple SHA-256 password hash. Use bcrypt in production."""
    return hashlib.sha256(password.encode()).hexdigest()


def _get_user_from_token(authorization: Optional[str]) -> Optional[Dict]:
    """
    Extract Bearer token from Authorization header and look up user.
    Returns user dict or None if invalid / not provided.
    """
    if not authorization:
        return None
    if not authorization.startswith('Bearer '):
        return None
    token = authorization[len('Bearer '):].strip()
    if not token:
        return None
    return db.get_user_by_token(token)


try:
    from cross_file_taint import analyze_project as cross_file_analyze
    CROSS_FILE_AVAILABLE = True
except ImportError:
    CROSS_FILE_AVAILABLE = False


# ==================== AUTH Endpoints (NEW) ====================

@app.post("/api/auth/register")
async def register(data: RegisterRequest):
    """
    Create a new account.
    Returns the user's permanent API token.
    This token is what the user pastes into VS Code.
    """
    # Check email not already taken
    existing = db.get_user_by_email(data.email)
    if existing:
        raise HTTPException(status_code=409, detail="Email already registered.")

    user_id = f"user_{uuid.uuid4().hex[:12]}"
    password_hash = _hash_password(data.password)

    # Generate a permanent API token for this user
    # Format: sast_<random> — easy to recognise
    token = f"sast_{secrets.token_urlsafe(32)}"

    db.create_auth_user(
        user_id=user_id,
        email=data.email,
        name=data.name or data.email.split('@')[0],
        password_hash=password_hash,
        token=token
    )

    return {
        "success": True,
        "message": "Account created. Copy your token and paste it into VS Code.",
        "user_id": user_id,
        "email": data.email,
        "name": data.name or data.email.split('@')[0],
        # ← This is what the user pastes into VS Code
        "token": token
    }


@app.post("/api/auth/login")
async def login(data: LoginRequest):
    """
    Login and get the token back (in case user lost it).
    """
    user = db.get_user_by_email(data.email)
    if not user:
        raise HTTPException(status_code=401, detail="Invalid email or password.")

    if user.get('password_hash') != _hash_password(data.password):
        raise HTTPException(status_code=401, detail="Invalid email or password.")

    return {
        "success": True,
        "user_id": user['user_id'],
        "email": user['email'],
        "name": user.get('name', ''),
        # ← User can copy this and re-paste into VS Code if needed
        "token": user['token']
    }


@app.get("/api/auth/validate-token")
async def validate_token(authorization: Optional[str] = Header(None)):
    """
    VS Code extension calls this once after the user pastes their token.
    Returns valid=True and user info so the extension can show a welcome message.
    """
    user = _get_user_from_token(authorization)
    if not user:
        raise HTTPException(status_code=401, detail="Invalid or expired token.")

    return {
        "valid": True,
        "user_id": user['user_id'],
        "email": user['email'],
        "name": user.get('name', '')
    }


@app.get("/api/auth/me")
async def get_me(authorization: Optional[str] = Header(None)):
    """Get current user info from token. Used by the web dashboard."""
    user = _get_user_from_token(authorization)
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated.")
    # Don't return password_hash
    return {
        "user_id": user['user_id'],
        "email": user['email'],
        "name": user.get('name', ''),
        "created_at": user.get('created_at', ''),
        "token": user['token']   # so dashboard can show "Your Token" section
    }


# ==================== Token-aware user resolution helper ====================

def _resolve_user_id(authorization: Optional[str], fallback_user_id: str) -> str:
    """
    If a valid Bearer token is present, use the real user_id from the database.
    Otherwise fall back to whatever user_id the client sent (backward compat).
    """
    user = _get_user_from_token(authorization)
    if user:
        return user['user_id']
    return fallback_user_id


# ==================== Scan Endpoints ====================

@app.post("/api/scan")
@limiter.limit("10/minute")
async def scan_code(request: Request, data: ScanRequest, authorization: Optional[str] = Header(None)):
    """Main scanning endpoint — token identifies the user automatically."""
    try:
        scan_id = data.scan_id or _generate_scan_id()

        # ── Resolve real user_id from token if available ──────────────────────
        user_id = _resolve_user_id(authorization, data.user_id)

        print(f"Starting enhanced scan {scan_id} for {data.language} (file: {data.filename}, user: {user_id})")

        db.ensure_user(user_id)

        start_time = time.time()
        rule_issues = rule_engine.scan_with_ast_analysis(data.code, data.language, data.filename)
        rule_scan_time = time.time() - start_time

        user_fp_history = _get_user_fp_history(user_id)
        filtered_issues = []
        for issue in rule_issues:
            is_likely_fp = fp_detector.is_likely_false_positive(issue, user_fp_history, data.filename)
            issue['is_likely_false_positive'] = is_likely_fp
            filtered_issues.append(issue)

        scan_record = _create_scan_record(
            scan_id=scan_id,
            user_id=user_id,
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
            'user_id': user_id,
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
async def scan_batch(request: Request, data: BatchScanRequest, authorization: Optional[str] = Header(None)):
    """Batch scan — token identifies the user automatically."""
    try:
        batch_scan_id = _generate_scan_id("batch")
        start_time = time.time()

        # ── Resolve real user_id from token ───────────────────────────────────
        user_id = _resolve_user_id(authorization, data.user_id)

        print(f"Starting batch scan {batch_scan_id} for {len(data.files)} files (user: {user_id})")

        db.ensure_user(user_id)

        all_issues = []
        total_issues = 0
        total_likely_fps = 0
        user_fp_history = _get_user_fp_history(user_id)

        for file_item in data.files:
            try:
                rule_issues = rule_engine.scan_with_ast_analysis(
                    file_item.code, file_item.language, file_item.filename
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

        combined_code = "\n".join(f.code for f in data.files)
        scan_record = _create_scan_record(
            scan_id=batch_scan_id,
            user_id=user_id,
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
            'user_id': user_id,
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
async def scan_project_endpoint(request: Request, data: ProjectScanRequest, authorization: Optional[str] = Header(None)):
    try:
        if not os.path.exists(data.project_path):
            raise HTTPException(status_code=404, detail="Project path not found")

        if not CROSS_FILE_AVAILABLE:
            raise HTTPException(status_code=503, detail="Cross-file analysis module not available")

        user_id = _resolve_user_id(authorization, data.user_id)
        db.ensure_user(user_id)

        start_time = time.time()
        report = cross_file_analyze(data.project_path)
        scan_time = time.time() - start_time

        project_scan_id = _generate_scan_id("project")

        scan_record = _create_scan_record(
            scan_id=project_scan_id,
            user_id=user_id,
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
            'user_id': user_id,
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
@limiter.limit("20/minute")
async def analyze_specific_issue(request: Request, data: AnalyzeIssueRequest, authorization: Optional[str] = Header(None)):
    try:
        scan_data = db.get_scan(data.scan_id)
        if not scan_data:
            raise HTTPException(status_code=404, detail='Scan not found')

        raw = scan_data.get('raw_results')
        if isinstance(raw, str):
            try:
                raw = json.loads(raw)
            except (json.JSONDecodeError, TypeError):
                raw = {}

        issues = raw.get('issues', []) if raw else []
        if not issues:
            issues = scan_data.get('vulnerabilities', [])

        if data.issue_index >= len(issues):
            raise HTTPException(status_code=404, detail='Issue not found')

        issue = issues[data.issue_index]
        language = issue.get('language') or scan_data.get('language', 'python')

        # Build a minimal, clean context for the AI.
        # Do NOT pass the full issue dict — it contains rule-engine metadata
        # (edtech categories, scanner names, rule descriptions) that leak into
        # the prompt and cause the AI to hallucinate domain-specific explanations
        # (e.g. "student bulk data") unrelated to the actual code snippet.
        ai_context = {
            'confidence': issue.get('confidence', 0.7),
            'severity': issue.get('severity', 'Medium'),
            'line': issue.get('line', 0),
            'filename': scan_data.get('filename', ''),
        }

        ai_analysis = deepseek_api.analyze_vulnerability(
            code_snippet=data.code_snippet,
            language=language,
            vulnerability_type=issue.get('type', 'unknown'),
            context=ai_context
        )

        db.update_scan_ai_analysis(data.scan_id, data.issue_index, json.dumps(ai_analysis))

        vulns = db.get_scan_vulnerabilities(data.scan_id)
        if data.issue_index < len(vulns):
            vuln_id = vulns[data.issue_index].get('id')
            if vuln_id:
                db.update_vulnerability_ai_analysis(vuln_id, json.dumps(ai_analysis))

        explanation = ai_analysis.get('explanation', '') or ai_analysis.get('false_positive_reason', 'No explanation provided')

        return {
            'success': True,
            'ai_analysis': {
                'suggested_fix': ai_analysis.get('suggested_fix', ''),
                'explanation': explanation,
                'confidence': ai_analysis.get('confidence', 0),
                'risk_level': ai_analysis.get('risk_level', 'Medium'),
                'is_confirmed': ai_analysis.get('is_confirmed_vulnerability', False),
                'false_positive_reason': ai_analysis.get('false_positive_reason', '')
            },
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
async def report_false_positive(data: FalsePositiveReportRequest, authorization: Optional[str] = Header(None)):
    try:
        scan_data = db.get_scan(data.scan_id)
        if not scan_data:
            raise HTTPException(status_code=404, detail='Scan not found')

        vulns = scan_data.get('vulnerabilities', [])
        if data.issue_index >= len(vulns):
            raise HTTPException(status_code=404, detail='Issue not found')

        issue = vulns[data.issue_index]
        fp_detector.record_feedback(issue, True, data.comment)

        vuln_id = issue.get('id')
        fingerprint = hashlib.sha256(
            f"{issue.get('vuln_type', '')}:{issue.get('line', 0)}:{issue.get('snippet', '')}".encode()
        ).hexdigest()

        user_id = _resolve_user_id(authorization, data.user_id)
        db.record_false_positive(
            vuln_id=vuln_id,
            fingerprint=fingerprint,
            is_fp=True,
            comment=data.comment,
            user_id=user_id
        )

        return {'success': True, 'message': 'False positive reported and recorded'}

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ==================== Scan Results Endpoint ====================

@app.get("/api/scan-results/{scan_id}")
async def get_scan_results(scan_id: str):
    scan_data = db.get_scan(scan_id)
    if not scan_data:
        raise HTTPException(status_code=404, detail='Scan not found')

    if scan_data.get('raw_results') and isinstance(scan_data['raw_results'], str):
        try:
            scan_data['raw_results'] = json.loads(scan_data['raw_results'])
        except (json.JSONDecodeError, TypeError):
            pass

    return scan_data


# ==================== Analytics Endpoint ====================

@app.get("/api/analytics")
async def get_analytics(user_id: str = 'anonymous', authorization: Optional[str] = Header(None)):
    # If token provided, use real user_id
    resolved_user_id = _resolve_user_id(authorization, user_id)
    query_user_id = None if resolved_user_id == 'all' else resolved_user_id

    stats = db.get_statistics(query_user_id)
    trends = db.get_vulnerability_trends(query_user_id, days=30)
    top_vulns = db.get_top_vulnerabilities(query_user_id, limit=10)
    fp_stats = fp_detector.get_false_positive_stats()

    if query_user_id:
        user_scans = db.get_user_scans(query_user_id, limit=50)
        scan_history = [s['scan_id'] for s in user_scans.get('scans', [])]
    else:
        scan_history = []

    return {
        'user_stats': {
            'total_scans': stats.get('total_scans', 0),
            'total_issues_found': stats.get('total_vulnerabilities', 0),
            'false_positive_history': {},
            'scan_history': scan_history
        },
        'false_positive_stats': fp_stats,
        'total_scans_in_system': db.get_statistics().get('total_scans', 0),
        'most_common_vulnerabilities': [
            {'type': v['vuln_type'], 'count': v['count']} for v in top_vulns
        ],
        'trends': trends
    }


@app.get("/api/users")
async def list_all_users():
    users = db.get_all_users()
    return {'success': True, 'users': users}


# ==================== User-Scoped Dashboard Endpoints ====================

@app.get("/api/users/{user_id}/dashboard")
async def get_user_dashboard(user_id: str, authorization: Optional[str] = Header(None)):
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
    page: int = Query(1, ge=1),
    limit: int = Query(20, ge=1, le=100)
):
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
    scan_data = db.get_user_scan(user_id, scan_id)
    if not scan_data:
        raise HTTPException(status_code=404, detail=f"Scan '{scan_id}' not found for user '{user_id}'")

    if scan_data.get('raw_results') and isinstance(scan_data['raw_results'], str):
        try:
            scan_data['raw_results'] = json.loads(scan_data['raw_results'])
        except (json.JSONDecodeError, TypeError):
            pass

    return {'success': True, 'user_id': user_id, 'scan': scan_data}


@app.get("/api/users/{user_id}/statistics")
async def get_user_statistics(user_id: str):
    stats = db.get_statistics(user_id)
    return {'success': True, 'user_id': user_id, 'statistics': stats}


@app.get("/api/users/{user_id}/trends")
async def get_user_trends(
    user_id: str,
    days: int = Query(30, ge=1, le=365)
):
    trends = db.get_vulnerability_trends(user_id, days=days)
    return {'success': True, 'user_id': user_id, 'trends': trends}


@app.get("/api/users/{user_id}/top-vulnerabilities")
async def get_user_top_vulnerabilities(
    user_id: str,
    limit: int = Query(10, ge=1, le=50)
):
    top_vulns = db.get_top_vulnerabilities(user_id, limit=limit)
    return {'success': True, 'user_id': user_id, 'top_vulnerabilities': top_vulns}


# ==================== System Endpoints ====================

@app.get("/api/health")
async def health_check():
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