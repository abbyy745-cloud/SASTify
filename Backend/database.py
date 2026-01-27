"""
Database Layer - Persistent Storage for SASTify

Provides SQLite-based storage for:
- Scan results and history
- API keys and authentication
- Analytics and trending data
- User feedback on false positives
"""

import sqlite3
import json
import hashlib
import secrets
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, asdict
from contextlib import contextmanager
import os
import threading


@dataclass
class ScanRecord:
    """A scan record in the database"""
    scan_id: str
    user_id: str
    filename: str
    language: str
    total_vulnerabilities: int
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    scan_type: str  # 'file', 'workspace', 'selection'
    created_at: str
    code_hash: str


@dataclass
class VulnerabilityRecord:
    """A vulnerability record in the database"""
    id: Optional[int]
    scan_id: str
    vuln_type: str
    severity: str
    line: int
    column: int
    snippet: str
    description: str
    remediation: str
    confidence: float
    cwe_id: Optional[str]
    is_false_positive: bool
    ai_analysis: Optional[str]


@dataclass
class ApiKey:
    """API key record"""
    key_id: str
    key_hash: str
    user_id: str
    name: str
    created_at: str
    last_used: Optional[str]
    is_active: bool
    rate_limit: int  # requests per minute
    scopes: str  # JSON array of allowed scopes


class Database:
    """
    Thread-safe SQLite database manager for SASTify.
    
    Features:
    - Connection pooling per thread
    - Automatic schema migration
    - ACID transactions
    - JSON field support
    """
    
    _local = threading.local()
    
    def __init__(self, db_path: str = None):
        if db_path is None:
            # Default to user's data directory
            data_dir = os.path.join(os.path.dirname(__file__), '.sastify_data')
            os.makedirs(data_dir, exist_ok=True)
            db_path = os.path.join(data_dir, 'sastify.db')
        
        self.db_path = db_path
        self._init_schema()
    
    @contextmanager
    def get_connection(self):
        """Get a thread-local database connection"""
        if not hasattr(self._local, 'connection') or self._local.connection is None:
            self._local.connection = sqlite3.connect(
                self.db_path,
                check_same_thread=False,
                timeout=30.0
            )
            self._local.connection.row_factory = sqlite3.Row
            # Enable foreign keys
            self._local.connection.execute("PRAGMA foreign_keys = ON")
        
        try:
            yield self._local.connection
        except Exception as e:
            self._local.connection.rollback()
            raise e
    
    def _init_schema(self):
        """Initialize database schema"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            
            # Scans table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS scans (
                    scan_id TEXT PRIMARY KEY,
                    user_id TEXT NOT NULL,
                    filename TEXT,
                    language TEXT,
                    total_vulnerabilities INTEGER DEFAULT 0,
                    critical_count INTEGER DEFAULT 0,
                    high_count INTEGER DEFAULT 0,
                    medium_count INTEGER DEFAULT 0,
                    low_count INTEGER DEFAULT 0,
                    scan_type TEXT DEFAULT 'file',
                    created_at TEXT NOT NULL,
                    code_hash TEXT,
                    raw_results TEXT  -- JSON blob of full results
                )
            """)
            
            # Vulnerabilities table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS vulnerabilities (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_id TEXT NOT NULL,
                    vuln_type TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    line INTEGER,
                    column_num INTEGER,
                    snippet TEXT,
                    description TEXT,
                    remediation TEXT,
                    confidence REAL DEFAULT 0.8,
                    cwe_id TEXT,
                    is_false_positive INTEGER DEFAULT 0,
                    ai_analysis TEXT,
                    created_at TEXT NOT NULL,
                    FOREIGN KEY (scan_id) REFERENCES scans(scan_id) ON DELETE CASCADE
                )
            """)
            
            # API Keys table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS api_keys (
                    key_id TEXT PRIMARY KEY,
                    key_hash TEXT NOT NULL UNIQUE,
                    user_id TEXT NOT NULL,
                    name TEXT,
                    created_at TEXT NOT NULL,
                    last_used TEXT,
                    is_active INTEGER DEFAULT 1,
                    rate_limit INTEGER DEFAULT 100,
                    scopes TEXT DEFAULT '["scan", "analyze"]'
                )
            """)
            
            # False positive feedback table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS false_positive_feedback (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    vuln_id INTEGER,
                    fingerprint TEXT NOT NULL,
                    is_false_positive INTEGER NOT NULL,
                    user_comment TEXT,
                    user_id TEXT,
                    created_at TEXT NOT NULL,
                    FOREIGN KEY (vuln_id) REFERENCES vulnerabilities(id)
                )
            """)
            
            # Analytics cache table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS analytics_cache (
                    cache_key TEXT PRIMARY KEY,
                    cache_value TEXT NOT NULL,
                    expires_at TEXT NOT NULL
                )
            """)
            
            # Create indexes for performance
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_scans_user ON scans(user_id)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_scans_created ON scans(created_at)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_vulns_scan ON vulnerabilities(scan_id)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_vulns_type ON vulnerabilities(vuln_type)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_vulns_severity ON vulnerabilities(severity)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_api_keys_user ON api_keys(user_id)")
            
            conn.commit()
    
    # ==================== Scan Operations ====================
    
    def save_scan(self, scan: ScanRecord, vulnerabilities: List[Dict], raw_results: Dict = None) -> str:
        """Save a scan and its vulnerabilities"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            
            # Insert scan record
            cursor.execute("""
                INSERT INTO scans (
                    scan_id, user_id, filename, language, total_vulnerabilities,
                    critical_count, high_count, medium_count, low_count,
                    scan_type, created_at, code_hash, raw_results
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                scan.scan_id, scan.user_id, scan.filename, scan.language,
                scan.total_vulnerabilities, scan.critical_count, scan.high_count,
                scan.medium_count, scan.low_count, scan.scan_type,
                scan.created_at, scan.code_hash,
                json.dumps(raw_results) if raw_results else None
            ))
            
            # Insert vulnerabilities
            now = datetime.utcnow().isoformat()
            for vuln in vulnerabilities:
                cursor.execute("""
                    INSERT INTO vulnerabilities (
                        scan_id, vuln_type, severity, line, column_num,
                        snippet, description, remediation, confidence,
                        cwe_id, is_false_positive, created_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    scan.scan_id,
                    vuln.get('type', 'unknown'),
                    vuln.get('severity', 'Medium'),
                    vuln.get('line', 0),
                    vuln.get('column', 0),
                    vuln.get('snippet', ''),
                    vuln.get('description', ''),
                    vuln.get('remediation', ''),
                    vuln.get('confidence', 0.8),
                    vuln.get('cwe_id'),
                    0,
                    now
                ))
            
            conn.commit()
            return scan.scan_id
    
    def get_scan(self, scan_id: str) -> Optional[Dict]:
        """Get a scan by ID with its vulnerabilities"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            
            cursor.execute("SELECT * FROM scans WHERE scan_id = ?", (scan_id,))
            scan_row = cursor.fetchone()
            
            if not scan_row:
                return None
            
            cursor.execute(
                "SELECT * FROM vulnerabilities WHERE scan_id = ? ORDER BY severity, line",
                (scan_id,)
            )
            vuln_rows = cursor.fetchall()
            
            return {
                'scan_id': scan_row['scan_id'],
                'user_id': scan_row['user_id'],
                'filename': scan_row['filename'],
                'language': scan_row['language'],
                'total_vulnerabilities': scan_row['total_vulnerabilities'],
                'critical_count': scan_row['critical_count'],
                'high_count': scan_row['high_count'],
                'medium_count': scan_row['medium_count'],
                'low_count': scan_row['low_count'],
                'scan_type': scan_row['scan_type'],
                'created_at': scan_row['created_at'],
                'vulnerabilities': [dict(row) for row in vuln_rows]
            }
    
    def get_user_scans(self, user_id: str, limit: int = 50) -> List[Dict]:
        """Get recent scans for a user"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT * FROM scans 
                WHERE user_id = ? 
                ORDER BY created_at DESC 
                LIMIT ?
            """, (user_id, limit))
            
            return [dict(row) for row in cursor.fetchall()]
    
    # ==================== API Key Operations ====================
    
    def create_api_key(self, user_id: str, name: str = "Default", 
                       rate_limit: int = 100, scopes: List[str] = None) -> tuple:
        """Create a new API key. Returns (key_id, raw_key)"""
        raw_key = secrets.token_urlsafe(32)
        key_hash = hashlib.sha256(raw_key.encode()).hexdigest()
        key_id = secrets.token_urlsafe(8)
        
        if scopes is None:
            scopes = ["scan", "analyze", "report"]
        
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO api_keys (
                    key_id, key_hash, user_id, name, created_at,
                    is_active, rate_limit, scopes
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                key_id, key_hash, user_id, name,
                datetime.utcnow().isoformat(),
                1, rate_limit, json.dumps(scopes)
            ))
            conn.commit()
        
        # Return full key (only shown once)
        return key_id, f"sast_{key_id}_{raw_key}"
    
    def validate_api_key(self, raw_key: str) -> Optional[Dict]:
        """Validate an API key and return its info"""
        if not raw_key or not raw_key.startswith('sast_'):
            return None
        
        try:
            parts = raw_key.split('_', 2)
            if len(parts) != 3:
                return None
            
            key_id = parts[1]
            key_secret = parts[2]
            key_hash = hashlib.sha256(key_secret.encode()).hexdigest()
            
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    SELECT * FROM api_keys 
                    WHERE key_id = ? AND key_hash = ? AND is_active = 1
                """, (key_id, key_hash))
                
                row = cursor.fetchone()
                if row:
                    # Update last used
                    cursor.execute(
                        "UPDATE api_keys SET last_used = ? WHERE key_id = ?",
                        (datetime.utcnow().isoformat(), key_id)
                    )
                    conn.commit()
                    
                    return {
                        'key_id': row['key_id'],
                        'user_id': row['user_id'],
                        'rate_limit': row['rate_limit'],
                        'scopes': json.loads(row['scopes'])
                    }
        except Exception:
            pass
        
        return None
    
    def revoke_api_key(self, key_id: str, user_id: str) -> bool:
        """Revoke an API key"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                UPDATE api_keys SET is_active = 0 
                WHERE key_id = ? AND user_id = ?
            """, (key_id, user_id))
            conn.commit()
            return cursor.rowcount > 0
    
    # ==================== Analytics Operations ====================
    
    def get_vulnerability_trends(self, user_id: str = None, days: int = 30) -> Dict:
        """Get vulnerability trends over time"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            
            cutoff = (datetime.utcnow() - timedelta(days=days)).isoformat()
            
            if user_id:
                cursor.execute("""
                    SELECT 
                        date(created_at) as scan_date,
                        SUM(critical_count) as critical,
                        SUM(high_count) as high,
                        SUM(medium_count) as medium,
                        SUM(low_count) as low,
                        COUNT(*) as scan_count
                    FROM scans
                    WHERE user_id = ? AND created_at >= ?
                    GROUP BY date(created_at)
                    ORDER BY scan_date
                """, (user_id, cutoff))
            else:
                cursor.execute("""
                    SELECT 
                        date(created_at) as scan_date,
                        SUM(critical_count) as critical,
                        SUM(high_count) as high,
                        SUM(medium_count) as medium,
                        SUM(low_count) as low,
                        COUNT(*) as scan_count
                    FROM scans
                    WHERE created_at >= ?
                    GROUP BY date(created_at)
                    ORDER BY scan_date
                """, (cutoff,))
            
            trends = []
            for row in cursor.fetchall():
                trends.append({
                    'date': row['scan_date'],
                    'critical': row['critical'] or 0,
                    'high': row['high'] or 0,
                    'medium': row['medium'] or 0,
                    'low': row['low'] or 0,
                    'scans': row['scan_count']
                })
            
            return {'trends': trends, 'days': days}
    
    def get_top_vulnerabilities(self, user_id: str = None, limit: int = 10) -> List[Dict]:
        """Get most common vulnerability types"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            
            if user_id:
                cursor.execute("""
                    SELECT 
                        v.vuln_type,
                        v.severity,
                        COUNT(*) as count
                    FROM vulnerabilities v
                    JOIN scans s ON v.scan_id = s.scan_id
                    WHERE s.user_id = ? AND v.is_false_positive = 0
                    GROUP BY v.vuln_type, v.severity
                    ORDER BY count DESC
                    LIMIT ?
                """, (user_id, limit))
            else:
                cursor.execute("""
                    SELECT 
                        vuln_type,
                        severity,
                        COUNT(*) as count
                    FROM vulnerabilities
                    WHERE is_false_positive = 0
                    GROUP BY vuln_type, severity
                    ORDER BY count DESC
                    LIMIT ?
                """, (limit,))
            
            return [dict(row) for row in cursor.fetchall()]
    
    def get_statistics(self, user_id: str = None) -> Dict:
        """Get overall statistics"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            
            if user_id:
                cursor.execute("""
                    SELECT 
                        COUNT(*) as total_scans,
                        SUM(total_vulnerabilities) as total_vulns,
                        SUM(critical_count) as total_critical,
                        SUM(high_count) as total_high
                    FROM scans WHERE user_id = ?
                """, (user_id,))
            else:
                cursor.execute("""
                    SELECT 
                        COUNT(*) as total_scans,
                        SUM(total_vulnerabilities) as total_vulns,
                        SUM(critical_count) as total_critical,
                        SUM(high_count) as total_high
                    FROM scans
                """)
            
            row = cursor.fetchone()
            
            return {
                'total_scans': row['total_scans'] or 0,
                'total_vulnerabilities': row['total_vulns'] or 0,
                'total_critical': row['total_critical'] or 0,
                'total_high': row['total_high'] or 0
            }
    
    # ==================== False Positive Operations ====================
    
    def record_false_positive(self, vuln_id: int, fingerprint: str, 
                              is_fp: bool, comment: str = "", user_id: str = None):
        """Record false positive feedback"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            
            cursor.execute("""
                INSERT INTO false_positive_feedback (
                    vuln_id, fingerprint, is_false_positive, 
                    user_comment, user_id, created_at
                ) VALUES (?, ?, ?, ?, ?, ?)
            """, (
                vuln_id, fingerprint, 1 if is_fp else 0,
                comment, user_id, datetime.utcnow().isoformat()
            ))
            
            # Update vulnerability record
            if vuln_id:
                cursor.execute(
                    "UPDATE vulnerabilities SET is_false_positive = ? WHERE id = ?",
                    (1 if is_fp else 0, vuln_id)
                )
            
            conn.commit()
    
    def is_known_false_positive(self, fingerprint: str) -> bool:
        """Check if a fingerprint is a known false positive"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT COUNT(*) as fp_count
                FROM false_positive_feedback
                WHERE fingerprint = ? AND is_false_positive = 1
            """, (fingerprint,))
            
            row = cursor.fetchone()
            return (row['fp_count'] or 0) > 0


# Singleton instance
_db_instance = None

def get_database(db_path: str = None) -> Database:
    """Get the database singleton"""
    global _db_instance
    if _db_instance is None:
        _db_instance = Database(db_path)
    return _db_instance
