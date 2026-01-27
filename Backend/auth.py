"""
Authentication Module - API Key Management

Provides secure API key authentication for SASTify:
- API key generation and validation
- Rate limiting per key
- Scope-based access control
- FastAPI middleware integration
"""

import time
import hashlib
from typing import Dict, Optional, List, Callable
from functools import wraps
from collections import defaultdict

from fastapi import Request, HTTPException, Depends
from fastapi.security import APIKeyHeader

from database import get_database


# API Key header scheme
API_KEY_HEADER = APIKeyHeader(name="X-API-Key", auto_error=False)


class RateLimiter:
    """
    Token bucket rate limiter.
    
    Tracks request counts per API key and enforces rate limits.
    """
    
    def __init__(self):
        self.requests: Dict[str, List[float]] = defaultdict(list)
        self.window_seconds = 60  # 1 minute window
    
    def is_allowed(self, key_id: str, limit: int) -> tuple:
        """
        Check if a request is allowed under the rate limit.
        
        Returns: (is_allowed, remaining, reset_time)
        """
        now = time.time()
        window_start = now - self.window_seconds
        
        # Clean old requests
        self.requests[key_id] = [
            ts for ts in self.requests[key_id] 
            if ts > window_start
        ]
        
        current_count = len(self.requests[key_id])
        remaining = max(0, limit - current_count)
        
        if current_count >= limit:
            # Calculate reset time
            if self.requests[key_id]:
                oldest = min(self.requests[key_id])
                reset_time = int(oldest + self.window_seconds - now)
            else:
                reset_time = self.window_seconds
            return False, 0, reset_time
        
        # Record this request
        self.requests[key_id].append(now)
        return True, remaining - 1, self.window_seconds


# Global rate limiter instance
_rate_limiter = RateLimiter()


class AuthManager:
    """
    Manages API key authentication and authorization.
    
    Features:
    - API key validation
    - Rate limiting
    - Scope-based access control
    """
    
    def __init__(self):
        self.db = get_database()
        self.rate_limiter = _rate_limiter
    
    def create_api_key(self, user_id: str, name: str = "Default",
                       rate_limit: int = 100, scopes: List[str] = None) -> Dict:
        """
        Create a new API key for a user.
        
        Returns dict with key_id and the raw key (only shown once).
        """
        key_id, raw_key = self.db.create_api_key(
            user_id=user_id,
            name=name,
            rate_limit=rate_limit,
            scopes=scopes
        )
        
        return {
            'key_id': key_id,
            'api_key': raw_key,
            'name': name,
            'rate_limit': rate_limit,
            'scopes': scopes or ['scan', 'analyze', 'report'],
            'message': 'Save this API key securely. It will not be shown again.'
        }
    
    def validate_key(self, api_key: str) -> Optional[Dict]:
        """
        Validate an API key and return user info.
        
        Returns None if invalid, otherwise returns key info dict.
        """
        if not api_key:
            return None
        
        return self.db.validate_api_key(api_key)
    
    def check_rate_limit(self, key_info: Dict) -> tuple:
        """
        Check rate limit for a key.
        
        Returns: (is_allowed, remaining, reset_time)
        """
        key_id = key_info.get('key_id', 'anonymous')
        limit = key_info.get('rate_limit', 100)
        
        return self.rate_limiter.is_allowed(key_id, limit)
    
    def has_scope(self, key_info: Dict, required_scope: str) -> bool:
        """Check if a key has a required scope"""
        scopes = key_info.get('scopes', [])
        return required_scope in scopes or 'admin' in scopes
    
    def revoke_key(self, key_id: str, user_id: str) -> bool:
        """Revoke an API key"""
        return self.db.revoke_api_key(key_id, user_id)
    
    def list_keys(self, user_id: str) -> List[Dict]:
        """List all API keys for a user (without revealing secrets)"""
        with self.db.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT key_id, name, created_at, last_used, is_active, rate_limit, scopes
                FROM api_keys
                WHERE user_id = ?
                ORDER BY created_at DESC
            """, (user_id,))
            
            return [dict(row) for row in cursor.fetchall()]


# Global auth manager instance
_auth_manager = None

def get_auth_manager() -> AuthManager:
    """Get the auth manager singleton"""
    global _auth_manager
    if _auth_manager is None:
        _auth_manager = AuthManager()
    return _auth_manager


# ==================== FastAPI Dependencies ====================

async def get_api_key(api_key: str = Depends(API_KEY_HEADER)) -> Optional[Dict]:
    """
    FastAPI dependency to extract and validate API key.
    
    Returns None for anonymous access (if allowed).
    """
    if not api_key:
        return None
    
    auth = get_auth_manager()
    key_info = auth.validate_key(api_key)
    
    return key_info


async def require_api_key(api_key: str = Depends(API_KEY_HEADER)) -> Dict:
    """
    FastAPI dependency that requires a valid API key.
    
    Raises HTTPException 401 if no key or invalid key.
    """
    if not api_key:
        raise HTTPException(
            status_code=401,
            detail={
                'error': 'missing_api_key',
                'message': 'API key required. Pass it in the X-API-Key header.'
            }
        )
    
    auth = get_auth_manager()
    key_info = auth.validate_key(api_key)
    
    if not key_info:
        raise HTTPException(
            status_code=401,
            detail={
                'error': 'invalid_api_key',
                'message': 'Invalid or revoked API key.'
            }
        )
    
    return key_info


async def check_rate_limit(
    request: Request,
    key_info: Dict = Depends(get_api_key)
) -> Dict:
    """
    FastAPI dependency to check and enforce rate limits.
    
    Adds rate limit headers to response.
    """
    auth = get_auth_manager()
    
    # For anonymous requests, use IP-based limiting
    if key_info is None:
        key_info = {
            'key_id': f"anon_{request.client.host}",
            'user_id': 'anonymous',
            'rate_limit': 20,  # Lower limit for anonymous
            'scopes': ['scan']
        }
    
    allowed, remaining, reset = auth.check_rate_limit(key_info)
    
    # Store rate limit info for headers
    request.state.rate_limit_remaining = remaining
    request.state.rate_limit_reset = reset
    request.state.rate_limit_limit = key_info.get('rate_limit', 100)
    
    if not allowed:
        raise HTTPException(
            status_code=429,
            detail={
                'error': 'rate_limit_exceeded',
                'message': f'Rate limit exceeded. Try again in {reset} seconds.',
                'retry_after': reset
            },
            headers={
                'Retry-After': str(reset),
                'X-RateLimit-Limit': str(key_info.get('rate_limit', 100)),
                'X-RateLimit-Remaining': '0',
                'X-RateLimit-Reset': str(reset)
            }
        )
    
    return key_info


def require_scope(scope: str):
    """
    Decorator to require a specific scope.
    
    Usage:
        @app.post("/admin/action")
        @require_scope("admin")
        async def admin_action(key_info: Dict = Depends(require_api_key)):
            ...
    """
    def decorator(func: Callable):
        @wraps(func)
        async def wrapper(*args, **kwargs):
            # Find key_info in kwargs
            key_info = kwargs.get('key_info')
            
            if not key_info:
                raise HTTPException(
                    status_code=401,
                    detail={'error': 'auth_required', 'message': 'Authentication required'}
                )
            
            auth = get_auth_manager()
            if not auth.has_scope(key_info, scope):
                raise HTTPException(
                    status_code=403,
                    detail={
                        'error': 'insufficient_scope',
                        'message': f"This action requires the '{scope}' scope."
                    }
                )
            
            return await func(*args, **kwargs)
        return wrapper
    return decorator


# ==================== Middleware ====================

class AuthMiddleware:
    """
    Authentication middleware for FastAPI.
    
    Adds rate limit headers and handles auth for all requests.
    """
    
    def __init__(self, app, exclude_paths: List[str] = None):
        self.app = app
        self.exclude_paths = exclude_paths or ['/health', '/docs', '/openapi.json']
    
    async def __call__(self, scope, receive, send):
        if scope['type'] != 'http':
            await self.app(scope, receive, send)
            return
        
        path = scope['path']
        
        # Skip auth for excluded paths
        if any(path.startswith(p) for p in self.exclude_paths):
            await self.app(scope, receive, send)
            return
        
        # Process request through app
        await self.app(scope, receive, send)


# ==================== Utility Functions ====================

def hash_password(password: str) -> str:
    """Hash a password for storage"""
    salt = hashlib.sha256(str(time.time()).encode()).hexdigest()[:16]
    hashed = hashlib.pbkdf2_hmac('sha256', password.encode(), salt.encode(), 100000)
    return f"{salt}${hashed.hex()}"


def verify_password(password: str, stored_hash: str) -> bool:
    """Verify a password against its hash"""
    try:
        salt, hash_hex = stored_hash.split('$')
        hashed = hashlib.pbkdf2_hmac('sha256', password.encode(), salt.encode(), 100000)
        return hashed.hex() == hash_hex
    except Exception:
        return False
