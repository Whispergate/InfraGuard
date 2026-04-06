"""Authentication for the dashboard API.

Supports two auth methods:
- Bearer token via Authorization header (for API clients / TUI)
- Session cookie via /api/auth/login (for the web dashboard)
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
import time
from collections import defaultdict
from datetime import datetime, timezone

import structlog
from starlette.requests import Request
from starlette.responses import JSONResponse

from infraguard.tracking.database import Database

log = structlog.get_logger()

# ── Per-IP rate limiting for failed login attempts ────────────────────
_rate_limit: dict[str, list[float]] = defaultdict(list)
_RATE_WINDOW = 60.0  # seconds
_MAX_ATTEMPTS = 5


def _check_rate_limit(ip: str) -> bool:
    """Return True if the IP is rate-limited (should be blocked)."""
    now = time.monotonic()
    # Prune expired attempts
    _rate_limit[ip] = [t for t in _rate_limit[ip] if now - t < _RATE_WINDOW]
    return len(_rate_limit[ip]) >= _MAX_ATTEMPTS


def _record_failed_attempt(ip: str) -> int:
    """Record a failed attempt and return current count in window."""
    _rate_limit[ip].append(time.monotonic())
    return len(_rate_limit[ip])


SESSION_COOKIE = "ig_session"
_SESSION_TTL = 86400  # 24 hours
_MAX_SESSIONS = 1000


def _token_hash(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


async def create_session(db: Database, api_token: str, ttl: int, client_ip: str = "") -> str:
    """Create a session ID backed by SQLite and return the session_id."""
    session_id = secrets.token_urlsafe(32)
    await db.create_session(session_id, _token_hash(api_token), ttl, client_ip)
    return session_id


async def validate_session(db: Database, session_id: str, expected_token: str) -> bool:
    """Check if a session ID is valid and not expired against the SQLite store."""
    row = await db.get_session(session_id)
    if not row:
        return False
    if datetime.fromisoformat(row["expires_at"]) < datetime.now(timezone.utc):
        await db.delete_session(session_id)
        return False
    return row["token_hash"] == _token_hash(expected_token)


async def check_auth(request: Request, expected_token: str | None) -> JSONResponse | None:
    """Validate bearer token or session cookie. Returns error response or None if valid."""
    if not expected_token:
        return None  # Auth disabled

    # Check Bearer token first (API clients, TUI)
    auth = request.headers.get("authorization", "")
    if auth.startswith("Bearer "):
        token = auth[7:]
        if hmac.compare_digest(token, expected_token):
            return None
        return JSONResponse({"error": "Invalid token"}, status_code=403)

    # Check session cookie (web dashboard)
    session_id = request.cookies.get(SESSION_COOKIE)
    if session_id:
        db: Database = request.app.state.db
        if await validate_session(db, session_id, expected_token):
            return None

    return JSONResponse({"error": "Authentication required"}, status_code=401)


async def login_handler(request: Request) -> JSONResponse:
    """POST /api/auth/login -- authenticate with token, receive session cookie."""
    expected_token = request.app.state.config.api.auth_token

    if not expected_token:
        # Auth disabled, just return success
        return JSONResponse({"status": "ok", "message": "Auth disabled"})

    client_ip = request.client.host if request.client else "unknown"

    # Rate limit check before token validation
    if _check_rate_limit(client_ip):
        log.warning("auth_locked", client_ip=client_ip)
        return JSONResponse(
            {"error": "Too many attempts. Try again later."},
            status_code=429,
        )

    body = await request.json()
    token = body.get("token", "")

    if not token or not hmac.compare_digest(token, expected_token):
        attempt_count = _record_failed_attempt(client_ip)
        log.warning("auth_failed", client_ip=client_ip, attempts=attempt_count)
        return JSONResponse({"error": "Invalid token"}, status_code=403)

    db: Database = request.app.state.db
    ttl: int = request.app.state.config.api.session_ttl
    session_id = await create_session(db, expected_token, ttl, client_ip)
    log.info("auth_success", client_ip=client_ip, session_created=True)
    response = JSONResponse({"status": "ok"})
    # Set Secure flag based on whether the request arrived over HTTPS
    is_secure = request.url.scheme == "https" or request.headers.get("x-forwarded-proto") == "https"
    response.set_cookie(
        SESSION_COOKIE,
        session_id,
        httponly=True,
        secure=is_secure,
        samesite="strict",
        max_age=ttl,
    )
    return response


async def logout_handler(request: Request) -> JSONResponse:
    """POST /api/auth/logout -- clear session cookie."""
    session_id = request.cookies.get(SESSION_COOKIE)
    if session_id:
        db: Database = request.app.state.db
        await db.delete_session(session_id)
    response = JSONResponse({"status": "ok"})
    response.delete_cookie(SESSION_COOKIE)
    return response


async def check_handler(request: Request) -> JSONResponse:
    """GET /api/auth/check -- check if current session/token is valid."""
    expected_token = request.app.state.config.api.auth_token
    if not expected_token:
        return JSONResponse({"authenticated": True, "auth_required": False})

    error = await check_auth(request, expected_token)
    if error:
        return JSONResponse({"authenticated": False, "auth_required": True})
    return JSONResponse({"authenticated": True, "auth_required": True})
