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

from starlette.requests import Request
from starlette.responses import JSONResponse

# Session tokens mapped to (token_hash, created_at)
_sessions: dict[str, tuple[str, float]] = {}

SESSION_COOKIE = "ig_session"
_SESSION_TTL = 86400  # 24 hours
_MAX_SESSIONS = 1000


def _token_hash(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def _evict_expired() -> None:
    """Remove expired sessions and enforce max count."""
    now = time.time()
    expired = [sid for sid, (_, ts) in _sessions.items() if now - ts > _SESSION_TTL]
    for sid in expired:
        del _sessions[sid]
    # If still over limit, evict oldest
    if len(_sessions) > _MAX_SESSIONS:
        by_age = sorted(_sessions.items(), key=lambda x: x[1][1])
        for sid, _ in by_age[: len(_sessions) - _MAX_SESSIONS]:
            del _sessions[sid]


def create_session(api_token: str) -> str:
    """Create a session ID that maps to the given API token."""
    _evict_expired()
    session_id = secrets.token_urlsafe(32)
    _sessions[session_id] = (_token_hash(api_token), time.time())
    return session_id


def validate_session(session_id: str, expected_token: str) -> bool:
    """Check if a session ID is valid and not expired."""
    entry = _sessions.get(session_id)
    if not entry:
        return False
    stored_hash, created_at = entry
    if time.time() - created_at > _SESSION_TTL:
        del _sessions[session_id]
        return False
    return hmac.compare_digest(stored_hash, _token_hash(expected_token))


def check_auth(request: Request, expected_token: str | None) -> JSONResponse | None:
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
    if session_id and validate_session(session_id, expected_token):
        return None

    return JSONResponse({"error": "Authentication required"}, status_code=401)


async def login_handler(request: Request) -> JSONResponse:
    """POST /api/auth/login -- authenticate with token, receive session cookie."""
    expected_token = request.app.state.config.api.auth_token

    if not expected_token:
        # Auth disabled, just return success
        return JSONResponse({"status": "ok", "message": "Auth disabled"})

    body = await request.json()
    token = body.get("token", "")

    if not token or not hmac.compare_digest(token, expected_token):
        return JSONResponse({"error": "Invalid token"}, status_code=403)

    session_id = create_session(expected_token)
    response = JSONResponse({"status": "ok"})
    # Set Secure flag based on whether the request arrived over HTTPS
    is_secure = request.url.scheme == "https" or request.headers.get("x-forwarded-proto") == "https"
    response.set_cookie(
        SESSION_COOKIE,
        session_id,
        httponly=True,
        secure=is_secure,
        samesite="strict",
        max_age=86400,  # 24 hours
    )
    return response


async def logout_handler(request: Request) -> JSONResponse:
    """POST /api/auth/logout -- clear session cookie."""
    session_id = request.cookies.get(SESSION_COOKIE)
    if session_id:
        _sessions.pop(session_id, None)
    response = JSONResponse({"status": "ok"})
    response.delete_cookie(SESSION_COOKIE)
    return response


async def check_handler(request: Request) -> JSONResponse:
    """GET /api/auth/check -- check if current session/token is valid."""
    expected_token = request.app.state.config.api.auth_token
    if not expected_token:
        return JSONResponse({"authenticated": True, "auth_required": False})

    error = check_auth(request, expected_token)
    if error:
        return JSONResponse({"authenticated": False, "auth_required": True})
    return JSONResponse({"authenticated": True, "auth_required": True})
