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

import structlog
from starlette.requests import Request
from starlette.responses import JSONResponse

log = structlog.get_logger()

# Session tokens mapped to (token_hash, created_at)
_sessions: dict[str, tuple[str, float]] = {}

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

    session_id = create_session(expected_token)
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
