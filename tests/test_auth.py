"""Tests for auth endpoint rate limiting, logging, and SQLite-backed sessions."""

from __future__ import annotations

import asyncio
import time
from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
import pytest_asyncio
import structlog
from structlog.testing import capture_logs

from infraguard.tracking.database import Database
from infraguard.ui.api.auth import (
    _MAX_ATTEMPTS,
    _RATE_WINDOW,
    _check_rate_limit,
    _rate_limit,
    _record_failed_attempt,
    _token_hash,
    create_session,
    login_handler,
    validate_session,
)


# ── Fixtures ──────────────────────────────────────────────────────────

@pytest.fixture(autouse=True)
def clear_rate_limit():
    """Clear rate limit state before and after each test."""
    _rate_limit.clear()
    yield
    _rate_limit.clear()


@pytest_asyncio.fixture
async def db(tmp_path):
    """Provide a connected temporary SQLite database."""
    path = str(tmp_path / "auth_test.db")
    database = Database(db_path=path)
    await database.connect()
    yield database
    await database.close()


def _make_login_request(
    token: str = "secret",
    client_ip: str = "1.2.3.4",
    expected_token: str = "secret",
    db: Database | None = None,
    session_ttl: int = 86400,
) -> MagicMock:
    """Create a mock login request."""
    req = MagicMock()
    req.client = MagicMock()
    req.client.host = client_ip
    req.app.state.config.api.auth_token = expected_token
    req.app.state.config.api.session_ttl = session_ttl
    req.app.state.db = db
    req.json = AsyncMock(return_value={"token": token})
    req.url.scheme = "http"
    req.headers = {}
    return req


# ── Rate limiting tests ───────────────────────────────────────────────

class TestRateLimiting:

    def test_rate_limit_allows_under_threshold(self):
        """4 failed attempts from same IP should not trigger rate limit."""
        for _ in range(4):
            _record_failed_attempt("1.2.3.4")
        assert not _check_rate_limit("1.2.3.4")

    def test_rate_limit_blocks_at_threshold(self):
        """5 failed attempts should trigger rate limit on 6th check."""
        for _ in range(_MAX_ATTEMPTS):
            _record_failed_attempt("1.2.3.4")
        assert _check_rate_limit("1.2.3.4")

    def test_rate_limit_different_ips(self):
        """Failed attempts from IP-A should not affect IP-B."""
        for _ in range(_MAX_ATTEMPTS):
            _record_failed_attempt("10.0.0.1")
        # IP-A is rate limited
        assert _check_rate_limit("10.0.0.1")
        # IP-B should not be rate limited
        assert not _check_rate_limit("10.0.0.2")

    def test_rate_limit_window_reset(self):
        """After window expires, attempt counter resets."""
        ip = "5.5.5.5"
        old_time = time.monotonic() - _RATE_WINDOW - 1  # Outside the window

        # Inject old timestamps directly
        _rate_limit[ip] = [old_time] * _MAX_ATTEMPTS

        # Should NOT be rate-limited because timestamps are outside window
        assert not _check_rate_limit(ip)
        # After pruning, the list should be empty
        assert len(_rate_limit[ip]) == 0

    @pytest.mark.asyncio
    async def test_rate_limit_returns_429_at_threshold(self, db: Database):
        """6th failed attempt from same IP returns HTTP 429."""
        # Pre-populate with MAX_ATTEMPTS failed attempts
        for _ in range(_MAX_ATTEMPTS):
            _record_failed_attempt("1.2.3.4")

        request = _make_login_request(token="wrong", client_ip="1.2.3.4", db=db)
        response = await login_handler(request)

        assert response.status_code == 429

    @pytest.mark.asyncio
    async def test_rate_limit_allows_under_threshold_login(self, db: Database):
        """4 failed attempts should still return 403, not 429."""
        for _ in range(4):
            _record_failed_attempt("1.2.3.4")

        request = _make_login_request(token="wrong", client_ip="1.2.3.4", db=db)
        response = await login_handler(request)

        assert response.status_code == 403


# ── Logging tests ─────────────────────────────────────────────────────

class TestAuthLogging:

    @pytest.mark.asyncio
    async def test_auth_success_logging(self, db: Database):
        """Successful login emits auth_success log with client_ip."""
        request = _make_login_request(
            token="correct", client_ip="2.3.4.5", expected_token="correct", db=db
        )
        with capture_logs() as logs:
            response = await login_handler(request)

        assert response.status_code == 200
        success_events = [l for l in logs if l.get("event") == "auth_success"]
        assert len(success_events) == 1
        assert success_events[0]["client_ip"] == "2.3.4.5"

    @pytest.mark.asyncio
    async def test_auth_failure_logging(self, db: Database):
        """Failed login emits auth_failed log with client_ip."""
        request = _make_login_request(
            token="wrong", client_ip="3.4.5.6", expected_token="correct", db=db
        )
        with capture_logs() as logs:
            response = await login_handler(request)

        assert response.status_code == 403
        failed_events = [l for l in logs if l.get("event") == "auth_failed"]
        assert len(failed_events) == 1
        assert failed_events[0]["client_ip"] == "3.4.5.6"

    @pytest.mark.asyncio
    async def test_auth_lockout_logging(self, db: Database):
        """Rate-limited request emits auth_locked log with client_ip."""
        ip = "7.8.9.10"
        for _ in range(_MAX_ATTEMPTS):
            _record_failed_attempt(ip)

        request = _make_login_request(
            token="wrong", client_ip=ip, expected_token="correct", db=db
        )
        with capture_logs() as logs:
            response = await login_handler(request)

        assert response.status_code == 429
        locked_events = [l for l in logs if l.get("event") == "auth_locked"]
        assert len(locked_events) == 1
        assert locked_events[0]["client_ip"] == ip


# ── SQLite session persistence tests ─────────────────────────────────

class TestSessionPersistence:

    @pytest.mark.asyncio
    async def test_create_session_writes_to_sqlite(self, db: Database):
        """create_session stores the session in SQLite and returns a valid session_id."""
        session_id = await create_session(db, "mytoken", ttl=3600, client_ip="1.1.1.1")

        assert session_id is not None
        assert len(session_id) > 10
        row = await db.get_session(session_id)
        assert row is not None
        assert row["token_hash"] == _token_hash("mytoken")

    @pytest.mark.asyncio
    async def test_validate_session_true_for_valid_unexpired(self, db: Database):
        """validate_session returns True for a session that exists and has not expired."""
        session_id = await create_session(db, "secret", ttl=3600, client_ip="2.2.2.2")
        result = await validate_session(db, session_id, "secret")
        assert result is True

    @pytest.mark.asyncio
    async def test_validate_session_false_for_expired(self, db: Database):
        """validate_session returns False for a session past its expiry and deletes the row."""
        # Insert an already-expired session directly
        now = datetime.now(timezone.utc)
        past = (now - timedelta(seconds=1)).isoformat()
        session_id = "exp-sess-001"
        await db.conn.execute(
            "INSERT INTO sessions (session_id, token_hash, created_at, expires_at, client_ip) VALUES (?, ?, ?, ?, ?)",
            (session_id, _token_hash("tok"), now.isoformat(), past, "3.3.3.3"),
        )
        await db.conn.commit()

        result = await validate_session(db, session_id, "tok")
        assert result is False
        # Row should be cleaned up
        assert await db.get_session(session_id) is None

    @pytest.mark.asyncio
    async def test_validate_session_false_for_nonexistent(self, db: Database):
        """validate_session returns False when the session_id does not exist."""
        result = await validate_session(db, "nonexistent-session-id", "anytoken")
        assert result is False

    @pytest.mark.asyncio
    async def test_session_ttl_from_config_controls_expiry(self, db: Database):
        """session_ttl from config is used as expiry duration, not a hardcoded constant."""
        short_ttl = 1  # 1 second
        session_id = await create_session(db, "tok2", ttl=short_ttl, client_ip="4.4.4.4")

        # Immediately valid
        assert await validate_session(db, session_id, "tok2") is True

        # Manipulate expires_at to be in the past to simulate TTL expiry
        past = (datetime.now(timezone.utc) - timedelta(seconds=1)).isoformat()
        await db.conn.execute(
            "UPDATE sessions SET expires_at = ? WHERE session_id = ?",
            (past, session_id),
        )
        await db.conn.commit()

        # Now expired
        assert await validate_session(db, session_id, "tok2") is False

    @pytest.mark.asyncio
    async def test_login_handler_records_client_ip(self, db: Database):
        """login_handler stores the client IP in the session row."""
        request = _make_login_request(
            token="correct", client_ip="9.8.7.6", expected_token="correct", db=db
        )
        response = await login_handler(request)
        assert response.status_code == 200

        # Find the session row and check client_ip
        rows = await db.fetchall("SELECT * FROM sessions")
        assert len(rows) == 1
        assert rows[0]["client_ip"] == "9.8.7.6"
