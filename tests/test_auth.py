"""Tests for auth endpoint rate limiting and logging."""

from __future__ import annotations

import asyncio
import time
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
import structlog
from structlog.testing import capture_logs

from infraguard.ui.api.auth import (
    _MAX_ATTEMPTS,
    _RATE_WINDOW,
    _check_rate_limit,
    _rate_limit,
    _record_failed_attempt,
    login_handler,
)


# ── Fixtures ──────────────────────────────────────────────────────────

@pytest.fixture(autouse=True)
def clear_rate_limit():
    """Clear rate limit state before and after each test."""
    _rate_limit.clear()
    yield
    _rate_limit.clear()


def _make_login_request(
    token: str = "secret",
    client_ip: str = "1.2.3.4",
    expected_token: str = "secret",
) -> MagicMock:
    """Create a mock login request."""
    req = MagicMock()
    req.client = MagicMock()
    req.client.host = client_ip
    req.app.state.config.api.auth_token = expected_token
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
    async def test_rate_limit_returns_429_at_threshold(self):
        """6th failed attempt from same IP returns HTTP 429."""
        # Pre-populate with MAX_ATTEMPTS failed attempts
        for _ in range(_MAX_ATTEMPTS):
            _record_failed_attempt("1.2.3.4")

        request = _make_login_request(token="wrong", client_ip="1.2.3.4")
        response = await login_handler(request)

        assert response.status_code == 429

    @pytest.mark.asyncio
    async def test_rate_limit_allows_under_threshold_login(self):
        """4 failed attempts should still return 403, not 429."""
        for _ in range(4):
            _record_failed_attempt("1.2.3.4")

        request = _make_login_request(token="wrong", client_ip="1.2.3.4")
        response = await login_handler(request)

        assert response.status_code == 403


# ── Logging tests ─────────────────────────────────────────────────────

class TestAuthLogging:

    @pytest.mark.asyncio
    async def test_auth_success_logging(self):
        """Successful login emits auth_success log with client_ip."""
        request = _make_login_request(
            token="correct", client_ip="2.3.4.5", expected_token="correct"
        )
        with capture_logs() as logs:
            response = await login_handler(request)

        assert response.status_code == 200
        success_events = [l for l in logs if l.get("event") == "auth_success"]
        assert len(success_events) == 1
        assert success_events[0]["client_ip"] == "2.3.4.5"

    @pytest.mark.asyncio
    async def test_auth_failure_logging(self):
        """Failed login emits auth_failed log with client_ip."""
        request = _make_login_request(
            token="wrong", client_ip="3.4.5.6", expected_token="correct"
        )
        with capture_logs() as logs:
            response = await login_handler(request)

        assert response.status_code == 403
        failed_events = [l for l in logs if l.get("event") == "auth_failed"]
        assert len(failed_events) == 1
        assert failed_events[0]["client_ip"] == "3.4.5.6"

    @pytest.mark.asyncio
    async def test_auth_lockout_logging(self):
        """Rate-limited request emits auth_locked log with client_ip."""
        ip = "7.8.9.10"
        for _ in range(_MAX_ATTEMPTS):
            _record_failed_attempt(ip)

        request = _make_login_request(
            token="wrong", client_ip=ip, expected_token="correct"
        )
        with capture_logs() as logs:
            response = await login_handler(request)

        assert response.status_code == 429
        locked_events = [l for l in logs if l.get("event") == "auth_locked"]
        assert len(locked_events) == 1
        assert locked_events[0]["client_ip"] == ip
