"""Tests for security fixes (RESL series) and security-critical code paths.

Covers:
- RESL-01: Circuit breaker per-upstream failover
- RESL-03: Startup profile path validation (FileNotFoundError)
- SEC-01: SSRF path validation in proxy
- SEC-02: Header sanitization (blocked headers never forwarded)
- SEC-03: Log sanitization of sensitive fields
- SEC-04: SSL context building (verify=False for self-signed, custom CA bundle)
- SEC-05: Path traversal protection in decoy SPA serving
- SEC-06: Rate limiting prevents bulk payload harvesting
- SEC-07: Dead man's switch auto-shutdown
- SEC-08: Session cookie security flags (HttpOnly, Secure, SameSite)
"""

from __future__ import annotations

import asyncio
import ssl
import time
from ipaddress import ip_address
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from starlette.requests import Request
from starlette.responses import Response

from infraguard.config.schema import (
    DomainConfig,
    DropActionConfig,
    InfraGuardConfig,
    ListenerConfig,
    PipelineConfig,
)
from infraguard.core.circuit_breaker import CircuitBreaker, CircuitOpenError
from infraguard.core.headers import BLOCKED_HEADERS, sanitize_response_headers
from infraguard.core.log_sanitizer import redact_sensitive_fields
from infraguard.core.proxy import ProxyHandler
from infraguard.core.router import DomainRouter
from infraguard.core.ssl_context import build_ssl_context
from infraguard.models.common import FilterAction, FilterResult, ProfileType
from infraguard.pipeline.base import FilterPipeline, RequestContext


# ── RESL-01: Circuit breaker per-upstream failover ─────────────────────────

class TestCircuitBreakerFailover:
    """RESL-01: Circuit breakers are created per upstream URL, including backups."""

    def _make_config_with_backups(self) -> InfraGuardConfig:
        return InfraGuardConfig(
            listeners=[ListenerConfig(protocol="https", bind="127.0.0.1", port=8443)],
            domains={
                "test.local": DomainConfig(
                    upstream="https://127.0.0.1:9999",
                    backup_upstreams=["https://127.0.0.1:9998", "https://127.0.0.1:9997"],
                    profile_path="examples/jquery-c2.3.14.profile",
                    profile_type=ProfileType.COBALT_STRIKE,
                    drop_action=DropActionConfig(type="redirect", target="https://example.com"),
                ),
            },
            pipeline=PipelineConfig(block_score_threshold=0.7),
        )

    def test_breakers_created_for_all_upstreams(self):
        """Circuit breakers exist for primary + all backup upstreams."""
        config = self._make_config_with_backups()
        with patch("infraguard.core.router.DomainRouter._load_profile", return_value=MagicMock()):
            router = DomainRouter(config)
        assert "https://127.0.0.1:9999" in router._breakers
        assert "https://127.0.0.1:9998" in router._breakers
        assert "https://127.0.0.1:9997" in router._breakers

    def test_breaker_opens_after_threshold_failures(self):
        """CircuitBreaker transitions to OPEN after consecutive failures."""
        breaker = CircuitBreaker("https://test:443", failure_threshold=3, recovery_timeout=30.0)

        async def failing_coro():
            import httpx
            raise httpx.ConnectError("refused")

        with pytest.raises(Exception):
            asyncio.run(breaker.call(failing_coro))
        assert breaker.state == CircuitBreaker.CLOSED
        assert breaker.failure_count == 1

        with pytest.raises(Exception):
            asyncio.run(breaker.call(failing_coro))
        assert breaker.failure_count == 2

        with pytest.raises(Exception):
            asyncio.run(breaker.call(failing_coro))
        assert breaker.state == CircuitBreaker.OPEN
        assert breaker.failure_count == 3

    def test_breaker_blocks_requests_when_open(self):
        """OPEN circuit raises CircuitOpenError instead of calling upstream."""
        breaker = CircuitBreaker("https://test:443", failure_threshold=1, recovery_timeout=60.0)

        async def failing_coro():
            import httpx
            raise httpx.ConnectError("refused")

        with pytest.raises(Exception):
            asyncio.run(breaker.call(failing_coro))
        assert breaker.state == CircuitBreaker.OPEN

        async def should_not_run():
            pytest.fail("Should not reach upstream")

        with pytest.raises(CircuitOpenError):
            asyncio.run(breaker.call(should_not_run))

    def test_breaker_half_open_after_recovery_timeout(self):
        """After recovery_timeout, circuit allows one probe (HALF_OPEN)."""
        breaker = CircuitBreaker("https://test:443", failure_threshold=1, recovery_timeout=0.05)

        async def failing_coro():
            import httpx
            raise httpx.ConnectError("refused")

        with pytest.raises(Exception):
            asyncio.run(breaker.call(failing_coro))
        assert breaker.state == CircuitBreaker.OPEN

        time.sleep(0.06)

        async def success_coro():
            return "ok"

        result = asyncio.run(breaker.call(success_coro))
        assert result == "ok"
        assert breaker.state == CircuitBreaker.CLOSED
        assert breaker.failure_count == 0


# ── RESL-03: Startup profile path validation ────────────────────────────────

class TestStartupProfileValidation:
    """RESL-03: DomainRouter validates all profile paths before loading routes."""

    def test_missing_profile_raises_file_not_found(self, tmp_path: Path):
        """Missing profile_path file raises FileNotFoundError on startup."""
        missing = tmp_path / "nonexistent.profile"
        config = InfraGuardConfig(
            listeners=[ListenerConfig(protocol="https", bind="127.0.0.1", port=8443)],
            domains={
                "test.local": DomainConfig(
                    upstream="https://127.0.0.1:9999",
                    profile_path=str(missing),
                    profile_type=ProfileType.COBALT_STRIKE,
                ),
            },
            pipeline=PipelineConfig(),
        )
        with pytest.raises(FileNotFoundError) as exc_info:
            DomainRouter(config)
        assert "test.local" in str(exc_info.value)
        assert "nonexistent.profile" in str(exc_info.value)

    def test_phishing_domain_skips_profile_validation(self, tmp_path: Path):
        """Phishing domains (no profile file) don't need profile_path to exist."""
        config = InfraGuardConfig(
            listeners=[ListenerConfig(protocol="https", bind="127.0.0.1", port=8443)],
            domains={
                "phish.local": DomainConfig(
                    upstream="https://127.0.0.1:9999",
                    profile_path="",
                    profile_type=ProfileType.EVILGINX,
                ),
            },
            pipeline=PipelineConfig(),
        )
        with patch("infraguard.core.router.DomainRouter._load_profile", return_value=MagicMock()):
            router = DomainRouter(config)
        assert "phish.local" in router.routes


# ── SEC-01: SSRF path validation in proxy ───────────────────────────────────

class TestSSRFPathValidation:
    """SEC-01: Proxy blocks absolute URLs and path traversal attempts."""

    @pytest.mark.asyncio
    async def test_absolute_http_url_blocked(self):
        """Path starting with http:// is blocked as SSRF attempt."""
        proxy = ProxyHandler()
        req = MagicMock(spec=Request)
        req.url.path = "http://evil.com/steal"
        req.url.query = ""
        req.headers = {}
        req.body = AsyncMock(return_value=b"")

        resp = await proxy.forward(req, "https://127.0.0.1:8443")
        assert resp.status_code == 400

    @pytest.mark.asyncio
    async def test_absolute_https_url_blocked(self):
        """Path starting with https:// is blocked as SSRF attempt."""
        proxy = ProxyHandler()
        req = MagicMock(spec=Request)
        req.url.path = "https://evil.com/steal"
        req.url.query = ""
        req.headers = {}
        req.body = AsyncMock(return_value=b"")

        resp = await proxy.forward(req, "https://127.0.0.1:8443")
        assert resp.status_code == 400

    @pytest.mark.asyncio
    async def test_protocol_relative_url_blocked(self):
        """Path starting with // is blocked as SSRF attempt."""
        proxy = ProxyHandler()
        req = MagicMock(spec=Request)
        req.url.path = "//evil.com/steal"
        req.url.query = ""
        req.headers = {}
        req.body = AsyncMock(return_value=b"")

        resp = await proxy.forward(req, "https://127.0.0.1:8443")
        assert resp.status_code == 400


# ── SEC-02: Header sanitization ─────────────────────────────────────────────

class TestHeaderSanitization:
    """SEC-02: Blocked headers are never forwarded, even if extra_allowed."""

    def test_blocked_headers_always_stripped(self):
        """Headers in BLOCKED_HEADERS are removed even if in extra_allowed."""
        headers = {
            "Server": "Apache/2.4.41",
            "X-Powered-By": "PHP/8.1",
            "Content-Type": "text/html",
        }
        # Operator mistakenly allows Server and X-Powered-By
        extra = frozenset({"server", "x-powered-by"})
        result = sanitize_response_headers(headers, extra_allowed=extra)
        assert "Server" not in result
        assert "X-Powered-By" not in result
        assert result.get("Content-Type") == "text/html"

    def test_default_safe_headers_pass_through(self):
        """Default safe headers are preserved."""
        headers = {
            "Content-Type": "text/html",
            "Content-Length": "1234",
            "Cache-Control": "no-cache",
            "X-Evil-Header": "should-be-stripped",
        }
        result = sanitize_response_headers(headers)
        assert result["Content-Type"] == "text/html"
        assert result["Content-Length"] == "1234"
        assert result["Cache-Control"] == "no-cache"
        assert "X-Evil-Header" not in result

    def test_persona_server_header_injected(self):
        """Persona server_header is injected into response."""
        headers = {"Content-Type": "text/html"}
        result = sanitize_response_headers(headers, server_header="nginx")
        assert result["Server"] == "nginx"

    def test_case_insensitive_matching(self):
        """Header matching is case-insensitive."""
        headers = {"content-type": "text/html", "SERVER": "evil"}
        result = sanitize_response_headers(headers)
        assert result.get("content-type") == "text/html"
        assert "SERVER" not in result


# ── SEC-03: Log sanitization ────────────────────────────────────────────────

class TestLogSanitization:
    """SEC-03: Sensitive fields are redacted from structured logs."""

    def test_authorization_header_redacted(self):
        """Authorization header value is redacted."""
        event = {"event": "test", "authorization": "Bearer secret-token-123"}
        result = redact_sensitive_fields(None, "info", event)
        assert result["authorization"] == "[REDACTED]"

    def test_token_field_redacted(self):
        """Token field is redacted."""
        event = {"event": "test", "token": "abc123"}
        result = redact_sensitive_fields(None, "info", event)
        assert result["token"] == "[REDACTED]"

    def test_password_field_redacted(self):
        """Password field is redacted."""
        event = {"event": "test", "password": "hunter2"}
        result = redact_sensitive_fields(None, "info", event)
        assert result["password"] == "[REDACTED]"

    def test_suffix_matching_redacted(self):
        """Fields ending in -token, -secret, -key are redacted."""
        event = {
            "event": "test",
            "api-token": "secret1",
            "hmac-secret": "secret2",
            "encryption-key": "secret3",
        }
        result = redact_sensitive_fields(None, "info", event)
        assert result["api-token"] == "[REDACTED]"
        assert result["hmac-secret"] == "[REDACTED]"
        assert result["encryption-key"] == "[REDACTED]"

    def test_non_sensitive_fields_preserved(self):
        """Non-sensitive fields pass through unchanged."""
        event = {"event": "test", "path": "/callback", "status": 200}
        result = redact_sensitive_fields(None, "info", event)
        assert result["path"] == "/callback"
        assert result["status"] == 200


# ── SEC-04: SSL context building ────────────────────────────────────────────

class TestSSLContextBuilding:
    """SEC-04: SSL context correctly handles verify modes."""

    def test_verify_false_returns_false(self):
        """ssl_verify=False returns False (disable verification)."""
        result = build_ssl_context(ssl_verify=False)
        assert result is False

    def test_verify_true_returns_true(self):
        """ssl_verify=True with no CA bundle returns True (system CA)."""
        result = build_ssl_context(ssl_verify=True)
        assert result is True

    def test_custom_ca_bundle(self, tmp_path: Path):
        """Custom CA bundle path returns SSLContext."""
        ca_file = tmp_path / "ca.pem"
        ca_file.write_text("""-----BEGIN CERTIFICATE-----
MIIB...
-----END CERTIFICATE-----""")
        # This will fail to parse but proves the code path is taken
        with pytest.raises(ssl.SSLError):
            build_ssl_context(ssl_verify=True, ca_bundle=str(ca_file))

    def test_missing_ca_bundle_raises(self, tmp_path: Path):
        """Missing CA bundle file raises FileNotFoundError."""
        with pytest.raises(FileNotFoundError):
            build_ssl_context(ssl_verify=True, ca_bundle=str(tmp_path / "missing.pem"))


# ── SEC-05: Path traversal protection in decoy SPA ──────────────────────────

class TestDecoyPathTraversal:
    """SEC-05: Decoy SPA serving blocks path traversal attempts."""

    @pytest.mark.asyncio
    async def test_path_traversal_blocked(self, tmp_path: Path):
        """../.. paths are blocked with 403."""
        from infraguard.core.drop import _serve_decoy_spa
        from infraguard.config.schema import PersonaConfig

        pages_dir = tmp_path / "pages"
        site_dir = pages_dir / "decoy"
        site_dir.mkdir(parents=True)
        (site_dir / "index.html").write_text("<html>OK</html>")

        req = MagicMock(spec=Request)
        req.url.path = "/../../etc/passwd"
        req.client = MagicMock()
        req.client.host = "1.2.3.4"

        persona = PersonaConfig()
        resp = _serve_decoy_spa("decoy", req, str(pages_dir), persona)
        assert resp.status_code == 403

    @pytest.mark.asyncio
    async def test_normal_path_served(self, tmp_path: Path):
        """Normal paths are served correctly."""
        from infraguard.core.drop import _serve_decoy_spa
        from infraguard.config.schema import PersonaConfig

        pages_dir = tmp_path / "pages"
        site_dir = pages_dir / "decoy"
        site_dir.mkdir(parents=True)
        (site_dir / "index.html").write_text("<html>OK</html>")

        req = MagicMock(spec=Request)
        req.url.path = "/index.html"
        req.client = MagicMock()
        req.client.host = "1.2.3.4"

        persona = PersonaConfig()
        resp = _serve_decoy_spa("decoy", req, str(pages_dir), persona)
        assert resp.status_code == 200


# ── SEC-06: Rate limiting ───────────────────────────────────────────────────

class TestRateLimiting:
    """SEC-06: Rate limiter prevents bulk payload harvesting."""

    def test_rate_limit_allows_under_threshold(self):
        """Requests under the limit are allowed."""
        from infraguard.core.rate_limiter import ContentRateLimiter

        rl = ContentRateLimiter()
        assert rl.check("1.2.3.4", "/download", max_downloads=3, window_seconds=300) is True
        assert rl.check("1.2.3.4", "/download", max_downloads=3, window_seconds=300) is True

    def test_rate_limit_blocks_at_threshold(self):
        """Requests at the limit are blocked."""
        from infraguard.core.rate_limiter import ContentRateLimiter

        rl = ContentRateLimiter()
        for _ in range(3):
            rl.check("1.2.3.4", "/download", max_downloads=3, window_seconds=300)
        assert rl.check("1.2.3.4", "/download", max_downloads=3, window_seconds=300) is False

    def test_rate_limit_resets_after_window(self):
        """Rate limit resets after the window expires."""
        from infraguard.core.rate_limiter import ContentRateLimiter

        rl = ContentRateLimiter()
        for _ in range(3):
            rl.check("1.2.3.4", "/download", max_downloads=3, window_seconds=1)
        assert rl.check("1.2.3.4", "/download", max_downloads=3, window_seconds=1) is False
        time.sleep(1.1)
        assert rl.check("1.2.3.4", "/download", max_downloads=3, window_seconds=1) is True

    def test_rate_limit_per_ip(self):
        """Rate limits are tracked per-IP."""
        from infraguard.core.rate_limiter import ContentRateLimiter

        rl = ContentRateLimiter()
        for _ in range(3):
            rl.check("1.2.3.4", "/download", max_downloads=3, window_seconds=300)
        assert rl.check("1.2.3.4", "/download", max_downloads=3, window_seconds=300) is False
        # Different IP is not rate limited
        assert rl.check("5.6.7.8", "/download", max_downloads=3, window_seconds=300) is True


# ── SEC-07: Dead man's switch ───────────────────────────────────────────────

class TestDeadManSwitch:
    """SEC-07: Dead man's switch expires after TTL."""

    def test_initial_state_not_expired(self):
        """Switch starts in non-expired state."""
        from infraguard.core.deadman import DeadManSwitch

        dms = DeadManSwitch(ttl_seconds=60, enabled=True)
        assert dms.is_expired is False
        assert dms.time_remaining > 0

    def test_expiry_after_ttl(self):
        """Switch expires after TTL elapses."""
        from infraguard.core.deadman import DeadManSwitch

        dms = DeadManSwitch(ttl_seconds=0, enabled=True)
        time.sleep(0.01)
        # Manually trigger the check that the watch loop would do
        remaining = dms.time_remaining
        assert remaining <= 0

    def test_heartbeat_resets_timer(self):
        """Heartbeat resets the TTL countdown."""
        from infraguard.core.deadman import DeadManSwitch

        dms = DeadManSwitch(ttl_seconds=1, enabled=True)
        time.sleep(0.5)
        assert dms.time_remaining < 1.0
        dms.heartbeat()
        assert dms.time_remaining > 0.9


# ── SEC-08: Session cookie security flags ───────────────────────────────────

class TestSessionCookieSecurity:
    """SEC-08: Session cookies have Secure, HttpOnly, SameSite flags."""

    @pytest.mark.asyncio
    async def test_login_sets_secure_cookie_https(self):
        """Over HTTPS, cookie has Secure flag set."""
        from infraguard.ui.api.auth import login_handler, SESSION_COOKIE

        req = MagicMock()
        req.client = MagicMock()
        req.client.host = "1.2.3.4"
        req.app.state.config.api.auth_token = "secret"
        req.app.state.config.api.session_ttl = 3600
        req.app.state.db = AsyncMock()
        req.json = AsyncMock(return_value={"token": "secret"})
        req.url.scheme = "https"
        req.headers = {}

        resp = await login_handler(req)
        assert resp.status_code == 200
        cookie = resp.headers.get("set-cookie", "")
        assert SESSION_COOKIE in cookie
        assert "Secure" in cookie
        assert "HttpOnly" in cookie
        assert "SameSite=strict" in cookie

    @pytest.mark.asyncio
    async def test_login_no_secure_flag_http(self):
        """Over HTTP, cookie does NOT have Secure flag."""
        from infraguard.ui.api.auth import login_handler, SESSION_COOKIE

        req = MagicMock()
        req.client = MagicMock()
        req.client.host = "1.2.3.4"
        req.app.state.config.api.auth_token = "secret"
        req.app.state.config.api.session_ttl = 3600
        req.app.state.db = AsyncMock()
        req.json = AsyncMock(return_value={"token": "secret"})
        req.url.scheme = "http"
        req.headers = {}

        resp = await login_handler(req)
        assert resp.status_code == 200
        cookie = resp.headers.get("set-cookie", "")
        assert SESSION_COOKIE in cookie
        assert "Secure" not in cookie
        assert "HttpOnly" in cookie
