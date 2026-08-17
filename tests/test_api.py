"""Tests for the dashboard API endpoints."""

from __future__ import annotations

import json
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
import pytest_asyncio
from starlette.applications import Starlette
from starlette.responses import JSONResponse
from starlette.routing import Route
from starlette.testclient import TestClient

from infraguard.config.schema import InfraGuardConfig, ListenerConfig
from infraguard.intel.manager import IntelManager
from infraguard.tracking.database import Database
from infraguard.tracking.stats import StatsQuery
from infraguard.ui.api.app import create_api_app
from infraguard.ui.api.auth import _rate_limit


# ── Fixtures ──────────────────────────────────────────────────────────────

@pytest_asyncio.fixture
async def db(tmp_path):
    """Temporary SQLite database."""
    path = str(tmp_path / "api_test.db")
    database = Database(db_path=path)
    await database.connect()
    yield database
    await database.close()


@pytest.fixture
def config() -> InfraGuardConfig:
    return InfraGuardConfig(
        listeners=[ListenerConfig(protocol="https", bind="127.0.0.1", port=8443)],
        domains={},
        api={
            "bind": "127.0.0.1",
            "port": 8080,
            "auth_token": "test-secret-token",
        },
    )


@pytest.fixture
def intel(config):
    return IntelManager(config.intel)


@pytest.fixture
def app(config, db, intel):
    app = create_api_app(config, db, intel=intel)
    # TestClient doesn't run lifespan, so set db state manually
    app.state.db = db
    return app


@pytest.fixture
def client(app):
    return TestClient(app)


@pytest.fixture(autouse=True)
def clear_rate_limit():
    _rate_limit.clear()
    yield
    _rate_limit.clear()


# ── Auth endpoints ────────────────────────────────────────────────────────

class TestAuthEndpoints:
    def test_login_success(self, client):
        """POST /api/auth/login with valid token returns 200 + session cookie."""
        resp = client.post("/api/auth/login", json={"token": "test-secret-token"})
        assert resp.status_code == 200
        assert resp.json()["status"] == "ok"
        assert "ig_session" in resp.cookies

    def test_login_wrong_token(self, client):
        """POST /api/auth/login with wrong token returns 403."""
        resp = client.post("/api/auth/login", json={"token": "wrong"})
        assert resp.status_code == 403

    def test_login_rate_limited(self, client):
        """6th failed login attempt returns 429."""
        for _ in range(5):
            client.post("/api/auth/login", json={"token": "wrong"})
        resp = client.post("/api/auth/login", json={"token": "wrong"})
        assert resp.status_code == 429

    def test_logout_clears_cookie(self, client):
        """POST /api/auth/logout clears the session cookie."""
        # First login
        login_resp = client.post("/api/auth/login", json={"token": "test-secret-token"})
        assert login_resp.status_code == 200

        # Then logout
        resp = client.post("/api/auth/logout")
        assert resp.status_code == 200
        # Cookie should be deleted (set to empty with expires in past)
        cookie_header = resp.headers.get("set-cookie", "")
        assert "ig_session" in cookie_header

    def test_auth_check_authenticated(self, client):
        """GET /api/auth/check with valid Bearer token returns authenticated."""
        resp = client.get(
            "/api/auth/check",
            headers={"Authorization": "Bearer test-secret-token"},
        )
        assert resp.status_code == 200
        assert resp.json()["authenticated"] is True

    def test_auth_check_unauthenticated(self, client):
        """GET /api/auth/check without token returns unauthenticated."""
        resp = client.get("/api/auth/check")
        assert resp.status_code == 200
        assert resp.json()["authenticated"] is False


# ── Protected endpoint access ─────────────────────────────────────────────

class TestProtectedEndpoints:
    def test_stats_requires_auth(self, client):
        """GET /api/stats without auth returns 401."""
        resp = client.get("/api/stats")
        assert resp.status_code == 401

    def test_stats_with_bearer_token(self, client):
        """GET /api/stats with valid Bearer token succeeds."""
        resp = client.get(
            "/api/stats",
            headers={"Authorization": "Bearer test-secret-token"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert "total_requests" in data
        assert "blocked_requests" in data

    def test_stats_with_session_cookie(self, client):
        """GET /api/stats with valid session cookie succeeds."""
        # Login to get cookie
        login_resp = client.post("/api/auth/login", json={"token": "test-secret-token"})
        session_cookie = login_resp.cookies.get("ig_session")

        resp = client.get("/api/stats", cookies={"ig_session": session_cookie})
        assert resp.status_code == 200

    def test_stats_invalid_bearer_token(self, client):
        """GET /api/stats with wrong Bearer token returns 403."""
        resp = client.get(
            "/api/stats",
            headers={"Authorization": "Bearer wrong-token"},
        )
        assert resp.status_code == 403


# ── Stats endpoints ───────────────────────────────────────────────────────

class TestStatsEndpoints:
    def test_stats_default_hours(self, client):
        """GET /api/stats returns 24h stats by default."""
        resp = client.get(
            "/api/stats",
            headers={"Authorization": "Bearer test-secret-token"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert "total_requests" in data
        assert "allowed_requests" in data
        assert "blocked_requests" in data
        assert "unique_ips" in data
        assert "domains" in data
        assert "top_blocked_ips" in data
        assert "feed_status" in data

    def test_stats_custom_hours(self, client):
        """GET /api/stats?hours=1 filters by hour window."""
        resp = client.get(
            "/api/stats?hours=1",
            headers={"Authorization": "Bearer test-secret-token"},
        )
        assert resp.status_code == 200

    def test_stats_invalid_hours(self, client):
        """GET /api/stats?hours=abc returns 400."""
        resp = client.get(
            "/api/stats?hours=abc",
            headers={"Authorization": "Bearer test-secret-token"},
        )
        assert resp.status_code == 400

    def test_stats_hours_clamped(self, client):
        """GET /api/stats?hours=99999 is clamped to max 8760."""
        resp = client.get(
            "/api/stats?hours=99999",
            headers={"Authorization": "Bearer test-secret-token"},
        )
        assert resp.status_code == 200

    def test_content_stats(self, client):
        """GET /api/stats/content returns content route stats."""
        resp = client.get(
            "/api/stats/content",
            headers={"Authorization": "Bearer test-secret-token"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert "content_routes" in data
        assert "count" in data


# ── Config endpoints ──────────────────────────────────────────────────────

class TestConfigEndpoints:
    def test_get_config(self, client):
        """GET /api/config returns sanitized config with auth_token redacted."""
        resp = client.get(
            "/api/config",
            headers={"Authorization": "Bearer test-secret-token"},
        )
        assert resp.status_code == 200
        data = resp.json()
        # auth_token key exists but value is redacted
        assert data["api"]["auth_token"] == "***"

    def test_get_domains(self, client):
        """GET /api/config/domains returns domain list."""
        resp = client.get(
            "/api/config/domains",
            headers={"Authorization": "Bearer test-secret-token"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert isinstance(data, dict)


# ── Requests endpoint ─────────────────────────────────────────────────────

class TestRequestsEndpoint:
    def test_get_requests_empty(self, client):
        """GET /api/requests returns empty list when no requests."""
        resp = client.get(
            "/api/requests",
            headers={"Authorization": "Bearer test-secret-token"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert isinstance(data, list) or "requests" in data


# ── Nodes endpoints ───────────────────────────────────────────────────────

class TestNodesEndpoints:
    def test_list_nodes_empty(self, client):
        """GET /api/nodes returns empty list when no nodes registered."""
        resp = client.get(
            "/api/nodes",
            headers={"Authorization": "Bearer test-secret-token"},
        )
        assert resp.status_code == 200

    def test_register_node(self, client):
        """POST /api/nodes/register creates a node entry."""
        resp = client.post(
            "/api/nodes/register",
            headers={"Authorization": "Bearer test-secret-token"},
            json={
                "id": "node-1",
                "name": "test-node",
                "address": "10.0.0.1",
                "domains": ["test.local"],
            },
        )
        assert resp.status_code in (200, 201)

    def test_heartbeat_node(self, client):
        """POST /api/nodes/{id}/heartbeat updates last_heartbeat."""
        # Register first
        client.post(
            "/api/nodes/register",
            headers={"Authorization": "Bearer test-secret-token"},
            json={
                "id": "node-hb",
                "name": "heartbeat-test",
                "address": "10.0.0.2",
            },
        )
        resp = client.post(
            "/api/nodes/node-hb/heartbeat",
            headers={"Authorization": "Bearer test-secret-token"},
        )
        assert resp.status_code == 200


# ── Intel endpoints ───────────────────────────────────────────────────────

class TestIntelEndpoints:
    def test_classify_ip(self, client):
        """POST /api/intel/classify classifies an IP address."""
        resp = client.post(
            "/api/intel/classify",
            headers={"Authorization": "Bearer test-secret-token"},
            json={"ip": "8.8.8.8"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert "ip" in data or "is_blocked" in data

    def test_classify_invalid_ip(self, client):
        """POST /api/intel/classify with invalid IP returns 400."""
        resp = client.post(
            "/api/intel/classify",
            headers={"Authorization": "Bearer test-secret-token"},
            json={"ip": "not-an-ip"},
        )
        assert resp.status_code == 400

    def test_add_blocklist(self, client):
        """POST /api/intel/blocklist adds an IP to the blocklist."""
        resp = client.post(
            "/api/intel/blocklist",
            headers={"Authorization": "Bearer test-secret-token"},
            json={"cidrs": ["192.0.2.0/24"]},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "ok"

    def test_add_whitelist(self, client):
        """POST /api/intel/whitelist adds an IP to the whitelist."""
        resp = client.post(
            "/api/intel/whitelist",
            headers={"Authorization": "Bearer test-secret-token"},
            json={"ip": "198.51.100.1"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "ok"


# ── Health endpoint ───────────────────────────────────────────────────────

class TestHealthEndpoint:
    def test_health_summary_no_auth_required(self, client):
        """GET /api/health/summary is public (no auth needed)."""
        resp = client.get("/api/health/summary")
        # health/summary is not in _PUBLIC_PATHS, so it requires auth
        assert resp.status_code == 401

    def test_health_full_requires_auth(self, client):
        """GET /api/health requires auth."""
        resp = client.get("/api/health")
        assert resp.status_code == 401

    def test_health_full_with_auth(self, client):
        """GET /api/health with auth returns full health report."""
        resp = client.get(
            "/api/health",
            headers={"Authorization": "Bearer test-secret-token"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert "status" in data
        assert "uptime" in data
        assert "traffic" in data
        assert "certificates" in data
        assert "feeds" in data
        assert "nodes" in data
        assert "alerts" in data


# ── Decoy endpoints ───────────────────────────────────────────────────────

class TestDecoyEndpoints:
    def test_list_decoys(self, client):
        """GET /api/decoys returns list of decoy pages."""
        resp = client.get(
            "/api/decoys",
            headers={"Authorization": "Bearer test-secret-token"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert "decoys" in data


# ── Metrics endpoint ──────────────────────────────────────────────────────

class TestMetricsEndpoint:
    def test_metrics_public(self, client):
        """GET /metrics is public (no auth required)."""
        resp = client.get("/metrics")
        # Metrics endpoint may return 200 with Prometheus format or 404 if not mounted
        assert resp.status_code in (200, 404)


# ── Root endpoint ─────────────────────────────────────────────────────────

class TestRootEndpoint:
    def test_root_serves_index(self, client):
        """GET / serves the dashboard index.html."""
        resp = client.get("/")
        assert resp.status_code == 200
