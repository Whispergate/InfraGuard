"""Tests for persona-aware drop response handlers."""

from __future__ import annotations

import asyncio
import os
import tempfile
from enum import Enum
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from starlette.requests import Request
from starlette.responses import StreamingResponse
from starlette.testclient import TestClient

from infraguard.config.schema import DropActionConfig, PersonaConfig
from infraguard.core.drop import (
    _proxy_decoy,
    _serve_decoy_spa,
    _tarpit_response,
    handle_drop,
)
from infraguard.models.common import DropActionType


def _make_request(path: str = "/", host: str = "127.0.0.1") -> Request:
    """Create a minimal mock Request object for testing."""
    scope = {
        "type": "http",
        "method": "GET",
        "path": path,
        "query_string": b"",
        "headers": [(b"host", host.encode())],
        "client": (host, 12345),
    }
    return Request(scope)


# ---------------------------------------------------------------------------
# Fallback / persona 404
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_persona_fallback_404_default():
    """handle_drop DECOY with nonexistent site returns persona 404 not bare 'Not Found'."""
    request = _make_request()
    persona = PersonaConfig()
    config = DropActionConfig(type=DropActionType.DECOY, target="nonexistent_xyz")

    # Using a pages_dir that won't exist forces the SPA path to return a persona 404
    response = await handle_drop(request, config, pages_dir="/tmp/nonexistent_pages_xyz", persona=persona)

    assert response.status_code == 404
    assert response.headers.get("server") == "nginx"
    assert b"Not Found" != response.body  # Must NOT be bare b"Not Found"
    assert b"nginx" in response.body


@pytest.mark.asyncio
async def test_persona_custom_server_header():
    """handle_drop with custom persona (server_header='Apache/2.4') returns correct Server header."""
    request = _make_request()
    persona = PersonaConfig(server_header="Apache/2.4")
    config = DropActionConfig(type=DropActionType.DECOY, target="nonexistent_xyz")

    response = await handle_drop(request, config, pages_dir="/tmp/nonexistent_pages_xyz", persona=persona)

    assert response.status_code == 404
    assert response.headers.get("server") == "Apache/2.4"


# ---------------------------------------------------------------------------
# Tarpit - must return StreamingResponse
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_tarpit_returns_streaming():
    """_tarpit_response returns a StreamingResponse instance (not plain Response)."""
    persona = PersonaConfig()
    response = await _tarpit_response(persona)

    assert isinstance(response, StreamingResponse)
    assert response.status_code == 200


@pytest.mark.asyncio
async def test_tarpit_uses_persona_server_header():
    """_tarpit_response sets Server header from persona."""
    persona = PersonaConfig(server_header="Cloudflare")
    response = await _tarpit_response(persona)

    assert isinstance(response, StreamingResponse)
    assert response.headers.get("server") == "Cloudflare"


@pytest.mark.asyncio
async def test_tarpit_via_handle_drop():
    """handle_drop TARPIT action returns a StreamingResponse."""
    request = _make_request()
    persona = PersonaConfig()
    config = DropActionConfig(type=DropActionType.TARPIT, target="")

    response = await handle_drop(request, config, persona=persona)

    assert isinstance(response, StreamingResponse)


# ---------------------------------------------------------------------------
# Decoy SPA - persona 404 when site not found
# ---------------------------------------------------------------------------


def test_decoy_spa_missing_site_persona():
    """_serve_decoy_spa with nonexistent site returns persona 404, not bare 'Not Found'."""
    request = _make_request()
    persona = PersonaConfig()

    response = _serve_decoy_spa("nonexistent_site_xyz", request, "/tmp/empty_pages_dir_xyz", persona)

    assert response.status_code == 404
    assert response.headers.get("server") == "nginx"
    # Must NOT be the old bare "Not Found"
    assert response.body != b"Not Found"
    assert b"nginx" in response.body


def test_decoy_spa_missing_index_persona():
    """_serve_decoy_spa with existing dir but no index.html returns persona 404."""
    request = _make_request(path="/some/path")

    with tempfile.TemporaryDirectory() as tmpdir:
        site_dir = os.path.join(tmpdir, "mysite")
        os.makedirs(site_dir)
        # No index.html, so SPA fallback will hit persona 404

        persona = PersonaConfig(server_header="IIS/8.5")
        response = _serve_decoy_spa("mysite", request, tmpdir, persona)

        assert response.status_code == 404
        assert response.headers.get("server") == "IIS/8.5"


# ---------------------------------------------------------------------------
# Proxy decoy - persona error on connection failure
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_proxy_decoy_connection_failure_returns_persona_error():
    """_proxy_decoy returns persona-consistent error on connection failure."""
    import httpx

    request = _make_request()
    persona = PersonaConfig(server_header="nginx")

    with patch("infraguard.core.drop.httpx.AsyncClient") as MockClient:
        mock_client_instance = AsyncMock()
        MockClient.return_value.__aenter__ = AsyncMock(return_value=mock_client_instance)
        MockClient.return_value.__aexit__ = AsyncMock(return_value=False)
        mock_client_instance.get.side_effect = httpx.ConnectError("Connection refused")

        response = await _proxy_decoy("https://decoy.example.com", request, persona)

    # Should not be the old bare "Bad Gateway" style bare bytes
    assert response.status_code == 502
    assert response.headers.get("server") == "nginx"
    # Body should be persona HTML, not bare b"Bad Gateway"
    assert response.body != b"Bad Gateway"
