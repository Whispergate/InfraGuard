"""Tests for DomainRouter content route ordering and IP blocklist check."""

from __future__ import annotations

import asyncio
from ipaddress import ip_address
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from infraguard.config.schema import (
    ContentBackendConfig,
    ContentRouteConfig,
    DomainConfig,
    DropActionConfig,
    InfraGuardConfig,
    PipelineConfig,
)
from infraguard.models.common import ContentBackendType


# ── Helpers ───────────────────────────────────────────────────────────

def _make_request(
    path: str = "/static/file.css",
    host: str = "test.local",
    client_ip: str = "1.2.3.4",
):
    """Create a mock Starlette request."""
    req = MagicMock()
    req.method = "GET"
    req.url.path = path
    req.url.query = ""
    req.headers = {"host": host}
    req.cookies = {}
    req.query_params = {}
    req.client = MagicMock()
    req.client.host = client_ip
    req.body = AsyncMock(return_value=b"")
    return req


def _make_config(content_route_filter: str = "ip_only") -> InfraGuardConfig:
    """Create a minimal InfraGuardConfig with content routes configured."""
    return InfraGuardConfig(
        domains={
            "test.local": DomainConfig(
                upstream="https://127.0.0.1:9999",
                profile_path="examples/jquery-c2.3.14.profile",
                profile_type="cobalt_strike",
                drop_action=DropActionConfig(type="redirect", target="https://example.com"),
                content_routes=[
                    ContentRouteConfig(
                        path="/static/*",
                        backend=ContentBackendConfig(
                            type=ContentBackendType.FILESYSTEM,
                            target="/var/www/static",
                        ),
                        track=False,
                    )
                ],
                content_route_filter=content_route_filter,
            )
        },
        pipeline=PipelineConfig(
            block_score_threshold=0.7,
            enable_ip_filter=False,
            enable_bot_filter=False,
            enable_header_filter=False,
            enable_dns_filter=False,
            enable_replay_filter=False,
        ),
    )


# ── Tests: content route filter ordering ─────────────────────────────

class TestContentRouteFilterOrdering:
    """Test that IP blocklist check runs before content route resolution."""

    @pytest.mark.asyncio
    async def test_blocked_ip_gets_drop_not_content(self):
        """Blocked IP matching a content route path must receive drop, not content."""
        config = _make_config()

        with patch("infraguard.core.router.IntelManager") as MockIntel, \
             patch("infraguard.core.router.ContentRouteResolver") as MockResolver, \
             patch("infraguard.core.router.handle_drop", new_callable=AsyncMock) as mock_drop:

            mock_intel = MockIntel.return_value
            # Simulate blocklist check: this IP is blocked
            mock_intel.is_blocked.return_value = True

            mock_resolver_inst = MockResolver.return_value
            # Content route matches the path
            mock_match = MagicMock()
            mock_match.domain = "test.local"
            mock_resolver_inst.match.return_value = mock_match

            from infraguard.core.router import DomainRouter

            router = DomainRouter(config)
            # Replace the resolver on the route directly
            route = router.routes["test.local"]
            route.content_resolver = mock_resolver_inst

            mock_drop.return_value = MagicMock(status_code=302)
            request = _make_request(path="/static/file.css", client_ip="1.2.3.4")

            response = await router.handle(request)

            # Drop must have been called
            mock_drop.assert_called_once()
            # Content resolver must NOT have been called with the IP blocked
            mock_resolver_inst.match.assert_not_called()

    @pytest.mark.asyncio
    async def test_allowed_ip_gets_content(self):
        """Non-blocked IP matching a content route must receive the content."""
        config = _make_config()

        with patch("infraguard.core.router.IntelManager") as MockIntel, \
             patch("infraguard.core.router.ContentRouteResolver") as MockResolver, \
             patch("infraguard.core.router.DomainRouter._handle_content_route", new_callable=AsyncMock) as mock_content:

            mock_intel = MockIntel.return_value
            # IP is not blocked
            mock_intel.is_blocked.return_value = False

            mock_resolver_inst = MockResolver.return_value
            mock_match = MagicMock()
            mock_match.domain = "test.local"
            mock_resolver_inst.match.return_value = mock_match

            from infraguard.core.router import DomainRouter

            router = DomainRouter(config)
            route = router.routes["test.local"]
            route.content_resolver = mock_resolver_inst

            mock_content.return_value = MagicMock(status_code=200)
            request = _make_request(path="/static/file.css", client_ip="5.6.7.8")

            response = await router.handle(request)

            # Content handler must have been called
            mock_content.assert_called_once()

    @pytest.mark.asyncio
    async def test_whitelisted_ip_gets_content(self):
        """Whitelisted IP matching a content route must receive content (not dropped)."""
        config = _make_config()

        with patch("infraguard.core.router.IntelManager") as MockIntel, \
             patch("infraguard.core.router.ContentRouteResolver") as MockResolver, \
             patch("infraguard.core.router.DomainRouter._handle_content_route", new_callable=AsyncMock) as mock_content:

            mock_intel = MockIntel.return_value
            # Whitelisted IP: is_blocked returns False
            mock_intel.is_blocked.return_value = False

            mock_resolver_inst = MockResolver.return_value
            mock_match = MagicMock()
            mock_match.domain = "test.local"
            mock_resolver_inst.match.return_value = mock_match

            from infraguard.core.router import DomainRouter

            router = DomainRouter(config)
            route = router.routes["test.local"]
            route.content_resolver = mock_resolver_inst

            mock_content.return_value = MagicMock(status_code=200)
            # Use an RFC1918 address (operators are usually on private networks)
            request = _make_request(path="/static/style.css", client_ip="192.168.1.100")

            response = await router.handle(request)

            mock_content.assert_called_once()

    @pytest.mark.asyncio
    async def test_full_pipeline_mode_blocks_before_content(self):
        """With content_route_filter='full_pipeline', pipeline evaluates before content resolution."""
        config = _make_config(content_route_filter="full_pipeline")

        with patch("infraguard.core.router.IntelManager") as MockIntel, \
             patch("infraguard.core.router.ContentRouteResolver") as MockResolver, \
             patch("infraguard.core.router.handle_drop", new_callable=AsyncMock) as mock_drop:

            mock_intel = MockIntel.return_value
            mock_intel.is_blocked.return_value = False  # ip_only not used in full_pipeline

            mock_resolver_inst = MockResolver.return_value
            mock_match = MagicMock()
            mock_match.domain = "test.local"
            mock_resolver_inst.match.return_value = mock_match

            from infraguard.core.router import DomainRouter
            from infraguard.pipeline.base import PipelineResult

            router = DomainRouter(config)
            route = router.routes["test.local"]
            route.content_resolver = mock_resolver_inst

            # Simulate pipeline blocking the request
            from infraguard.models.common import FilterResult, FilterAction
            block_filter_result = FilterResult(
                action=FilterAction.BLOCK,
                reason="bot detected",
                filter_name="bot",
                score=1.0,
            )
            blocked_result = PipelineResult(
                allowed=False,
                total_score=1.0,
                results=[block_filter_result],
                duration_ms=0.1,
            )
            route.pipeline.evaluate = AsyncMock(return_value=blocked_result)

            mock_drop.return_value = MagicMock(status_code=302)
            request = _make_request(path="/static/file.css", client_ip="10.0.0.5")

            response = await router.handle(request)

            # Drop must have been called due to pipeline block
            mock_drop.assert_called_once()
            # Content resolver must NOT have been called
            mock_resolver_inst.match.assert_not_called()

    @pytest.mark.asyncio
    async def test_full_pipeline_mode_allows_clean_request_to_content(self):
        """With content_route_filter='full_pipeline', clean requests reach content routes."""
        config = _make_config(content_route_filter="full_pipeline")

        with patch("infraguard.core.router.IntelManager") as MockIntel, \
             patch("infraguard.core.router.ContentRouteResolver") as MockResolver, \
             patch("infraguard.core.router.DomainRouter._handle_content_route", new_callable=AsyncMock) as mock_content:

            mock_intel = MockIntel.return_value

            mock_resolver_inst = MockResolver.return_value
            mock_match = MagicMock()
            mock_match.domain = "test.local"
            mock_resolver_inst.match.return_value = mock_match

            from infraguard.core.router import DomainRouter
            from infraguard.pipeline.base import PipelineResult

            router = DomainRouter(config)
            route = router.routes["test.local"]
            route.content_resolver = mock_resolver_inst

            # Pipeline allows the request
            allowed_result = PipelineResult(
                allowed=True,
                total_score=0.1,
                results=[],
                duration_ms=0.1,
            )
            route.pipeline.evaluate = AsyncMock(return_value=allowed_result)

            mock_content.return_value = MagicMock(status_code=200)
            request = _make_request(path="/static/file.css", client_ip="10.0.0.5")

            response = await router.handle(request)

            mock_content.assert_called_once()
