"""Tests for traffic shaping — response timing normalization (TimingConfig).

Timing normalization adds a random delay to every response to defeat
side-channel timing analysis that would otherwise let blue team distinguish
proxied vs. locally-generated (drop) responses.
"""

from __future__ import annotations

import asyncio
import time
from ipaddress import ip_address
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from infraguard.config.schema import (
    DomainConfig,
    DropActionConfig,
    InfraGuardConfig,
    ListenerConfig,
    PipelineConfig,
    TimingConfig,
)
from infraguard.models.common import FilterResult


# ── TimingConfig schema ───────────────────────────────────────────────────

class TestTimingConfigSchema:
    def test_defaults(self):
        cfg = TimingConfig()
        assert cfg.enabled is False
        assert cfg.min_delay_ms == 50
        assert cfg.max_delay_ms == 200

    def test_custom_values(self):
        cfg = TimingConfig(enabled=True, min_delay_ms=10, max_delay_ms=50)
        assert cfg.enabled is True
        assert cfg.min_delay_ms == 10
        assert cfg.max_delay_ms == 50

    def test_integrated_into_infraguard_config(self):
        cfg = InfraGuardConfig(
            timing=TimingConfig(enabled=True, min_delay_ms=100, max_delay_ms=500)
        )
        assert cfg.timing.enabled is True
        assert cfg.timing.min_delay_ms == 100
        assert cfg.timing.max_delay_ms == 500


# ── Timing jitter application in router ──────────────────────────────────

class TestTimingJitterApplication:
    """Verify that the router applies jitter when TimingConfig is enabled."""

    def _make_router(self, timing: TimingConfig):
        """Build a DomainRouter with a mocked profile and one route."""
        from infraguard.core.router import DomainRouter

        config = InfraGuardConfig(
            listeners=[ListenerConfig(protocol="https", bind="127.0.0.1", port=8443)],
            domains={
                "test.local": DomainConfig(
                    upstream="https://127.0.0.1:9999",
                    profile_path="examples/jquery-c2.3.14.profile",
                    profile_type="cobalt_strike",
                    drop_action=DropActionConfig(type="redirect", target="https://example.com"),
                ),
            },
            pipeline=PipelineConfig(block_score_threshold=0.7),
            timing=timing,
        )
        with patch("infraguard.core.router.DomainRouter._load_profile", return_value=MagicMock()):
            router = DomainRouter(config)
        return router

    @pytest.mark.asyncio
    async def test_jitter_applied_when_enabled(self):
        """Enabled timing → asyncio.sleep is called with a value in the configured range."""
        router = self._make_router(TimingConfig(enabled=True, min_delay_ms=10, max_delay_ms=20))

        sleep_calls: list[float] = []
        real_sleep = asyncio.sleep

        async def fake_sleep(seconds):
            sleep_calls.append(seconds)

        # Build a minimal fake request that resolves to our domain
        request = MagicMock()
        request.headers = {"host": "test.local"}
        request.url.path = "/nonexistent"  # will be dropped
        request.url.query = ""
        request.method = "GET"
        request.client = MagicMock()
        request.client.host = "1.2.3.4"
        request.body = AsyncMock(return_value=b"")
        request.cookies = {}
        request.query_params = {}
        request.state = MagicMock(ja3=None)

        # Patch pipeline to allow the request through so we exercise the timing code
        from infraguard.pipeline.base import PipelineResult
        allow_result = PipelineResult(allowed=True, total_score=0.0, results=[], duration_ms=1.0)

        async def fake_evaluate(ctx):
            return allow_result

        for route in router.routes.values():
            route.pipeline.evaluate = fake_evaluate

        # Patch proxy.forward to return a minimal response without network
        from starlette.responses import Response

        async def fake_forward(*args, **kwargs):
            return Response(content=b"ok", status_code=200)

        router.proxy.forward = fake_forward

        with patch("infraguard.core.router.asyncio.sleep", side_effect=fake_sleep):
            with patch("infraguard.core.router.random.randint", return_value=15):
                response = await router.handle(request)

        # Jitter of 15ms = 0.015s sleep should have been scheduled
        assert 0.015 in sleep_calls

    @pytest.mark.asyncio
    async def test_no_jitter_when_disabled(self):
        """Disabled timing → asyncio.sleep is NOT called for jitter."""
        router = self._make_router(TimingConfig(enabled=False))

        sleep_calls: list[float] = []

        async def fake_sleep(seconds):
            sleep_calls.append(seconds)

        request = MagicMock()
        request.headers = {"host": "test.local"}
        request.url.path = "/nonexistent"
        request.url.query = ""
        request.method = "GET"
        request.client = MagicMock()
        request.client.host = "1.2.3.4"
        request.body = AsyncMock(return_value=b"")
        request.cookies = {}
        request.query_params = {}
        request.state = MagicMock(ja3=None)

        from infraguard.pipeline.base import PipelineResult
        allow_result = PipelineResult(allowed=True, total_score=0.0, results=[], duration_ms=1.0)

        async def fake_evaluate(ctx):
            return allow_result

        for route in router.routes.values():
            route.pipeline.evaluate = fake_evaluate

        from starlette.responses import Response

        async def fake_forward(*args, **kwargs):
            return Response(content=b"ok", status_code=200)

        router.proxy.forward = fake_forward

        with patch("infraguard.core.router.asyncio.sleep", side_effect=fake_sleep):
            response = await router.handle(request)

        assert sleep_calls == []

    @pytest.mark.asyncio
    async def test_jitter_within_configured_range(self):
        """The jitter value picked is always within [min_delay_ms, max_delay_ms]."""
        router = self._make_router(TimingConfig(enabled=True, min_delay_ms=50, max_delay_ms=200))

        captured_randint_ranges: list[tuple[int, int]] = []

        real_randint = __import__("random").randint

        def spy_randint(lo, hi):
            captured_randint_ranges.append((lo, hi))
            return lo  # always pick lower bound for determinism

        request = MagicMock()
        request.headers = {"host": "test.local"}
        request.url.path = "/nonexistent"
        request.url.query = ""
        request.method = "GET"
        request.client = MagicMock()
        request.client.host = "1.2.3.4"
        request.body = AsyncMock(return_value=b"")
        request.cookies = {}
        request.query_params = {}
        request.state = MagicMock(ja3=None)

        from infraguard.pipeline.base import PipelineResult
        allow_result = PipelineResult(allowed=True, total_score=0.0, results=[], duration_ms=1.0)

        async def fake_evaluate(ctx):
            return allow_result

        for route in router.routes.values():
            route.pipeline.evaluate = fake_evaluate

        from starlette.responses import Response

        async def fake_forward(*args, **kwargs):
            return Response(content=b"ok", status_code=200)

        router.proxy.forward = fake_forward

        with patch("infraguard.core.router.random.randint", side_effect=spy_randint):
            with patch("infraguard.core.router.asyncio.sleep", new=AsyncMock()):
                await router.handle(request)

        # random.randint was called with the configured bounds
        assert (50, 200) in captured_randint_ranges


# ── Timing behavior invariants ────────────────────────────────────────────

class TestTimingInvariants:
    """Higher-level invariants: timing normalization applies uniformly."""

    def test_min_less_than_max_validation(self):
        """Schema allows min <= max but doesn't enforce; behavior test pins the assumption."""
        cfg = TimingConfig(min_delay_ms=100, max_delay_ms=200)
        assert cfg.min_delay_ms <= cfg.max_delay_ms

    def test_zero_jitter_allowed(self):
        """min=max=0 is a valid configuration (no jitter despite enabled)."""
        cfg = TimingConfig(enabled=True, min_delay_ms=0, max_delay_ms=0)
        assert cfg.enabled is True
