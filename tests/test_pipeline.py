"""Tests for the filter pipeline and individual filters."""

import asyncio
from ipaddress import ip_address
from unittest.mock import MagicMock, AsyncMock

import pytest

from infraguard.models.common import FilterAction, FilterResult
from infraguard.pipeline.base import FilterPipeline, PipelineResult, RequestContext
from infraguard.pipeline.bot_filter import BotFilter
from infraguard.pipeline.header_filter import HeaderFilter
from infraguard.pipeline.profile_filter import ProfileFilter
from infraguard.pipeline.replay_filter import ReplayFilter
from infraguard.config.schema import DomainConfig, DropActionConfig, PipelineConfig


def _make_request(
    method="GET",
    path="/callback",
    headers=None,
    cookies=None,
):
    """Create a mock Starlette Request."""
    req = MagicMock()
    req.method = method
    req.url.path = path
    req.headers = headers or {}
    req.cookies = cookies or {}
    req.query_params = {}
    return req


def _make_ctx(request, profile, body=b""):
    """Create a RequestContext for testing."""
    return RequestContext(
        request=request,
        client_ip=ip_address("192.168.1.100"),
        domain_config=DomainConfig(
            upstream="https://127.0.0.1:8443",
            profile_path="test.profile",
            profile_type="cobalt_strike",
        ),
        profile=profile,
        metadata={"body": body},
    )


# ── ProfileFilter ─────────────────────────────────────────────────────

class TestProfileFilter:
    @pytest.fixture
    def pf(self):
        return ProfileFilter()

    @pytest.mark.asyncio
    async def test_valid_get_request(self, pf, sample_profile):
        req = _make_request(
            method="GET",
            path="/callback",
            headers={
                "Accept": "text/html",
                "Host": "test.local",
                "user-agent": "TestAgent/1.0",
                "cookie": "session=abc123",
            },
            cookies={"session": "abc123"},
        )
        ctx = _make_ctx(req, sample_profile)
        result = await pf.check(ctx)
        assert result.action == FilterAction.ALLOW

    @pytest.mark.asyncio
    async def test_unknown_uri_blocked(self, pf, sample_profile):
        req = _make_request(path="/evil-scan")
        ctx = _make_ctx(req, sample_profile)
        result = await pf.check(ctx)
        assert result.action == FilterAction.BLOCK
        assert "not in profile" in result.reason

    @pytest.mark.asyncio
    async def test_wrong_method_blocked(self, pf, sample_profile):
        req = _make_request(method="POST", path="/callback")
        ctx = _make_ctx(req, sample_profile)
        result = await pf.check(ctx)
        assert result.action == FilterAction.BLOCK

    @pytest.mark.asyncio
    async def test_missing_header_blocked(self, pf, sample_profile):
        req = _make_request(
            method="GET",
            path="/callback",
            headers={"Host": "test.local"},  # missing Accept
        )
        ctx = _make_ctx(req, sample_profile)
        result = await pf.check(ctx)
        assert result.action == FilterAction.BLOCK
        assert "Missing required header" in result.reason

    @pytest.mark.asyncio
    async def test_wrong_useragent_blocked(self, pf, sample_profile):
        req = _make_request(
            method="GET",
            path="/callback",
            headers={
                "Accept": "text/html",
                "Host": "test.local",
                "user-agent": "WrongAgent/2.0",
                "cookie": "session=abc",
            },
            cookies={"session": "abc"},
        )
        ctx = _make_ctx(req, sample_profile)
        result = await pf.check(ctx)
        assert result.action == FilterAction.BLOCK
        assert "User-Agent" in result.reason

    @pytest.mark.asyncio
    async def test_no_useragent_in_profile_skips_check(self, pf, sample_profile):
        sample_profile.useragent = None
        req = _make_request(
            method="GET",
            path="/callback",
            headers={
                "Accept": "text/html",
                "Host": "test.local",
                "user-agent": "AnyAgent",
                "cookie": "session=abc",
            },
            cookies={"session": "abc"},
        )
        ctx = _make_ctx(req, sample_profile)
        result = await pf.check(ctx)
        assert result.action == FilterAction.ALLOW


# ── BotFilter ─────────────────────────────────────────────────────────

class TestBotFilter:
    @pytest.fixture
    def bf(self):
        return BotFilter()

    @pytest.mark.asyncio
    async def test_normal_ua_allowed(self, bf, sample_profile):
        req = _make_request(headers={"user-agent": "Mozilla/5.0", "accept": "*/*"})
        ctx = _make_ctx(req, sample_profile)
        result = await bf.check(ctx)
        assert result.action != FilterAction.BLOCK

    @pytest.mark.asyncio
    async def test_nmap_blocked(self, bf, sample_profile):
        req = _make_request(headers={"user-agent": "Nmap Scripting Engine"})
        ctx = _make_ctx(req, sample_profile)
        result = await bf.check(ctx)
        assert result.action == FilterAction.BLOCK

    @pytest.mark.asyncio
    async def test_curl_blocked(self, bf, sample_profile):
        req = _make_request(headers={"user-agent": "curl/7.68.0"})
        ctx = _make_ctx(req, sample_profile)
        result = await bf.check(ctx)
        assert result.action == FilterAction.BLOCK

    @pytest.mark.asyncio
    async def test_empty_ua_suspect(self, bf, sample_profile):
        req = _make_request(headers={"user-agent": ""})
        ctx = _make_ctx(req, sample_profile)
        result = await bf.check(ctx)
        assert result.action == FilterAction.SUSPECT


# ── HeaderFilter ──────────────────────────────────────────────────────

class TestHeaderFilter:
    @pytest.fixture
    def hf(self):
        return HeaderFilter()

    @pytest.mark.asyncio
    async def test_clean_headers_allowed(self, hf, sample_profile):
        req = _make_request(headers={"Accept": "text/html", "Host": "test.local"})
        ctx = _make_ctx(req, sample_profile)
        result = await hf.check(ctx)
        assert result.action == FilterAction.ALLOW

    @pytest.mark.asyncio
    async def test_banned_header_name_blocked(self, hf, sample_profile):
        req = _make_request(headers={"X-Burp-Token": "abc"})
        ctx = _make_ctx(req, sample_profile)
        result = await hf.check(ctx)
        assert result.action == FilterAction.BLOCK

    @pytest.mark.asyncio
    async def test_banned_header_value_blocked(self, hf, sample_profile):
        req = _make_request(headers={"X-Custom": "powered by nikto"})
        ctx = _make_ctx(req, sample_profile)
        result = await hf.check(ctx)
        assert result.action == FilterAction.BLOCK


# ── ReplayFilter ──────────────────────────────────────────────────────

class TestReplayFilter:
    @pytest.fixture
    def rf(self):
        return ReplayFilter(window_seconds=60)

    @pytest.mark.asyncio
    async def test_first_request_allowed(self, rf, sample_profile):
        req = _make_request(headers={"user-agent": "test", "cookie": "a=1"})
        ctx = _make_ctx(req, sample_profile)
        result = await rf.check(ctx)
        assert result.action == FilterAction.ALLOW

    @pytest.mark.asyncio
    async def test_duplicate_request_blocked(self, rf, sample_profile):
        req = _make_request(headers={"user-agent": "test", "cookie": "a=1"})
        ctx = _make_ctx(req, sample_profile)
        await rf.check(ctx)
        result = await rf.check(ctx)
        assert result.action == FilterAction.BLOCK
        assert "Replay" in result.reason


# ── FilterPipeline ────────────────────────────────────────────────────

class TestFilterPipeline:
    @pytest.mark.asyncio
    async def test_all_allow_passes(self, sample_profile):
        class AllowFilter:
            name = "allow"
            async def check(self, ctx):
                return FilterResult.allow(filter_name="allow")

        pipeline = FilterPipeline([AllowFilter()], PipelineConfig())
        req = _make_request()
        ctx = _make_ctx(req, sample_profile)
        result = await pipeline.evaluate(ctx)
        assert result.allowed

    @pytest.mark.asyncio
    async def test_hard_block_shortcircuits(self, sample_profile):
        class BlockFilter:
            name = "blocker"
            async def check(self, ctx):
                return FilterResult.block(reason="test block", filter_name="blocker")

        class NeverReached:
            name = "never"
            async def check(self, ctx):
                raise AssertionError("Should not be called")

        pipeline = FilterPipeline(
            [BlockFilter(), NeverReached()], PipelineConfig()
        )
        req = _make_request()
        ctx = _make_ctx(req, sample_profile)
        result = await pipeline.evaluate(ctx)
        assert not result.allowed
        assert "test block" in result.blocking_reasons

    @pytest.mark.asyncio
    async def test_score_accumulation(self, sample_profile):
        class SuspectFilter:
            name = "suspect"
            async def check(self, ctx):
                return FilterResult.suspect(reason="meh", score=0.4, filter_name="s")

        pipeline = FilterPipeline(
            [SuspectFilter(), SuspectFilter()],
            PipelineConfig(block_score_threshold=0.7),
        )
        req = _make_request()
        ctx = _make_ctx(req, sample_profile)
        result = await pipeline.evaluate(ctx)
        assert not result.allowed  # 0.4 + 0.4 = 0.8 > 0.7

    @pytest.mark.asyncio
    async def test_filter_error_fails_open(self, sample_profile):
        class BrokenFilter:
            name = "broken"
            async def check(self, ctx):
                raise RuntimeError("oops")

        class AllowFilter:
            name = "allow"
            async def check(self, ctx):
                return FilterResult.allow()

        pipeline = FilterPipeline(
            [BrokenFilter(), AllowFilter()], PipelineConfig()
        )
        req = _make_request()
        ctx = _make_ctx(req, sample_profile)
        result = await pipeline.evaluate(ctx)
        assert result.allowed  # broken filter skipped, allow filter passes
