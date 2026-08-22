"""Tests for the domain fronting module."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest
from starlette.requests import Request
from starlette.responses import Response

from infraguard.config.schema import FrontingRuleConfig
from infraguard.core.fronting import (
    CDNProvider,
    DomainFronting,
    FrontingHealthReport,
    FrontingHealthStatus,
    _CDN_BLOCKED_HEADERS,
    _CDN_DEFAULT_PROBES,
)


# ── Fixtures ──────────────────────────────────────────────────────────────

@pytest.fixture
def cloudfront_rule() -> FrontingRuleConfig:
    return FrontingRuleConfig(
        domain="c2.example.com",
        front_domain="d1234abcd.cloudfront.net",
        cdn="cloudfront",
        enabled=True,
    )


@pytest.fixture
def azure_rule() -> FrontingRuleConfig:
    return FrontingRuleConfig(
        domain="cdn-c2.contoso.com",
        front_domain="edge.azurefd.net",
        cdn="azure",
        enabled=True,
    )


@pytest.fixture
def disabled_rule() -> FrontingRuleConfig:
    return FrontingRuleConfig(
        domain="disabled.example.com",
        front_domain="d5678efgh.cloudfront.net",
        cdn="cloudfront",
        enabled=False,
    )


@pytest.fixture
def multi_rules(cloudfront_rule, azure_rule) -> list[FrontingRuleConfig]:
    return [cloudfront_rule, azure_rule]


@pytest.fixture
def fronting(multi_rules) -> DomainFronting:
    return DomainFronting(multi_rules)


def _make_request(host: str = "c2.example.com", path: str = "/api/v1/status") -> Request:
    """Create a minimal Starlette request for testing."""
    scope = {
        "type": "http",
        "method": "GET",
        "path": path,
        "query_string": b"",
        "headers": [
            (b"host", host.encode()),
            (b"user-agent", b"TestAgent/1.0"),
            (b"accept", b"*/*"),
        ],
        "client": ("192.168.1.100", 12345),
    }

    async def _receive():
        return {"type": "http.request", "body": b"", "more_body": False}

    return Request(scope, _receive)


# ── CDN provider support ─────────────────────────────────────────────

class TestCDNProviders:
    def test_all_providers_valid(self):
        for provider in ["cloudfront", "azure", "google", "fastly"]:
            rule = FrontingRuleConfig(
                domain="test.example.com",
                front_domain="front.example.com",
                cdn=provider,
            )
            assert rule.cdn == provider

    def test_cdn_enum_values(self):
        assert CDNProvider.CLOUDFRONT.value == "cloudfront"
        assert CDNProvider.AZURE.value == "azure"
        assert CDNProvider.GOOGLE.value == "google"
        assert CDNProvider.FASTLY.value == "fastly"

    def test_all_providers_have_default_probes(self):
        for cdn_name in ("cloudfront", "azure", "google", "fastly"):
            assert cdn_name in _CDN_DEFAULT_PROBES


# ── Rule resolution ──────────────────────────────────────────────────

class TestRuleResolution:
    def test_resolve_by_host_match(self, fronting):
        rule = fronting.resolve_by_host("c2.example.com")
        assert rule is not None
        assert rule.domain == "c2.example.com"
        assert rule.cdn == "cloudfront"

    def test_resolve_by_host_with_port(self, fronting):
        rule = fronting.resolve_by_host("c2.example.com:443")
        assert rule is not None
        assert rule.domain == "c2.example.com"

    def test_resolve_by_host_case_insensitive(self, fronting):
        rule = fronting.resolve_by_host("C2.Example.COM")
        assert rule is not None

    def test_resolve_by_host_no_match(self, fronting):
        assert fronting.resolve_by_host("unknown.example.com") is None

    def test_resolve_by_host_empty(self, fronting):
        assert fronting.resolve_by_host("") is None

    def test_resolve_rule_by_front_domain(self, fronting):
        rule = fronting.resolve_rule("d1234abcd.cloudfront.net")
        assert rule is not None
        assert rule.front_domain == "d1234abcd.cloudfront.net"

    def test_resolve_rule_missing(self, fronting):
        assert fronting.resolve_rule("nonexistent.cdn.com") is None

    def test_enabled_rules_excludes_disabled(self, multi_rules, disabled_rule):
        f = DomainFronting([*multi_rules, disabled_rule])
        assert len(f.enabled_rules) == 2
        assert all(r.enabled for r in f.enabled_rules)

    def test_disabled_rule_not_matched(self, multi_rules, disabled_rule):
        f = DomainFronting([*multi_rules, disabled_rule])
        assert f.resolve_by_host("disabled.example.com") is None


# ── Health dataclasses ───────────────────────────────────────────────

class TestHealthDataclasses:
    def test_health_status_fields(self):
        s = FrontingHealthStatus(
            domain="c2.example.com",
            front_domain="d1234.cloudfront.net",
            cdn="cloudfront",
            healthy=True,
            status_code=200,
            latency_ms=45.2,
        )
        assert s.healthy is True
        assert s.error is None
        assert s.cdn == "cloudfront"

    def test_health_report_all_healthy(self):
        report = FrontingHealthReport(results=[
            FrontingHealthStatus(
                domain="a.com", front_domain="cdn1.com",
                cdn="cloudfront", healthy=True,
            ),
            FrontingHealthStatus(
                domain="b.com", front_domain="cdn2.com",
                cdn="azure", healthy=True,
            ),
        ])
        assert report.all_healthy is True
        assert report.unhealthy_domains == []

    def test_health_report_unhealthy(self):
        report = FrontingHealthReport(results=[
            FrontingHealthStatus(
                domain="a.com", front_domain="cdn1.com",
                cdn="cloudfront", healthy=True,
            ),
            FrontingHealthStatus(
                domain="b.com", front_domain="cdn2.com",
                cdn="azure", healthy=False,
            ),
        ])
        assert report.all_healthy is False
        assert report.unhealthy_domains == ["b.com"]


# ── Header rewriting ─────────────────────────────────────────────────

class TestHeaderRewriting:
    def test_host_header_rewritten_to_real_domain(self, fronting):
        rule = fronting.resolve_by_host("c2.example.com")
        request = _make_request(host="c2.example.com")
        headers = DomainFronting._build_fronted_headers(request, rule)
        assert headers["Host"] == "c2.example.com"

    def test_hop_by_hop_headers_filtered(self, fronting):
        rule = fronting.resolve_by_host("c2.example.com")
        scope = {
            "type": "http",
            "method": "GET",
            "path": "/",
            "query_string": b"",
            "headers": [
                (b"host", b"c2.example.com"),
                (b"connection", b"keep-alive"),
                (b"transfer-encoding", b"chunked"),
                (b"upgrade", b"h2c"),
                (b"user-agent", b"TestAgent/1.0"),
            ],
            "client": ("10.0.0.1", 1234),
        }
        request = Request(scope)
        headers = DomainFronting._build_fronted_headers(request, rule)
        header_keys_lower = {k.lower() for k in headers}
        assert "connection" not in header_keys_lower
        assert "transfer-encoding" not in header_keys_lower
        assert "upgrade" not in header_keys_lower
        assert "user-agent" in header_keys_lower

    def test_custom_headers_applied(self):
        rule = FrontingRuleConfig(
            domain="c2.example.com",
            front_domain="d1234.cloudfront.net",
            cdn="cloudfront",
            custom_headers={"X-Custom-Origin": "true"},
        )
        request = _make_request()
        headers = DomainFronting._build_fronted_headers(request, rule)
        assert headers["X-Custom-Origin"] == "true"

    def test_custom_headers_can_override_host(self):
        """Custom headers apply after the Host rewrite, so they can override it."""
        rule = FrontingRuleConfig(
            domain="c2.example.com",
            front_domain="d1234.cloudfront.net",
            cdn="cloudfront",
            custom_headers={"Host": "override.example.com"},
        )
        request = _make_request()
        headers = DomainFronting._build_fronted_headers(request, rule)
        assert headers["Host"] == "override.example.com"


# ── Forwarding ───────────────────────────────────────────────────────

class TestForwarding:
    @pytest.mark.asyncio
    async def test_forward_ssrf_absolute_url_blocked(self, fronting):
        """Absolute URLs in path are blocked (SSRF protection).

        Starlette normalizes the path, so 'https://evil.com/steal' becomes
        '/https://evil.com/steal'.  The check catches both forms.
        """
        rule = fronting.resolve_by_host("c2.example.com")
        request = _make_request(path="https://evil.com/steal")
        response = await fronting.forward(request, rule)
        assert response.status_code == 400

    @pytest.mark.asyncio
    async def test_forward_ssrf_protocol_relative_blocked(self, fronting):
        rule = fronting.resolve_by_host("c2.example.com")
        request = _make_request(path="//evil.com/steal")
        response = await fronting.forward(request, rule)
        assert response.status_code == 400

    @pytest.mark.asyncio
    async def test_forward_timeout(self, fronting):
        rule = fronting.resolve_by_host("c2.example.com")
        request = _make_request()
        client = fronting._get_client(rule)
        with patch.object(client, "request", side_effect=httpx.TimeoutException("timeout")):
            response = await fronting.forward(request, rule)
        assert response.status_code == 504

    @pytest.mark.asyncio
    async def test_forward_connect_error(self, fronting):
        rule = fronting.resolve_by_host("c2.example.com")
        request = _make_request()
        client = fronting._get_client(rule)
        with patch.object(client, "request", side_effect=httpx.ConnectError("refused")):
            response = await fronting.forward(request, rule)
        assert response.status_code == 502

    @pytest.mark.asyncio
    async def test_forward_strips_cdn_headers(self, fronting):
        """CDN-identifying headers must be stripped from fronted responses."""
        rule = fronting.resolve_by_host("c2.example.com")
        request = _make_request()

        mock_response = MagicMock(spec=httpx.Response)
        mock_response.status_code = 200
        mock_response.content = b"OK"
        mock_response.headers = httpx.Headers({
            "content-type": "text/html",
            "x-amz-cf-pop": "IAD89-C1",
            "x-amz-cf-id": "abc123==",
            "x-cache": "Hit from cloudfront",
            "via": "1.1 abc123.cloudfront.net (CloudFront)",
            "set-cookie": "session=abc",
        })
        mock_response.headers.multi_items = lambda: [
            ("content-type", "text/html"),
            ("x-amz-cf-pop", "IAD89-C1"),
            ("x-cache", "Hit from cloudfront"),
            ("set-cookie", "session=abc"),
        ]

        client = fronting._get_client(rule)
        with patch.object(client, "request", return_value=mock_response):
            response = await fronting.forward(request, rule)

        assert response.status_code == 200
        header_keys = {k.decode("latin-1").lower() for k, v in response.raw_headers}
        # CDN fingerprint headers must be gone
        for blocked in ("x-amz-cf-pop", "x-amz-cf-id", "x-cache", "via"):
            assert blocked not in header_keys, f"CDN header {blocked!r} leaked"
        # Safe headers preserved
        assert "content-type" in header_keys
        assert "set-cookie" in header_keys


# ── Health checks ────────────────────────────────────────────────────

class TestHealthChecks:
    @pytest.mark.asyncio
    async def test_health_check_single_healthy(self, fronting):
        rule = fronting.resolve_by_host("c2.example.com")
        mock_response = MagicMock(spec=httpx.Response)
        mock_response.status_code = 200

        client = fronting._get_client(rule)
        with patch.object(client, "get", return_value=mock_response):
            status = await fronting.health_check(rule)

        assert isinstance(status, FrontingHealthStatus)
        assert status.healthy is True
        assert status.status_code == 200
        assert status.error is None

    @pytest.mark.asyncio
    async def test_health_check_single_unhealthy_status(self, fronting):
        rule = fronting.resolve_by_host("c2.example.com")
        mock_response = MagicMock(spec=httpx.Response)
        mock_response.status_code = 503

        client = fronting._get_client(rule)
        with patch.object(client, "get", return_value=mock_response):
            status = await fronting.health_check(rule)

        assert status.healthy is False
        assert status.status_code == 503

    @pytest.mark.asyncio
    async def test_health_check_timeout(self, fronting):
        rule = fronting.resolve_by_host("c2.example.com")
        client = fronting._get_client(rule)
        with patch.object(client, "get", side_effect=httpx.TimeoutException("timeout")):
            status = await fronting.health_check(rule)

        assert status.healthy is False
        assert "timeout" in status.error

    @pytest.mark.asyncio
    async def test_health_check_connect_error(self, fronting):
        rule = fronting.resolve_by_host("c2.example.com")
        client = fronting._get_client(rule)
        with patch.object(client, "get", side_effect=httpx.ConnectError("refused")):
            status = await fronting.health_check(rule)

        assert status.healthy is False
        assert "connect error" in status.error

    @pytest.mark.asyncio
    async def test_health_check_all_rules(self, fronting):
        mock_response = MagicMock(spec=httpx.Response)
        mock_response.status_code = 200

        with patch.object(httpx.AsyncClient, "get", return_value=mock_response):
            report = await fronting.health_check()

        assert isinstance(report, FrontingHealthReport)
        assert len(report.results) == 2
        assert report.all_healthy is True
        assert report.unhealthy_domains == []

    @pytest.mark.asyncio
    async def test_health_report_mixed(self, fronting):
        call_count = 0

        async def _mock_get(url, **kwargs):
            nonlocal call_count
            call_count += 1
            resp = MagicMock(spec=httpx.Response)
            # First call succeeds, second fails
            resp.status_code = 200 if call_count == 1 else 503
            return resp

        with patch.object(httpx.AsyncClient, "get", side_effect=_mock_get):
            report = await fronting.health_check()

        assert report.all_healthy is False
        assert len(report.unhealthy_domains) == 1


# ── Client reuse ─────────────────────────────────────────────────────

class TestClientReuse:
    def test_same_front_domain_reuses_client(self):
        rules = [
            FrontingRuleConfig(
                domain="c2-1.example.com",
                front_domain="shared.cloudfront.net",
                cdn="cloudfront",
            ),
            FrontingRuleConfig(
                domain="c2-2.example.com",
                front_domain="shared.cloudfront.net",
                cdn="cloudfront",
            ),
        ]
        f = DomainFronting(rules)
        client1 = f._get_client(rules[0])
        client2 = f._get_client(rules[1])
        assert client1 is client2

    def test_different_front_domains_different_clients(self, fronting, cloudfront_rule, azure_rule):
        client1 = fronting._get_client(cloudfront_rule)
        client2 = fronting._get_client(azure_rule)
        assert client1 is not client2

    @pytest.mark.asyncio
    async def test_close_clears_clients(self, fronting):
        rule = fronting.resolve_by_host("c2.example.com")
        fronting._get_client(rule)
        assert len(fronting._clients) > 0
        await fronting.close()
        assert len(fronting._clients) == 0


# ── CDN blocked headers coverage ─────────────────────────────────────

class TestCDNBlockedHeaders:
    def test_cloudfront_headers_blocked(self):
        cf_headers = {"x-amz-cf-pop", "x-amz-cf-id", "x-cache", "via"}
        assert cf_headers.issubset(_CDN_BLOCKED_HEADERS)

    def test_azure_headers_blocked(self):
        azure_headers = {"x-azure-ref", "x-ms-request-id", "x-msedge-ref"}
        assert azure_headers.issubset(_CDN_BLOCKED_HEADERS)

    def test_google_headers_blocked(self):
        google_headers = {"x-cloud-trace-context", "x-goog-request-id", "server-timing"}
        assert google_headers.issubset(_CDN_BLOCKED_HEADERS)

    def test_fastly_headers_blocked(self):
        fastly_headers = {"x-served-by", "x-cache-hits", "x-timer", "fastly-restarts"}
        assert fastly_headers.issubset(_CDN_BLOCKED_HEADERS)

    def test_generic_cdn_headers_blocked(self):
        generic = {"x-cdn", "x-edge-location", "age"}
        assert generic.issubset(_CDN_BLOCKED_HEADERS)
