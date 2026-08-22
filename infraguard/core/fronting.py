"""Domain fronting support - rewrites SNI and Host headers to route traffic through CDN edge nodes.

Domain fronting hides the true destination of HTTPS traffic by exploiting
the way CDNs route requests.  The TLS handshake (SNI) uses a high-reputation
CDN domain, while the HTTP Host header carries the real C2 domain.  The CDN
edge decrypts TLS and forwards based on the Host header.

Supported CDNs:
  - Amazon CloudFront
  - Microsoft Azure CDN
  - Google Cloud CDN
  - Fastly

.. warning::

    CDN providers (AWS, Azure, Google, Fastly) actively detect and block
    domain fronting.  AWS and Azure have both deployed mitigations since
    2018/2022 respectively.  Use as a *secondary* transport with fallback
    redirectors, not as the primary C2 channel.
"""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

import httpx
import structlog

from infraguard.config.schema import DomainConfig, FrontingRuleConfig
from infraguard.core.headers import sanitize_response_headers, preserve_multi_value_headers
from infraguard.core.ssl_context import build_ssl_context

log = structlog.get_logger()


class CDNProvider(str, Enum):
    """CDN providers that support domain fronting."""

    CLOUDFRONT = "cloudfront"
    AZURE = "azure"
    GOOGLE = "google"
    FASTLY = "fastly"


# CDN-specific default edge domains used for health checks when no explicit
# probe URL is configured.  These are well-known properties on each CDN that
# return predictable responses.
_CDN_DEFAULT_PROBES: dict[str, str] = {
    "cloudfront": "https://d1.awsstatic.com/0x0.png",
    "azure": "https://ajax.aspnetcdn.com/ajax/4.0/1/MicrosoftAjax.js",
    "google": "https://www.gstatic.com/generate_204",
    "fastly": "https://www.fastly.com/favicon.ico",
}

# Headers that CDN providers inject and that should never be forwarded back
# to the client (they leak the CDN edge identity and can fingerprint the
# fronting technique).
_CDN_BLOCKED_HEADERS: frozenset[str] = frozenset(
    {
        # CloudFront
        "x-amz-cf-pop",
        "x-amz-cf-id",
        "x-amz-cf-ray",
        "x-cache",
        "via",
        # Azure CDN
        "x-azure-ref",
        "x-ms-request-id",
        "x-msedge-ref",
        # Google Cloud CDN
        "x-cloud-trace-context",
        "x-goog-request-id",
        "x-google-cache-control",
        "server-timing",
        # Fastly
        "x-served-by",
        "x-cache-hits",
        "x-timer",
        "fastly-restarts",
        # Generic CDN fingerprints
        "x-cdn",
        "x-edge-location",
        "age",
    }
)


@dataclass
class FrontingHealthStatus:
    """Result of a single health probe against a fronted domain."""

    domain: str
    front_domain: str
    cdn: str
    healthy: bool
    status_code: int | None = None
    latency_ms: float = 0.0
    error: str | None = None
    checked_at: float = field(default_factory=time.monotonic)


@dataclass
class FrontingHealthReport:
    """Aggregated health across all fronted domains."""

    results: list[FrontingHealthStatus] = field(default_factory=list)

    @property
    def all_healthy(self) -> bool:
        return all(r.healthy for r in self.results)

    @property
    def unhealthy_domains(self) -> list[str]:
        return [r.domain for r in self.results if not r.healthy]


class DomainFronting:
    """Rewrite SNI and Host headers to route C2 traffic through CDN edge nodes.

    The :class:`DomainFronting` class owns a set of :class:`httpx.AsyncClient`
    instances keyed by fronted domain.  Each client connects to the CDN edge
    (the *front domain*) at the TLS layer while sending the real C2 domain in
    the HTTP Host header.

    Usage::

        fronting = DomainFronting(rules, domain_config)
        response = await fronting.forward(request, front_domain="cdn.example.com")
    """

    def __init__(
        self,
        rules: list[FrontingRuleConfig],
        domain_config: DomainConfig | None = None,
        default_timeout: float = 30.0,
    ):
        self.rules = rules
        self.domain_config = domain_config
        self.default_timeout = default_timeout
        self._clients: dict[str, httpx.AsyncClient] = {}

        # Build lookup: front_domain -> rule
        self._rule_map: dict[str, FrontingRuleConfig] = {}
        for rule in rules:
            self._rule_map[rule.front_domain] = rule
            if rule.enabled:
                log.info(
                    "fronting_rule_loaded",
                    domain=rule.domain,
                    front_domain=rule.front_domain,
                    cdn=rule.cdn,
                )

    @property
    def enabled_rules(self) -> list[FrontingRuleConfig]:
        """Return only the rules marked as enabled."""
        return [r for r in self.rules if r.enabled]

    def resolve_rule(self, front_domain: str) -> FrontingRuleConfig | None:
        """Look up the fronting rule for a given front domain."""
        return self._rule_map.get(front_domain)

    def resolve_by_host(self, host: str) -> FrontingRuleConfig | None:
        """Find a rule whose *domain* matches the Host header value.

        This is the routing entry-point: when a request arrives at the
        redirector with a Host header matching a fronted domain, the rule
        tells us which CDN front domain to use for the upstream connection.
        """
        hostname = host.split(":")[0].lower()
        for rule in self.enabled_rules:
            if rule.domain.lower() == hostname:
                return rule
        return None

    async def forward(
        self,
        request: "Request",
        rule: FrontingRuleConfig,
        *,
        timeout: float | None = None,
    ) -> "Response":
        """Forward a request through CDN domain fronting.

        The TLS SNI is set to the CDN *front_domain* while the HTTP Host
        header is set to the real *domain* from the rule.  The CDN edge
        decrypts TLS, reads the Host header, and routes to the origin
        (the C2 upstream).

        Args:
            request: The incoming Starlette request.
            rule: The :class:`FrontingRuleConfig` matching this request.
            timeout: Optional per-request timeout override.

        Returns:
            The upstream response, sanitized.
        """
        from starlette.requests import Request  # noqa: F811
        from starlette.responses import Response

        client = self._get_client(rule)
        timeout = timeout or rule.timeout_seconds or self.default_timeout

        # Build the upstream URL: scheme is always HTTPS to the front domain
        path = request.url.path
        # Starlette normalizes paths to start with '/', so an absolute URL like
        # 'https://evil.com/steal' becomes '/https://evil.com/steal'.  Check both.
        if path.startswith(("http://", "https://", "//")) or path.startswith(("/http://", "/https://")):
            log.warning("fronting_ssrf_blocked", path=path, front_domain=rule.front_domain)
            return Response(status_code=400, content=b"Bad Request")
        upstream_url = f"https://{rule.front_domain}{path}"
        if request.url.query:
            upstream_url += f"?{request.url.query}"

        # Build headers: copy from incoming request, then apply fronting
        headers = self._build_fronted_headers(request, rule)

        body = await request.body()

        try:
            resp = await client.request(
                method=request.method,
                url=upstream_url,
                headers=headers,
                content=body if body else None,
                timeout=timeout,
            )
        except httpx.TimeoutException:
            log.warning(
                "fronting_upstream_timeout",
                front_domain=rule.front_domain,
                domain=rule.domain,
                path=request.url.path,
            )
            return Response(status_code=504, content=b"Gateway Timeout")
        except httpx.ConnectError:
            log.warning(
                "fronting_upstream_connect_error",
                front_domain=rule.front_domain,
                domain=rule.domain,
            )
            return Response(status_code=502, content=b"Bad Gateway")
        except httpx.RequestError as e:
            log.exception(
                "fronting_upstream_error",
                front_domain=rule.front_domain,
                domain=rule.domain,
                path=request.url.path,
                error_type=type(e).__name__,
            )
            return Response(status_code=502, content=b"Bad Gateway")

        # Sanitize response headers - strip CDN-identifying headers plus
        # the standard blocklist.  CDN headers (X-Amz-CF-*, X-Cache, Via, etc.)
        # would fingerprint the fronting technique to the blue team.
        extra = (
            frozenset(self.domain_config.extra_allowed_headers)
            if self.domain_config and self.domain_config.extra_allowed_headers
            else None
        )
        persona_server = None
        if self.domain_config and self.domain_config.drop_action.persona:
            persona_server = self.domain_config.drop_action.persona.server_header
        resp_headers = sanitize_response_headers(
            dict(resp.headers),
            extra_allowed=extra,
            server_header=persona_server,
        )
        # Strip CDN-specific headers that leak the edge node identity
        for cdn_header in _CDN_BLOCKED_HEADERS:
            resp_headers.pop(cdn_header, None)
            resp_headers.pop(cdn_header.title(), None)
        # httpx auto-decompresses - strip encoding/framing headers so the
        # client doesn't try to re-decompress an already-decoded body.
        resp_headers.pop("content-encoding", None)
        resp_headers.pop("Content-Encoding", None)
        resp_headers.pop("transfer-encoding", None)
        resp_headers.pop("Transfer-Encoding", None)
        resp_headers.pop("content-length", None)
        resp_headers.pop("Content-Length", None)

        response = Response(
            content=resp.content,
            status_code=resp.status_code,
            headers=resp_headers,
        )
        preserve_multi_value_headers(response, resp.headers)
        return response

    async def health_check(
        self,
        rule: FrontingRuleConfig | None = None,
        *,
        timeout: float = 10.0,
    ) -> FrontingHealthStatus | FrontingHealthReport:
        """Probe the health of fronted domains.

        When *rule* is given, checks that single rule.  When ``None``,
        checks all enabled rules and returns a :class:`FrontingHealthReport`.

        The probe performs an HTTPS GET against the front domain, optionally
        using a CDN-specific well-known URL.  A healthy result means the CDN
        edge is reachable and the front domain resolves.
        """
        if rule is not None:
            return await self._probe(rule, timeout=timeout)

        report = FrontingHealthReport()
        tasks = [self._probe(r, timeout=timeout) for r in self.enabled_rules]
        report.results = list(await asyncio.gather(*tasks, return_exceptions=False))
        return report

    async def start_health_monitor(
        self,
        interval_seconds: float = 300.0,
        on_unhealthy: "callable | None" = None,
    ) -> asyncio.Task:
        """Start a background health-check loop.

        Args:
            interval_seconds: Time between full health sweeps.
            on_unhealthy: Optional async callback receiving
                :class:`FrontingHealthStatus` for each unhealthy domain.

        Returns:
            The ``asyncio.Task`` running the loop.  Cancel it to stop.
        """

        async def _loop() -> None:
            while True:
                report: FrontingHealthReport = await self.health_check()
                if not report.all_healthy:
                    for status in report.results:
                        if not status.healthy:
                            log.warning(
                                "fronting_health_check_failed",
                                domain=status.domain,
                                front_domain=status.front_domain,
                                cdn=status.cdn,
                                error=status.error,
                                status_code=status.status_code,
                            )
                            if on_unhealthy is not None:
                                try:
                                    await on_unhealthy(status)
                                except Exception:
                                    log.exception("fronting_health_callback_error")
                await asyncio.sleep(interval_seconds)

        task = asyncio.create_task(_loop())
        log.info(
            "fronting_health_monitor_started",
            domains=[r.domain for r in self.enabled_rules],
            interval=interval_seconds,
        )
        return task

    # ── Internal ──────────────────────────────────────────────────────

    def _get_client(self, rule: FrontingRuleConfig) -> httpx.AsyncClient:
        """Get or create the httpx client for a fronting rule.

        The client is keyed by ``front_domain`` so multiple rules that share
        the same CDN edge reuse the connection pool.
        """
        if rule.front_domain not in self._clients:
            ssl_ctx = (
                build_ssl_context(rule.ssl_verify, rule.ssl_ca_bundle)
                if rule
                else True  # Fronted domains should always verify (public CA)
            )
            self._clients[rule.front_domain] = httpx.AsyncClient(
                verify=ssl_ctx,
                follow_redirects=False,
                # Force HTTP/1.1 - some CDN edges handle HTTP/2 streams
                # differently for fronted vs. direct traffic, which can
                # cause subtle fingerprinting.  HTTP/1.1 keeps the profile
                # consistent with typical CDN client behaviour.
                http2=False,
            )
        return self._clients[rule.front_domain]

    @staticmethod
    def _build_fronted_headers(
        request: "Request",
        rule: FrontingRuleConfig,
    ) -> dict[str, str]:
        """Build headers for the fronted request.

        The critical rewrite: Host header carries the *real* C2 domain
        (``rule.domain``), not the CDN front domain.  The CDN edge uses
        this Host header to route to the origin.

        Any operator-defined ``custom_headers`` from the rule are applied
        last, overriding both the incoming request headers and the Host
        rewrite (use with caution - a custom Host header will break
        fronting if set incorrectly).
        """
        # Copy hop-by-hop-filtered incoming headers
        hop_by_hop = {
            "connection",
            "keep-alive",
            "proxy-authenticate",
            "proxy-authorization",
            "te",
            "trailers",
            "transfer-encoding",
            "upgrade",
        }
        headers: dict[str, str] = {
            k: v
            for k, v in request.headers.items()
            if k.lower() not in hop_by_hop
        }

        # ── Domain fronting rewrite ──────────────────────────────────
        # The Host header must carry the real C2 domain so the CDN edge
        # routes to the correct origin.  The TLS SNI (handled by httpx
        # connecting to rule.front_domain) already contains the front
        # domain - no manual SNI manipulation needed.
        headers["Host"] = rule.domain

        # Apply operator-defined custom headers (can override anything)
        if rule.custom_headers:
            headers.update(rule.custom_headers)

        return headers

    async def _probe(
        self,
        rule: FrontingRuleConfig,
        *,
        timeout: float = 10.0,
    ) -> FrontingHealthStatus:
        """Execute a single health probe against a fronted domain."""
        start = time.perf_counter()
        probe_url = rule.health_probe_url or _CDN_DEFAULT_PROBES.get(rule.cdn)

        try:
            client = self._get_client(rule)
            resp = await client.get(probe_url, timeout=timeout, follow_redirects=True)
            latency_ms = (time.perf_counter() - start) * 1000
            healthy = resp.status_code < 400
            status = FrontingHealthStatus(
                domain=rule.domain,
                front_domain=rule.front_domain,
                cdn=rule.cdn,
                healthy=healthy,
                status_code=resp.status_code,
                latency_ms=round(latency_ms, 1),
                error=None if healthy else f"HTTP {resp.status_code}",
            )
        except httpx.TimeoutException:
            latency_ms = (time.perf_counter() - start) * 1000
            status = FrontingHealthStatus(
                domain=rule.domain,
                front_domain=rule.front_domain,
                cdn=rule.cdn,
                healthy=False,
                latency_ms=round(latency_ms, 1),
                error="probe timeout",
            )
        except httpx.ConnectError as e:
            latency_ms = (time.perf_counter() - start) * 1000
            status = FrontingHealthStatus(
                domain=rule.domain,
                front_domain=rule.front_domain,
                cdn=rule.cdn,
                healthy=False,
                latency_ms=round(latency_ms, 1),
                error=f"connect error: {e}",
            )
        except httpx.RequestError as e:
            latency_ms = (time.perf_counter() - start) * 1000
            status = FrontingHealthStatus(
                domain=rule.domain,
                front_domain=rule.front_domain,
                cdn=rule.cdn,
                healthy=False,
                latency_ms=round(latency_ms, 1),
                error=f"request error: {type(e).__name__}: {e}",
            )

        level = "info" if status.healthy else "warning"
        getattr(log, level)(
            "fronting_health_probe",
            domain=rule.domain,
            front_domain=rule.front_domain,
            cdn=rule.cdn,
            healthy=status.healthy,
            status_code=status.status_code,
            latency_ms=status.latency_ms,
            error=status.error,
        )
        return status

    async def close(self) -> None:
        """Close all httpx clients."""
        for client in self._clients.values():
            await client.aclose()
        self._clients.clear()
