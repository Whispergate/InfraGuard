"""Reverse proxy handler - forwards validated requests to upstream C2."""

from __future__ import annotations

import httpx
import structlog
from starlette.requests import Request
from starlette.responses import Response, StreamingResponse

from infraguard.config.schema import DomainConfig
from infraguard.core.headers import sanitize_response_headers
from infraguard.core.ssl_context import build_ssl_context

log = structlog.get_logger()


class ProxyHandler:
    """Forward requests to an upstream server using httpx."""

    def __init__(self, default_timeout: float = 30.0):
        self.default_timeout = default_timeout
        self._clients: dict[str, httpx.AsyncClient] = {}

    async def forward(
        self,
        request: Request,
        upstream: str,
        *,
        timeout: float | None = None,
        domain_config: DomainConfig | None = None,
    ) -> Response:
        """Proxy a request to the upstream and return the response."""
        client = self._get_client(upstream, domain_config)
        timeout = timeout or self.default_timeout

        # Build the upstream URL
        upstream_url = upstream.rstrip("/") + request.url.path
        if request.url.query:
            upstream_url += f"?{request.url.query}"

        # Forward headers (filter hop-by-hop)
        headers = self._filter_headers(request.headers)

        # Read body
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
            log.warning("upstream_timeout", upstream=upstream, path=request.url.path)
            return Response(status_code=504, content=b"Gateway Timeout")
        except httpx.ConnectError:
            log.warning("upstream_connect_error", upstream=upstream)
            return Response(status_code=502, content=b"Bad Gateway")
        except httpx.RequestError as e:
            log.exception("upstream_error", upstream=upstream, path=request.url.path, error_type=type(e).__name__)
            return Response(status_code=502, content=b"Bad Gateway")

        # Sanitize response headers using the whitelist sanitizer
        extra = (
            frozenset(domain_config.extra_allowed_headers)
            if domain_config and domain_config.extra_allowed_headers
            else None
        )
        resp_headers = sanitize_response_headers(dict(resp.headers), extra_allowed=extra)

        return Response(
            content=resp.content,
            status_code=resp.status_code,
            headers=resp_headers,
        )

    def _get_client(
        self, upstream: str, domain_config: DomainConfig | None = None
    ) -> httpx.AsyncClient:
        if upstream not in self._clients:
            ssl_ctx = (
                build_ssl_context(domain_config.ssl_verify, domain_config.ssl_ca_bundle)
                if domain_config
                else False
            )
            if domain_config and not domain_config.ssl_verify:
                log.warning("ssl_verification_disabled", upstream=upstream)
            self._clients[upstream] = httpx.AsyncClient(
                verify=ssl_ctx,
                follow_redirects=False,
            )
        return self._clients[upstream]

    @staticmethod
    def _filter_headers(headers: dict) -> dict[str, str]:
        """Remove hop-by-hop headers before forwarding."""
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
        return {
            k: v
            for k, v in headers.items()
            if k.lower() not in hop_by_hop
        }

    async def close(self) -> None:
        for client in self._clients.values():
            await client.aclose()
        self._clients.clear()
