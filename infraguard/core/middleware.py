"""ASGI middleware for logging, timing, and error handling."""

from __future__ import annotations

import time
from typing import Any

import httpx
import structlog
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import Response

from infraguard.core.tls_protocol import get_ja3_for_peer

log = structlog.get_logger()


class JA3InjectionMiddleware(BaseHTTPMiddleware):
    """Inject JA3 fingerprint into request.state from header or TLS registry.

    Checks the reverse-proxy JA3 header first (nginx ssl_fingerprint / HAProxy
    native JA3). Falls back to the in-process registry populated by
    JA3InjectingProtocol when running with a custom asyncio server.
    """

    def __init__(self, app, ja3_header: str = "x-ja3") -> None:
        super().__init__(app)
        self._ja3_header = ja3_header

    async def dispatch(
        self, request: Request, call_next: RequestResponseEndpoint
    ) -> Response:
        ja3 = request.headers.get(self._ja3_header)
        if ja3 is None and request.client:
            ja3 = get_ja3_for_peer((request.client.host, request.client.port))
        if ja3 is not None:
            request.state.ja3 = ja3
        return await call_next(request)


class RequestLoggingMiddleware(BaseHTTPMiddleware):
    """Log every request with timing information."""

    async def dispatch(
        self, request: Request, call_next: RequestResponseEndpoint
    ) -> Response:
        start = time.perf_counter()
        client_ip = self._get_client_ip(request)

        try:
            response = await call_next(request)
        except (httpx.TimeoutException, httpx.ConnectError):
            log.exception(
                "upstream_error",
                method=request.method,
                path=request.url.path,
                client=client_ip,
            )
            return Response(status_code=502, content=b"Bad Gateway")
        except Exception:
            log.exception(
                "request_error",
                method=request.method,
                path=request.url.path,
                client=client_ip,
            )
            return Response(status_code=500, content=b"Internal Server Error")

        duration_ms = (time.perf_counter() - start) * 1000

        log.info(
            "request",
            method=request.method,
            path=request.url.path,
            status=response.status_code,
            client=client_ip,
            duration_ms=round(duration_ms, 1),
            host=request.headers.get("host", ""),
        )

        return response

    @staticmethod
    def _get_client_ip(request: Request) -> str:
        """Extract client IP, honoring X-Forwarded-For only from trusted proxies."""
        direct_ip = request.client.host if request.client else "unknown"

        # Only trust X-Forwarded-For if the direct peer is a trusted proxy
        trusted = getattr(request.app.state, "trusted_proxies", [])
        if not trusted:
            return direct_ip

        from ipaddress import ip_address, ip_network
        try:
            direct = ip_address(direct_ip)
            for cidr in trusted:
                if direct in ip_network(cidr, strict=False):
                    xff = request.headers.get("X-Forwarded-For", "")
                    if xff:
                        return xff.split(",")[0].strip()
                    break
        except ValueError:
            pass

        return direct_ip
