"""ASGI middleware for logging, timing, and error handling."""

from __future__ import annotations

import time
from typing import Any

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
        client_ip = request.client.host if request.client else "unknown"

        try:
            response = await call_next(request)
        except Exception:
            log.exception(
                "request_error",
                method=request.method,
                path=request.url.path,
                client=client_ip,
            )
            return Response(status_code=502, content=b"Bad Gateway")

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
