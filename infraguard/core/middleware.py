"""ASGI middleware for logging, timing, and error handling."""

from __future__ import annotations

import time
from typing import Any

import structlog
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import Response

log = structlog.get_logger()


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
