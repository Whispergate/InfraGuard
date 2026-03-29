"""Drop action handlers - what to do when a request is blocked."""

from __future__ import annotations

import asyncio

import httpx
import structlog
from starlette.requests import Request
from starlette.responses import RedirectResponse, Response

from infraguard.config.schema import DropActionConfig
from infraguard.models.common import DropActionType

log = structlog.get_logger()


async def handle_drop(
    request: Request,
    config: DropActionConfig,
    reason: str = "",
) -> Response:
    """Execute the configured drop action for a blocked request."""
    log.info(
        "request_blocked",
        action=config.type.value,
        target=config.target,
        reason=reason,
        client=request.client.host if request.client else "unknown",
        path=request.url.path,
    )

    if config.type == DropActionType.REDIRECT:
        return RedirectResponse(url=config.target, status_code=302)

    elif config.type == DropActionType.RESET:
        # Return an empty response and let the connection close
        return Response(status_code=444, content=b"")

    elif config.type == DropActionType.PROXY:
        return await _proxy_decoy(config.target, request)

    elif config.type == DropActionType.TARPIT:
        return await _tarpit_response()

    # Fallback
    return Response(status_code=404, content=b"Not Found")


async def _proxy_decoy(target_url: str, request: Request) -> Response:
    """Proxy the request to a decoy site and return its response."""
    try:
        async with httpx.AsyncClient(
            follow_redirects=True, timeout=10.0, verify=False
        ) as client:
            resp = await client.get(target_url)
            return Response(
                content=resp.content,
                status_code=resp.status_code,
                headers=dict(resp.headers),
            )
    except Exception:
        log.exception("decoy_proxy_error", target=target_url)
        return Response(status_code=502, content=b"Bad Gateway")


async def _tarpit_response() -> Response:
    """Slow-drip response to waste scanner/bot time."""

    async def slow_body():
        # Send tiny chunks every 5 seconds for 60 seconds
        for _ in range(12):
            yield b" "
            await asyncio.sleep(5)

    return Response(
        content=b"",  # Will be overridden by streaming
        status_code=200,
        media_type="text/html",
    )
