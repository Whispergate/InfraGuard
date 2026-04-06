"""Drop action handlers - what to do when a request is blocked."""

from __future__ import annotations

import asyncio
import itertools
import mimetypes
import random
from pathlib import Path

import httpx
import structlog
from starlette.requests import Request
from starlette.responses import FileResponse, RedirectResponse, Response, StreamingResponse

from infraguard.config.schema import CanaryConfig, DropActionConfig, PersonaConfig
from infraguard.core.headers import sanitize_response_headers
from infraguard.core.ssl_context import build_ssl_context
from infraguard.intel.canary import inject_all_canaries
from infraguard.models.common import DropActionType

log = structlog.get_logger()

# Per-config round-robin state (maps config id to cycle iterator)
_round_robin_cycles: dict[int, itertools.cycle] = {}


def _select_target(config: DropActionConfig) -> str:
    """Select the effective target, applying rotation if configured."""
    if not config.rotation_targets:
        return config.target

    all_targets = [config.target] + config.rotation_targets

    if config.rotation_strategy == "round_robin":
        cfg_id = id(config)
        if cfg_id not in _round_robin_cycles:
            _round_robin_cycles[cfg_id] = itertools.cycle(all_targets)
        return next(_round_robin_cycles[cfg_id])

    # Default: random
    return random.choice(all_targets)


async def handle_drop(
    request: Request,
    config: DropActionConfig,
    reason: str = "",
    pages_dir: str = "pages",
    persona: PersonaConfig | None = None,
) -> Response:
    """Execute the configured drop action for a blocked request."""
    resolved_persona = persona or config.persona or PersonaConfig()
    target = _select_target(config)

    log.info(
        "request_blocked",
        action=config.type.value,
        target=target,
        reason=reason,
        client=request.client.host if request.client else "unknown",
        path=request.url.path,
    )

    if config.type == DropActionType.REDIRECT:
        return RedirectResponse(url=target, status_code=302)

    elif config.type == DropActionType.RESET:
        return Response(status_code=444, content=b"")

    elif config.type == DropActionType.PROXY:
        return await _proxy_decoy(target, request, resolved_persona)

    elif config.type == DropActionType.TARPIT:
        return await _tarpit_response(resolved_persona)

    elif config.type == DropActionType.DECOY:
        return _serve_decoy_spa(
            target, request, pages_dir, resolved_persona,
            canary=config.canary,
        )

    # Fallback - persona-consistent 404
    return Response(
        status_code=404,
        content=(
            resolved_persona.error_body_404.encode()
            if isinstance(resolved_persona.error_body_404, str)
            else resolved_persona.error_body_404
        ),
        headers={
            "Server": resolved_persona.server_header,
            "Content-Type": resolved_persona.error_content_type,
            **resolved_persona.extra_headers,
        },
    )


async def _proxy_decoy(
    target_url: str,
    request: Request,
    persona: PersonaConfig,
    ssl_verify: bool = False,
) -> Response:
    """Proxy the request to the decoy site, preserving the original path."""
    # Build the full URL: target base + original request path
    base = target_url.rstrip("/")
    path = request.url.path or "/"
    query = f"?{request.url.query}" if request.url.query else ""
    full_url = f"{base}{path}{query}"

    # Forward headers that make the response look legitimate
    forward_headers = {
        "Accept": request.headers.get("accept", "text/html"),
        "Accept-Language": request.headers.get("accept-language", "en-US,en;q=0.9"),
        "Accept-Encoding": "gzip, deflate",
        "User-Agent": request.headers.get("user-agent", "Mozilla/5.0"),
    }

    try:
        async with httpx.AsyncClient(
            follow_redirects=True, timeout=10.0, verify=build_ssl_context(ssl_verify)
        ) as client:
            resp = await client.get(full_url, headers=forward_headers)
            resp_headers = sanitize_response_headers(dict(resp.headers))

            return Response(
                content=resp.content,
                status_code=resp.status_code,
                headers=resp_headers,
            )
    except (httpx.RequestError, httpx.TimeoutException):
        log.warning("decoy_proxy_error", target=full_url)
        return Response(
            status_code=502,
            content=(
                persona.error_body_404.encode()
                if isinstance(persona.error_body_404, str)
                else persona.error_body_404
            ),
            headers={
                "Server": persona.server_header,
                "Content-Type": persona.error_content_type,
                **persona.extra_headers,
            },
        )


async def _tarpit_response(persona: PersonaConfig) -> Response:
    """Slow-drip response to waste scanner/bot time."""

    async def slow_body():
        # Send tiny chunks every 5 seconds for 60 seconds
        for _ in range(12):
            yield b" "
            await asyncio.sleep(5)

    return StreamingResponse(
        slow_body(),
        status_code=200,
        media_type=persona.error_content_type,
        headers={"Server": persona.server_header, **persona.extra_headers},
    )


def _serve_decoy_spa(
    site_name: str,
    request: Request,
    pages_dir: str,
    persona: PersonaConfig,
    canary: CanaryConfig | None = None,
) -> Response:
    """Serve a local SPA from the pages directory.

    The ``site_name`` is a folder inside ``pages_dir``. Requests are
    mapped to files within that folder. Unknown paths fall back to
    ``index.html`` so client-side SPA routing works.
    """
    root = Path(pages_dir).resolve() / site_name

    if not root.is_dir():
        log.warning("decoy_site_not_found", site=site_name, pages_dir=pages_dir)
        return Response(
            status_code=404,
            content=(
                persona.error_body_404.encode()
                if isinstance(persona.error_body_404, str)
                else persona.error_body_404
            ),
            headers={
                "Server": persona.server_header,
                "Content-Type": persona.error_content_type,
                **persona.extra_headers,
            },
        )

    # Map request path to a file
    req_path = request.url.path.lstrip("/") or "index.html"
    file_path = (root / req_path).resolve()

    # Path traversal protection
    try:
        file_path.relative_to(root)
    except ValueError:
        return Response(status_code=403, content=b"Forbidden")

    # Serve the file if it exists, otherwise SPA fallback to index.html
    if not file_path.is_file():
        index = root / "index.html"
        if index.is_file():
            file_path = index
        else:
            return Response(
                status_code=404,
                content=(
                    persona.error_body_404.encode()
                    if isinstance(persona.error_body_404, str)
                    else persona.error_body_404
                ),
                headers={
                    "Server": persona.server_header,
                    "Content-Type": persona.error_content_type,
                    **persona.extra_headers,
                },
            )

    content_type, _ = mimetypes.guess_type(str(file_path))

    # Inject canary tokens into HTML responses
    if canary and canary.enabled and content_type and "html" in content_type:
        html = file_path.read_text(encoding="utf-8")
        html = inject_all_canaries(
            html,
            enable_pixel=canary.tracking_pixel,
            enable_honeypot_link=canary.honeypot_link,
            enable_honeypot_form=canary.honeypot_form,
        )
        return Response(
            content=html,
            media_type=content_type,
            headers={"Server": persona.server_header, **persona.extra_headers},
        )

    return FileResponse(str(file_path), media_type=content_type)
