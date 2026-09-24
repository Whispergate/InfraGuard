"""Inject canarytokens.org (or self-hosted) tracking artifacts into decoy responses.

When a scanner or blue-team analyst downloads decoy HTML we serve, the
canary fires and pings a webhook, telling the operator that:

  * the specific decoy variant was inspected
  * from what network / user agent
  * at what time

Two artifacts injected (both configurable):

  * an invisible <img src="{token_url}" width=0 height=0> pixel
  * a <script src="{token_url}"> tag (some inspection sandboxes strip
    images but still execute JS)

Only mutates HTML responses coming out of the decoy / content-route
path (Content-Type: text/html*). Passthrough traffic to the C2
teamserver is never touched.
"""

from __future__ import annotations

from typing import Any

import structlog
from starlette.responses import Response

from infraguard.pipeline.base import RequestContext
from infraguard.plugins.base import BasePlugin

log = structlog.get_logger()

_INJECT_MARKER = b"</body>"


class Plugin(BasePlugin):
    name = "response_canary"
    version = "1.0.0"

    def __init__(self) -> None:
        self._settings: Any = None

    def configure(self, settings: Any) -> None:
        self._settings = settings

    def _opt(self, key: str, default: Any = None) -> Any:
        if self._settings and hasattr(self._settings, "options"):
            return self._settings.options.get(key, default)
        return default

    async def on_response(
        self, ctx: RequestContext, response: Response
    ) -> Response | None:
        token_url = self._opt("token_url")
        if not token_url:
            return None

        ct = response.headers.get("content-type", "")
        if "text/html" not in ct.lower():
            return None

        body = getattr(response, "body", None)
        if not body or _INJECT_MARKER not in body:
            # Streaming or file responses skip cleanly canary injection
            # into a chunked stream needs a different code path.
            return None

        inject = self._build_inject(token_url).encode("utf-8")
        new_body = body.replace(_INJECT_MARKER, inject + _INJECT_MARKER, 1)

        response.body = new_body
        # Keep Content-Length honest so downstream proxies do not truncate.
        response.headers["content-length"] = str(len(new_body))
        log.debug("response_canary_injected", client=str(ctx.client_ip))
        return response

    def _build_inject(self, token_url: str) -> str:
        # Both artifacts wrapped in one place so operators can disable
        # either via config without turning off the plugin.
        include_pixel = self._opt("include_pixel", True)
        include_script = self._opt("include_script", False)
        parts: list[str] = []
        if include_pixel:
            parts.append(
                f'<img src="{token_url}" width="1" height="1" '
                'style="position:absolute;left:-9999px" alt="">'
            )
        if include_script:
            parts.append(f'<script src="{token_url}" async></script>')
        return "".join(parts)
