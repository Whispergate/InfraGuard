"""Example: Response transformer plugin that injects headers.

Demonstrates:
- Implementing on_response to modify outgoing responses
- Adding security headers
- Conditional transformation based on request context
"""

from __future__ import annotations

import structlog
from starlette.responses import Response

from infraguard.pipeline.base import RequestContext
from infraguard.plugins.base import BasePlugin

log = structlog.get_logger()

DEFAULT_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "X-XSS-Protection": "1; mode=block",
    "Referrer-Policy": "strict-origin-when-cross-origin",
}


class Plugin(BasePlugin):
    """Injects configurable security headers into every response."""

    name = "header_injector"
    version = "1.0.0"

    def configure(self, settings):
        super().configure(settings)
        opts = getattr(settings, "options", {}) if settings else {}
        custom = opts.get("headers", {})
        self._headers: dict[str, str] = {**DEFAULT_HEADERS, **custom}
        self._exclude_paths: list[str] = opts.get("exclude_paths", [])

    async def on_response(
        self, ctx: RequestContext, response: Response
    ) -> Response | None:
        path = ctx.request.url.path
        for prefix in self._exclude_paths:
            if path.startswith(prefix):
                return None

        for key, value in self._headers.items():
            response.headers[key] = value

        log.debug(
            "header_injector_applied",
            path=path,
            headers=list(self._headers.keys()),
        )
        return response


plugin = Plugin()
