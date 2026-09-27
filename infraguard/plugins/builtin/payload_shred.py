"""Zero out payload responses after N fetches.

The existing ``payload_tokens`` table already enforces max_uses at the
token layer. This plugin adds a secondary counter on the response
path: for a content route flagged with ``shred: true``, after the Nth
response the plugin returns an empty body regardless of what upstream
would have sent. Covers the case where the token counter is bypassed
or corrupted.

Config:

    plugins:
      - name: payload_shred
        options:
          max_fetches_per_path: 3
          shred_body: ""              # optional replacement body
          shred_status: 200           # keep 200 to blend
"""

from __future__ import annotations

from collections import defaultdict
from typing import Any

import structlog
from starlette.responses import Response

from infraguard.pipeline.base import RequestContext
from infraguard.plugins.base import BasePlugin

log = structlog.get_logger()


class Plugin(BasePlugin):
    name = "payload_shred"
    version = "1.0.0"

    def __init__(self) -> None:
        self._settings: Any = None
        self._counts: dict[str, int] = defaultdict(int)

    def configure(self, settings: Any) -> None:
        self._settings = settings

    def _opt(self, key: str, default: Any = None) -> Any:
        if self._settings and hasattr(self._settings, "options"):
            return self._settings.options.get(key, default)
        return default

    async def on_response(
        self, ctx: RequestContext, response: Response
    ) -> Response | None:
        # Only touch responses served through a content route.
        if not ctx.metadata.get("content_route_hit"):
            return None
        path = ctx.request.url.path
        self._counts[path] += 1
        cap = int(self._opt("max_fetches_per_path", 3))
        if self._counts[path] <= cap:
            return None
        body = str(self._opt("shred_body", "")).encode()
        status = int(self._opt("shred_status", 200))
        log.info("payload_shred_fired", path=path, count=self._counts[path])
        return Response(
            content=body,
            status_code=status,
            media_type=response.headers.get("content-type", "text/plain"),
        )
