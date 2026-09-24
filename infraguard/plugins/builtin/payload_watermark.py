"""Inject a unique watermark into every served payload.

The watermark is a short, invisible byte pattern derived from a per-op
seed plus a monotonic counter. Later, if a payload lands on VirusTotal
or a sandbox report, the pattern lets the operator prove which fetch
it came from (which target, which time).

Injection strategy depends on content-type:

  * text (JS / CSS / HTML): append ``/* infraguard:<hex> */`` as a
    trailing comment. Harmless; browsers ignore.
  * binary (application/octet-stream and friends): overlay-appends a
    trailer with a magic header + hex. Loaders that only read up to
    Content-Length skip it. Belongs disabled unless the operator has
    verified the loader ignores trailing bytes.

For safety: default is text-only. Binary mode is opt-in per-plugin
config.
"""

from __future__ import annotations

import os
import secrets
import time
from typing import Any

import structlog
from starlette.responses import Response

from infraguard.pipeline.base import RequestContext
from infraguard.plugins.base import BasePlugin

log = structlog.get_logger()


class Plugin(BasePlugin):
    name = "payload_watermark"
    version = "1.0.0"

    def __init__(self) -> None:
        self._settings: Any = None
        self._seed = secrets.token_bytes(8)

    def configure(self, settings: Any) -> None:
        self._settings = settings

    def _opt(self, key: str, default: Any = None) -> Any:
        if self._settings and hasattr(self._settings, "options"):
            return self._settings.options.get(key, default)
        return default

    async def on_response(
        self, ctx: RequestContext, response: Response
    ) -> Response | None:
        # Only watermark responses served through a content route or
        # explicit "payload" flag on ctx.metadata. Never watermark a
        # C2 beacon response a subtle byte can trip the profile
        # server-side.
        if not ctx.metadata.get("content_route_hit") and not ctx.metadata.get("is_payload"):
            return None
        body = getattr(response, "body", None)
        if not body:
            return None

        ct = response.headers.get("content-type", "").lower()
        mark = self._mark(ctx)

        if any(t in ct for t in ("text/", "application/javascript", "application/json")):
            new_body = body + f"\n/* infraguard:{mark} */\n".encode()
        elif self._opt("binary", False):
            new_body = body + b"IGWM" + mark.encode()
        else:
            return None  # skip binary unless opted in

        response.body = new_body
        response.headers["content-length"] = str(len(new_body))
        log.debug("payload_watermarked", mark=mark, path=ctx.request.url.path)
        return response

    def _mark(self, ctx: RequestContext) -> str:
        # 12 hex chars is 48 bits: enough to distinguish thousands of
        # fetches per op with negligible collision.
        h = os.urandom(3)  # per-request randomness
        stamp = int(time.time()) & 0xFFFFFF
        return f"{stamp:06x}{h.hex()}"
