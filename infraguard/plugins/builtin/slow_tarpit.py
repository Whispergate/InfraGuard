"""Slow-byte-drip drop action.

Not a filter; extends the drop path. When a request is destined for
the drop, this plugin (if configured for the domain) intercepts the
response and replaces it with a StreamingResponse that dribbles bytes
one at a time. Result: the scanner spends its connection budget
waiting on nothing, and we spend bandwidth of a few KB.

Config:

    plugins:
      - name: slow_tarpit
        options:
          only_domains: []             # empty = all domains
          bytes_per_second: 20
          total_bytes: 4096
          headers:
            content-type: text/html
"""

from __future__ import annotations

import asyncio
from typing import Any

import structlog
from starlette.responses import StreamingResponse

from infraguard.pipeline.base import RequestContext
from infraguard.plugins.base import BasePlugin

log = structlog.get_logger()


class Plugin(BasePlugin):
    name = "slow_tarpit"
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
        self, ctx: RequestContext, response
    ) -> StreamingResponse | None:
        # Only tarpit blocked requests. Allowed traffic must never be
        # slowed.
        pipeline_result = ctx.metadata.get("pipeline_result")
        if pipeline_result is None or getattr(pipeline_result, "allowed", True):
            return None

        only = self._opt("only_domains") or []
        if only and getattr(ctx, "domain", "") not in only:
            return None

        bps = int(self._opt("bytes_per_second", 20))
        total = int(self._opt("total_bytes", 4096))
        headers = self._opt("headers") or {}

        async def _drip():
            delay = 1.0 / max(bps, 1)
            sent = 0
            filler = b"<!-- " + b" " * 80 + b" -->\n"
            while sent < total:
                chunk = filler[: min(len(filler), total - sent)]
                yield chunk
                sent += len(chunk)
                await asyncio.sleep(delay)

        return StreamingResponse(
            _drip(),
            status_code=200,
            headers={k: str(v) for k, v in headers.items()} or {"content-type": "text/html"},
        )
