"""Aggressive response-header sanitizer.

The base :mod:`infraguard.core.headers` sanitizer removes the most
common leakers (Server, X-Powered-By, Via) from upstream responses.
This plugin extends that with a configurable denylist and also
normalizes the ``Date`` header format (nginx and Apache format
seconds-since-epoch subtly differently, which can fingerprint).

Config:

    plugins:
      - name: sig_strip
        options:
          extra_strip:
            - x-generator
            - x-turbo-charged-by
            - x-runtime
          normalize_date: true
"""

from __future__ import annotations

import email.utils
import time
from typing import Any

import structlog
from starlette.responses import Response

from infraguard.pipeline.base import RequestContext
from infraguard.plugins.base import BasePlugin

log = structlog.get_logger()


class Plugin(BasePlugin):
    name = "sig_strip"
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
        extra = [h.lower() for h in (self._opt("extra_strip") or [])]
        for h in extra:
            if h in response.headers:
                del response.headers[h]

        if self._opt("normalize_date", True):
            # RFC 7231 Date format: canonical formatting so upstream
            # variance does not leak.
            response.headers["date"] = email.utils.formatdate(
                timeval=time.time(), usegmt=True
            )
        return response
