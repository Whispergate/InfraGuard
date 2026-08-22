"""Example: Request filter plugin that blocks by User-Agent pattern.

Demonstrates:
- Implementing on_request to filter incoming requests
- Using FilterResult to allow/block/suspect
- Reading configuration from plugin settings
"""

from __future__ import annotations

import re

import structlog

from infraguard.models.common import FilterResult
from infraguard.pipeline.base import RequestContext
from infraguard.plugins.base import BasePlugin

log = structlog.get_logger()


class Plugin(BasePlugin):
    """Blocks requests whose User-Agent matches a configurable regex."""

    name = "ua_blocker"
    version = "1.0.0"

    def configure(self, settings):
        super().configure(settings)
        self._pattern: str = self._get_opt("ua_pattern", r"(curl|wget|python-requests)")
        self._action: str = self._get_opt("action", "block")
        self._score: float = float(self._get_opt("score", 0.9))
        try:
            self._regex = re.compile(self._pattern, re.IGNORECASE)
        except re.error:
            log.warning("ua_blocker_bad_regex", pattern=self._pattern)
            self._regex = re.compile(r"$^")  # never matches

    def _get_opt(self, key: str, default=None):
        if self._settings and hasattr(self._settings, "options"):
            return self._settings.options.get(key, default)
        return default

    async def on_request(self, ctx: RequestContext) -> FilterResult | None:
        ua = ctx.request.headers.get("user-agent", "")
        if self._regex.search(ua):
            if self._action == "block":
                return FilterResult.block(
                    f"Blocked User-Agent: {ua[:80]}",
                    filter_name=self.name,
                    score=self._score,
                )
            return FilterResult.suspect(
                f"Suspicious User-Agent: {ua[:80]}",
                filter_name=self.name,
                score=self._score,
            )
        return None


plugin = Plugin()
