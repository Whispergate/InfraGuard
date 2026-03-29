"""Anti-crawler and anti-bot detection filter."""

from __future__ import annotations

import re

from infraguard.intel.known_ranges import BOT_USER_AGENT_PATTERNS
from infraguard.models.common import FilterResult
from infraguard.pipeline.base import RequestContext


class BotFilter:
    name = "bot"

    def __init__(self, extra_patterns: list[str] | None = None):
        patterns = BOT_USER_AGENT_PATTERNS + (extra_patterns or [])
        # Compile a single regex for efficiency
        escaped = [re.escape(p) for p in patterns]
        self._ua_regex = re.compile("|".join(escaped), re.IGNORECASE)

    async def check(self, ctx: RequestContext) -> FilterResult:
        ua = ctx.request.headers.get("user-agent", "")

        # Empty User-Agent is suspicious
        if not ua:
            return FilterResult.suspect(
                reason="Empty User-Agent",
                filter_name=self.name,
                score=0.4,
            )

        # Check against known bot patterns
        if self._ua_regex.search(ua):
            return FilterResult.block(
                reason=f"Bot/scanner User-Agent detected",
                filter_name=self.name,
                score=0.9,
            )

        # Header anomaly: missing Accept header is suspicious for browsers
        if not ctx.request.headers.get("accept"):
            return FilterResult.suspect(
                reason="Missing Accept header",
                filter_name=self.name,
                score=0.3,
            )

        return FilterResult.allow(filter_name=self.name)
