"""Banned words in HTTP headers filter."""

from __future__ import annotations

import re

from infraguard.intel.known_ranges import BANNED_HEADER_KEYWORDS
from infraguard.models.common import FilterResult
from infraguard.pipeline.base import RequestContext


class HeaderFilter:
    name = "header"

    def __init__(self, extra_keywords: list[str] | None = None):
        keywords = BANNED_HEADER_KEYWORDS + (extra_keywords or [])
        escaped = [re.escape(k) for k in keywords]
        self._regex = re.compile("|".join(escaped), re.IGNORECASE)

    async def check(self, ctx: RequestContext) -> FilterResult:
        for header_name, header_value in ctx.request.headers.items():
            if self._regex.search(header_name):
                return FilterResult.block(
                    reason=f"Banned keyword in header name: {header_name}",
                    filter_name=self.name,
                    score=0.9,
                )
            if self._regex.search(header_value):
                return FilterResult.block(
                    reason=f"Banned keyword in header value: {header_name}",
                    filter_name=self.name,
                    score=0.8,
                )

        return FilterResult.allow(filter_name=self.name)
