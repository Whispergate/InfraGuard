"""Banned words in HTTP headers filter."""

from __future__ import annotations

import re

from infraguard.intel.known_ranges import BANNED_HEADER_KEYWORDS
from infraguard.models.common import FilterResult
from infraguard.pipeline.base import RequestContext


class HeaderFilter:
    name = "header"

    # Standard headers whose values contain opaque/encoded data that
    # should NOT be scanned for banned keywords (base64 beacon data
    # will randomly contain short strings like "nmap", "zap", etc.)
    _SKIP_VALUE_CHECK = frozenset({
        "cookie",
        "set-cookie",
        "authorization",
        "proxy-authorization",
        "accept",
        "accept-encoding",
        "accept-language",
        "content-type",
        "content-length",
        "host",
        "referer",
        "origin",
        "user-agent",
        "if-none-match",
        "if-modified-since",
        "cache-control",
        "connection",
        "upgrade",
        "sec-websocket-key",
        "sec-websocket-version",
        "sec-fetch-dest",
        "sec-fetch-mode",
        "sec-fetch-site",
    })

    def __init__(self, extra_keywords: list[str] | None = None):
        keywords = BANNED_HEADER_KEYWORDS + (extra_keywords or [])
        escaped = [re.escape(k) for k in keywords]
        self._regex = re.compile("|".join(escaped), re.IGNORECASE)

    async def check(self, ctx: RequestContext) -> FilterResult:
        for header_name, header_value in ctx.request.headers.items():
            lower_name = header_name.lower()

            # Check header names for banned keywords
            if self._regex.search(header_name):
                return FilterResult.block(
                    reason=f"Banned keyword in header name: {header_name}",
                    filter_name=self.name,
                    score=0.9,
                )

            # Only check values of non-standard headers - standard headers
            # carry opaque data (base64, encoded cookies) that will false-
            # positive on short keywords like "nmap", "zap", etc.
            if lower_name not in self._SKIP_VALUE_CHECK:
                if self._regex.search(header_value):
                    return FilterResult.block(
                        reason=f"Banned keyword in header value: {header_name}",
                        filter_name=self.name,
                        score=0.8,
                    )

        return FilterResult.allow(filter_name=self.name)
