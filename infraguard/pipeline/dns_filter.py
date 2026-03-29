"""Reverse DNS hostname checking filter."""

from __future__ import annotations

import re

from infraguard.intel.dns import reverse_dns
from infraguard.intel.known_ranges import BANNED_RDNS_KEYWORDS
from infraguard.models.common import FilterResult
from infraguard.pipeline.base import RequestContext


class DNSFilter:
    name = "dns"

    def __init__(self, extra_keywords: list[str] | None = None):
        keywords = BANNED_RDNS_KEYWORDS + (extra_keywords or [])
        escaped = [re.escape(k) for k in keywords]
        self._regex = re.compile("|".join(escaped), re.IGNORECASE)

    async def check(self, ctx: RequestContext) -> FilterResult:
        ip_str = str(ctx.client_ip)

        # Check if rdns was already resolved (e.g., by IntelManager)
        rdns = ctx.metadata.get("rdns")
        if rdns is None:
            rdns = await reverse_dns(ip_str)
            ctx.metadata["rdns"] = rdns

        if rdns and self._regex.search(rdns):
            return FilterResult.block(
                reason=f"Banned keyword in reverse DNS: {rdns}",
                filter_name=self.name,
                score=0.9,
            )

        return FilterResult.allow(filter_name=self.name)
