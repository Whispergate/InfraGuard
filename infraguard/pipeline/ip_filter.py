"""IP whitelist/blacklist filter."""

from __future__ import annotations

from infraguard.intel.ip_lists import CIDRList
from infraguard.intel.manager import IntelManager
from infraguard.models.common import FilterResult
from infraguard.pipeline.base import RequestContext


class IPFilter:
    name = "ip"

    def __init__(self, intel: IntelManager, domain_whitelists: dict[str, CIDRList] | None = None):
        self.intel = intel
        self.domain_whitelists = domain_whitelists or {}

    async def check(self, ctx: RequestContext) -> FilterResult:
        ip = ctx.client_ip
        ip_str = str(ip)

        # Check domain-specific whitelist (if whitelist is set, ONLY those IPs are allowed)
        domain_wl = self.domain_whitelists.get(
            ctx.request.headers.get("host", "").split(":")[0]
        )
        if domain_wl and domain_wl.size > 0:
            if not domain_wl.contains(ip):
                return FilterResult.block(
                    reason=f"IP {ip_str} not in domain whitelist",
                    filter_name=self.name,
                    score=1.0,
                )

        # Run full classification
        classification = await self.intel.classify(ip)

        if classification.is_whitelisted:
            return FilterResult.allow(filter_name=self.name)

        if classification.is_blocked:
            return FilterResult.block(
                reason=classification.reason or f"IP {ip_str} blocked",
                filter_name=self.name,
                score=1.0,
            )

        return FilterResult.allow(filter_name=self.name)
