"""GeoIP-based filtering."""

from __future__ import annotations

from infraguard.intel.manager import IntelManager
from infraguard.models.common import FilterResult
from infraguard.pipeline.base import RequestContext


class GeoFilter:
    name = "geo"

    def __init__(self, intel: IntelManager):
        self.intel = intel

    async def check(self, ctx: RequestContext) -> FilterResult:
        # GeoIP checks are already handled by IntelManager.classify()
        # called from IPFilter. This filter adds scoring for suspicious
        # but not blocked geolocations.
        geo = self.intel.geoip.lookup(str(ctx.client_ip))

        if not geo.country_code:
            # Can't determine geolocation - slight suspicion
            return FilterResult.suspect(
                reason="Unknown geolocation",
                filter_name=self.name,
                score=0.1,
            )

        return FilterResult.allow(filter_name=self.name)
