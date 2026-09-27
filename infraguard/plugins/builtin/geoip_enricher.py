"""Enrich ctx.metadata with country / ASN / org from the GeoIP DB.

Passive enricher: never blocks. Populates keys other filters can read:

    ctx.metadata["geo"] = {"country": "US", "asn": 15169, "org": "Google LLC"}

Uses whatever IntelManager already has open (the MMDB files at
/app/geoip/). Cheap: one dict lookup per request.
"""

from __future__ import annotations

from typing import Any

import structlog

from infraguard.pipeline.base import RequestContext
from infraguard.plugins.base import BasePlugin

log = structlog.get_logger()


class Plugin(BasePlugin):
    name = "geoip_enricher"
    version = "1.0.0"

    def __init__(self) -> None:
        self._settings: Any = None
        self._intel = None

    def configure(self, settings: Any) -> None:
        self._settings = settings
        # The IntelManager the router built at startup is on
        # ``app.state.intel_manager``; the loader attaches it here.
        self._intel = getattr(settings, "intel_manager", None)

    async def on_request(self, ctx: RequestContext) -> None:
        if self._intel is None:
            return None
        ip = str(ctx.client_ip)
        try:
            geo = self._intel.classify_ip(ip) if hasattr(self._intel, "classify_ip") else None
        except Exception as exc:
            log.debug("geoip_lookup_failed", ip=ip, error=str(exc))
            return None
        if geo is None:
            return None
        ctx.metadata.setdefault("geo", {}).update({
            "country": getattr(geo, "country", None),
            "asn":     getattr(geo, "asn", None),
            "org":     getattr(geo, "org", None),
        })
        return None
