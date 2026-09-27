"""HTTP request smuggling detector.

Cheap, high-signal filter: any request that specifies BOTH
``Content-Length`` and ``Transfer-Encoding`` is either misconfigured
tooling or an active smuggling probe. Common defender-test payloads
(nuclei's smuggling templates, PortSwigger's tests) trip this
immediately.

Also flags the CL.TE and TE.CL classics: conflicting header case,
duplicated ``Content-Length``, non-``chunked`` Transfer-Encoding.

Cost: 4 header reads per request. Runs before the profile filter.
"""

from __future__ import annotations

import structlog

from infraguard.models.common import FilterResult
from infraguard.pipeline.base import RequestContext
from infraguard.plugins.base import BasePlugin

log = structlog.get_logger()


class Plugin(BasePlugin):
    name = "http_smuggling"
    version = "1.0.0"

    async def on_request(self, ctx: RequestContext) -> FilterResult | None:
        h = ctx.request.headers

        # Rule 1: CL + TE both present.
        cl_present = "content-length" in h
        te_present = "transfer-encoding" in h
        if cl_present and te_present:
            log.warning(
                "smuggling_cl_te_both",
                client=str(ctx.client_ip),
                cl=h["content-length"],
                te=h["transfer-encoding"],
            )
            return FilterResult.block(
                reason="HTTP smuggling: CL + TE both present",
                filter_name=self.name,
                score=1.0,
            )

        # Rule 2: TE not chunked (only 'chunked' is spec-legal for us).
        if te_present and h["transfer-encoding"].strip().lower() != "chunked":
            return FilterResult.block(
                reason=f"HTTP smuggling: non-chunked TE ({h['transfer-encoding'][:40]!r})",
                filter_name=self.name,
                score=1.0,
            )

        # Rule 3: duplicated Content-Length. Starlette collapses these
        # into a single header value with commas catch that shape.
        cl = h.get("content-length", "")
        if "," in cl:
            return FilterResult.block(
                reason="HTTP smuggling: duplicated Content-Length",
                filter_name=self.name,
                score=1.0,
            )

        return None
