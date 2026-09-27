"""Make proxied responses look like cached CDN assets.

Beacon URIs are typically things like ``/assets/style.css`` and
``/api/v1/telemetry``. A real CDN would return them with a suite of
cache headers (ETag, Last-Modified, Cache-Control, Age, X-Cache).
Bare responses without any of these stand out on the wire when a
defender is watching network flows.

This plugin injects a plausible set into every response served
through a beacon URI, with values derived deterministically from the
response body so they are stable across redeploys but differ per
resource.
"""

from __future__ import annotations

import email.utils
import hashlib
import time

import structlog
from starlette.responses import Response

from infraguard.pipeline.base import RequestContext
from infraguard.plugins.base import BasePlugin

log = structlog.get_logger()


class Plugin(BasePlugin):
    name = "cache_mimicry"
    version = "1.0.0"

    async def on_response(
        self, ctx: RequestContext, response: Response
    ) -> Response | None:
        body = getattr(response, "body", b"") or b""
        if not body:
            return None  # nothing to hash

        # Only shape asset-like paths.
        path = ctx.request.url.path
        if not any(path.startswith(p) for p in ("/assets/", "/static/", "/img/", "/js/")):
            return None

        # ETag: stable hash of body (weak validator so we do not have
        # to promise byte-for-byte revalidation).
        etag = 'W/"' + hashlib.sha1(body).hexdigest()[:16] + '"'
        response.headers.setdefault("etag", etag)

        # Last-Modified: 6 hours ago, rounded to the hour so it stays
        # stable within a bucket instead of ticking every second.
        lm_ts = int(time.time() // 3600) * 3600 - 6 * 3600
        response.headers.setdefault(
            "last-modified", email.utils.formatdate(lm_ts, usegmt=True)
        )

        response.headers.setdefault("cache-control", "public, max-age=3600")
        response.headers.setdefault("age", str(int(time.time()) % 3600))
        response.headers.setdefault("x-cache", "HIT")

        return response
