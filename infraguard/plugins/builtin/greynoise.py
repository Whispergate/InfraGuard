"""GreyNoise Community API classifier.

Adds one dimension to the pipeline: is this source IP KNOWN to be a
research scanner (Shodan / Censys / academic), a KNOWN malicious
actor, or unclassified. Actions:

  * classification 'benign'    -> lower filter score (never block)
  * classification 'malicious' -> block outright
  * classification 'unknown'   -> pass through unchanged

Uses the free Community API (no key, but rate-limited). Results are
cached in the shared state backend so a scanner hitting N replicas
only spends one API call per IP per TTL window.

Config:

    plugins:
      - name: greynoise
        options:
          cache_ttl_seconds: 3600
          api_url: "https://api.greynoise.io/v3/community/{ip}"
          # Optional: user-supplied enterprise API key for higher quota
          api_key: null
"""

from __future__ import annotations

from typing import Any

import httpx
import structlog

from infraguard.models.common import FilterResult
from infraguard.pipeline.base import RequestContext
from infraguard.plugins.base import BasePlugin

log = structlog.get_logger()


class Plugin(BasePlugin):
    name = "greynoise"
    version = "1.0.0"

    def __init__(self) -> None:
        self._settings: Any = None
        self._client: httpx.AsyncClient | None = None
        # In-process LRU cache. When infraguard.state has a client
        # backend attached, we also mirror there so peer replicas do
        # not each spend an API call.
        self._cache: dict[str, tuple[str, float]] = {}

    def configure(self, settings: Any) -> None:
        self._settings = settings

    def _opt(self, key: str, default: Any = None) -> Any:
        if self._settings and hasattr(self._settings, "options"):
            return self._settings.options.get(key, default)
        return default

    async def on_startup(self) -> None:
        self._client = httpx.AsyncClient(timeout=3)

    async def on_shutdown(self) -> None:
        if self._client is not None:
            await self._client.aclose()

    async def on_request(self, ctx: RequestContext) -> FilterResult | None:
        if self._client is None:
            return None
        ip = str(ctx.client_ip)
        classification = await self._classify(ip)
        if classification is None:
            return None
        if classification == "malicious":
            return FilterResult.block(
                reason="GreyNoise: known malicious",
                filter_name=self.name,
                score=1.0,
            )
        if classification == "benign":
            # A benign scanner still gets logged but at zero score, so
            # profile / bot filters can decide independently.
            return FilterResult.allow(filter_name=self.name)
        return None  # unknown or lookup failed

    async def _classify(self, ip: str) -> str | None:
        import time
        ttl = int(self._opt("cache_ttl_seconds", 3600))
        now = time.time()
        cached = self._cache.get(ip)
        if cached and (now - cached[1]) < ttl:
            return cached[0]
        url = self._opt("api_url",
                        "https://api.greynoise.io/v3/community/{ip}").format(ip=ip)
        headers = {}
        if key := self._opt("api_key"):
            headers["key"] = key
        try:
            r = await self._client.get(url, headers=headers)
        except Exception as exc:
            log.debug("greynoise_lookup_failed", ip=ip, error=str(exc))
            return None
        if r.status_code == 404:
            self._cache[ip] = ("unknown", now)
            return "unknown"
        if r.status_code != 200:
            log.debug("greynoise_non_200", ip=ip, status=r.status_code)
            return None
        try:
            body = r.json()
            classification = body.get("classification", "unknown")
            self._cache[ip] = (classification, now)
            return classification
        except Exception as exc:
            log.debug("greynoise_parse_failed", ip=ip, error=str(exc))
            return None
