"""Per-source rate limit on the stager URI.

The C2 profile's ``http_stager`` transaction serves the initial
shellcode. It is single-fetch by design anyone hitting it more than a
handful of times per hour is either an attacker replaying a captured
staging URL or a defender's sandbox looping. Both should be blocked.

Sits in-process a shared-state version is left for a follow-up (uses
the same primitive as ``state/drop_rate_limit``).
"""

from __future__ import annotations

import time
from collections import defaultdict, deque
from typing import Any

import structlog

from infraguard.models.common import FilterResult
from infraguard.pipeline.base import RequestContext
from infraguard.plugins.base import BasePlugin

log = structlog.get_logger()


class Plugin(BasePlugin):
    name = "stager_rate_limit"
    version = "1.0.0"

    def __init__(self) -> None:
        self._settings: Any = None
        self._hits: dict[str, deque[float]] = defaultdict(lambda: deque(maxlen=100))

    def configure(self, settings: Any) -> None:
        self._settings = settings

    def _opt(self, key: str, default: Any = None) -> Any:
        if self._settings and hasattr(self._settings, "options"):
            return self._settings.options.get(key, default)
        return default

    async def on_request(self, ctx: RequestContext) -> FilterResult | None:
        profile = ctx.profile
        if profile is None or profile.http_stager is None:
            return None
        path = ctx.request.url.path
        stager_uris = set(profile.http_stager.uris or [])
        if path not in stager_uris:
            return None

        window = float(self._opt("window_seconds", 3600))
        cap = int(self._opt("max_per_window", 5))
        key = str(ctx.client_ip)
        now = time.time()
        buf = self._hits[key]
        buf.append(now)
        # Trim older-than-window entries.
        cutoff = now - window
        while buf and buf[0] < cutoff:
            buf.popleft()

        if len(buf) > cap:
            log.warning(
                "stager_rate_limit_fired",
                client=key,
                count=len(buf),
                cap=cap,
                path=path,
            )
            return FilterResult.block(
                reason=f"stager fetched {len(buf)}x in {int(window)}s",
                filter_name=self.name,
                score=1.0,
            )
        return None
