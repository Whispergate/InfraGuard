"""Anti-replay filter - rejects duplicate requests within a time window."""

from __future__ import annotations

import hashlib
import time

from infraguard.models.common import FilterResult
from infraguard.pipeline.base import RequestContext


class ReplayFilter:
    name = "replay"

    def __init__(self, window_seconds: int = 300, max_cache: int = 10000):
        self._window = window_seconds
        self._max_cache = max_cache
        self._seen: dict[str, float] = {}

    async def check(self, ctx: RequestContext) -> FilterResult:
        request = ctx.request
        body = ctx.metadata.get("body", b"")

        # Build a hash of the request signature
        sig = hashlib.sha256()
        sig.update(request.method.encode())
        sig.update(request.url.path.encode())
        sig.update(request.headers.get("user-agent", "").encode())
        sig.update(request.headers.get("cookie", "").encode())
        if isinstance(body, bytes):
            sig.update(body)
        request_hash = sig.hexdigest()

        now = time.time()

        # Prune expired entries if cache is getting large
        if len(self._seen) > self._max_cache:
            cutoff = now - self._window
            self._seen = {k: v for k, v in self._seen.items() if v > cutoff}

        # Check for replay
        if request_hash in self._seen:
            last_seen = self._seen[request_hash]
            if now - last_seen < self._window:
                return FilterResult.block(
                    reason="Replay detected (duplicate request)",
                    filter_name=self.name,
                    score=0.8,
                )

        self._seen[request_hash] = now
        return FilterResult.allow(filter_name=self.name)
