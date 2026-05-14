"""Anti-replay filter - rejects duplicate requests within a time window.

Supports optional SQLite persistence so the replay window survives restarts.
A captured beacon request cannot be replayed after InfraGuard is restarted.
"""

from __future__ import annotations

import asyncio
import hashlib
import time
from typing import TYPE_CHECKING

import structlog

from infraguard.models.common import FilterResult
from infraguard.pipeline.base import RequestContext

if TYPE_CHECKING:
    from infraguard.tracking.database import Database

log = structlog.get_logger()


class ReplayFilter:
    name = "replay"

    def __init__(
        self,
        window_seconds: int = 86400,
        max_cache: int = 50000,
        db: "Database | None" = None,
        persist: bool = True,
    ):
        self._window = window_seconds
        self._max_cache = max_cache
        self._db = db
        self._persist = persist and db is not None
        # L1: in-memory hash -> seen_at (unix epoch float)
        self._seen: dict[str, float] = {}

    async def load_from_db(self) -> None:
        """Hydrate in-memory cache from SQLite on startup."""
        if not self._persist or self._db is None:
            return
        cutoff = int(time.time()) - self._window
        try:
            rows = await self._db.load_replay_tokens(cutoff)
            for hash_, seen_at in rows:
                self._seen[hash_] = float(seen_at)
            log.info("replay_cache_loaded", entries=len(rows))
        except Exception:
            log.exception("replay_cache_load_error")

    async def prune(self) -> None:
        """Remove expired entries from both in-memory cache and DB."""
        cutoff = time.time() - self._window
        self._seen = {k: v for k, v in self._seen.items() if v > cutoff}
        if self._persist and self._db is not None:
            try:
                deleted = await self._db.prune_replay_tokens(int(cutoff))
                if deleted:
                    log.debug("replay_tokens_pruned", count=deleted)
            except Exception:
                log.exception("replay_token_prune_error")

    async def check(self, ctx: RequestContext) -> FilterResult:
        request = ctx.request
        body = ctx.metadata.get("body", b"")

        sig = hashlib.sha256()
        sig.update(request.method.encode())
        sig.update(request.url.path.encode())
        sig.update(request.headers.get("user-agent", "").encode())
        sig.update(request.headers.get("cookie", "").encode())
        if isinstance(body, bytes):
            sig.update(body)
        request_hash = sig.hexdigest()

        now = time.time()

        # Prune in-memory cache when it exceeds the max size
        if len(self._seen) > self._max_cache:
            cutoff = now - self._window
            self._seen = {k: v for k, v in self._seen.items() if v > cutoff}

        if request_hash in self._seen:
            last_seen = self._seen[request_hash]
            if now - last_seen < self._window:
                return FilterResult.block(
                    reason="Replay detected (duplicate request)",
                    filter_name=self.name,
                    score=0.8,
                )

        self._seen[request_hash] = now
        if self._persist and self._db is not None:
            asyncio.create_task(
                self._db.add_replay_token(request_hash, int(now))
            )
        return FilterResult.allow(filter_name=self.name)
