"""Anti-replay filter - rejects duplicate requests within a time window.

Supports optional SQLite persistence so the replay window survives restarts.
A captured beacon request cannot be replayed after InfraGuard is restarted.
"""

from __future__ import annotations

import asyncio
import time
from typing import TYPE_CHECKING

import structlog

from infraguard.models.common import FilterResult
from infraguard.models.events import compute_request_hash
from infraguard.pipeline.base import RequestContext

if TYPE_CHECKING:
    from infraguard.state import StateBackend
    from infraguard.tracking.database import Database

log = structlog.get_logger()


class ReplayFilter:
    """Anti-replay filter with three optional persistence tiers.

    * In-memory ``_seen`` dict - always present, fastest path.
    * SQLite ``replay_tokens`` - survives restarts of a single node.
    * Shared :class:`StateBackend` - survives horizontal scaling; when
      configured, the first node to record a hash wins across the
      cluster via SETNX-with-TTL, so replay-detection is consistent no
      matter which replica the beacon hits first.
    """

    name = "replay"

    def __init__(
        self,
        window_seconds: int = 86400,
        max_cache: int = 50000,
        db: Database | None = None,
        persist: bool = True,
        state_backend: StateBackend | None = None,
    ):
        self._window = window_seconds
        self._max_cache = max_cache
        self._db = db
        self._persist = persist and db is not None
        self._state = state_backend
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
        # Prefer a hash already stashed by the router so a single
        # computation flows into both replay detection and the tracking DB.
        request_hash = ctx.metadata.get("request_hash")
        if not request_hash:
            request_hash = compute_request_hash(
                method=request.method,
                path=request.url.path,
                user_agent=request.headers.get("user-agent", ""),
                cookie=request.headers.get("cookie", ""),
                body=ctx.metadata.get("body", b""),
            )
            ctx.metadata["request_hash"] = request_hash

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

        # Cluster-wide replay check: SETNX with TTL. If another replica
        # already claimed this hash within the window, treat as replay.
        if self._state is not None:
            claimed = await self._state.check_and_set(
                f"replay:{request_hash}", str(int(now)), ttl_seconds=self._window
            )
            if not claimed:
                return FilterResult.block(
                    reason="Replay detected (duplicate request, cluster-wide)",
                    filter_name=self.name,
                    score=0.85,
                )

        self._seen[request_hash] = now
        if self._persist and self._db is not None:
            asyncio.create_task(
                self._db.add_replay_token(request_hash, int(now))
            )
        return FilterResult.allow(filter_name=self.name)
