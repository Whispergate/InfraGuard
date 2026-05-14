"""Path enumeration detection filter.

Detects web scanners (dirbuster, ffuf, gobuster, feroxbuster) by tracking
unique URI paths per IP within a sliding time window. Legitimate beacons
and phishing victims hit 1-3 unique paths per session; scanners hit dozens
per minute.
"""

from __future__ import annotations

import time
from collections import defaultdict, deque

import structlog

from infraguard.models.common import FilterResult
from infraguard.pipeline.base import RequestContext

log = structlog.get_logger()

# Maximum path history entries kept per IP to bound memory usage
_MAX_HISTORY = 250


class EnumerationFilter:
    name = "enumeration"

    def __init__(
        self,
        unique_path_threshold: int = 20,
        unique_path_suspect_threshold: int = 8,
        window_seconds: int = 60,
    ) -> None:
        self._block_threshold = unique_path_threshold
        self._suspect_threshold = unique_path_suspect_threshold
        self._window = window_seconds
        # ip -> deque of (timestamp, path) tuples
        self._path_history: dict[str, deque[tuple[float, str]]] = defaultdict(
            lambda: deque(maxlen=_MAX_HISTORY)
        )

    async def check(self, ctx: RequestContext) -> FilterResult:
        ip = str(ctx.client_ip)
        path = ctx.request.url.path
        now = time.time()
        cutoff = now - self._window

        history = self._path_history[ip]

        # Slide the window: remove entries older than the cutoff
        while history and history[0][0] < cutoff:
            history.popleft()

        history.append((now, path))
        unique_paths = len({p for _, p in history})

        if unique_paths >= self._block_threshold:
            log.warning(
                "enumeration_detected",
                ip=ip,
                unique_paths=unique_paths,
                window_seconds=self._window,
            )
            return FilterResult.block(
                reason=f"Path enumeration: {unique_paths} unique URIs in {self._window}s",
                filter_name=self.name,
                score=0.85,
            )

        if unique_paths >= self._suspect_threshold:
            return FilterResult.suspect(
                reason=f"Possible enumeration: {unique_paths} unique URIs",
                filter_name=self.name,
                score=0.4,
            )

        return FilterResult.allow(filter_name=self.name)

    def prune_stale(self, max_age_seconds: int = 300) -> None:
        """Remove IPs whose last request is older than max_age_seconds."""
        cutoff = time.time() - max_age_seconds
        stale = [
            ip for ip, dq in self._path_history.items()
            if not dq or dq[-1][0] < cutoff
        ]
        for ip in stale:
            del self._path_history[ip]
