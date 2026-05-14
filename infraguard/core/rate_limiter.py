"""Per-IP sliding-window rate limiter for content delivery routes.

Prevents bulk payload harvesting: even an IP that passes all pipeline
filters cannot exceed the configured download rate.
"""

from __future__ import annotations

import time
from collections import defaultdict, deque


class ContentRateLimiter:
    """Sliding-window per-IP download rate limiter."""

    def __init__(self) -> None:
        # (ip, route_path) -> deque of request timestamps
        self._windows: dict[tuple[str, str], deque[float]] = defaultdict(deque)

    def check(self, ip: str, route_path: str, max_downloads: int, window_seconds: int) -> bool:
        """Return True if request is within rate limit, False if exceeded."""
        key = (ip, route_path)
        now = time.time()
        cutoff = now - window_seconds
        dq = self._windows[key]

        # Prune expired timestamps
        while dq and dq[0] < cutoff:
            dq.popleft()

        if len(dq) >= max_downloads:
            return False

        dq.append(now)
        return True

    def reset(self, ip: str, route_path: str = "") -> None:
        """Clear rate limit state for an IP (and optionally a specific route)."""
        if route_path:
            self._windows.pop((ip, route_path), None)
        else:
            keys = [k for k in self._windows if k[0] == ip]
            for k in keys:
                del self._windows[k]

    def prune_stale(self, max_window_seconds: int = 3600) -> None:
        """Remove entries that haven't been touched in max_window_seconds."""
        cutoff = time.time() - max_window_seconds
        stale = [k for k, dq in self._windows.items() if not dq or dq[-1] < cutoff]
        for k in stale:
            del self._windows[k]
