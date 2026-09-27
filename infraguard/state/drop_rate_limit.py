"""Distributed rate-limit for the drop-action response path.

A scanner hitting the fleet at N replicas today gets N drop redirects
back. the redirector effectively becomes a small amplifier and,
worse, leaks the domain's drop_action to the attacker N times as fast.

This limiter is checked BEFORE ``handle_drop`` sends a response. When a
source IP has hit the per-window quota, we return a bare TCP reset
(status 444 in nginx parlance. an empty ``Response`` with no body)
instead of the configured redirect / decoy / tarpit. That way an
overrun scanner spends bandwidth on nothing and receives no signal
about what our real drop_action looks like.

Uses the shared state counter (``incr`` + TTL) so the quota is
enforced fleet-wide, not per-process.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import structlog

if TYPE_CHECKING:
    from infraguard.state import StateBackend

log = structlog.get_logger()

_KEY_PREFIX = "drop_rl:"


class DropRateLimiter:
    """Per-source-IP token bucket for the drop-response path.

    Configuration is intentionally coarse (one dimension: requests per
    ``window_seconds``) a full multi-tier limiter belongs in the
    dashboard's rate_limit stack, not on the hot path.
    """

    def __init__(
        self,
        backend: StateBackend | None,
        limit: int = 30,
        window_seconds: int = 60,
    ):
        self._backend = backend
        self._limit = limit
        self._window = window_seconds

    async def should_soft_drop(self, client_ip: str) -> bool:
        """Return True if the source IP has exceeded its drop quota.

        Falls open (returns False) if the backend is unavailable. a
        broken Redis must never turn the whole fleet into a black
        hole. The per-process ratelimit in ui/api/rate_limit.py is a
        secondary safety net.
        """
        if self._backend is None:
            return False
        try:
            count = await self._backend.incr(
                _KEY_PREFIX + client_ip, ttl_seconds=self._window
            )
        except Exception:
            log.debug("drop_rate_limit_backend_error", ip=client_ip)
            return False
        return count > self._limit


__all__ = ["DropRateLimiter"]
