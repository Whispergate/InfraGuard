"""Dead man's switch - auto-shutdown when operator stops checking in.

If no operator heartbeat is received within the configured TTL, the
redirector stops accepting C2 traffic. This prevents abandoned
infrastructure from running indefinitely after an engagement ends.

Heartbeats are triggered by:
  - Any authenticated API request (dashboard access)
  - Explicit keepalive call to /api/keepalive
  - Config reload
"""

from __future__ import annotations

import asyncio
import time

import structlog

log = structlog.get_logger()


class DeadManSwitch:
    """Auto-shutdown mechanism based on operator heartbeat TTL."""

    def __init__(
        self,
        ttl_seconds: int = 86400,  # 24 hours default
        enabled: bool = False,
        on_expire: asyncio.Event | None = None,
    ):
        self.ttl_seconds = ttl_seconds
        self.enabled = enabled
        self._last_heartbeat = time.time()
        self._expired = False
        self._expire_event = on_expire or asyncio.Event()
        self._task: asyncio.Task | None = None

    def heartbeat(self) -> None:
        """Record an operator heartbeat, resetting the TTL countdown."""
        self._last_heartbeat = time.time()
        if self._expired:
            self._expired = False
            self._expire_event.clear()
            log.info("deadman_switch_reset", ttl=self.ttl_seconds)

    @property
    def time_remaining(self) -> float:
        """Seconds until the switch expires. Negative if expired."""
        return (self._last_heartbeat + self.ttl_seconds) - time.time()

    @property
    def is_expired(self) -> bool:
        return self._expired

    def get_status(self) -> dict:
        return {
            "enabled": self.enabled,
            "expired": self._expired,
            "time_remaining_seconds": max(0, self.time_remaining),
            "ttl_seconds": self.ttl_seconds,
            "last_heartbeat": self._last_heartbeat,
        }

    async def _watch_loop(self) -> None:
        """Background task that checks for TTL expiry."""
        while True:
            remaining = self.time_remaining
            if remaining <= 0 and not self._expired:
                self._expired = True
                self._expire_event.set()
                log.critical(
                    "deadman_switch_expired",
                    ttl=self.ttl_seconds,
                    last_heartbeat=self._last_heartbeat,
                )
                # Don't break — keep checking in case operator comes back
                # and calls heartbeat() to reset

            # Check every 1/10th of TTL or 60s, whichever is smaller
            check_interval = min(self.ttl_seconds / 10, 60)
            await asyncio.sleep(check_interval)

    def start(self) -> None:
        """Start the dead man's switch watchdog."""
        if self.enabled:
            self._last_heartbeat = time.time()
            self._task = asyncio.create_task(self._watch_loop())
            log.info("deadman_switch_started", ttl=self.ttl_seconds)

    async def stop(self) -> None:
        """Stop the watchdog."""
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
