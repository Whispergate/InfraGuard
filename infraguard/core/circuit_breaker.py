"""Async circuit breaker for upstream C2 connections."""
from __future__ import annotations

import asyncio
import time

import httpx
import structlog

log = structlog.get_logger()


class CircuitOpenError(Exception):
    """Raised when the circuit is OPEN and the request should not be forwarded."""

    def __init__(self, upstream: str):
        self.upstream = upstream
        super().__init__(f"Circuit open for {upstream}")


class CircuitBreaker:
    """Per-upstream circuit breaker: CLOSED -> OPEN -> HALF_OPEN -> CLOSED.

    Args:
        upstream: Upstream URL identifier for logging.
        failure_threshold: Consecutive failures before opening circuit.
        recovery_timeout: Seconds to wait in OPEN before allowing a probe.
    """

    CLOSED = "CLOSED"
    OPEN = "OPEN"
    HALF_OPEN = "HALF_OPEN"

    def __init__(
        self,
        upstream: str,
        failure_threshold: int = 5,
        recovery_timeout: float = 30.0,
    ):
        self.upstream = upstream
        self._threshold = failure_threshold
        self._recovery_timeout = recovery_timeout
        self._failures = 0
        self._state = self.CLOSED
        self._opened_at: float | None = None
        self._lock = asyncio.Lock()

    @property
    def state(self) -> str:
        return self._state

    @property
    def failure_count(self) -> int:
        return self._failures

    async def call(self, coro_fn, *args, **kwargs):
        """Execute ``coro_fn(*args, **kwargs)`` with circuit-breaker protection.

        Raises:
            CircuitOpenError: When the circuit is OPEN and no probe is allowed.
            httpx.TimeoutException | httpx.ConnectError: Re-raised on upstream
                failure so the caller can take the appropriate drop action.
        """
        async with self._lock:
            if self._state == self.OPEN:
                elapsed = time.monotonic() - self._opened_at
                if elapsed >= self._recovery_timeout:
                    self._state = self.HALF_OPEN
                    log.info("circuit_half_open", upstream=self.upstream)
                else:
                    raise CircuitOpenError(self.upstream)

        try:
            result = await coro_fn(*args, **kwargs)
            await self._on_success()
            return result
        except (httpx.TimeoutException, httpx.ConnectError):
            await self._on_failure()
            raise

    async def _on_success(self) -> None:
        async with self._lock:
            if self._state in (self.HALF_OPEN, self.OPEN):
                log.info(
                    "circuit_closed",
                    upstream=self.upstream,
                    previous_state=self._state,
                )
            self._failures = 0
            self._state = self.CLOSED
            self._opened_at = None

    async def _on_failure(self) -> None:
        async with self._lock:
            self._failures += 1
            if self._failures >= self._threshold and self._state == self.CLOSED:
                self._state = self.OPEN
                self._opened_at = time.monotonic()
                log.warning(
                    "circuit_opened",
                    upstream=self.upstream,
                    failures=self._failures,
                )
            elif self._state == self.HALF_OPEN:
                self._state = self.OPEN
                self._opened_at = time.monotonic()
                log.warning("circuit_reopened", upstream=self.upstream)
