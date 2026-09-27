"""Async circuit breaker for upstream C2 connections."""
from __future__ import annotations

import asyncio
import time
from typing import TYPE_CHECKING

import httpx
import structlog

if TYPE_CHECKING:
    from infraguard.state import StateBackend

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
        state_backend: Optional shared :class:`~infraguard.state.StateBackend`.
            When present, failure counts and the ``opened_at`` timestamp
            are mirrored into the backend so every proxy replica sees
            the same breaker state. Without it, behavior is unchanged
            (per-process breaker, single-node deploys).
    """

    CLOSED = "CLOSED"
    OPEN = "OPEN"
    HALF_OPEN = "HALF_OPEN"

    def __init__(
        self,
        upstream: str,
        failure_threshold: int = 5,
        recovery_timeout: float = 30.0,
        state_backend: StateBackend | None = None,
    ):
        self.upstream = upstream
        self._threshold = failure_threshold
        self._recovery_timeout = recovery_timeout
        self._failures = 0
        self._state = self.CLOSED
        self._opened_at: float | None = None
        self._probe_in_flight = False
        self._lock = asyncio.Lock()
        self._backend = state_backend
        # Namespaced keys - one breaker per upstream, cluster-wide.
        self._failure_key = f"breaker:{upstream}:failures"
        self._opened_key = f"breaker:{upstream}:opened_at"

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
                    self._probe_in_flight = True
                    log.info("circuit_half_open", upstream=self.upstream)
                else:
                    raise CircuitOpenError(self.upstream)
            elif self._state == self.HALF_OPEN and self._probe_in_flight:
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
            self._probe_in_flight = False
            self._failures = 0
            self._state = self.CLOSED
            self._opened_at = None
            if self._backend is not None:
                # Best-effort - a Redis blip must not fail a healthy request.
                try:
                    await self._backend.reset(self._failure_key)
                    await self._backend.delete(self._opened_key)
                except Exception:
                    log.debug("breaker_state_backend_reset_failed", upstream=self.upstream)

    async def _on_failure(self) -> None:
        async with self._lock:
            self._probe_in_flight = False
            self._failures += 1
            shared_failures = self._failures
            if self._backend is not None:
                try:
                    shared_failures = await self._backend.incr(
                        self._failure_key, ttl_seconds=int(self._recovery_timeout * 4)
                    )
                except Exception:
                    log.debug("breaker_incr_failed", upstream=self.upstream)
            trip = max(self._failures, shared_failures)
            if trip >= self._threshold and self._state == self.CLOSED:
                self._state = self.OPEN
                self._opened_at = time.monotonic()
                if self._backend is not None:
                    try:
                        await self._backend.set(
                            self._opened_key,
                            str(int(time.time())),
                            ttl_seconds=int(self._recovery_timeout * 4),
                        )
                    except Exception:
                        pass
                log.warning(
                    "circuit_opened",
                    upstream=self.upstream,
                    failures=trip,
                )
            elif self._state == self.HALF_OPEN:
                self._state = self.OPEN
                self._opened_at = time.monotonic()
                log.warning("circuit_reopened", upstream=self.upstream)
