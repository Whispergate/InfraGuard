"""Tests for the CircuitBreaker state machine.

Tests cover all three states (CLOSED, OPEN, HALF_OPEN) and the transitions
between them, using mock async functions to avoid real network calls.
"""
from __future__ import annotations

import asyncio
import time

import httpx
import pytest

from infraguard.core.circuit_breaker import CircuitBreaker, CircuitOpenError


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

async def _ok():
    """Successful upstream coroutine."""
    return "ok"


async def _timeout():
    """Upstream coroutine that raises httpx.TimeoutException."""
    raise httpx.TimeoutException("timed out")


async def _connect_error():
    """Upstream coroutine that raises httpx.ConnectError."""
    raise httpx.ConnectError("connection refused")


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestCircuitBreakerClosed:
    """Behaviour when the circuit starts CLOSED."""

    @pytest.mark.asyncio
    async def test_successful_call_returns_result(self):
        """Test 1: CLOSED state - successful call returns result, failure count stays 0."""
        cb = CircuitBreaker(upstream="https://c2.test", failure_threshold=5)
        result = await cb.call(_ok)
        assert result == "ok"
        assert cb.state == CircuitBreaker.CLOSED
        assert cb.failure_count == 0

    @pytest.mark.asyncio
    async def test_closed_to_open_on_consecutive_failures(self):
        """Test 2: CLOSED->OPEN transition after N consecutive httpx.TimeoutException."""
        cb = CircuitBreaker(upstream="https://c2.test", failure_threshold=5)
        for _ in range(4):
            with pytest.raises(httpx.TimeoutException):
                await cb.call(_timeout)
            assert cb.state == CircuitBreaker.CLOSED

        # 5th failure trips the breaker
        with pytest.raises(httpx.TimeoutException):
            await cb.call(_timeout)
        assert cb.state == CircuitBreaker.OPEN

    @pytest.mark.asyncio
    async def test_success_resets_failure_count(self):
        """Test 7: Success in CLOSED resets failure count (intermittent failures don't accumulate)."""
        cb = CircuitBreaker(upstream="https://c2.test", failure_threshold=5)
        # 3 failures, then a success - count must reset
        for _ in range(3):
            with pytest.raises(httpx.TimeoutException):
                await cb.call(_timeout)
        assert cb.failure_count == 3

        await cb.call(_ok)
        assert cb.failure_count == 0
        assert cb.state == CircuitBreaker.CLOSED

        # 4 more failures - still under threshold
        for _ in range(4):
            with pytest.raises(httpx.TimeoutException):
                await cb.call(_timeout)
        assert cb.state == CircuitBreaker.CLOSED


class TestCircuitBreakerOpen:
    """Behaviour when the circuit is OPEN."""

    @pytest.mark.asyncio
    async def test_open_raises_circuit_open_error_immediately(self):
        """Test 3: OPEN state - call raises CircuitOpenError without executing the coroutine."""
        cb = CircuitBreaker(upstream="https://c2.test", failure_threshold=3, recovery_timeout=999)
        for _ in range(3):
            with pytest.raises(httpx.TimeoutException):
                await cb.call(_timeout)

        assert cb.state == CircuitBreaker.OPEN

        called = []

        async def _should_not_run():
            called.append(True)
            return "should not run"

        with pytest.raises(CircuitOpenError) as exc_info:
            await cb.call(_should_not_run)

        assert not called, "Coroutine must not be executed when circuit is OPEN"
        assert "https://c2.test" in str(exc_info.value)

    @pytest.mark.asyncio
    async def test_circuit_open_error_carries_upstream(self):
        """CircuitOpenError stores the upstream URL for logging."""
        cb = CircuitBreaker(upstream="https://my-c2.example.com", failure_threshold=1)
        with pytest.raises(httpx.TimeoutException):
            await cb.call(_timeout)

        err = None
        try:
            await cb.call(_ok)
        except CircuitOpenError as e:
            err = e

        assert err is not None
        assert err.upstream == "https://my-c2.example.com"


class TestCircuitBreakerHalfOpen:
    """Behaviour during HALF_OPEN probe window."""

    def _open_breaker(self, recovery_timeout: float = 999) -> CircuitBreaker:
        """Return a breaker that is already OPEN."""
        cb = CircuitBreaker(
            upstream="https://c2.test",
            failure_threshold=1,
            recovery_timeout=recovery_timeout,
        )
        # Trip it synchronously by manually setting state (avoids real time.sleep)
        cb._state = CircuitBreaker.OPEN
        cb._failures = 1
        cb._opened_at = time.monotonic() - recovery_timeout - 1  # past the timeout
        return cb

    @pytest.mark.asyncio
    async def test_open_transitions_to_half_open_after_timeout(self):
        """Test 4: OPEN->HALF_OPEN - after recovery_timeout, next call is allowed as probe."""
        cb = self._open_breaker(recovery_timeout=0.01)
        # Wait just over the cooldown
        await asyncio.sleep(0.02)

        # The call should be let through (HALF_OPEN probe)
        result = await cb.call(_ok)
        assert result == "ok"
        assert cb.state == CircuitBreaker.CLOSED

    @pytest.mark.asyncio
    async def test_half_open_success_resets_to_closed(self):
        """Test 5: HALF_OPEN->CLOSED - successful probe resets failure count to 0."""
        cb = self._open_breaker()

        # Force HALF_OPEN directly
        cb._state = CircuitBreaker.HALF_OPEN

        result = await cb.call(_ok)
        assert result == "ok"
        assert cb.state == CircuitBreaker.CLOSED
        assert cb.failure_count == 0

    @pytest.mark.asyncio
    async def test_half_open_failure_reopens_circuit(self):
        """Test 6: HALF_OPEN->OPEN - failed probe re-opens the circuit."""
        cb = self._open_breaker()

        # Force HALF_OPEN directly
        cb._state = CircuitBreaker.HALF_OPEN

        with pytest.raises(httpx.ConnectError):
            await cb.call(_connect_error)

        assert cb.state == CircuitBreaker.OPEN
