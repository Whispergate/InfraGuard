"""In-memory :class:`StateBackend` implementation.

Preserves the tool's historical single-node behavior. Safe for tests
and any deploy that is not scaled horizontally. TTLs are honored
lazily on read.
"""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass


@dataclass
class _Entry:
    value: str
    expires_at: float | None  # monotonic seconds; None = no TTL


class InMemoryBackend:
    def __init__(self) -> None:
        self._kv: dict[str, _Entry] = {}
        self._counters: dict[str, int] = {}
        self._counter_expiry: dict[str, float] = {}
        self._lock = asyncio.Lock()

    def _now(self) -> float:
        return time.monotonic()

    def _expired(self, entry: _Entry) -> bool:
        return entry.expires_at is not None and entry.expires_at <= self._now()

    # ── KV ─────────────────────────────────────────────────────────────

    async def get(self, key: str) -> str | None:
        async with self._lock:
            entry = self._kv.get(key)
            if entry is None:
                return None
            if self._expired(entry):
                self._kv.pop(key, None)
                return None
            return entry.value

    async def set(
        self, key: str, value: str, *, ttl_seconds: int | None = None
    ) -> None:
        async with self._lock:
            expires = self._now() + ttl_seconds if ttl_seconds else None
            self._kv[key] = _Entry(value, expires)

    async def delete(self, key: str) -> None:
        async with self._lock:
            self._kv.pop(key, None)

    async def check_and_set(
        self, key: str, value: str, *, ttl_seconds: int
    ) -> bool:
        async with self._lock:
            entry = self._kv.get(key)
            if entry is not None and not self._expired(entry):
                return False
            self._kv[key] = _Entry(value, self._now() + ttl_seconds)
            return True

    # ── Counters ───────────────────────────────────────────────────────

    def _expire_counter_if_due(self, key: str) -> None:
        exp = self._counter_expiry.get(key)
        if exp is not None and exp <= self._now():
            self._counters.pop(key, None)
            self._counter_expiry.pop(key, None)

    async def incr(self, key: str, *, ttl_seconds: int | None = None) -> int:
        async with self._lock:
            self._expire_counter_if_due(key)
            new = self._counters.get(key, 0) + 1
            self._counters[key] = new
            if ttl_seconds is not None:
                # Only set the expiry on first-write, matching Redis EXPIRE-only-if-new semantics.
                self._counter_expiry.setdefault(key, self._now() + ttl_seconds)
            return new

    async def counter(self, key: str) -> int:
        async with self._lock:
            self._expire_counter_if_due(key)
            return self._counters.get(key, 0)

    async def reset(self, key: str) -> None:
        async with self._lock:
            self._counters.pop(key, None)
            self._counter_expiry.pop(key, None)

    async def close(self) -> None:
        return None
