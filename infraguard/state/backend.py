"""Shared-state Protocol + factory."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

import structlog

log = structlog.get_logger()


class StateBackend(Protocol):
    """Minimum surface a distributed-state backend must provide.

    Only the operations InfraGuard's subsystems actually use are here.
    Keeping it small means the in-memory implementation stays tiny and
    the Redis one maps 1:1 to native commands.
    """

    # ── Basic KV with TTL ──────────────────────────────────────────────

    async def get(self, key: str) -> str | None: ...
    async def set(self, key: str, value: str, *, ttl_seconds: int | None = None) -> None: ...
    async def delete(self, key: str) -> None: ...

    # ── Replay-cache primitive ─────────────────────────────────────────

    async def check_and_set(
        self, key: str, value: str, *, ttl_seconds: int
    ) -> bool:
        """SETNX-with-TTL. Returns True iff this call was the first to set the key."""
        ...

    # ── Shared counters (circuit-breaker failure count, etc.) ──────────

    async def incr(self, key: str, *, ttl_seconds: int | None = None) -> int: ...
    async def counter(self, key: str) -> int: ...
    async def reset(self, key: str) -> None: ...

    # ── Lifecycle ──────────────────────────────────────────────────────

    async def close(self) -> None: ...


@dataclass
class StateConfig:
    """Runtime configuration for the shared-state backend."""

    backend: str = "memory"  # "memory" | "redis"
    redis_url: str = "redis://redis:6379/0"
    key_prefix: str = "infraguard:"


def build_state_backend(cfg: StateConfig) -> StateBackend:
    """Instantiate the backend named by ``cfg.backend``.

    Falls back to the in-memory backend with a loud warning if the
    Redis backend was requested but ``redis`` is not importable - the
    tool stays up, but the operator sees the misconfiguration.
    """
    kind = (cfg.backend or "memory").lower()
    if kind == "memory":
        from infraguard.state.memory import InMemoryBackend

        return InMemoryBackend()
    if kind == "redis":
        try:
            from infraguard.state.redis_backend import RedisBackend
        except ImportError:
            log.warning(
                "state_backend_redis_unavailable_falling_back_to_memory",
                hint="pip install redis, or set state.backend: memory",
            )
            from infraguard.state.memory import InMemoryBackend

            return InMemoryBackend()
        return RedisBackend(url=cfg.redis_url, prefix=cfg.key_prefix)
    raise ValueError(f"unknown state backend: {cfg.backend!r}")
