"""Redis-backed :class:`StateBackend` implementation.

Opt-in. Requires the ``redis`` package (``pip install redis``). Enables
``docker compose --scale proxy-node=N`` - every proxy replica sees the
same replay cache, breaker state, and dynamic whitelist.

The module deliberately imports ``redis.asyncio`` lazily so a build
without the dep still passes ``python -c "import infraguard.state"``.
"""

from __future__ import annotations

from typing import Any

import structlog

log = structlog.get_logger()


class RedisBackend:
    def __init__(
        self,
        url: str = "redis://redis:6379/0",
        prefix: str = "infraguard:",
    ) -> None:
        self._url = url
        self._prefix = prefix
        self._client: Any | None = None
        self._counter_prefix = f"{prefix}ctr:"
        self._kv_prefix = f"{prefix}kv:"

    async def _get_client(self) -> Any:
        if self._client is None:
            try:
                import redis.asyncio as aioredis
            except ImportError as exc:
                raise RuntimeError(
                    "redis package not installed; run 'pip install redis' or "
                    "set state.backend: memory in config.yaml"
                ) from exc
            self._client = aioredis.from_url(self._url, decode_responses=True)
        return self._client

    def _kv(self, key: str) -> str:
        return f"{self._kv_prefix}{key}"

    def _ctr(self, key: str) -> str:
        return f"{self._counter_prefix}{key}"

    # ── KV ─────────────────────────────────────────────────────────────

    async def get(self, key: str) -> str | None:
        client = await self._get_client()
        return await client.get(self._kv(key))

    async def set(
        self, key: str, value: str, *, ttl_seconds: int | None = None
    ) -> None:
        client = await self._get_client()
        await client.set(self._kv(key), value, ex=ttl_seconds)

    async def delete(self, key: str) -> None:
        client = await self._get_client()
        await client.delete(self._kv(key))

    async def check_and_set(
        self, key: str, value: str, *, ttl_seconds: int
    ) -> bool:
        client = await self._get_client()
        # SET NX + EX in one round-trip. Returns True iff the key was set.
        result = await client.set(self._kv(key), value, ex=ttl_seconds, nx=True)
        return bool(result)

    # ── Counters ───────────────────────────────────────────────────────

    async def incr(self, key: str, *, ttl_seconds: int | None = None) -> int:
        client = await self._get_client()
        full = self._ctr(key)
        pipe = client.pipeline()
        pipe.incr(full)
        if ttl_seconds is not None:
            # NX so we don't reset the window on every incr.
            pipe.expire(full, ttl_seconds, nx=True)
        results = await pipe.execute()
        return int(results[0])

    async def counter(self, key: str) -> int:
        client = await self._get_client()
        raw = await client.get(self._ctr(key))
        return int(raw) if raw is not None else 0

    async def reset(self, key: str) -> None:
        client = await self._get_client()
        await client.delete(self._ctr(key))

    async def close(self) -> None:
        if self._client is not None:
            try:
                await self._client.close()
            except Exception:  # noqa: BLE001 - best-effort cleanup
                log.warning("redis_close_failed")
            self._client = None
