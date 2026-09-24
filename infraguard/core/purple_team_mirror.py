"""Purple-team mirror: duplicate every allowed request to a defender view.

When enabled, every request the pipeline allowed is fire-and-forget
copied to a secondary upstream (typically a SIEM ingest endpoint or a
blue-team lab). The primary C2 path is unaffected: the mirror runs
after the response has been sent to the beacon.

Scaffold. The dispatch primitive here is a bounded asyncio queue and
a worker task. Wiring into ``DomainRouter._forward_with_failover`` is
a one-line addition guarded by ``config.purple_team.enabled``, left
as the follow-up because it needs the same operator sign-off flow as
adding a plugin (the blue team receiving the mirror is by definition
a third party).

Config sketch:

    purple_team:
      enabled: false
      mirror_url: "https://blueteam.internal/collector/infraguard"
      auth_header: "Bearer <token>"
      only_allowed: true
      max_queue_depth: 5000
      drop_body_over_kib: 128
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from typing import Any

import structlog

log = structlog.get_logger()


@dataclass
class PurpleMirrorConfig:
    enabled: bool = False
    mirror_url: str = ""
    auth_header: str = ""
    only_allowed: bool = True
    max_queue_depth: int = 5000
    drop_body_over_kib: int = 128


class PurpleMirror:
    """Bounded-queue background dispatcher. Never blocks the hot path."""

    def __init__(self, cfg: PurpleMirrorConfig):
        self._cfg = cfg
        self._queue: asyncio.Queue = asyncio.Queue(maxsize=cfg.max_queue_depth)
        self._task: asyncio.Task | None = None
        self._client: Any = None

    async def start(self) -> None:
        if not self._cfg.enabled or not self._cfg.mirror_url:
            log.info("purple_mirror_disabled")
            return
        try:
            import httpx
        except ImportError:
            log.warning("purple_mirror_no_httpx")
            return
        self._client = httpx.AsyncClient(timeout=5)
        self._task = asyncio.create_task(self._worker())
        log.info("purple_mirror_started", url=self._cfg.mirror_url)

    async def stop(self) -> None:
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
        if self._client:
            await self._client.aclose()

    def submit(self, event: dict) -> None:
        """Enqueue an event for mirroring. Never raises."""
        try:
            self._queue.put_nowait(event)
        except asyncio.QueueFull:
            log.debug("purple_mirror_queue_full_dropping")

    async def _worker(self) -> None:
        headers = {"content-type": "application/json"}
        if self._cfg.auth_header:
            headers["authorization"] = self._cfg.auth_header
        while True:
            try:
                event = await self._queue.get()
                assert self._client is not None
                await self._client.post(
                    self._cfg.mirror_url, json=event, headers=headers,
                )
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                log.debug("purple_mirror_post_failed", error=str(exc))


__all__ = ["PurpleMirror", "PurpleMirrorConfig"]
