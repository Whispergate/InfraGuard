"""Async batched event recording to SQLite."""

from __future__ import annotations

import asyncio
from collections import deque

import structlog

from infraguard.models.events import RequestEvent
from infraguard.tracking.database import Database

log = structlog.get_logger()


class EventRecorder:
    """Batched async writer for request events.

    Events are buffered and flushed to SQLite either when the buffer
    reaches ``batch_size`` or every ``flush_interval`` seconds.
    """

    def __init__(
        self,
        db: Database,
        batch_size: int = 50,
        flush_interval: float = 5.0,
    ):
        self.db = db
        self.batch_size = batch_size
        self.flush_interval = flush_interval
        self._buffer: deque[RequestEvent] = deque()
        self._task: asyncio.Task | None = None

    async def start(self) -> None:
        self._task = asyncio.create_task(self._flush_loop())
        log.info("recorder_started", batch_size=self.batch_size)

    async def stop(self) -> None:
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
        await self._flush()

    def record(self, event: RequestEvent) -> None:
        """Add an event to the buffer (non-blocking)."""
        self._buffer.append(event)
        if len(self._buffer) >= self.batch_size:
            asyncio.create_task(self._flush())

    async def _flush_loop(self) -> None:
        while True:
            await asyncio.sleep(self.flush_interval)
            await self._flush()

    async def _flush(self) -> None:
        if not self._buffer:
            return

        events = []
        while self._buffer:
            events.append(self._buffer.popleft())

        params = [
            (
                e.timestamp.isoformat(),
                e.domain,
                e.client_ip,
                e.method,
                e.uri,
                e.user_agent,
                e.filter_result,
                e.filter_reason,
                e.filter_score,
                e.response_status,
                e.request_hash,
                e.duration_ms,
            )
            for e in events
        ]

        try:
            await self.db.executemany(
                """INSERT INTO requests
                   (timestamp, domain, client_ip, method, uri, user_agent,
                    filter_result, filter_reason, filter_score, response_status,
                    request_hash, duration_ms)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                params,
            )
            log.debug("events_flushed", count=len(events))
        except Exception:
            log.exception("flush_error", count=len(events))
