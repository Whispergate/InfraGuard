"""Async batched event recording to SQLite with plugin dispatch."""

from __future__ import annotations

import asyncio
import sqlite3
from collections import deque
from typing import Any

import structlog

from infraguard.models.events import RequestEvent
from infraguard.tracking.database import Database

log = structlog.get_logger()


class EventRecorder:
    """Batched async writer for request events.

    Events are buffered and flushed to SQLite either when the buffer
    reaches ``batch_size`` or every ``flush_interval`` seconds.

    If *plugins* are provided, each plugin's ``on_event`` is called
    with a per-task timeout via a tracked task set. All tasks are
    cancelled and awaited on stop().
    """

    def __init__(
        self,
        db: Database,
        batch_size: int = 50,
        flush_interval: float = 5.0,
        plugins: list[Any] | None = None,
    ):
        self.db = db
        self.batch_size = batch_size
        self.flush_interval = flush_interval
        self._buffer: deque[RequestEvent] = deque()
        self._plugins = plugins or []
        self._tasks: set[asyncio.Task] = set()
        self._task_timeout: float = 10.0  # per-task timeout for plugin dispatch

    # ------------------------------------------------------------------
    # Task lifecycle helpers
    # ------------------------------------------------------------------

    def _create_tracked_task(
        self,
        coro,
        *,
        name: str | None = None,
        timeout: float | None = None,
    ) -> asyncio.Task:
        """Create a task that is tracked and cleaned up on completion."""
        if timeout is not None:
            coro = asyncio.wait_for(coro, timeout=timeout)
        task = asyncio.create_task(coro, name=name)
        self._tasks.add(task)
        task.add_done_callback(self._task_done)
        return task

    def _task_done(self, task: asyncio.Task) -> None:
        """Remove completed task from tracked set and log errors."""
        self._tasks.discard(task)
        if task.cancelled():
            return
        exc = task.exception()
        if exc is not None:
            log.error(
                "background_task_failed",
                task_name=task.get_name(),
                error_type=type(exc).__name__,
                error=str(exc),
            )

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------

    async def start(self) -> None:
        self._create_tracked_task(self._flush_loop(), name="flush_loop")
        log.info("recorder_started", batch_size=self.batch_size, plugins=len(self._plugins))

    async def stop(self) -> None:
        # Cancel all tracked tasks
        for task in list(self._tasks):
            task.cancel()
        # Wait for all to finish (with timeout to prevent hanging shutdown)
        if self._tasks:
            await asyncio.wait(self._tasks, timeout=5.0)
        self._tasks.clear()
        # Final flush of remaining buffered events
        await self._flush()
        log.info("recorder_stopped")

    def record(self, event: RequestEvent) -> None:
        """Add an event to the buffer (non-blocking)."""
        self._buffer.append(event)
        if len(self._buffer) >= self.batch_size:
            self._create_tracked_task(self._flush(), name="batch_flush")

        # Dispatch to plugins with per-task timeout
        for plugin in self._plugins:
            self._create_tracked_task(
                self._safe_on_event(plugin, event),
                name=f"plugin_{getattr(plugin, 'name', 'unknown')}",
                timeout=self._task_timeout,
            )

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    async def _safe_on_event(plugin: Any, event: RequestEvent) -> None:
        try:
            await plugin.on_event(event)
        except asyncio.TimeoutError:
            name = getattr(plugin, "name", "unknown")
            log.warning("plugin_on_event_timeout", plugin=name)
        except Exception as e:
            name = getattr(plugin, "name", "unknown")
            log.exception("plugin_on_event_error", plugin=name, error_type=type(e).__name__)

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
                e.protocol,
            )
            for e in events
        ]

        try:
            await self.db.executemany(
                """INSERT INTO requests
                   (timestamp, domain, client_ip, method, uri, user_agent,
                    filter_result, filter_reason, filter_score, response_status,
                    request_hash, duration_ms, protocol)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                params,
            )
            log.debug("events_flushed", count=len(events))
        except (OSError, sqlite3.Error) as e:
            log.exception("flush_error", count=len(events), error_type=type(e).__name__)
