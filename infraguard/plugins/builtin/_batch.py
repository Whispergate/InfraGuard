"""Batching base class for SIEM forwarding plugins."""

from __future__ import annotations

import asyncio
from collections import deque

import structlog

from infraguard.models.events import RequestEvent
from infraguard.plugins.builtin._base import ForwardingPlugin

log = structlog.get_logger()


class BatchForwardingPlugin(ForwardingPlugin):
    """ForwardingPlugin that buffers events and flushes in configurable batches.

    Subclasses implement ``_send_batch(events)`` with the actual transport.
    """

    def __init__(self):
        super().__init__()
        self._batch_buffer: deque[RequestEvent] = deque()
        self._flush_task: asyncio.Task | None = None

    @property
    def _batch_size(self) -> int:
        return int(self._opt("batch_size", 50))

    @property
    def _flush_interval(self) -> float:
        return float(self._opt("flush_interval", 10.0))

    async def on_event(self, event: RequestEvent) -> None:
        if not self._should_forward(event):
            return
        self._batch_buffer.append(event)
        if len(self._batch_buffer) >= self._batch_size:
            await self._flush_batch()

    async def _flush_batch(self) -> None:
        if not self._batch_buffer:
            return
        events: list[RequestEvent] = []
        while self._batch_buffer:
            events.append(self._batch_buffer.popleft())
        try:
            await self._send_batch(events)
        except Exception:
            log.exception("batch_send_error", plugin=self.name, count=len(events))

    async def _send_batch(self, events: list[RequestEvent]) -> None:
        """Override in subclass to send the batch to the external system."""
        raise NotImplementedError

    async def on_startup(self) -> None:
        await super().on_startup()
        self._flush_task = asyncio.create_task(self._flush_loop())
        log.info(
            "batch_plugin_started",
            plugin=self.name,
            batch_size=self._batch_size,
            flush_interval=self._flush_interval,
        )

    async def on_shutdown(self) -> None:
        if self._flush_task:
            self._flush_task.cancel()
            try:
                await self._flush_task
            except asyncio.CancelledError:
                pass
        await self._flush_batch()
        await super().on_shutdown()

    async def _flush_loop(self) -> None:
        while True:
            await asyncio.sleep(self._flush_interval)
            await self._flush_batch()
