"""Listener abstraction layer for multi-protocol support.

Each listener binds a port and handles one protocol (HTTP, DNS, MQTT,
WebSocket). The ListenerManager starts and stops all listeners in the
same asyncio event loop.
"""

from __future__ import annotations

import asyncio
from typing import Protocol, runtime_checkable

import structlog

from infraguard.config.schema import InfraGuardConfig, ListenerConfig

log = structlog.get_logger()


@runtime_checkable
class Listener(Protocol):
    """Interface for protocol listeners."""

    protocol: str

    async def start(self) -> None: ...
    async def stop(self) -> None: ...


class ListenerManager:
    """Start and stop multiple listeners in the same event loop."""

    def __init__(self):
        self._listeners: list[Listener] = []

    def add(self, listener: Listener) -> None:
        self._listeners.append(listener)

    async def start_all(self) -> None:
        for listener in self._listeners:
            try:
                await listener.start()
                log.info(
                    "listener_started",
                    protocol=listener.protocol,
                )
            except Exception:
                log.exception(
                    "listener_start_error",
                    protocol=listener.protocol,
                )

    async def stop_all(self) -> None:
        for listener in self._listeners:
            try:
                await listener.stop()
            except Exception:
                log.exception(
                    "listener_stop_error",
                    protocol=listener.protocol,
                )

    @property
    def count(self) -> int:
        return len(self._listeners)
