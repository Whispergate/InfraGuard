"""WebSocket manager for real-time event streaming to dashboard clients."""

from __future__ import annotations

import asyncio
import json
from typing import Any

import structlog
from starlette.websockets import WebSocket, WebSocketDisconnect

log = structlog.get_logger()


class EventBroadcaster:
    """Manages WebSocket connections and broadcasts events."""

    def __init__(self):
        self._clients: list[WebSocket] = []

    async def connect(self, ws: WebSocket) -> None:
        await ws.accept()
        self._clients.append(ws)
        log.info("ws_client_connected", total=len(self._clients))

    def disconnect(self, ws: WebSocket) -> None:
        self._clients.remove(ws)
        log.info("ws_client_disconnected", total=len(self._clients))

    async def broadcast(self, event: dict[str, Any]) -> None:
        """Send an event to all connected WebSocket clients."""
        if not self._clients:
            return
        message = json.dumps(event)
        dead: list[WebSocket] = []
        for ws in self._clients:
            try:
                await ws.send_text(message)
            except Exception:
                dead.append(ws)
        for ws in dead:
            self._clients.remove(ws)

    async def handler(self, ws: WebSocket) -> None:
        """WebSocket endpoint handler."""
        await self.connect(ws)
        try:
            while True:
                # Keep connection alive; we only push events
                await ws.receive_text()
        except WebSocketDisconnect:
            self.disconnect(ws)
