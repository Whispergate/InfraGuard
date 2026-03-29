"""WebSocket manager for real-time event streaming to dashboard clients."""

from __future__ import annotations

import asyncio
import hmac
import json
from typing import Any

import structlog
from starlette.websockets import WebSocket, WebSocketDisconnect

from infraguard.ui.api.auth import SESSION_COOKIE, validate_session

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
        if ws in self._clients:
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
            if ws in self._clients:
                self._clients.remove(ws)

    async def handler(self, ws: WebSocket) -> None:
        """WebSocket endpoint handler with authentication."""
        # Authenticate before accepting the connection
        expected_token = ws.app.state.config.api.auth_token
        if expected_token:
            # Check query param: ws://host/ws/events?token=xxx
            token = ws.query_params.get("token", "")
            # Check session cookie
            session_id = ws.cookies.get(SESSION_COOKIE, "")

            token_ok = token and hmac.compare_digest(token, expected_token)
            session_ok = session_id and validate_session(session_id, expected_token)

            if not token_ok and not session_ok:
                await ws.close(code=4003)
                log.warning("ws_auth_failed", client=ws.client.host if ws.client else "unknown")
                return

        await self.connect(ws)
        try:
            while True:
                await ws.receive_text()
        except WebSocketDisconnect:
            self.disconnect(ws)
