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

    _SEND_TIMEOUT: float = 5.0  # per-client send timeout in seconds

    async def broadcast(self, event: dict[str, Any]) -> None:
        """Send an event to all connected WebSocket clients concurrently."""
        if not self._clients:
            return
        message = json.dumps(event)

        async def _safe_send(ws: WebSocket) -> WebSocket | None:
            try:
                await asyncio.wait_for(ws.send_text(message), timeout=self._SEND_TIMEOUT)
                return None
            except Exception:
                return ws

        results = await asyncio.gather(
            *(_safe_send(ws) for ws in list(self._clients)),
            return_exceptions=False,
        )
        for ws in results:
            if ws is not None and ws in self._clients:
                self._clients.remove(ws)
                log.info("ws_dead_client_removed")

    async def _receive_loop(self, ws: WebSocket) -> None:
        """Read messages from *ws* and send periodic keepalive pings."""
        ping_interval = 30  # seconds
        while True:
            receive_task = asyncio.ensure_future(ws.receive_text())
            done, _ = await asyncio.wait(
                {receive_task}, timeout=ping_interval
            )
            if done:
                # Client sent a message (or disconnect raised); consume it
                receive_task.result()
            else:
                # Timeout: send a ping frame to keep the connection alive
                try:
                    await asyncio.wait_for(
                        ws.send_json({"type": "ping"}),
                        timeout=self._SEND_TIMEOUT,
                    )
                except Exception:
                    receive_task.cancel()
                    break

    async def handler(self, ws: WebSocket) -> None:
        """WebSocket endpoint handler with authentication."""
        expected_token = ws.app.state.config.api.auth_token
        if expected_token:
            # Check query param: ws://host/ws/events?token=xxx
            token = ws.query_params.get("token", "")
            # Check session cookie
            session_id = ws.cookies.get(SESSION_COOKIE, "")

            token_ok = token and hmac.compare_digest(token, expected_token)
            db = ws.app.state.db
            session_ok = session_id and await validate_session(db, session_id, expected_token)

            if not token_ok and not session_ok:
                # Neither query-param nor cookie auth succeeded.  Accept the
                # connection and allow the client to authenticate by sending an
                # auth message as the first frame (used by the Command Post to
                # avoid leaking tokens in URL query strings / logs).
                await ws.accept()
                try:
                    first_msg = await asyncio.wait_for(ws.receive_text(), timeout=10.0)
                    data = json.loads(first_msg)
                    first_msg_token = data.get("token", "") if data.get("type") == "auth" else ""
                    if not (first_msg_token and hmac.compare_digest(first_msg_token, expected_token)):
                        await ws.close(code=4003)
                        log.warning("ws_auth_failed", client=ws.client.host if ws.client else "unknown")
                        return
                except Exception:
                    await ws.close(code=4003)
                    log.warning("ws_auth_failed", client=ws.client.host if ws.client else "unknown")
                    return

                # First-message auth succeeded
                self._clients.append(ws)
                log.info("ws_client_connected", total=len(self._clients), auth="first_message")
                try:
                    await self._receive_loop(ws)
                except (WebSocketDisconnect, asyncio.CancelledError):
                    pass
                finally:
                    self.disconnect(ws)
                return

        await self.connect(ws)
        try:
            await self._receive_loop(ws)
        except (WebSocketDisconnect, asyncio.CancelledError):
            pass
        finally:
            self.disconnect(ws)
