"""WebSocket beacon transport.

A first-class C2 transport alongside HTTP. Wire format is
newline-delimited JSON frames carrying the same shape the profile
filter already scores:

    {"method": "POST", "uri": "/api/v1/telemetry",
     "headers": {"user-agent": "...", "cookie": "..."},
     "body_b64": "<base64>"}

Frames are adapted into ASGI scopes and pushed through
``DomainRouter.handle`` exactly like an HTTP request. The router's
response comes back as:

    {"status": 200, "headers": {...}, "body_b64": "..."}

Ping/pong is left to the underlying WebSocket layer; the profile's
``sleep`` and ``jitter`` fields do not participate in the wire
protocol because the beacon owns its own timing.
"""

from __future__ import annotations

import base64
import json
from typing import TYPE_CHECKING

import structlog
from starlette.requests import Request
from starlette.websockets import WebSocket, WebSocketDisconnect

if TYPE_CHECKING:
    from infraguard.core.router import DomainRouter

log = structlog.get_logger()


class BeaconWebSocket:
    """Handler that adapts JSON frames to router calls and back."""

    def __init__(self, router: DomainRouter):
        self._router = router

    async def handler(self, ws: WebSocket) -> None:
        await ws.accept(subprotocol="ig-beacon-v1")
        client_host = ws.client.host if ws.client else "unknown"
        client_port = ws.client.port if ws.client else 0
        log.info("ws_beacon_connected", client=f"{client_host}:{client_port}")
        try:
            while True:
                raw = await ws.receive_text()
                try:
                    frame = json.loads(raw)
                except json.JSONDecodeError:
                    await ws.send_text(json.dumps({"error": "bad-json"}))
                    continue
                try:
                    request = _frame_to_request(frame, client_host, client_port)
                except (KeyError, ValueError) as exc:
                    await ws.send_text(json.dumps({"error": f"bad-frame: {exc}"}))
                    continue
                response = await self._router.handle(request)
                await ws.send_text(json.dumps(_response_to_frame(response)))
        except WebSocketDisconnect:
            log.info("ws_beacon_disconnected", client=f"{client_host}:{client_port}")


def _frame_to_request(frame: dict, client_host: str, client_port: int) -> Request:
    """Build a Starlette Request from a beacon JSON frame."""
    method = str(frame.get("method", "GET")).upper()
    uri = str(frame.get("uri", "/"))
    headers = {str(k).lower(): str(v) for k, v in (frame.get("headers") or {}).items()}
    body_b64 = frame.get("body_b64", "")
    body = base64.b64decode(body_b64) if body_b64 else b""

    path, _, query = uri.partition("?")
    header_list = [(k.encode(), v.encode()) for k, v in headers.items()]

    scope = {
        "type": "http",
        "asgi": {"version": "3.0"},
        "http_version": "1.1",
        "method": method,
        "scheme": "https",
        "path": path,
        "raw_path": path.encode(),
        "query_string": query.encode(),
        "headers": header_list,
        "server": ("0.0.0.0", 443),
        "client": (client_host, client_port),
        "root_path": "",
    }

    async def _receive():
        return {"type": "http.request", "body": body, "more_body": False}

    return Request(scope, receive=_receive)


def _response_to_frame(response) -> dict:
    """Serialize a Starlette Response back into a JSON frame."""
    body = getattr(response, "body", b"") or b""
    return {
        "status": getattr(response, "status_code", 200),
        "headers": {k: v for k, v in response.headers.items()},
        "body_b64": base64.b64encode(body).decode(),
    }


__all__ = ["BeaconWebSocket"]
