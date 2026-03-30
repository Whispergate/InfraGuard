"""WebSocket listener - bidirectional proxy for WebSocket C2 channels.

Adds a WebSocket route to the existing Starlette ASGI app that proxies
WebSocket connections to an upstream C2 server. Connections are filtered
through IP intelligence and the bot/header filters from the HTTP upgrade
request.

Uses Starlette's native WebSocket support + httpx/websockets for upstream.
"""

from __future__ import annotations

import asyncio
import time
from ipaddress import ip_address

import structlog
from starlette.applications import Starlette
from starlette.routing import WebSocketRoute
from starlette.websockets import WebSocket, WebSocketDisconnect

from infraguard.config.schema import ListenerConfig
from infraguard.intel.manager import IntelManager
from infraguard.models.events import RequestEvent
from infraguard.tracking.recorder import EventRecorder

log = structlog.get_logger()


class WebSocketListener:
    """WebSocket bidirectional proxy integrated into the Starlette app."""

    protocol = "websocket"

    def __init__(
        self,
        config: ListenerConfig,
        intel: IntelManager,
        recorder: EventRecorder | None = None,
    ):
        self._config = config
        self._intel = intel
        self._recorder = recorder
        self._upstream = config.options.get("upstream", "")
        self._path = config.options.get("path", "/ws")

    def get_route(self) -> WebSocketRoute:
        """Return a Starlette WebSocketRoute to mount on the ASGI app."""
        return WebSocketRoute(self._path, self._handle)

    async def start(self) -> None:
        log.info(
            "websocket_listener_configured",
            path=self._path,
            upstream=self._upstream,
        )

    async def stop(self) -> None:
        pass

    async def _handle(self, ws: WebSocket) -> None:
        """Handle a WebSocket connection: filter, then proxy bidirectionally."""
        start = time.perf_counter()
        client_ip_str = ws.client.host if ws.client else "0.0.0.0"

        # IP filter
        try:
            client_ip = ip_address(client_ip_str)
            classification = await self._intel.classify(client_ip)
            if classification.is_blocked:
                self._record_event(
                    "", client_ip_str, "CONNECT", self._path, "block",
                    classification.reason, start,
                )
                await ws.close(code=4003)
                return
        except Exception:
            pass

        await ws.accept()
        self._record_event(
            "", client_ip_str, "CONNECT", self._path, "allow", None, start,
        )

        if not self._upstream:
            # No upstream configured - just accept and echo (useful for testing)
            try:
                while True:
                    data = await ws.receive_text()
                    await ws.send_text(data)
            except WebSocketDisconnect:
                return
            return

        # Proxy to upstream WebSocket
        try:
            import websockets

            async with websockets.connect(self._upstream) as upstream_ws:
                async def _client_to_upstream():
                    try:
                        while True:
                            data = await ws.receive_text()
                            await upstream_ws.send(data)
                            self._record_event(
                                "", client_ip_str, "MESSAGE", self._path,
                                "allow", None, time.perf_counter(),
                            )
                    except WebSocketDisconnect:
                        await upstream_ws.close()
                    except Exception:
                        pass

                async def _upstream_to_client():
                    try:
                        async for msg in upstream_ws:
                            if isinstance(msg, str):
                                await ws.send_text(msg)
                            else:
                                await ws.send_bytes(msg)
                    except Exception:
                        pass

                await asyncio.gather(
                    _client_to_upstream(),
                    _upstream_to_client(),
                )
        except ImportError:
            log.error(
                "websocket_upstream_unavailable",
                reason="websockets package required for upstream proxy",
            )
            await ws.close(code=1011)
        except Exception:
            log.exception("websocket_proxy_error", client=client_ip_str)

    def _record_event(
        self,
        domain: str,
        client_ip: str,
        method: str,
        uri: str,
        result: str,
        reason: str | None,
        start: float,
    ) -> None:
        if not self._recorder:
            return
        duration_ms = (time.perf_counter() - start) * 1000
        self._recorder.record(
            RequestEvent.now(
                domain=domain or "websocket",
                client_ip=client_ip,
                method=method,
                uri=uri,
                user_agent="",
                filter_result=result,
                filter_reason=reason,
                filter_score=1.0 if result == "block" else 0.0,
                response_status=0,
                duration_ms=round(duration_ms, 1),
                protocol="websocket",
            )
        )
