"""Command Post - multi-instance aggregating dashboard API."""

from __future__ import annotations

import asyncio
import hmac
import json
from contextlib import asynccontextmanager
from pathlib import Path

import structlog
from starlette.applications import Starlette
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import FileResponse, JSONResponse, Response
from starlette.routing import Route, WebSocketRoute
from starlette.websockets import WebSocket, WebSocketDisconnect

from infraguard.ui.api.auth import (
    SESSION_COOKIE,
    check_auth,
    check_handler,
    create_session,
    login_handler,
    logout_handler,
    validate_session,
)
from infraguard.ui.command_post.aggregator import MultiInstanceAggregator
from infraguard.ui.command_post.config import CommandPostConfig

log = structlog.get_logger()

_PUBLIC_PATHS = frozenset({"/", "", "/api/auth/login", "/api/auth/check"})


class AuthMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        path = request.url.path
        if path in _PUBLIC_PATHS or path == "/ws/events":
            return await call_next(request)
        token = request.app.state.auth_token
        error = check_auth(request, token)
        if error:
            return error
        return await call_next(request)


def create_command_post_app(config: CommandPostConfig) -> Starlette:
    """Create the Command Post aggregation API."""
    aggregator = MultiInstanceAggregator(config.instances)

    static_dir = Path(__file__).parent / "static"
    index_html = static_dir / "index.html"

    # ── Handlers ──────────────────────────────────────────────────

    async def serve_index(request: Request) -> Response:
        if index_html.exists():
            return FileResponse(str(index_html))
        return JSONResponse({"error": "Command Post dashboard not found"}, status_code=404)

    async def get_instances(request: Request) -> JSONResponse:
        health = await aggregator.get_instances_health()
        return JSONResponse({"instances": health})

    async def get_stats(request: Request) -> JSONResponse:
        hours = int(request.query_params.get("hours", "24"))
        stats = await aggregator.get_merged_stats(hours=hours)
        return JSONResponse(stats)

    async def get_requests(request: Request) -> JSONResponse:
        limit = min(int(request.query_params.get("limit", "50")), 200)
        requests_list = await aggregator.get_merged_requests(limit=limit)
        return JSONResponse({"requests": requests_list, "count": len(requests_list)})

    async def post_whitelist(request: Request) -> JSONResponse:
        body = await request.json()
        instance = body.pop("_instance", None)
        results = await aggregator.fan_out_post("/api/intel/whitelist", body, instance)
        return JSONResponse({"status": "ok", "results": results})

    async def post_blocklist(request: Request) -> JSONResponse:
        body = await request.json()
        instance = body.pop("_instance", None)
        results = await aggregator.fan_out_post("/api/intel/blocklist", body, instance)
        return JSONResponse({"status": "ok", "results": results})

    async def delete_blocklist(request: Request) -> JSONResponse:
        body = await request.json()
        instance = body.pop("_instance", None)
        results = await aggregator.fan_out_delete("/api/intel/blocklist", body, instance)
        return JSONResponse({"status": "ok", "results": results})

    # ── WebSocket multiplexer ─────────────────────────────────────

    async def ws_events(ws: WebSocket) -> None:
        """Multiplex WebSocket events from all instances."""
        # Auth check
        auth_token = config.auth_token
        if auth_token:
            token = ws.query_params.get("token", "")
            session_id = ws.cookies.get(SESSION_COOKIE, "")
            token_ok = token and hmac.compare_digest(token, auth_token)
            session_ok = session_id and validate_session(session_id, auth_token)
            if not token_ok and not session_ok:
                await ws.close(code=4003)
                return

        await ws.accept()

        async def _stream_instance(client, ws: WebSocket):
            """Connect to one instance's WebSocket and forward events."""
            try:
                import websockets
                ws_url = client.url.replace("https://", "wss://").replace("http://", "ws://")
                ws_url += f"/ws/events?token={client._token}"
                async with websockets.connect(ws_url, ssl=False) as upstream:
                    async for msg in upstream:
                        try:
                            data = json.loads(msg)
                            data["_instance"] = client.name
                            await ws.send_text(json.dumps(data))
                        except Exception:
                            pass
            except Exception:
                log.debug("ws_instance_disconnected", instance=client.name)

        tasks = [
            asyncio.create_task(_stream_instance(c, ws))
            for c in aggregator.clients
        ]
        try:
            while True:
                await ws.receive_text()
        except WebSocketDisconnect:
            for t in tasks:
                t.cancel()

    # ── Lifespan ──────────────────────────────────────────────────

    @asynccontextmanager
    async def lifespan(app: Starlette):
        instance_names = [c.name for c in aggregator.clients]
        log.info("command_post_started", instances=instance_names)
        yield
        await aggregator.close()

    # ── App ───────────────────────────────────────────────────────

    app = Starlette(
        routes=[
            Route("/", serve_index, methods=["GET"]),
            # Auth
            Route("/api/auth/login", login_handler, methods=["POST"]),
            Route("/api/auth/logout", logout_handler, methods=["POST"]),
            Route("/api/auth/check", check_handler, methods=["GET"]),
            # API
            Route("/api/instances", get_instances, methods=["GET"]),
            Route("/api/stats", get_stats, methods=["GET"]),
            Route("/api/requests", get_requests, methods=["GET"]),
            Route("/api/intel/whitelist", post_whitelist, methods=["POST"]),
            Route("/api/intel/blocklist", post_blocklist, methods=["POST"]),
            Route("/api/intel/blocklist", delete_blocklist, methods=["DELETE"]),
            WebSocketRoute("/ws/events", ws_events),
        ],
        lifespan=lifespan,
    )

    app.add_middleware(AuthMiddleware)

    # Store auth token and config on app state for the auth handlers
    app.state.auth_token = config.auth_token
    # The login_handler reads from app.state.config.api.auth_token - create a shim
    from types import SimpleNamespace
    app.state.config = SimpleNamespace(api=SimpleNamespace(auth_token=config.auth_token))

    return app
