"""FastAPI/Starlette sub-application for the InfraGuard dashboard API."""

from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager
from pathlib import Path

import structlog
from starlette.applications import Starlette
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import FileResponse, JSONResponse, Response
from starlette.routing import Mount, Route, WebSocketRoute
from starlette.staticfiles import StaticFiles

from infraguard.config.schema import InfraGuardConfig
from infraguard.intel.manager import IntelManager
from infraguard.tracking.database import Database
from infraguard.tracking.nodes import NodeRegistry
from infraguard.tracking.stats import StatsQuery
from infraguard.ui.api.auth import (
    check_auth,
    check_handler,
    login_handler,
    logout_handler,
)
from infraguard.ui.api.routes.config import get_config, get_domains
from infraguard.ui.api.routes.decoys import get_decoy_file, list_decoys, update_decoy_file
from infraguard.ui.api.routes.intel import add_blocklist, classify_ip
from infraguard.ui.api.routes.nodes import heartbeat_node, list_nodes, register_node
from infraguard.ui.api.routes.requests import get_requests
from infraguard.ui.api.routes.stats import get_content_stats, get_stats
from infraguard.ui.api.websocket import EventBroadcaster

log = structlog.get_logger()

# Paths that don't require authentication
_PUBLIC_PATHS = frozenset({"/", "", "/api/auth/login", "/api/auth/check"})
_PUBLIC_PREFIXES = ("/static",)


class AuthMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        path = request.url.path

        # Skip auth for public paths
        if path in _PUBLIC_PATHS:
            return await call_next(request)
        for prefix in _PUBLIC_PREFIXES:
            if path.startswith(prefix):
                return await call_next(request)
        # WebSocket auth is handled in the handler itself (via query param)
        if path == "/ws/events":
            return await call_next(request)

        token = request.app.state.config.api.auth_token
        error = check_auth(request, token)
        if error:
            return error
        return await call_next(request)


def create_api_app(
    config: InfraGuardConfig,
    db: Database,
    intel: IntelManager | None = None,
) -> Starlette:
    """Create the dashboard API application."""
    broadcaster = EventBroadcaster()
    stats_query = StatsQuery(db)
    node_registry = NodeRegistry(db)

    async def _poll_and_broadcast() -> None:
        """Poll the DB for new requests and broadcast them via WebSocket."""
        last_id = 0
        # Get the current max ID so we only broadcast genuinely new events
        try:
            row = await db.fetchone("SELECT MAX(id) as max_id FROM requests")
            if row and row["max_id"]:
                last_id = row["max_id"]
        except Exception:
            pass

        while True:
            await asyncio.sleep(2)
            try:
                rows = await db.fetchall(
                    "SELECT * FROM requests WHERE id > ? ORDER BY id ASC LIMIT 50",
                    (last_id,),
                )
                for row in rows:
                    await broadcaster.broadcast(dict(row))
                    last_id = row["id"]
            except Exception:
                pass

    @asynccontextmanager
    async def lifespan(app: Starlette):
        await db.connect()
        poll_task = asyncio.create_task(_poll_and_broadcast())
        log.info("api_started", bind=config.api.bind, port=config.api.port)
        yield
        poll_task.cancel()
        try:
            await poll_task
        except asyncio.CancelledError:
            pass
        await db.close()

    static_dir = Path(__file__).parent.parent / "web" / "static"
    index_html = static_dir / "index.html"

    async def serve_index(request: Request) -> Response:
        if index_html.exists():
            return FileResponse(str(index_html))
        return JSONResponse(
            {"error": "Dashboard not found", "hint": "Static files missing from ui/web/static/"},
            status_code=404,
        )

    routes = [
        # Dashboard root
        Route("/", serve_index, methods=["GET"]),
        # Auth routes (public)
        Route("/api/auth/login", login_handler, methods=["POST"]),
        Route("/api/auth/logout", logout_handler, methods=["POST"]),
        Route("/api/auth/check", check_handler, methods=["GET"]),
        # API routes (require auth)
        Route("/api/stats", get_stats, methods=["GET"]),
        Route("/api/stats/content", get_content_stats, methods=["GET"]),
        Route("/api/requests", get_requests, methods=["GET"]),
        Route("/api/nodes", list_nodes, methods=["GET"]),
        Route("/api/nodes/register", register_node, methods=["POST"]),
        Route("/api/nodes/{node_id}/heartbeat", heartbeat_node, methods=["POST"]),
        Route("/api/intel/classify", classify_ip, methods=["POST"]),
        Route("/api/intel/blocklist", add_blocklist, methods=["POST"]),
        Route("/api/config", get_config, methods=["GET"]),
        Route("/api/config/domains", get_domains, methods=["GET"]),
        Route("/api/decoys", list_decoys, methods=["GET"]),
        Route("/api/decoys/{domain}/{filename}", get_decoy_file, methods=["GET"]),
        Route("/api/decoys/{domain}/{filename}", update_decoy_file, methods=["PUT"]),
        # WebSocket
        WebSocketRoute("/ws/events", broadcaster.handler),
    ]

    # Mount static files if the directory exists
    if static_dir.exists():
        routes.append(Mount("/static", app=StaticFiles(directory=str(static_dir)), name="static"))

    app = Starlette(routes=routes, lifespan=lifespan)
    app.add_middleware(AuthMiddleware)

    # Attach shared state
    app.state.config = config
    app.state.stats_query = stats_query
    app.state.node_registry = node_registry
    app.state.broadcaster = broadcaster
    if intel:
        app.state.intel_manager = intel

    return app
