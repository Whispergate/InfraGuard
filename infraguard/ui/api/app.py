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
from infraguard.ui.api.rate_limit import (
    APIKeyManager,
    InMemoryRateLimiterBackend,
    RateLimitMiddleware,
    RedisRateLimiterBackend,
    TokenBucketRateLimiter,
    UsageTracker,
    create_api_key,
    get_api_key_usage,
    list_api_keys,
    revoke_api_key,
    rotate_api_key,
)
from infraguard.ui.api.routes.ai import ai_chat, ai_status
from infraguard.ui.api.routes.config import (
    generate_profile_endpoint,
    get_config,
    get_domains,
    list_profiles,
    swap_profile,
    update_drop_action,
    upload_profile,
)
from infraguard.ui.api.routes.decoys import (
    get_decoy_file,
    list_decoy_pages,
    list_decoys,
    preview_decoy_page,
    update_decoy_file,
)
from infraguard.ui.api.routes.intel import add_blocklist, add_whitelist, classify_ip, remove_blocklist
from infraguard.ui.api.routes.health import get_health, get_health_summary
from infraguard.ui.api.routes.nodes import heartbeat_node, list_nodes, register_node
from infraguard.ui.api.routes.pdns import (
    clear_pdns_history,
    get_pdns_events,
    get_pdns_history,
    get_pdns_status,
)
from infraguard.ui.api.routes.reports import export_report
from infraguard.ui.api.routes.requests import get_requests
from infraguard.ui.api.routes.stats import get_content_stats, get_stats
from infraguard.ui.api.routes.burn import get_burn_score, get_burn_scores
from infraguard.ui.api.metrics import create_metrics_app
from infraguard.ui.api.websocket import EventBroadcaster

log = structlog.get_logger()

# Paths that don't require authentication
_PUBLIC_PATHS = frozenset({"/", "", "/api/auth/login", "/api/auth/check"})
_PUBLIC_PREFIXES = ("/static", "/metrics")


async def _apply_rate_limit(request: Request, rate_limiter: TokenBucketRateLimiter) -> JSONResponse | None:
    """Apply rate limiting. Returns error response if limited, None otherwise."""
    # Determine rate limit key: API key > bearer token hash > IP
    rate_key = _get_rate_key(request)
    if rate_key is None:
        return None

    allowed, info = await rate_limiter.allow(rate_key)
    if not allowed:
        return JSONResponse(
            {
                "error": "Rate limit exceeded",
                "retry_after": info["reset_after"],
            },
            status_code=429,
            headers={
                "X-RateLimit-Limit": str(int(info["capacity"])),
                "X-RateLimit-Remaining": str(int(info["remaining"])),
                "X-RateLimit-Reset": str(int(asyncio.get_event_loop().time()) + info["reset_after"]),
                "Retry-After": str(info["reset_after"]),
            },
        )
    return None


def _get_rate_key(request: Request) -> str | None:
    """Extract a rate limiting key from the request."""
    # Check API key header
    api_key = request.headers.get("x-api-key")
    if api_key:
        return f"apikey:{api_key[:16]}"

    # Check bearer token
    auth = request.headers.get("authorization", "")
    if auth.startswith("Bearer "):
        token = auth[7:]
        return f"bearer:{token[:16]}"

    # Check session cookie
    session_id = request.cookies.get("ig_session")
    if session_id:
        return f"session:{session_id[:16]}"

    # Fallback to IP
    client_ip = request.client.host if request.client else "unknown"
    return f"ip:{client_ip}"


class AuthMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        path = request.url.path

        # Skip auth for public paths
        if path in _PUBLIC_PATHS:
            return await call_next(request)
        for prefix in _PUBLIC_PREFIXES:
            if path.startswith(prefix):
                return await call_next(request)
        # Note: BaseHTTPMiddleware does not intercept WebSocket routes;
        # WS auth is handled in the websocket.py handler directly.

        token = request.app.state.config.api.auth_token
        error = await check_auth(request, token)
        if error:
            return error

        # Apply rate limiting after successful auth
        rate_limiter = getattr(request.app.state, "rate_limiter", None)
        if rate_limiter is not None:
            rl_response = await _apply_rate_limit(request, rate_limiter)
            if rl_response is not None:
                return rl_response

        return await call_next(request)


def create_api_app(
    config: InfraGuardConfig,
    db: Database,
    intel: IntelManager | None = None,
    router=None,
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
        app.state.db = db

        # Initialize rate limiting
        rl_config = config.api.rate_limit
        if rl_config.enabled:
            if rl_config.backend == "redis":
                try:
                    backend = RedisRateLimiterBackend(rl_config.redis_url)
                    # Test connection
                    await backend._get_client()
                    log.info("rate_limiter_redis_connected", url=rl_config.redis_url)
                except Exception as e:
                    log.warning("rate_limiter_redis_failed", error=str(e), fallback="memory")
                    backend = InMemoryRateLimiterBackend()
            else:
                backend = InMemoryRateLimiterBackend()

            limiter = TokenBucketRateLimiter(
                backend,
                default_capacity=rl_config.default_capacity,
                default_refill_rate=rl_config.default_refill_rate,
            )
            app.state.rate_limiter = limiter
            app.state.usage_tracker = UsageTracker(db)
            app.state.api_key_manager = APIKeyManager(db)
            log.info("rate_limiter_initialized", backend=rl_config.backend)
        else:
            app.state.rate_limiter = None
            app.state.usage_tracker = None
            app.state.api_key_manager = None

        poll_task = asyncio.create_task(_poll_and_broadcast())
        log.info("api_started", bind=config.api.bind, port=config.api.port)
        yield
        poll_task.cancel()
        try:
            await poll_task
        except asyncio.CancelledError:
            pass
        if app.state.rate_limiter:
            await app.state.rate_limiter.close()
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
        # API key management routes (require auth)
        Route("/api/keys", list_api_keys, methods=["GET"]),
        Route("/api/keys", create_api_key, methods=["POST"]),
        Route("/api/keys/{key_id}", revoke_api_key, methods=["DELETE"]),
        Route("/api/keys/{key_id}/rotate", rotate_api_key, methods=["POST"]),
        Route("/api/keys/{key_id}/usage", get_api_key_usage, methods=["GET"]),
        # API routes (require auth)
        Route("/api/stats", get_stats, methods=["GET"]),
        Route("/api/stats/content", get_content_stats, methods=["GET"]),
        Route("/api/reports/export", export_report, methods=["GET"]),
        Route("/api/requests", get_requests, methods=["GET"]),
        Route("/api/nodes", list_nodes, methods=["GET"]),
        Route("/api/nodes/register", register_node, methods=["POST"]),
        Route("/api/nodes/{node_id}/heartbeat", heartbeat_node, methods=["POST"]),
        Route("/api/intel/classify", classify_ip, methods=["POST"]),
        Route("/api/intel/blocklist", add_blocklist, methods=["POST"]),
        Route("/api/intel/blocklist", remove_blocklist, methods=["DELETE"]),
        Route("/api/intel/whitelist", add_whitelist, methods=["POST"]),
        # Passive DNS monitoring
        Route("/api/intel/pdns/status", get_pdns_status, methods=["GET"]),
        Route("/api/intel/pdns/events", get_pdns_events, methods=["GET"]),
        Route("/api/intel/pdns/history/{domain}", get_pdns_history, methods=["GET"]),
        Route("/api/intel/pdns/history", clear_pdns_history, methods=["DELETE"]),
        Route("/api/config", get_config, methods=["GET"]),
        Route("/api/config/domains/{domain}/drop-action", update_drop_action, methods=["PATCH"]),
        Route("/api/config/domains/{domain}/profile", swap_profile, methods=["PATCH"]),
        Route("/api/config/domains", get_domains, methods=["GET"]),
        Route("/api/profiles/upload", upload_profile, methods=["POST"]),
        Route("/api/profiles/generate", generate_profile_endpoint, methods=["POST"]),
        Route("/api/profiles", list_profiles, methods=["GET"]),
        Route("/api/ai/chat", ai_chat, methods=["POST"]),
        Route("/api/ai/status", ai_status, methods=["GET"]),
        Route("/api/decoys/pages/{page_name}/preview", preview_decoy_page, methods=["GET"]),
        Route("/api/decoys/pages", list_decoy_pages, methods=["GET"]),
        Route("/api/decoys", list_decoys, methods=["GET"]),
        Route("/api/decoys/{domain}/{filename}", get_decoy_file, methods=["GET"]),
        Route("/api/decoys/{domain}/{filename}", update_decoy_file, methods=["PUT"]),
        # Burn confidence scoring
        Route("/api/burn/score/{domain}", get_burn_score, methods=["GET"]),
        Route("/api/burn/scores", get_burn_scores, methods=["GET"]),
        # Infrastructure health
        Route("/api/health", get_health, methods=["GET"]),
        Route("/api/health/summary", get_health_summary, methods=["GET"]),
        # WebSocket
        WebSocketRoute("/ws/events", broadcaster.handler),
    ]

    # Mount static files if the directory exists
    if static_dir.exists():
        routes.append(Mount("/static", app=StaticFiles(directory=str(static_dir)), name="static"))

    app = Starlette(routes=routes, lifespan=lifespan)
    app.mount("/metrics", create_metrics_app())
    app.add_middleware(AuthMiddleware)

    # Attach shared state
    app.state.config = config
    app.state.stats_query = stats_query
    app.state.node_registry = node_registry
    app.state.broadcaster = broadcaster
    app.state.router = router
    if intel:
        app.state.intel_manager = intel

    return app
