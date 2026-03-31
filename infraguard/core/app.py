"""ASGI application factory for InfraGuard."""

from __future__ import annotations

from contextlib import asynccontextmanager

import structlog
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import Response
from starlette.routing import Route

from infraguard.config.schema import InfraGuardConfig
from infraguard.core.log_sanitizer import redact_sensitive_fields
from infraguard.core.middleware import RequestLoggingMiddleware
from infraguard.core.router import DomainRouter
from infraguard.plugins.loader import load_plugins
from infraguard.tracking.database import Database
from infraguard.tracking.recorder import EventRecorder

log = structlog.get_logger()


def create_app(config: InfraGuardConfig) -> Starlette:
    """Create the ASGI application from configuration."""
    # Configure structlog with redaction processor before renderer
    structlog.configure(
        processors=[
            structlog.contextvars.merge_contextvars,
            structlog.stdlib.add_log_level,
            structlog.processors.TimeStamper(fmt="iso"),
            structlog.processors.StackInfoRenderer(),
            structlog.processors.format_exc_info,
            redact_sensitive_fields,
            structlog.dev.ConsoleRenderer()
            if config.logging.format == "console"
            else structlog.processors.JSONRenderer(),
        ],
        wrapper_class=structlog.stdlib.BoundLogger,
        context_class=dict,
        logger_factory=structlog.PrintLoggerFactory(),
        cache_logger_on_first_use=True,
    )

    # Load plugins
    plugins = load_plugins(config.plugins, config.plugin_settings)

    db = Database(config.tracking.db_path)
    recorder = EventRecorder(db, plugins=plugins)
    router = DomainRouter(config, recorder=recorder)

    # Health endpoint path is configurable to avoid fingerprinting
    health_path = config.api.health_path.strip("/")
    health_route = f"/{health_path}" if health_path else "/health"

    async def proxy_handler(request: Request) -> Response:
        return await router.handle(request)

    async def health_check(request: Request) -> Response:
        return Response(content=b'{"status":"ok"}', media_type="application/json")

    @asynccontextmanager
    async def lifespan(app: Starlette):
        await db.connect()
        # Start plugins (isolated - one failure doesn't stop others)
        for p in plugins:
            try:
                await p.on_startup()
            except Exception:
                log.exception("plugin_startup_error", plugin=getattr(p, "name", "?"))
        await recorder.start()
        log.info(
            "infraguard_started",
            domains=list(config.domains.keys()),
            plugins=[getattr(p, "name", "?") for p in plugins],
            health_endpoint=health_route,
        )
        yield
        await recorder.stop()
        # Shutdown plugins
        for p in plugins:
            try:
                await p.on_shutdown()
            except Exception:
                log.exception("plugin_shutdown_error", plugin=getattr(p, "name", "?"))
        await router.close()
        await db.close()

    app = Starlette(
        routes=[
            Route(health_route, health_check, methods=["GET"]),
            Route("/{path:path}", proxy_handler, methods=["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"]),
            Route("/", proxy_handler, methods=["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"]),
        ],
        lifespan=lifespan,
    )

    app.add_middleware(RequestLoggingMiddleware)

    return app
