"""ASGI application factory for InfraGuard."""

from __future__ import annotations

import asyncio
import os
from contextlib import asynccontextmanager
from pathlib import Path

import structlog
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import Response
from starlette.routing import Route

from infraguard.config.reloader import ConfigReloader
from infraguard.config.schema import InfraGuardConfig
from infraguard.core.log_sanitizer import redact_sensitive_fields
from infraguard.core.middleware import RequestLoggingMiddleware
from infraguard.core.router import DomainRouter
from infraguard.plugins.loader import load_plugins
from infraguard.tracking.database import Database
from infraguard.tracking.recorder import EventRecorder

log = structlog.get_logger()

_SESSION_CLEANUP_INTERVAL = 300  # seconds


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

    async def _session_cleanup_loop(database: Database) -> None:
        """Periodically purge expired sessions from the database."""
        while True:
            await asyncio.sleep(_SESSION_CLEANUP_INTERVAL)
            try:
                deleted = await database.delete_expired_sessions()
                if deleted:
                    log.info("sessions_cleaned", expired_count=deleted)
            except Exception:
                log.exception("session_cleanup_error")

    @asynccontextmanager
    async def lifespan(app: Starlette):
        await db.connect()
        # Expose db and config on app state for auth and other handlers
        app.state.db = db
        app.state.config = config
        # Start plugins (isolated - one failure doesn't stop others)
        for p in plugins:
            try:
                await p.on_startup()
            except Exception:
                log.exception("plugin_startup_error", plugin=getattr(p, "name", "?"))
        await recorder.start()

        # Install SIGHUP handler for config hot-reload
        config_path = Path(os.environ.get("INFRAGUARD_CONFIG", "config/config.yaml"))
        reloader = ConfigReloader(config_path, router)
        loop = asyncio.get_event_loop()
        reloader.install(loop)

        # Collect background tasks for structured shutdown
        _background_tasks: list[asyncio.Task] = []

        # Background task: initial feed load and periodic refresh
        if config.intel.feeds.enabled:
            from infraguard.intel.feeds import feed_refresh_loop, update_feeds
            feed_urls = config.intel.feeds.urls or None
            # Initial feed load (respect require_feeds)
            try:
                await update_feeds(
                    router.intel.blocklist,
                    feed_urls,
                    config.intel.feeds.cache_dir,
                    require=config.intel.feeds.require_feeds,
                )
            except RuntimeError as e:
                log.error("startup_feed_requirement_failed", error=str(e))
                raise
            feed_task = asyncio.create_task(
                feed_refresh_loop(
                    router.intel.blocklist,
                    feed_urls,
                    config.intel.feeds.cache_dir,
                    config.intel.feeds.refresh_interval_hours,
                )
            )
            _background_tasks.append(feed_task)

        # Background task: purge expired sessions every 5 minutes
        _cleanup_task = asyncio.create_task(_session_cleanup_loop(db))
        _background_tasks.append(_cleanup_task)

        log.info(
            "infraguard_started",
            domains=list(config.domains.keys()),
            plugins=[getattr(p, "name", "?") for p in plugins],
            health_endpoint=health_route,
        )
        yield

        # 1. Cancel all background tasks (feeds, session cleanup)
        for task in _background_tasks:
            task.cancel()
        if _background_tasks:
            await asyncio.gather(*_background_tasks, return_exceptions=True)
        _background_tasks.clear()

        # 2. Stop recorder (cancels tracked tasks and does final flush)
        await recorder.stop()

        # 3. Shutdown plugins
        for p in plugins:
            try:
                await p.on_shutdown()
            except Exception:
                log.exception("plugin_shutdown_error", plugin=getattr(p, "name", "?"))

        # 4. Close database
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
