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
from infraguard.core.middleware import JA3InjectionMiddleware, RequestLoggingMiddleware
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
    router = DomainRouter(config, recorder=recorder, db=db)

    # Health endpoint path is configurable to avoid fingerprinting
    health_path = config.api.health_path.strip("/")
    health_route = f"/{health_path}" if health_path else "/health"

    async def proxy_handler(request: Request) -> Response:
        return await router.handle(request)

    async def health_check(request: Request) -> Response:
        return Response(content=b'{"status":"ok"}', media_type="application/json")

    # Phishing.club webhook receiver
    pc_cfg = config.phishingclub
    _phishingclub_handler = None
    if pc_cfg.enabled:
        from infraguard.integrations.phishingclub import make_webhook_handler
        _phishingclub_handler = make_webhook_handler(pc_cfg, db, recorder)

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
        # Hydrate persistent caches (replay filter) from the now-connected database
        await router.startup()
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

        # Dead man's switch
        _deadman = None
        if config.deadman.enabled:
            from infraguard.core.deadman import DeadManSwitch
            _deadman = DeadManSwitch(
                ttl_seconds=config.deadman.ttl_seconds,
                enabled=True,
            )
            _deadman.start()
            app.state.deadman = _deadman

        # Background task: fronting health monitor
        _fronting_health_task = None
        if config.fronting.enabled and config.fronting.rules and router._fronting is not None:
            _fronting_health_task = await router._fronting.start_health_monitor(
                interval_seconds=config.fronting.health_check_interval_seconds,
            )
            _background_tasks.append(_fronting_health_task)

        # Background task: Certificate Transparency monitoring
        _ct_monitor = None
        _burn_detector = None
        if config.intel.ct_monitor.enabled:
            from infraguard.intel.ct_monitor import CTMonitor
            from infraguard.intel.burn_detect import BurnDetector, BurnConfig
            _burn_detector = BurnDetector(db=db, recorder=recorder)
            ct_domains = config.intel.ct_monitor.monitored_domains or list(config.domains.keys())
            _ct_monitor = CTMonitor(
                domains=ct_domains,
                interval_hours=config.intel.ct_monitor.interval_hours,
                burn_detector=_burn_detector,
                recorder=recorder,
            )
            await _ct_monitor.start()

        # Background task: Domain reputation self-monitoring
        _rep_monitor = None
        if config.intel.reputation_monitor.enabled:
            from infraguard.intel.reputation import DomainReputationMonitor
            _burn_det = _burn_detector if _burn_detector else None
            rep_domains = (
                config.intel.reputation_monitor.monitored_domains or list(config.domains.keys())
            )
            _rep_monitor = DomainReputationMonitor(
                domains=rep_domains,
                interval_hours=config.intel.reputation_monitor.interval_hours,
                check_urlhaus=config.intel.reputation_monitor.check_urlhaus,
                check_openphish=config.intel.reputation_monitor.check_openphish,
                check_google_safebrowsing=config.intel.reputation_monitor.check_google_safebrowsing,
                google_safebrowsing_api_key=config.intel.reputation_monitor.google_safebrowsing_api_key,
                burn_detector=_burn_det,
                recorder=recorder,
            )
            await _rep_monitor.start()

        # Background task: Passive DNS monitoring
        _pdns_monitor = None
        if config.intel.passive_dns.enabled:
            from infraguard.intel.passive_dns import PassiveDNSMonitor
            # Lazily create a BurnDetector so PDNS alerts flow into burn
            # scoring/cooldown even when CT monitoring is disabled.
            if _burn_detector is None:
                from infraguard.intel.burn_detect import BurnDetector
                _burn_detector = BurnDetector(db=db, recorder=recorder)
            pdns_cfg = config.intel.passive_dns
            pdns_domains = pdns_cfg.monitored_domains or list(config.domains.keys())
            _pdns_monitor = PassiveDNSMonitor(
                domains=pdns_domains,
                interval_hours=pdns_cfg.interval_hours,
                provider=pdns_cfg.provider,
                circl_user=pdns_cfg.circl_user,
                circl_password=pdns_cfg.circl_password,
                nxdomain_spike_threshold=pdns_cfg.nxdomain_spike_threshold,
                nxdomain_window_seconds=pdns_cfg.nxdomain_window_seconds,
                alert_on_first_seen=pdns_cfg.alert_on_first_seen,
                burn_detector=_burn_detector,
                recorder=recorder,
            )
            await _pdns_monitor.start()
            app.state.pdns_monitor = _pdns_monitor

        # Burn confidence scorer - aggregates signals from all monitors
        from infraguard.intel.burn_scorer import BurnScorer
        _burn_scorer = BurnScorer(db=db, burn_detector=_burn_detector)

        # Background task: Rotation scheduler
        _rotation_scheduler = None
        if config.rotation.enabled:
            from infraguard.deploy.scheduler import RotationScheduler
            _rotation_scheduler = RotationScheduler(
                config.rotation,
                router=router,
                db=db,
                recorder=recorder,
            )
            _rotation_task = asyncio.create_task(_rotation_scheduler.run())
            _background_tasks.append(_rotation_task)
            app.state.rotation_scheduler = _rotation_scheduler

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

        # ── Non-HTTP listeners (DNS, MQTT, WebSocket, TCP tunnel) ────
        # All non-HTTP listeners are started here so they ride alongside
        # the uvicorn HTTP listener in the same event loop.
        from infraguard.listeners.base import ListenerManager
        _listener_mgr = ListenerManager()

        # Protocol string → listener class mapping (lazy imports)
        _PROTOCOL_CLASSES = {
            "tcp_tunnel": ("infraguard.listeners.tcp_tunnel", "TCPTunnelListener"),
            "dns": ("infraguard.listeners.dns", "DNSListener"),
            "mqtt": ("infraguard.listeners.mqtt", "MQTTListener"),
            "websocket": ("infraguard.listeners.websocket", "WebSocketListener"),
        }

        for lis in config.listeners:
            if lis.protocol in ("http", "https"):
                # HTTP/HTTPS is served by uvicorn directly, skip here
                continue
            entry = _PROTOCOL_CLASSES.get(lis.protocol)
            if entry is None:
                log.warning(
                    "unknown_listener_protocol",
                    protocol=lis.protocol,
                    bind=lis.bind,
                    port=lis.port,
                )
                continue

            module_path, class_name = entry
            try:
                import importlib
                mod = importlib.import_module(module_path)
                cls = getattr(mod, class_name)
            except (ImportError, AttributeError):
                log.exception(
                    "listener_import_error",
                    protocol=lis.protocol,
                    module=module_path,
                )
                continue

            # Build constructor kwargs - all listeners take (config, intel, recorder).
            # DNSListener additionally accepts intel_config.
            kwargs: dict = dict(config=lis, intel=router.intel, recorder=recorder)
            if lis.protocol == "dns":
                kwargs["intel_config"] = config.intel

            try:
                listener_inst = cls(**kwargs)
            except Exception:
                log.exception(
                    "listener_init_error",
                    protocol=lis.protocol,
                    bind=lis.bind,
                    port=lis.port,
                )
                continue

            # WebSocket listeners expose a Starlette route that must be
            # mounted on the ASGI app before the catch-all proxy handler.
            if lis.protocol == "websocket":
                ws_route = listener_inst.get_route()
                # Insert before the catch-all routes (last two entries)
                app.routes.insert(len(app.routes) - 2, ws_route)
                log.info(
                    "websocket_route_mounted",
                    path=lis.options.get("path", "/ws"),
                )

            _listener_mgr.add(listener_inst)

        await _listener_mgr.start_all()

        # Embed dashboard API in-process so it shares the proxy's IntelManager.
        # Whitelist/blocklist changes from the dashboard take effect immediately.
        _dashboard_server = None
        try:
            import uvicorn as _uvicorn
            from infraguard.ui.api.app import create_api_app

            _dashboard_db = Database(config.tracking.db_path)
            _dashboard_app = create_api_app(
                config, _dashboard_db, intel=router.intel, router=router,
            )
            _dashboard_app.state.burn_scorer = _burn_scorer
            if _pdns_monitor is not None:
                _dashboard_app.state.pdns_monitor = _pdns_monitor
            _api_bind = os.environ.get("INFRAGUARD_API_BIND", config.api.bind)
            _uvi_cfg = _uvicorn.Config(
                _dashboard_app,
                host=_api_bind,
                port=config.api.port,
                log_level="warning",
                server_header=False,
                date_header=False,
            )
            _dashboard_server = _uvicorn.Server(_uvi_cfg)
            _background_tasks.append(
                asyncio.create_task(_dashboard_server.serve())
            )
            log.info(
                "dashboard_embedded",
                bind=config.api.bind,
                port=config.api.port,
            )
        except Exception:
            log.exception("dashboard_embed_failed")

        log.info(
            "infraguard_started",
            domains=list(config.domains.keys()),
            plugins=[getattr(p, "name", "?") for p in plugins],
            health_endpoint=health_route,
        )
        yield

        # 0. Gracefully stop embedded dashboard
        if _dashboard_server is not None:
            _dashboard_server.should_exit = True

        # 1. Cancel all background tasks (feeds, session cleanup, dashboard)
        for task in _background_tasks:
            task.cancel()
        if _background_tasks:
            await asyncio.gather(*_background_tasks, return_exceptions=True)
        _background_tasks.clear()

        # Stop all non-HTTP listeners (DNS, MQTT, WebSocket, TCP tunnel)
        await _listener_mgr.stop_all()

        # Stop dead man's switch
        if _deadman is not None:
            await _deadman.stop()

        # Stop optional monitors
        if _ct_monitor is not None:
            await _ct_monitor.stop()
        if _rep_monitor is not None:
            await _rep_monitor.stop()
        if _pdns_monitor is not None:
            await _pdns_monitor.stop()

        # Stop rotation scheduler
        if _rotation_scheduler is not None:
            _rotation_scheduler.stop()

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

    routes = [
        Route(health_route, health_check, methods=["GET"]),
    ]
    if _phishingclub_handler is not None:
        pc_path = "/" + pc_cfg.webhook_path.strip("/")
        routes.append(Route(pc_path, _phishingclub_handler, methods=["POST"]))
        log.info("phishingclub_webhook_registered", path=pc_path)
    routes.extend([
        Route("/{path:path}", proxy_handler, methods=["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"]),
        Route("/", proxy_handler, methods=["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"]),
    ])

    app = Starlette(routes=routes, lifespan=lifespan)

    # Store trusted proxies on app state for middleware access
    app.state.trusted_proxies = config.api.trusted_proxies

    app.add_middleware(RequestLoggingMiddleware)
    app.add_middleware(
        JA3InjectionMiddleware,
        ja3_header=config.pipeline.ja3_filter.ja3_header,
    )

    return app
