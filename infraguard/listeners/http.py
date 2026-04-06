"""HTTP/HTTPS listener wrapping uvicorn."""

from __future__ import annotations

import asyncio

import structlog
import uvicorn
from starlette.applications import Starlette

from infraguard.config.schema import ListenerConfig

log = structlog.get_logger()


class HTTPListener:
    """HTTP/HTTPS listener using uvicorn."""

    protocol = "http"

    def __init__(
        self,
        app: Starlette,
        config: ListenerConfig,
        ssl_certfile: str | None = None,
        ssl_keyfile: str | None = None,
    ):
        self._app = app
        self._config = config
        self._ssl_certfile = ssl_certfile
        self._ssl_keyfile = ssl_keyfile
        self._server: uvicorn.Server | None = None

    async def start(self) -> None:
        uv_kwargs: dict[str, object] = {
            "app": self._app,
            "host": self._config.bind,
            "port": self._config.port,
            "log_level": "info",
            "ssl_certfile": self._ssl_certfile,
            "ssl_keyfile": self._ssl_keyfile,
        }

        # HTTP/2 support via h2 (requires TLS and the h2 package)
        if self._config.http2 and self._ssl_certfile:
            uv_kwargs["h11_max_incomplete_event_size"] = None
            # uvicorn supports http2 natively when h2 is installed
            try:
                import h2  # noqa: F401
                uv_kwargs["http"] = "h2"
                log.info("http2_enabled")
            except ImportError:
                log.warning(
                    "http2_requested_but_h2_not_installed",
                    hint="pip install h2",
                )

        uv_config = uvicorn.Config(**uv_kwargs)
        self._server = uvicorn.Server(uv_config)
        # Run in background task so we don't block other listeners
        asyncio.create_task(self._server.serve())
        log.info(
            "http_listener_started",
            bind=self._config.bind,
            port=self._config.port,
            tls=bool(self._ssl_certfile),
            http2=self._config.http2,
        )

    async def stop(self) -> None:
        if self._server:
            self._server.should_exit = True
