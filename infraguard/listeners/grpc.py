"""gRPC beacon listener.

Binds a port, stands up ``grpc.aio.server`` and registers the
``BeaconGrpcService`` from :mod:`infraguard.listeners.experimental.grpc_transport`
as a generic (byte-stream) handler.

TLS is on when both ``options.cert`` and ``options.key`` resolve to
readable files, off otherwise. gRPC does not permit a plain-text
listener from many client stacks; keep insecure only for dev.
"""

from __future__ import annotations

from pathlib import Path

import structlog

from infraguard.config.schema import ListenerConfig
from infraguard.intel.manager import IntelManager
from infraguard.tracking.recorder import EventRecorder

log = structlog.get_logger()


class GRPCListener:
    """Serve the beacon gRPC service alongside the HTTP listener."""

    protocol = "grpc"

    def __init__(
        self,
        config: ListenerConfig,
        intel: IntelManager,
        recorder: EventRecorder | None = None,
        router=None,
    ):
        self._config = config
        self._intel = intel
        self._recorder = recorder
        self._router = router
        self._server = None
        self._bind = f"{config.bind}:{config.port}"

    async def start(self) -> None:
        try:
            import grpc
        except ImportError:
            log.warning(
                "grpc_listener_missing_dep",
                hint="pip install grpcio; skipping listener",
                bind=self._bind,
            )
            return

        # The listener needs the router to adapt frames; the standard
        # ListenerManager wiring passes intel/recorder, so callers
        # attach the router with ``.attach_router(router)`` OR pass it
        # in the constructor. Fail loud if neither happened.
        if self._router is None:
            log.error("grpc_listener_no_router", bind=self._bind)
            return

        from infraguard.listeners.experimental.grpc_transport import (
            build_generic_handler,
        )

        self._server = grpc.aio.server()
        self._server.add_generic_rpc_handlers((build_generic_handler(self._router),))

        cert_path = self._config.options.get("cert")
        key_path = self._config.options.get("key")
        if cert_path and key_path and Path(cert_path).is_file() and Path(key_path).is_file():
            with open(cert_path, "rb") as f:
                cert = f.read()
            with open(key_path, "rb") as f:
                key = f.read()
            creds = grpc.ssl_server_credentials([(key, cert)])
            self._server.add_secure_port(self._bind, creds)
            scheme = "grpcs"
        else:
            self._server.add_insecure_port(self._bind)
            scheme = "grpc"
            log.warning(
                "grpc_listener_insecure",
                bind=self._bind,
                hint="set options.cert + options.key for TLS",
            )

        await self._server.start()
        log.info("grpc_listener_started", scheme=scheme, bind=self._bind)

    def attach_router(self, router) -> None:
        self._router = router

    async def stop(self) -> None:
        if self._server is not None:
            # 5s grace period for in-flight streams.
            await self._server.stop(5)
            self._server = None


__all__ = ["GRPCListener"]
