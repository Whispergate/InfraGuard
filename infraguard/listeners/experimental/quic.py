"""HTTP/3 (QUIC) listener scaffold.

Wires into the same Router the HTTP/1.1 and HTTP/2 listeners use, but
speaks QUIC on UDP/443 via the ``aioquic`` package. Modern browsers
negotiate H3 first via Alt-Svc a redirector that only speaks H1/H2
stands out to defenders watching for the H3 upgrade dance.

Status: scaffold. The wiring here is real (config surface, lifecycle
hooks, uvicorn-free asyncio serve loop skeleton). The actual H3
frame handling is delegated to a small aioquic H3Connection subclass
which needs one more pass to hand off completed requests to the
router. Marked ``EXPERIMENTAL`` in :mod:`infraguard.listeners`.

TODOs for the follow-up PR:

  1. Adapt aioquic's ``H3Connection`` events (HeadersReceived,
     DataReceived, StreamEnded) into a Starlette-compatible ASGI
     scope so ``DomainRouter.handle`` can be reused unchanged.
  2. Emit an ``Alt-Svc: h3=":443" ma=86400`` header from the H1/H2
     listeners so clients discover the H3 endpoint.
  3. Configuration: ``listeners: [{protocol: h3, port: 443, ...}]``.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

import structlog

if TYPE_CHECKING:
    from infraguard.core.router import DomainRouter

log = structlog.get_logger()


@dataclass
class QuicListenerConfig:
    bind: str = "0.0.0.0"
    port: int = 443
    cert: str = ""
    key: str = ""
    alpn: tuple[str, ...] = ("h3",)
    max_datagram_size: int = 1350


class QuicListener:
    """Scaffold. Not runnable until the H3 frame adapter lands."""

    def __init__(self, cfg: QuicListenerConfig, router: DomainRouter):
        self._cfg = cfg
        self._router = router
        self._server = None

    async def start(self) -> None:
        try:
            import aioquic  # noqa: F401
        except ImportError:
            log.warning(
                "quic_listener_disabled_no_aioquic",
                install="pip install aioquic",
            )
            return
        log.info(
            "quic_listener_scaffold_only",
            hint="H3 frame adapter is not yet implemented see module docstring.",
        )
        # Real implementation:
        #   from aioquic.asyncio import serve
        #   from aioquic.h3.connection import H3Connection
        #   self._server = await serve(self._cfg.bind, self._cfg.port, ...)

    async def stop(self) -> None:
        if self._server is not None:
            self._server.close()
            await self._server.wait_closed()


__all__ = ["QuicListener", "QuicListenerConfig"]
