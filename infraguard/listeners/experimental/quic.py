"""HTTP/3 (QUIC) listener.

Wires into the same Router the HTTP/1.1 and HTTP/2 listeners use, but
speaks QUIC on UDP/443 via the ``aioquic`` package. Modern browsers
negotiate H3 first via Alt-Svc; a redirector without it stands out to
defenders watching for the H3 upgrade dance.

Enable by adding a listener block to ``config.yaml``:

    listeners:
      - protocol: h3
        bind: 0.0.0.0
        port: 443
        tls:
          cert: /path/to/fullchain.pem
          key:  /path/to/privkey.pem

And emit an ``Alt-Svc`` header from the HTTP/1.1 or HTTP/2 listener so
clients discover the H3 endpoint.
"""

from __future__ import annotations

import asyncio
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
    """QUIC listener that hands off each H3 request to ``DomainRouter.handle``."""

    def __init__(self, cfg: QuicListenerConfig, router: DomainRouter):
        self._cfg = cfg
        self._router = router
        self._server = None

    async def start(self) -> None:
        try:
            from aioquic.asyncio import serve
            from aioquic.h3.connection import H3Connection
            from aioquic.h3.events import DataReceived, HeadersReceived
            from aioquic.quic.configuration import QuicConfiguration
            from aioquic.quic.events import ProtocolNegotiated
        except ImportError:
            log.warning(
                "quic_listener_disabled_no_aioquic",
                install="pip install aioquic",
            )
            return

        configuration = QuicConfiguration(
            alpn_protocols=list(self._cfg.alpn),
            is_client=False,
            max_datagram_size=self._cfg.max_datagram_size,
        )
        if not self._cfg.cert or not self._cfg.key:
            log.warning("quic_listener_no_certs")
            return
        configuration.load_cert_chain(self._cfg.cert, self._cfg.key)

        router = self._router

        class _Session:
            """Per-connection H3 session."""

            def __init__(self, quic):
                self._quic = quic
                self._h3: H3Connection | None = None
                self._streams: dict[int, dict] = {}

            def quic_event(self, event) -> None:
                if isinstance(event, ProtocolNegotiated) and event.alpn_protocol == "h3":
                    self._h3 = H3Connection(self._quic)
                if self._h3 is None:
                    return
                for h3_event in self._h3.handle_event(event):
                    if isinstance(h3_event, HeadersReceived):
                        self._streams[h3_event.stream_id] = {
                            "headers": h3_event.headers,
                            "body": bytearray(),
                            "ended": h3_event.stream_ended,
                        }
                        if h3_event.stream_ended:
                            asyncio.create_task(self._dispatch(h3_event.stream_id))
                    elif isinstance(h3_event, DataReceived):
                        st = self._streams.get(h3_event.stream_id)
                        if st is None:
                            continue
                        st["body"] += h3_event.data
                        if h3_event.stream_ended:
                            asyncio.create_task(self._dispatch(h3_event.stream_id))

            async def _dispatch(self, stream_id: int) -> None:
                st = self._streams.pop(stream_id, None)
                if st is None or self._h3 is None:
                    return
                try:
                    request = _h3_to_starlette_request(st["headers"], bytes(st["body"]))
                    response = await router.handle(request)
                    headers = [
                        (b":status", str(response.status_code).encode()),
                        *[(k.encode(), v.encode()) for k, v in response.headers.items()],
                    ]
                    self._h3.send_headers(stream_id, headers, end_stream=False)
                    body = getattr(response, "body", b"") or b""
                    self._h3.send_data(stream_id, body, end_stream=True)
                except Exception as exc:
                    log.warning("quic_dispatch_failed", stream=stream_id, error=str(exc))

        # aioquic.serve returns a QuicServer object; keep it so stop()
        # closes the transport cleanly at shutdown.
        self._server = await serve(
            self._cfg.bind,
            self._cfg.port,
            configuration=configuration,
            create_protocol=lambda *args, **kw: _AioQuicShim(_Session, *args, **kw),
        )
        log.info("quic_listener_started",
                 bind=self._cfg.bind, port=self._cfg.port)

    async def stop(self) -> None:
        if self._server is not None:
            self._server.close()
            try:
                await self._server.wait_closed()
            except Exception:
                pass
            self._server = None


def _h3_to_starlette_request(headers: list[tuple[bytes, bytes]], body: bytes):
    """Build a Starlette Request from H3 pseudo-headers + body."""
    from starlette.requests import Request

    method = "GET"
    path = "/"
    scheme = "https"
    authority = ""
    header_list: list[tuple[bytes, bytes]] = []
    for name, value in headers:
        if name == b":method":
            method = value.decode()
        elif name == b":path":
            path = value.decode()
        elif name == b":scheme":
            scheme = value.decode()
        elif name == b":authority":
            authority = value.decode()
            header_list.append((b"host", value))
        elif not name.startswith(b":"):
            header_list.append((name, value))

    path_only, _, query = path.partition("?")
    scope = {
        "type": "http",
        "asgi": {"version": "3.0"},
        "http_version": "3",
        "method": method,
        "scheme": scheme,
        "path": path_only,
        "raw_path": path_only.encode(),
        "query_string": query.encode(),
        "headers": header_list,
        "server": (authority.split(":")[0] if authority else "0.0.0.0", 443),
        "client": (None, None),
        "root_path": "",
    }

    async def _receive():
        return {"type": "http.request", "body": body, "more_body": False}

    return Request(scope, receive=_receive)


class _AioQuicShim:
    """Adapter connecting aioquic's protocol callback to our _Session."""

    def __init__(self, session_factory, quic, stream_handler=None):
        self._session = session_factory(quic)
        self._quic = quic

    def quic_event_received(self, event) -> None:
        self._session.quic_event(event)


__all__ = ["QuicListener", "QuicListenerConfig"]
