"""Custom asyncio SSL protocol that extracts JA3 fingerprints from ClientHello.

Uvicorn terminates TLS before any ASGI code runs. To inspect the raw
ClientHello we wrap the transport's write side to intercept the first bytes
received on the connection - before Python's ssl module processes them.

Architecture:
  1. JA3InjectingProtocol wraps the real TLS protocol.
  2. On first data_received(), it attempts to parse a ClientHello and stash
     the JA3 hash in _ja3_registry keyed by the peer (ip, port) tuple.
  3. connection_lost() evicts the entry to prevent unbounded growth.
  4. RequestLoggingMiddleware (or a dedicated middleware) calls get_ja3_for_peer()
     and injects the hash into request.state.ja3 for downstream filters.

Uvicorn extension point:
  Pass this class via the `ssl_protocol_class` kwarg when building a uvicorn
  Server, or monkey-patch uvicorn.protocols.http.httptools_impl.HttpToolsProtocol
  (used when lifespan="on" and tls=True). Exact hook depends on uvicorn version;
  the middleware fallback approach is version-independent.
"""

from __future__ import annotations

import asyncio
from typing import Any

import structlog

from infraguard.core.ja3 import ClientHelloFields, compute_ja3, parse_client_hello

log = structlog.get_logger()

# Global registry: (ip, port) -> ja3_hash
# Entries are short-lived (connection lifetime); cleaned up in connection_lost().
_ja3_registry: dict[tuple[str, int], str] = {}

_MAX_REGISTRY_SIZE = 10_000  # hard cap against unbounded growth under DoS


def get_ja3_for_peer(peer: tuple[str, int] | None) -> str | None:
    """Return the JA3 hash for a peer address, or None if not captured."""
    if peer is None:
        return None
    return _ja3_registry.get(peer)


class JA3InjectingProtocol(asyncio.Protocol):
    """asyncio Protocol that sniffs the TLS ClientHello before passing data through.

    This class delegates all actual TLS processing to the wrapped protocol
    (uvicorn's SSL protocol). It only looks at the first flight of bytes to
    extract the ClientHello, compute JA3, and store it in the registry.
    """

    def __init__(self, wrapped: asyncio.Protocol) -> None:
        self._wrapped = wrapped
        self._transport: asyncio.Transport | None = None
        self._peer: tuple[str, int] | None = None
        self._handshake_done = False

    def connection_made(self, transport: asyncio.Transport) -> None:
        self._transport = transport
        try:
            peer = transport.get_extra_info("peername")
            if peer:
                self._peer = (peer[0], peer[1])
        except Exception:
            pass
        self._wrapped.connection_made(transport)

    def data_received(self, data: bytes) -> None:
        if not self._handshake_done and self._peer is not None:
            self._handshake_done = True
            try:
                fields = parse_client_hello(data)
                if fields is not None:
                    ja3 = compute_ja3(fields)
                    # Evict oldest entry if registry is at capacity
                    if len(_ja3_registry) >= _MAX_REGISTRY_SIZE:
                        try:
                            oldest = next(iter(_ja3_registry))
                            del _ja3_registry[oldest]
                        except StopIteration:
                            pass
                    _ja3_registry[self._peer] = ja3
                    log.debug("ja3_captured", peer=self._peer, ja3=ja3)
            except Exception:
                pass
        self._wrapped.data_received(data)

    def eof_received(self) -> bool | None:
        return self._wrapped.eof_received()

    def connection_lost(self, exc: Exception | None) -> None:
        if self._peer is not None:
            _ja3_registry.pop(self._peer, None)
        self._wrapped.connection_lost(exc)

    def pause_writing(self) -> None:
        self._wrapped.pause_writing()

    def resume_writing(self) -> None:
        self._wrapped.resume_writing()
