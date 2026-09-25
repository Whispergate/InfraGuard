"""gRPC beacon transport.

Speaks the same wire shape as the WebSocket transport (JSON frames
carrying the fields the profile filter already scores), just over gRPC
stream-stream so implants that already link gRPC for legitimate reasons
can blend in.

Wire format per frame (both directions):

    {"method": "POST", "uri": "/api/v1/telemetry",
     "headers": {"user-agent": "...", "cookie": "..."},
     "body_b64": "<base64>"}

Server frames come back as:

    {"status": 200, "headers": {...}, "body_b64": "..."}

There is no ``.proto`` because the handler is registered with pass-
through serializers (``bytes -> bytes``). That skips the whole
``grpcio-tools`` codegen step and keeps the runtime footprint down to
just the ``grpcio`` wheel. Clients can be raw ``grpc`` in any language
that lets them declare a stream/stream RPC with byte payloads.

Service name and RPC name are what a client must invoke:

    /infraguard.beacon.v1.BeaconService/Session

Enable via a ``listeners:`` block:

    listeners:
      - protocol: grpc
        bind: 0.0.0.0
        port: 9443
        options:
          # Optional TLS. Omit for insecure (dev only).
          cert: /app/certs/tls.crt
          key:  /app/certs/tls.key
"""

from __future__ import annotations

import base64
import json
from typing import TYPE_CHECKING

import structlog
from starlette.requests import Request

if TYPE_CHECKING:
    from infraguard.core.router import DomainRouter

log = structlog.get_logger()


SERVICE_NAME = "infraguard.beacon.v1.BeaconService"
RPC_NAME = "Session"


class BeaconGrpcService:
    """Adapts incoming gRPC frames to ``DomainRouter.handle`` and back."""

    def __init__(self, router: DomainRouter):
        self._router = router

    async def session(self, request_iterator, context):
        """Bidirectional stream handler. Yields one response per request."""
        peer = context.peer() if context is not None else "unknown"
        client_host, client_port = _split_peer(peer)
        log.info("grpc_beacon_connected", peer=peer)
        async for raw in request_iterator:
            try:
                frame = json.loads(raw)
            except (json.JSONDecodeError, TypeError) as exc:
                yield _err_frame(f"bad-json: {exc}")
                continue
            try:
                request = _frame_to_request(frame, client_host, client_port)
            except (KeyError, ValueError) as exc:
                yield _err_frame(f"bad-frame: {exc}")
                continue
            try:
                response = await self._router.handle(request)
            except Exception as exc:
                log.exception("grpc_beacon_handler_error")
                yield _err_frame(f"handler-error: {exc}")
                continue
            yield json.dumps(_response_to_frame(response)).encode()
        log.info("grpc_beacon_disconnected", peer=peer)


def build_generic_handler(router: DomainRouter):
    """Return a gRPC ``GenericRpcHandler`` that serves ``SERVICE_NAME``.

    Registered with pass-through serializers so the handler moves raw
    ``bytes`` and no protobuf codegen is needed.
    """
    import grpc  # local import so the module loads without grpcio

    service = BeaconGrpcService(router)
    handler = grpc.stream_stream_rpc_method_handler(
        service.session,
        request_deserializer=None,     # None == raw bytes
        response_serializer=None,
    )
    return grpc.method_handlers_generic_handler(
        SERVICE_NAME,
        {RPC_NAME: handler},
    )


def _frame_to_request(frame: dict, client_host: str, client_port: int) -> Request:
    """Build a Starlette Request from a beacon JSON frame."""
    method = str(frame.get("method", "GET")).upper()
    uri = str(frame.get("uri", "/"))
    headers = {str(k).lower(): str(v) for k, v in (frame.get("headers") or {}).items()}
    body_b64 = frame.get("body_b64", "")
    body = base64.b64decode(body_b64) if body_b64 else b""

    path, _, query = uri.partition("?")
    header_list = [(k.encode(), v.encode()) for k, v in headers.items()]

    scope = {
        "type": "http",
        "asgi": {"version": "3.0"},
        "http_version": "1.1",
        "method": method,
        "scheme": "https",
        "path": path,
        "raw_path": path.encode(),
        "query_string": query.encode(),
        "headers": header_list,
        "server": ("0.0.0.0", 443),
        "client": (client_host, client_port),
        "root_path": "",
    }

    async def _receive():
        return {"type": "http.request", "body": body, "more_body": False}

    return Request(scope, receive=_receive)


def _response_to_frame(response) -> dict:
    """Serialize a Starlette Response back into a JSON frame."""
    body = getattr(response, "body", b"") or b""
    return {
        "status": getattr(response, "status_code", 200),
        "headers": {k: v for k, v in response.headers.items()},
        "body_b64": base64.b64encode(body).decode(),
    }


def _err_frame(msg: str) -> bytes:
    return json.dumps({"status": 400, "headers": {}, "body_b64": "",
                       "error": msg}).encode()


def _split_peer(peer: str) -> tuple[str, int]:
    """Parse gRPC ``ipv4:1.2.3.4:5678`` / ``ipv6:[::1]:5678`` into (host, port)."""
    if not peer:
        return "unknown", 0
    _, _, rest = peer.partition(":")
    host, sep, port = rest.rpartition(":")
    if not sep:
        return rest, 0
    host = host.strip("[]")
    try:
        return host, int(port)
    except ValueError:
        return host, 0


__all__ = [
    "RPC_NAME",
    "SERVICE_NAME",
    "BeaconGrpcService",
    "build_generic_handler",
]
