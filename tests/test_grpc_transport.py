"""Smoke tests for the gRPC beacon transport.

Covers the frame-to-request adapter and the servicer contract without
actually binding a socket - the ``grpcio`` wheel is optional, and CI
should stay green even where it's missing.
"""

from __future__ import annotations

import base64
import json

import pytest

from infraguard.listeners.experimental.grpc_transport import (
    RPC_NAME,
    SERVICE_NAME,
    BeaconGrpcService,
    _frame_to_request,
    _response_to_frame,
    _split_peer,
)


def test_service_and_rpc_name_stable():
    # Clients bind to /<SERVICE_NAME>/<RPC_NAME>; renaming these is a
    # breaking wire change.
    assert SERVICE_NAME == "infraguard.beacon.v1.BeaconService"
    assert RPC_NAME == "Session"


def test_frame_to_request_round_trips_headers_and_body():
    frame = {
        "method": "POST",
        "uri": "/api/telemetry?x=1",
        "headers": {"User-Agent": "curl/8", "X-Beacon": "abc"},
        "body_b64": base64.b64encode(b'{"k":"v"}').decode(),
    }
    req = _frame_to_request(frame, client_host="203.0.113.7", client_port=42000)
    assert req.method == "POST"
    assert req.url.path == "/api/telemetry"
    assert req.headers["user-agent"] == "curl/8"
    assert req.headers["x-beacon"] == "abc"
    assert req.client.host == "203.0.113.7"
    assert req.client.port == 42000


def test_frame_to_request_defaults_when_fields_missing():
    req = _frame_to_request({}, "127.0.0.1", 1)
    assert req.method == "GET"
    assert req.url.path == "/"


class _StubResponse:
    """Lookalike for starlette.responses.Response minus the ASGI plumbing."""

    def __init__(self, status: int, body: bytes, headers: dict):
        self.status_code = status
        self.body = body
        self.headers = headers


def test_response_to_frame_encodes_body_and_status():
    resp = _StubResponse(200, b"ok", {"content-type": "text/plain"})
    frame = _response_to_frame(resp)
    assert frame["status"] == 200
    assert frame["headers"] == {"content-type": "text/plain"}
    assert base64.b64decode(frame["body_b64"]) == b"ok"


@pytest.mark.parametrize(
    "peer,expected",
    [
        ("ipv4:203.0.113.7:42000", ("203.0.113.7", 42000)),
        ("ipv6:[::1]:31337", ("::1", 31337)),
        ("", ("unknown", 0)),
        ("weird:noport", ("noport", 0)),
    ],
)
def test_split_peer(peer, expected):
    assert _split_peer(peer) == expected


@pytest.mark.asyncio
async def test_servicer_forwards_frame_to_router_and_yields_response():
    """Feed one frame in, get exactly one response frame back."""

    seen: list = []

    class _RouterStub:
        async def handle(self, request):
            seen.append((request.method, request.url.path))
            return _StubResponse(204, b"", {"x-test": "yes"})

    async def _stream():
        yield json.dumps({"method": "POST", "uri": "/hi"}).encode()

    class _CtxStub:
        def peer(self):
            return "ipv4:127.0.0.1:12345"

    service = BeaconGrpcService(router=_RouterStub())
    responses = [r async for r in service.session(_stream(), _CtxStub())]
    assert len(responses) == 1
    got = json.loads(responses[0])
    assert got["status"] == 204
    assert got["headers"] == {"x-test": "yes"}
    assert seen == [("POST", "/hi")]


@pytest.mark.asyncio
async def test_servicer_returns_error_frame_on_bad_json():
    class _RouterStub:
        async def handle(self, request):  # pragma: no cover - not reached
            raise AssertionError("router should not be called for bad json")

    async def _stream():
        yield b"not json {{"

    class _CtxStub:
        def peer(self):
            return ""

    service = BeaconGrpcService(router=_RouterStub())
    responses = [r async for r in service.session(_stream(), _CtxStub())]
    assert len(responses) == 1
    err = json.loads(responses[0])
    assert err["status"] == 400
    assert "bad-json" in err.get("error", "")


def test_build_generic_handler_registers_service():
    """Skip if grpcio isn't installed - it's an optional extra."""
    grpc = pytest.importorskip("grpc")

    from infraguard.listeners.experimental.grpc_transport import build_generic_handler

    class _RouterStub:
        pass

    handler = build_generic_handler(_RouterStub())
    # GenericRpcHandler has a service_name() method matching what we
    # registered; renaming SERVICE_NAME is a wire break.
    assert handler.service_name() == SERVICE_NAME

    # Resolve the RPC to prove the servicer is wired into the handler.
    class _Details(grpc.HandlerCallDetails):
        method = f"/{SERVICE_NAME}/{RPC_NAME}"
        invocation_metadata = ()

    method_handler = handler.service(_Details())
    assert method_handler is not None
    assert method_handler.stream_stream is not None
