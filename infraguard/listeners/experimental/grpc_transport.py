"""gRPC beacon transport scaffold.

Complements the WebSocket transport (binary + HTTP/2 mux useful for
implants that already link gRPC for legitimate purposes and want to
blend). Ships a minimal .proto and a service skeleton the actual
bidirectional stream handler is a follow-up.

Depends on ``grpcio`` and ``grpcio-tools`` which are NOT in
pyproject.toml today installers must add them explicitly.

TODOs:

  1. Ship the generated ``beacon_pb2`` / ``beacon_pb2_grpc`` modules
     (build step in Dockerfile).
  2. Adapter from gRPC BeaconRequest -> DomainRouter.handle Request.
"""

from __future__ import annotations

import structlog

log = structlog.get_logger()


PROTO = """\
syntax = "proto3";
package infraguard.beacon.v1;

service BeaconService {
  // Long-lived bidirectional stream. Client sends Task acknowledgments
  // and telemetry server pushes Tasks.
  rpc Session (stream ClientFrame) returns (stream ServerFrame);
}

message ClientFrame {
  string beacon_id = 1;
  string domain = 2;
  bytes  payload = 3;
  map<string, string> metadata = 4;
}

message ServerFrame {
  bytes payload = 1;
  int32 next_sleep_ms = 2;
  int32 next_jitter_pct = 3;
}
"""


class BeaconGrpcService:
    """Skeleton. Not wired into the compose stack yet."""

    def __init__(self, router):
        self._router = router

    async def Session(self, request_iterator, context):
        log.info("grpc_beacon_scaffold_only")
        # Real implementation: async for frame in request_iterator: ...


__all__ = ["PROTO", "BeaconGrpcService"]
