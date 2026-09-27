"""Event types for internal pub/sub and tracking."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from datetime import UTC, datetime


def compute_request_hash(
    method: str, path: str, user_agent: str, cookie: str, body: bytes | None
) -> str:
    """Stable per-request fingerprint used by ReplayFilter and the tracking DB.

    Keeping this in one place ensures the replay-detection hash and the
    `requests.request_hash` column always agree.
    """
    sig = hashlib.sha256()
    sig.update(method.encode())
    sig.update(path.encode())
    sig.update(user_agent.encode())
    sig.update(cookie.encode())
    if isinstance(body, (bytes, bytearray)):
        sig.update(body)
    return sig.hexdigest()


@dataclass
class RequestEvent:
    """Emitted for every incoming request."""

    timestamp: datetime
    domain: str
    client_ip: str
    method: str
    uri: str
    user_agent: str
    filter_result: str  # "allow" or "block"
    filter_reason: str | None
    filter_score: float
    response_status: int
    duration_ms: float
    request_hash: str = ""
    protocol: str = "http"  # http, dns, mqtt, websocket

    @classmethod
    def now(cls, **kwargs) -> RequestEvent:
        return cls(timestamp=datetime.now(UTC), **kwargs)


@dataclass
class NodeEvent:
    """Emitted when a node status changes."""

    node_id: str
    name: str
    address: str
    status: str  # active, degraded, offline
    timestamp: datetime = field(default_factory=lambda: datetime.now(UTC))
