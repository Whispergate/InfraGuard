"""Event types for internal pub/sub and tracking."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone


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
        return cls(timestamp=datetime.now(timezone.utc), **kwargs)


@dataclass
class NodeEvent:
    """Emitted when a node status changes."""

    node_id: str
    name: str
    address: str
    status: str  # active, degraded, offline
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
