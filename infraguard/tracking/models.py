"""Database row dataclasses for the tracking system."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime


@dataclass
class RequestRow:
    id: int | None
    timestamp: str
    domain: str
    client_ip: str
    method: str
    uri: str
    user_agent: str
    filter_result: str
    filter_reason: str | None
    filter_score: float
    response_status: int
    request_hash: str
    duration_ms: float


@dataclass
class NodeRow:
    id: str
    name: str
    address: str
    domains: str  # JSON list
    last_heartbeat: str
    status: str
    config_hash: str


@dataclass
class DynamicWhitelistRow:
    ip: str
    valid_request_count: int
    first_seen: str
    last_seen: str
    whitelisted_at: str | None
