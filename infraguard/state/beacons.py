"""Cluster-wide beacon session tracking.

Each proxy replica used to keep its own beacon-first-seen map (or none). That meant:

* the dynamic whitelist scoped to one node. a beacon accepted on
  proxy-node-A got blocked on B (see :mod:`infraguard.intel.manager`);
* the dashboard could not show a coherent per-beacon session view
  because two nodes reported the same beacon twice with different
  ``first_seen`` timestamps;
* burn scoring per beacon was per-node instead of per-fleet.

This module derives a stable ``beacon_id`` from
``(client_ip, JA3, first_seen_user_agent)`` and stores per-beacon
counters + timestamps in the shared :class:`StateBackend`. It is
optional. the tracking DB still holds the ground-truth per-request
log the shared state is a fast in-memory cache used by the pipeline.
"""

from __future__ import annotations

import hashlib
import json
import time
from dataclasses import asdict, dataclass
from typing import TYPE_CHECKING

import structlog

if TYPE_CHECKING:
    from infraguard.state import StateBackend

log = structlog.get_logger()

# Cluster-wide keys.
_BEACON_KEY_PREFIX = "beacon:"
_DEFAULT_TTL = 86_400 * 7  # 7 days. plenty for a red-team engagement.


@dataclass
class BeaconSession:
    """Public view of a beacon's cluster-wide state."""

    beacon_id: str
    client_ip: str
    ja3: str | None
    user_agent: str
    first_seen: float          # unix epoch
    last_seen: float           # unix epoch
    request_count: int
    domains: list[str]         # every domain this beacon has hit


def compute_beacon_id(
    client_ip: str, ja3: str | None, user_agent: str
) -> str:
    """Deterministic ID for a beacon session.

    Uses SHA-256 of the tuple. The client IP alone is not stable
    (NAT, proxy) but combined with JA3 + first-seen UA it's a
    reasonable session key for the lifetime of one engagement.
    """
    material = f"{client_ip}|{ja3 or ''}|{user_agent}".encode()
    return hashlib.sha256(material).hexdigest()[:24]


async def record_beacon_request(
    state: StateBackend | None,
    *,
    beacon_id: str,
    client_ip: str,
    ja3: str | None,
    user_agent: str,
    domain: str,
    ttl_seconds: int = _DEFAULT_TTL,
) -> BeaconSession:
    """Upsert this beacon in shared state return the freshest view.

    On error: a shared-state hiccup is logged, and this call falls
    back to returning a synthetic session built only from this request.
    Never blocks or fails the hot path.
    """
    now = time.time()
    key = _BEACON_KEY_PREFIX + beacon_id

    if state is None:
        return BeaconSession(
            beacon_id=beacon_id,
            client_ip=client_ip,
            ja3=ja3,
            user_agent=user_agent,
            first_seen=now,
            last_seen=now,
            request_count=1,
            domains=[domain],
        )

    existing_raw = None
    try:
        existing_raw = await state.get(key)
    except Exception:
        log.debug("beacon_state_read_failed", beacon_id=beacon_id)

    if existing_raw:
        try:
            existing = json.loads(existing_raw)
            domains = list({*(existing.get("domains") or []), domain})
            session = BeaconSession(
                beacon_id=beacon_id,
                client_ip=existing.get("client_ip", client_ip),
                ja3=existing.get("ja3", ja3),
                user_agent=existing.get("user_agent", user_agent),
                first_seen=float(existing.get("first_seen", now)),
                last_seen=now,
                request_count=int(existing.get("request_count", 0)) + 1,
                domains=domains,
            )
        except (ValueError, TypeError):
            log.debug("beacon_state_corrupt", beacon_id=beacon_id)
            session = BeaconSession(
                beacon_id, client_ip, ja3, user_agent, now, now, 1, [domain]
            )
    else:
        session = BeaconSession(
            beacon_id, client_ip, ja3, user_agent, now, now, 1, [domain]
        )

    try:
        await state.set(key, json.dumps(asdict(session)), ttl_seconds=ttl_seconds)
    except Exception:
        log.debug("beacon_state_write_failed", beacon_id=beacon_id)

    return session


async def get_beacon(
    state: StateBackend, beacon_id: str
) -> BeaconSession | None:
    """Fetch a beacon session by id, or None if never seen / expired."""
    raw = await state.get(_BEACON_KEY_PREFIX + beacon_id)
    if not raw:
        return None
    try:
        d = json.loads(raw)
        return BeaconSession(
            beacon_id=beacon_id,
            client_ip=d["client_ip"],
            ja3=d.get("ja3"),
            user_agent=d.get("user_agent", ""),
            first_seen=float(d.get("first_seen", 0)),
            last_seen=float(d.get("last_seen", 0)),
            request_count=int(d.get("request_count", 0)),
            domains=d.get("domains", []),
        )
    except (ValueError, KeyError, TypeError):
        return None


__all__ = ["BeaconSession", "compute_beacon_id", "get_beacon", "record_beacon_request"]
