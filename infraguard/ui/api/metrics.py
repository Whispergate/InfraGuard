"""Prometheus metric definitions and update helpers for InfraGuard.

Exposes observability metrics on the API port (not the proxy port).
Uses a dedicated CollectorRegistry to avoid cross-test pollution and
prevent accidental exposure of Go/Python runtime defaults.

Exported metrics:
    REQUESTS_TOTAL           - request rate counters per domain and result
    UPSTREAM_LATENCY         - upstream proxy latency histogram per domain
    CIRCUIT_BREAKER_STATE    - circuit breaker state gauge per upstream
    FEED_LAST_REFRESH        - unix epoch of last successful feed refresh per URL
    ACTIVE_CONNECTIONS       - current in-flight proxy connection count

Helper functions:
    update_circuit_breaker_metrics(breakers) - sync current breaker states
    update_feed_metrics()                    - sync current feed refresh times
    create_metrics_app()                     - return ASGI app for /metrics mount
"""

from __future__ import annotations

from datetime import datetime
from typing import TYPE_CHECKING

from prometheus_client import CollectorRegistry, Counter, Gauge, Histogram, make_asgi_app
from starlette.types import ASGIApp

from infraguard.intel.feeds import get_feed_status

if TYPE_CHECKING:
    from infraguard.core.circuit_breaker import CircuitBreaker

# Dedicated registry - keeps tests isolated and avoids exposing default
# Python/process metrics on the /metrics endpoint.
REGISTRY = CollectorRegistry()

# ---------------------------------------------------------------------------
# Metric definitions
# ---------------------------------------------------------------------------

REQUESTS_TOTAL = Counter(
    "infraguard_requests_total",
    "Total requests processed by domain and result",
    ["domain", "result"],
    registry=REGISTRY,
)

UPSTREAM_LATENCY = Histogram(
    "infraguard_upstream_latency_seconds",
    "Upstream proxy request latency in seconds",
    ["domain"],
    buckets=[0.01, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0],
    registry=REGISTRY,
)

CIRCUIT_BREAKER_STATE = Gauge(
    "infraguard_circuit_breaker_state",
    "Circuit breaker state per upstream (0=CLOSED, 1=OPEN, 2=HALF_OPEN)",
    ["upstream"],
    registry=REGISTRY,
)

FEED_LAST_REFRESH = Gauge(
    "infraguard_feed_last_refresh_seconds",
    "Unix timestamp of last successful threat intel feed refresh",
    ["feed_url"],
    registry=REGISTRY,
)

ACTIVE_CONNECTIONS = Gauge(
    "infraguard_active_connections",
    "Current number of active in-flight proxy connections",
    registry=REGISTRY,
)

# ---------------------------------------------------------------------------
# State code mapping
# ---------------------------------------------------------------------------

_STATE_CODES: dict[str, int] = {
    "CLOSED": 0,
    "OPEN": 1,
    "HALF_OPEN": 2,
}

# ---------------------------------------------------------------------------
# Update helpers
# ---------------------------------------------------------------------------


def update_circuit_breaker_metrics(breakers: dict[str, "CircuitBreaker"]) -> None:
    """Sync circuit breaker gauge values from current breaker states.

    Args:
        breakers: Mapping of upstream URL -> CircuitBreaker instance.
    """
    for upstream, breaker in breakers.items():
        code = _STATE_CODES.get(breaker.state, -1)
        CIRCUIT_BREAKER_STATE.labels(upstream=upstream).set(code)


def update_feed_metrics() -> None:
    """Sync feed staleness gauges from current feed refresh timestamps.

    Calls get_feed_status() and converts ISO timestamp strings to unix
    epoch seconds. Sets 0.0 for feeds that have never successfully refreshed.
    """
    status = get_feed_status()
    for feed_url, iso_ts in status.items():
        if iso_ts is None:
            FEED_LAST_REFRESH.labels(feed_url=feed_url).set(0.0)
        else:
            epoch = datetime.fromisoformat(iso_ts).timestamp()
            FEED_LAST_REFRESH.labels(feed_url=feed_url).set(epoch)


# ---------------------------------------------------------------------------
# ASGI app factory
# ---------------------------------------------------------------------------


def create_metrics_app() -> ASGIApp:
    """Return an ASGI app that serves Prometheus metrics text format.

    Mount at /metrics on the API application only - never on the proxy app.
    """
    return make_asgi_app(registry=REGISTRY)
