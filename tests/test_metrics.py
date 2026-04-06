"""Tests for Prometheus metrics module (OPER-02).

TDD-driven: covers metric definitions, update helpers, and ASGI endpoint
behaviour for both the API app (/metrics exposed) and proxy app (/metrics 404).
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

import httpx
import pytest
import pytest_asyncio
from prometheus_client import CollectorRegistry, Counter, Gauge, Histogram

# ---------------------------------------------------------------------------
# Unit tests - metric definitions and update helpers
# ---------------------------------------------------------------------------


def test_requests_total_counter_increments():
    """REQUESTS_TOTAL counter increments and appears in registry output."""
    from infraguard.ui.api.metrics import REGISTRY, REQUESTS_TOTAL

    REQUESTS_TOTAL.labels(domain="test.com", result="allowed").inc()
    output = _registry_output(REGISTRY)
    assert "infraguard_requests_total" in output


def test_upstream_latency_histogram_observes():
    """UPSTREAM_LATENCY histogram observes values and appears in registry output."""
    from infraguard.ui.api.metrics import REGISTRY, UPSTREAM_LATENCY

    UPSTREAM_LATENCY.labels(domain="test.com").observe(0.123)
    output = _registry_output(REGISTRY)
    assert "infraguard_upstream_latency_seconds" in output


def test_circuit_breaker_state_closed():
    """update_circuit_breaker_metrics sets gauge to 0 for CLOSED."""
    from infraguard.core.circuit_breaker import CircuitBreaker
    from infraguard.ui.api.metrics import CIRCUIT_BREAKER_STATE, update_circuit_breaker_metrics

    breaker = CircuitBreaker("https://c2.example.com")
    # Default state is CLOSED
    assert breaker.state == CircuitBreaker.CLOSED

    update_circuit_breaker_metrics({"https://c2.example.com": breaker})

    value = CIRCUIT_BREAKER_STATE.labels(upstream="https://c2.example.com")._value.get()
    assert value == 0


def test_circuit_breaker_state_open():
    """update_circuit_breaker_metrics sets gauge to 1 for OPEN."""
    from infraguard.core.circuit_breaker import CircuitBreaker
    from infraguard.ui.api.metrics import CIRCUIT_BREAKER_STATE, update_circuit_breaker_metrics

    breaker = CircuitBreaker("https://c2-open.example.com")
    breaker._state = CircuitBreaker.OPEN

    update_circuit_breaker_metrics({"https://c2-open.example.com": breaker})

    value = CIRCUIT_BREAKER_STATE.labels(upstream="https://c2-open.example.com")._value.get()
    assert value == 1


def test_circuit_breaker_state_half_open():
    """update_circuit_breaker_metrics sets gauge to 2 for HALF_OPEN."""
    from infraguard.core.circuit_breaker import CircuitBreaker
    from infraguard.ui.api.metrics import CIRCUIT_BREAKER_STATE, update_circuit_breaker_metrics

    breaker = CircuitBreaker("https://c2-halfopen.example.com")
    breaker._state = CircuitBreaker.HALF_OPEN

    update_circuit_breaker_metrics({"https://c2-halfopen.example.com": breaker})

    value = CIRCUIT_BREAKER_STATE.labels(upstream="https://c2-halfopen.example.com")._value.get()
    assert value == 2


def test_update_feed_metrics_with_timestamp():
    """update_feed_metrics sets gauge from ISO timestamp string."""
    from infraguard.ui.api.metrics import FEED_LAST_REFRESH, update_feed_metrics

    ts = "2024-01-15T12:00:00+00:00"
    expected_epoch = datetime.fromisoformat(ts).timestamp()

    fake_feed_url = "https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.txt"
    feed_status = {fake_feed_url: ts}

    with patch("infraguard.ui.api.metrics.get_feed_status", return_value=feed_status):
        update_feed_metrics()

    value = FEED_LAST_REFRESH.labels(feed_url=fake_feed_url)._value.get()
    assert abs(value - expected_epoch) < 1.0


def test_update_feed_metrics_none_sets_zero():
    """update_feed_metrics sets gauge to 0.0 for None entries."""
    from infraguard.ui.api.metrics import FEED_LAST_REFRESH, update_feed_metrics

    fake_feed_url = "https://rules.emergingthreats.net/blockrules/compromised-ips.txt"
    feed_status = {fake_feed_url: None}

    with patch("infraguard.ui.api.metrics.get_feed_status", return_value=feed_status):
        update_feed_metrics()

    value = FEED_LAST_REFRESH.labels(feed_url=fake_feed_url)._value.get()
    assert value == 0.0


def test_active_connections_gauge_increment_decrement():
    """ACTIVE_CONNECTIONS gauge can be incremented and decremented."""
    from infraguard.ui.api.metrics import ACTIVE_CONNECTIONS

    initial = ACTIVE_CONNECTIONS._value.get()
    ACTIVE_CONNECTIONS.inc()
    assert ACTIVE_CONNECTIONS._value.get() == initial + 1
    ACTIVE_CONNECTIONS.dec()
    assert ACTIVE_CONNECTIONS._value.get() == initial


# ---------------------------------------------------------------------------
# Integration tests - /metrics ASGI endpoint
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_metrics_endpoint_returns_200_on_api_app():
    """/metrics on the API app returns 200 with Prometheus text format."""
    from infraguard.config.schema import InfraGuardConfig
    from infraguard.tracking.database import Database
    from infraguard.ui.api.app import create_api_app

    config = InfraGuardConfig()
    db = Database(":memory:")
    app = create_api_app(config, db)

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://testserver", follow_redirects=True
    ) as client:
        resp = await client.get("/metrics")

    assert resp.status_code == 200
    assert "text/plain" in resp.headers.get("content-type", "")


@pytest.mark.asyncio
async def test_metrics_endpoint_not_on_proxy_app():
    """/metrics on the proxy app does NOT return Prometheus text content.

    The proxy app has no /metrics mount - /metrics is handled by the
    generic proxy_handler, which scores the request and drops it (redirect,
    403, etc.).  Any non-200 or non-prometheus response satisfies the
    negative test: metrics are NOT exposed on the proxy port.
    """
    from infraguard.config.schema import (
        DomainConfig,
        DropActionConfig,
        InfraGuardConfig,
        ListenerConfig,
        PipelineConfig,
    )
    from infraguard.core.app import create_app

    config = InfraGuardConfig(
        listeners=[ListenerConfig(protocol="https", bind="127.0.0.1", port=8443)],
        domains={
            "test.local": DomainConfig(
                upstream="https://127.0.0.1:9999",
                profile_path="examples/jquery-c2.3.14.profile",
                drop_action=DropActionConfig(type="redirect", target="https://example.com"),
            ),
        },
        pipeline=PipelineConfig(block_score_threshold=0.7),
    )
    app = create_app(config)

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://testserver"
    ) as client:
        resp = await client.get("/metrics")

    # Proxy app must NOT serve Prometheus metrics - any response that is NOT
    # a Prometheus text-format 200 proves /metrics is not mounted on proxy.
    is_prometheus = (
        resp.status_code == 200
        and "text/plain" in resp.headers.get("content-type", "")
        and "infraguard_" in resp.text
    )
    assert not is_prometheus, (
        f"Prometheus metrics leaked on proxy port! status={resp.status_code}, "
        f"content-type={resp.headers.get('content-type', '')}"
    )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _registry_output(registry: CollectorRegistry) -> str:
    """Generate Prometheus text output from a registry."""
    from prometheus_client import generate_latest

    return generate_latest(registry).decode("utf-8")
