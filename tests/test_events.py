"""Tests for event models and tracking."""

from datetime import datetime, timezone

import pytest

from infraguard.models.events import RequestEvent, NodeEvent


class TestRequestEvent:
    def test_now_factory(self):
        event = RequestEvent.now(
            domain="test.local",
            client_ip="1.2.3.4",
            method="GET",
            uri="/callback",
            user_agent="TestAgent",
            filter_result="allow",
            filter_reason=None,
            filter_score=0.0,
            response_status=200,
            duration_ms=5.0,
        )
        assert event.domain == "test.local"
        assert event.protocol == "http"  # default
        assert isinstance(event.timestamp, datetime)

    def test_protocol_field(self):
        event = RequestEvent.now(
            domain="dns.local",
            client_ip="1.2.3.4",
            method="A",
            uri="example.com",
            user_agent="",
            filter_result="allow",
            filter_reason=None,
            filter_score=0.0,
            response_status=0,
            duration_ms=1.0,
            protocol="dns",
        )
        assert event.protocol == "dns"

    def test_content_served_result(self):
        event = RequestEvent.now(
            domain="cdn.local",
            client_ip="5.6.7.8",
            method="GET",
            uri="/downloads/payload.exe",
            user_agent="Mozilla/5.0",
            filter_result="content_served",
            filter_reason=None,
            filter_score=0.0,
            response_status=200,
            duration_ms=50.0,
        )
        assert event.filter_result == "content_served"


class TestNodeEvent:
    def test_creation(self):
        event = NodeEvent(
            node_id="abc-123",
            name="redirector-1",
            address="10.0.0.1",
            status="active",
        )
        assert event.node_id == "abc-123"
        assert event.status == "active"
        assert isinstance(event.timestamp, datetime)
