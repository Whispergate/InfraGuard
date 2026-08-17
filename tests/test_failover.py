"""Tests for ProtocolFailover - multi-protocol C2 failover and failback."""

from __future__ import annotations

import asyncio
import time
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from infraguard.config.schema import InfraGuardConfig, ListenerConfig
from infraguard.core.failover import (
    ProtocolFailover,
    ProtocolHealth,
    ProtocolPriority,
    create_failover_manager,
)


# ── Fixtures ──────────────────────────────────────────────────────────────

@pytest.fixture
def multi_protocol_config() -> InfraGuardConfig:
    return InfraGuardConfig(
        listeners=[
            ListenerConfig(protocol="https", bind="0.0.0.0", port=443),
            ListenerConfig(protocol="dns", bind="0.0.0.0", port=53),
            ListenerConfig(protocol="mqtt", bind="0.0.0.0", port=1883),
        ],
        domains={},
    )


@pytest.fixture
def failover(multi_protocol_config) -> ProtocolFailover:
    return ProtocolFailover(
        multi_protocol_config,
        max_consecutive_failures=3,
        health_check_interval=0.05,
        failback_cooldown=0.1,
    )


# ── Protocol priority ordering ────────────────────────────────────────────

class TestProtocolPriority:
    def test_https_highest_priority(self):
        assert ProtocolPriority.HTTPS < ProtocolPriority.DNS
        assert ProtocolPriority.DNS < ProtocolPriority.MQTT
        assert ProtocolPriority.MQTT < ProtocolPriority.WEBSOCKET
        assert ProtocolPriority.WEBSOCKET < ProtocolPriority.TCP_TUNNEL

    def test_protocol_map_covers_all_listeners(self):
        from infraguard.core.failover import _PROTOCOL_MAP
        assert "https" in _PROTOCOL_MAP
        assert "dns" in _PROTOCOL_MAP
        assert "mqtt" in _PROTOCOL_MAP
        assert "websocket" in _PROTOCOL_MAP
        assert "tcp_tunnel" in _PROTOCOL_MAP


# ── ProtocolHealth dataclass ──────────────────────────────────────────────

class TestProtocolHealth:
    def test_record_success_resets_failures(self):
        ph = ProtocolHealth(protocol="https", priority=ProtocolPriority.HTTPS)
        ph.record_failure()
        ph.record_failure()
        assert ph.consecutive_failures == 2
        ph.record_success()
        assert ph.consecutive_failures == 0
        assert ph.is_up is True
        assert ph.total_successes == 1

    def test_record_failure_increments(self):
        ph = ProtocolHealth(protocol="dns", priority=ProtocolPriority.DNS)
        ph.record_failure()
        assert ph.consecutive_failures == 1
        assert ph.is_up is False
        assert ph.total_failures == 1


# ── Initial protocol selection ────────────────────────────────────────────

class TestInitialSelection:
    @pytest.mark.asyncio
    async def test_no_protocols_returns_none(self):
        config = InfraGuardConfig(listeners=[], domains={})
        fo = ProtocolFailover(config)
        assert await fo.current_protocol() is None

    @pytest.mark.asyncio
    async def test_single_protocol_selected(self, failover):
        """With one protocol up, it becomes active."""
        assert await failover.current_protocol() == "https"

    @pytest.mark.asyncio
    async def test_ordered_protocols(self, failover):
        """get_ordered_protocols returns priority-sorted list."""
        ordered = await failover.get_ordered_protocols()
        assert ordered == ["https", "dns", "mqtt"]


# ── Failover on consecutive failures ──────────────────────────────────────

class TestFailover:
    @pytest.mark.asyncio
    async def test_failover_after_threshold(self, failover):
        """After max_consecutive_failures, active protocol switches."""
        assert await failover.current_protocol() == "https"

        # Record 3 failures on https
        for _ in range(3):
            await failover.record_failure("https", reason="timeout")

        # Should have failed over to dns
        assert await failover.current_protocol() == "dns"

    @pytest.mark.asyncio
    async def test_no_failover_below_threshold(self, failover):
        """Failures below threshold don't trigger failover."""
        assert await failover.current_protocol() == "https"
        await failover.record_failure("https")
        await failover.record_failure("https")
        assert await failover.current_protocol() == "https"

    @pytest.mark.asyncio
    async def test_failover_to_next_best(self, failover):
        """Failover picks the next highest-priority healthy protocol."""
        await failover.record_failure("https")
        await failover.record_failure("https")
        await failover.record_failure("https")
        assert await failover.current_protocol() == "dns"

        # Now fail dns too
        await failover.record_failure("dns")
        await failover.record_failure("dns")
        await failover.record_failure("dns")
        assert await failover.current_protocol() == "mqtt"

    @pytest.mark.asyncio
    async def test_all_down_returns_none(self, failover):
        """All protocols down → current_protocol returns None."""
        for proto in ("https", "dns", "mqtt"):
            for _ in range(3):
                await failover.record_failure(proto)
        assert await failover.current_protocol() is None


# ── Failback on recovery ──────────────────────────────────────────────────

class TestFailback:
    @pytest.mark.asyncio
    async def test_failback_to_higher_priority(self, failover):
        """Recovered higher-priority protocol triggers failback."""
        # Failover to dns
        for _ in range(3):
            await failover.record_failure("https")
        assert await failover.current_protocol() == "dns"

        # Wait for cooldown
        await asyncio.sleep(0.15)

        # https recovers
        await failover.record_success("https")
        assert await failover.current_protocol() == "https"

    @pytest.mark.asyncio
    async def test_failback_respects_cooldown(self, failover):
        """Failback is skipped if cooldown hasn't elapsed."""
        # Failover to dns
        for _ in range(3):
            await failover.record_failure("https")
        assert await failover.current_protocol() == "dns"

        # Immediate recovery attempt (within cooldown)
        await failover.record_success("https")
        # Should still be on dns due to cooldown
        assert await failover.current_protocol() == "dns"

    @pytest.mark.asyncio
    async def test_no_failback_to_lower_priority(self, failover):
        """Recovered lower-priority protocol doesn't steal active."""
        # Start on dns (https is down)
        for _ in range(3):
            await failover.record_failure("https")
        assert await failover.current_protocol() == "dns"

        # mqtt recovers (lower priority than dns)
        await failover.record_success("mqtt")
        assert await failover.current_protocol() == "dns"


# ── Manual failover ───────────────────────────────────────────────────────

class TestManualFailover:
    @pytest.mark.asyncio
    async def test_force_failover_success(self, failover):
        """force_failover to a healthy protocol succeeds."""
        result = await failover.force_failover("dns", reason="operator")
        assert result is True
        assert await failover.current_protocol() == "dns"

    @pytest.mark.asyncio
    async def test_force_failover_to_down_protocol_fails(self, failover):
        """force_failover to a down protocol fails."""
        for _ in range(3):
            await failover.record_failure("dns")
        result = await failover.force_failover("dns", reason="operator")
        assert result is False

    @pytest.mark.asyncio
    async def test_force_failover_unknown_protocol(self, failover):
        """force_failover to unknown protocol fails."""
        result = await failover.force_failover("gopher", reason="operator")
        assert result is False


# ── Unknown protocol handling ─────────────────────────────────────────────

class TestUnknownProtocol:
    @pytest.mark.asyncio
    async def test_record_success_unknown_ignored(self, failover):
        """record_success on unknown protocol logs warning, doesn't crash."""
        await failover.record_success("gopher")  # should not raise

    @pytest.mark.asyncio
    async def test_record_failure_unknown_ignored(self, failover):
        """record_failure on unknown protocol logs warning, doesn't crash."""
        await failover.record_failure("gopher")  # should not raise


# ── Status reporting ──────────────────────────────────────────────────────

class TestStatus:
    def test_status_structure(self, failover):
        """status() returns expected structure."""
        status = failover.status()
        assert "active_protocol" in status
        assert "active_since" in status
        assert "protocols" in status
        assert "https" in status["protocols"]
        assert "dns" in status["protocols"]
        assert "mqtt" in status["protocols"]
        assert status["protocols"]["https"]["is_up"] is True
        assert status["protocols"]["https"]["priority"] == 10

    @pytest.mark.asyncio
    async def test_status_after_failover(self, failover):
        """status() reflects active protocol after failover."""
        # Establish https as active first
        assert await failover.current_protocol() == "https"
        for _ in range(3):
            await failover.record_failure("https")
        status = failover.status()
        assert status["active_protocol"] == "dns"
        assert status["protocols"]["https"]["is_up"] is False
        assert status["protocols"]["https"]["consecutive_failures"] == 3


# ── Health loop ───────────────────────────────────────────────────────────

class TestHealthLoop:
    @pytest.mark.asyncio
    async def test_health_loop_probes_down_protocols(self, failover):
        """Health loop calls _probe_protocol on down protocols."""
        # Take https down
        for _ in range(3):
            await failover.record_failure("https")
        assert failover._protocols["https"].is_up is False

        # Mock _probe_protocol to return True (recovered)
        with patch.object(failover, "_probe_protocol", return_value=True):
            await failover._probe_all()

        # https should be back up
        assert failover._protocols["https"].is_up is True

    @pytest.mark.asyncio
    async def test_health_loop_stops(self, failover):
        """stop() signals the health loop to exit."""
        task = asyncio.create_task(failover.run_health_loop())
        failover.stop()
        await asyncio.sleep(0.1)
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass


# ── Factory function ──────────────────────────────────────────────────────

class TestFactory:
    def test_create_failover_manager(self, multi_protocol_config):
        """create_failover_manager returns a configured ProtocolFailover."""
        fo = create_failover_manager(
            multi_protocol_config,
            max_consecutive_failures=5,
            health_check_interval=60.0,
            failback_cooldown=120.0,
        )
        assert isinstance(fo, ProtocolFailover)
        assert fo._max_failures == 5
        assert fo._health_interval == 60.0
        assert fo._failback_cooldown == 120.0
