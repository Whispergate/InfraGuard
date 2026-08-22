"""Tests for burn detection (BurnDetector / BurnConfig)."""

from __future__ import annotations

import asyncio
import time
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from infraguard.intel.burn_detect import (
    BurnConfig,
    BurnDetector,
    BurnIndicator,
    _MAX_BURN_EVENTS,
)


# ── BurnConfig / BurnIndicator dataclasses ────────────────────────────────

class TestBurnConfig:
    def test_defaults(self):
        cfg = BurnConfig()
        assert cfg.enabled is False
        assert cfg.check_interval_seconds == 60
        assert cfg.vendor_spike_threshold == 10
        assert cfg.multi_asn_probe_threshold == 3
        assert cfg.cooldown_on_burn is False

    def test_custom_values(self):
        cfg = BurnConfig(
            enabled=True,
            vendor_spike_threshold=5,
            cooldown_on_burn=True,
            cooldown_duration_seconds=600,
        )
        assert cfg.enabled is True
        assert cfg.vendor_spike_threshold == 5
        assert cfg.cooldown_on_burn is True
        assert cfg.cooldown_duration_seconds == 600


class TestBurnIndicator:
    def test_indicator_fields(self):
        ind = BurnIndicator(
            indicator_type="vendor_spike",
            description="test",
            severity="critical",
        )
        assert ind.indicator_type == "vendor_spike"
        assert ind.severity == "critical"
        assert ind.timestamp > 0


# ── Vendor spike detection ────────────────────────────────────────────────

class TestVendorSpikeDetection:
    def test_no_spike_under_threshold(self):
        """Fewer than threshold vendor blocks → no indicator."""
        detector = BurnDetector(BurnConfig(vendor_spike_threshold=5))
        for _ in range(4):
            detector.record_vendor_block()
        indicators = detector.check()
        assert len(indicators) == 0
        assert detector.is_burned is False

    def test_spike_at_threshold_triggers_indicator(self):
        """Exactly threshold vendor blocks → vendor_spike indicator."""
        detector = BurnDetector(BurnConfig(vendor_spike_threshold=5))
        for _ in range(5):
            detector.record_vendor_block()
        indicators = detector.check()
        assert len(indicators) == 1
        assert indicators[0].indicator_type == "vendor_spike"
        assert indicators[0].severity == "critical"
        assert detector.is_burned is True

    def test_spike_window_expiry(self):
        """Old vendor blocks outside the window don't count."""
        detector = BurnDetector(
            BurnConfig(vendor_spike_threshold=3, vendor_spike_window_seconds=60)
        )
        # Record old blocks (outside window)
        old_time = time.time() - 120
        for _ in range(5):
            detector.record_vendor_block(timestamp=old_time)
        # Record new blocks (inside window)
        for _ in range(2):
            detector.record_vendor_block()
        indicators = detector.check()
        assert len(indicators) == 0

    def test_spike_clears_queue_after_trigger(self):
        """After triggering, the vendor blocked queue is cleared."""
        detector = BurnDetector(BurnConfig(vendor_spike_threshold=3))
        for _ in range(3):
            detector.record_vendor_block()
        detector.check()
        assert len(detector._vendor_blocked) == 0


# ── Multi-ASN probe detection ─────────────────────────────────────────────

class TestMultiASNProbe:
    def test_no_probe_under_threshold(self):
        """Fewer than threshold unique ASNs → no indicator."""
        detector = BurnDetector(BurnConfig(multi_asn_probe_threshold=3))
        detector.record_probe_asn(13335)   # Cloudflare
        detector.record_probe_asn(13335)   # same ASN again
        indicators = detector.check()
        assert len(indicators) == 0

    def test_probe_at_threshold_triggers(self):
        """Exactly threshold unique ASNs → multi_asn_probe indicator."""
        detector = BurnDetector(BurnConfig(multi_asn_probe_threshold=3))
        detector.record_probe_asn(13335)
        detector.record_probe_asn(15169)   # Google
        detector.record_probe_asn(8075)    # Microsoft
        indicators = detector.check()
        assert len(indicators) == 1
        assert indicators[0].indicator_type == "multi_asn_probe"
        assert "13335" in indicators[0].description

    def test_probe_window_expiry(self):
        """Old probes outside the window don't count."""
        detector = BurnDetector(
            BurnConfig(multi_asn_probe_threshold=2, multi_asn_window_seconds=60)
        )
        old_time = time.time() - 120
        detector.record_probe_asn(13335, timestamp=old_time)
        detector.record_probe_asn(15169, timestamp=old_time)
        indicators = detector.check()
        assert len(indicators) == 0


# ── Cooldown ──────────────────────────────────────────────────────────────

class TestCooldown:
    def test_cooldown_activated_on_burn(self):
        """Cooldown is triggered when cooldown_on_burn=True."""
        detector = BurnDetector(
            BurnConfig(
                vendor_spike_threshold=2,
                cooldown_on_burn=True,
                cooldown_duration_seconds=300,
            )
        )
        for _ in range(2):
            detector.record_vendor_block()
        detector.check()
        assert detector.in_cooldown is True

    def test_cooldown_not_activated_when_disabled(self):
        """No cooldown when cooldown_on_burn=False."""
        detector = BurnDetector(
            BurnConfig(vendor_spike_threshold=2, cooldown_on_burn=False)
        )
        for _ in range(2):
            detector.record_vendor_block()
        detector.check()
        assert detector.in_cooldown is False

    def test_cooldown_expires(self):
        """Cooldown expires after duration."""
        detector = BurnDetector(
            BurnConfig(
                vendor_spike_threshold=2,
                cooldown_on_burn=True,
                cooldown_duration_seconds=0,
            )
        )
        for _ in range(2):
            detector.record_vendor_block()
        detector.check()
        # With duration=0, cooldown should already be expired
        assert detector.in_cooldown is False


# ── Status and clear ──────────────────────────────────────────────────────

class TestStatusAndClear:
    def test_get_status(self):
        """get_status returns expected keys."""
        detector = BurnDetector(BurnConfig())
        status = detector.get_status()
        assert "is_burned" in status
        assert "in_cooldown" in status
        assert "cooldown_remaining_seconds" in status
        assert "active_indicators" in status
        assert "vendor_blocked_window" in status
        assert "probe_asns_window" in status

    def test_clear_resets_state(self):
        """clear() resets all burn indicators and cooldown."""
        detector = BurnDetector(
            BurnConfig(vendor_spike_threshold=2, cooldown_on_burn=True)
        )
        for _ in range(2):
            detector.record_vendor_block()
        detector.check()
        assert detector.is_burned is True
        detector.clear()
        assert detector.is_burned is False
        assert detector.in_cooldown is False


# ── Cross-domain analyst detection ────────────────────────────────────────

class TestCrossDomainAnalyst:
    @pytest.mark.asyncio
    async def test_cross_domain_no_db_returns_empty(self):
        """No database → no cross-domain indicators."""
        detector = BurnDetector(BurnConfig())
        indicators = await detector.cross_domain_check()
        assert indicators == []

    @pytest.mark.asyncio
    async def test_cross_domain_analyst_detected(self):
        """IP accessing multiple domains → cross_domain_analyst indicator."""
        mock_db = AsyncMock()
        mock_db.fetchall.return_value = [
            {"client_ip": "1.2.3.4", "domain_count": 5},
        ]
        detector = BurnDetector(
            BurnConfig(analyst_domain_threshold=3),
            db=mock_db,
        )
        indicators = await detector.cross_domain_check()
        assert len(indicators) == 1
        assert indicators[0].indicator_type == "cross_domain_analyst"
        assert "1.2.3.4" in indicators[0].description

    @pytest.mark.asyncio
    async def test_cross_domain_db_error_returns_empty(self):
        """Database error → graceful empty result."""
        mock_db = AsyncMock()
        mock_db.fetchall.side_effect = Exception("db error")
        detector = BurnDetector(BurnConfig(), db=mock_db)
        indicators = await detector.cross_domain_check()
        assert indicators == []


# ── Burn event cap ────────────────────────────────────────────────────────

class TestBurnEventCap:
    def test_events_capped_at_max(self):
        """Burn events list is capped at _MAX_BURN_EVENTS."""
        detector = BurnDetector(BurnConfig(vendor_spike_threshold=1))
        for _ in range(_MAX_BURN_EVENTS + 10):
            detector.record_vendor_block()
            detector.check()
        assert len(detector._burn_events) <= _MAX_BURN_EVENTS


# ── Watch loop lifecycle ──────────────────────────────────────────────────

class TestWatchLoop:
    @pytest.mark.asyncio
    async def test_start_creates_task_when_enabled(self):
        """start() creates an asyncio task when enabled=True."""
        detector = BurnDetector(BurnConfig(enabled=True, check_interval_seconds=9999))
        detector.start()
        assert detector._task is not None
        assert not detector._task.done()
        await detector.stop()

    @pytest.mark.asyncio
    async def test_start_noop_when_disabled(self):
        """start() does nothing when enabled=False."""
        detector = BurnDetector(BurnConfig(enabled=False))
        detector.start()
        assert detector._task is None

    @pytest.mark.asyncio
    async def test_stop_cancels_task(self):
        """stop() cancels the background task."""
        detector = BurnDetector(BurnConfig(enabled=True, check_interval_seconds=9999))
        detector.start()
        await detector.stop()
        assert detector._task.cancelled() or detector._task.done()
