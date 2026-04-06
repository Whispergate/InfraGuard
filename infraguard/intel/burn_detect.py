"""Burn detection watchdog.

Monitors request patterns for indicators that the redirector's domain
or IP has been identified ("burned") by blue team or security vendors.

Burn indicators:
  - Spike in blocked requests from security vendor IP ranges
  - Requests matching known sandbox/analysis User-Agents
  - Rapid sequential probing from multiple security vendor ASNs
  - Requests to paths that only scanners would know about

When burn is detected, the watchdog:
  1. Emits a structured log event at CRITICAL level
  2. Records the burn event for plugin forwarding (Discord/Slack alerts)
  3. Optionally triggers a cooldown (stop accepting C2 traffic temporarily)
"""

from __future__ import annotations

import asyncio
import time
from collections import deque
from dataclasses import dataclass, field

import structlog

log = structlog.get_logger()


@dataclass
class BurnIndicator:
    """A single burn detection signal."""

    indicator_type: str  # "vendor_spike", "scanner_probe", "multi_asn_probe"
    description: str
    severity: str  # "warning", "critical"
    timestamp: float = field(default_factory=time.time)


@dataclass
class BurnConfig:
    """Configuration for the burn detection watchdog."""

    enabled: bool = False
    check_interval_seconds: int = 60
    # Thresholds
    vendor_spike_threshold: int = 10  # blocked reqs from vendor IPs per window
    vendor_spike_window_seconds: int = 300  # 5 min window
    multi_asn_probe_threshold: int = 3  # unique security ASNs probing per window
    multi_asn_window_seconds: int = 600  # 10 min window
    # Actions
    cooldown_on_burn: bool = False
    cooldown_duration_seconds: int = 300


class BurnDetector:
    """Monitors request patterns for burn indicators."""

    def __init__(self, config: BurnConfig | None = None):
        self.config = config or BurnConfig()
        self._vendor_blocked: deque[float] = deque()
        self._probe_asns: deque[tuple[float, int]] = deque()
        self._burn_events: list[BurnIndicator] = []
        self._cooldown_until: float = 0.0
        self._task: asyncio.Task | None = None

    @property
    def is_burned(self) -> bool:
        """True if any active burn indicators exist."""
        return len(self._burn_events) > 0

    @property
    def in_cooldown(self) -> bool:
        """True if cooldown is active (C2 traffic should be paused)."""
        return time.time() < self._cooldown_until

    def record_vendor_block(self, timestamp: float | None = None) -> None:
        """Record a blocked request from a known security vendor IP."""
        self._vendor_blocked.append(timestamp or time.time())

    def record_probe_asn(self, asn: int, timestamp: float | None = None) -> None:
        """Record a probe from a security-related ASN."""
        self._probe_asns.append((timestamp or time.time(), asn))

    def check(self) -> list[BurnIndicator]:
        """Run all burn detection checks. Returns new indicators found."""
        now = time.time()
        new_indicators: list[BurnIndicator] = []

        # Check 1: Vendor IP spike
        cutoff = now - self.config.vendor_spike_window_seconds
        while self._vendor_blocked and self._vendor_blocked[0] < cutoff:
            self._vendor_blocked.popleft()

        if len(self._vendor_blocked) >= self.config.vendor_spike_threshold:
            indicator = BurnIndicator(
                indicator_type="vendor_spike",
                description=(
                    f"{len(self._vendor_blocked)} blocked vendor requests in "
                    f"{self.config.vendor_spike_window_seconds}s window"
                ),
                severity="critical",
            )
            new_indicators.append(indicator)
            log.critical(
                "burn_detected",
                type="vendor_spike",
                blocked_count=len(self._vendor_blocked),
                window_seconds=self.config.vendor_spike_window_seconds,
            )

        # Check 2: Multi-ASN probing
        asn_cutoff = now - self.config.multi_asn_window_seconds
        while self._probe_asns and self._probe_asns[0][0] < asn_cutoff:
            self._probe_asns.popleft()

        unique_asns = {asn for _, asn in self._probe_asns}
        if len(unique_asns) >= self.config.multi_asn_probe_threshold:
            indicator = BurnIndicator(
                indicator_type="multi_asn_probe",
                description=(
                    f"{len(unique_asns)} unique security ASNs probing in "
                    f"{self.config.multi_asn_window_seconds}s window: "
                    f"{sorted(unique_asns)}"
                ),
                severity="critical",
            )
            new_indicators.append(indicator)
            log.critical(
                "burn_detected",
                type="multi_asn_probe",
                unique_asns=sorted(unique_asns),
                window_seconds=self.config.multi_asn_window_seconds,
            )

        # Trigger cooldown if configured
        if new_indicators and self.config.cooldown_on_burn:
            self._cooldown_until = now + self.config.cooldown_duration_seconds
            log.warning(
                "burn_cooldown_activated",
                duration_seconds=self.config.cooldown_duration_seconds,
            )

        self._burn_events.extend(new_indicators)
        return new_indicators

    def get_status(self) -> dict:
        """Return current burn detection status for API/dashboard."""
        return {
            "is_burned": self.is_burned,
            "in_cooldown": self.in_cooldown,
            "cooldown_remaining_seconds": max(0, self._cooldown_until - time.time()),
            "active_indicators": len(self._burn_events),
            "vendor_blocked_window": len(self._vendor_blocked),
            "probe_asns_window": len({asn for _, asn in self._probe_asns}),
        }

    def clear(self) -> None:
        """Clear all burn indicators (operator acknowledges and resets)."""
        self._burn_events.clear()
        self._cooldown_until = 0.0
        log.info("burn_indicators_cleared")

    async def watch_loop(self) -> None:
        """Background task that periodically runs burn detection checks."""
        while True:
            try:
                self.check()
            except Exception:
                log.exception("burn_check_error")
            await asyncio.sleep(self.config.check_interval_seconds)

    def start(self) -> None:
        """Start the background watchdog task."""
        if self.config.enabled:
            self._task = asyncio.create_task(self.watch_loop())
            log.info(
                "burn_detector_started",
                interval=self.config.check_interval_seconds,
            )

    async def stop(self) -> None:
        """Stop the background watchdog task."""
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
