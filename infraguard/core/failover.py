"""Multi-protocol C2 failover and failback management.

Monitors the health of every configured listener protocol and provides
automatic failover to the next available protocol when the current one
fails.  When a higher-priority protocol recovers, automatic failback
restores it.

Protocol priority (highest first):
    HTTPS -> DNS -> MQTT -> WebSocket -> TCP tunnel

Health is tracked per-protocol as a rolling count of consecutive
failures.  Once a protocol accumulates ``max_consecutive_failures``
failures, it is marked *down* and the manager promotes the next healthy
protocol.  A periodic health-check loop re-probes down protocols so
they can be restored when they recover.

Metrics:
    infraguard_failover_events_total{from_protocol, to_protocol, reason}
    infraguard_protocol_health{protocol}  (0=down, 1=up)
    infraguard_active_protocol{protocol}  (1 = currently selected)

Logging:
    All failover/failback events are logged at ``warning`` / ``info``
    level via structlog with structured fields.
"""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass, field
from enum import IntEnum
from typing import TYPE_CHECKING

import structlog

if TYPE_CHECKING:
    from infraguard.config.schema import InfraGuardConfig, ListenerConfig

log = structlog.get_logger()

# ---------------------------------------------------------------------------
# Prometheus metrics (mirrors the pattern in infraguard.ui.api.metrics)
# ---------------------------------------------------------------------------
try:
    from prometheus_client import Counter, Gauge

    FAILOVER_EVENTS_TOTAL = Counter(
        "infraguard_failover_events_total",
        "Total failover/failback events",
        ["from_protocol", "to_protocol", "reason"],
    )
    PROTOCOL_HEALTH = Gauge(
        "infraguard_protocol_health",
        "Protocol health status (0=down, 1=up)",
        ["protocol"],
    )
    ACTIVE_PROTOCOL = Gauge(
        "infraguard_active_protocol",
        "Currently selected protocol (1=active)",
        ["protocol"],
    )
    _HAS_PROMETHEUS = True
except ImportError:
    _HAS_PROMETHEUS = False


# ---------------------------------------------------------------------------
# Protocol priority
# ---------------------------------------------------------------------------

class ProtocolPriority(IntEnum):
    """Explicit priority ordering - lower value = higher priority."""

    HTTPS = 10
    DNS = 20
    MQTT = 30
    WEBSOCKET = 40
    TCP_TUNNEL = 50


# Map config protocol strings to our priority enum
_PROTOCOL_MAP: dict[str, ProtocolPriority] = {
    "https": ProtocolPriority.HTTPS,
    "http": ProtocolPriority.HTTPS,       # plain HTTP is treated as HTTPS priority
    "dns": ProtocolPriority.DNS,
    "mqtt": ProtocolPriority.MQTT,
    "websocket": ProtocolPriority.WEBSOCKET,
    "tcp_tunnel": ProtocolPriority.TCP_TUNNEL,
}


def _priority_for(protocol: str) -> ProtocolPriority:
    """Return the priority enum for a protocol string.

    Unknown protocols sort to the bottom (highest int value).
    """
    return _PROTOCOL_MAP.get(protocol, ProtocolPriority.TCP_TUNNEL + 10)


# ---------------------------------------------------------------------------
# Per-protocol health state
# ---------------------------------------------------------------------------

@dataclass
class ProtocolHealth:
    """Mutable health state for a single protocol."""

    protocol: str
    priority: ProtocolPriority
    consecutive_failures: int = 0
    is_up: bool = True
    last_failure_at: float | None = None
    last_success_at: float | None = None
    total_failures: int = 0
    total_successes: int = 0
    metadata: dict[str, object] = field(default_factory=dict)

    def record_success(self) -> None:
        self.consecutive_failures = 0
        self.is_up = True
        self.last_success_at = time.monotonic()
        self.total_successes += 1

    def record_failure(self, threshold: int = 1) -> None:
        """Record a failure. ``is_up`` flips only when *threshold* is reached."""
        self.consecutive_failures += 1
        if self.consecutive_failures >= threshold:
            self.is_up = False
        self.last_failure_at = time.monotonic()
        self.total_failures += 1


# ---------------------------------------------------------------------------
# Failover manager
# ---------------------------------------------------------------------------

class ProtocolFailover:
    """Manages multi-protocol C2 failover and failback.

    The manager is *listener-agnostic*: it only knows about protocol names
    and their priorities.  Callers feed it health-check results via
    :meth:`record_success` / :meth:`record_failure`, and query the current
    best protocol via :meth:`current_protocol` or :meth:`get_ordered_protocols`.

    A background task (:meth:`run_health_loop`) periodically re-probes
    down protocols to detect recovery (failback).

    Args:
        config: InfraGuard configuration containing listener definitions.
        max_consecutive_failures: How many consecutive failures mark a protocol down.
        health_check_interval: Seconds between periodic health-check probes.
        failback_cooldown: Seconds a protocol must be stable (up) before
            failback is allowed.  Prevents flapping.
    """

    def __init__(
        self,
        config: InfraGuardConfig,
        max_consecutive_failures: int = 3,
        health_check_interval: float = 30.0,
        failback_cooldown: float = 60.0,
    ):
        self._config = config
        self._max_failures = max_consecutive_failures
        self._health_interval = health_check_interval
        self._failback_cooldown = failback_cooldown

        # Build health state for every configured listener protocol
        self._protocols: dict[str, ProtocolHealth] = {}
        for listener in config.listeners:
            proto = listener.protocol
            if proto in self._protocols:
                # Multiple listeners on the same protocol - keep first config
                continue
            self._protocols[proto] = ProtocolHealth(
                protocol=proto,
                priority=_priority_for(proto),
            )

        # Currently selected protocol
        self._active: str | None = None
        self._active_since: float | None = None
        self._lock = asyncio.Lock()
        self._stop_event = asyncio.Event()

        # Initialize metrics
        if _HAS_PROMETHEUS:
            for ph in self._protocols.values():
                PROTOCOL_HEALTH.labels(protocol=ph.protocol).set(1)
                ACTIVE_PROTOCOL.labels(protocol=ph.protocol).set(0)
            self._update_active_metric()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    @property
    def protocols(self) -> dict[str, ProtocolHealth]:
        """Read-only view of all protocol health states."""
        return dict(self._protocols)

    async def current_protocol(self) -> str | None:
        """Return the currently selected protocol, or ``None`` if none are healthy."""
        async with self._lock:
            if self._active is not None and self._protocols[self._active].is_up:
                return self._active
            # Re-evaluate in case the active protocol went down without an explicit failover
            return self._select_best()

    async def get_ordered_protocols(self) -> list[str]:
        """Return all protocols sorted by priority (highest first)."""
        return [
            p.protocol
            for p in sorted(self._protocols.values(), key=lambda x: x.priority)
        ]

    async def record_success(self, protocol: str) -> None:
        """Record a successful health check / operation for a protocol.

        If this protocol was previously down and is a higher priority than
        the currently active one, automatic failback is triggered.  Also
        triggers failback evaluation when the protocol is already up but
        outranks the current selection.
        """
        async with self._lock:
            if protocol not in self._protocols:
                log.warning("failover_unknown_protocol", protocol=protocol)
                return

            ph = self._protocols[protocol]
            was_down = not ph.is_up
            ph.record_success()
            self._set_health_metric(protocol, up=True)

            if was_down:
                log.info(
                    "protocol_recovered",
                    protocol=protocol,
                    total_successes=ph.total_successes,
                )

            # Evaluate failback: either the protocol just recovered, or it's
            # already up and outranks the current selection (e.g. after a
            # force_failover to a lower-priority protocol).
            if self._active is not None and protocol != self._active:
                await self._maybe_failback(protocol)
            elif self._active is None:
                await self._maybe_failback(protocol)

    async def record_failure(self, protocol: str, reason: str = "") -> None:
        """Record a failed health check / operation for a protocol.

        If the failure count reaches ``max_consecutive_failures``, the
        protocol is marked down and automatic failover is triggered.
        """
        async with self._lock:
            if protocol not in self._protocols:
                log.warning("failover_unknown_protocol", protocol=protocol)
                return

            ph = self._protocols[protocol]
            ph.record_failure(threshold=self._max_failures)
            self._set_health_metric(protocol, up=ph.is_up)

            if ph.consecutive_failures >= self._max_failures and self._active == protocol:
                log.warning(
                    "protocol_down",
                    protocol=protocol,
                    consecutive_failures=ph.consecutive_failures,
                    reason=reason,
                )
                await self._failover(reason=reason or "consecutive_failures")

    async def force_failover(self, to_protocol: str, reason: str = "manual") -> bool:
        """Manually force a failover to a specific protocol.

        Returns ``True`` if the switch was made.
        """
        async with self._lock:
            if to_protocol not in self._protocols:
                log.warning("failover_unknown_protocol", protocol=to_protocol)
                return False
            if not self._protocols[to_protocol].is_up:
                log.warning(
                    "failover_target_down",
                    from_protocol=self._active,
                    to_protocol=to_protocol,
                )
                return False

            old = self._active
            self._active = to_protocol
            self._active_since = time.monotonic()
            self._update_active_metric()
            self._emit_event(old, to_protocol, reason)
            return True

    async def run_health_loop(self) -> None:
        """Background loop that periodically re-probes down protocols.

        This loop does NOT perform the health checks itself - it merely
        marks down protocols as eligible for re-check by calling
        :meth:`_probe_protocol`.  Subclasses or integrators should override
        :meth:`_probe_protocol` with a real implementation (e.g. TCP dial,
        DNS query, HTTP GET).

        The loop exits when :meth:`stop` is called.
        """
        log.info(
            "failover_health_loop_started",
            interval=self._health_interval,
            protocols=list(self._protocols.keys()),
        )
        try:
            while not self._stop_event.is_set():
                await asyncio.sleep(self._health_interval)
                if self._stop_event.is_set():
                    break
                await self._probe_all()
        finally:
            log.info("failover_health_loop_stopped")

    def stop(self) -> None:
        """Signal the health-check loop to exit."""
        self._stop_event.set()

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _select_best(self) -> str | None:
        """Choose the highest-priority protocol that is currently up.

        Updates ``self._active`` but does NOT emit events — callers are
        responsible for that.  Caller must hold ``self._lock``.
        """
        candidates = sorted(
            (p for p in self._protocols.values() if p.is_up),
            key=lambda x: x.priority,
        )
        if not candidates:
            self._active = None
            self._active_since = None
            self._update_active_metric()
            return None

        best = candidates[0].protocol
        if best != self._active:
            self._active = best
            self._active_since = time.monotonic()
            self._update_active_metric()
        return self._active

    async def _failover(self, reason: str) -> None:
        """Switch to the next best protocol.

        Caller must hold ``self._lock``.
        """
        old = self._active
        self._select_best()  # picks the highest-priority healthy protocol
        if self._active != old and self._active is not None:
            self._emit_event(old, self._active, reason)
        elif self._active is None:
            log.error("failover_no_healthy_protocols", from_protocol=old)

    async def _maybe_failback(self, recovered_protocol: str) -> None:
        """Fail back to a recovered protocol if it outranks the current one.

        Caller must hold ``self._lock``.
        """
        if self._active is None:
            self._active = recovered_protocol
            self._active_since = time.monotonic()
            self._update_active_metric()
            self._emit_event(None, recovered_protocol, "failback_initial")
            return

        recovered = self._protocols[recovered_protocol]
        current = self._protocols[self._active]

        # Only fail back if the recovered protocol is strictly higher priority
        if recovered.priority >= current.priority:
            return

        # Cooldown check: don't flap
        if (
            self._active_since is not None
            and (time.monotonic() - self._active_since) < self._failback_cooldown
        ):
            log.info(
                "failback_cooldown_skip",
                recovered=recovered_protocol,
                current=self._active,
                cooldown_remaining=self._failback_cooldown
                - (time.monotonic() - self._active_since),
            )
            return

        old = self._active
        self._active = recovered_protocol
        self._active_since = time.monotonic()
        self._update_active_metric()
        self._emit_event(old, recovered_protocol, "failback")

    async def _probe_all(self) -> None:
        """Re-probe all down protocols to detect recovery.

        Caller does NOT need to hold the lock; this method acquires it
        internally for each probe.
        """
        down = [
            p.protocol
            for p in self._protocols.values()
            if not p.is_up
        ]
        if not down:
            return

        for proto in down:
            try:
                healthy = await self._probe_protocol(proto)
                if healthy:
                    await self.record_success(proto)
                else:
                    # Just increment failure count; don't spam failover
                    # while we're already on a fallback.
                    async with self._lock:
                        self._protocols[proto].consecutive_failures += 1
            except Exception:
                log.exception("failover_probe_error", protocol=proto)

    async def _probe_protocol(self, protocol: str) -> bool:
        """Perform a lightweight health check for a protocol.

        Override this method in a subclass to implement real probes
        (e.g. TCP dial to the listener port, DNS query, HTTP GET).

        Default implementation returns ``True`` if the protocol has been
        down for longer than ``health_check_interval`` (optimistic
        recovery).
        """
        ph = self._protocols.get(protocol)
        if ph is None or ph.is_up:
            return True
        # Optimistic probe: assume it might be back after one interval
        elapsed = time.monotonic() - (ph.last_failure_at or 0)
        return elapsed >= self._health_interval

    # ------------------------------------------------------------------
    # Metrics helpers
    # ------------------------------------------------------------------

    def _set_health_metric(self, protocol: str, up: bool) -> None:
        if _HAS_PROMETHEUS:
            PROTOCOL_HEALTH.labels(protocol=protocol).set(1 if up else 0)

    def _update_active_metric(self) -> None:
        if not _HAS_PROMETHEUS:
            return
        for proto in self._protocols:
            ACTIVE_PROTOCOL.labels(protocol=proto).set(0)
        if self._active:
            ACTIVE_PROTOCOL.labels(protocol=self._active).set(1)

    def _emit_event(
        self,
        from_protocol: str | None,
        to_protocol: str,
        reason: str,
    ) -> None:
        """Log and record a failover/failback event."""
        from_p = from_protocol or "none"
        log.warning(
            "failover_event",
            from_protocol=from_p,
            to_protocol=to_protocol,
            reason=reason,
            active_since=self._active_since,
        )
        if _HAS_PROMETHEUS:
            FAILOVER_EVENTS_TOTAL.labels(
                from_protocol=from_p,
                to_protocol=to_protocol,
                reason=reason,
            ).inc()

    # ------------------------------------------------------------------
    # Status / introspection
    # ------------------------------------------------------------------

    def status(self) -> dict[str, object]:
        """Return a JSON-serialisable status snapshot."""
        return {
            "active_protocol": self._active,
            "active_since": self._active_since,
            "protocols": {
                p.protocol: {
                    "priority": int(p.priority),
                    "is_up": p.is_up,
                    "consecutive_failures": p.consecutive_failures,
                    "total_failures": p.total_failures,
                    "total_successes": p.total_successes,
                    "last_failure_at": p.last_failure_at,
                    "last_success_at": p.last_success_at,
                }
                for p in sorted(self._protocols.values(), key=lambda x: x.priority)
            },
        }


# ---------------------------------------------------------------------------
# Convenience factory
# ---------------------------------------------------------------------------

def create_failover_manager(
    config: InfraGuardConfig,
    max_consecutive_failures: int = 3,
    health_check_interval: float = 30.0,
    failback_cooldown: float = 60.0,
) -> ProtocolFailover:
    """Create a :class:`ProtocolFailover` pre-populated from config.

    The manager starts with no protocol selected.  Call
    :meth:`ProtocolFailover.record_success` on the initial protocol you
    want to use, or let the first health-check cycle select the best one.
    """
    return ProtocolFailover(
        config,
        max_consecutive_failures=max_consecutive_failures,
        health_check_interval=health_check_interval,
        failback_cooldown=failback_cooldown,
    )
