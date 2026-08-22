"""Burn confidence scoring engine.

Aggregates multiple detection signals into a per-domain confidence score (0-100)
that indicates how likely it is that a domain has been identified ("burned")
by blue team or security vendors.

Signals evaluated:
  - JA3 changes: shift in observed TLS fingerprints (new/unknown JA3s seen)
  - Request volume spikes: sudden increase in request rate vs baseline
  - New ASN appearances: first-seen ASNs probing the domain
  - CT log entries: new certificate transparency issuances (from CTMonitor)
  - Reputation feed hits: domain listed in threat intel feeds (from DomainReputationMonitor)
  - Failed auth attempts: dashboard/API auth failures indicating probing

Recommended actions:
  - score < 50   -> "monitor"    : domain likely still clean, continue watching
  - score 50-79  -> "rotate"     : schedule domain/IP rotation, prepare replacement
  - score >= 80  -> "immediate_burn" : domain is compromised, retire immediately
"""

from __future__ import annotations

import time
from collections import deque
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

import structlog

if TYPE_CHECKING:
    from infraguard.intel.burn_detect import BurnDetector
    from infraguard.tracking.database import Database

log = structlog.get_logger()

# Signal weights (must sum to 100)
_WEIGHT_JA3_CHANGE = 20
_WEIGHT_VOLUME_SPIKE = 20
_WEIGHT_NEW_ASN = 15
_WEIGHT_CT_LOG = 20
_WEIGHT_REPUTATION_HIT = 15
_WEIGHT_FAILED_AUTH = 10

# Thresholds for recommended actions
ACTION_MONITOR = "monitor"
ACTION_ROTATE = "rotate"
ACTION_IMMEDIATE_BURN = "immediate_burn"


@dataclass
class BurnSignal:
    """A single signal contribution to the burn score."""

    signal_type: str          # "ja3_change", "volume_spike", "new_asn", "ct_log", "reputation_hit", "failed_auth"
    description: str
    weight: int               # contribution to total score
    detected_at: float = field(default_factory=time.time)


@dataclass
class BurnScore:
    """Result of a burn confidence assessment for one domain."""

    domain: str
    score: int                              # 0-100
    action: str                             # "monitor", "rotate", "immediate_burn"
    signals: list[BurnSignal] = field(default_factory=list)
    evaluated_at: float = field(default_factory=time.time)


class BurnScorer:
    """Aggregates burn signals into a per-domain confidence score.

    Works alongside BurnDetector: BurnDetector fires binary alerts on
    critical thresholds; BurnScorer provides a continuous, weighted
    assessment that operators can use to plan rotation before a hard
    burn is declared.
    """

    def __init__(
        self,
        db: "Database | None" = None,
        burn_detector: "BurnDetector | None" = None,
        # Time windows (seconds)
        ja3_window: int = 3600,
        volume_window: int = 300,
        asn_window: int = 600,
        ct_window: int = 86400,
        reputation_window: int = 86400,
        failed_auth_window: int = 3600,
        # Spike thresholds
        volume_spike_multiplier: float = 3.0,
        ja3_change_threshold: int = 2,       # unique new JA3s in window
        asn_new_threshold: int = 2,          # new ASNs in window
        failed_auth_threshold: int = 5,      # failed auth attempts in window
    ) -> None:
        self._db = db
        self._burn_detector = burn_detector

        self._ja3_window = ja3_window
        self._volume_window = volume_window
        self._asn_window = asn_window
        self._ct_window = ct_window
        self._reputation_window = reputation_window
        self._failed_auth_window = failed_auth_window

        self._volume_spike_multiplier = volume_spike_multiplier
        self._ja3_change_threshold = ja3_change_threshold
        self._asn_new_threshold = asn_new_threshold
        self._failed_auth_threshold = failed_auth_threshold

        # Per-domain rolling state
        # domain -> deque[tuple[timestamp, ja3_hash]]
        self._ja3_seen: dict[str, deque[tuple[float, str]]] = {}
        # domain -> deque[timestamp]
        self._request_times: dict[str, deque[float]] = {}
        # domain -> set[asn] (baseline ASNs seen before window)
        self._baseline_asns: dict[str, set[int]] = {}
        # domain -> deque[tuple[timestamp, asn]]
        self._recent_asns: dict[str, deque[tuple[float, int]]] = {}
        # domain -> deque[timestamp] of failed auth attempts
        self._failed_auths: dict[str, deque[float]] = {}

    # ── Signal recording API ─────────────────────────────────────────

    def record_ja3(self, domain: str, ja3_hash: str, timestamp: float | None = None) -> None:
        """Record an observed JA3 fingerprint for a domain."""
        ts = timestamp or time.time()
        if domain not in self._ja3_seen:
            self._ja3_seen[domain] = deque()
        self._ja3_seen[domain].append((ts, ja3_hash))

    def record_request(self, domain: str, timestamp: float | None = None) -> None:
        """Record a request for volume tracking."""
        ts = timestamp or time.time()
        if domain not in self._request_times:
            self._request_times[domain] = deque()
        self._request_times[domain].append(ts)

    def record_asn(self, domain: str, asn: int, timestamp: float | None = None) -> None:
        """Record an ASN observation for a domain."""
        ts = timestamp or time.time()
        if domain not in self._recent_asns:
            self._recent_asns[domain] = deque()
        self._recent_asns[domain].append((ts, asn))

    def record_failed_auth(self, domain: str, timestamp: float | None = None) -> None:
        """Record a failed authentication attempt against the domain/API."""
        ts = timestamp or time.time()
        if domain not in self._failed_auths:
            self._failed_auths[domain] = deque()
        self._failed_auths[domain].append(ts)

    def set_baseline_asns(self, domain: str, asns: set[int]) -> None:
        """Seed the baseline ASN set for a domain (e.g. from historical data)."""
        self._baseline_asns[domain] = set(asns)

    # ── Score computation ────────────────────────────────────────────

    async def compute_score(self, domain: str) -> BurnScore:
        """Compute the burn confidence score for a domain."""
        signals: list[BurnSignal] = []
        now = time.time()

        # ── 1. JA3 changes ───────────────────────────────────────────
        ja3_signal = self._check_ja3_changes(domain, now)
        if ja3_signal:
            signals.append(ja3_signal)

        # ── 2. Request volume spike ──────────────────────────────────
        volume_signal = self._check_volume_spike(domain, now)
        if volume_signal:
            signals.append(volume_signal)

        # ── 3. New ASN appearances ───────────────────────────────────
        asn_signal = self._check_new_asns(domain, now)
        if asn_signal:
            signals.append(asn_signal)

        # ── 4. CT log entries (from BurnDetector events) ─────────────
        ct_signal = self._check_ct_logs(domain, now)
        if ct_signal:
            signals.append(ct_signal)

        # ── 5. Reputation feed hits (from BurnDetector events) ───────
        rep_signal = self._check_reputation_hits(domain, now)
        if rep_signal:
            signals.append(rep_signal)

        # ── 6. Failed auth attempts ──────────────────────────────────
        auth_signal = self._check_failed_auths(domain, now)
        if auth_signal:
            signals.append(auth_signal)

        # Aggregate
        total = sum(s.weight for s in signals)
        score = min(100, total)

        if score >= 80:
            action = ACTION_IMMEDIATE_BURN
        elif score >= 50:
            action = ACTION_ROTATE
        else:
            action = ACTION_MONITOR

        result = BurnScore(
            domain=domain,
            score=score,
            action=action,
            signals=signals,
        )

        log.info(
            "burn_score_evaluated",
            domain=domain,
            score=score,
            action=action,
            signal_count=len(signals),
        )
        return result

    async def compute_all_scores(self, domains: list[str]) -> dict[str, BurnScore]:
        """Compute burn scores for a list of domains."""
        results: dict[str, BurnScore] = {}
        for d in domains:
            results[d] = await self.compute_score(d)
        return results

    # ── Signal check internals ───────────────────────────────────────

    def _check_ja3_changes(self, domain: str, now: float) -> BurnSignal | None:
        """Detect shift in JA3 fingerprint population."""
        dq = self._ja3_seen.get(domain)
        if not dq:
            return None

        cutoff = now - self._ja3_window
        while dq and dq[0][0] < cutoff:
            dq.popleft()

        recent_ja3s = {ja3 for _, ja3 in dq}
        if len(recent_ja3s) >= self._ja3_change_threshold:
            return BurnSignal(
                signal_type="ja3_change",
                description=(
                    f"{len(recent_ja3s)} unique JA3 fingerprints observed in "
                    f"{self._ja3_window}s window (threshold: {self._ja3_change_threshold})"
                ),
                weight=_WEIGHT_JA3_CHANGE,
            )
        return None

    def _check_volume_spike(self, domain: str, now: float) -> BurnSignal | None:
        """Detect sudden request volume increase."""
        dq = self._request_times.get(domain)
        if not dq or len(dq) < 10:
            return None

        cutoff = now - self._volume_window
        while dq and dq[0] < cutoff:
            dq.popleft()

        current_count = len(dq)
        if current_count < 5:
            return None

        # Baseline: average per-window rate over the full history.
        # If all recorded requests are inside the current window, the baseline
        # equals the current rate and no spike is detectable.  In that case
        # we treat the raw count itself as the signal (high absolute volume).
        oldest = dq[0]
        elapsed = max(now - oldest, 1.0)
        if elapsed <= self._volume_window:
            # Entire history is within the window - use absolute threshold
            if current_count >= 20:
                return BurnSignal(
                    signal_type="volume_spike",
                    description=(
                        f"High request volume: {current_count} reqs in {self._volume_window}s "
                        f"(all history within window)"
                    ),
                    weight=_WEIGHT_VOLUME_SPIKE,
                )
            return None

        baseline_rate = len(dq) / (elapsed / self._volume_window)
        if baseline_rate <= 0:
            return None

        if current_count >= baseline_rate * self._volume_spike_multiplier:
            return BurnSignal(
                signal_type="volume_spike",
                description=(
                    f"Request volume spike: {current_count} reqs in {self._volume_window}s "
                    f"(baseline ~{baseline_rate:.1f}, multiplier {self._volume_spike_multiplier}x)"
                ),
                weight=_WEIGHT_VOLUME_SPIKE,
            )
        return None

    def _check_new_asns(self, domain: str, now: float) -> BurnSignal | None:
        """Detect probing from previously unseen ASNs."""
        dq = self._recent_asns.get(domain)
        if not dq:
            return None

        cutoff = now - self._asn_window
        while dq and dq[0][0] < cutoff:
            dq.popleft()

        recent_asns = {asn for _, asn in dq}
        baseline = self._baseline_asns.get(domain, set())
        new_asns = recent_asns - baseline

        if len(new_asns) >= self._asn_new_threshold:
            return BurnSignal(
                signal_type="new_asn",
                description=(
                    f"{len(new_asns)} new ASNs probing in {self._asn_window}s window: "
                    f"{sorted(new_asns)[:5]}"
                ),
                weight=_WEIGHT_NEW_ASN,
            )
        return None

    def _check_ct_logs(self, domain: str, now: float) -> BurnSignal | None:
        """Check for CT log exposure events recorded by BurnDetector."""
        if self._burn_detector is None:
            return None

        cutoff = now - self._ct_window
        ct_events = [
            e for e in self._burn_detector._burn_events
            if e.indicator_type == "ct_domain_exposure"
            and domain in e.description
            and e.timestamp >= cutoff
        ]
        if ct_events:
            latest = max(ct_events, key=lambda e: e.timestamp)
            return BurnSignal(
                signal_type="ct_log",
                description=f"CT log exposure: {latest.description}",
                weight=_WEIGHT_CT_LOG,
            )
        return None

    def _check_reputation_hits(self, domain: str, now: float) -> BurnSignal | None:
        """Check for reputation feed listing events recorded by BurnDetector."""
        if self._burn_detector is None:
            return None

        cutoff = now - self._reputation_window
        rep_events = [
            e for e in self._burn_detector._burn_events
            if e.indicator_type == "domain_listed"
            and domain in e.description
            and e.timestamp >= cutoff
        ]
        if rep_events:
            latest = max(rep_events, key=lambda e: e.timestamp)
            return BurnSignal(
                signal_type="reputation_hit",
                description=f"Reputation feed hit: {latest.description}",
                weight=_WEIGHT_REPUTATION_HIT,
            )
        return None

    def _check_failed_auths(self, domain: str, now: float) -> BurnSignal | None:
        """Detect elevated failed authentication attempts."""
        dq = self._failed_auths.get(domain)
        if not dq:
            return None

        cutoff = now - self._failed_auth_window
        while dq and dq[0] < cutoff:
            dq.popleft()

        if len(dq) >= self._failed_auth_threshold:
            return BurnSignal(
                signal_type="failed_auth",
                description=(
                    f"{len(dq)} failed auth attempts in {self._failed_auth_window}s window "
                    f"(threshold: {self._failed_auth_threshold})"
                ),
                weight=_WEIGHT_FAILED_AUTH,
            )
        return None

    # ── Status / management ─────────────────────────────────────────

    def get_status(self, domain: str) -> dict:
        """Return current signal state for a domain (for API/dashboard)."""
        now = time.time()
        return {
            "domain": domain,
            "ja3_unique_window": len({j for _, j in self._ja3_seen.get(domain, deque()) if now - _ <= self._ja3_window}),
            "requests_window": len([t for t in self._request_times.get(domain, deque()) if now - t <= self._volume_window]),
            "asns_window": len({a for _, a in self._recent_asns.get(domain, deque()) if now - _ <= self._asn_window}),
            "failed_auth_window": len([t for t in self._failed_auths.get(domain, deque()) if now - t <= self._failed_auth_window]),
        }

    def clear(self, domain: str | None = None) -> None:
        """Clear signal state for one domain or all domains."""
        if domain is None:
            self._ja3_seen.clear()
            self._request_times.clear()
            self._recent_asns.clear()
            self._failed_auths.clear()
        else:
            self._ja3_seen.pop(domain, None)
            self._request_times.pop(domain, None)
            self._recent_asns.pop(domain, None)
            self._failed_auths.pop(domain, None)
        log.info("burn_scorer_cleared", domain=domain or "all")
