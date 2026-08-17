"""Passive DNS (PDNS) monitoring.

Tracks historical DNS resolutions for operator-controlled C2 / phishing
domains by polling a passive DNS provider. Passive DNS visibility is one of
the earliest external signals that blue team or a threat-intel vendor has
started investigating a domain:

  - The domain appears in a PDNS database at all (someone resolved it that
    wasn't our implant or target) - possible analyst reconnaissance.
  - New A/AAAA records observed for the domain - unexpected answers mean
    someone else (sinkhole, registrar action, DNS hijack) is answering for
    our domain, or our own DNS change is now visible worldwide.
  - Sudden NXDOMAIN spike for a previously-resolving domain - classic
    indicator that the registrar/registry has pulled the zone (takedown)
    or that a major resolver has started refusing to resolve it.

When any of these fire:
  1. A ``BurnIndicator`` is recorded on the shared ``BurnDetector``
     (when configured) so cooldown / scoring logic can react.
  2. A synthetic ``RequestEvent(filter_result="burn_alert")`` is dispatched
     through the plugin system (Discord/Slack/Syslog receive it).

Provider support:
  - CIRCL Passive DNS (https://www.circl.lu/pdns/) - the default; free API
    with a CIRCL account (user/password HTTP basic auth). Returns NDJSON.
  - ``provider="local"`` - no upstream; the monitor only ingests answers
    observed locally by InfraGuard's own DNS listener via
    :meth:`record_observation`. Useful for offline testing or as a pure
    self-telemetry source.
"""

from __future__ import annotations

import asyncio
import json
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Iterable

import httpx
import structlog

if TYPE_CHECKING:
    from infraguard.intel.burn_detect import BurnDetector
    from infraguard.tracking.recorder import EventRecorder

log = structlog.get_logger()

_CIRCL_PDNS_URL = "https://www.circl.lu/pdns/query/{domain}"
_REQUEST_TIMEOUT = 30.0
_MAX_EVENTS = 200
_MAX_HISTORY_PER_DOMAIN = 500


@dataclass
class PassiveDNSEvent:
    """A single PDNS monitoring signal."""

    event_type: str          # "domain_flagged", "new_record", "nxdomain_spike"
    domain: str
    description: str
    severity: str            # "warning", "critical"
    timestamp: float = field(default_factory=time.time)
    details: dict = field(default_factory=dict)


@dataclass
class DNSObservation:
    """One observed (domain, rrtype, rdata) resolution."""

    rrtype: str              # "A", "AAAA", "CNAME", ...
    rdata: str               # the resolved value (IP, hostname, ...)
    first_seen: float
    last_seen: float
    count: int = 1


class PassiveDNSMonitor:
    """Polls passive DNS sources and detects suspicious DNS changes.

    The monitor keeps an in-memory history of every (rrtype, rdata) tuple
    observed per domain. On each poll, new records and PDNS state changes
    are compared against the baseline established on the first poll; only
    deltas generate alerts, so we don't re-alert on the same records every
    interval.
    """

    def __init__(
        self,
        domains: list[str],
        interval_hours: float = 6.0,
        provider: str = "circl",
        circl_user: str | None = None,
        circl_password: str | None = None,
        nxdomain_spike_threshold: int = 5,
        nxdomain_window_seconds: int = 3600,
        alert_on_first_seen: bool = True,
        burn_detector: "BurnDetector | None" = None,
        recorder: "EventRecorder | None" = None,
    ) -> None:
        self._domains = [d.lower().strip() for d in domains if d.strip()]
        self._interval = interval_hours * 3600
        self._provider = provider
        self._circl_auth = (
            (circl_user, circl_password)
            if circl_user and circl_password
            else None
        )
        self._nxdomain_threshold = nxdomain_spike_threshold
        self._nxdomain_window = nxdomain_window_seconds
        self._alert_on_first_seen = alert_on_first_seen
        self._burn_detector = burn_detector
        self._recorder = recorder

        # domain -> {(rrtype, rdata): DNSObservation}
        self._history: dict[str, dict[tuple[str, str], DNSObservation]] = defaultdict(dict)
        # domain -> True once the baseline poll has run
        self._baseline_done: dict[str, bool] = {}
        # per-domain NXDOMAIN timestamps (local observations only)
        self._nxdomain_times: dict[str, deque[float]] = defaultdict(deque)
        # ring buffer of recent events (for API/dashboard)
        self._events: deque[PassiveDNSEvent] = deque(maxlen=_MAX_EVENTS)

        self._task: asyncio.Task | None = None
        self._client: httpx.AsyncClient | None = None

    # ── lifecycle ─────────────────────────────────────────────────────

    async def start(self) -> None:
        """Start the background polling task (skipped for provider='local')."""
        if self._provider != "local":
            self._client = httpx.AsyncClient(
                timeout=_REQUEST_TIMEOUT,
                follow_redirects=True,
                auth=self._circl_auth,
                headers={"User-Agent": "InfraGuard-PDNS/1.0"},
            )
            self._task = asyncio.create_task(self._poll_loop())
            log.info(
                "passive_dns_monitor_started",
                provider=self._provider,
                domains=self._domains,
                interval_hours=self._interval / 3600,
            )
        else:
            log.info(
                "passive_dns_monitor_started_local_only",
                domains=self._domains,
            )

    async def stop(self) -> None:
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
        if self._client:
            await self._client.aclose()

    # ── public surface for DNS listener / API ─────────────────────────

    def record_observation(
        self,
        domain: str,
        rrtype: str,
        rdata: str,
        timestamp: float | None = None,
    ) -> PassiveDNSEvent | None:
        """Record a DNS answer observed by our own infrastructure.

        Called by the DNS listener (or tests) to fold local resolution
        telemetry into the PDNS history. Returns a ``PassiveDNSEvent`` if
        this observation produced an alert, else ``None``.
        """
        ts = timestamp or time.time()
        domain = domain.lower().rstrip(".")
        if domain not in self._domains:
            return None

        if rrtype.upper() == "NXDOMAIN":
            return self._record_nxdomain(domain, ts)

        key = (rrtype.upper(), rdata)
        bucket = self._history[domain]
        if key in bucket:
            obs = bucket[key]
            obs.last_seen = ts
            obs.count += 1
            return None

        bucket[key] = DNSObservation(rrtype=rrtype.upper(), rdata=rdata,
                                     first_seen=ts, last_seen=ts)
        # Cap history to avoid unbounded memory growth on hostile zones
        if len(bucket) > _MAX_HISTORY_PER_DOMAIN:
            oldest = sorted(bucket.values(), key=lambda o: o.last_seen)[0]
            bucket.pop((oldest.rrtype, oldest.rdata), None)

        # Only alert on locally-observed new A/AAAA records once the
        # baseline exists; otherwise every legitimate resolution would fire.
        if self._baseline_done.get(domain) and rrtype.upper() in ("A", "AAAA"):
            return self._emit(
                PassiveDNSEvent(
                    event_type="new_record",
                    domain=domain,
                    description=(
                        f"New {rrtype.upper()} record observed locally for "
                        f"'{domain}': {rdata}"
                    ),
                    severity="warning",
                    details={"rrtype": rrtype.upper(), "rdata": rdata,
                             "source": "local"},
                )
            )
        return None

    def _record_nxdomain(self, domain: str, ts: float) -> PassiveDNSEvent | None:
        dq = self._nxdomain_times[domain]
        dq.append(ts)
        cutoff = ts - self._nxdomain_window
        while dq and dq[0] < cutoff:
            dq.popleft()
        if len(dq) >= self._nxdomain_threshold:
            count = len(dq)
            dq.clear()  # reset window so we don't fire every request
            return self._emit(
                PassiveDNSEvent(
                    event_type="nxdomain_spike",
                    domain=domain,
                    description=(
                        f"NXDOMAIN spike for '{domain}': {count} NXDOMAIN "
                        f"responses in {self._nxdomain_window}s - possible "
                        f"zone takedown or resolver-level blocking"
                    ),
                    severity="critical",
                    details={"count": count, "window_seconds": self._nxdomain_window},
                )
            )
        return None

    # ── polling loop ──────────────────────────────────────────────────

    async def _poll_loop(self) -> None:
        # Small initial delay so the rest of startup finishes first
        await asyncio.sleep(5)
        while True:
            for domain in self._domains:
                try:
                    await self._check_domain(domain)
                except Exception:
                    log.exception("pdns_check_error", domain=domain)
            await asyncio.sleep(self._interval)

    async def _check_domain(self, domain: str) -> None:
        if self._client is None:
            return
        if self._provider == "circl":
            records = await self._fetch_circl(domain)
        else:
            log.warning("pdns_unknown_provider", provider=self._provider)
            return
        if records is None:
            return

        now = time.time()
        first_poll = not self._baseline_done.get(domain, False)

        new_records: list[tuple[str, str]] = []
        bucket = self._history[domain]
        for rrtype, rdata, _first_seen, last_seen in records:
            key = (rrtype, rdata)
            if key in bucket:
                bucket[key].last_seen = last_seen or now
                bucket[key].count += 1
            else:
                bucket[key] = DNSObservation(
                    rrtype=rrtype,
                    rdata=rdata,
                    first_seen=now,
                    last_seen=last_seen or now,
                )
                new_records.append(key)

        if first_poll:
            self._baseline_done[domain] = True
            log.info(
                "pdns_baseline_established",
                domain=domain,
                record_count=len(bucket),
            )
            # Domain is in PDNS at all - someone (possibly not us) has been
            # resolving it. Flag on first sighting so the operator knows the
            # domain already has PDNS visibility.
            if self._alert_on_first_seen and bucket:
                self._emit(
                    PassiveDNSEvent(
                        event_type="domain_flagged",
                        domain=domain,
                        description=(
                            f"Domain '{domain}' present in passive DNS with "
                            f"{len(bucket)} historical record(s) - domain has "
                            f"external PDNS visibility"
                        ),
                        severity="warning",
                        details={"record_count": len(bucket),
                                 "provider": self._provider},
                    )
                )
            return

        # Subsequent polls: alert on new A/AAAA only (CNAME/TXT churn is noisy)
        interesting = [k for k in new_records if k[0] in ("A", "AAAA")]
        if interesting:
            sample = interesting[:5]
            self._emit(
                PassiveDNSEvent(
                    event_type="new_record",
                    domain=domain,
                    description=(
                        f"PDNS observed {len(interesting)} new A/AAAA record(s) "
                        f"for '{domain}': "
                        + ", ".join(f"{t}:{v}" for t, v in sample)
                    ),
                    severity="warning",
                    details={"records": [list(k) for k in interesting],
                             "provider": self._provider},
                )
            )

    async def _fetch_circl(
        self, domain: str
    ) -> list[tuple[str, str, float | None, float | None]] | None:
        """Query CIRCL PDNS. Returns list of (rrtype, rdata, first_seen, last_seen)."""
        assert self._client is not None
        try:
            resp = await self._client.get(_CIRCL_PDNS_URL.format(domain=domain))
        except Exception:
            log.warning("pdns_fetch_failed", domain=domain, provider="circl")
            return None

        if resp.status_code == 404:
            # CIRCL returns 404 when it has no records - not an error.
            return []
        if resp.status_code in (401, 403):
            log.warning("pdns_auth_failed", domain=domain, status=resp.status_code)
            return None
        try:
            resp.raise_for_status()
        except Exception:
            log.warning("pdns_fetch_failed", domain=domain, status=resp.status_code)
            return None

        out: list[tuple[str, str, float | None, float | None]] = []
        # CIRCL returns newline-delimited JSON
        for line in resp.text.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue
            rrtype = (obj.get("rrtype") or "").upper()
            rdata = obj.get("rdata") or ""
            if not rrtype or not rdata:
                continue
            out.append(
                (
                    rrtype,
                    rdata,
                    _to_epoch(obj.get("time_first")),
                    _to_epoch(obj.get("time_last")),
                )
            )
        return out

    # ── alerting ──────────────────────────────────────────────────────

    def _emit(self, event: PassiveDNSEvent) -> PassiveDNSEvent:
        """Record an event locally and forward to burn detector / plugins."""
        self._events.append(event)
        _log_fn = log.critical if event.severity == "critical" else log.warning
        _log_fn(
            "passive_dns_alert",
            type=event.event_type,
            domain=event.domain,
            description=event.description,
        )

        if self._burn_detector is not None:
            from infraguard.intel.burn_detect import BurnIndicator
            ind = BurnIndicator(
                indicator_type=f"pdns_{event.event_type}",
                description=event.description,
                severity=event.severity,
            )
            self._burn_detector._burn_events.append(ind)
            self._burn_detector._fire_burn_alert(ind)
        elif self._recorder is not None:
            try:
                from infraguard.models.events import RequestEvent
                self._recorder.record(
                    RequestEvent.now(
                        domain=event.domain,
                        client_ip="0.0.0.0",
                        method="PDNS_MONITOR",
                        uri="/_pdns_alert",
                        user_agent=event.event_type,
                        filter_result="burn_alert",
                        filter_reason=event.description,
                        filter_score=1.0,
                        response_status=0,
                        duration_ms=0.0,
                    )
                )
            except Exception:
                log.exception("pdns_event_dispatch_error")
        return event

    # ── status / API surface ──────────────────────────────────────────

    def get_status(self) -> dict:
        """Summary for the dashboard/API."""
        return {
            "provider": self._provider,
            "monitored_domains": list(self._domains),
            "domains_with_baseline": sum(1 for d in self._domains
                                         if self._baseline_done.get(d)),
            "total_records_tracked": sum(len(v) for v in self._history.values()),
            "events_buffered": len(self._events),
            "interval_hours": self._interval / 3600,
            "running": self._task is not None and not self._task.done(),
        }

    def get_events(self, limit: int = 50) -> list[dict]:
        """Most recent PDNS events, newest first."""
        items = list(self._events)[-limit:]
        items.reverse()
        return [
            {
                "event_type": e.event_type,
                "domain": e.domain,
                "description": e.description,
                "severity": e.severity,
                "timestamp": e.timestamp,
                "details": e.details,
            }
            for e in items
        ]

    def get_history(self, domain: str) -> list[dict]:
        """Full observation history for a single domain."""
        bucket = self._history.get(domain.lower().rstrip("."), {})
        return [
            {
                "rrtype": obs.rrtype,
                "rdata": obs.rdata,
                "first_seen": obs.first_seen,
                "last_seen": obs.last_seen,
                "count": obs.count,
            }
            for obs in sorted(bucket.values(), key=lambda o: o.last_seen, reverse=True)
        ]

    def clear_history(self, domain: str | None = None) -> None:
        """Reset PDNS history (single domain or all). Used by operators to
        re-baseline after intentional DNS changes."""
        if domain is None:
            self._history.clear()
            self._baseline_done.clear()
            log.info("pdns_history_cleared_all")
        else:
            d = domain.lower().rstrip(".")
            self._history.pop(d, None)
            self._baseline_done.pop(d, None)
            self._nxdomain_times.pop(d, None)
            log.info("pdns_history_cleared", domain=d)


def _to_epoch(value) -> float | None:
    """CIRCL sometimes returns epoch as int, sometimes ISO strings; normalize."""
    if value is None:
        return None
    if isinstance(value, (int, float)):
        return float(value)
    if isinstance(value, str):
        try:
            return float(value)
        except ValueError:
            pass
        try:
            from datetime import datetime
            return datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp()
        except ValueError:
            return None
    return None
