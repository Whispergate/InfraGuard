"""Certificate Transparency log monitor.

Polls crt.sh to detect new TLS certificate issuances for configured domains.
A new cert issuance means someone queried CT logs for the domain - advance
warning that blue team or threat intel has the domain on their radar before
active scanning begins.

When a new issuance is detected:
  1. A BurnIndicator(indicator_type="ct_domain_exposure") is recorded
  2. A synthetic RequestEvent(filter_result="burn_alert") is dispatched through
     the plugin system (Discord/Slack/Syslog receive the alert automatically)
"""

from __future__ import annotations

import asyncio
import time
from typing import TYPE_CHECKING

import httpx
import structlog

if TYPE_CHECKING:
    from infraguard.intel.burn_detect import BurnDetector
    from infraguard.tracking.recorder import EventRecorder

log = structlog.get_logger()

_CRTSH_URL = "https://crt.sh/?q=%.{domain}&output=json"
_REQUEST_TIMEOUT = 30.0


class CTMonitor:
    """Background task that polls crt.sh for new cert issuances per domain."""

    def __init__(
        self,
        domains: list[str],
        interval_hours: float = 6.0,
        burn_detector: "BurnDetector | None" = None,
        recorder: "EventRecorder | None" = None,
    ) -> None:
        self._domains = domains
        self._interval = interval_hours * 3600
        self._burn_detector = burn_detector
        self._recorder = recorder
        # domain -> highest cert id seen so far (avoids re-alerting on same certs)
        self._last_seen_id: dict[str, int] = {}
        self._task: asyncio.Task | None = None
        self._client: httpx.AsyncClient | None = None

    async def start(self) -> None:
        self._client = httpx.AsyncClient(timeout=_REQUEST_TIMEOUT, follow_redirects=True)
        self._task = asyncio.create_task(self._poll_loop())
        log.info("ct_monitor_started", domains=self._domains, interval_hours=self._interval / 3600)

    async def stop(self) -> None:
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
        if self._client:
            await self._client.aclose()

    async def _poll_loop(self) -> None:
        while True:
            for domain in self._domains:
                try:
                    await self._check_domain(domain)
                except Exception:
                    log.exception("ct_check_error", domain=domain)
            await asyncio.sleep(self._interval)

    async def _check_domain(self, domain: str) -> None:
        if self._client is None:
            return
        url = _CRTSH_URL.format(domain=domain)
        try:
            resp = await self._client.get(url)
            resp.raise_for_status()
            entries = resp.json()
        except Exception:
            log.warning("ct_fetch_failed", domain=domain)
            return

        if not isinstance(entries, list):
            return

        last_id = self._last_seen_id.get(domain, 0)
        new_entries = [e for e in entries if isinstance(e, dict) and e.get("id", 0) > last_id]

        if not new_entries:
            return

        # Update high-water mark
        max_id = max(e.get("id", 0) for e in new_entries)
        self._last_seen_id[domain] = max(last_id, max_id)

        # Skip alert on very first poll - we're just learning the baseline
        if last_id == 0:
            log.info("ct_baseline_established", domain=domain, cert_count=len(entries))
            return

        issuers = list({e.get("issuer_name", "unknown") for e in new_entries})
        description = (
            f"Domain '{domain}' found in CT logs: "
            f"{len(new_entries)} new cert(s), issuers: {issuers[:3]}"
        )
        log.critical("burn_detected", type="ct_domain_exposure", domain=domain, new_certs=len(new_entries))

        if self._burn_detector is not None:
            from infraguard.intel.burn_detect import BurnIndicator
            ind = BurnIndicator(
                indicator_type="ct_domain_exposure",
                description=description,
                severity="critical",
            )
            self._burn_detector._burn_events.append(ind)
            self._burn_detector._fire_burn_alert(ind)
        elif self._recorder is not None:
            self._dispatch_event(domain, description)

    def _dispatch_event(self, domain: str, description: str) -> None:
        if self._recorder is None:
            return
        try:
            from infraguard.models.events import RequestEvent
            self._recorder.record(
                RequestEvent.now(
                    domain=domain,
                    client_ip="0.0.0.0",
                    method="CT_MONITOR",
                    uri="/_ct_alert",
                    user_agent="crt.sh",
                    filter_result="burn_alert",
                    filter_reason=description,
                    filter_score=1.0,
                    response_status=0,
                    duration_ms=0.0,
                )
            )
        except Exception:
            log.exception("ct_event_dispatch_error")
