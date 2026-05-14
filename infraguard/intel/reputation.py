"""Domain reputation self-monitor.

Periodically checks C2 and phishing domains against public threat intelligence
feeds. When a domain appears in a feed, the operator is immediately alerted via
the plugin system before callbacks stop arriving.

Feeds checked:
  - URLhaus (abuse.ch) - C2/malware hosting
  - OpenPhish - active phishing URLs (plain-text, no API key needed)
  - Google Safe Browsing Lookup API v4 (optional, requires API key)
"""

from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING

import httpx
import structlog

if TYPE_CHECKING:
    from infraguard.intel.burn_detect import BurnDetector
    from infraguard.tracking.recorder import EventRecorder

log = structlog.get_logger()

_URLHAUS_API = "https://urlhaus-api.abuse.ch/v1/host/"
_OPENPHISH_FEED = "https://openphish.com/feed.txt"
_GSB_API = "https://safebrowsing.googleapis.com/v4/threatMatches:find"
_REQUEST_TIMEOUT = 20.0


class DomainReputationMonitor:
    """Checks operator domains against threat intelligence feeds."""

    def __init__(
        self,
        domains: list[str],
        interval_hours: float = 4.0,
        check_urlhaus: bool = True,
        check_openphish: bool = True,
        check_google_safebrowsing: bool = False,
        google_safebrowsing_api_key: str | None = None,
        burn_detector: "BurnDetector | None" = None,
        recorder: "EventRecorder | None" = None,
    ) -> None:
        self._domains = domains
        self._interval = interval_hours * 3600
        self._check_urlhaus = check_urlhaus
        self._check_openphish = check_openphish
        self._check_gsb = check_google_safebrowsing
        self._gsb_key = google_safebrowsing_api_key
        self._burn_detector = burn_detector
        self._recorder = recorder
        self._task: asyncio.Task | None = None
        self._client: httpx.AsyncClient | None = None
        # Cache OpenPhish feed to avoid re-fetching per domain
        self._openphish_cache: set[str] = set()
        self._openphish_last_fetch: float = 0.0

    async def start(self) -> None:
        self._client = httpx.AsyncClient(timeout=_REQUEST_TIMEOUT, follow_redirects=True)
        self._task = asyncio.create_task(self._monitor_loop())
        log.info(
            "reputation_monitor_started",
            domains=self._domains,
            interval_hours=self._interval / 3600,
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

    async def _monitor_loop(self) -> None:
        while True:
            for domain in self._domains:
                await self._check_domain(domain)
            await asyncio.sleep(self._interval)

    async def _check_domain(self, domain: str) -> None:
        if self._check_urlhaus:
            await self._check_urlhaus_domain(domain)
        if self._check_openphish:
            await self._check_openphish_domain(domain)
        if self._check_gsb and self._gsb_key:
            await self._check_gsb_domain(domain)

    async def _check_urlhaus_domain(self, domain: str) -> None:
        if self._client is None:
            return
        try:
            resp = await self._client.post(_URLHAUS_API, data={"host": domain})
            resp.raise_for_status()
            data = resp.json()
            if data.get("query_status") == "is_host":
                self._fire_burn(domain, "URLhaus", f"Listed as malware host in URLhaus")
        except Exception:
            log.debug("urlhaus_check_failed", domain=domain)

    async def _check_openphish_domain(self, domain: str) -> None:
        if self._client is None:
            return
        import time
        # Refresh feed cache every hour
        if time.time() - self._openphish_last_fetch > 3600:
            try:
                resp = await self._client.get(_OPENPHISH_FEED)
                resp.raise_for_status()
                self._openphish_cache = set(resp.text.splitlines())
                self._openphish_last_fetch = time.time()
            except Exception:
                log.debug("openphish_fetch_failed")
                return

        matched = any(domain in url for url in self._openphish_cache)
        if matched:
            self._fire_burn(domain, "OpenPhish", f"Domain found in OpenPhish active phishing feed")

    async def _check_gsb_domain(self, domain: str) -> None:
        if self._client is None or not self._gsb_key:
            return
        payload = {
            "client": {"clientId": "infraguard", "clientVersion": "1.0"},
            "threatInfo": {
                "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE"],
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [
                    {"url": f"https://{domain}/"},
                    {"url": f"http://{domain}/"},
                ],
            },
        }
        try:
            resp = await self._client.post(
                f"{_GSB_API}?key={self._gsb_key}", json=payload
            )
            resp.raise_for_status()
            data = resp.json()
            if data.get("matches"):
                threat_type = data["matches"][0].get("threatType", "unknown")
                self._fire_burn(domain, "Google Safe Browsing", f"Listed as {threat_type}")
        except Exception:
            log.debug("gsb_check_failed", domain=domain)

    def _fire_burn(self, domain: str, source: str, description: str) -> None:
        log.critical(
            "burn_detected",
            type="domain_listed",
            domain=domain,
            source=source,
        )
        if self._burn_detector is not None:
            from infraguard.intel.burn_detect import BurnIndicator
            ind = BurnIndicator(
                indicator_type="domain_listed",
                description=f"[{source}] {description} - domain: {domain}",
                severity="critical",
            )
            self._burn_detector._burn_events.append(ind)
            self._burn_detector._fire_burn_alert(ind)
        elif self._recorder is not None:
            try:
                from infraguard.models.events import RequestEvent
                self._recorder.record(
                    RequestEvent.now(
                        domain=domain,
                        client_ip="0.0.0.0",
                        method="REPUTATION_CHECK",
                        uri="/_reputation_alert",
                        user_agent=source,
                        filter_result="burn_alert",
                        filter_reason=description,
                        filter_score=1.0,
                        response_status=0,
                        duration_ms=0.0,
                    )
                )
            except Exception:
                log.exception("reputation_event_dispatch_error")
