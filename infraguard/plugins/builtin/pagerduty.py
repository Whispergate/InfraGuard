"""PagerDuty Events API v2 alerter.

Fires an incident on: circuit_open, all_upstreams_failed, cert_expiring
(under 14 days), rotation_failed. Uses PagerDuty's dedup_key so a
flapping breaker does not page N times per minute.

Config (in ``config.yaml``):

    plugins:
      - name: pagerduty
        options:
          integration_key: "R0123ABC..."
          severity: "warning"            # default for non-critical events
          event_types:
            - circuit_open
            - all_upstreams_failed
            - cert_expiring
"""

from __future__ import annotations

import hashlib

import structlog

from infraguard.models.events import RequestEvent
from infraguard.plugins.builtin._base import ForwardingPlugin

log = structlog.get_logger()

_PD_EVENTS_URL = "https://events.pagerduty.com/v2/enqueue"

# Events we consider incident-worthy. filter_reason values from the
# router that map into PD.
_INCIDENT_TRIGGERS: dict[str, str] = {
    "all_upstreams_failed":    "critical",
    "circuit_open":            "error",
    "cert_expiring":           "warning",
    "rotation_failed":         "critical",
    "burn_threshold_crossed":  "warning",
}


class Plugin(ForwardingPlugin):
    name = "pagerduty"
    version = "1.0.0"

    async def on_event(self, event: RequestEvent) -> None:
        if not self._client:
            return

        reason = (event.filter_reason or "").strip()
        severity_override = None
        matched = None
        for trigger, sev in _INCIDENT_TRIGGERS.items():
            if trigger in reason:
                matched = trigger
                severity_override = sev
                break

        allowed_types = set(self._opt("event_types") or _INCIDENT_TRIGGERS.keys())
        if matched not in allowed_types:
            return

        integration_key = self._opt("integration_key")
        if not integration_key:
            log.warning("pagerduty_missing_integration_key")
            return

        severity = severity_override or self._opt("severity", "warning")
        # Dedup key so PD groups repeat pages: one key per
        # (domain, trigger). PD auto-resolves when we send `resolve`.
        dedup_key = hashlib.sha1(
            f"{event.domain}:{matched}".encode()
        ).hexdigest()

        payload = {
            "routing_key": integration_key,
            "event_action": "trigger",
            "dedup_key": dedup_key,
            "payload": {
                "summary": f"InfraGuard {matched} on {event.domain}",
                "source": event.domain,
                "severity": severity,
                "component": "infraguard-proxy",
                "group": event.domain,
                "class": matched,
                "custom_details": {
                    "client_ip": event.client_ip,
                    "uri": event.uri,
                    "reason": reason[:500],
                    "score": event.filter_score,
                },
            },
        }

        try:
            r = await self._client.post(_PD_EVENTS_URL, json=payload, timeout=5)
            if r.status_code >= 300:
                log.warning(
                    "pagerduty_post_non_2xx",
                    status=r.status_code,
                    body=r.text[:200],
                )
        except Exception as exc:
            log.warning("pagerduty_post_failed", error=str(exc))
