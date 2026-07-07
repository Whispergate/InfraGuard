"""Phishing.club webhook receiver integration.

Phishing.club fires HMAC-SHA256-signed POST requests to a configured webhook
URL whenever a campaign event occurs (recipient click, credential submission,
browser metadata collection, etc.).

InfraGuard registers a dedicated route (configurable path) that:
  1. Validates the X-Signature HMAC-SHA256 header
  2. Parses the event payload
  3. Records the event to the InfraGuard tracking database
  4. Optionally promotes the clicking IP to the dynamic whitelist
  5. Dispatches a synthetic RequestEvent through the recorder so plugins
     (Discord, Slack, syslog) receive phishing campaign hit notifications

Phishing.club webhook payload schema (from their source):
  {
    "campaignId": "uuid",
    "eventId": "string",        -- e.g. "email_opened", "link_clicked", "data_submitted"
    "recipientId": "uuid",
    "anonymizedId": "uuid",
    "ip": "1.2.3.4",
    "userAgent": "Mozilla/5.0...",
    "data": { ... },            -- form submission fields (credentials etc.)
    "metadata": { ... },        -- browser fingerprint, JA4, geolocation
    "createdAt": "ISO8601"
  }

HMAC validation:
  Header: X-Signature: sha256=<hex>
  HMAC-SHA256(secret, raw_body_bytes)
"""

from __future__ import annotations

import hashlib
import hmac
import json
from datetime import datetime, timezone
from typing import Any, Callable, Awaitable

import structlog
from starlette.requests import Request
from starlette.responses import Response

from infraguard.models.events import RequestEvent
from infraguard.tracking.database import Database
from infraguard.tracking.recorder import EventRecorder

log = structlog.get_logger()

# Phishing.club event IDs that indicate a high-value target action
_HIGH_VALUE_EVENTS = frozenset({
    "data_submitted",
    "credentials_submitted",
    "oauth_token_captured",
    "device_code_captured",
    "mfa_submitted",
})


def _verify_signature(secret: str, body: bytes, signature_header: str | None) -> bool:
    """Return True if X-Signature matches HMAC-SHA256(secret, body)."""
    if not signature_header:
        return False
    # Header format: "sha256=<hexdigest>"
    if signature_header.startswith("sha256="):
        received = signature_header[7:]
    else:
        received = signature_header
    expected = hmac.new(
        secret.encode("utf-8"),
        body,
        hashlib.sha256,
    ).hexdigest()
    return hmac.compare_digest(expected, received)


def make_webhook_handler(
    pc_cfg: Any,
    db: Database,
    recorder: EventRecorder,
) -> Callable[[Request], Awaitable[Response]]:
    """Return an ASGI handler for phishing.club webhook events."""

    secret: str | None = pc_cfg.webhook_secret
    whitelist_on_click: bool = pc_cfg.whitelist_on_click
    result_label: str = pc_cfg.event_result_label

    async def handler(request: Request) -> Response:
        body = await request.body()

        # HMAC validation
        if secret:
            sig = request.headers.get("x-signature") or request.headers.get("x-webhook-signature")
            if not _verify_signature(secret, body, sig):
                log.warning(
                    "phishingclub_webhook_invalid_signature",
                    remote=request.client.host if request.client else "?",
                )
                return Response(status_code=403, content=b"forbidden")

        try:
            payload: dict = json.loads(body)
        except (ValueError, UnicodeDecodeError):
            log.warning("phishingclub_webhook_bad_json")
            return Response(status_code=400, content=b"bad request")

        campaign_id = payload.get("campaignId", "?")
        event_id = payload.get("eventId", "unknown")
        recipient_id = payload.get("recipientId") or payload.get("anonymizedId", "?")
        client_ip = payload.get("ip", "")
        user_agent = payload.get("userAgent", "")
        created_at_raw = payload.get("createdAt")

        try:
            ts = datetime.fromisoformat(created_at_raw) if created_at_raw else datetime.now(timezone.utc)
            if ts.tzinfo is None:
                ts = ts.replace(tzinfo=timezone.utc)
        except (ValueError, TypeError):
            ts = datetime.now(timezone.utc)

        is_high_value = event_id in _HIGH_VALUE_EVENTS

        log.info(
            "phishingclub_event",
            campaign=campaign_id,
            event=event_id,
            recipient=recipient_id,
            ip=client_ip,
            high_value=is_high_value,
        )

        # Optionally whitelist the clicking IP so it passes InfraGuard's filters
        if whitelist_on_click and client_ip:
            try:
                app_state = getattr(request.app, "state", None)
                router = getattr(app_state, "router", None) if app_state else None
                if router and hasattr(router, "intel"):
                    router.intel.dynamic_whitelist._whitelisted.add(client_ip)
                    log.info("phishingclub_ip_whitelisted", ip=client_ip, event=event_id)
            except Exception:
                log.exception("phishingclub_whitelist_error", ip=client_ip)

        # Synthesize a RequestEvent so recorder dispatches to plugins (Discord, Slack, etc.)
        synthetic_event = RequestEvent.now(
            domain=f"phishingclub/{campaign_id}",
            client_ip=client_ip or "0.0.0.0",
            method="POST",
            uri=f"/campaign/{campaign_id}/{event_id}",
            user_agent=user_agent,
            filter_result=result_label,
            filter_reason=f"phishing.club: {event_id} (recipient={recipient_id})",
            filter_score=1.0 if is_high_value else 0.5,
            response_status=200,
            duration_ms=0.0,
            request_hash="",
            protocol="webhook",
        )
        synthetic_event.timestamp = ts

        try:
            recorder.record(synthetic_event)
        except Exception:
            log.exception("phishingclub_record_error")

        return Response(status_code=200, content=b"ok")

    return handler
