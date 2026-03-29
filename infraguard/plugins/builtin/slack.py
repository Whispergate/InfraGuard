"""Slack webhook plugin — sends alerts using Block Kit formatting."""

from __future__ import annotations

import structlog

from infraguard.models.events import RequestEvent
from infraguard.plugins.builtin._base import ForwardingPlugin

log = structlog.get_logger()


class Plugin(ForwardingPlugin):
    name = "slack"
    version = "1.0.0"

    async def on_event(self, event: RequestEvent) -> None:
        if not self._should_forward(event) or not self._client:
            return

        webhook_url = self._opt("webhook_url")
        if not webhook_url:
            return

        channel = self._opt("channel")
        username = self._opt("username", "InfraGuard")
        icon_emoji = self._opt("icon_emoji", ":shield:")

        blocked = event.filter_result == "block"
        emoji = ":red_circle:" if blocked else ":large_green_circle:"
        title = f"{emoji} Request {'Blocked' if blocked else 'Allowed'}"

        fields = [
            {"type": "mrkdwn", "text": f"*Domain:*\n{event.domain}"},
            {"type": "mrkdwn", "text": f"*Client IP:*\n{event.client_ip}"},
            {"type": "mrkdwn", "text": f"*Method:*\n{event.method}"},
            {"type": "mrkdwn", "text": f"*URI:*\n{event.uri}"},
            {"type": "mrkdwn", "text": f"*Score:*\n{event.filter_score:.2f}"},
        ]
        if event.filter_reason:
            fields.append(
                {"type": "mrkdwn", "text": f"*Reason:*\n{event.filter_reason[:300]}"}
            )

        payload: dict = {
            "username": username,
            "icon_emoji": icon_emoji,
            "blocks": [
                {
                    "type": "header",
                    "text": {"type": "plain_text", "text": title},
                },
                {
                    "type": "section",
                    "fields": fields,
                },
                {
                    "type": "context",
                    "elements": [
                        {
                            "type": "mrkdwn",
                            "text": (
                                f"{event.timestamp.isoformat()} | "
                                f"Status: {event.response_status} | "
                                f"Duration: {event.duration_ms:.1f}ms"
                            ),
                        }
                    ],
                },
            ],
        }
        if channel:
            payload["channel"] = channel

        try:
            resp = await self._client.post(webhook_url, json=payload)
            if resp.status_code >= 400:
                log.warning("slack_error", status=resp.status_code, body=resp.text[:200])
            else:
                log.debug("slack_sent", result=event.filter_result)
        except Exception:
            log.exception("slack_send_error")
