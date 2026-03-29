"""Discord webhook plugin — sends alerts with rich embeds."""

from __future__ import annotations

import asyncio

import structlog

from infraguard.models.events import RequestEvent
from infraguard.plugins.builtin._base import ForwardingPlugin

log = structlog.get_logger()

COLOR_BLOCK = 0xE74C3C  # red
COLOR_ALLOW = 0x2ECC71  # green


class Plugin(ForwardingPlugin):
    name = "discord"
    version = "1.0.0"

    async def on_event(self, event: RequestEvent) -> None:
        if not self._should_forward(event) or not self._client:
            return

        webhook_url = self._opt("webhook_url")
        if not webhook_url:
            return

        username = self._opt("username", "InfraGuard")
        avatar_url = self._opt("avatar_url")
        mention_role = self._opt("mention_role")

        blocked = event.filter_result == "block"
        color = COLOR_BLOCK if blocked else COLOR_ALLOW
        title = "Request Blocked" if blocked else "Request Allowed"

        fields = [
            {"name": "Domain", "value": event.domain, "inline": True},
            {"name": "Client IP", "value": event.client_ip, "inline": True},
            {"name": "Method", "value": event.method, "inline": True},
            {"name": "URI", "value": event.uri, "inline": False},
            {"name": "Score", "value": f"{event.filter_score:.2f}", "inline": True},
            {"name": "Status", "value": str(event.response_status), "inline": True},
        ]
        if event.filter_reason:
            fields.append(
                {"name": "Reason", "value": event.filter_reason[:1024], "inline": False}
            )

        payload: dict = {
            "username": username,
            "embeds": [
                {
                    "title": title,
                    "color": color,
                    "fields": fields,
                    "timestamp": event.timestamp.isoformat(),
                }
            ],
        }
        if avatar_url:
            payload["avatar_url"] = avatar_url
        if mention_role and blocked:
            payload["content"] = f"<@&{mention_role}>"

        try:
            resp = await self._client.post(webhook_url, json=payload)
            if resp.status_code == 429:
                retry_after = resp.json().get("retry_after", 1)
                log.warning("discord_rate_limited", retry_after=retry_after)
                await asyncio.sleep(retry_after)
            elif resp.status_code >= 400:
                log.warning("discord_error", status=resp.status_code)
            else:
                log.debug("discord_sent", result=event.filter_result)
        except Exception:
            log.exception("discord_send_error")
