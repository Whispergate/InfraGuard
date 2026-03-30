"""Generic webhook plugin - POST JSON events to any URL.

Covers Rocket.Chat, Mattermost, Microsoft Teams, and custom endpoints.
"""

from __future__ import annotations

import json

import structlog

from infraguard.models.events import RequestEvent
from infraguard.plugins.builtin._base import ForwardingPlugin

log = structlog.get_logger()


class Plugin(ForwardingPlugin):
    name = "generic_webhook"
    version = "1.0.0"

    async def on_event(self, event: RequestEvent) -> None:
        if not self._should_forward(event) or not self._client:
            return

        url = self._opt("url")
        if not url:
            return

        method = self._opt("method", "POST").upper()
        extra_headers = self._opt("headers", {})
        content_type = self._opt("content_type", "application/json")

        event_dict = self._event_to_dict(event)

        # Optional body template (simple string.format substitution)
        body_template = self._opt("body_template")
        if body_template:
            try:
                body = body_template.format(**event_dict)
            except (KeyError, IndexError):
                body = json.dumps(event_dict)
        else:
            body = json.dumps(event_dict)

        headers = {"Content-Type": content_type}
        headers.update(extra_headers)

        try:
            resp = await self._client.request(method, url, content=body, headers=headers)
            if resp.status_code >= 400:
                log.warning(
                    "webhook_error",
                    plugin=self.name,
                    url=url,
                    status=resp.status_code,
                )
            else:
                log.debug("webhook_sent", plugin=self.name, url=url)
        except Exception:
            log.exception("webhook_send_error", plugin=self.name, url=url)
