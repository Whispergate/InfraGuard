"""Elasticsearch SIEM plugin - forwards events via the _bulk API."""

from __future__ import annotations

import json

import structlog

from infraguard.models.events import RequestEvent
from infraguard.plugins.builtin._batch import BatchForwardingPlugin

log = structlog.get_logger()


class Plugin(BatchForwardingPlugin):
    name = "elasticsearch"
    version = "1.0.0"

    async def _send_batch(self, events: list[RequestEvent]) -> None:
        if not self._client:
            return

        url = self._opt("url", "http://localhost:9200")
        index = self._opt("index", "infraguard-events")
        api_key = self._opt("api_key")
        username = self._opt("username")
        password = self._opt("password")

        # Build NDJSON bulk payload
        lines: list[str] = []
        for event in events:
            lines.append(json.dumps({"index": {"_index": index}}))
            lines.append(json.dumps(self._event_to_dict(event)))
        body = "\n".join(lines) + "\n"

        headers: dict[str, str] = {"Content-Type": "application/x-ndjson"}
        if api_key:
            headers["Authorization"] = f"ApiKey {api_key}"

        auth = None
        if username and password:
            auth = (username, password)

        verify = self._opt("verify_ssl", True)

        try:
            resp = await self._client.post(
                f"{url.rstrip('/')}/_bulk",
                content=body,
                headers=headers,
                auth=auth,
            )
            if resp.status_code == 429:
                log.warning("elasticsearch_rate_limited", plugin=self.name)
            elif resp.status_code >= 400:
                log.warning(
                    "elasticsearch_error",
                    status=resp.status_code,
                    body=resp.text[:200],
                )
            else:
                log.debug("elasticsearch_bulk_sent", events=len(events))
        except Exception:
            log.exception("elasticsearch_send_error", events=len(events))
