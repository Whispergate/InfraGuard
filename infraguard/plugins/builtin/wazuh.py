"""Wazuh SIEM plugin - forwards events to Wazuh-Indexer via _bulk API.

Authenticates against the Wazuh API to get a JWT token, then sends
events to the Wazuh-Indexer (OpenSearch-compatible) using the same
NDJSON bulk format as Elasticsearch.
"""

from __future__ import annotations

import json
import time

import structlog

from infraguard.models.events import RequestEvent
from infraguard.plugins.builtin._batch import BatchForwardingPlugin

log = structlog.get_logger()


class Plugin(BatchForwardingPlugin):
    name = "wazuh"
    version = "1.0.0"

    def __init__(self):
        super().__init__()
        self._token: str | None = None
        self._token_expires_at: float = 0

    async def _get_token(self) -> str | None:
        """Authenticate with Wazuh API and cache the JWT token."""
        if self._token and time.time() < self._token_expires_at:
            return self._token

        api_url = self._opt("url", "https://localhost:55000")
        username = self._opt("username", "wazuh-wui")
        password = self._opt("password", "")

        if not self._client or not password:
            return None

        try:
            resp = await self._client.post(
                f"{api_url.rstrip('/')}/security/user/authenticate",
                auth=(username, password),
            )
            if resp.status_code == 200:
                data = resp.json()
                self._token = data.get("data", {}).get("token")
                # Wazuh tokens expire in 900s by default; refresh at 800s
                self._token_expires_at = time.time() + 800
                log.debug("wazuh_authenticated")
                return self._token
            else:
                log.warning("wazuh_auth_failed", status=resp.status_code)
                return None
        except Exception:
            log.exception("wazuh_auth_error")
            return None

    async def _send_batch(self, events: list[RequestEvent]) -> None:
        if not self._client:
            return

        token = await self._get_token()
        if not token:
            log.warning("wazuh_skip_batch", reason="no auth token")
            return

        indexer_url = self._opt("indexer_url") or self._opt("url", "https://localhost:9200")
        index = self._opt("index", "infraguard-events")

        # Build NDJSON bulk payload
        lines: list[str] = []
        for event in events:
            lines.append(json.dumps({"index": {"_index": index}}))
            lines.append(json.dumps(self._event_to_dict(event)))
        body = "\n".join(lines) + "\n"

        headers = {
            "Content-Type": "application/x-ndjson",
            "Authorization": f"Bearer {token}",
        }

        try:
            resp = await self._client.post(
                f"{indexer_url.rstrip('/')}/_bulk",
                content=body,
                headers=headers,
            )
            if resp.status_code >= 400:
                log.warning("wazuh_bulk_error", status=resp.status_code)
            else:
                log.debug("wazuh_bulk_sent", events=len(events))
        except Exception:
            log.exception("wazuh_send_error", events=len(events))
