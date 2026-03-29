"""Base class for plugins that forward RequestEvents to external systems."""

from __future__ import annotations

from typing import Any

import httpx
import structlog

from infraguard.models.events import RequestEvent
from infraguard.plugins.base import BasePlugin

log = structlog.get_logger()


class ForwardingPlugin(BasePlugin):
    """Base for plugins that forward events to external systems.

    Provides event filtering, config access, event serialization,
    and an httpx.AsyncClient lifecycle.
    """

    def __init__(self):
        self._settings: Any = None
        self._event_filter: Any = None
        self._client: httpx.AsyncClient | None = None

    def configure(self, settings: Any) -> None:
        self._settings = settings
        self._event_filter = getattr(settings, "event_filter", None)

    def _opt(self, key: str, default: Any = None) -> Any:
        """Read a value from plugin_settings.options."""
        if self._settings and hasattr(self._settings, "options"):
            return self._settings.options.get(key, default)
        return default

    def _should_forward(self, event: RequestEvent) -> bool:
        """Apply the EventFilterConfig to decide if this event is forwarded."""
        ef = self._event_filter
        if ef is None:
            return True
        if ef.only_blocked and event.filter_result != "block":
            return False
        if ef.only_allowed and event.filter_result != "allow":
            return False
        if ef.min_score is not None and event.filter_score < ef.min_score:
            return False
        if ef.include_domains and event.domain not in ef.include_domains:
            return False
        if ef.exclude_domains and event.domain in ef.exclude_domains:
            return False
        return True

    @staticmethod
    def _event_to_dict(event: RequestEvent) -> dict[str, Any]:
        """Serialize a RequestEvent to a JSON-friendly dict."""
        return {
            "timestamp": event.timestamp.isoformat(),
            "domain": event.domain,
            "client_ip": event.client_ip,
            "method": event.method,
            "uri": event.uri,
            "user_agent": event.user_agent,
            "filter_result": event.filter_result,
            "filter_reason": event.filter_reason,
            "filter_score": event.filter_score,
            "response_status": event.response_status,
            "duration_ms": event.duration_ms,
        }

    async def on_startup(self) -> None:
        self._client = httpx.AsyncClient(timeout=httpx.Timeout(10.0))

    async def on_shutdown(self) -> None:
        if self._client:
            await self._client.aclose()
