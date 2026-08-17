"""Example: Event forwarder plugin that logs to a file.

Demonstrates:
- Extending ForwardingPlugin for file-based event output
- Using _should_forward for event filtering
- Using _event_to_dict for serialization
- Configuring via plugin settings options
"""

from __future__ import annotations

import json
from pathlib import Path

import structlog

from infraguard.models.events import RequestEvent
from infraguard.plugins.builtin._base import ForwardingPlugin

log = structlog.get_logger()


class Plugin(ForwardingPlugin):
    """Appends filtered RequestEvents as JSONL to a local file."""

    name = "file_logger"
    version = "1.0.0"
    _needs_http_client = False

    def configure(self, settings):
        super().configure(settings)
        self._output_path: str = self._opt("output_path", "events.jsonl")
        self._pretty: bool = bool(self._opt("pretty", False))

    async def on_startup(self) -> None:
        # No httpx client needed, but ensure directory exists
        path = Path(self._output_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        log.info("file_logger_started", path=str(path))

    async def on_event(self, event: RequestEvent) -> None:
        if not self._should_forward(event):
            return

        data = self._event_to_dict(event)
        line = (
            json.dumps(data, indent=2 if self._pretty else None, default=str)
            + "\n"
        )

        try:
            with open(self._output_path, "a", encoding="utf-8") as f:
                f.write(line)
        except OSError:
            log.exception("file_logger_write_error", path=self._output_path)

    async def on_shutdown(self) -> None:
        log.info("file_logger_stopped", path=self._output_path)


plugin = Plugin()
