"""Record allowed requests to a rotating JSONL file for later replay.

Enables the (planned) ``infraguard replay`` command: change a profile,
replay the recorded traffic through the pipeline, see how many
formerly-allowed beacons the new profile blocks.

Records only ALLOWED events (blocks are already in the tracking DB
with reasons). File rotates by size to avoid unbounded growth.

Config:

    plugins:
      - name: request_recorder
        options:
          path: /var/log/infraguard/allowed.jsonl
          max_mib: 100
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

import structlog

from infraguard.models.events import RequestEvent
from infraguard.plugins.base import BasePlugin

log = structlog.get_logger()


class Plugin(BasePlugin):
    name = "request_recorder"
    version = "1.0.0"

    def __init__(self) -> None:
        self._settings: Any = None
        self._path: Path | None = None

    def configure(self, settings: Any) -> None:
        self._settings = settings

    def _opt(self, key: str, default: Any = None) -> Any:
        if self._settings and hasattr(self._settings, "options"):
            return self._settings.options.get(key, default)
        return default

    async def on_startup(self) -> None:
        p = self._opt("path")
        if p:
            self._path = Path(p)
            self._path.parent.mkdir(parents=True, exist_ok=True)

    async def on_event(self, event: RequestEvent) -> None:
        if self._path is None:
            return
        if event.filter_result != "allow":
            return
        self._maybe_rotate()
        try:
            with self._path.open("a", encoding="utf-8") as f:
                f.write(json.dumps({
                    "ts":     event.timestamp,
                    "domain": event.domain,
                    "method": event.method,
                    "uri":    event.uri,
                    "ua":     event.user_agent,
                    "ip":     event.client_ip,
                    "score":  event.filter_score,
                }, separators=(",", ":")))
                f.write("\n")
        except OSError as exc:
            log.debug("request_recorder_write_failed", error=str(exc))

    def _maybe_rotate(self) -> None:
        if self._path is None or not self._path.exists():
            return
        cap_mib = int(self._opt("max_mib", 100))
        try:
            if self._path.stat().st_size >= cap_mib * 1024 * 1024:
                rotated = self._path.with_suffix(self._path.suffix + ".1")
                if rotated.exists():
                    rotated.unlink()
                os.rename(self._path, rotated)
        except OSError as exc:
            log.debug("request_recorder_rotate_failed", error=str(exc))
