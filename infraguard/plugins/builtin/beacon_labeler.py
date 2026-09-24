"""Tag beacons with operator-supplied metadata at first sight.

At the first request from a new beacon, this plugin records the
operator's per-engagement metadata onto the beacon session. Later
requests are labeled automatically, so the dashboard can show:

    Beacon a1b2c3...  campaign=phantom  target=alice@corp.com  lure=invoice-q1

Label keys come from headers the beacon itself sends (the operator
controls the beacon config, so this is safe) OR from a static
per-domain config block.

Config:

    plugins:
      - name: beacon_labeler
        options:
          static:
            cdn.example.com:
              campaign: phantom-2026
              target_group: finance
          header_map:
            campaign: x-igb-campaign
            target:   x-igb-target
"""

from __future__ import annotations

from typing import Any

import structlog

from infraguard.pipeline.base import RequestContext
from infraguard.plugins.base import BasePlugin

log = structlog.get_logger()


class Plugin(BasePlugin):
    name = "beacon_labeler"
    version = "1.0.0"

    def __init__(self) -> None:
        self._settings: Any = None

    def configure(self, settings: Any) -> None:
        self._settings = settings

    def _opt(self, key: str, default: Any = None) -> Any:
        if self._settings and hasattr(self._settings, "options"):
            return self._settings.options.get(key, default)
        return default

    async def on_request(self, ctx: RequestContext) -> None:
        labels: dict[str, str] = {}

        # Static per-domain labels: applied unconditionally.
        static = (self._opt("static") or {}).get(getattr(ctx, "domain", ""), {})
        if isinstance(static, dict):
            labels.update({str(k): str(v) for k, v in static.items()})

        # Dynamic labels pulled from beacon-set headers.
        header_map = self._opt("header_map") or {}
        for label_key, header_name in header_map.items():
            v = ctx.request.headers.get(header_name)
            if v:
                labels[str(label_key)] = str(v)[:120]

        if labels:
            ctx.metadata.setdefault("beacon_labels", {}).update(labels)
