"""Evaluate the pipeline as-if a filter were active, without blocking.

Lets operators tune scoring thresholds risk-free. Every request runs
through the real pipeline (unchanged); this plugin then re-scores it
with a shadow config the operator supplies. The delta is logged and
emitted as a Prometheus counter so a Grafana panel can show:

    "if I raised block_score_threshold from 0.7 to 0.85, requests
     from IP 1.2.3.4 would now pass."

Config:

    plugins:
      - name: shadow_block
        options:
          shadow_threshold: 0.85     # what-if score
          only_currently_blocked: true
          log_hits: true
"""

from __future__ import annotations

from typing import Any

import structlog

from infraguard.pipeline.base import RequestContext
from infraguard.plugins.base import BasePlugin

log = structlog.get_logger()


class Plugin(BasePlugin):
    name = "shadow_block"
    version = "1.0.0"

    def __init__(self) -> None:
        self._settings: Any = None
        self._delta_count = 0

    def configure(self, settings: Any) -> None:
        self._settings = settings

    def _opt(self, key: str, default: Any = None) -> Any:
        if self._settings and hasattr(self._settings, "options"):
            return self._settings.options.get(key, default)
        return default

    async def on_request(self, ctx: RequestContext) -> None:
        # Shadow logic runs post-pipeline; hook on_response instead so
        # we can read the real score. We record intent here and act in
        # on_response.
        return None

    async def on_response(self, ctx: RequestContext, response) -> None:
        # The pipeline stores the last-evaluated result on ctx.metadata
        # under "pipeline_result" (Router does this after evaluate()).
        pipeline_result = ctx.metadata.get("pipeline_result")
        if pipeline_result is None:
            return None
        shadow_threshold = float(self._opt("shadow_threshold", 0.85))
        real_score = float(getattr(pipeline_result, "total_score", 0.0))
        was_blocked = not getattr(pipeline_result, "allowed", True)
        would_block = real_score >= shadow_threshold
        if was_blocked != would_block:
            self._delta_count += 1
            if self._opt("log_hits", True):
                log.info(
                    "shadow_block_delta",
                    client=str(ctx.client_ip),
                    real_blocked=was_blocked,
                    shadow_blocked=would_block,
                    real_score=real_score,
                    shadow_threshold=shadow_threshold,
                )
        return None
