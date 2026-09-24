"""Cadence-based beacon-vs-human classifier.

A real Cobalt Strike beacon at ``sleep 60 jitter 20`` produces requests
at 48-72 second intervals with a distinctive standard deviation. Real
browsers do not do that. Very cheap detection when it fires: only cost
is a moving-window ring buffer per source.

Config:

    plugins:
      - name: timing_profiler
        options:
          window: 5           # minimum samples before we decide
          low_cv:  0.02       # coefficient-of-variation floor for "too regular"
          high_cv: 0.60       # ceiling for "too erratic to be a beacon"
          interval_min_sec: 10
          interval_max_sec: 3600
          action: suspect     # suspect | block | log-only
"""

from __future__ import annotations

import statistics
import time
from collections import defaultdict, deque
from typing import Any

import structlog

from infraguard.models.common import FilterResult
from infraguard.pipeline.base import RequestContext
from infraguard.plugins.base import BasePlugin

log = structlog.get_logger()


class Plugin(BasePlugin):
    name = "timing_profiler"
    version = "1.0.0"

    def __init__(self) -> None:
        self._settings: Any = None
        # per-source ring buffer of arrival times
        self._buffers: dict[str, deque[float]] = defaultdict(lambda: deque(maxlen=12))

    def configure(self, settings: Any) -> None:
        self._settings = settings

    def _opt(self, key: str, default: Any = None) -> Any:
        if self._settings and hasattr(self._settings, "options"):
            return self._settings.options.get(key, default)
        return default

    async def on_request(self, ctx: RequestContext) -> FilterResult | None:
        window = int(self._opt("window", 5))
        low_cv = float(self._opt("low_cv", 0.02))
        high_cv = float(self._opt("high_cv", 0.60))
        interval_min = float(self._opt("interval_min_sec", 10))
        interval_max = float(self._opt("interval_max_sec", 3600))
        action = self._opt("action", "suspect")

        key = str(ctx.client_ip)
        now = time.time()
        buf = self._buffers[key]
        buf.append(now)

        if len(buf) < window:
            return None

        # Compute inter-arrival intervals; drop any implausible ones.
        intervals = [buf[i] - buf[i - 1] for i in range(1, len(buf))]
        intervals = [i for i in intervals if interval_min <= i <= interval_max]
        if len(intervals) < window - 1:
            return None

        mean = statistics.mean(intervals)
        try:
            stdev = statistics.stdev(intervals)
        except statistics.StatisticsError:
            return None
        if mean <= 0:
            return None
        cv = stdev / mean

        # A CS-shaped beacon lands near cv=0.15 (jitter=15%). Users who
        # explicitly set jitter=0 produce cv=0. Real human traffic is
        # highly bursty (cv > 0.6 in practice).
        is_beacon_shaped = low_cv <= cv <= high_cv
        if not is_beacon_shaped:
            return None

        reason = f"timing profile (mean={mean:.1f}s cv={cv:.2f})"
        log.info("timing_profiler_beacon_shape", client=key, mean=mean, cv=cv)
        if action == "block":
            return FilterResult.block(reason=reason, filter_name=self.name, score=0.7)
        if action == "suspect":
            return FilterResult.suspect(reason=reason, filter_name=self.name, score=0.4)
        return None
