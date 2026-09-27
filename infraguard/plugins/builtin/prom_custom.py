"""Operator-defined Prometheus counters and histograms.

The built-in metrics module covers the standard set (requests, drops,
duration_ms, upstream latency). This plugin lets operators emit
custom-labeled counters from request features without editing code:

    plugins:
      - name: prom_custom
        options:
          counters:
            - name: infraguard_requests_by_country_total
              labels: ["country"]
              from: "metadata.geo.country"
            - name: infraguard_requests_by_beacon_label_total
              labels: ["campaign"]
              from: "metadata.beacon_labels.campaign"

The ``from`` key is a dotted path resolved against the RequestContext
(``client_ip``, ``request.method``, ``metadata.*``).
"""

from __future__ import annotations

from typing import Any

import structlog

from infraguard.pipeline.base import RequestContext
from infraguard.plugins.base import BasePlugin

log = structlog.get_logger()


class Plugin(BasePlugin):
    name = "prom_custom"
    version = "1.0.0"

    def __init__(self) -> None:
        self._settings: Any = None
        self._counters: dict[str, Any] = {}
        self._configs: list[dict] = []

    def configure(self, settings: Any) -> None:
        self._settings = settings

    def _opt(self, key: str, default: Any = None) -> Any:
        if self._settings and hasattr(self._settings, "options"):
            return self._settings.options.get(key, default)
        return default

    async def on_startup(self) -> None:
        try:
            from prometheus_client import Counter
        except ImportError:
            log.warning("prom_custom_disabled_no_prometheus_client")
            return
        for spec in self._opt("counters") or []:
            name = spec.get("name")
            labels = spec.get("labels") or []
            if not name:
                continue
            try:
                self._counters[name] = Counter(name, spec.get("help", name), labels)
                self._configs.append(spec)
            except ValueError:
                # duplicate registration on reload
                log.debug("prom_custom_counter_already_registered", name=name)

    async def on_request(self, ctx: RequestContext) -> None:
        for spec in self._configs:
            counter = self._counters.get(spec["name"])
            if counter is None:
                continue
            value = _resolve_path(ctx, spec.get("from", ""))
            if value is None:
                continue
            labels = spec.get("labels") or []
            if labels:
                try:
                    counter.labels(**{labels[0]: str(value)}).inc()
                except Exception as exc:
                    log.debug("prom_custom_inc_failed", name=spec["name"], error=str(exc))
            else:
                counter.inc()


def _resolve_path(ctx: RequestContext, path: str) -> Any:
    """Resolve ``metadata.geo.country`` etc. against ctx."""
    if not path:
        return None
    parts = path.split(".")
    cur: Any = ctx
    for p in parts:
        if isinstance(cur, dict):
            cur = cur.get(p)
        else:
            cur = getattr(cur, p, None)
        if cur is None:
            return None
    return cur
