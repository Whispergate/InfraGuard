"""Lightweight ML bot / scanner / human classifier.

Trains a logistic-regression model on request features that historically
distinguish scanner traffic from beacon and human traffic. Ships with a
baseline model derived from labelled sample data under
``infraguard/plugins/builtin/models/bot_classifier_baseline.json``; the
operator can retrain from their own tracking DB with
``infraguard preflight`` output as ground truth.

Features (all cheap to compute in the hot path):

  * header_count: number of request headers
  * has_referer: 0/1
  * has_cookie:  0/1
  * has_accept_language: 0/1
  * ua_length:   len(user-agent) / 200 (clamped)
  * ua_has_slash: 0/1 (curl/1.2, wget/2.3, python-requests/2.31 all have '/')
  * ua_has_paren: 0/1 (browsers include "Mozilla (compatible; ...)" style)
  * uri_depth:   path.count('/')
  * uri_has_ext: 0/1 (path ends with a common asset ext)

The model is a single-layer logistic regression, so inference is one
dot product + sigmoid. No sklearn or numpy required at runtime.
"""

from __future__ import annotations

import json
import math
from pathlib import Path
from typing import Any

import structlog

from infraguard.models.common import FilterResult
from infraguard.pipeline.base import RequestContext
from infraguard.plugins.base import BasePlugin

log = structlog.get_logger()

# Baseline weights fit on a small labelled sample (curl, wget, sqlmap,
# nuclei, python-requests, real Chrome / Firefox / Safari). Deliberately
# small; operators retrain on their own traffic for better precision.
_BASELINE = {
    "intercept": -1.10,
    "weights": {
        "header_count":         -0.20,
        "has_referer":          -0.50,
        "has_cookie":           -0.60,
        "has_accept_language":  -0.55,
        "ua_length":            -0.60,
        "ua_has_slash":          1.70,
        "ua_has_paren":         -0.90,
        "uri_depth":            -0.10,
        "uri_has_ext":          -0.30,
    },
}

_ASSET_EXTS = (
    ".css", ".js", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".woff",
    ".woff2", ".ico", ".webp", ".map",
)


class Plugin(BasePlugin):
    name = "ml_bot_classifier"
    version = "1.0.0"

    def __init__(self) -> None:
        self._settings: Any = None
        self._weights: dict[str, float] = dict(_BASELINE["weights"])
        self._intercept: float = float(_BASELINE["intercept"])
        self._threshold: float = 0.7   # >= threshold => bot
        self._action: str = "suspect"  # suspect | block | log-only

    def configure(self, settings: Any) -> None:
        self._settings = settings
        opts = getattr(settings, "options", None)
        if opts is None:
            return
        self._threshold = float(opts.get("threshold", self._threshold))
        self._action = opts.get("action", self._action)
        model_path = opts.get("model")
        if model_path:
            self._load_model(Path(model_path))

    def _load_model(self, path: Path) -> None:
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            self._weights = {str(k): float(v) for k, v in data["weights"].items()}
            self._intercept = float(data.get("intercept", 0.0))
            log.info("ml_bot_classifier_model_loaded", path=str(path))
        except Exception as exc:
            log.warning("ml_bot_classifier_model_load_failed",
                        path=str(path), error=str(exc))

    async def on_request(self, ctx: RequestContext) -> FilterResult | None:
        feats = _extract_features(ctx)
        score = self._intercept
        for k, v in feats.items():
            score += self._weights.get(k, 0.0) * v
        prob = 1.0 / (1.0 + math.exp(-score))
        ctx.metadata["bot_prob"] = prob
        if prob < self._threshold:
            return None

        reason = f"ML bot classifier prob={prob:.2f}"
        if self._action == "block":
            return FilterResult.block(reason=reason, filter_name=self.name, score=prob)
        if self._action == "suspect":
            return FilterResult.suspect(reason=reason, filter_name=self.name, score=prob)
        log.info("ml_bot_classifier_log_only", prob=prob, client=str(ctx.client_ip))
        return None


def _extract_features(ctx: RequestContext) -> dict[str, float]:
    r = ctx.request
    ua = r.headers.get("user-agent", "")
    path = r.url.path
    return {
        "header_count":        min(len(r.headers), 30) / 30.0,
        "has_referer":         1.0 if "referer" in r.headers else 0.0,
        "has_cookie":          1.0 if "cookie" in r.headers else 0.0,
        "has_accept_language": 1.0 if "accept-language" in r.headers else 0.0,
        "ua_length":           min(len(ua), 200) / 200.0,
        "ua_has_slash":        1.0 if "/" in ua else 0.0,
        "ua_has_paren":        1.0 if "(" in ua else 0.0,
        "uri_depth":           min(path.count("/"), 10) / 10.0,
        "uri_has_ext":         1.0 if path.lower().endswith(_ASSET_EXTS) else 0.0,
    }
