"""Textual widget: per-domain burn-score sparkline.

Reads :class:`~infraguard.intel.burn_scorer.BurnScorer` and renders a
compact one-line-per-domain view suitable for the TUI's main screen:

    banking.corp     score=0.42 ###################...............
    cdn.example      score=0.81 ################################### warn

Uses Textual's Static widget refreshes every ``interval`` seconds.
"""

from __future__ import annotations

from typing import Any

try:
    from textual.reactive import reactive
    from textual.widget import Widget
    _TEXTUAL = True
except ImportError:
    _TEXTUAL = False
    Widget = object  # type: ignore
    def reactive(*_a, **_k):  # type: ignore
        def _decorator(x): return x
        return _decorator


BAR_WIDTH = 40
_WARN_THRESHOLD = 0.7


class BurnScoreWidget(Widget):
    """Per-domain burn-score bar chart. Auto-refreshes."""

    interval: float = 5.0

    if _TEXTUAL:
        scores: reactive[dict[str, float]] = reactive({})

    def __init__(self, scorer: Any = None, **kwargs):
        super().__init__(**kwargs)
        self._scorer = scorer

    def on_mount(self) -> None:  # Textual lifecycle
        if _TEXTUAL:
            self.set_interval(self.interval, self._refresh)
            self._refresh()

    def _refresh(self) -> None:
        if self._scorer is None:
            return
        try:
            snapshot = self._scorer.all_scores() if hasattr(self._scorer, "all_scores") else {}
        except Exception:
            snapshot = {}
        if _TEXTUAL:
            self.scores = dict(snapshot)

    def render(self) -> str:
        if not _TEXTUAL:
            return "(textual not installed)"
        lines: list[str] = []
        for domain in sorted(self.scores):
            score = float(self.scores[domain])
            width = int(score * BAR_WIDTH)
            bar = "#" * width + "." * (BAR_WIDTH - width)
            marker = "  warn" if score >= _WARN_THRESHOLD else ""
            lines.append(f"{domain[:24]:<24} score={score:.2f} {bar}{marker}")
        if not lines:
            return "(no burn data yet)"
        return "\n".join(lines)
