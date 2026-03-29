"""Content route resolver — matches request URIs to content delivery backends.

Supports three pattern types:
- Exact:  ``/file.exe`` — string equality
- Prefix: ``/downloads/*`` — startswith, captures remainder after prefix
- Regex:  ``~^/d/[a-f0-9]+`` — leading ``~`` indicates regex
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Protocol

from starlette.requests import Request

from infraguard.config.schema import ContentRouteConfig
from infraguard.core.content import RouteMatch


@dataclass
class _CompiledPattern:
    """A compiled URI pattern for matching."""

    raw: str
    kind: str  # "exact", "prefix", "regex"
    regex: re.Pattern[str] | None = None
    prefix: str = ""

    def match(self, path: str) -> tuple[bool, str]:
        """Return (matched, remainder) for the given path."""
        if self.kind == "exact":
            if path == self.raw:
                return True, ""
            return False, ""
        elif self.kind == "prefix":
            if path.startswith(self.prefix):
                remainder = path[len(self.prefix) :]
                return True, remainder
            return False, ""
        elif self.kind == "regex" and self.regex:
            m = self.regex.match(path)
            if m:
                return True, m.group("remainder") if "remainder" in m.groupdict() else ""
            return False, ""
        return False, ""


def _compile_pattern(pattern: str) -> _CompiledPattern:
    """Compile a URI pattern string into a matcher."""
    if pattern.startswith("~"):
        # Regex pattern
        raw_regex = pattern[1:]
        return _CompiledPattern(
            raw=pattern,
            kind="regex",
            regex=re.compile(raw_regex),
        )
    elif pattern.endswith("/*"):
        # Prefix glob
        prefix = pattern[:-1]  # "/downloads/*" → "/downloads/"
        return _CompiledPattern(raw=pattern, kind="prefix", prefix=prefix)
    elif "*" in pattern:
        # Convert simple glob to prefix
        prefix = pattern.split("*")[0]
        return _CompiledPattern(raw=pattern, kind="prefix", prefix=prefix)
    else:
        # Exact match
        return _CompiledPattern(raw=pattern, kind="exact")


class ContentRouteResolver:
    """Matches incoming request URIs against configured content routes."""

    def __init__(self, routes: list[ContentRouteConfig]):
        self._routes: list[tuple[ContentRouteConfig, _CompiledPattern]] = []
        for route in routes:
            self._routes.append((route, _compile_pattern(route.path)))

    def match(self, request: Request) -> RouteMatch | None:
        """Return the first matching content route, or None."""
        path = request.url.path
        method = request.method.upper()

        for route, pattern in self._routes:
            if method not in [m.upper() for m in route.methods]:
                continue
            matched, remainder = pattern.match(path)
            if matched:
                return RouteMatch(route=route, path_remainder=remainder)

        return None
