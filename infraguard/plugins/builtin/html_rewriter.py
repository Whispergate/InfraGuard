"""Server-side HTML rewriter for decoy responses.

CSS-selector-based rewriter. Common patterns:

  * swap analytics IDs so a shared decoy tree can differ per domain
  * change og:image so social previews of the decoy URL look distinct
  * inject a per-domain banner or notice

Uses BeautifulSoup if available falls back to a small regex path
for the string-set operations if not. Never rewrites non-HTML.

Config:

    plugins:
      - name: html_rewriter
        options:
          rules:
            - select: 'meta[property="og:image"]'
              attr: content
              value: "https://cdn.example.com/og-{domain}.png"
            - select: "script[data-ga-id]"
              attr: "data-ga-id"
              value: "UA-12345-6"
"""

from __future__ import annotations

from typing import Any

import structlog
from starlette.responses import Response

from infraguard.pipeline.base import RequestContext
from infraguard.plugins.base import BasePlugin

log = structlog.get_logger()


class Plugin(BasePlugin):
    name = "html_rewriter"
    version = "1.0.0"

    def __init__(self) -> None:
        self._settings: Any = None
        self._bs4 = None

    def configure(self, settings: Any) -> None:
        self._settings = settings

    def _opt(self, key: str, default: Any = None) -> Any:
        if self._settings and hasattr(self._settings, "options"):
            return self._settings.options.get(key, default)
        return default

    async def on_startup(self) -> None:
        try:
            import bs4  # type: ignore
            self._bs4 = bs4
        except ImportError:
            log.warning("html_rewriter_no_bs4_install", hint="pip install beautifulsoup4")

    async def on_response(
        self, ctx: RequestContext, response: Response
    ) -> Response | None:
        if self._bs4 is None:
            return None
        ct = response.headers.get("content-type", "")
        if "text/html" not in ct.lower():
            return None
        body = getattr(response, "body", None)
        if not body:
            return None
        rules = self._opt("rules") or []
        if not rules:
            return None
        try:
            soup = self._bs4.BeautifulSoup(body, "html.parser")
        except Exception as exc:
            log.debug("html_rewriter_parse_failed", error=str(exc))
            return None

        domain = getattr(ctx, "domain", "") or ""
        for rule in rules:
            selector = rule.get("select")
            if not selector:
                continue
            template = str(rule.get("value", ""))
            value = template.format(domain=domain)
            attr = rule.get("attr")
            for el in soup.select(selector):
                if attr:
                    el[attr] = value
                else:
                    el.string = value

        new_body = str(soup).encode("utf-8")
        response.body = new_body
        response.headers["content-length"] = str(len(new_body))
        return response
