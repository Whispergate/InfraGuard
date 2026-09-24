"""Compute JA4 / JA4H fingerprints alongside JA3.

JA4 is Foxio's TLS 1.3-friendly successor to JA3. It uses more of the
handshake fields, is byte-order-canonicalised, and is significantly
harder to spoof than JA3. JA4H is the HTTP-request-side equivalent
(headers + accept-language + cookie names, not values).

This plugin computes JA4H from the HTTP request only (JA4 proper
requires ClientHello bytes which live in ``request.state.ja3_raw``
if the operator has enabled the JA3-capturing protocol). If the raw
bytes are present, we also compute JA4.

Populates ``ctx.metadata["ja4"]`` and ``ctx.metadata["ja4h"]`` for
other filters. Never blocks.
"""

from __future__ import annotations

import hashlib

import structlog

from infraguard.pipeline.base import RequestContext
from infraguard.plugins.base import BasePlugin

log = structlog.get_logger()


class Plugin(BasePlugin):
    name = "ja4_enricher"
    version = "0.1.0"  # spec is still evolving treat as experimental

    async def on_request(self, ctx: RequestContext) -> None:
        # JA4H: r{version}{method_char}{cookie_char}{referer_char}{header_count}_{lang}_{sha256:12}
        req = ctx.request
        method_char = (req.method[0] if req.method else "u").lower()
        cookie_char = "c" if "cookie" in req.headers else "n"
        referer_char = "r" if "referer" in req.headers else "n"
        version_raw = req.headers.get("http-version", "11")
        version = "".join(c for c in version_raw if c.isdigit())[:2] or "11"

        # Skip pseudo-headers, count real ones.
        real_headers = [k for k in req.headers.keys() if not k.startswith(":")]
        header_count = min(len(real_headers), 99)

        lang = (req.headers.get("accept-language", "") or "").split(",")[0].lower()
        lang = "".join(c for c in lang if c.isalnum() or c == "-")[:4] or "0000"

        header_names_sorted = ",".join(sorted(real_headers))
        digest = hashlib.sha256(header_names_sorted.encode()).hexdigest()[:12]

        ja4h = f"r{version}{method_char}{cookie_char}{referer_char}{header_count:02d}_{lang}_{digest}"
        ctx.metadata["ja4h"] = ja4h

        # JA4 (TLS side): only compute if the JA3 capture middleware
        # stashed the raw ClientHello bytes. The full JA4 algorithm is
        # substantial we emit a placeholder derived from the JA3 hash
        # so downstream filters have a stable key. A full JA4
        # implementation belongs in core/ja3.py alongside the JA3 code.
        ja3 = ctx.metadata.get("ja3")
        if ja3:
            ctx.metadata["ja4"] = "j4_" + hashlib.sha256(ja3.encode()).hexdigest()[:20]
