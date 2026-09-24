"""Proof-of-work JavaScript challenge for suspect requests.

A cheap browser (< 100ms of one CPU) can solve it; a headless-scanner
fleet that reissues without a JS engine cannot. Not a CAPTCHA, so no
accessibility issue.

Flow:

1. Request comes in scored ``suspect`` (or above threshold) by the
   pipeline.
2. If the request has no ``x-igjs`` header carrying a valid proof,
   we return an HTML page that runs a small SHA-256 hashcash loop
   in the browser, then reloads with ``x-igjs`` set.
3. Second request carries the header, we validate it, allow through.

Uses HMAC(secret, IP + hour_bucket) as the challenge nonce so proofs
naturally expire and cannot be replayed across attackers.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import time
from typing import Any

import structlog
from starlette.responses import HTMLResponse

from infraguard.pipeline.base import RequestContext
from infraguard.plugins.base import BasePlugin

log = structlog.get_logger()

_HTML_TEMPLATE = """<!doctype html>
<html><head><meta name="viewport" content="width=device-width"><title>Loading</title>
<style>body{{font-family:sans-serif;color:#666;text-align:center;margin-top:15%}}</style></head>
<body><p>Verifying you are not a robot...</p>
<script>
(async () => {{
  const nonce = "{nonce}";
  const difficulty = {difficulty};
  const target = "0".repeat(difficulty);
  const enc = new TextEncoder();
  for (let i = 0; ; i++) {{
    const msg = nonce + ":" + i;
    const digest = await crypto.subtle.digest("SHA-256", enc.encode(msg));
    const hex = [...new Uint8Array(digest)].map(b => b.toString(16).padStart(2, "0")).join("");
    if (hex.startsWith(target)) {{
      document.cookie = "ig_pow=" + msg + "; path=/; max-age=3600; SameSite=Lax";
      location.reload();
      return;
    }}
  }}
}})();
</script></body></html>
"""


class Plugin(BasePlugin):
    name = "js_challenge"
    version = "1.0.0"

    def __init__(self) -> None:
        self._settings: Any = None
        self._secret = os.urandom(16)

    def configure(self, settings: Any) -> None:
        self._settings = settings

    def _opt(self, key: str, default: Any = None) -> Any:
        if self._settings and hasattr(self._settings, "options"):
            return self._settings.options.get(key, default)
        return default

    def _nonce_for(self, client_ip: str) -> str:
        # Rebuilt each hour so a solve does not amortize forever.
        bucket = int(time.time()) // 3600
        return hmac.new(
            self._secret, f"{client_ip}:{bucket}".encode(), hashlib.sha256
        ).hexdigest()[:24]

    async def on_response(
        self, ctx: RequestContext, response
    ) -> HTMLResponse | None:
        pr = ctx.metadata.get("pipeline_result")
        if pr is None:
            return None
        # Only challenge SUSPECT responses (score under block, above allow).
        threshold = float(self._opt("challenge_score", 0.4))
        score = float(getattr(pr, "total_score", 0.0))
        if score < threshold or not getattr(pr, "allowed", True):
            return None

        # If the client has already solved this hour's puzzle, pass.
        cookie = ctx.request.cookies.get("ig_pow", "")
        nonce = self._nonce_for(str(ctx.client_ip))
        if self._valid_pow(cookie, nonce):
            return None

        difficulty = int(self._opt("difficulty", 4))  # 4 hex zeros ~ 4M ops
        html = _HTML_TEMPLATE.format(nonce=nonce, difficulty=difficulty)
        return HTMLResponse(content=html, status_code=200)

    def _valid_pow(self, cookie: str, nonce: str) -> bool:
        if not cookie or ":" not in cookie:
            return False
        # We only need the nonce half; the counter half participates in
        # the hash check further down but is not validated separately.
        n, _counter = cookie.split(":", 1)
        if n != nonce:
            return False
        difficulty = int(self._opt("difficulty", 4))
        digest = hashlib.sha256(cookie.encode()).hexdigest()
        return digest.startswith("0" * difficulty)
