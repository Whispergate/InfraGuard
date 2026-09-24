"""YARA rule scanner for request bodies and upstream responses.

Two use cases:

1. Catch defenders probing our redirector with known-bad payloads
   (Metasploit exploits, common webshell uploads, etc.) so we can
   fingerprint them into the blocklist.
2. Validate that the C2 payload we serve is not matching a public
   signature. If it is, that beacon is going to get lit up on the
   target host anyway better to know before shipping.

The plugin is a no-op if the ``yara-python`` package is not installed;
we log a warning at startup and disable the hooks. This keeps
InfraGuard's install surface small (yara has native deps).

Config:

    plugins:
      - name: yara_scan
        options:
          rules_dir: /etc/infraguard/yara     # scans *.yar files
          scan_requests: true                 # scan inbound bodies
          scan_responses: false               # scan upstream responses (perf hit)
          action_on_request_hit: block        # block | suspect | log-only
          max_body_bytes: 1048576             # 1 MiB per request
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import structlog

from infraguard.models.common import FilterResult
from infraguard.pipeline.base import RequestContext
from infraguard.plugins.base import BasePlugin

log = structlog.get_logger()


class Plugin(BasePlugin):
    name = "yara_scan"
    version = "1.0.0"

    def __init__(self) -> None:
        self._settings: Any = None
        self._rules = None
        self._yara = None

    def configure(self, settings: Any) -> None:
        self._settings = settings

    def _opt(self, key: str, default: Any = None) -> Any:
        if self._settings and hasattr(self._settings, "options"):
            return self._settings.options.get(key, default)
        return default

    async def on_startup(self) -> None:
        try:
            import yara  # type: ignore
        except ImportError:
            log.warning(
                "yara_scan_disabled_no_yara_python",
                install="pip install yara-python",
            )
            return
        self._yara = yara

        rules_dir = self._opt("rules_dir")
        if not rules_dir:
            log.warning("yara_scan_no_rules_dir")
            return
        rule_files = sorted(str(p) for p in Path(rules_dir).glob("*.yar"))
        if not rule_files:
            log.warning("yara_scan_no_rule_files", dir=rules_dir)
            return
        try:
            # Compile all rules into one namespaced object.
            self._rules = yara.compile(filepaths={
                Path(p).stem: p for p in rule_files
            })
            log.info("yara_rules_loaded", count=len(rule_files))
        except Exception as exc:
            log.warning("yara_compile_failed", error=str(exc))

    async def on_request(self, ctx: RequestContext) -> FilterResult | None:
        if self._rules is None or not self._opt("scan_requests", True):
            return None
        body: bytes = ctx.metadata.get("body", b"") or b""
        cap = int(self._opt("max_body_bytes", 1_048_576))
        if len(body) > cap:
            body = body[:cap]
        if not body:
            return None
        try:
            matches = self._rules.match(data=body, timeout=2)
        except Exception as exc:
            log.debug("yara_match_error", error=str(exc))
            return None
        if not matches:
            return None
        names = ", ".join(m.rule for m in matches[:5])
        action = self._opt("action_on_request_hit", "block")
        log.warning("yara_request_match", rules=names, client=str(ctx.client_ip))
        if action == "block":
            return FilterResult.block(
                reason=f"YARA: {names}", filter_name=self.name, score=1.0,
            )
        if action == "suspect":
            return FilterResult.suspect(
                reason=f"YARA: {names}", filter_name=self.name, score=0.6,
            )
        return None  # log-only
