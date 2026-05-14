"""TLS ClientHello / JA3 fingerprint filter.

Blocks known scanner tools at the TLS handshake layer - before any HTTP data
is exchanged and before the C2 profile pipeline runs. JA3 hashes are injected
into request state by JA3InjectionMiddleware (infraguard/core/middleware.py)
using the registry populated by JA3InjectingProtocol.

Known scanner JA3 hashes (seed set - extend via config):
  e7d705a3286e19ea42f587b344ee6865  Masscan
  6734f37431670b3ab4292b8f60f29984  Python requests (default SSL context)
  b386946a5a44d1ddcc843bc75336dfce  curl (Linux default)
  c35b0c7bd583d49d5b0f17de25ecdf7a  ZGrab2
  07b8a29f8a4b7eb7d9bd0b11a4e03399  Nmap TLS probe
  19e29534fd49dd27d09234e639c4057e  Shodan scanner
"""

from __future__ import annotations

import structlog

from infraguard.models.common import FilterResult
from infraguard.pipeline.base import RequestContext

log = structlog.get_logger()

# Known scanner JA3 fingerprints (MD5 hex strings)
_DEFAULT_BLOCKED_JA3: frozenset[str] = frozenset({
    "e7d705a3286e19ea42f587b344ee6865",  # Masscan
    "6734f37431670b3ab4292b8f60f29984",  # Python requests
    "b386946a5a44d1ddcc843bc75336dfce",  # curl
    "c35b0c7bd583d49d5b0f17de25ecdf7a",  # ZGrab2
    "07b8a29f8a4b7eb7d9bd0b11a4e03399",  # Nmap
    "19e29534fd49dd27d09234e639c4057e",  # Shodan
})


class TLSFilter:
    """Filter based on TLS ClientHello JA3 fingerprint.

    The JA3 hash is read from ``ctx.metadata["ja3"]`` which is populated by
    JA3InjectionMiddleware. If no hash is present (plain HTTP or JA3 capture
    failed), the filter passes through silently.
    """

    name = "tls"

    def __init__(
        self,
        blocked_ja3: set[str] | None = None,
        allowed_ja3: set[str] | None = None,
        log_ja3: bool = True,
        block_unknown: bool = False,
    ) -> None:
        self._blocked = (_DEFAULT_BLOCKED_JA3 | (blocked_ja3 or set()))
        self._allowed = allowed_ja3  # None = no allowlist (beacon JA3 not enforced)
        self._log_ja3 = log_ja3
        self._block_unknown = block_unknown

    async def check(self, ctx: RequestContext) -> FilterResult:
        ja3 = ctx.metadata.get("ja3")

        if ja3 is None:
            # No JA3 captured (plain HTTP connection or capture failed)
            return FilterResult.allow(filter_name=self.name)

        if self._log_ja3:
            log.debug("ja3_seen", ja3=ja3, ip=str(ctx.client_ip))

        if ja3 in self._blocked:
            log.warning("ja3_blocked", ja3=ja3, ip=str(ctx.client_ip))
            return FilterResult.block(
                reason=f"Blocked TLS fingerprint (JA3: {ja3})",
                filter_name=self.name,
                score=1.0,
            )

        if self._allowed is not None and ja3 not in self._allowed:
            if self._block_unknown:
                log.warning("ja3_unknown_blocked", ja3=ja3, ip=str(ctx.client_ip))
                return FilterResult.block(
                    reason=f"Unknown TLS fingerprint (JA3: {ja3})",
                    filter_name=self.name,
                    score=1.0,
                )
            # Suspicious but not hard-blocked - add a small score
            return FilterResult.suspect(
                reason=f"Unknown TLS fingerprint (JA3: {ja3})",
                filter_name=self.name,
                score=0.25,
            )

        return FilterResult.allow(filter_name=self.name)
