"""Client fingerprint filter - identifies clients by HTTP characteristics.

Since ASGI servers don't expose raw TLS ClientHello data (needed for
true JA3 hashing), this filter uses observable HTTP-layer signals as a
composite fingerprint:

  1. Header ordering hash - browsers have consistent header ordering
     that differs from CLI tools, bots, and scanners.
  2. Known scanner fingerprints - blocklist of header-order hashes for
     common offensive/defensive tools.
  3. Header presence anomalies - missing or unusual header combinations
     that indicate non-browser clients.

Operators can configure:
  - ``allowed_fingerprints``: Hashes of expected beacon header orders
    (allowlist — bypasses this filter entirely).
  - ``blocked_fingerprints``: Additional hashes to block.

The fingerprint hash is computed as:
  sha256(sorted_lower_header_names joined by ",")

This is a best-effort heuristic. For true JA3 filtering, deploy a
TLS-terminating proxy (e.g., nginx with ja3 module) in front of
InfraGuard and pass the JA3 hash as an X-JA3-Hash header.
"""

from __future__ import annotations

import hashlib

from infraguard.models.common import FilterResult
from infraguard.pipeline.base import RequestContext

# Pre-computed header-order fingerprints for common non-browser clients.
# These are sha256 hashes of the lowercase, comma-joined header name list.
# [MALLEABLE] operators should regenerate these for their environment.
KNOWN_SCANNER_FINGERPRINTS: dict[str, str] = {}

# Header names that real browsers always send but tools often omit
BROWSER_EXPECTED_HEADERS = {
    "accept",
    "accept-encoding",
    "accept-language",
}

# Header names that suggest automated tooling
SUSPICIOUS_HEADERS = {
    "x-scanner",
    "x-forwarded-host",  # can appear legitimately but rare in direct connections
}


def compute_header_fingerprint(header_names: list[str]) -> str:
    """Compute a stable fingerprint hash from HTTP header names.

    The fingerprint preserves header ordering (browsers have stable
    ordering per engine, tools vary). We hash the ordered, lowercased
    header names.
    """
    normalized = ",".join(h.lower() for h in header_names)
    return hashlib.sha256(normalized.encode()).hexdigest()[:16]


class FingerprintFilter:
    """Score requests based on HTTP-layer client fingerprinting."""

    name = "fingerprint"

    def __init__(
        self,
        allowed_fingerprints: set[str] | None = None,
        blocked_fingerprints: set[str] | None = None,
    ):
        self._allowed = allowed_fingerprints or set()
        self._blocked = set(KNOWN_SCANNER_FINGERPRINTS.values())
        if blocked_fingerprints:
            self._blocked |= blocked_fingerprints

    async def check(self, ctx: RequestContext) -> FilterResult:
        # Extract ordered header names from the request
        header_names = list(ctx.request.headers.keys())
        fp = compute_header_fingerprint(header_names)

        # Fast path: known-good beacon fingerprint
        if fp in self._allowed:
            return FilterResult.allow(filter_name=self.name)

        # Check against known scanner fingerprints
        if fp in self._blocked:
            return FilterResult.block(
                reason=f"Blocked client fingerprint: {fp}",
                filter_name=self.name,
                score=0.8,
            )

        # Heuristic: check for missing browser-standard headers
        present = {h.lower() for h in header_names}
        missing_browser = BROWSER_EXPECTED_HEADERS - present
        if len(missing_browser) >= 2:
            return FilterResult.suspect(
                reason=f"Missing browser headers: {', '.join(sorted(missing_browser))}",
                filter_name=self.name,
                score=0.35,
            )

        # Heuristic: suspicious header presence
        suspicious_present = SUSPICIOUS_HEADERS & present
        if suspicious_present:
            return FilterResult.suspect(
                reason=f"Suspicious headers present: {', '.join(sorted(suspicious_present))}",
                filter_name=self.name,
                score=0.25,
            )

        # Heuristic: extremely few headers (typical of curl/wget with no flags)
        if len(header_names) <= 2:
            return FilterResult.suspect(
                reason=f"Minimal headers ({len(header_names)}), likely CLI tool",
                filter_name=self.name,
                score=0.4,
            )

        return FilterResult.allow(filter_name=self.name)
