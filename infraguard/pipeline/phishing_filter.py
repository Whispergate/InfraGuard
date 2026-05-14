"""Phishing path filter - replaces ProfileFilter for phishing domains.

Instead of validating C2 profile URI/header conformance, this filter
checks whether the request path matches the phishing framework's
allowed patterns. Passthrough mode allows all paths.

Optionally validates per-campaign tokens embedded in phishing URLs to
prevent analysts from loading phishing pages without the token that
was included in the actual phishing email link.
"""

from __future__ import annotations

import hashlib
import hmac
import time

import structlog

from infraguard.models.common import FilterResult
from infraguard.pipeline.base import RequestContext
from infraguard.profiles.phishing import PhishingProfile

log = structlog.get_logger()


class PhishingFilter:
    """Filter that validates requests against phishing framework path patterns."""

    name = "phishing"

    def __init__(self, phishing_profile: PhishingProfile) -> None:
        self._profile = phishing_profile

    async def check(self, ctx: RequestContext) -> FilterResult:
        path = ctx.request.url.path

        if not self._profile.matches(path):
            return FilterResult.block(
                reason=f"Path '{path}' not allowed by {self._profile.name} profile",
                filter_name=self.name,
                score=1.0,
            )

        # Campaign token validation (optional - only when configured)
        ct = ctx.domain_config.campaign_token
        if ct.enabled:
            result = self._check_campaign_token(ctx, ct)
            if result is not None:
                return result

        return FilterResult.allow(filter_name=self.name)

    def _check_campaign_token(self, ctx: RequestContext, ct) -> FilterResult | None:
        """Return a FilterResult if the campaign token is missing or invalid, else None."""
        token = ctx.request.query_params.get(ct.token_param)

        if not token:
            log.info(
                "campaign_token_missing",
                ip=str(ctx.client_ip),
                path=ctx.request.url.path,
            )
            return FilterResult.suspect(
                reason="Missing campaign token in URL",
                filter_name=self.name,
                score=ct.score_on_missing,
            )

        if self._validate_token(token, ct):
            return None  # valid - continue pipeline

        log.warning(
            "campaign_token_invalid",
            ip=str(ctx.client_ip),
            path=ctx.request.url.path,
        )
        return FilterResult.block(
            reason="Invalid campaign token",
            filter_name=self.name,
            score=1.0,
        )

    @staticmethod
    def _validate_token(token: str, ct) -> bool:
        # Static token list check
        if ct.tokens and token in ct.tokens:
            return True
        # HMAC-based time-limited token
        if ct.hmac_secret:
            return PhishingFilter._validate_hmac_token(token, ct)
        return False

    @staticmethod
    def _validate_hmac_token(token: str, ct) -> bool:
        """Validate HMAC token format: <payload>.<ts>.<sig> (base64url-free variant).

        Token structure: "{payload}:{timestamp}:{hmac_hex}"
        where hmac = HMAC-SHA256(secret, payload:timestamp)
        """
        try:
            parts = token.split(":")
            if len(parts) != 3:
                return False
            payload, ts_str, sig_hex = parts
            ts = int(ts_str)
            if abs(time.time() - ts) > ct.hmac_ttl_seconds:
                return False
            expected = hmac.new(
                ct.hmac_secret.encode(),
                f"{payload}:{ts_str}".encode(),
                hashlib.sha256,
            ).hexdigest()
            return hmac.compare_digest(expected, sig_hex)
        except Exception:
            return False
