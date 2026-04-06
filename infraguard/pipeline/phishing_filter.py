"""Phishing path filter - replaces ProfileFilter for phishing domains.

Instead of validating C2 profile URI/header conformance, this filter
checks whether the request path matches the phishing framework's
allowed patterns. Passthrough mode allows all paths.
"""

from __future__ import annotations

from infraguard.models.common import FilterResult
from infraguard.pipeline.base import RequestContext
from infraguard.profiles.phishing import PhishingProfile


class PhishingFilter:
    """Filter that validates requests against phishing framework path patterns."""

    name = "phishing"

    def __init__(self, phishing_profile: PhishingProfile) -> None:
        self._profile = phishing_profile

    async def check(self, ctx: RequestContext) -> FilterResult:
        path = ctx.request.url.path

        if self._profile.matches(path):
            return FilterResult.allow(filter_name=self.name)

        return FilterResult.block(
            reason=f"Path '{path}' not allowed by {self._profile.name} profile",
            filter_name=self.name,
            score=1.0,
        )
