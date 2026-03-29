"""Request validation pipeline framework.

Each filter in the pipeline inspects an incoming request and returns a
FilterResult with a score between 0.0 (definitely legitimate) and 1.0
(definitely malicious). The pipeline runner aggregates scores and makes
a final allow/block decision based on the configured threshold.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from ipaddress import IPv4Address, IPv6Address
from typing import Any, Protocol, runtime_checkable

import structlog
from starlette.requests import Request

from infraguard.config.schema import DomainConfig, PipelineConfig
from infraguard.models.common import FilterAction, FilterResult
from infraguard.profiles.models import C2Profile

log = structlog.get_logger()


@dataclass
class RequestContext:
    """Context passed through the filter pipeline for each request."""

    request: Request
    client_ip: IPv4Address | IPv6Address
    domain_config: DomainConfig
    profile: C2Profile
    metadata: dict[str, Any] = field(default_factory=dict)


@runtime_checkable
class RequestFilter(Protocol):
    """Interface for request validation filters."""

    name: str

    async def check(self, ctx: RequestContext) -> FilterResult: ...


@dataclass
class PipelineResult:
    """Aggregate result from the full filter pipeline."""

    allowed: bool
    total_score: float
    results: list[FilterResult]
    duration_ms: float

    @property
    def blocking_reasons(self) -> list[str]:
        return [
            r.reason
            for r in self.results
            if r.action == FilterAction.BLOCK and r.reason
        ]

    @property
    def summary(self) -> str:
        if self.allowed:
            return f"ALLOW (score={self.total_score:.2f}, {self.duration_ms:.1f}ms)"
        reasons = ", ".join(self.blocking_reasons) or "threshold exceeded"
        return f"BLOCK (score={self.total_score:.2f}, {self.duration_ms:.1f}ms): {reasons}"


class FilterPipeline:
    """Runs a chain of RequestFilters and aggregates results."""

    def __init__(
        self,
        filters: list[RequestFilter],
        config: PipelineConfig,
    ):
        self.filters = filters
        self.config = config

    async def evaluate(self, ctx: RequestContext) -> PipelineResult:
        start = time.perf_counter()
        results: list[FilterResult] = []
        total_score = 0.0

        for f in self.filters:
            try:
                result = await f.check(ctx)
                result.filter_name = f.name
                results.append(result)

                if result.action == FilterAction.BLOCK:
                    # Hard block - short-circuit immediately
                    total_score = max(total_score + result.score, 1.0)
                    break
                else:
                    total_score += result.score

                # Early exit if score already exceeds threshold
                if total_score >= self.config.block_score_threshold:
                    break

            except Exception:
                log.exception("filter_error", filter=f.name)
                # Filter errors don't block - fail open
                continue

        duration_ms = (time.perf_counter() - start) * 1000
        allowed = total_score < self.config.block_score_threshold

        return PipelineResult(
            allowed=allowed,
            total_score=total_score,
            results=results,
            duration_ms=duration_ms,
        )
