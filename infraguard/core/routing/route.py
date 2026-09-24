"""The :class:`DomainRoute` dataclass - a single domain's runtime bundle."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from infraguard.config.schema import DomainConfig
    from infraguard.core.content_router import ContentRouteResolver
    from infraguard.pipeline.base import FilterPipeline
    from infraguard.profiles.models import C2Profile


class DomainRoute:
    """A single domain's configuration, profile, and pipeline."""

    def __init__(
        self,
        domain: str,
        config: "DomainConfig",
        profile: "C2Profile",
        pipeline: "FilterPipeline",
        content_resolver: "ContentRouteResolver | None" = None,
        fingerprint_pipeline: "FilterPipeline | None" = None,
    ):
        self.domain = domain
        self.config = config
        self.profile = profile
        self.pipeline = pipeline
        self.content_resolver = content_resolver
        self.fingerprint_pipeline = fingerprint_pipeline
