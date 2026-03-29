"""Domain-based request routing.

Routes incoming requests to the correct DomainConfig based on the Host
header. Each domain has its own C2 profile and filter pipeline instance.
"""

from __future__ import annotations

from ipaddress import IPv4Address, IPv6Address, ip_address
from pathlib import Path

import structlog
from starlette.requests import Request
from starlette.responses import Response

import time

from infraguard.config.schema import DomainConfig, InfraGuardConfig, PipelineConfig
from infraguard.core.drop import handle_drop
from infraguard.core.proxy import ProxyHandler
from infraguard.intel.ip_lists import CIDRList
from infraguard.intel.manager import IntelManager
from infraguard.models.common import DropActionType
from infraguard.models.events import RequestEvent
from infraguard.pipeline.base import FilterPipeline, RequestContext
from infraguard.pipeline.bot_filter import BotFilter
from infraguard.pipeline.dns_filter import DNSFilter
from infraguard.pipeline.header_filter import HeaderFilter
from infraguard.pipeline.ip_filter import IPFilter
from infraguard.pipeline.profile_filter import ProfileFilter
from infraguard.pipeline.replay_filter import ReplayFilter
from infraguard.profiles.cobalt_strike import parse_cobalt_strike_file
from infraguard.profiles.models import C2Profile
from infraguard.tracking.recorder import EventRecorder
from infraguard.profiles.mythic import parse_mythic_file

log = structlog.get_logger()


class DomainRoute:
    """A single domain's configuration, profile, and pipeline."""

    def __init__(
        self,
        domain: str,
        config: DomainConfig,
        profile: C2Profile,
        pipeline: FilterPipeline,
    ):
        self.domain = domain
        self.config = config
        self.profile = profile
        self.pipeline = pipeline


class DomainRouter:
    """Route requests to the correct domain handler based on Host header."""

    def __init__(
        self,
        config: InfraGuardConfig,
        extra_filters: list | None = None,
        recorder: EventRecorder | None = None,
    ):
        self.config = config
        self.proxy = ProxyHandler()
        self.routes: dict[str, DomainRoute] = {}
        self._extra_filters = extra_filters or []
        self._recorder = recorder

        # Initialize shared intel manager
        self.intel = IntelManager(config.intel)

        # Build per-domain whitelists
        self._domain_whitelists: dict[str, CIDRList] = {}
        for domain_name, domain_config in config.domains.items():
            if domain_config.whitelist_cidrs:
                wl = CIDRList(name=f"whitelist:{domain_name}")
                wl.add_many(domain_config.whitelist_cidrs)
                self._domain_whitelists[domain_name] = wl

        self._load_routes()

    def _build_filters(self) -> list:
        """Build the full filter chain based on pipeline config."""
        pc = self.config.pipeline
        filters: list = []

        if pc.enable_ip_filter:
            filters.append(IPFilter(self.intel, self._domain_whitelists))
        if pc.enable_bot_filter:
            filters.append(BotFilter())
        if pc.enable_header_filter:
            filters.append(HeaderFilter())
        if pc.enable_dns_filter:
            filters.append(DNSFilter())

        # Profile filter is always present
        filters.append(ProfileFilter())

        if pc.enable_replay_filter:
            filters.append(ReplayFilter())

        filters.extend(self._extra_filters)
        return filters

    def _load_routes(self) -> None:
        filters = self._build_filters()

        for domain_name, domain_config in self.config.domains.items():
            profile = self._load_profile(domain_config)
            pipeline = FilterPipeline(filters, self.config.pipeline)
            route = DomainRoute(domain_name, domain_config, profile, pipeline)
            self.routes[domain_name] = route
            log.info(
                "domain_loaded",
                domain=domain_name,
                profile=profile.name,
                uris=profile.all_uris(),
            )

    @staticmethod
    def _load_profile(config: DomainConfig) -> C2Profile:
        path = Path(config.profile_path)
        if config.profile_type.value == "cobalt_strike":
            return parse_cobalt_strike_file(path)
        else:
            return parse_mythic_file(path)

    def resolve(self, request: Request) -> DomainRoute | None:
        """Find the DomainRoute for a request based on Host header."""
        host = request.headers.get("host", "")
        # Strip port if present
        hostname = host.split(":")[0]

        if hostname in self.routes:
            return self.routes[hostname]

        # Fallback: if only one domain is configured, use it
        if len(self.routes) == 1:
            return next(iter(self.routes.values()))

        return None

    async def handle(self, request: Request) -> Response:
        """Main request handler: route, filter, proxy or drop."""
        start = time.perf_counter()
        route = self.resolve(request)

        if route is None:
            log.warning(
                "no_route",
                host=request.headers.get("host", ""),
                path=request.url.path,
            )
            return Response(status_code=404, content=b"Not Found")

        # Parse client IP
        client_ip: IPv4Address | IPv6Address
        if request.client:
            try:
                client_ip = ip_address(request.client.host)
            except ValueError:
                client_ip = ip_address("0.0.0.0")
        else:
            client_ip = ip_address("0.0.0.0")

        # Build request context
        body = await request.body()
        ctx = RequestContext(
            request=request,
            client_ip=client_ip,
            domain_config=route.config,
            profile=route.profile,
            metadata={"body": body},
        )

        # Run filter pipeline
        result = await route.pipeline.evaluate(ctx)

        if result.allowed:
            log.info(
                "request_allowed",
                domain=route.domain,
                client=str(client_ip),
                path=request.url.path,
                score=round(result.total_score, 2),
            )
            response = await self.proxy.forward(request, route.config.upstream)
            filter_result_str = "allow"
            filter_reason = None
            status_code = response.status_code
        else:
            log.warning(
                "request_dropped",
                domain=route.domain,
                client=str(client_ip),
                path=request.url.path,
                score=round(result.total_score, 2),
                reasons=result.blocking_reasons,
            )
            response = await handle_drop(
                request,
                route.config.drop_action,
                reason=result.summary,
            )
            filter_result_str = "block"
            filter_reason = "; ".join(result.blocking_reasons) or result.summary
            status_code = response.status_code

        # Record the request to the tracking database
        duration_ms = (time.perf_counter() - start) * 1000
        if self._recorder:
            self._recorder.record(
                RequestEvent.now(
                    domain=route.domain,
                    client_ip=str(client_ip),
                    method=request.method,
                    uri=request.url.path,
                    user_agent=request.headers.get("user-agent", ""),
                    filter_result=filter_result_str,
                    filter_reason=filter_reason,
                    filter_score=result.total_score,
                    response_status=status_code,
                    duration_ms=round(duration_ms, 1),
                )
            )

        return response

    async def close(self) -> None:
        await self.proxy.close()
