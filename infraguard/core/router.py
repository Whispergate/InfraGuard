"""Domain-based request routing.

Routes incoming requests to the correct DomainConfig based on the Host
header. Each domain has its own C2 profile, filter pipeline, and optional
content delivery routes.
"""

from __future__ import annotations

import asyncio
import time
from ipaddress import IPv4Address, IPv6Address, ip_address
from pathlib import Path

import httpx
import structlog
from starlette.requests import Request
from starlette.responses import Response

from infraguard.config.schema import DomainConfig, InfraGuardConfig, PipelineConfig
from infraguard.core.circuit_breaker import CircuitBreaker, CircuitOpenError
from infraguard.core.content import ContentBackend, RouteMatch, create_backend
from infraguard.core.content_router import ContentRouteResolver
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
from infraguard.profiles.mythic import parse_mythic_file
from infraguard.tracking.recorder import EventRecorder

log = structlog.get_logger()


class DomainRoute:
    """A single domain's configuration, profile, and pipeline."""

    def __init__(
        self,
        domain: str,
        config: DomainConfig,
        profile: C2Profile,
        pipeline: FilterPipeline,
        content_resolver: ContentRouteResolver | None = None,
        fingerprint_pipeline: FilterPipeline | None = None,
    ):
        self.domain = domain
        self.config = config
        self.profile = profile
        self.pipeline = pipeline
        self.content_resolver = content_resolver
        self.fingerprint_pipeline = fingerprint_pipeline


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
        self._routes_lock = asyncio.Lock()
        self._extra_filters = extra_filters or []
        self._recorder = recorder
        self._content_backends: list[ContentBackend] = []
        self._breakers: dict[str, CircuitBreaker] = {}

        # Initialize shared intel manager
        self.intel = IntelManager(config.intel)

        # Build per-domain whitelists
        self._domain_whitelists: dict[str, CIDRList] = {}
        for domain_name, domain_config in config.domains.items():
            if domain_config.whitelist_cidrs:
                wl = CIDRList(name=f"whitelist:{domain_name}")
                wl.add_many(domain_config.whitelist_cidrs)
                self.intel.enrich_cidr_list(wl)
                self._domain_whitelists[domain_name] = wl

        self._load_routes()

    def _build_filters(self, phishing_filter=None) -> list:
        """Build the full filter chain based on pipeline config.

        Args:
            phishing_filter: If provided, replaces ProfileFilter for phishing domains.
        """
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

        if phishing_filter:
            filters.append(phishing_filter)
        else:
            filters.append(ProfileFilter())

        if pc.enable_replay_filter:
            filters.append(ReplayFilter())

        filters.extend(self._extra_filters)
        return filters

    def _build_fingerprint_filters(self) -> list:
        """Build a filter chain WITHOUT ProfileFilter and ReplayFilter.

        Used for content route conditional delivery - catches bots and
        scanners without requiring C2 profile conformance.
        """
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
        return filters

    def _load_routes(self) -> None:
        fp_filters = self._build_fingerprint_filters()

        from infraguard.models.common import PHISHING_PROFILE_TYPES
        from infraguard.pipeline.phishing_filter import PhishingFilter
        from infraguard.profiles.phishing import build_phishing_profile

        # RESL-03: Validate all C2 profile paths before loading any routes
        # (phishing domains don't need profile files)
        for domain_name, domain_config in self.config.domains.items():
            if domain_config.profile_type not in PHISHING_PROFILE_TYPES:
                profile_path = Path(domain_config.profile_path)
                if not profile_path.exists():
                    raise FileNotFoundError(
                        f"C2 profile not found for domain '{domain_name}': {profile_path.resolve()}"
                    )

        for domain_name, domain_config in self.config.domains.items():
            is_phishing = domain_config.profile_type in PHISHING_PROFILE_TYPES

            if is_phishing:
                phishing_prof = build_phishing_profile(
                    domain_config.profile_type,
                    operator_paths=domain_config.allowed_paths or None,
                    phishlet_path=domain_config.profile_path or None,
                )
                pf = PhishingFilter(phishing_prof)
                filters = self._build_filters(phishing_filter=pf)
                profile = C2Profile(name=phishing_prof.name)
            else:
                filters = self._build_filters()
                profile = self._load_profile(domain_config)

            pipeline = FilterPipeline(filters, self.config.pipeline)

            # Build content route resolver
            content_routes = list(domain_config.content_routes)

            # If the drop action is "decoy", auto-register a catch-all content
            # route so the decoy site's assets (CSS, JS, images) are served
            # directly without going through the C2 filter pipeline.
            if domain_config.drop_action.type.value == "decoy" and domain_config.drop_action.target:
                from infraguard.config.schema import ContentBackendConfig, ContentRouteConfig
                from infraguard.models.common import ContentBackendType
                decoy_site = domain_config.drop_action.target
                decoy_path = str(Path(self.config.decoy_pages_dir) / decoy_site)
                # Add as lowest-priority catch-all (appended last)
                content_routes.append(ContentRouteConfig(
                    path="/*",
                    backend=ContentBackendConfig(
                        type=ContentBackendType.FILESYSTEM,
                        target=decoy_path,
                    ),
                    track=False,
                ))

            content_resolver = None
            fp_pipeline = None
            if content_routes:
                content_resolver = ContentRouteResolver(content_routes)
                fp_pipeline = FilterPipeline(fp_filters, self.config.pipeline)

            route = DomainRoute(
                domain_name, domain_config, profile, pipeline,
                content_resolver, fp_pipeline,
            )
            self.routes[domain_name] = route

            # RESL-01: Create a circuit breaker per unique upstream URL
            upstream = domain_config.upstream
            if upstream not in self._breakers:
                self._breakers[upstream] = CircuitBreaker(
                    upstream=upstream,
                    failure_threshold=domain_config.circuit_breaker_threshold,
                    recovery_timeout=domain_config.circuit_breaker_cooldown,
                )

            content_count = len(domain_config.content_routes)
            log.info(
                "domain_loaded",
                domain=domain_name,
                profile=profile.name,
                mode="phishing" if is_phishing else "c2",
                uris=profile.all_uris() if not is_phishing else [],
                content_routes=content_count,
            )

    @staticmethod
    def _load_profile(config: DomainConfig) -> C2Profile:
        from infraguard.profiles.brute_ratel import parse_brute_ratel_file
        from infraguard.profiles.havoc import parse_havoc_file
        from infraguard.profiles.sliver import parse_sliver_file

        path = Path(config.profile_path)
        if config.profile_type.value == "cobalt_strike":
            return parse_cobalt_strike_file(path)
        elif config.profile_type.value == "brute_ratel":
            return parse_brute_ratel_file(path)
        elif config.profile_type.value == "sliver":
            return parse_sliver_file(path)
        elif config.profile_type.value == "havoc":
            return parse_havoc_file(path)
        else:
            return parse_mythic_file(path)

    async def reload(self, new_config: InfraGuardConfig) -> None:
        """Hot-reload domains, profiles, and blocklists atomically.

        Reloadable: domains, pipeline, intel.feeds, decoy_pages_dir.
        Restart-required: listeners, tracking.db_path, api.bind/port.
        """
        from infraguard.models.common import PHISHING_PROFILE_TYPES
        from infraguard.pipeline.phishing_filter import PhishingFilter
        from infraguard.profiles.phishing import build_phishing_profile

        # Validate all C2 profile paths in new config first (RESL-03)
        for domain_name, domain_config in new_config.domains.items():
            if domain_config.profile_type not in PHISHING_PROFILE_TYPES:
                profile_path = Path(domain_config.profile_path)
                if not profile_path.exists():
                    raise FileNotFoundError(
                        f"C2 profile not found for domain '{domain_name}': {profile_path.resolve()}"
                    )

        # Save old state for rollback
        old_config = self.config
        old_breakers = self._breakers

        self.config = new_config
        try:
            fp_filters = self._build_fingerprint_filters()
            new_routes: dict[str, DomainRoute] = {}
            for domain_name, domain_config in new_config.domains.items():
                is_phishing = domain_config.profile_type in PHISHING_PROFILE_TYPES

                if is_phishing:
                    phishing_prof = build_phishing_profile(
                        domain_config.profile_type,
                        operator_paths=domain_config.allowed_paths or None,
                        phishlet_path=domain_config.profile_path or None,
                    )
                    pf = PhishingFilter(phishing_prof)
                    filters = self._build_filters(phishing_filter=pf)
                    profile = C2Profile(name=phishing_prof.name)
                else:
                    filters = self._build_filters()
                    profile = self._load_profile(domain_config)

                pipeline = FilterPipeline(filters, new_config.pipeline)

                content_routes = list(domain_config.content_routes)
                if domain_config.drop_action.type.value == "decoy" and domain_config.drop_action.target:
                    from infraguard.config.schema import ContentBackendConfig, ContentRouteConfig
                    from infraguard.models.common import ContentBackendType
                    decoy_site = domain_config.drop_action.target
                    decoy_path = str(Path(new_config.decoy_pages_dir) / decoy_site)
                    content_routes.append(ContentRouteConfig(
                        path="/*",
                        backend=ContentBackendConfig(
                            type=ContentBackendType.FILESYSTEM,
                            target=decoy_path,
                        ),
                        track=False,
                    ))

                content_resolver = None
                fp_pipeline = None
                if content_routes:
                    content_resolver = ContentRouteResolver(content_routes)
                    fp_pipeline = FilterPipeline(fp_filters, new_config.pipeline)

                new_routes[domain_name] = DomainRoute(
                    domain=domain_name,
                    config=domain_config,
                    profile=profile,
                    pipeline=pipeline,
                    content_resolver=content_resolver,
                    fingerprint_pipeline=fp_pipeline,
                )

            # Build new circuit breakers, preserving state for unchanged upstreams
            new_breakers: dict[str, CircuitBreaker] = {}
            for domain_name, domain_config in new_config.domains.items():
                upstream = domain_config.upstream
                if upstream not in new_breakers:
                    if upstream in old_breakers:
                        # Preserve existing breaker state if upstream unchanged
                        new_breakers[upstream] = old_breakers[upstream]
                    else:
                        new_breakers[upstream] = CircuitBreaker(
                            upstream=upstream,
                            failure_threshold=domain_config.circuit_breaker_threshold,
                            recovery_timeout=domain_config.circuit_breaker_cooldown,
                        )
        except Exception:
            # Restore old config on build failure
            self.config = old_config
            raise

        # Atomic swap under lock
        async with self._routes_lock:
            self.routes = new_routes
            self._breakers = new_breakers

        # Update intel/whitelists for new config
        self._domain_whitelists.clear()
        for domain_name, domain_config in new_config.domains.items():
            if domain_config.whitelist_cidrs:
                wl = CIDRList(name=f"whitelist:{domain_name}")
                wl.add_many(domain_config.whitelist_cidrs)
                self.intel.enrich_cidr_list(wl)
                self._domain_whitelists[domain_name] = wl

        log.info("routes_swapped", domains=list(new_routes.keys()))

    def resolve(self, request: Request) -> DomainRoute | None:
        """Find the DomainRoute for a request based on Host header."""
        host = request.headers.get("host", "")
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
            # Use the first domain's drop action so unmatched hosts see
            # the decoy site instead of a suspicious bare 404
            if self.routes:
                first_route = next(iter(self.routes.values()))
                return await handle_drop(
                    request, first_route.config.drop_action,
                    reason="no matching domain",
                    pages_dir=self.config.decoy_pages_dir,
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

        # ── IP check before content routes (OPSEC-06) ────────────
        if route.content_resolver:
            if route.config.content_route_filter == "full_pipeline":
                # Full pipeline evaluation before content routes
                body = await request.body()
                ctx = RequestContext(
                    request=request,
                    client_ip=client_ip,
                    domain_config=route.config,
                    profile=route.profile,
                    metadata={"body": body},
                )
                pre_result = await route.pipeline.evaluate(ctx)
                if not pre_result.allowed:
                    log.warning(
                        "request_dropped_before_content",
                        domain=route.domain,
                        client=str(client_ip),
                        path=request.url.path,
                        reasons=pre_result.blocking_reasons,
                    )
                    return await handle_drop(
                        request, route.config.drop_action,
                        reason="full_pipeline_block_before_content",
                        pages_dir=self.config.decoy_pages_dir,
                    )
            else:
                # Default "ip_only": fast blocklist check only
                if self.intel and self.intel.is_blocked(client_ip):
                    log.warning(
                        "ip_blocked_before_content_route",
                        domain=route.domain,
                        client=str(client_ip),
                        path=request.url.path,
                    )
                    return await handle_drop(
                        request, route.config.drop_action,
                        reason="ip_blocked_before_content_route",
                        pages_dir=self.config.decoy_pages_dir,
                    )

            # Now safe to check content routes
            content_match = route.content_resolver.match(request)
            if content_match is not None:
                content_match.domain = route.domain
                return await self._handle_content_route(
                    request, route, content_match, client_ip, start,
                )

        # ── C2 filter pipeline ────────────────────────────────────
        body = await request.body()
        ctx = RequestContext(
            request=request,
            client_ip=client_ip,
            domain_config=route.config,
            profile=route.profile,
            metadata={"body": body},
        )

        result = await route.pipeline.evaluate(ctx)

        if result.allowed:
            log.info(
                "request_allowed",
                domain=route.domain,
                client=str(client_ip),
                path=request.url.path,
                score=round(result.total_score, 2),
            )
            try:
                breaker = self._breakers.get(route.config.upstream)
                if breaker:
                    response = await breaker.call(
                        self.proxy.forward,
                        request,
                        route.config.upstream,
                        domain_config=route.config,
                        reraise_transport_errors=True,
                    )
                else:
                    response = await self.proxy.forward(
                        request, route.config.upstream, domain_config=route.config,
                    )
                filter_result_str = "allow"
                filter_reason = None
                status_code = response.status_code
            except CircuitOpenError:
                log.warning(
                    "circuit_open_drop",
                    domain=route.domain,
                    upstream=route.config.upstream,
                )
                response = await handle_drop(
                    request,
                    route.config.drop_action,
                    reason="circuit_open",
                    pages_dir=self.config.decoy_pages_dir,
                )
                filter_result_str = "block"
                filter_reason = "circuit_open"
                status_code = response.status_code
            except (httpx.TimeoutException, httpx.ConnectError):
                response = await handle_drop(
                    request,
                    route.config.drop_action,
                    reason="upstream_error",
                    pages_dir=self.config.decoy_pages_dir,
                )
                filter_result_str = "block"
                filter_reason = "upstream_error"
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
                pages_dir=self.config.decoy_pages_dir,
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

    async def _handle_content_route(
        self,
        request: Request,
        route: DomainRoute,
        match: RouteMatch,
        client_ip: IPv4Address | IPv6Address,
        start: float,
    ) -> Response:
        """Handle a request that matched a content delivery route."""
        content_config = match.route
        filter_score = 0.0

        # Optional fingerprint check for conditional delivery
        if content_config.conditional and content_config.conditional.use_fingerprint_filters:
            body = await request.body()
            ctx = RequestContext(
                request=request,
                client_ip=client_ip,
                domain_config=route.config,
                profile=route.profile,
                metadata={"body": body},
            )
            if route.fingerprint_pipeline:
                fp_result = await route.fingerprint_pipeline.evaluate(ctx)
                filter_score = fp_result.total_score

                if filter_score >= content_config.conditional.score_threshold:
                    # Scanner/bot detected - serve decoy or redirect
                    log.info(
                        "content_blocked",
                        domain=route.domain,
                        client=str(client_ip),
                        path=request.url.path,
                        score=round(filter_score, 2),
                    )
                    if content_config.conditional.scanner_backend:
                        backend = create_backend(content_config.conditional.scanner_backend)
                        self._content_backends.append(backend)
                        response = await backend.serve(request, match)
                    else:
                        response = Response(status_code=404, content=b"Not Found")

                    self._record_content_event(
                        route.domain, client_ip, request, response,
                        "content_blocked", filter_score, start, content_config.track,
                    )
                    return response

        # Serve real content
        backend = create_backend(content_config.backend)
        self._content_backends.append(backend)
        response = await backend.serve(request, match)

        log.info(
            "content_served",
            domain=route.domain,
            client=str(client_ip),
            path=request.url.path,
            status=response.status_code,
        )

        self._record_content_event(
            route.domain, client_ip, request, response,
            "content_served", filter_score, start, content_config.track,
        )
        return response

    def _record_content_event(
        self,
        domain: str,
        client_ip: IPv4Address | IPv6Address,
        request: Request,
        response: Response,
        filter_result: str,
        filter_score: float,
        start: float,
        track: bool,
    ) -> None:
        """Record a content delivery event to the tracking database."""
        if not track or not self._recorder:
            return
        duration_ms = (time.perf_counter() - start) * 1000
        self._recorder.record(
            RequestEvent.now(
                domain=domain,
                client_ip=str(client_ip),
                method=request.method,
                uri=request.url.path,
                user_agent=request.headers.get("user-agent", ""),
                filter_result=filter_result,
                filter_reason=None,
                filter_score=filter_score,
                response_status=response.status_code,
                duration_ms=round(duration_ms, 1),
            )
        )

    async def close(self) -> None:
        await self.proxy.close()
        for backend in self._content_backends:
            try:
                await backend.close()
            except Exception:
                pass
