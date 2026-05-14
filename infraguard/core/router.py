"""Domain-based request routing.

Routes incoming requests to the correct DomainConfig based on the Host
header. Each domain has its own C2 profile, filter pipeline, and optional
content delivery routes.
"""

from __future__ import annotations

import asyncio
import re
import random
import time
from ipaddress import IPv4Address, IPv6Address, ip_address
from pathlib import Path

import httpx
import structlog
from starlette.requests import Request
from starlette.responses import Response

from infraguard.config.schema import ContentRouteGuardConfig, DomainConfig, InfraGuardConfig, PipelineConfig
from infraguard.core.circuit_breaker import CircuitBreaker, CircuitOpenError
from infraguard.core.content import ContentBackend, RouteMatch, create_backend
from infraguard.core.content_router import ContentRouteResolver
from infraguard.core.drop import handle_drop
from infraguard.core.proxy import ProxyHandler
from infraguard.core.rate_limiter import ContentRateLimiter
from infraguard.intel.ip_lists import CIDRList
from infraguard.intel.manager import IntelManager
from infraguard.models.common import DropActionType
from infraguard.models.events import RequestEvent
from infraguard.pipeline.base import FilterPipeline, RequestContext
from infraguard.pipeline.bot_filter import BotFilter
from infraguard.pipeline.dns_filter import DNSFilter
from infraguard.pipeline.enumeration_filter import EnumerationFilter
from infraguard.pipeline.header_filter import HeaderFilter
from infraguard.pipeline.sandbox_filter import SandboxFilter
from infraguard.pipeline.ip_filter import IPFilter
from infraguard.pipeline.profile_filter import ProfileFilter
from infraguard.pipeline.fingerprint_filter import FingerprintFilter
from infraguard.pipeline.replay_filter import ReplayFilter
from infraguard.pipeline.tls_filter import TLSFilter
from infraguard.profiles.cobalt_strike import parse_cobalt_strike_file
from infraguard.profiles.models import C2Profile
from infraguard.profiles.mythic import parse_mythic_file
from infraguard.tracking.database import Database
from infraguard.tracking.recorder import EventRecorder
from infraguard.tracking.tokens import PayloadTokenStore

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
        db: Database | None = None,
    ):
        self.config = config
        self.proxy = ProxyHandler()
        self.routes: dict[str, DomainRoute] = {}
        self._routes_lock = asyncio.Lock()
        self._extra_filters = extra_filters or []
        self._recorder = recorder
        self._db = db
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

        # Shared filters (state must survive per-domain construction)
        pc = config.pipeline
        self._replay_filter: ReplayFilter | None = (
            ReplayFilter(
                window_seconds=pc.replay_window_seconds,
                max_cache=50000,
                db=db,
                persist=pc.replay_persist,
            )
            if pc.enable_replay_filter
            else None
        )
        self._enumeration_filter: EnumerationFilter | None = (
            EnumerationFilter(
                unique_path_threshold=pc.enumeration_unique_path_threshold,
                unique_path_suspect_threshold=pc.enumeration_unique_path_suspect_threshold,
                window_seconds=pc.enumeration_window_seconds,
            )
            if pc.enable_enumeration_filter
            else None
        )
        self._sandbox_filter: SandboxFilter | None = (
            SandboxFilter() if pc.enable_sandbox_filter else None
        )
        ja3_cfg = pc.ja3_filter
        self._tls_filter: TLSFilter | None = (
            TLSFilter(
                blocked_ja3=set(ja3_cfg.blocked_ja3) if ja3_cfg.blocked_ja3 else None,
                allowed_ja3=set(ja3_cfg.allowed_ja3) if ja3_cfg.allowed_ja3 is not None else None,
                log_ja3=ja3_cfg.log_ja3,
                block_unknown=ja3_cfg.block_unknown,
            )
            if pc.enable_ja3_filter
            else None
        )
        self._rate_limiter = ContentRateLimiter()
        self._token_store: PayloadTokenStore | None = (
            PayloadTokenStore(db) if db is not None and config.payload_tokens.enabled else None
        )

        self._load_routes()

    async def startup(self) -> None:
        """Post-connect startup: hydrate persistent caches from the database."""
        if self._replay_filter is not None:
            await self._replay_filter.load_from_db()
        if self._token_store is not None:
            await self._token_store.prune_expired()

    def _build_filters(self, phishing_filter=None) -> list:
        """Build the full filter chain based on pipeline config.

        Args:
            phishing_filter: If provided, replaces ProfileFilter for phishing domains.
        """
        pc = self.config.pipeline
        filters: list = []

        # TLS fingerprint check runs first - before any IP/bot/header logic
        if self._tls_filter is not None:
            filters.append(self._tls_filter)

        if pc.enable_ip_filter:
            filters.append(IPFilter(self.intel, self._domain_whitelists))
        if pc.enable_bot_filter:
            filters.append(BotFilter())
        if pc.enable_header_filter:
            filters.append(HeaderFilter())
        if pc.enable_dns_filter:
            filters.append(DNSFilter())

        if pc.enable_fingerprint_filter:
            filters.append(FingerprintFilter(
                allowed_fingerprints=set(pc.allowed_fingerprints) if pc.allowed_fingerprints else None,
                blocked_fingerprints=set(pc.blocked_fingerprints) if pc.blocked_fingerprints else None,
            ))

        if phishing_filter:
            filters.append(phishing_filter)
        else:
            filters.append(ProfileFilter())

        if self._replay_filter is not None:
            filters.append(self._replay_filter)

        if self._enumeration_filter is not None:
            filters.append(self._enumeration_filter)

        if self._sandbox_filter is not None:
            filters.append(self._sandbox_filter)

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
            # (includes backup upstreams for failover support)
            all_upstreams = [domain_config.upstream] + list(domain_config.backup_upstreams)
            for upstream in all_upstreams:
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
        from infraguard.profiles.nighthawk import parse_nighthawk_file
        from infraguard.profiles.poshc2 import parse_poshc2_file
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
        elif config.profile_type.value == "nighthawk":
            return parse_nighthawk_file(path)
        elif config.profile_type.value == "poshc2":
            return parse_poshc2_file(path)
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
                all_upstreams = [domain_config.upstream] + list(domain_config.backup_upstreams)
                for upstream in all_upstreams:
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
                    metadata={"body": body, "ja3": getattr(request.state, "ja3", None)},
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
            metadata={"body": body, "ja3": getattr(request.state, "ja3", None)},
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
            # Record valid request for dynamic whitelisting.
            # If this causes the IP to be newly whitelisted, issue a payload token.
            newly_whitelisted = self.intel.record_valid_request(str(client_ip))
            if newly_whitelisted and self._token_store is not None:
                pt_cfg = self.config.payload_tokens
                # Issue tokens for all token-gated content routes on this domain
                for cr in route.config.content_routes:
                    if cr.require_token:
                        token = await self._token_store.issue(
                            beacon_ip=str(client_ip),
                            route_path=cr.path,
                            ttl_seconds=pt_cfg.default_ttl_seconds,
                            max_uses=pt_cfg.default_max_uses,
                        )
                        # Token delivered via response header after proxying
                        ctx.metadata.setdefault("issued_tokens", {})[cr.path] = token

            # Build ordered upstream list: primary + backups
            upstreams = [route.config.upstream] + list(route.config.backup_upstreams)
            response = None
            filter_result_str = "allow"
            filter_reason = None

            for i, upstream in enumerate(upstreams):
                try:
                    breaker = self._breakers.get(upstream)
                    if breaker:
                        response = await breaker.call(
                            self.proxy.forward,
                            request,
                            upstream,
                            domain_config=route.config,
                            reraise_transport_errors=True,
                        )
                    else:
                        response = await self.proxy.forward(
                            request, upstream, domain_config=route.config,
                        )
                    break  # Success - stop trying upstreams
                except CircuitOpenError:
                    log.warning(
                        "upstream_circuit_open",
                        domain=route.domain,
                        upstream=upstream,
                        backup_index=i,
                    )
                    continue  # Try next upstream
                except (httpx.TimeoutException, httpx.ConnectError):
                    log.warning(
                        "upstream_failover",
                        domain=route.domain,
                        upstream=upstream,
                        backup_index=i,
                    )
                    continue  # Try next upstream

            if response is None:
                # All upstreams exhausted
                log.error(
                    "all_upstreams_failed",
                    domain=route.domain,
                    upstreams=upstreams,
                )
                response = await handle_drop(
                    request,
                    route.config.drop_action,
                    reason="all_upstreams_failed",
                    pages_dir=self.config.decoy_pages_dir,
                )
                filter_result_str = "block"
                filter_reason = "all_upstreams_failed"

            # Attach any issued payload tokens to the response headers
            issued_tokens: dict[str, str] = ctx.metadata.get("issued_tokens", {})
            if issued_tokens:
                pt_cfg = self.config.payload_tokens
                # Encode as JSON if multiple tokens; plain string if single
                import json as _json
                token_value = (
                    next(iter(issued_tokens.values()))
                    if len(issued_tokens) == 1
                    else _json.dumps(issued_tokens)
                )
                response.headers[pt_cfg.issuance_header] = token_value

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

        # Timing normalization: add random jitter to prevent side-channel
        # analysis that could distinguish proxied vs locally-generated responses.
        if self.config.timing.enabled:
            jitter_ms = random.randint(
                self.config.timing.min_delay_ms,
                self.config.timing.max_delay_ms,
            )
            await asyncio.sleep(jitter_ms / 1000.0)

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
                metadata={"body": body, "ja3": getattr(request.state, "ja3", None)},
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

        # Environment keying / delivery guardrails
        if content_config.guard:
            guard_reason = self._check_content_guard(request, content_config.guard, client_ip)
            if guard_reason:
                log.warning(
                    "content_guard_blocked",
                    domain=route.domain,
                    client=str(client_ip),
                    path=request.url.path,
                    reason=guard_reason,
                )
                self._record_content_event(
                    route.domain, client_ip, request,
                    Response(status_code=403, content=b"Forbidden"),
                    "guard_blocked", filter_score, start, content_config.track,
                )
                return await handle_drop(request, route.config.drop_action)

        # One-time payload token validation
        if content_config.require_token and self._token_store is not None:
            pt_cfg = self.config.payload_tokens
            token = (
                request.headers.get(pt_cfg.token_header)
                or request.query_params.get(pt_cfg.token_param)
            )
            if not token:
                log.warning(
                    "payload_token_missing",
                    domain=route.domain,
                    client=str(client_ip),
                    path=request.url.path,
                )
                return Response(status_code=403, content=b"Forbidden")
            validation = await self._token_store.validate_and_consume(token, content_config.path)
            if not validation.valid:
                log.warning(
                    "payload_token_invalid",
                    domain=route.domain,
                    client=str(client_ip),
                    path=request.url.path,
                )
                return Response(status_code=403, content=b"Forbidden")

        # Per-route download rate limiting
        if content_config.rate_limit and content_config.rate_limit.enabled:
            rl = content_config.rate_limit
            allowed = self._rate_limiter.check(
                str(client_ip), content_config.path, rl.max_downloads, rl.window_seconds,
            )
            if not allowed:
                log.warning(
                    "rate_limit_exceeded",
                    domain=route.domain,
                    client=str(client_ip),
                    path=request.url.path,
                    max_downloads=rl.max_downloads,
                    window_seconds=rl.window_seconds,
                )
                if content_config.conditional and content_config.conditional.scanner_backend:
                    backend = create_backend(content_config.conditional.scanner_backend)
                    self._content_backends.append(backend)
                    response = await backend.serve(request, match)
                    self._record_content_event(
                        route.domain, client_ip, request, response,
                        "rate_limited", filter_score, start, content_config.track,
                    )
                    return response
                return Response(status_code=429, content=b"Too Many Requests")

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

    def _check_content_guard(
        self,
        request: Request,
        guard: ContentRouteGuardConfig,
        client_ip: IPv4Address | IPv6Address,
    ) -> str | None:
        """Return None if all guard checks pass, or a reason string if blocked."""
        if guard.require_beacon_ip:
            if not self.intel.dynamic_whitelist.is_whitelisted(str(client_ip)):
                return "not a whitelisted beacon IP"

        if guard.allowed_user_agents:
            ua = request.headers.get("user-agent", "")
            if not any(re.search(pat, ua, re.IGNORECASE) for pat in guard.allowed_user_agents):
                return f"UA not in allowlist ({ua[:80]!r})"

        for header_name, expected_value in guard.required_headers.items():
            actual = request.headers.get(header_name, "")
            if actual != expected_value:
                return f"required header mismatch: {header_name}"

        for header_name in guard.forbidden_headers:
            if header_name.lower() in request.headers:
                return f"forbidden header present: {header_name}"

        return None

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
