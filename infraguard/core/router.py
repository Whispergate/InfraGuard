"""Domain-based request routing.

Routes incoming requests to the correct DomainConfig based on the Host
header. Each domain has its own C2 profile, filter pipeline, and optional
content delivery routes.
"""

from __future__ import annotations

import asyncio
import random
import time
from ipaddress import IPv4Address, IPv6Address, ip_address
from pathlib import Path

import httpx
import structlog
from starlette.requests import Request
from starlette.responses import Response

from infraguard.config.schema import (
    ContentRouteGuardConfig,
    DomainConfig,
    InfraGuardConfig,
)
from infraguard.core.circuit_breaker import CircuitBreaker, CircuitOpenError
from infraguard.core.content import ContentBackend, RouteMatch, create_backend
from infraguard.core.content_router import ContentRouteResolver
from infraguard.core.drop import handle_drop
from infraguard.core.fronting import DomainFronting
from infraguard.core.proxy import ProxyHandler
from infraguard.core.rate_limiter import ContentRateLimiter
from infraguard.core.routing import (
    DomainRoute,
    check_content_guard,
    load_c2_profile_from_config,
    record_content_event,
)
from infraguard.intel.ip_lists import CIDRList
from infraguard.intel.manager import IntelManager
from infraguard.models.common import TUNNEL_PROFILE_TYPES
from infraguard.models.events import RequestEvent, compute_request_hash
from infraguard.pipeline.base import FilterPipeline, RequestContext
from infraguard.pipeline.bot_filter import BotFilter
from infraguard.pipeline.dns_filter import DNSFilter
from infraguard.pipeline.enumeration_filter import EnumerationFilter
from infraguard.pipeline.fingerprint_filter import FingerprintFilter
from infraguard.pipeline.geo_filter import GeoFilter
from infraguard.pipeline.header_filter import HeaderFilter
from infraguard.pipeline.ip_filter import IPFilter
from infraguard.pipeline.profile_filter import ProfileFilter
from infraguard.pipeline.replay_filter import ReplayFilter
from infraguard.pipeline.sandbox_filter import SandboxFilter
from infraguard.pipeline.tls_filter import TLSFilter
from infraguard.profiles.models import C2Profile
from infraguard.tracking.database import Database
from infraguard.tracking.recorder import EventRecorder
from infraguard.tracking.tokens import PayloadTokenStore

log = structlog.get_logger()


# DomainRoute now lives in infraguard.core.routing.route - re-exported via
# ``from infraguard.core.routing import DomainRoute`` above so downstream
# imports (`from infraguard.core.router import DomainRoute`) keep working.


class DomainRouter:
    """Route requests to the correct domain handler based on Host header."""

    def __init__(
        self,
        config: InfraGuardConfig,
        extra_filters: list | None = None,
        recorder: EventRecorder | None = None,
        db: Database | None = None,
        state_backend=None,
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
        self._state_backend = state_backend

        # Wire the state-backed overlays (SharedWhitelist, DropRateLimiter,
        # beacon session bag) only when a backend was actually provided.
        # Behavior on a single-node deploy is unchanged: every overlay
        # falls back to per-process defaults when the backend is None.
        from infraguard.state.beacons import compute_beacon_id, record_beacon_request
        from infraguard.state.drop_rate_limit import DropRateLimiter
        from infraguard.state.whitelist import SharedWhitelist

        self._shared_whitelist = SharedWhitelist(state_backend) if state_backend else None
        self._drop_rate_limiter = (
            DropRateLimiter(state_backend) if state_backend else None
        )
        # Cache the callables so hot paths do not re-import.
        self._compute_beacon_id = compute_beacon_id
        self._record_beacon_request = record_beacon_request

        # Initialize shared intel manager (pass the shared whitelist so
        # is_blocked / record_valid_request can consult it).
        self.intel = IntelManager(config.intel, shared_whitelist=self._shared_whitelist)

        # Domain fronting (SNI/Host header rewriting through CDN edges)
        self._fronting: DomainFronting | None = (
            DomainFronting(config.fronting.rules)
            if config.fronting.enabled and config.fronting.rules
            else None
        )

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
        if pc.enable_geo_filter:
            filters.append(GeoFilter(intel=self.intel))
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

        if pc.enable_profile_filter:
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
        return filters

    def _load_routes(self) -> None:
        fp_filters = self._build_fingerprint_filters()

        from infraguard.models.common import PHISHING_PROFILE_TYPES
        from infraguard.pipeline.phishing_filter import PhishingFilter
        from infraguard.profiles.phishing import build_phishing_profile

        # RESL-03: Validate all C2 profile paths before loading any routes
        # (phishing and tunnel domains don't need profile files)
        for domain_name, domain_config in self.config.domains.items():
            if (
                domain_config.profile_type not in PHISHING_PROFILE_TYPES
                and domain_config.profile_type not in TUNNEL_PROFILE_TYPES
            ):
                profile_path = Path(domain_config.profile_path)
                if not profile_path.exists():
                    raise FileNotFoundError(
                        f"C2 profile not found for domain '{domain_name}': {profile_path.resolve()}"
                    )

        for domain_name, domain_config in self.config.domains.items():
            is_phishing = domain_config.profile_type in PHISHING_PROFILE_TYPES
            is_tunnel = domain_config.profile_type in TUNNEL_PROFILE_TYPES

            if is_tunnel:
                # Tunnel types are opaque passthrough - no profile, no
                # ProfileFilter / PhishingFilter, just the base pipeline.
                filters = self._build_filters()
                profile = C2Profile(name=domain_config.profile_type.value)
            elif is_phishing:
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
        # Kept as a thin shim so any external caller doing
        # ``DomainRouter._load_profile(cfg)`` still works. New code should
        # import :func:`load_c2_profile_from_config` from
        # :mod:`infraguard.core.routing`.
        return load_c2_profile_from_config(config)

    async def reload(self, new_config: InfraGuardConfig) -> None:
        """Hot-reload domains, profiles, and blocklists atomically.

        Reloadable: domains, pipeline, intel.feeds, decoy_pages_dir.
        Restart-required: listeners, tracking.db_path, api.bind/port.
        """
        from infraguard.models.common import PHISHING_PROFILE_TYPES
        from infraguard.pipeline.phishing_filter import PhishingFilter
        from infraguard.profiles.phishing import build_phishing_profile

        # Validate all C2 profile paths in new config first
        for domain_name, domain_config in new_config.domains.items():
            if (
                domain_config.profile_type not in PHISHING_PROFILE_TYPES
                and domain_config.profile_type not in TUNNEL_PROFILE_TYPES
            ):
                profile_path = Path(domain_config.profile_path)
                if not profile_path.exists():
                    raise FileNotFoundError(
                        f"C2 profile not found for domain '{domain_name}': {profile_path.resolve()}"
                    )

        # Save old state for rollback
        old_config = self.config
        old_breakers = self._breakers
        old_intel = self.intel
        old_fronting = self._fronting

        # Rebuild fronting from new config
        self._fronting = (
            DomainFronting(new_config.fronting.rules)
            if new_config.fronting.enabled and new_config.fronting.rules
            else None
        )

        # Rebuild IntelManager from new config
        self.intel = IntelManager(new_config.intel)

        # Rebuild shared filters from new config values
        pc = new_config.pipeline
        self._replay_filter = (
            ReplayFilter(
                window_seconds=pc.replay_window_seconds,
                max_cache=50000,
                db=self._db,
                persist=pc.replay_persist,
            )
            if pc.enable_replay_filter
            else None
        )
        self._enumeration_filter = (
            EnumerationFilter(
                unique_path_threshold=pc.enumeration_unique_path_threshold,
                unique_path_suspect_threshold=pc.enumeration_unique_path_suspect_threshold,
                window_seconds=pc.enumeration_window_seconds,
            )
            if pc.enable_enumeration_filter
            else None
        )
        self._sandbox_filter = (
            SandboxFilter() if pc.enable_sandbox_filter else None
        )
        ja3_cfg = pc.ja3_filter
        self._tls_filter = (
            TLSFilter(
                blocked_ja3=set(ja3_cfg.blocked_ja3) if ja3_cfg.blocked_ja3 else None,
                allowed_ja3=set(ja3_cfg.allowed_ja3) if ja3_cfg.allowed_ja3 is not None else None,
                log_ja3=ja3_cfg.log_ja3,
                block_unknown=ja3_cfg.block_unknown,
            )
            if pc.enable_ja3_filter
            else None
        )

        # Rebuild _token_store if payload_tokens.enabled changed
        self._token_store = (
            PayloadTokenStore(self._db)
            if self._db is not None and new_config.payload_tokens.enabled
            else None
        )

        self.config = new_config
        try:
            fp_filters = self._build_fingerprint_filters()
            new_routes: dict[str, DomainRoute] = {}
            for domain_name, domain_config in new_config.domains.items():
                is_phishing = domain_config.profile_type in PHISHING_PROFILE_TYPES
                is_tunnel = domain_config.profile_type in TUNNEL_PROFILE_TYPES

                if is_tunnel:
                    filters = self._build_filters()
                    profile = C2Profile(name=domain_config.profile_type.value)
                elif is_phishing:
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
            # Restore old config and shared state on build failure
            self.config = old_config
            self.intel = old_intel
            self._fronting = old_fronting
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
        """Main request handler: route, filter, proxy or drop.

        Composed out of small private methods (``_route_or_drop``,
        ``_try_fronting``, ``_parse_client_ip``, ``_pre_content_gate``,
        ``_run_plugin_on_request``, ``_forward_with_failover``,
        ``_run_plugin_on_response``, ``_record_request_event``) so each
        step is testable and the hot-path top-level stays linear.
        Behavior is byte-identical to the pre-split monolithic version.
        """
        from infraguard.models.common import PHISHING_PROFILE_TYPES

        start = time.perf_counter()

        # 1. Resolve route (or drop with the first domain's decoy).
        route, early = await self._route_or_drop(request)
        if early is not None:
            return early
        assert route is not None  # for the type checker

        # 2. Domain-fronting interception.
        fronted = await self._try_fronting(request)
        if fronted is not None:
            return fronted

        # 3. Parse client IP.
        client_ip = self._parse_client_ip(request)

        # 4. If a beacon URI, skip content_routes and let the C2 pipeline
        #    decide (ProfileFilter validates headers/cookie/transforms).
        #    Otherwise, if content routes exist, run the pre-content gate
        #    and dispatch to a content route on match.
        is_beacon_uri = (
            route.config.profile_type not in PHISHING_PROFILE_TYPES
            and route.profile is not None
            and request.url.path in route.profile.all_uris()
        )
        if route.content_resolver and not is_beacon_uri:
            gate = await self._pre_content_gate(route, request, client_ip)
            if gate is not None:
                return gate
            content_match = route.content_resolver.match(request)
            if content_match is not None:
                content_match.domain = route.domain
                return await self._handle_content_route(
                    request, route, content_match, client_ip, start,
                )

        # 5. Build the C2-pipeline request context.
        body = await request.body()
        request_hash = compute_request_hash(
            method=request.method,
            path=request.url.path,
            user_agent=request.headers.get("user-agent", ""),
            cookie=request.headers.get("cookie", ""),
            body=body,
        )
        ctx = RequestContext(
            request=request,
            client_ip=client_ip,
            domain_config=route.config,
            profile=route.profile,
            metadata={
                "body": body,
                "ja3": getattr(request.state, "ja3", None),
                "request_hash": request_hash,
            },
            domain=route.domain,
        )

        # 6. Plugin on_request hooks.
        plugin_drop = await self._run_plugin_on_request(ctx, request, route)
        if plugin_drop is not None:
            return plugin_drop

        # 7. Pipeline evaluate + allowed/blocked branches.
        result = await route.pipeline.evaluate(ctx)
        if result.allowed:
            log.info(
                "request_allowed",
                domain=route.domain,
                client=str(client_ip),
                path=request.url.path,
                score=round(result.total_score, 2),
            )
            await self._maybe_record_whitelist_and_issue_tokens(route, ctx, client_ip)
            response, filter_result_str, filter_reason = (
                await self._forward_with_failover(request, route)
            )
            self._attach_issued_tokens(ctx, response)
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
                pages_dir=self.config.decoy_pages_dir, drop_rate_limiter=self._drop_rate_limiter,
            )
            filter_result_str = "block"
            filter_reason = "; ".join(result.blocking_reasons) or result.summary

        # 8. Plugin on_response hooks.
        response = await self._run_plugin_on_response(ctx, response)

        # 9. Timing normalization (side-channel resistance).
        await self._apply_timing_jitter()

        # 10. Record the request.
        self._record_request_event(
            route=route,
            request=request,
            client_ip=client_ip,
            ctx=ctx,
            response=response,
            filter_result_str=filter_result_str,
            filter_reason=filter_reason,
            filter_score=result.total_score,
            start=start,
        )
        return response

    # ── handle() sub-steps ─────────────────────────────────────────────
    # Each of these is called from exactly one place (``handle`` itself);
    # they exist so ``handle`` reads top-to-bottom and each step is small
    # enough to review or test in isolation.

    async def _route_or_drop(
        self, request: Request
    ) -> tuple[DomainRoute | None, Response | None]:
        """Resolve the Host to a route, or synthesize an early drop.

        Returns ``(route, None)`` on match, ``(None, response)`` when
        no domain matches - using the first configured domain's drop
        action so unmatched hosts see the decoy rather than a bare 404.
        """
        route = self.resolve(request)
        if route is not None:
            return route, None
        log.warning(
            "no_route",
            host=request.headers.get("host", ""),
            path=request.url.path,
        )
        if self.routes:
            first_route = next(iter(self.routes.values()))
            resp = await handle_drop(
                request, first_route.config.drop_action,
                reason="no matching domain",
                pages_dir=self.config.decoy_pages_dir, drop_rate_limiter=self._drop_rate_limiter,
            )
            return None, resp
        return None, Response(status_code=404, content=b"Not Found")

    async def _try_fronting(self, request: Request) -> Response | None:
        """Return a fronted response if the Host maps to a CDN rule."""
        if self._fronting is None:
            return None
        host = request.headers.get("host", "")
        rule = self._fronting.resolve_by_host(host)
        if rule is None:
            return None
        log.info(
            "fronting_request",
            domain=rule.domain,
            front_domain=rule.front_domain,
            cdn=rule.cdn.value,
            path=request.url.path,
        )
        return await self._fronting.forward(request, rule)

    @staticmethod
    def _parse_client_ip(request: Request) -> IPv4Address | IPv6Address:
        """Best-effort IP parse; falls back to 0.0.0.0 on absence/error."""
        if request.client:
            try:
                return ip_address(request.client.host)
            except ValueError:
                pass
        return ip_address("0.0.0.0")

    async def _pre_content_gate(
        self,
        route: DomainRoute,
        request: Request,
        client_ip: IPv4Address | IPv6Address,
    ) -> Response | None:
        """Run the pre-content-route safety gate.

        Two modes selected by ``route.config.content_route_filter``:
        * ``"full_pipeline"`` - evaluate the entire C2 filter pipeline
          up-front and drop on any blocker.
        * ``"ip_only"`` (default) - fast blocklist-only check.
        Returns a drop ``Response`` on block, ``None`` on pass.
        """
        if route.config.content_route_filter == "full_pipeline":
            body = await request.body()
            ctx = RequestContext(
                request=request,
                client_ip=client_ip,
                domain_config=route.config,
                profile=route.profile,
                metadata={
                    "body": body,
                    "ja3": getattr(request.state, "ja3", None),
                },
                domain=route.domain,
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
                    pages_dir=self.config.decoy_pages_dir, drop_rate_limiter=self._drop_rate_limiter,
            )
            return None

        # Default "ip_only": fast blocklist check only.
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
                pages_dir=self.config.decoy_pages_dir, drop_rate_limiter=self._drop_rate_limiter,
            )
        return None

    async def _run_plugin_on_request(
        self,
        ctx: RequestContext,
        request: Request,
        route: DomainRoute,
    ) -> Response | None:
        """Invoke each plugin's ``on_request``; return a drop on first block."""
        if not self._recorder:
            return None
        for plugin in self._recorder._plugins:
            if not getattr(plugin, "_runtime_enabled", True):
                continue
            try:
                plugin_result = await plugin.on_request(ctx)
                if plugin_result is not None and not plugin_result.allowed:
                    log.info(
                        "plugin_blocked_request",
                        plugin=getattr(plugin, "name", "unknown"),
                        domain=route.domain,
                        path=request.url.path,
                    )
                    return await handle_drop(
                        request, route.config.drop_action,
                        reason=f"plugin:{getattr(plugin, 'name', 'unknown')}",
                        pages_dir=self.config.decoy_pages_dir, drop_rate_limiter=self._drop_rate_limiter,
            )
            except Exception:
                log.exception(
                    "plugin_on_request_error",
                    plugin=getattr(plugin, "name", "unknown"),
                )
        return None

    async def _maybe_record_whitelist_and_issue_tokens(
        self,
        route: DomainRoute,
        ctx: RequestContext,
        client_ip: IPv4Address | IPv6Address,
    ) -> None:
        """Update the dynamic whitelist and mint payload tokens on first-ever
        allowed request from this client.

        Phishing/passthrough domains are open by design; letting them feed
        the dynamic whitelist would let any target click-through bypass
        CIDR-restricted domains (e.g. operator admin panels).
        """
        from infraguard.models.common import PHISHING_PROFILE_TYPES

        newly_whitelisted = False
        if route.config.profile_type not in PHISHING_PROFILE_TYPES:
            newly_whitelisted = self.intel.record_valid_request(str(client_ip))
        if newly_whitelisted and self._token_store is not None:
            pt_cfg = self.config.payload_tokens
            for cr in route.config.content_routes:
                if cr.require_token:
                    token = await self._token_store.issue(
                        beacon_ip=str(client_ip),
                        route_path=cr.path,
                        ttl_seconds=pt_cfg.default_ttl_seconds,
                        max_uses=pt_cfg.default_max_uses,
                    )
                    ctx.metadata.setdefault("issued_tokens", {})[cr.path] = token

        # Track the beacon in the cluster-wide session bag. Non-fatal:
        # a state-backend hiccup logs at DEBUG and does not affect the
        # response. Skipped for phishing / passthrough where the notion
        # of a "beacon session" does not apply.
        if route.config.profile_type not in PHISHING_PROFILE_TYPES:
            ua = ctx.request.headers.get("user-agent", "")
            ja3 = ctx.metadata.get("ja3")
            beacon_id = self._compute_beacon_id(str(client_ip), ja3, ua)
            session = await self._record_beacon_request(
                self._state_backend,
                beacon_id=beacon_id,
                client_ip=str(client_ip),
                ja3=ja3,
                user_agent=ua,
                domain=route.domain,
            )
            ctx.metadata["beacon_id"] = beacon_id
            ctx.metadata["beacon_session"] = session
            # HPA gates on the active-beacons gauge. See
            # infraguard/ui/api/metrics.py for the prune loop.
            try:
                from infraguard.ui.api.metrics import record_beacon_activity

                record_beacon_activity()
            except Exception:
                pass

    async def _forward_with_failover(
        self, request: Request, route: DomainRoute
    ) -> tuple[Response, str, str | None]:
        """Try each upstream (primary + backups) in order.

        Returns ``(response, filter_result_str, filter_reason)``. On the
        happy path ``filter_result_str = "allow"``. When every upstream
        fails or the circuit is open on all of them, returns a drop
        response with ``filter_result_str = "block"`` and
        ``filter_reason = "all_upstreams_failed"``.
        """
        upstreams = [route.config.upstream] + list(route.config.backup_upstreams)
        response: Response | None = None
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
                break  # Success - stop trying upstreams.
            except CircuitOpenError:
                log.warning(
                    "upstream_circuit_open",
                    domain=route.domain,
                    upstream=upstream,
                    backup_index=i,
                )
                continue
            except (httpx.TimeoutException, httpx.ConnectError):
                log.warning(
                    "upstream_failover",
                    domain=route.domain,
                    upstream=upstream,
                    backup_index=i,
                )
                continue

        if response is None:
            log.error(
                "all_upstreams_failed",
                domain=route.domain,
                upstreams=upstreams,
            )
            response = await handle_drop(
                request,
                route.config.drop_action,
                reason="all_upstreams_failed",
                pages_dir=self.config.decoy_pages_dir, drop_rate_limiter=self._drop_rate_limiter,
            )
            return response, "block", "all_upstreams_failed"
        return response, "allow", None

    def _attach_issued_tokens(
        self, ctx: RequestContext, response: Response
    ) -> None:
        """Attach payload tokens minted in this request to the response."""
        issued: dict[str, str] = ctx.metadata.get("issued_tokens", {}) or {}
        if not issued:
            return
        import json as _json
        pt_cfg = self.config.payload_tokens
        # Single token → plain string header. Multiple → JSON blob.
        # Preserved from the historical code so consumers do not break.
        token_value = (
            next(iter(issued.values()))
            if len(issued) == 1
            else _json.dumps(issued)
        )
        response.headers[pt_cfg.issuance_header] = token_value

    async def _run_plugin_on_response(
        self, ctx: RequestContext, response: Response
    ) -> Response:
        """Invoke each plugin's ``on_response``; a returned value replaces the response."""
        if not self._recorder:
            return response
        for plugin in self._recorder._plugins:
            if not getattr(plugin, "_runtime_enabled", True):
                continue
            try:
                modified = await plugin.on_response(ctx, response)
                if modified is not None:
                    response = modified
            except Exception:
                log.exception(
                    "plugin_on_response_error",
                    plugin=getattr(plugin, "name", "unknown"),
                )
        return response

    async def _apply_timing_jitter(self) -> None:
        """Sleep for a random interval in the configured range."""
        if not self.config.timing.enabled:
            return
        jitter_ms = random.randint(
            self.config.timing.min_delay_ms,
            self.config.timing.max_delay_ms,
        )
        await asyncio.sleep(jitter_ms / 1000.0)

    def _record_request_event(
        self,
        *,
        route: DomainRoute,
        request: Request,
        client_ip: IPv4Address | IPv6Address,
        ctx: RequestContext,
        response: Response,
        filter_result_str: str,
        filter_reason: str | None,
        filter_score: float,
        start: float,
    ) -> None:
        """Emit the tracking-DB event that captures one handled request.

        Also mirrors to the purple-team collector if configured. The
        mirror is fire-and-forget: a slow collector never blocks the
        hot path.
        """
        duration_ms = (time.perf_counter() - start) * 1000
        mirror = getattr(self, "_purple_mirror", None)
        if mirror is not None and (
            not mirror._cfg.only_allowed or filter_result_str == "allow"
        ):
            mirror.submit({
                "domain": route.domain,
                "client_ip": str(client_ip),
                "method": request.method,
                "uri": request.url.path,
                "user_agent": request.headers.get("user-agent", ""),
                "filter_result": filter_result_str,
                "filter_reason": filter_reason,
                "filter_score": filter_score,
                "response_status": response.status_code,
                "duration_ms": round(duration_ms, 1),
                "beacon_id": ctx.metadata.get("beacon_id"),
                "request_hash": ctx.metadata.get("request_hash", ""),
            })
        if not self._recorder:
            return
        self._recorder.record(
            RequestEvent.now(
                domain=route.domain,
                client_ip=str(client_ip),
                method=request.method,
                uri=request.url.path,
                user_agent=request.headers.get("user-agent", ""),
                filter_result=filter_result_str,
                filter_reason=filter_reason,
                filter_score=filter_score,
                response_status=response.status_code,
                duration_ms=round(duration_ms, 1),
                request_hash=ctx.metadata.get("request_hash", ""),
            )
        )

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

        # Compute the request hash once up-front so every recorded event in
        # this path (content_blocked / guard_blocked / rate_limited /
        # content_served) gets a populated request_hash column. Starlette
        # caches the body, so downstream backends still see it.
        body = await request.body()
        request_hash = compute_request_hash(
            method=request.method,
            path=request.url.path,
            user_agent=request.headers.get("user-agent", ""),
            cookie=request.headers.get("cookie", ""),
            body=body,
        )

        # Optional fingerprint check for conditional delivery
        if content_config.conditional and content_config.conditional.use_fingerprint_filters:
            ctx = RequestContext(
                request=request,
                client_ip=client_ip,
                domain_config=route.config,
                profile=route.profile,
                metadata={
                    "body": body,
                    "ja3": getattr(request.state, "ja3", None),
                    "request_hash": request_hash,
                },
                domain=route.domain,
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
                        request_hash=request_hash,
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
                    request_hash=request_hash,
                )
                return await handle_drop(request, route.config.drop_action, drop_rate_limiter=self._drop_rate_limiter)

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
                        request_hash=request_hash,
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
            request_hash=request_hash,
        )
        return response

    def _check_content_guard(
        self,
        request: Request,
        guard: ContentRouteGuardConfig,
        client_ip: IPv4Address | IPv6Address,
    ) -> str | None:
        """Thin wrapper around :func:`check_content_guard`.

        Kept as an instance method so ``self._check_content_guard(...)``
        call sites inside ``handle()`` do not have to be rewritten.
        """
        return check_content_guard(self.intel, request, guard, client_ip)

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
        request_hash: str = "",
    ) -> None:
        """Thin wrapper around :func:`record_content_event`."""
        record_content_event(
            self._recorder,
            domain,
            client_ip,
            request,
            response,
            filter_result,
            filter_score,
            start,
            track,
            request_hash,
        )

    async def close(self) -> None:
        await self.proxy.close()
        if self._fronting is not None:
            await self._fronting.close()
        for backend in self._content_backends:
            try:
                await backend.close()
            except Exception:
                pass
