"""Pydantic configuration models for InfraGuard."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field

from infraguard.config.defaults import (
    DEFAULT_API_BIND,
    DEFAULT_API_PORT,
    DEFAULT_BLOCK_SCORE_THRESHOLD,
    DEFAULT_DB_PATH,
    DEFAULT_DYNAMIC_WHITELIST_THRESHOLD,
    DEFAULT_LOG_FORMAT,
    DEFAULT_LOG_LEVEL,
    DEFAULT_RETENTION_DAYS,
)
from infraguard.models.common import ContentBackendType, DropActionType, ProfileType


class TLSConfig(BaseModel):
    cert: Path
    key: Path


class PersonaConfig(BaseModel):
    """Persona settings - controls how InfraGuard presents itself to blocked clients."""

    server_header: str = "nginx"
    error_body_404: str = (
        "<html><head><title>404 Not Found</title></head>"
        "<body><center><h1>404 Not Found</h1></center>"
        "<hr><center>nginx</center></body></html>"
    )
    error_content_type: str = "text/html; charset=utf-8"
    extra_headers: dict[str, str] = Field(default_factory=dict)


class CanaryConfig(BaseModel):
    """Honeypot token injection for decoy pages."""

    enabled: bool = False
    tracking_pixel: bool = True
    honeypot_link: bool = True
    honeypot_form: bool = False


class DropActionConfig(BaseModel):
    type: DropActionType = DropActionType.REDIRECT
    target: str = "https://www.google.com"
    rotation_targets: list[str] = Field(default_factory=list)
    rotation_strategy: str = "random"  # "random" | "round_robin"
    persona: PersonaConfig = Field(default_factory=PersonaConfig)
    canary: CanaryConfig = Field(default_factory=CanaryConfig)


class ContentBackendConfig(BaseModel):
    """Configuration for a content delivery backend."""

    type: ContentBackendType
    target: str = ""
    auth_token: str | None = None
    headers: dict[str, str] = Field(default_factory=dict)
    ssl_verify: bool = False
    ssl_ca_bundle: str | None = None
    # mythic_file only: UUID of the file in Mythic's file store
    file_id: str | None = None


class ConditionalDeliveryConfig(BaseModel):
    """Serve different content based on fingerprint filter score."""

    score_threshold: float = 0.5
    scanner_backend: ContentBackendConfig | None = None
    use_fingerprint_filters: bool = True


class RateLimitConfig(BaseModel):
    """Per-route download rate limiting."""

    enabled: bool = True
    max_downloads: int = 3
    window_seconds: int = 300


class PayloadTokenConfig(BaseModel):
    """One-time download token configuration (root-level)."""

    enabled: bool = False
    default_ttl_seconds: int = 3600       # token validity window
    default_max_uses: int = 1             # token reuse limit
    token_header: str = "X-DL-Token"     # header name for inbound token
    token_param: str = "_t"              # query param fallback
    issuance_header: str = "X-Payload-Token"  # response header carrying new token


class ContentRouteGuardConfig(BaseModel):
    """Environment keying and delivery guardrails for content routes.

    Evaluated before the backend is called. Blocks requests that do not match
    the expected beacon environment — preventing automated scanners, analysts,
    and sandboxes from retrieving payloads even if they know the URL.

    All checks are AND-ed: every enabled check must pass.
    Failed checks serve the domain drop_action (redirect/reset/proxy), not a
    raw 403, to avoid fingerprinting InfraGuard as the gatekeeper.
    """

    require_beacon_ip: bool = False
    # Only serve to IPs that have been promoted to the dynamic whitelist
    # (i.e., IPs that already completed N successful C2 checkins).

    allowed_user_agents: list[str] = Field(default_factory=list)
    # Regex patterns (re.IGNORECASE). Empty = any UA passes.
    # Match is a re.search (not fullmatch), so partial patterns work.
    # Example: ["^Mozilla/5\\.0 .* Windows NT", "WinHTTP"]

    required_headers: dict[str, str] = Field(default_factory=dict)
    # Headers that must be present with an exact value.
    # Keys are case-insensitive. Example: {"X-C2-Implant": "v2"}

    forbidden_headers: list[str] = Field(default_factory=list)
    # Request must NOT contain any of these headers.
    # Catches: Via (proxy traversal), X-Forwarded-For (CDN/scanner proxy),
    # X-Scanner (automated tools), CF-Worker (Cloudflare Workers).


class ContentRouteConfig(BaseModel):
    """Maps a URI pattern to a content delivery backend."""

    path: str
    backend: ContentBackendConfig
    conditional: ConditionalDeliveryConfig | None = None
    track: bool = True
    methods: list[str] = Field(default_factory=lambda: ["GET"])
    rate_limit: RateLimitConfig | None = None
    require_token: bool = False  # gate this route behind a one-time payload token
    guard: ContentRouteGuardConfig | None = None  # environment keying / delivery guardrails


class CampaignTokenConfig(BaseModel):
    """Validate per-campaign tokens embedded in phishing URLs.

    Prevents analysts who discover the phishing URL (via CT logs, threat feeds,
    or paste sites) from loading the phishing page - they lack the campaign token
    that was embedded in the actual phishing email link.
    """

    enabled: bool = False
    token_param: str = "t"
    tokens: list[str] = Field(default_factory=list)  # static token allowlist
    hmac_secret: str | None = None      # if set, validate HMAC(secret, token, ts)
    hmac_ttl_seconds: int = 604800      # 7 days
    score_on_missing: float = 0.8       # pipeline score added for missing token


class DomainConfig(BaseModel):
    upstream: str
    backup_upstreams: list[str] = Field(default_factory=list)
    profile_path: str = ""
    profile_type: ProfileType = ProfileType.COBALT_STRIKE
    allowed_paths: list[str] = Field(default_factory=list)  # operator-defined path patterns for phishing domains
    whitelist_cidrs: list[str] = Field(default_factory=list)
    decoy_dir: str | None = None
    drop_action: DropActionConfig = Field(default_factory=DropActionConfig)
    rules: list[str] = Field(default_factory=list)
    content_routes: list[ContentRouteConfig] = Field(default_factory=list)
    ssl_verify: bool = False
    ssl_ca_bundle: str | None = None
    extra_allowed_headers: list[str] = Field(default_factory=list)
    content_route_filter: str = "ip_only"  # "ip_only" | "full_pipeline"
    circuit_breaker_threshold: int = 5  # consecutive failures before OPEN
    circuit_breaker_cooldown: float = 30.0  # seconds before HALF_OPEN probe
    campaign_token: CampaignTokenConfig = Field(default_factory=CampaignTokenConfig)


class ListenerConfig(BaseModel):
    protocol: str = "https"  # https | http | dns | mqtt | wss | ws
    bind: str = "0.0.0.0"
    port: int = 443
    tls: TLSConfig | None = None
    http2: bool = False
    domains: list[str] = Field(default_factory=list)
    options: dict[str, Any] = Field(default_factory=dict)


class FeedConfig(BaseModel):
    urls: list[str] = Field(default_factory=list)
    refresh_interval_hours: int = 6
    cache_dir: str = ".infraguard/feeds"
    enabled: bool = True
    require_feeds: bool = False  # if True, startup fails when no feeds fetchable
    staleness_threshold_hours: int = 24


class CloudRangeConfig(BaseModel):
    """Block requests originating from cloud provider IP ranges.

    Useful for blocking sandbox/analysis environments that run in AWS,
    Azure, or GCP.  Operators whose beacons legitimately run in cloud
    should either disable this or add those IPs to a whitelist.
    """

    enabled: bool = False
    providers: list[str] = Field(default_factory=lambda: ["aws", "azure", "gcp"])
    refresh_interval_hours: int = 24


class CTMonitorConfig(BaseModel):
    """Certificate Transparency log monitoring."""

    enabled: bool = False
    interval_hours: float = 6.0
    monitored_domains: list[str] = Field(default_factory=list)
    # Empty = auto-populate from config.domains keys at startup


class ReputationMonitorConfig(BaseModel):
    """Domain reputation self-monitoring against threat intel feeds."""

    enabled: bool = False
    interval_hours: float = 4.0
    monitored_domains: list[str] = Field(default_factory=list)
    check_urlhaus: bool = True
    check_openphish: bool = True
    check_google_safebrowsing: bool = False
    google_safebrowsing_api_key: str | None = None


class IntelConfig(BaseModel):
    geoip_db: str | None = None
    geoip_asn_db: str | None = None
    geoip_country_db: str | None = None
    blocked_countries: list[str] = Field(default_factory=list)
    allowed_countries: list[str] = Field(default_factory=list)
    blocked_asns: list[int] = Field(default_factory=list)
    allowed_asns: list[int] = Field(default_factory=list)
    auto_block_scanners: bool = True
    dynamic_whitelist_threshold: int = DEFAULT_DYNAMIC_WHITELIST_THRESHOLD
    banned_ip_file: str | None = None
    banned_words_file: str | None = None
    rules_dir: str | None = None  # auto-ingest .htaccess / robots.txt on startup
    feeds: FeedConfig = Field(default_factory=FeedConfig)
    cloud_ranges: CloudRangeConfig = Field(default_factory=CloudRangeConfig)
    dns_enum_nxdomain_threshold: int = 15  # NXDOMAIN responses per window before blocking
    dns_enum_window_seconds: int = 30
    ct_monitor: CTMonitorConfig = Field(default_factory=CTMonitorConfig)
    reputation_monitor: ReputationMonitorConfig = Field(default_factory=ReputationMonitorConfig)


class TrackingConfig(BaseModel):
    db_path: str = DEFAULT_DB_PATH
    retention_days: int = DEFAULT_RETENTION_DAYS


class APIConfig(BaseModel):
    bind: str = DEFAULT_API_BIND
    port: int = DEFAULT_API_PORT
    auth_token: str | None = None
    health_path: str = "/health"
    session_ttl: int = 86400  # seconds, default 24h


class JA3FilterConfig(BaseModel):
    """JA3 TLS fingerprint filter configuration."""

    blocked_ja3: list[str] = Field(default_factory=list)
    allowed_ja3: list[str] | None = None
    log_ja3: bool = True
    block_unknown: bool = False
    # Header set by a reverse proxy (nginx ssl_fingerprint, HAProxy 2.2+ native JA3)
    ja3_header: str = "x-ja3"


class PipelineConfig(BaseModel):
    filter_mode: str = "scoring"  # "scoring" | "hard"
    block_score_threshold: float = DEFAULT_BLOCK_SCORE_THRESHOLD
    enable_ip_filter: bool = True
    enable_bot_filter: bool = True
    enable_header_filter: bool = True
    enable_geo_filter: bool = True
    enable_dns_filter: bool = True
    enable_replay_filter: bool = True
    enable_profile_filter: bool = True
    enable_fingerprint_filter: bool = False
    allowed_fingerprints: list[str] = Field(default_factory=list)
    blocked_fingerprints: list[str] = Field(default_factory=list)
    # Replay filter persistence
    replay_window_seconds: int = 86400  # 24h rolling dedup window
    replay_persist: bool = True  # persist replay hashes to SQLite across restarts
    # Enumeration detection
    enable_enumeration_filter: bool = True
    enumeration_unique_path_threshold: int = 20   # hard-block above this
    enumeration_unique_path_suspect_threshold: int = 8
    enumeration_window_seconds: int = 60
    # Sandbox / headless browser detection
    enable_sandbox_filter: bool = True
    # JA3 TLS fingerprint filter (works with reverse proxy JA3 header or JA3InjectingProtocol)
    enable_ja3_filter: bool = True
    ja3_filter: JA3FilterConfig = Field(default_factory=JA3FilterConfig)


class LoggingConfig(BaseModel):
    level: str = DEFAULT_LOG_LEVEL
    format: str = DEFAULT_LOG_FORMAT
    file: str | None = None


class EventFilterConfig(BaseModel):
    """Controls which events a plugin forwards."""

    only_blocked: bool = False
    only_allowed: bool = False
    min_score: float | None = None
    exclude_domains: list[str] = Field(default_factory=list)
    include_domains: list[str] = Field(default_factory=list)


class PluginSettings(BaseModel):
    """Per-plugin settings. Each plugin reads its own keys from ``options``."""

    enabled: bool = True
    event_filter: EventFilterConfig = Field(default_factory=EventFilterConfig)
    options: dict[str, Any] = Field(default_factory=dict)


class DeadManConfig(BaseModel):
    """Dead man's switch - auto-shutdown if operator stops checking in."""

    enabled: bool = False
    ttl_seconds: int = 86400  # 24 hours


class TimingConfig(BaseModel):
    """Response timing normalization to prevent side-channel analysis.

    When enabled, all responses (both allowed and blocked) are delayed by a
    random duration within [min_delay_ms, max_delay_ms] to eliminate the
    timing difference between proxied and locally-generated responses.
    """

    enabled: bool = False
    min_delay_ms: int = 50
    max_delay_ms: int = 200


class InfraGuardConfig(BaseModel):
    """Root configuration model for InfraGuard."""

    listeners: list[ListenerConfig] = Field(default_factory=list)
    domains: dict[str, DomainConfig] = Field(default_factory=dict)
    intel: IntelConfig = Field(default_factory=IntelConfig)
    tracking: TrackingConfig = Field(default_factory=TrackingConfig)
    api: APIConfig = Field(default_factory=APIConfig)
    pipeline: PipelineConfig = Field(default_factory=PipelineConfig)
    logging: LoggingConfig = Field(default_factory=LoggingConfig)
    timing: TimingConfig = Field(default_factory=TimingConfig)
    deadman: DeadManConfig = Field(default_factory=DeadManConfig)
    payload_tokens: PayloadTokenConfig = Field(default_factory=PayloadTokenConfig)
    decoy_pages_dir: str = "pages"
    plugins: list[str] = Field(default_factory=list)
    plugin_settings: dict[str, PluginSettings] = Field(default_factory=dict)
    default_persona: PersonaConfig = Field(default_factory=PersonaConfig)
