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
from infraguard.models.common import DropActionType, ProfileType


class TLSConfig(BaseModel):
    cert: Path
    key: Path


class DropActionConfig(BaseModel):
    type: DropActionType = DropActionType.REDIRECT
    target: str = "https://www.google.com"


class DomainConfig(BaseModel):
    upstream: str
    profile_path: str
    profile_type: ProfileType = ProfileType.COBALT_STRIKE
    whitelist_cidrs: list[str] = Field(default_factory=list)
    decoy_dir: str | None = None
    drop_action: DropActionConfig = Field(default_factory=DropActionConfig)
    rules: list[str] = Field(default_factory=list)


class ListenerConfig(BaseModel):
    bind: str = "0.0.0.0"
    port: int = 443
    tls: TLSConfig | None = None
    domains: list[str] = Field(default_factory=list)


class FeedConfig(BaseModel):
    urls: list[str] = Field(default_factory=list)
    refresh_interval_hours: int = 6
    cache_dir: str = ".infraguard/feeds"
    enabled: bool = True


class IntelConfig(BaseModel):
    geoip_db: str | None = None
    geoip_asn_db: str | None = None
    geoip_country_db: str | None = None
    blocked_countries: list[str] = Field(default_factory=list)
    blocked_asns: list[int] = Field(default_factory=list)
    auto_block_scanners: bool = True
    dynamic_whitelist_threshold: int = DEFAULT_DYNAMIC_WHITELIST_THRESHOLD
    banned_ip_file: str | None = None
    banned_words_file: str | None = None
    feeds: FeedConfig = Field(default_factory=FeedConfig)


class TrackingConfig(BaseModel):
    db_path: str = DEFAULT_DB_PATH
    retention_days: int = DEFAULT_RETENTION_DAYS


class APIConfig(BaseModel):
    bind: str = DEFAULT_API_BIND
    port: int = DEFAULT_API_PORT
    auth_token: str | None = None
    health_path: str = "/health"


class PipelineConfig(BaseModel):
    block_score_threshold: float = DEFAULT_BLOCK_SCORE_THRESHOLD
    enable_ip_filter: bool = True
    enable_bot_filter: bool = True
    enable_header_filter: bool = True
    enable_geo_filter: bool = True
    enable_dns_filter: bool = True
    enable_replay_filter: bool = True
    enable_profile_filter: bool = True


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


class InfraGuardConfig(BaseModel):
    """Root configuration model for InfraGuard."""

    listeners: list[ListenerConfig] = Field(default_factory=list)
    domains: dict[str, DomainConfig] = Field(default_factory=dict)
    intel: IntelConfig = Field(default_factory=IntelConfig)
    tracking: TrackingConfig = Field(default_factory=TrackingConfig)
    api: APIConfig = Field(default_factory=APIConfig)
    pipeline: PipelineConfig = Field(default_factory=PipelineConfig)
    logging: LoggingConfig = Field(default_factory=LoggingConfig)
    plugins: list[str] = Field(default_factory=list)
    plugin_settings: dict[str, PluginSettings] = Field(default_factory=dict)
