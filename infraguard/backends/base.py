"""Base types for web server config generators."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Protocol

from infraguard.config.schema import InfraGuardConfig
from infraguard.profiles.models import C2Profile


@dataclass
class GeneratorOptions:
    """Operator-supplied overrides for generated server configs."""

    listen_port: int = 443
    listen_host: str = "0.0.0.0"
    ssl_cert: str | None = None
    ssl_key: str | None = None
    redirect_url: str | None = None
    default_action: str = "redirect"  # redirect | 404
    include_ip_filtering: bool = True
    include_header_checks: bool = True
    server_name_aliases: dict[str, list[str]] = field(default_factory=dict)
    custom_headers: dict[str, str] = field(default_factory=dict)


class ConfigGenerator(Protocol):
    """Interface for backend config generators."""

    def generate(
        self,
        config: InfraGuardConfig,
        profiles: dict[str, C2Profile],
        options: GeneratorOptions,
    ) -> str: ...
