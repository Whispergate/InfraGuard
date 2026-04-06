"""Config generation and deployment bundle writing.

Produces a deployment-ready bundle (config.yaml + .env + docker-compose.yml)
from minimal operator inputs so operators can go from "I have a domain, a C2
profile, and a teamserver IP" to a working deployment without hand-editing YAML.
"""

from __future__ import annotations

import shutil
from pathlib import Path

import yaml

from infraguard.config.schema import (
    APIConfig,
    DomainConfig,
    DropActionConfig,
    InfraGuardConfig,
    ListenerConfig,
)
from infraguard.deploy.profile_detect import detect_profile_type
from infraguard.models.common import DropActionType, ProfileType

# ── docker-compose template ───────────────────────────────────────────

_DOCKER_COMPOSE_TEMPLATE = """\
version: "3.9"

services:
  infraguard:
    image: infraguard:latest
    restart: unless-stopped
    command: infraguard run -c /config/config.yaml
    env_file:
      - .env
    ports:
      - "443:443"
      - "127.0.0.1:8080:8080"
    volumes:
      - ./config.yaml:/config/config.yaml:ro
      - ./profiles:/config/profiles:ro
"""

# ── .env template ─────────────────────────────────────────────────────

def _generate_env(
    domain: str,
    upstream: str,
    profile_type: str,
    api_token: str | None = None,
    health_path: str | None = None,
    letsencrypt: bool = True,
) -> str:
    """Generate a populated .env file for a deployment.

    Auto-generates an API token and health path if not provided.
    """
    import secrets

    token = api_token or secrets.token_urlsafe(32)
    hpath = health_path or secrets.token_hex(8)

    # Map profile type to the correct upstream env var name
    upstream_var_map = {
        "cobalt_strike": "INFRAGUARD_CS_UPSTREAM",
        "mythic": "INFRAGUARD_MYTHIC_UPSTREAM",
        "brute_ratel": "INFRAGUARD_BRC4_UPSTREAM",
        "sliver": "INFRAGUARD_SLIVER_UPSTREAM",
        "havoc": "INFRAGUARD_HAVOC_UPSTREAM",
    }
    upstream_var = upstream_var_map.get(profile_type, "INFRAGUARD_MYTHIC_UPSTREAM")

    le_email = f"le@{domain}"

    return f"""\
# InfraGuard environment variables (auto-generated)
# Secrets - do NOT commit to version control.

INFRAGUARD_DOMAIN={domain}
INFRAGUARD_DOMAIN_EMAIL={le_email}

# TLS - Let's Encrypt
INFRAGUARD_LETSENCRYPT={'true' if letsencrypt else 'false'}
INFRAGUARD_TLS_CERT=/app/certs/live/{domain}/fullchain.pem
INFRAGUARD_TLS_KEY=/app/certs/live/{domain}/privkey.pem

# Dashboard API token
INFRAGUARD_API_TOKEN={token}

# Upstream teamserver
{upstream_var}={upstream}

# Database
INFRAGUARD_DB_PATH=/app/data/infraguard.db

# Pipeline
INFRAGUARD_FILTER_MODE=scoring

# OPSEC - randomized health path to avoid fingerprinting
INFRAGUARD_HEALTH_PATH={hpath}

# Decoy pages
IG_DECOY_PAGES_DIR=/app/pages
IG_DECOY_SITE=

# Rules / blocklists
INFRAGUARD_RULES_DIR=/app/rules
INFRAGUARD_BANNED_IP_FILE=/app/rules/banned_ips.txt

# Logging
INFRAGUARD_LOG_LEVEL=INFO
"""


# ── public API ────────────────────────────────────────────────────────


def generate_config(
    domain: str,
    c2_profile_path: str,
    upstream: str,
    profile_type: str = "auto",
    drop_target: str = "https://www.google.com",
) -> InfraGuardConfig:
    """Build an :class:`InfraGuardConfig` from minimal operator inputs.

    Args:
        domain: Primary domain for the redirector (e.g. ``evil.com``).
        c2_profile_path: Path to the C2 profile file.  This should be the
            *container-relative* path (e.g. ``/config/profiles/cs.profile``)
            so the generated ``config.yaml`` is valid inside the container.
        upstream: C2 teamserver URL (e.g. ``https://10.0.0.5:8443``).
        profile_type: ``"auto"`` to detect from ``c2_profile_path``, or an
            explicit ``ProfileType`` value string.
        drop_target: Redirect URL served to blocked traffic.

    Returns:
        A fully-constructed :class:`InfraGuardConfig` with sensible defaults.
    """
    # Resolve profile type
    if profile_type == "auto":
        resolved_type: ProfileType = detect_profile_type(Path(c2_profile_path))
    else:
        resolved_type = ProfileType(profile_type)

    domain_cfg = DomainConfig(
        upstream=upstream,
        profile_path=c2_profile_path,
        profile_type=resolved_type,
        drop_action=DropActionConfig(
            type=DropActionType.REDIRECT,
            target=drop_target,
        ),
    )

    listener_cfg = ListenerConfig(
        bind="0.0.0.0",
        port=443,
        domains=[domain],
    )

    api_cfg = APIConfig(
        auth_token="${INFRAGUARD_API_TOKEN}",
    )

    return InfraGuardConfig(
        listeners=[listener_cfg],
        domains={domain: domain_cfg},
        api=api_cfg,
    )


def write_bundle(
    config: InfraGuardConfig,
    out_dir: Path,
    profile_source: Path | None = None,
    domain: str = "",
    upstream: str = "",
    profile_type: str = "mythic",
) -> None:
    """Write a deployment bundle to *out_dir*.

    Creates the following layout::

        out_dir/
          config.yaml          - InfraGuard configuration
          .env                 - Environment variables (populated)
          docker-compose.yml   - Docker Compose deployment manifest
          profiles/            - C2 profile files (if profile_source given)

    Args:
        config: The :class:`InfraGuardConfig` to serialise.
        out_dir: Destination directory (created if absent).
        profile_source: Local path to the C2 profile file.  When provided,
            the file is copied to ``out_dir/profiles/`` so the bundle is
            self-contained.
        domain: Primary domain for .env generation.
        upstream: Upstream teamserver URL for .env generation.
        profile_type: C2 profile type for .env upstream variable selection.
    """
    out_dir.mkdir(parents=True, exist_ok=True)

    # config.yaml
    config_data = config.model_dump(mode="json", exclude_none=True)
    config_yaml = yaml.dump(config_data, default_flow_style=False, allow_unicode=True)
    (out_dir / "config.yaml").write_text(config_yaml, encoding="utf-8")

    # .env - fully populated with auto-generated secrets
    env_content = _generate_env(
        domain=domain,
        upstream=upstream,
        profile_type=profile_type,
    )
    (out_dir / ".env").write_text(env_content, encoding="utf-8")

    # docker-compose.yml
    (out_dir / "docker-compose.yml").write_text(_DOCKER_COMPOSE_TEMPLATE, encoding="utf-8")

    # profiles/ - copy the profile so the bundle is self-contained
    if profile_source is not None:
        profiles_dir = out_dir / "profiles"
        profiles_dir.mkdir(exist_ok=True)
        shutil.copy2(profile_source, profiles_dir / profile_source.name)
