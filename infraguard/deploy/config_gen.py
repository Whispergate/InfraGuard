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

_ENV_TEMPLATE = """\
# InfraGuard environment variables
# Edit this file before deploying - do NOT commit secrets to version control.

INFRAGUARD_API_TOKEN=change_me_before_deploy
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
) -> None:
    """Write a deployment bundle to *out_dir*.

    Creates the following layout::

        out_dir/
          config.yaml          - InfraGuard configuration
          .env                 - Environment variable placeholders
          docker-compose.yml   - Docker Compose deployment manifest
          profiles/            - C2 profile files (if profile_source given)

    Args:
        config: The :class:`InfraGuardConfig` to serialise.
        out_dir: Destination directory (created if absent).
        profile_source: Local path to the C2 profile file.  When provided,
            the file is copied to ``out_dir/profiles/`` so the bundle is
            self-contained.
    """
    out_dir.mkdir(parents=True, exist_ok=True)

    # config.yaml
    config_data = config.model_dump(mode="json", exclude_none=True)
    config_yaml = yaml.dump(config_data, default_flow_style=False, allow_unicode=True)
    (out_dir / "config.yaml").write_text(config_yaml, encoding="utf-8")

    # .env
    (out_dir / ".env").write_text(_ENV_TEMPLATE, encoding="utf-8")

    # docker-compose.yml
    (out_dir / "docker-compose.yml").write_text(_DOCKER_COMPOSE_TEMPLATE, encoding="utf-8")

    # profiles/ - copy the profile so the bundle is self-contained
    if profile_source is not None:
        profiles_dir = out_dir / "profiles"
        profiles_dir.mkdir(exist_ok=True)
        shutil.copy2(profile_source, profiles_dir / profile_source.name)
