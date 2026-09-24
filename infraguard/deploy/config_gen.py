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
    TrackingConfig,
)
from infraguard.deploy.profile_detect import detect_profile_type
from infraguard.models.common import DropActionType, ProfileType

# ── docker-compose template ───────────────────────────────────────────
#
# Deliberately generated as an f-string in write_bundle so the volume list
# doesn't drift between the two services. Notes on the shape:
#
# * The container ENTRYPOINT is ``infraguard`` (see repo Dockerfile), so
#   ``command:`` is just the sub-command + its flags - writing
#   ``command: infraguard run ...`` here yielded ``infraguard infraguard
#   run ...`` at runtime (v0.4 bundle bug F1).
# * The proxy expects its config at ``/app/config/config.yaml`` (the
#   Dockerfile's default CMD path); the earlier bundle used ``/config/``
#   which was silently unbound.
# * ``/app/data`` needs a writable bind mount so SQLite can create the
#   tracking DB (bug F2 - sqlite ``unable to open database file``).
# * The dashboard ``command:`` used to be a bare ``dashboard`` - but
#   ``infraguard dashboard`` REQUIRES ``-c`` (bug F3).

def _render_docker_compose(domain: str) -> str:
    return """\
services:
  # ── Data-volume permission fixer ────────────────────────────────────
  # Docker creates fresh named volumes owned by root, but InfraGuard
  # runs as UID 1000 in the container. Without this init step the
  # proxy/dashboard hit ``sqlite3.OperationalError: unable to open
  # database file`` because ``/app/data`` is not writable (v0.4 bundle
  # bug F2 - final layer). Mirrors ``data-init`` in the top-level
  # docker-compose.yml, but scoped to the named volume so it also works
  # from Windows/WSL where bind-mount ``chown`` does not stick.
  data-init:
    image: alpine:latest
    container_name: infraguard-data-init
    volumes:
      - infraguard-data:/app/data
    entrypoint: /bin/sh
    command: ["-c", "mkdir -p /app/data && chown -R 1000:1000 /app/data"]
    restart: "no"

  proxy:
    image: infraguard:latest
    container_name: infraguard-proxy
    restart: unless-stopped
    command: ["run", "-c", "/app/config/config.yaml"]
    env_file:
      - .env
    environment:
      # Bind embedded API to all interfaces so the dashboard container
      # can reach it over the compose network. Not published to the
      # host - only reachable inside the compose network.
      - INFRAGUARD_API_BIND=0.0.0.0
    ports:
      - "443:443"
    depends_on:
      data-init:
        condition: service_completed_successfully
    tmpfs:
      # Writable scratch for the intel-feed cache (default: ./.infraguard).
      # Without it the container-side UID 1000 hits PermissionError when
      # trying to persist downloaded feeds under /app/.infraguard.
      - /app/.infraguard:noexec,nosuid,nodev,size=10m,uid=1000,gid=1000
    volumes:
      - ./config.yaml:/app/config/config.yaml:ro
      - ./profiles:/app/config/profiles:ro
      # Managed volume - see data-init above for why. Inspect the DB with:
      #   docker cp infraguard-proxy:/app/data/infraguard.db .
      - infraguard-data:/app/data

  dashboard:
    image: infraguard:latest
    container_name: infraguard-dashboard
    restart: unless-stopped
    command: ["dashboard", "-c", "/app/config/config.yaml"]
    env_file:
      - .env
    environment:
      # Same reasoning as the proxy - the dashboard's ``api.bind`` in
      # config.yaml defaults to 127.0.0.1, but inside the container that
      # means only the container itself can reach it. The published port
      # (127.0.0.1:8080:8080) then delivers a connection refused. Bind
      # to 0.0.0.0 so the compose port publish actually works.
      - INFRAGUARD_API_BIND=0.0.0.0
      - INFRAGUARD_PROXY_API=http://infraguard-proxy:8080
    ports:
      - "127.0.0.1:8080:8080"
    depends_on:
      data-init:
        condition: service_completed_successfully
      proxy:
        condition: service_started
    tmpfs:
      - /app/.infraguard:noexec,nosuid,nodev,size=10m,uid=1000,gid=1000
    volumes:
      - ./config.yaml:/app/config/config.yaml:ro
      - ./profiles:/app/config/profiles:ro
      - infraguard-data:/app/data

volumes:
  infraguard-data:
"""

# ── .env template ─────────────────────────────────────────────────────

def _generate_env(
    domain: str,
    upstream: str,
    profile_type: str,
    api_token: str | None = None,
    health_path: str | None = None,
    letsencrypt: bool = False,
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
# Cert paths below are only consulted when INFRAGUARD_LETSENCRYPT=true
# AND the certbot service in the compose file has actually run against
# INFRAGUARD_DOMAIN. Enable both together:
#   1. Point DNS for the domain at this host.
#   2. Set INFRAGUARD_LETSENCRYPT=true and edit INFRAGUARD_DOMAIN_EMAIL.
#   3. docker compose --profile letsencrypt up certbot
#   4. Restart the proxy to pick up the new cert.
# With LE=false the proxy falls back to HTTP on 443. Use for local dev
# and staging only; production always needs a real cert.
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
        # Bind the dashboard API to 0.0.0.0 inside the container so the
        # compose ``ports:`` publish (127.0.0.1:8080:8080) can reach it.
        # The default is 127.0.0.1 which is safe on a bare host but
        # renders the container port unusable - v0.4 bundle bug F5. The
        # published mapping still restricts external exposure.
        bind="0.0.0.0",
    )

    # Force the tracking DB path to the container's writable volume
    # mount. The default from :data:`~infraguard.config.schema.DEFAULT_DB_PATH`
    # is platform-dependent - on Windows it resolves to
    # ``C:\Users\<who>\.config\infraguard\infraguard.db`` and gets baked
    # into the generated YAML, which the containerised proxy (running
    # as UID 1000 on Linux) cannot open - v0.4 bundle bug F2 (root
    # cause). ``${INFRAGUARD_DB_PATH}`` lets .env still override it.
    tracking_cfg = TrackingConfig(db_path="${INFRAGUARD_DB_PATH}")

    return InfraGuardConfig(
        listeners=[listener_cfg],
        domains={domain: domain_cfg},
        api=api_cfg,
        tracking=tracking_cfg,
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

    # .env - fully populated with auto-generated secrets.
    # A blank ``domain`` here would produce a malformed cert path
    # ``/app/certs/live//fullchain.pem`` (v0.4 bug F4); the caller in
    # infraguard/cli/config_cmds.py now passes domain/upstream through so
    # the placeholder branch below only fires for direct API callers.
    env_content = _generate_env(
        domain=domain or "example.com",
        upstream=upstream or "https://10.0.0.5:8443",
        profile_type=profile_type,
    )
    (out_dir / ".env").write_text(env_content, encoding="utf-8")

    # docker-compose.yml - templated per-bundle so the volume list is
    # rendered once and can grow later (e.g. rules/, decoys/).
    (out_dir / "docker-compose.yml").write_text(
        _render_docker_compose(domain or "example.com"), encoding="utf-8"
    )

    # profiles/ - copy the profile so the bundle is self-contained.
    if profile_source is not None:
        profiles_dir = out_dir / "profiles"
        profiles_dir.mkdir(exist_ok=True)
        shutil.copy2(profile_source, profiles_dir / profile_source.name)

    # data/ - must exist and be writable for the SQLite tracking DB.
    # Without this, ``docker compose up`` failed with
    # ``sqlite3.OperationalError: unable to open database file`` because
    # the compose bind-mount source did not exist (v0.4 bug F2).
    (out_dir / "data").mkdir(exist_ok=True)
