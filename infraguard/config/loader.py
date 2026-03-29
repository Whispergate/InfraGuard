"""Configuration loading from YAML files with environment variable overlay.

Automatically loads a ``.env`` file (if present) before resolving
``${ENV_VAR}`` references in the YAML config.  The lookup order is:

1. Real environment variables (always win)
2. Values from ``.env`` in the current working directory
3. Values from ``.env`` next to the config file
"""

from __future__ import annotations

import os
import re
from pathlib import Path

import yaml

from infraguard.config.schema import InfraGuardConfig


def _load_dotenv(*search_paths: Path) -> None:
    """Load .env files into os.environ (first found wins, no overwrite)."""
    for base in search_paths:
        env_file = base / ".env" if base.is_dir() else base.parent / ".env"
        if env_file.is_file():
            for line in env_file.read_text(encoding="utf-8").splitlines():
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                if "=" not in line:
                    continue
                key, _, value = line.partition("=")
                key = key.strip()
                value = value.strip().strip("'\"")
                # Don't overwrite existing env vars
                if key and key not in os.environ:
                    os.environ[key] = value
            break  # only load the first .env found


_ENV_VAR_PATTERN = re.compile(r"\$\{([^}]+)\}")


def _resolve_env_vars(obj: object) -> object:
    """Recursively resolve ${ENV_VAR} references in config values."""
    if isinstance(obj, str):
        def _replacer(match: re.Match[str]) -> str:
            var_name = match.group(1)
            return os.environ.get(var_name, match.group(0))
        return _ENV_VAR_PATTERN.sub(_replacer, obj)
    elif isinstance(obj, dict):
        return {k: _resolve_env_vars(v) for k, v in obj.items()}
    elif isinstance(obj, list):
        return [_resolve_env_vars(item) for item in obj]
    return obj


def load_config(path: str | Path) -> InfraGuardConfig:
    """Load and validate an InfraGuard configuration from a YAML file."""
    config_path = Path(path).resolve()
    if not config_path.exists():
        raise FileNotFoundError(f"Config file not found: {config_path}")

    # Load .env before resolving variables
    _load_dotenv(config_path.parent, Path.cwd())

    with open(config_path) as f:
        raw = yaml.safe_load(f)

    if raw is None:
        raw = {}

    resolved = _resolve_env_vars(raw)
    return InfraGuardConfig.model_validate(resolved)


def generate_default_config() -> str:
    """Generate a starter YAML config string."""
    return """\
# InfraGuard Configuration
# See documentation for full reference

listeners:
  - bind: "0.0.0.0"
    port: 443
    tls:
      cert: "/etc/letsencrypt/live/example.com/fullchain.pem"
      key: "/etc/letsencrypt/live/example.com/privkey.pem"
    domains:
      - "cdn.example.com"

domains:
  cdn.example.com:
    upstream: "https://10.0.0.5:8443"
    profile_path: "profiles/jquery-c2.3.14.profile"
    profile_type: "cobalt_strike"
    whitelist_cidrs:
      - "192.168.1.0/24"
    decoy_dir: null
    drop_action:
      type: "redirect"
      target: "https://jquery.com"

intel:
  geoip_db: null
  blocked_countries: []
  blocked_asns: []
  auto_block_scanners: true
  dynamic_whitelist_threshold: 3

tracking:
  db_path: "infraguard.db"
  retention_days: 30

pipeline:
  block_score_threshold: 0.7
  enable_ip_filter: true
  enable_bot_filter: true
  enable_header_filter: true
  enable_geo_filter: true
  enable_dns_filter: true
  enable_replay_filter: true
  enable_profile_filter: true

api:
  bind: "127.0.0.1"
  port: 8080
  auth_token: "${INFRAGUARD_API_TOKEN}"

logging:
  level: "INFO"
  format: "json"

plugins: []
"""
