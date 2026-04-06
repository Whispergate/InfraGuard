"""Configuration loading from YAML files with environment variable overlay.

Automatically loads a ``.env`` file (if present) before resolving
``${ENV_VAR}`` references in the YAML config.  The lookup order is:

1. Real environment variables (always win)
2. Values from ``.env`` in the current working directory
3. Values from ``.env`` next to the config file

Encrypted config support:
  If the config path ends in ``.age``, InfraGuard will attempt to
  decrypt it using the ``age`` CLI tool before parsing.  The decryption
  identity is resolved from (in order):

  1. ``INFRAGUARD_AGE_KEY`` env var (inline private key)
  2. ``INFRAGUARD_AGE_KEY_FILE`` env var (path to identity file)
  3. ``~/.config/infraguard/age-identity.txt``
  4. ``~/.config/age/keys.txt`` (age default)
"""

from __future__ import annotations

import os
import re
import subprocess
import tempfile
from pathlib import Path

import structlog
import yaml

from infraguard.config.schema import InfraGuardConfig

log = structlog.get_logger()


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

_AGE_IDENTITY_SEARCH_PATHS = [
    Path.home() / ".config" / "infraguard" / "age-identity.txt",
    Path.home() / ".config" / "age" / "keys.txt",
]


def _resolve_age_identity() -> Path | None:
    """Find the age identity file for decryption."""
    # Inline key via env var — write to temp file for age CLI
    inline_key = os.environ.get("INFRAGUARD_AGE_KEY")
    if inline_key:
        tmp = Path(tempfile.mkdtemp()) / "age-identity.txt"
        tmp.write_text(inline_key, encoding="utf-8")
        return tmp

    # Explicit path via env var
    key_file = os.environ.get("INFRAGUARD_AGE_KEY_FILE")
    if key_file:
        p = Path(key_file)
        if p.is_file():
            return p
        raise FileNotFoundError(f"INFRAGUARD_AGE_KEY_FILE not found: {key_file}")

    # Search default locations
    for candidate in _AGE_IDENTITY_SEARCH_PATHS:
        if candidate.is_file():
            return candidate

    return None


def _decrypt_age_file(encrypted_path: Path) -> str:
    """Decrypt an age-encrypted file and return the plaintext content.

    Requires the ``age`` CLI tool to be installed.
    """
    identity = _resolve_age_identity()
    if identity is None:
        raise RuntimeError(
            "Cannot decrypt age-encrypted config: no identity found. "
            "Set INFRAGUARD_AGE_KEY, INFRAGUARD_AGE_KEY_FILE, or place "
            "an identity at ~/.config/infraguard/age-identity.txt"
        )

    cmd = ["age", "--decrypt", "--identity", str(identity), str(encrypted_path)]
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            check=True,
            timeout=10,
        )
    except FileNotFoundError:
        raise RuntimeError(
            "age CLI not found. Install it: https://github.com/FiloSottile/age"
        )
    except subprocess.CalledProcessError as e:
        raise RuntimeError(f"age decryption failed: {e.stderr.strip()}")

    log.info("config_decrypted", path=str(encrypted_path))
    return result.stdout


def _decrypt_sops_file(config_path: Path) -> dict:
    """Decrypt a SOPS-encrypted YAML file and return parsed dict."""
    cmd = ["sops", "--decrypt", str(config_path)]
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            check=True,
            timeout=15,
        )
    except FileNotFoundError:
        raise RuntimeError(
            "sops CLI not found. Install it: https://github.com/getsops/sops"
        )
    except subprocess.CalledProcessError as e:
        raise RuntimeError(f"SOPS decryption failed: {e.stderr.strip()}")

    log.info("config_decrypted_sops", path=str(config_path))
    return yaml.safe_load(result.stdout)


def _resolve_env_vars(obj: object) -> object:
    """Recursively resolve ${ENV_VAR} references in config values.

    Unset env vars resolve to empty string. The None-coercion for
    top-level keys is handled separately in ``load_config``.
    """
    if isinstance(obj, str):
        def _replacer(match: re.Match[str]) -> str:
            var_name = match.group(1)
            return os.environ.get(var_name, "")
        return _ENV_VAR_PATTERN.sub(_replacer, obj)
    elif isinstance(obj, dict):
        return {_resolve_env_vars(k): _resolve_env_vars(v) for k, v in obj.items()}
    elif isinstance(obj, list):
        return [_resolve_env_vars(item) for item in obj]
    return obj


def load_config(path: str | Path) -> InfraGuardConfig:
    """Load and validate an InfraGuard configuration from a YAML file.

    Supports age-encrypted configs: if *path* ends in ``.age``, the file
    is decrypted in-memory before parsing.  SOPS-encrypted YAML files
    (detected by a top-level ``sops`` key) are decrypted via ``sops -d``.
    """
    config_path = Path(path).resolve()
    if not config_path.exists():
        raise FileNotFoundError(f"Config file not found: {config_path}")

    # Load .env before resolving variables
    _load_dotenv(config_path.parent, Path.cwd())

    # Handle encrypted configs
    if config_path.suffix == ".age":
        plaintext = _decrypt_age_file(config_path)
        raw = yaml.safe_load(plaintext)
    else:
        with open(config_path) as f:
            raw = yaml.safe_load(f)

        # Detect SOPS-encrypted YAML (has a top-level "sops" metadata key)
        if isinstance(raw, dict) and "sops" in raw:
            raw = _decrypt_sops_file(config_path)

    if raw is None:
        raw = {}

    resolved = _resolve_env_vars(raw)

    # Post-processing for Pydantic compatibility
    if isinstance(resolved, dict):
        for key, value in resolved.items():
            # YAML produces None for keys with no value (all entries commented out)
            if value is None:
                resolved[key] = {}

    # Remove keys with empty string values from nested dicts so Pydantic
    # uses the field's default. This handles unset env vars that resolved
    # to "" (e.g., ${INFRAGUARD_GEOIP_DB} when not set).
    # Also drop empty-string dict keys (from unset env vars used as keys)
    # and collapse resulting empty dicts to None so parent keys fall back
    # to Pydantic defaults.
    def _drop_empty_strings(obj):
        if isinstance(obj, dict):
            cleaned = {}
            for k, v in obj.items():
                if k == "":
                    continue  # skip empty-string keys (unset env var as key)
                if v == "":
                    continue
                child = _drop_empty_strings(v)
                # Drop dicts that became empty after cleaning (e.g. tls: {})
                # so the parent field falls back to its Pydantic default (None).
                if isinstance(child, dict) and not child:
                    continue
                cleaned[k] = child
            return cleaned
        elif isinstance(obj, list):
            return [_drop_empty_strings(i) for i in obj if i != ""]
        return obj

    resolved = _drop_empty_strings(resolved)

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
