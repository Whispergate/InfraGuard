"""Tests for infraguard.deploy.config_gen and infraguard.deploy.profile_detect."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
import yaml


# ── profile_detect tests ──────────────────────────────────────────────


def test_detect_profile_type_cobalt_strike(tmp_path):
    from infraguard.deploy.profile_detect import detect_profile_type
    from infraguard.models.common import ProfileType

    p = tmp_path / "test.profile"
    p.write_text("# cobalt strike profile")
    assert detect_profile_type(p) == ProfileType.COBALT_STRIKE


def test_detect_profile_type_havoc(tmp_path):
    from infraguard.deploy.profile_detect import detect_profile_type
    from infraguard.models.common import ProfileType

    p = tmp_path / "test.toml"
    p.write_text("[Demon]\nSleep = 5000")
    assert detect_profile_type(p) == ProfileType.HAVOC


def test_detect_profile_type_mythic(tmp_path):
    from infraguard.deploy.profile_detect import detect_profile_type
    from infraguard.models.common import ProfileType

    p = tmp_path / "test.json"
    p.write_text(json.dumps({"payload_type": "apfell", "c2_profiles": []}))
    assert detect_profile_type(p) == ProfileType.MYTHIC


def test_detect_profile_type_brute_ratel(tmp_path):
    from infraguard.deploy.profile_detect import detect_profile_type
    from infraguard.models.common import ProfileType

    p = tmp_path / "test.json"
    p.write_text(json.dumps({"listeners": [], "c2_handler": {}}))
    assert detect_profile_type(p) == ProfileType.BRUTE_RATEL


def test_detect_profile_type_sliver(tmp_path):
    from infraguard.deploy.profile_detect import detect_profile_type
    from infraguard.models.common import ProfileType

    p = tmp_path / "test.json"
    p.write_text(json.dumps({"implant_config": {}, "server_config": {}}))
    assert detect_profile_type(p) == ProfileType.SLIVER


def test_detect_profile_type_unknown_extension(tmp_path):
    from infraguard.deploy.profile_detect import detect_profile_type

    p = tmp_path / "test.xyz"
    p.write_text("unknown")
    with pytest.raises(ValueError, match="Cannot auto-detect"):
        detect_profile_type(p)


# Path-only detection (file may not exist - container path)
def test_detect_profile_type_by_extension_only():
    """detect_profile_type should work from extension alone when file doesn't exist."""
    from infraguard.deploy.profile_detect import detect_profile_type
    from infraguard.models.common import ProfileType

    # File does not exist - extension-only fallback
    p = Path("/config/profiles/cs.profile")
    assert detect_profile_type(p) == ProfileType.COBALT_STRIKE

    p2 = Path("/config/profiles/havoc.toml")
    assert detect_profile_type(p2) == ProfileType.HAVOC


# ── generate_config tests ─────────────────────────────────────────────


def test_generate_config_returns_infraguard_config():
    from infraguard.config.schema import InfraGuardConfig
    from infraguard.deploy.config_gen import generate_config

    cfg = generate_config(
        domain="evil.com",
        c2_profile_path="/config/profiles/cs.profile",
        upstream="https://10.0.0.5:8443",
    )
    assert isinstance(cfg, InfraGuardConfig)


def test_generate_config_domain_in_domains():
    from infraguard.deploy.config_gen import generate_config

    cfg = generate_config(
        domain="evil.com",
        c2_profile_path="/config/profiles/cs.profile",
        upstream="https://10.0.0.5:8443",
    )
    assert "evil.com" in cfg.domains


def test_generate_config_upstream_matches():
    from infraguard.deploy.config_gen import generate_config

    cfg = generate_config(
        domain="evil.com",
        c2_profile_path="/config/profiles/cs.profile",
        upstream="https://10.0.0.5:8443",
    )
    assert cfg.domains["evil.com"].upstream == "https://10.0.0.5:8443"


def test_generate_config_container_relative_profile_path():
    from infraguard.deploy.config_gen import generate_config

    cfg = generate_config(
        domain="evil.com",
        c2_profile_path="/config/profiles/cs.profile",
        upstream="https://10.0.0.5:8443",
    )
    assert cfg.domains["evil.com"].profile_path == "/config/profiles/cs.profile"


def test_generate_config_auto_profile_type_from_extension():
    from infraguard.deploy.config_gen import generate_config
    from infraguard.models.common import ProfileType

    cfg = generate_config(
        domain="evil.com",
        c2_profile_path="/config/profiles/cs.profile",
        upstream="https://10.0.0.5:8443",
        profile_type="auto",
    )
    assert cfg.domains["evil.com"].profile_type == ProfileType.COBALT_STRIKE


def test_generate_config_api_auth_token_is_env_ref():
    from infraguard.deploy.config_gen import generate_config

    cfg = generate_config(
        domain="evil.com",
        c2_profile_path="/config/profiles/cs.profile",
        upstream="https://10.0.0.5:8443",
    )
    assert cfg.api.auth_token == "${INFRAGUARD_API_TOKEN}"


def test_generate_config_listener_on_443():
    from infraguard.deploy.config_gen import generate_config

    cfg = generate_config(
        domain="evil.com",
        c2_profile_path="/config/profiles/cs.profile",
        upstream="https://10.0.0.5:8443",
    )
    assert len(cfg.listeners) == 1
    listener = cfg.listeners[0]
    assert listener.bind == "0.0.0.0"
    assert listener.port == 443
    assert "evil.com" in listener.domains


# ── write_bundle tests ────────────────────────────────────────────────


def test_write_bundle_creates_output_directory(tmp_path):
    from infraguard.deploy.config_gen import generate_config, write_bundle

    out = tmp_path / "bundle"
    cfg = generate_config("evil.com", "/config/profiles/cs.profile", "https://10.0.0.5:8443")
    write_bundle(cfg, out)
    assert out.is_dir()


def test_write_bundle_creates_config_yaml(tmp_path):
    from infraguard.deploy.config_gen import generate_config, write_bundle

    out = tmp_path / "bundle"
    cfg = generate_config("evil.com", "/config/profiles/cs.profile", "https://10.0.0.5:8443")
    write_bundle(cfg, out)
    assert (out / "config.yaml").is_file()


def test_write_bundle_creates_env(tmp_path):
    from infraguard.deploy.config_gen import generate_config, write_bundle

    out = tmp_path / "bundle"
    cfg = generate_config("evil.com", "/config/profiles/cs.profile", "https://10.0.0.5:8443")
    write_bundle(cfg, out)
    assert (out / ".env").is_file()


def test_write_bundle_creates_docker_compose(tmp_path):
    from infraguard.deploy.config_gen import generate_config, write_bundle

    out = tmp_path / "bundle"
    cfg = generate_config("evil.com", "/config/profiles/cs.profile", "https://10.0.0.5:8443")
    write_bundle(cfg, out)
    assert (out / "docker-compose.yml").is_file()


def test_write_bundle_config_yaml_is_valid(tmp_path):
    from infraguard.deploy.config_gen import generate_config, write_bundle

    out = tmp_path / "bundle"
    cfg = generate_config("evil.com", "/config/profiles/cs.profile", "https://10.0.0.5:8443")
    write_bundle(cfg, out)
    content = (out / "config.yaml").read_text()
    parsed = yaml.safe_load(content)
    assert isinstance(parsed, dict)


def test_write_bundle_env_contains_api_token(tmp_path):
    from infraguard.deploy.config_gen import generate_config, write_bundle

    out = tmp_path / "bundle"
    cfg = generate_config("evil.com", "/config/profiles/cs.profile", "https://10.0.0.5:8443")
    write_bundle(cfg, out)
    env_content = (out / ".env").read_text()
    assert "INFRAGUARD_API_TOKEN" in env_content


def test_write_bundle_docker_compose_has_profiles_mount(tmp_path):
    from infraguard.deploy.config_gen import generate_config, write_bundle

    out = tmp_path / "bundle"
    cfg = generate_config("evil.com", "/config/profiles/cs.profile", "https://10.0.0.5:8443")
    write_bundle(cfg, out)
    dc_content = (out / "docker-compose.yml").read_text()
    assert "/config/profiles" in dc_content


def test_write_bundle_copies_profile_source(tmp_path):
    from infraguard.deploy.config_gen import generate_config, write_bundle

    # Create a fake profile file
    profile_file = tmp_path / "cs.profile"
    profile_file.write_text("# fake cobalt strike profile")

    out = tmp_path / "bundle"
    cfg = generate_config("evil.com", "/config/profiles/cs.profile", "https://10.0.0.5:8443")
    write_bundle(cfg, out, profile_source=profile_file)

    assert (out / "profiles" / "cs.profile").is_file()
