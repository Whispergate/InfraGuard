"""Tests for configuration loading and schema validation."""

import os
import tempfile
from pathlib import Path
from unittest.mock import patch

import pytest

from infraguard.config.loader import load_config, _resolve_env_vars
from infraguard.config.schema import (
    ContentBackendConfig,
    ContentRouteConfig,
    DomainConfig,
    EventFilterConfig,
    InfraGuardConfig,
    ListenerConfig,
    PluginSettings,
)
from infraguard.models.common import ContentBackendType


class TestEnvVarResolution:
    def test_resolve_string_value(self):
        os.environ["TEST_VAR_1"] = "hello"
        result = _resolve_env_vars("${TEST_VAR_1}")
        assert result == "hello"
        del os.environ["TEST_VAR_1"]

    def test_resolve_in_dict_value(self):
        os.environ["TEST_VAR_2"] = "world"
        result = _resolve_env_vars({"key": "${TEST_VAR_2}"})
        assert result["key"] == "world"
        del os.environ["TEST_VAR_2"]

    def test_resolve_in_dict_key(self):
        os.environ["TEST_KEY"] = "mykey"
        result = _resolve_env_vars({"${TEST_KEY}": "value"})
        assert "mykey" in result
        del os.environ["TEST_KEY"]

    def test_resolve_in_list(self):
        os.environ["TEST_VAR_3"] = "item"
        result = _resolve_env_vars(["${TEST_VAR_3}", "static"])
        assert result[0] == "item"
        del os.environ["TEST_VAR_3"]

    def test_unset_var_preserved(self):
        result = _resolve_env_vars("${NONEXISTENT_VAR_XYZ}")
        assert result == "${NONEXISTENT_VAR_XYZ}"


class TestConfigLoading:
    def test_load_minimal_config(self):
        yaml_content = """
domains:
  test.local:
    upstream: "https://127.0.0.1:8443"
    profile_path: "test.profile"
    profile_type: "cobalt_strike"
"""
        with tempfile.NamedTemporaryFile("w", suffix=".yaml", delete=False) as f:
            f.write(yaml_content)
            f.flush()
            cfg = load_config(f.name)
        assert "test.local" in cfg.domains
        assert cfg.domains["test.local"].upstream == "https://127.0.0.1:8443"
        os.unlink(f.name)

    def test_load_multi_protocol_listeners(self):
        yaml_content = """
listeners:
  - protocol: https
    port: 443
  - protocol: dns
    port: 53
    options:
      upstream: "8.8.8.8:53"
  - protocol: mqtt
    port: 1883
    options:
      upstream: "mqtt://broker:1883"
domains:
  test.local:
    upstream: "https://127.0.0.1:8443"
    profile_path: "test.profile"
"""
        with tempfile.NamedTemporaryFile("w", suffix=".yaml", delete=False) as f:
            f.write(yaml_content)
            f.flush()
            cfg = load_config(f.name)
        assert len(cfg.listeners) == 3
        assert cfg.listeners[0].protocol == "https"
        assert cfg.listeners[1].protocol == "dns"
        assert cfg.listeners[1].options["upstream"] == "8.8.8.8:53"
        assert cfg.listeners[2].protocol == "mqtt"
        os.unlink(f.name)

    def test_load_content_routes(self):
        yaml_content = """
domains:
  test.local:
    upstream: "https://127.0.0.1:8443"
    profile_path: "test.profile"
    content_routes:
      - path: "/downloads/*"
        backend:
          type: "filesystem"
          target: "/tmp/decoys"
        track: true
"""
        with tempfile.NamedTemporaryFile("w", suffix=".yaml", delete=False) as f:
            f.write(yaml_content)
            f.flush()
            cfg = load_config(f.name)
        routes = cfg.domains["test.local"].content_routes
        assert len(routes) == 1
        assert routes[0].path == "/downloads/*"
        assert routes[0].backend.type == ContentBackendType.FILESYSTEM
        os.unlink(f.name)

    def test_load_plugin_settings(self):
        yaml_content = """
domains:
  test.local:
    upstream: "https://127.0.0.1:8443"
    profile_path: "test.profile"
plugins:
  - "infraguard.plugins.builtin.example"
plugin_settings:
  example:
    enabled: true
    event_filter:
      only_blocked: true
      min_score: 0.5
    options:
      key1: "value1"
"""
        with tempfile.NamedTemporaryFile("w", suffix=".yaml", delete=False) as f:
            f.write(yaml_content)
            f.flush()
            cfg = load_config(f.name)
        assert "example" in cfg.plugin_settings
        ps = cfg.plugin_settings["example"]
        assert ps.enabled is True
        assert ps.event_filter.only_blocked is True
        assert ps.event_filter.min_score == 0.5
        assert ps.options["key1"] == "value1"
        os.unlink(f.name)


class TestSchemaModels:
    def test_listener_config_defaults(self):
        lc = ListenerConfig()
        assert lc.protocol == "https"
        assert lc.bind == "0.0.0.0"
        assert lc.port == 443
        assert lc.options == {}

    def test_domain_config_defaults(self):
        dc = DomainConfig(
            upstream="https://test:443",
            profile_path="test.profile",
        )
        assert dc.profile_type.value == "cobalt_strike"
        assert dc.content_routes == []
        assert dc.whitelist_cidrs == []

    def test_event_filter_config(self):
        ef = EventFilterConfig(only_blocked=True, min_score=0.5)
        assert ef.only_blocked is True
        assert ef.min_score == 0.5
        assert ef.include_domains == []

    def test_plugin_settings(self):
        ps = PluginSettings(
            enabled=False,
            options={"url": "https://example.com"},
        )
        assert ps.enabled is False
        assert ps.options["url"] == "https://example.com"

    def test_domain_config_circuit_breaker_defaults(self):
        """DomainConfig has circuit_breaker_threshold and circuit_breaker_cooldown fields."""
        dc = DomainConfig(upstream="https://test:443", profile_path="test.profile")
        assert dc.circuit_breaker_threshold == 5
        assert dc.circuit_breaker_cooldown == 30.0


class TestStartupValidation:
    """Startup profile path validation in DomainRouter (RESL-03)."""

    def _make_config(self, domains: dict) -> "InfraGuardConfig":
        from infraguard.config.schema import (
            DropActionConfig,
            InfraGuardConfig,
            ListenerConfig,
            PipelineConfig,
        )
        return InfraGuardConfig(
            listeners=[ListenerConfig(protocol="https", bind="127.0.0.1", port=8443)],
            domains=domains,
            pipeline=PipelineConfig(
                enable_ip_filter=False,
                enable_bot_filter=False,
                enable_header_filter=False,
                enable_dns_filter=False,
                enable_replay_filter=False,
            ),
        )

    def test_profile_valid_path_initializes_without_error(self, tmp_path: Path):
        """Test 1: Valid profile_path files - DomainRouter initializes without error."""
        from infraguard.core.router import DomainRouter
        from unittest.mock import patch, MagicMock
        from infraguard.profiles.models import C2Profile, HttpTransaction, ClientConfig, ServerConfig, MessageConfig

        profile_file = tmp_path / "test.profile"
        profile_file.write_text("# profile")

        config = self._make_config({
            "test.local": DomainConfig(
                upstream="https://127.0.0.1:9999",
                profile_path=str(profile_file),
            )
        })

        dummy_profile = C2Profile(
            name="test",
            http_get=HttpTransaction(
                verb="GET", uris=["/cb"],
                client=ClientConfig(
                    headers={}, message=MessageConfig(location="cookie", name="s"),
                    transforms=[],
                ),
                server=ServerConfig(headers={}),
            ),
            http_post=HttpTransaction(
                verb="POST", uris=["/post"],
                client=ClientConfig(
                    headers={}, message=MessageConfig(location="body", name=""),
                    transforms=[],
                ),
                server=ServerConfig(headers={}),
            ),
            useragent="Test/1.0",
        )

        with patch("infraguard.core.router.DomainRouter._load_profile", return_value=dummy_profile):
            router = DomainRouter(config)
        assert "test.local" in router.routes

    def test_startup_missing_profile_raises_file_not_found(self, tmp_path: Path):
        """Test 2: Missing profile_path file - DomainRouter.__init__ raises FileNotFoundError."""
        from infraguard.core.router import DomainRouter

        missing = tmp_path / "nonexistent.profile"
        # Do NOT create the file

        config = self._make_config({
            "test.local": DomainConfig(
                upstream="https://127.0.0.1:9999",
                profile_path=str(missing),
            )
        })

        with pytest.raises(FileNotFoundError) as exc_info:
            DomainRouter(config)

        error_msg = str(exc_info.value)
        assert "test.local" in error_msg
        assert "nonexistent.profile" in error_msg

    def test_startup_missing_profile_identifies_specific_domain(self, tmp_path: Path):
        """Test 3: Multiple domains, one missing profile - error names the bad domain."""
        from infraguard.core.router import DomainRouter
        from unittest.mock import patch
        from infraguard.profiles.models import C2Profile, HttpTransaction, ClientConfig, ServerConfig, MessageConfig

        good_file = tmp_path / "good.profile"
        good_file.write_text("# profile")
        missing = tmp_path / "bad.profile"
        # Do NOT create bad.profile

        config = self._make_config({
            "good.local": DomainConfig(
                upstream="https://127.0.0.1:9999",
                profile_path=str(good_file),
            ),
            "bad.local": DomainConfig(
                upstream="https://127.0.0.1:9999",
                profile_path=str(missing),
            ),
        })

        with pytest.raises(FileNotFoundError) as exc_info:
            DomainRouter(config)

        error_msg = str(exc_info.value)
        assert "bad.local" in error_msg
        assert "bad.profile" in error_msg
