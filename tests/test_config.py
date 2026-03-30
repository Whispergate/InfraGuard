"""Tests for configuration loading and schema validation."""

import os
import tempfile

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
