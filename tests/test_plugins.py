"""Tests for the plugin system and built-in plugins."""

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch
from datetime import datetime, timezone

import pytest

from infraguard.config.schema import EventFilterConfig, PluginSettings
from infraguard.models.events import RequestEvent
from infraguard.plugins.base import BasePlugin
from infraguard.plugins.loader import load_plugins
from infraguard.plugins.builtin._base import ForwardingPlugin
from infraguard.plugins.builtin._batch import BatchForwardingPlugin


def _make_event(**kwargs) -> RequestEvent:
    defaults = dict(
        timestamp=datetime.now(timezone.utc),
        domain="test.local",
        client_ip="1.2.3.4",
        method="GET",
        uri="/callback",
        user_agent="TestAgent/1.0",
        filter_result="block",
        filter_reason="test block",
        filter_score=0.9,
        response_status=302,
        duration_ms=1.5,
        protocol="http",
    )
    defaults.update(kwargs)
    return RequestEvent(**defaults)


# ── BasePlugin ────────────────────────────────────────────────────────

class TestBasePlugin:
    def test_defaults(self):
        p = BasePlugin()
        assert p.name == "unnamed"
        assert p.version == "0.0.0"

    @pytest.mark.asyncio
    async def test_on_event_noop(self):
        p = BasePlugin()
        await p.on_event(_make_event())  # should not raise

    def test_configure(self):
        p = BasePlugin()
        settings = PluginSettings(options={"key": "value"})
        p.configure(settings)
        assert p._settings.options["key"] == "value"


# ── ForwardingPlugin ──────────────────────────────────────────────────

class TestForwardingPlugin:
    def test_should_forward_default_true(self):
        p = ForwardingPlugin()
        assert p._should_forward(_make_event())

    def test_only_blocked_filter(self):
        p = ForwardingPlugin()
        p.configure(PluginSettings(
            event_filter=EventFilterConfig(only_blocked=True),
        ))
        assert p._should_forward(_make_event(filter_result="block"))
        assert not p._should_forward(_make_event(filter_result="allow"))

    def test_only_allowed_filter(self):
        p = ForwardingPlugin()
        p.configure(PluginSettings(
            event_filter=EventFilterConfig(only_allowed=True),
        ))
        assert not p._should_forward(_make_event(filter_result="block"))
        assert p._should_forward(_make_event(filter_result="allow"))

    def test_min_score_filter(self):
        p = ForwardingPlugin()
        p.configure(PluginSettings(
            event_filter=EventFilterConfig(min_score=0.5),
        ))
        assert p._should_forward(_make_event(filter_score=0.9))
        assert not p._should_forward(_make_event(filter_score=0.3))

    def test_include_domains_filter(self):
        p = ForwardingPlugin()
        p.configure(PluginSettings(
            event_filter=EventFilterConfig(include_domains=["test.local"]),
        ))
        assert p._should_forward(_make_event(domain="test.local"))
        assert not p._should_forward(_make_event(domain="other.com"))

    def test_exclude_domains_filter(self):
        p = ForwardingPlugin()
        p.configure(PluginSettings(
            event_filter=EventFilterConfig(exclude_domains=["noisy.local"]),
        ))
        assert p._should_forward(_make_event(domain="test.local"))
        assert not p._should_forward(_make_event(domain="noisy.local"))

    def test_event_to_dict(self):
        p = ForwardingPlugin()
        event = _make_event()
        d = p._event_to_dict(event)
        assert d["domain"] == "test.local"
        assert d["client_ip"] == "1.2.3.4"
        assert d["filter_result"] == "block"

    def test_opt_reads_options(self):
        p = ForwardingPlugin()
        p.configure(PluginSettings(options={"url": "https://es.example.com"}))
        assert p._opt("url") == "https://es.example.com"
        assert p._opt("missing", "default") == "default"


# ── Plugin loader ─────────────────────────────────────────────────────

class TestPluginLoader:
    def test_load_example_plugin(self):
        plugins = load_plugins(["infraguard.plugins.builtin.example"])
        assert len(plugins) == 1
        assert plugins[0].name == "example"

    def test_skip_disabled_plugin(self):
        settings = {
            "example": PluginSettings(enabled=False),
        }
        plugins = load_plugins(
            ["infraguard.plugins.builtin.example"],
            plugin_settings=settings,
        )
        assert len(plugins) == 0

    def test_configure_called(self):
        settings = {
            "example": PluginSettings(options={"test": True}),
        }
        plugins = load_plugins(
            ["infraguard.plugins.builtin.example"],
            plugin_settings=settings,
        )
        assert len(plugins) == 1

    def test_invalid_module_skipped(self):
        plugins = load_plugins(["nonexistent.module.path"])
        assert len(plugins) == 0

    def test_load_all_builtin_plugins(self):
        from infraguard.plugins.builtin import BUILTIN_PLUGINS
        plugins = load_plugins(BUILTIN_PLUGINS)
        names = [p.name for p in plugins]
        assert "elasticsearch" in names
        assert "discord" in names
        assert "slack" in names
        assert "syslog" in names
        assert "wazuh" in names
        assert "generic_webhook" in names


# ── Built-in plugin imports ───────────────────────────────────────────

class TestBuiltinPluginImports:
    def test_elasticsearch_plugin(self):
        from infraguard.plugins.builtin.elasticsearch import Plugin
        p = Plugin()
        assert p.name == "elasticsearch"

    def test_wazuh_plugin(self):
        from infraguard.plugins.builtin.wazuh import Plugin
        p = Plugin()
        assert p.name == "wazuh"

    def test_syslog_plugin(self):
        from infraguard.plugins.builtin.syslog import Plugin
        p = Plugin()
        assert p.name == "syslog"

    def test_discord_plugin(self):
        from infraguard.plugins.builtin.discord import Plugin
        p = Plugin()
        assert p.name == "discord"

    def test_slack_plugin(self):
        from infraguard.plugins.builtin.slack import Plugin
        p = Plugin()
        assert p.name == "slack"

    def test_generic_webhook_plugin(self):
        from infraguard.plugins.builtin.generic_webhook import Plugin
        p = Plugin()
        assert p.name == "generic_webhook"
