"""Tests for SIGHUP config hot-reload (RESL-04)."""

from __future__ import annotations

import asyncio
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from pydantic import ValidationError

from infraguard.config.reloader import ConfigReloader
from infraguard.config.schema import (
    DomainConfig,
    DropActionConfig,
    InfraGuardConfig,
    ListenerConfig,
    PipelineConfig,
)
from infraguard.core.router import DomainRouter

# Path to a real example profile (used by DomainRouter.reload() tests)
_EXAMPLE_PROFILE = "examples/jquery-c2.3.14.profile"


def _make_config(profile_path: str = _EXAMPLE_PROFILE) -> InfraGuardConfig:
    """Build a minimal InfraGuardConfig pointing at an existing profile."""
    return InfraGuardConfig(
        listeners=[ListenerConfig(protocol="https", bind="127.0.0.1", port=8443)],
        domains={
            "test.local": DomainConfig(
                upstream="https://127.0.0.1:9999",
                profile_path=profile_path,
                profile_type="cobalt_strike",
                drop_action=DropActionConfig(type="redirect", target="https://example.com"),
            ),
        },
        pipeline=PipelineConfig(block_score_threshold=0.7),
    )


# ---------------------------------------------------------------------------
# Test 1: ConfigReloader._reload() with valid config calls router.reload()
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_config_reloader_calls_router_reload_on_valid_config():
    """_reload() with valid config should call router.reload() with new config."""
    valid_config = _make_config()
    mock_router = MagicMock()
    mock_router.reload = AsyncMock(return_value=None)

    reloader = ConfigReloader(Path("config/config.yaml"), mock_router)

    with patch("infraguard.config.reloader.load_config", return_value=valid_config):
        await reloader._reload()

    mock_router.reload.assert_awaited_once_with(valid_config)


# ---------------------------------------------------------------------------
# Test 2: ConfigReloader._reload() with invalid config does NOT call router.reload()
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_config_reloader_rejects_invalid_config():
    """_reload() with invalid config (ValidationError) should NOT call router.reload()."""
    mock_router = MagicMock()
    mock_router.reload = AsyncMock(return_value=None)

    reloader = ConfigReloader(Path("config/config.yaml"), mock_router)

    # Simulate load_config raising a pydantic ValidationError
    from pydantic import TypeAdapter
    try:
        TypeAdapter(int).validate_python("not-an-int")
    except ValidationError as ve:
        fake_error = ve
    else:
        # Fallback: manually construct similar error
        fake_error = ValidationError.from_exception_data("test", [])

    with patch("infraguard.config.reloader.load_config", side_effect=fake_error):
        await reloader._reload()

    mock_router.reload.assert_not_awaited()


# ---------------------------------------------------------------------------
# Test 3: ConfigReloader._reload() with missing config file does NOT call router.reload()
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_config_reloader_rejects_missing_file():
    """_reload() with missing config file should NOT call router.reload()."""
    mock_router = MagicMock()
    mock_router.reload = AsyncMock(return_value=None)

    reloader = ConfigReloader(Path("/nonexistent/config.yaml"), mock_router)

    with patch("infraguard.config.reloader.load_config", side_effect=FileNotFoundError("not found")):
        await reloader._reload()

    mock_router.reload.assert_not_awaited()


# ---------------------------------------------------------------------------
# Test 4: DomainRouter.reload() swaps routes atomically
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_domain_router_reload_swaps_routes():
    """DomainRouter.reload() should make new routes visible after swap."""
    config = _make_config()
    router = DomainRouter(config)

    # Verify initial state
    assert "test.local" in router.routes

    # Build a new config with a different domain name
    new_config = InfraGuardConfig(
        listeners=[ListenerConfig(protocol="https", bind="127.0.0.1", port=8443)],
        domains={
            "new.local": DomainConfig(
                upstream="https://127.0.0.1:9998",
                profile_path=_EXAMPLE_PROFILE,
                profile_type="cobalt_strike",
                drop_action=DropActionConfig(type="redirect", target="https://example.com"),
            ),
        },
        pipeline=PipelineConfig(block_score_threshold=0.7),
    )

    await router.reload(new_config)

    assert "new.local" in router.routes
    assert "test.local" not in router.routes
    assert router.config is new_config


# ---------------------------------------------------------------------------
# Test 5: DomainRouter.reload() creates new circuit breakers for new upstreams
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_domain_router_reload_creates_new_circuit_breakers():
    """reload() should create new CircuitBreaker instances for new upstream URLs."""
    config = _make_config()
    router = DomainRouter(config)

    original_upstream = "https://127.0.0.1:9999"
    assert original_upstream in router._breakers
    original_breaker = router._breakers[original_upstream]

    # New config with a different upstream
    new_upstream = "https://127.0.0.1:7777"
    new_config = InfraGuardConfig(
        listeners=[ListenerConfig(protocol="https", bind="127.0.0.1", port=8443)],
        domains={
            "test.local": DomainConfig(
                upstream=new_upstream,
                profile_path=_EXAMPLE_PROFILE,
                profile_type="cobalt_strike",
                drop_action=DropActionConfig(type="redirect", target="https://example.com"),
            ),
        },
        pipeline=PipelineConfig(block_score_threshold=0.7),
    )

    await router.reload(new_config)

    # New upstream should have a new breaker
    assert new_upstream in router._breakers
    new_breaker = router._breakers[new_upstream]
    # It's a new instance (old upstream is gone)
    assert original_upstream not in router._breakers
    assert new_breaker is not original_breaker


# ---------------------------------------------------------------------------
# Test 5b: DomainRouter.reload() preserves existing breaker for unchanged upstream
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_domain_router_reload_preserves_breaker_for_unchanged_upstream():
    """reload() should preserve existing CircuitBreaker state for unchanged upstreams."""
    config = _make_config()
    router = DomainRouter(config)

    upstream = "https://127.0.0.1:9999"
    original_breaker = router._breakers[upstream]

    # New config keeping same upstream
    new_config = _make_config()

    await router.reload(new_config)

    # Same upstream -> same breaker object preserved
    assert upstream in router._breakers
    assert router._breakers[upstream] is original_breaker
