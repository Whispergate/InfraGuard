"""SIGHUP-triggered config hot-reload."""

from __future__ import annotations

import asyncio
import signal
from pathlib import Path

import structlog
from pydantic import ValidationError

from infraguard.config.loader import load_config

log = structlog.get_logger()


class ConfigReloader:
    """Handles SIGHUP-triggered config reload.

    Validates new config before applying. On validation failure,
    the running config is preserved and an error is logged.
    """

    def __init__(self, config_path: Path, router) -> None:
        self._config_path = config_path
        self._router = router

    def install(self, loop: asyncio.AbstractEventLoop) -> None:
        """Register SIGHUP handler on the given event loop."""
        loop.add_signal_handler(
            signal.SIGHUP,
            lambda: asyncio.create_task(self._reload()),
        )
        log.info("sighup_handler_installed", config_path=str(self._config_path))

    async def _reload(self) -> None:
        """Attempt config reload. Reject invalid config, preserve running state."""
        log.info("config_reload_triggered")
        try:
            new_config = load_config(self._config_path)
        except (FileNotFoundError, ValidationError) as exc:
            log.error("config_reload_rejected", error=str(exc))
            return
        try:
            await self._router.reload(new_config)
            log.info("config_reloaded", path=str(self._config_path))
        except Exception as exc:
            log.error("config_reload_apply_failed", error=str(exc))
