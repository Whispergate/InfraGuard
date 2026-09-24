"""Cluster-wide dynamic whitelist.

The historical whitelist lives on :class:`~infraguard.intel.manager.
IntelManager.dynamic_whitelist`. a per-process set. Two proxy replicas
in the same fleet had two independent whitelists, so a beacon that
graduated on replica A was still CIDR-blocked on replica B until it
re-earned trust there.

This module adds a shared-state overlay that any node can push
whitelisted IPs into. The overlay is checked *in addition to* the
process-local set. so a lookup fails only if neither knows about the
IP. Writes flow both ways: the overlay records what the local
IntelManager promoted, and the local manager consults the overlay on
first-request-from-unknown-IP.

Best-effort against the state backend. a Redis blip must never block
a real beacon failures degrade to per-process behavior with a debug
log.
"""

from __future__ import annotations

import time
from typing import TYPE_CHECKING

import structlog

if TYPE_CHECKING:
    from infraguard.state import StateBackend

log = structlog.get_logger()

_WHITELIST_KEY_PREFIX = "wl:"
_DEFAULT_TTL = 86_400 * 3  # 3 days. matches typical engagement window.


class SharedWhitelist:
    """Wraps a :class:`StateBackend` with per-IP TTL entries.

    Callers use the two-line contract: ``await add(ip)`` when the local
    IntelManager grants trust; ``await contains(ip)`` before falling
    back to CIDR gating.
    """

    def __init__(
        self,
        backend: StateBackend | None,
        ttl_seconds: int = _DEFAULT_TTL,
    ):
        self._backend = backend
        self._ttl = ttl_seconds

    async def add(self, ip: str) -> None:
        if self._backend is None:
            return
        try:
            await self._backend.set(
                _WHITELIST_KEY_PREFIX + ip,
                str(int(time.time())),
                ttl_seconds=self._ttl,
            )
        except Exception:
            log.debug("shared_whitelist_write_failed", ip=ip)

    async def contains(self, ip: str) -> bool:
        if self._backend is None:
            return False
        try:
            v = await self._backend.get(_WHITELIST_KEY_PREFIX + ip)
            return v is not None
        except Exception:
            log.debug("shared_whitelist_read_failed", ip=ip)
            return False

    async def remove(self, ip: str) -> None:
        if self._backend is None:
            return
        try:
            await self._backend.delete(_WHITELIST_KEY_PREFIX + ip)
        except Exception:
            log.debug("shared_whitelist_delete_failed", ip=ip)


__all__ = ["SharedWhitelist"]
