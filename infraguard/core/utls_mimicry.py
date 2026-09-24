"""uTLS-style ClientHello mimicry for the proxy -> teamserver leg.

The default asyncio SSL context negotiates a JA3 that screams "python
httpx". Any defender inspecting the redirector's outbound leg to the
teamserver fingerprints that instantly. This module wraps the outbound
HTTP client so it presents a Chrome or Firefox ClientHello via
``curl_cffi`` (which links a modified curl with real browser TLS
profiles).

Scaffold: the wrapping is straightforward but requires swapping the
router's ``httpx.AsyncClient`` for a curl_cffi ``AsyncSession``. The
call sites are :class:`~infraguard.core.proxy.ProxyHandler` and the
health checks in :class:`~infraguard.core.circuit_breaker.CircuitBreaker`.
Left as a follow-up because both call sites use httpx-specific
exceptions in their retry logic.

TODOs:

  1. Add ``curl_cffi`` to pyproject.toml optional-deps [tls].
  2. Introduce an ``OutboundClient`` protocol that both httpx and
     curl_cffi satisfy.
  3. Config: ``upstream.tls_profile: chrome120`` per-domain.
"""

from __future__ import annotations

from typing import Protocol

import structlog

log = structlog.get_logger()

BROWSER_PROFILES = (
    "chrome110", "chrome116", "chrome119", "chrome120",
    "firefox102", "firefox109",
    "safari15_5", "safari16_0",
    "edge99", "edge101",
)


class OutboundClient(Protocol):
    """Duck-typed subset of httpx.AsyncClient used by the router."""

    async def request(self, method: str, url: str, **kwargs): ...
    async def aclose(self) -> None: ...


def build_mimic_client(profile: str, **kwargs) -> OutboundClient | None:
    """Build a mimicking client for the given profile, or None if unavailable."""
    try:
        from curl_cffi.requests import AsyncSession  # type: ignore
    except ImportError:
        log.warning(
            "utls_mimicry_disabled_no_curl_cffi",
            install="pip install curl_cffi",
        )
        return None
    if profile not in BROWSER_PROFILES:
        log.warning("utls_unknown_profile", profile=profile,
                    known=list(BROWSER_PROFILES))
        return None
    return AsyncSession(impersonate=profile, **kwargs)  # type: ignore


__all__ = ["BROWSER_PROFILES", "OutboundClient", "build_mimic_client"]
