"""Async reverse DNS lookups."""

from __future__ import annotations

import asyncio
import socket
from functools import lru_cache

import structlog

log = structlog.get_logger()


async def reverse_dns(ip: str, timeout: float = 2.0) -> str | None:
    """Perform a reverse DNS lookup for an IP address."""
    try:
        loop = asyncio.get_event_loop()
        result = await asyncio.wait_for(
            loop.run_in_executor(None, _sync_rdns, ip),
            timeout=timeout,
        )
        return result
    except (asyncio.TimeoutError, Exception):
        return None


def _sync_rdns(ip: str) -> str | None:
    try:
        hostname, _, _ = socket.gethostbyaddr(ip)
        return hostname
    except (socket.herror, socket.gaierror, OSError):
        return None
