"""One-time payload download token store.

Issues a cryptographically random token when a beacon is newly promoted to
the dynamic whitelist. Content routes with ``require_token: true`` validate
and consume the token before serving the payload.

An analyst who intercepts a payload URL from network traffic or a beacon
config dump cannot replay it - the token is single-use and expires after
the configured TTL.
"""

from __future__ import annotations

import asyncio
import secrets
import time
from dataclasses import dataclass

import structlog

from infraguard.tracking.database import Database

log = structlog.get_logger()

_TOKEN_BYTES = 32   # 256-bit token -> 64 hex chars


@dataclass
class TokenValidation:
    valid: bool
    reason: str | None = None  # "expired" | "exhausted" | "path_mismatch" | "not_found"


class PayloadTokenStore:
    """SQLite-backed store for one-time payload download tokens."""

    def __init__(self, db: Database) -> None:
        self._db = db

    async def issue(
        self,
        beacon_ip: str,
        route_path: str,
        ttl_seconds: int = 3600,
        max_uses: int = 1,
    ) -> str:
        """Generate, persist, and return a new download token."""
        token = secrets.token_hex(_TOKEN_BYTES)
        now = int(time.time())
        await self._db.insert_payload_token(
            token=token,
            beacon_ip=beacon_ip,
            route_path=route_path,
            issued_at=now,
            expires_at=now + ttl_seconds,
            max_uses=max_uses,
        )
        log.info(
            "payload_token_issued",
            beacon_ip=beacon_ip,
            route_path=route_path,
            ttl_seconds=ttl_seconds,
            max_uses=max_uses,
        )
        return token

    async def validate_and_consume(
        self, token: str, route_path: str
    ) -> TokenValidation:
        """Atomically validate and consume a token.

        The UPDATE is atomic - no read-then-write race condition is possible.
        """
        now = int(time.time())
        result = await self._db.consume_payload_token(token, route_path, now)
        if result is not None:
            log.info("payload_token_consumed", route_path=route_path)
            return TokenValidation(valid=True)

        # Token either doesn't exist, is expired, exhausted, or path mismatches.
        # Don't distinguish - give no info to the requester.
        log.warning("payload_token_rejected", route_path=route_path)
        return TokenValidation(valid=False, reason="invalid")

    async def prune_expired(self) -> int:
        """Delete expired and exhausted tokens. Returns count removed."""
        removed = await self._db.prune_payload_tokens(int(time.time()))
        if removed:
            log.debug("payload_tokens_pruned", count=removed)
        return removed
