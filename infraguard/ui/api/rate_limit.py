"""Rate limiting and API key management for the dashboard API.

Provides:
- Token bucket rate limiter with Redis backend (fallback to in-memory)
- Per-key rate limits
- API key management (create, revoke, rotate)
- Usage tracking and quotas
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import secrets
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Protocol

import structlog
from starlette.requests import Request
from starlette.responses import JSONResponse

from infraguard.tracking.database import Database

log = structlog.get_logger()

# ── Token bucket rate limiter ──────────────────────────────────────────

@dataclass
class BucketState:
    """State for a single token bucket."""
    tokens: float
    last_refill: float  # monotonic time
    # Optional: per-key override of capacity / refill_rate
    capacity: float | None = None
    refill_rate: float | None = None


class RateLimiterBackend(Protocol):
    """Protocol for rate limiter storage backends."""

    async def get_bucket(self, key: str) -> BucketState | None: ...
    async def set_bucket(self, key: str, state: BucketState) -> None: ...
    async def delete_bucket(self, key: str) -> None: ...
    async def close(self) -> None: ...


class InMemoryRateLimiterBackend:
    """Simple in-memory backend using a dict."""

    def __init__(self) -> None:
        self._buckets: dict[str, BucketState] = {}
        self._lock = asyncio.Lock()

    async def get_bucket(self, key: str) -> BucketState | None:
        async with self._lock:
            return self._buckets.get(key)

    async def set_bucket(self, key: str, state: BucketState) -> None:
        async with self._lock:
            self._buckets[key] = state

    async def delete_bucket(self, key: str) -> None:
        async with self._lock:
            self._buckets.pop(key, None)

    async def close(self) -> None:
        pass


class RedisRateLimiterBackend:
    """Redis-backed rate limiter using Redis hashes."""

    def __init__(self, redis_url: str = "redis://localhost:6379/0") -> None:
        self._redis_url = redis_url
        self._client: Any = None
        self._prefix = "infraguard:ratelimit:"

    async def _get_client(self) -> Any:
        if self._client is None:
            try:
                import redis.asyncio as aioredis
            except ImportError:
                raise RuntimeError(
                    "redis package not installed. Install with: pip install redis"
                )
            self._client = aioredis.from_url(self._redis_url, decode_responses=True)
        return self._client

    async def get_bucket(self, key: str) -> BucketState | None:
        client = await self._get_client()
        data = await client.hgetall(f"{self._prefix}{key}")
        if not data:
            return None
        return BucketState(
            tokens=float(data["tokens"]),
            last_refill=float(data["last_refill"]),
            capacity=float(data["capacity"]) if data.get("capacity") else None,
            refill_rate=float(data["refill_rate"]) if data.get("refill_rate") else None,
        )

    async def set_bucket(self, key: str, state: BucketState) -> None:
        client = await self._get_client()
        mapping = {
            "tokens": str(state.tokens),
            "last_refill": str(state.last_refill),
        }
        if state.capacity is not None:
            mapping["capacity"] = str(state.capacity)
        if state.refill_rate is not None:
            mapping["refill_rate"] = str(state.refill_rate)
        await client.hset(f"{self._prefix}{key}", mapping=mapping)
        # Set TTL to avoid stale buckets (2x the refill window)
        ttl = max(60, int(2 * (state.capacity or 60) / (state.refill_rate or 1)))
        await client.expire(f"{self._prefix}{key}", ttl)

    async def delete_bucket(self, key: str) -> None:
        client = await self._get_client()
        await client.delete(f"{self._prefix}{key}")

    async def close(self) -> None:
        if self._client:
            await self._client.close()
            self._client = None


class TokenBucketRateLimiter:
    """Token bucket rate limiter.

    Each key (API key, IP, etc.) has a bucket with:
    - capacity: max tokens
    - refill_rate: tokens per second

    A request consumes 1 token. If tokens < 1, the request is rejected.
    """

    def __init__(
        self,
        backend: RateLimiterBackend,
        default_capacity: float = 60.0,
        default_refill_rate: float = 1.0,
    ) -> None:
        self._backend = backend
        self._default_capacity = default_capacity
        self._default_refill_rate = default_refill_rate

    async def _get_or_create_bucket(self, key: str, capacity: float | None = None, refill_rate: float | None = None) -> BucketState:
        state = await self._backend.get_bucket(key)
        if state is None:
            now = time.monotonic()
            state = BucketState(
                tokens=capacity or self._default_capacity,
                last_refill=now,
                capacity=capacity or self._default_capacity,
                refill_rate=refill_rate or self._default_refill_rate,
            )
            await self._backend.set_bucket(key, state)
        return state

    async def allow(self, key: str, cost: float = 1.0) -> tuple[bool, dict[str, Any]]:
        """Check if a request is allowed.

        Returns (allowed, info) where info includes remaining tokens and reset time.
        """
        state = await self._get_or_create_bucket(key)
        now = time.monotonic()

        capacity = state.capacity or self._default_capacity
        refill_rate = state.refill_rate or self._default_refill_rate

        # Refill tokens
        elapsed = now - state.last_refill
        state.tokens = min(capacity, state.tokens + elapsed * refill_rate)
        state.last_refill = now

        allowed = state.tokens >= cost
        if allowed:
            state.tokens -= cost

        await self._backend.set_bucket(key, state)

        info = {
            "remaining": max(0, state.tokens),
            "capacity": capacity,
            "reset_after": int((capacity - state.tokens) / refill_rate) if refill_rate > 0 else 0,
        }
        return allowed, info

    async def set_key_limits(self, key: str, capacity: float, refill_rate: float) -> None:
        """Override limits for a specific key."""
        state = await self._get_or_create_bucket(key, capacity=capacity, refill_rate=refill_rate)
        state.capacity = capacity
        state.refill_rate = refill_rate
        state.tokens = min(state.tokens, capacity)
        await self._backend.set_bucket(key, state)

    async def reset_key(self, key: str) -> None:
        """Reset a key's bucket to full capacity."""
        state = await self._get_or_create_bucket(key)
        state.tokens = state.capacity or self._default_capacity
        state.last_refill = time.monotonic()
        await self._backend.set_bucket(key, state)

    async def close(self) -> None:
        await self._backend.close()


# ── API key management ────────────────────────────────────────────────

API_KEY_PREFIX = "ig_"
API_KEY_LENGTH = 32  # bytes, base64url-encoded


def _hash_api_key(key: str) -> str:
    """Hash an API key for storage."""
    return hashlib.sha256(key.encode()).hexdigest()


def generate_api_key() -> str:
    """Generate a new API key."""
    return API_KEY_PREFIX + secrets.token_urlsafe(API_KEY_LENGTH)


@dataclass
class APIKeyInfo:
    """Metadata about an API key."""
    key_id: str
    name: str
    created_at: datetime
    created_by: str
    last_used_at: datetime | None = None
    revoked: bool = False
    revoked_at: datetime | None = None
    rate_limit_capacity: float | None = None
    rate_limit_refill_rate: float | None = None
    quota_limit: int | None = None
    quota_window_seconds: int | None = None


class APIKeyManager:
    """Manage API keys for programmatic access."""

    def __init__(self, db: Database) -> None:
        self._db = db

    async def create_key(
        self,
        name: str,
        created_by: str,
        rate_limit_capacity: float | None = None,
        rate_limit_refill_rate: float | None = None,
        quota_limit: int | None = None,
        quota_window_seconds: int | None = None,
    ) -> tuple[str, str]:
        """Create a new API key.

        Returns (key_id, plaintext_key). The plaintext key is only returned once.
        """
        key = generate_api_key()
        key_id = secrets.token_urlsafe(16)
        key_hash = _hash_api_key(key)
        now = datetime.now(timezone.utc)

        await self._db.execute(
            """INSERT INTO api_keys
               (key_id, key_hash, name, created_at, created_by,
                rate_limit_capacity, rate_limit_refill_rate,
                quota_limit, quota_window_seconds)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                key_id, key_hash, name, now.isoformat(), created_by,
                rate_limit_capacity, rate_limit_refill_rate,
                quota_limit, quota_window_seconds,
            ),
        )
        log.info("api_key_created", key_id=key_id, name=name, created_by=created_by)
        return key_id, key

    async def revoke_key(self, key_id: str, revoked_by: str) -> bool:
        """Revoke an API key. Returns True if the key existed."""
        now = datetime.now(timezone.utc)
        cursor = await self._db.execute(
            """UPDATE api_keys
               SET revoked = 1, revoked_at = ?, revoked_by = ?
               WHERE key_id = ? AND revoked = 0""",
            (now.isoformat(), revoked_by, key_id),
        )
        if cursor.rowcount > 0:
            log.info("api_key_revoked", key_id=key_id, revoked_by=revoked_by)
            return True
        return False

    async def rotate_key(self, key_id: str, rotated_by: str) -> tuple[str, str] | None:
        """Rotate an API key: revoke the old one and create a new one.

        Returns (new_key_id, new_plaintext_key) or None if old key not found.
        """
        row = await self._db.fetchone(
            "SELECT * FROM api_keys WHERE key_id = ? AND revoked = 0", (key_id,)
        )
        if not row:
            return None

        # Revoke old key
        await self.revoke_key(key_id, rotated_by)

        # Create new key with same metadata
        new_key_id, new_key = await self.create_key(
            name=row["name"] + " (rotated)",
            created_by=rotated_by,
            rate_limit_capacity=row.get("rate_limit_capacity"),
            rate_limit_refill_rate=row.get("rate_limit_refill_rate"),
            quota_limit=row.get("quota_limit"),
            quota_window_seconds=row.get("quota_window_seconds"),
        )
        log.info("api_key_rotated", old_key_id=key_id, new_key_id=new_key_id, rotated_by=rotated_by)
        return new_key_id, new_key

    async def validate_key(self, key: str) -> APIKeyInfo | None:
        """Validate an API key and return its metadata, or None if invalid."""
        key_hash = _hash_api_key(key)
        row = await self._db.fetchone(
            "SELECT * FROM api_keys WHERE key_hash = ? AND revoked = 0", (key_hash,)
        )
        if not row:
            return None

        # Update last_used_at
        now = datetime.now(timezone.utc)
        await self._db.execute(
            "UPDATE api_keys SET last_used_at = ? WHERE key_id = ?",
            (now.isoformat(), row["key_id"]),
        )

        return APIKeyInfo(
            key_id=row["key_id"],
            name=row["name"],
            created_at=datetime.fromisoformat(row["created_at"]),
            created_by=row["created_by"],
            last_used_at=now,
            revoked=bool(row.get("revoked", 0)),
            revoked_at=datetime.fromisoformat(row["revoked_at"]) if row.get("revoked_at") else None,
            rate_limit_capacity=row.get("rate_limit_capacity"),
            rate_limit_refill_rate=row.get("rate_limit_refill_rate"),
            quota_limit=row.get("quota_limit"),
            quota_window_seconds=row.get("quota_window_seconds"),
        )

    async def list_keys(self, include_revoked: bool = False) -> list[dict]:
        """List all API keys (without plaintext)."""
        if include_revoked:
            return await self._db.fetchall(
                "SELECT key_id, name, created_at, created_by, last_used_at, "
                "revoked, revoked_at, rate_limit_capacity, rate_limit_refill_rate, "
                "quota_limit, quota_window_seconds FROM api_keys ORDER BY created_at DESC"
            )
        return await self._db.fetchall(
            "SELECT key_id, name, created_at, created_by, last_used_at, "
            "revoked, revoked_at, rate_limit_capacity, rate_limit_refill_rate, "
            "quota_limit, quota_window_seconds FROM api_keys WHERE revoked = 0 ORDER BY created_at DESC"
        )

    async def get_key_info(self, key_id: str) -> dict | None:
        """Get metadata for a single key."""
        return await self._db.fetchone(
            "SELECT key_id, name, created_at, created_by, last_used_at, "
            "revoked, revoked_at, rate_limit_capacity, rate_limit_refill_rate, "
            "quota_limit, quota_window_seconds FROM api_keys WHERE key_id = ?",
            (key_id,),
        )


# ── Usage tracking and quotas ─────────────────────────────────────────

class UsageTracker:
    """Track API usage per key for quota enforcement."""

    def __init__(self, db: Database) -> None:
        self._db = db

    async def record_request(self, key_id: str, endpoint: str, status_code: int) -> None:
        """Record a single API request."""
        now = datetime.now(timezone.utc)
        await self._db.execute(
            """INSERT INTO api_usage
               (key_id, timestamp, endpoint, status_code)
               VALUES (?, ?, ?, ?)""",
            (key_id, now.isoformat(), endpoint, status_code),
        )

    async def get_usage_count(
        self, key_id: str, window_start: datetime, window_end: datetime
    ) -> int:
        """Get the number of requests in a time window."""
        row = await self._db.fetchone(
            """SELECT COUNT(*) as count FROM api_usage
               WHERE key_id = ? AND timestamp >= ? AND timestamp <= ?""",
            (key_id, window_start.isoformat(), window_end.isoformat()),
        )
        return row["count"] if row else 0

    async def check_quota(
        self, key_id: str, quota_limit: int, quota_window_seconds: int
    ) -> tuple[bool, dict[str, Any]]:
        """Check if a key is within its quota.

        Returns (allowed, info) where info includes current usage and reset time.
        """
        now = datetime.now(timezone.utc)
        window_start = now - timedelta(seconds=quota_window_seconds)
        current_usage = await self.get_usage_count(key_id, window_start, now)
        allowed = current_usage < quota_limit
        reset_at = window_start + timedelta(seconds=quota_window_seconds)
        info = {
            "current_usage": current_usage,
            "quota_limit": quota_limit,
            "reset_at": reset_at.isoformat(),
        }
        return allowed, info

    async def get_usage_summary(
        self, key_id: str, days: int = 7
    ) -> list[dict]:
        """Get daily usage counts for the past N days."""
        since = datetime.now(timezone.utc) - timedelta(days=days)
        return await self._db.fetchall(
            """SELECT date(timestamp) as date, COUNT(*) as count
               FROM api_usage
               WHERE key_id = ? AND timestamp >= ?
               GROUP BY date(timestamp)
               ORDER BY date DESC""",
            (key_id, since.isoformat()),
        )


# ── Integrated rate limit + auth helpers ──────────────────────────────

class RateLimitMiddleware:
    """Starlette middleware for rate limiting API requests."""

    def __init__(
        self,
        app: Any,
        rate_limiter: TokenBucketRateLimiter,
        usage_tracker: UsageTracker | None = None,
        key_manager: APIKeyManager | None = None,
        default_capacity: float = 60.0,
        default_refill_rate: float = 1.0,
    ) -> None:
        self.app = app
        self._limiter = rate_limiter
        self._usage = usage_tracker
        self._keys = key_manager
        self._default_capacity = default_capacity
        self._default_refill_rate = default_refill_rate

    async def __call__(self, scope: dict, receive: Any, send: Any) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        request = Request(scope, receive)
        path = request.url.path

        # Skip rate limiting for public paths
        from infraguard.ui.api.app import _PUBLIC_PATHS, _PUBLIC_PREFIXES
        if path in _PUBLIC_PATHS or any(path.startswith(p) for p in _PUBLIC_PREFIXES):
            await self.app(scope, receive, send)
            return

        # Determine rate limit key: API key > bearer token hash > IP
        rate_key = await self._get_rate_key(request)
        if rate_key is None:
            # No auth, no rate limiting (shouldn't happen after AuthMiddleware)
            await self.app(scope, receive, send)
            return

        # Check quota if key manager available
        if self._keys and rate_key.startswith("apikey:"):
            key_id = rate_key[7:]
            key_info = await self._keys.get_key_info(key_id)
            if key_info and key_info.get("quota_limit") and key_info.get("quota_window_seconds"):
                allowed, quota_info = await self._usage.check_quota(
                    key_id, key_info["quota_limit"], key_info["quota_window_seconds"]
                )
                if not allowed:
                    response = JSONResponse(
                        {
                            "error": "Quota exceeded",
                            "quota": quota_info,
                        },
                        status_code=429,
                    )
                    await response(scope, receive, send)
                    return

        # Check rate limit
        allowed, info = await self._limiter.allow(rate_key)
        if not allowed:
            response = JSONResponse(
                {
                    "error": "Rate limit exceeded",
                    "retry_after": info["reset_after"],
                },
                status_code=429,
                headers={
                    "X-RateLimit-Limit": str(int(info["capacity"])),
                    "X-RateLimit-Remaining": str(int(info["remaining"])),
                    "X-RateLimit-Reset": str(int(time.time()) + info["reset_after"]),
                    "Retry-After": str(info["reset_after"]),
                },
            )
            await response(scope, receive, send)
            return

        # Record usage
        if self._usage and rate_key.startswith("apikey:"):
            key_id = rate_key[7:]
            # We record after the request completes to capture status code
            # For simplicity, record now with 200; a more robust approach
            # would wrap the send to capture the actual status.
            asyncio.create_task(
                self._usage.record_request(key_id, path, 200)
            )

        # Add rate limit headers to response
        async def send_with_headers(message: dict) -> None:
            if message["type"] == "http.response.start":
                headers = list(message.get("headers", []))
                headers.extend([
                    (b"x-ratelimit-limit", str(int(info["capacity"])).encode()),
                    (b"x-ratelimit-remaining", str(int(info["remaining"])).encode()),
                    (b"x-ratelimit-reset", str(int(time.time()) + info["reset_after"]).encode()),
                ])
                message["headers"] = headers
            await send(message)

        await self.app(scope, receive, send_with_headers)

    async def _get_rate_key(self, request: Request) -> str | None:
        """Extract a rate limiting key from the request."""
        # Check API key header
        api_key = request.headers.get("x-api-key")
        if api_key and self._keys:
            key_info = await self._keys.validate_key(api_key)
            if key_info:
                # Set per-key rate limits if configured
                if key_info.rate_limit_capacity and key_info.rate_limit_refill_rate:
                    await self._limiter.set_key_limits(
                        f"apikey:{key_info.key_id}",
                        key_info.rate_limit_capacity,
                        key_info.rate_limit_refill_rate,
                    )
                return f"apikey:{key_info.key_id}"
            return None

        # Check bearer token
        auth = request.headers.get("authorization", "")
        if auth.startswith("Bearer "):
            token = auth[7:]
            return f"bearer:{_hash_api_key(token)[:16]}"

        # Check session cookie
        session_id = request.cookies.get("ig_session")
        if session_id:
            return f"session:{session_id[:16]}"

        # Fallback to IP
        client_ip = request.client.host if request.client else "unknown"
        return f"ip:{client_ip}"


# ── Route handlers for API key management ─────────────────────────────

async def list_api_keys(request: Request) -> JSONResponse:
    """GET /api/keys - list all API keys."""
    manager: APIKeyManager = request.app.state.api_key_manager
    include_revoked = request.query_params.get("include_revoked", "").lower() == "true"
    keys = await manager.list_keys(include_revoked=include_revoked)
    return JSONResponse({"keys": keys})


async def create_api_key(request: Request) -> JSONResponse:
    """POST /api/keys - create a new API key."""
    manager: APIKeyManager = request.app.state.api_key_manager
    try:
        body = await request.json()
    except Exception:
        return JSONResponse({"error": "Invalid JSON body"}, status_code=400)

    name = body.get("name", "")
    if not name:
        return JSONResponse({"error": "name is required"}, status_code=400)

    # Get operator identity from auth context
    operator = _get_operator_identity(request)

    key_id, plaintext_key = await manager.create_key(
        name=name,
        created_by=operator,
        rate_limit_capacity=body.get("rate_limit_capacity"),
        rate_limit_refill_rate=body.get("rate_limit_refill_rate"),
        quota_limit=body.get("quota_limit"),
        quota_window_seconds=body.get("quota_window_seconds"),
    )
    return JSONResponse(
        {
            "key_id": key_id,
            "key": plaintext_key,
            "name": name,
            "message": "Store the key securely; it will not be shown again.",
        },
        status_code=201,
    )


async def revoke_api_key(request: Request) -> JSONResponse:
    """DELETE /api/keys/{key_id} - revoke an API key."""
    manager: APIKeyManager = request.app.state.api_key_manager
    key_id = request.path_params["key_id"]
    operator = _get_operator_identity(request)
    success = await manager.revoke_key(key_id, operator)
    if not success:
        return JSONResponse({"error": "Key not found or already revoked"}, status_code=404)
    return JSONResponse({"status": "ok", "key_id": key_id})


async def rotate_api_key(request: Request) -> JSONResponse:
    """POST /api/keys/{key_id}/rotate - rotate an API key."""
    manager: APIKeyManager = request.app.state.api_key_manager
    key_id = request.path_params["key_id"]
    operator = _get_operator_identity(request)
    result = await manager.rotate_key(key_id, operator)
    if not result:
        return JSONResponse({"error": "Key not found or already revoked"}, status_code=404)
    new_key_id, new_key = result
    return JSONResponse(
        {
            "old_key_id": key_id,
            "new_key_id": new_key_id,
            "key": new_key,
            "message": "Store the new key securely; it will not be shown again.",
        }
    )


async def get_api_key_usage(request: Request) -> JSONResponse:
    """GET /api/keys/{key_id}/usage - get usage stats for an API key."""
    tracker: UsageTracker = request.app.state.usage_tracker
    key_id = request.path_params["key_id"]
    days = int(request.query_params.get("days", "7"))
    summary = await tracker.get_usage_summary(key_id, days=days)
    return JSONResponse({"key_id": key_id, "days": days, "usage": summary})


def _get_operator_identity(request: Request) -> str:
    """Extract operator identity from request for audit logging."""
    auth = request.headers.get("authorization", "")
    if auth.startswith("Bearer "):
        return f"bearer:{auth[7:][:8]}..."
    api_key = request.headers.get("x-api-key", "")
    if api_key:
        return f"apikey:{api_key[:8]}..."
    session_id = request.cookies.get("ig_session", "")
    if session_id:
        return f"session:{session_id[:8]}..."
    return "unknown"
