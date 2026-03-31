"""SQLite database management with async support via aiosqlite."""

from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone
from pathlib import Path

import aiosqlite
import structlog

log = structlog.get_logger()

SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS requests (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL,
    domain TEXT NOT NULL,
    client_ip TEXT NOT NULL,
    method TEXT NOT NULL,
    uri TEXT NOT NULL,
    user_agent TEXT DEFAULT '',
    filter_result TEXT NOT NULL,
    filter_reason TEXT,
    filter_score REAL DEFAULT 0.0,
    response_status INTEGER DEFAULT 0,
    request_hash TEXT DEFAULT '',
    duration_ms REAL DEFAULT 0.0,
    protocol TEXT DEFAULT 'http'
);

CREATE INDEX IF NOT EXISTS idx_requests_timestamp ON requests(timestamp);
CREATE INDEX IF NOT EXISTS idx_requests_client_ip ON requests(client_ip);
CREATE INDEX IF NOT EXISTS idx_requests_domain ON requests(domain);
CREATE INDEX IF NOT EXISTS idx_requests_protocol ON requests(protocol);
CREATE INDEX IF NOT EXISTS idx_requests_filter_result ON requests(filter_result);

CREATE TABLE IF NOT EXISTS nodes (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    address TEXT NOT NULL,
    domains TEXT DEFAULT '[]',
    last_heartbeat TEXT,
    status TEXT DEFAULT 'active',
    config_hash TEXT DEFAULT ''
);

CREATE TABLE IF NOT EXISTS ip_intel_cache (
    ip TEXT PRIMARY KEY,
    classification TEXT,
    cached_at TEXT,
    ttl_seconds INTEGER DEFAULT 3600
);

CREATE TABLE IF NOT EXISTS dynamic_whitelist (
    ip TEXT PRIMARY KEY,
    valid_request_count INTEGER DEFAULT 0,
    first_seen TEXT,
    last_seen TEXT,
    whitelisted_at TEXT
);

CREATE TABLE IF NOT EXISTS sessions (
    session_id TEXT PRIMARY KEY,
    token_hash TEXT NOT NULL,
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    client_ip TEXT NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS idx_sessions_expires_at ON sessions(expires_at);
"""


class Database:
    """Async SQLite database wrapper for InfraGuard tracking."""

    def __init__(self, db_path: str = "infraguard.db"):
        self.db_path = db_path
        self._conn: aiosqlite.Connection | None = None
        self._write_lock = asyncio.Lock()

    async def connect(self) -> None:
        # Ensure the parent directory exists
        db_dir = Path(self.db_path).parent
        db_dir.mkdir(parents=True, exist_ok=True)

        self._conn = await aiosqlite.connect(self.db_path)
        # Enable WAL mode for better concurrent read/write performance
        await self._conn.execute("PRAGMA journal_mode=WAL")
        await self._conn.execute("PRAGMA synchronous=NORMAL")
        await self._conn.executescript(SCHEMA_SQL)
        await self._migrate()
        await self._conn.commit()
        log.info("database_connected", path=self.db_path)

    async def _migrate(self) -> None:
        """Add columns that may be missing from older databases."""
        # Get existing columns in the requests table
        cursor = await self._conn.execute("PRAGMA table_info(requests)")
        rows = await cursor.fetchall()
        existing = {row[1] for row in rows}  # column names

        if "protocol" not in existing:
            await self._conn.execute(
                "ALTER TABLE requests ADD COLUMN protocol TEXT DEFAULT 'http'"
            )
            log.info("migration_applied", column="protocol")

        # Ensure sessions table has expected columns (migration for older DBs)
        cursor = await self._conn.execute("PRAGMA table_info(sessions)")
        rows = await cursor.fetchall()
        session_cols = {row[1] for row in rows}

        if "client_ip" not in session_cols and session_cols:
            await self._conn.execute(
                "ALTER TABLE sessions ADD COLUMN client_ip TEXT NOT NULL DEFAULT ''"
            )
            log.info("migration_applied", column="sessions.client_ip")

    async def close(self) -> None:
        if self._conn:
            await self._conn.close()
            self._conn = None

    @property
    def conn(self) -> aiosqlite.Connection:
        if self._conn is None:
            raise RuntimeError("Database not connected. Call connect() first.")
        return self._conn

    @staticmethod
    def _is_write(sql: str) -> bool:
        """Return True if the SQL statement is a write operation."""
        first_word = sql.strip().split()[0].upper() if sql.strip() else ""
        return first_word in {"INSERT", "UPDATE", "DELETE", "CREATE", "ALTER", "DROP", "REPLACE"}

    async def execute(self, sql: str, params: tuple = ()) -> aiosqlite.Cursor:
        if self._is_write(sql):
            async with self._write_lock:
                cursor = await self.conn.execute(sql, params)
                await self.conn.commit()
                return cursor
        return await self.conn.execute(sql, params)

    async def executemany(self, sql: str, params_list: list[tuple]) -> None:
        async with self._write_lock:
            await self.conn.executemany(sql, params_list)
            await self.conn.commit()

    async def fetchone(self, sql: str, params: tuple = ()) -> dict | None:
        self.conn.row_factory = aiosqlite.Row
        cursor = await self.conn.execute(sql, params)
        row = await cursor.fetchone()
        if row:
            return dict(row)
        return None

    async def fetchall(self, sql: str, params: tuple = ()) -> list[dict]:
        self.conn.row_factory = aiosqlite.Row
        cursor = await self.conn.execute(sql, params)
        rows = await cursor.fetchall()
        return [dict(r) for r in rows]

    # ── Session helpers ────────────────────────────────────────────────

    async def create_session(self, session_id: str, token_hash: str, ttl: int, client_ip: str = "") -> None:
        """Insert a new session row."""
        now = datetime.now(timezone.utc)
        expires = now + timedelta(seconds=ttl)
        await self.execute(
            "INSERT INTO sessions (session_id, token_hash, created_at, expires_at, client_ip) VALUES (?, ?, ?, ?, ?)",
            (session_id, token_hash, now.isoformat(), expires.isoformat(), client_ip),
        )

    async def get_session(self, session_id: str) -> dict | None:
        """Fetch a session row by session_id."""
        return await self.fetchone(
            "SELECT * FROM sessions WHERE session_id = ?", (session_id,)
        )

    async def delete_session(self, session_id: str) -> None:
        """Delete a single session by session_id."""
        await self.execute("DELETE FROM sessions WHERE session_id = ?", (session_id,))

    async def delete_expired_sessions(self) -> int:
        """Delete all sessions where expires_at < now. Returns count deleted."""
        now = datetime.now(timezone.utc).isoformat()
        cursor = await self.execute("DELETE FROM sessions WHERE expires_at < ?", (now,))
        return cursor.rowcount
