"""SQLite database management with async support via aiosqlite."""

from __future__ import annotations

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
"""


class Database:
    """Async SQLite database wrapper for InfraGuard tracking."""

    def __init__(self, db_path: str = "infraguard.db"):
        self.db_path = db_path
        self._conn: aiosqlite.Connection | None = None

    async def connect(self) -> None:
        self._conn = await aiosqlite.connect(self.db_path)
        # Enable WAL mode for better concurrent read/write performance
        await self._conn.execute("PRAGMA journal_mode=WAL")
        await self._conn.execute("PRAGMA synchronous=NORMAL")
        await self._conn.executescript(SCHEMA_SQL)
        await self._conn.commit()
        log.info("database_connected", path=self.db_path)

    async def close(self) -> None:
        if self._conn:
            await self._conn.close()
            self._conn = None

    @property
    def conn(self) -> aiosqlite.Connection:
        if self._conn is None:
            raise RuntimeError("Database not connected. Call connect() first.")
        return self._conn

    async def execute(self, sql: str, params: tuple = ()) -> aiosqlite.Cursor:
        return await self.conn.execute(sql, params)

    async def executemany(self, sql: str, params_list: list[tuple]) -> None:
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
