"""Tests for Database write serialization, sessions table, and session CRUD."""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone

import pytest
import pytest_asyncio

from infraguard.tracking.database import Database


# ── Fixtures ──────────────────────────────────────────────────────────

@pytest_asyncio.fixture
async def db(tmp_path):
    """Provide a connected in-memory-like Database backed by a temp file."""
    path = str(tmp_path / "test.db")
    database = Database(db_path=path)
    await database.connect()
    yield database
    await database.close()


# ── Write serialization tests ─────────────────────────────────────────

class TestWriteSerialization:

    @pytest.mark.asyncio
    async def test_concurrent_writes_serialized(self, db: Database):
        """Two concurrent INSERT operations complete without 'database is locked' error."""
        async def insert_row(i: int):
            await db.execute(
                "INSERT INTO nodes (id, name, address) VALUES (?, ?, ?)",
                (f"node-{i}", f"Node {i}", f"10.0.0.{i}"),
            )

        # Run two writes concurrently - both must succeed
        await asyncio.gather(insert_row(1), insert_row(2))

        rows = await db.fetchall("SELECT id FROM nodes ORDER BY id")
        ids = [r["id"] for r in rows]
        assert "node-1" in ids
        assert "node-2" in ids

    @pytest.mark.asyncio
    async def test_concurrent_reads_do_not_block(self, db: Database):
        """Concurrent SELECT operations succeed without acquiring the write lock."""
        # Insert a row first
        await db.execute(
            "INSERT INTO nodes (id, name, address) VALUES (?, ?, ?)",
            ("node-read", "ReadNode", "192.168.0.1"),
        )

        # Two simultaneous reads must both complete
        results = await asyncio.gather(
            db.fetchall("SELECT * FROM nodes"),
            db.fetchall("SELECT * FROM nodes"),
        )
        assert len(results[0]) >= 1
        assert len(results[1]) >= 1

    @pytest.mark.asyncio
    async def test_write_lock_not_held_by_reads(self, db: Database):
        """Verify the write lock is free after read operations."""
        await db.fetchall("SELECT * FROM nodes")
        # Lock should be uncontested after reads
        assert not db._write_lock.locked()


# ── Sessions table structure ─────────────────────────────────────────

class TestSessionsTable:

    @pytest.mark.asyncio
    async def test_sessions_table_created_on_connect(self, db: Database):
        """Sessions table must exist after connect()."""
        cursor = await db.conn.execute("PRAGMA table_info(sessions)")
        rows = await cursor.fetchall()
        col_names = {row[1] for row in rows}
        expected = {"session_id", "token_hash", "created_at", "expires_at", "client_ip"}
        assert expected.issubset(col_names), f"Missing columns: {expected - col_names}"


# ── Session CRUD ──────────────────────────────────────────────────────

class TestSessionCRUD:

    @pytest.mark.asyncio
    async def test_create_and_fetch_session(self, db: Database):
        """Insert a session row and retrieve it by session_id with all fields intact."""
        await db.create_session(
            session_id="sess-abc123",
            token_hash="deadbeef" * 8,
            ttl=3600,
            client_ip="10.1.2.3",
        )
        row = await db.get_session("sess-abc123")

        assert row is not None
        assert row["session_id"] == "sess-abc123"
        assert row["token_hash"] == "deadbeef" * 8
        assert row["client_ip"] == "10.1.2.3"
        assert "created_at" in row
        assert "expires_at" in row

    @pytest.mark.asyncio
    async def test_get_session_returns_none_for_missing(self, db: Database):
        """get_session returns None for a non-existent session_id."""
        result = await db.get_session("does-not-exist")
        assert result is None

    @pytest.mark.asyncio
    async def test_delete_expired_sessions_removes_stale_rows(self, db: Database):
        """delete_expired_sessions removes rows where expires_at < now."""
        # Insert one expired session (expires 1 second in the past)
        from datetime import timedelta
        now = datetime.now(timezone.utc)
        past = (now - timedelta(seconds=1)).isoformat()
        future = (now + timedelta(seconds=3600)).isoformat()

        await db.conn.execute(
            "INSERT INTO sessions (session_id, token_hash, created_at, expires_at, client_ip) VALUES (?, ?, ?, ?, ?)",
            ("expired-sess", "hash1", now.isoformat(), past, "1.2.3.4"),
        )
        await db.conn.execute(
            "INSERT INTO sessions (session_id, token_hash, created_at, expires_at, client_ip) VALUES (?, ?, ?, ?, ?)",
            ("valid-sess", "hash2", now.isoformat(), future, "5.6.7.8"),
        )
        await db.conn.commit()

        deleted = await db.delete_expired_sessions()

        assert deleted >= 1
        remaining = await db.fetchall("SELECT session_id FROM sessions")
        remaining_ids = [r["session_id"] for r in remaining]
        assert "expired-sess" not in remaining_ids
        assert "valid-sess" in remaining_ids

    @pytest.mark.asyncio
    async def test_delete_session_by_id(self, db: Database):
        """delete_session removes only the targeted session row."""
        await db.create_session("sess-del", "hashX", 3600, "9.9.9.9")
        await db.create_session("sess-keep", "hashY", 3600, "8.8.8.8")

        await db.delete_session("sess-del")

        assert await db.get_session("sess-del") is None
        assert await db.get_session("sess-keep") is not None
