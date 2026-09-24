"""Async SQLite migration runner.

Design goals (why not Alembic): the tracking layer already uses async
aiosqlite + raw SQL - Alembic requires SQLAlchemy models and a sync
engine, which would either duplicate the schema or force a rewrite. A
hand-rolled runner is ~100 LOC, has no extra deps, and matches the
existing idiom.

Contract:
    * Migration files live in ``infraguard/tracking/migrations/``
    * Filenames must be ``NNNN_<slug>.sql`` with a 4-digit prefix; they
      are applied in numeric order.
    * Applied migrations are recorded in the ``schema_migrations`` table
      with (version, name, sha256, applied_at). A checksum mismatch on a
      recorded migration aborts the boot - never edit an applied file.
    * Multiple statements per file are supported (``executescript``); the
      runner splits on ``;`` only inside the "tolerate duplicate column"
      helper below.
    * Explicit downgrade is NOT supported; roll forward with a new file.
"""

from __future__ import annotations

import hashlib
import re
from datetime import UTC, datetime
from pathlib import Path

import aiosqlite
import structlog

log = structlog.get_logger()

_MIGRATIONS_DIR = Path(__file__).resolve().parent / "migrations"
_FILENAME_RE = re.compile(r"^(\d{4})_[a-z0-9_]+\.sql$")

# Substrings SQLite emits when an ALTER TABLE ADD COLUMN targets an
# already-present column. Case-insensitive substring match.
_TOLERATED_ADD_COLUMN_ERRORS = ("duplicate column name",)


def _discover_migrations() -> list[tuple[int, str, Path]]:
    """Return sorted [(version, name, path), …] for every valid file."""
    out: list[tuple[int, str, Path]] = []
    for p in sorted(_MIGRATIONS_DIR.glob("*.sql")):
        m = _FILENAME_RE.match(p.name)
        if not m:
            raise RuntimeError(
                f"migration filename {p.name!r} does not match NNNN_<slug>.sql"
            )
        out.append((int(m.group(1)), p.stem, p))
    return out


def _sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


async def _ensure_version_table(conn: aiosqlite.Connection) -> None:
    await conn.execute(
        """
        CREATE TABLE IF NOT EXISTS schema_migrations (
            version    INTEGER PRIMARY KEY,
            name       TEXT NOT NULL,
            sha256     TEXT NOT NULL,
            applied_at TEXT NOT NULL
        )
        """
    )
    await conn.commit()


async def _applied(conn: aiosqlite.Connection) -> dict[int, tuple[str, str]]:
    conn.row_factory = aiosqlite.Row
    cursor = await conn.execute(
        "SELECT version, name, sha256 FROM schema_migrations"
    )
    rows = await cursor.fetchall()
    return {int(r["version"]): (r["name"], r["sha256"]) for r in rows}


async def _apply_sql_tolerant(conn: aiosqlite.Connection, sql: str) -> None:
    """Run each statement in ``sql``; swallow SQLite's "duplicate column"
    error so legacy ALTER-only migrations are idempotent for DBs that
    already went through the ad-hoc ``_migrate()`` path."""
    for stmt in _split_statements(sql):
        try:
            await conn.execute(stmt)
        except aiosqlite.OperationalError as exc:
            msg = str(exc).lower()
            if any(t in msg for t in _TOLERATED_ADD_COLUMN_ERRORS):
                log.debug("migration_stmt_tolerated", stmt=stmt[:80], error=str(exc))
                continue
            raise


def _split_statements(sql: str) -> list[str]:
    # Strip line comments, split on ';' at statement boundaries. This is
    # deliberately naive - migrations should not contain literal ';' in
    # string literals; if a future migration needs that, use a marker
    # comment ``-- @noscript`` and call executescript instead.
    lines = [ln for ln in sql.splitlines() if not ln.lstrip().startswith("--")]
    joined = "\n".join(lines)
    return [s.strip() for s in joined.split(";") if s.strip()]


async def run_migrations(conn: aiosqlite.Connection) -> list[int]:
    """Apply every pending migration in order. Returns versions applied.

    Raises:
        RuntimeError: if an applied migration's file no longer matches
            its recorded sha256, or the migrations directory is empty.
    """
    discovered = _discover_migrations()
    if not discovered:
        raise RuntimeError(f"no migrations found under {_MIGRATIONS_DIR}")

    await _ensure_version_table(conn)
    applied = await _applied(conn)

    newly_applied: list[int] = []
    for version, name, path in discovered:
        sql = path.read_text(encoding="utf-8")
        digest = _sha256(sql)

        if version in applied:
            recorded_name, recorded_digest = applied[version]
            if recorded_digest != digest:
                raise RuntimeError(
                    f"migration {version:04d} ({recorded_name}) checksum mismatch; "
                    "an already-applied migration file was edited. Add a new "
                    "migration file instead of modifying history."
                )
            continue

        log.info("applying_migration", version=version, name=name)
        await _apply_sql_tolerant(conn, sql)
        await conn.execute(
            "INSERT INTO schema_migrations (version, name, sha256, applied_at) "
            "VALUES (?, ?, ?, ?)",
            (version, name, digest, datetime.now(UTC).isoformat()),
        )
        await conn.commit()
        newly_applied.append(version)

    return newly_applied


async def current_version(conn: aiosqlite.Connection) -> int:
    """Return the highest applied migration version, or 0 if none."""
    await _ensure_version_table(conn)
    conn.row_factory = aiosqlite.Row
    cursor = await conn.execute(
        "SELECT MAX(version) AS v FROM schema_migrations"
    )
    row = await cursor.fetchone()
    return int(row["v"] or 0) if row else 0


__all__ = ["current_version", "run_migrations"]
