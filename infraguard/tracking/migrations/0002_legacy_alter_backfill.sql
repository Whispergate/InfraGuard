-- 0002_legacy_alter_backfill.sql
-- Replaces the ad-hoc _migrate() logic that ran on every boot. SQLite has
-- no IF NOT EXISTS for ADD COLUMN, so the runner treats each ALTER as
-- "may fail with 'duplicate column' - that's fine". See migrator.py for
-- the retry/tolerate rule; every other error still aborts the boot.

ALTER TABLE requests ADD COLUMN protocol TEXT DEFAULT 'http';
ALTER TABLE sessions ADD COLUMN client_ip TEXT NOT NULL DEFAULT '';
