-- 0001_baseline.sql
-- Captures the schema as it existed at the introduction of the migrator
-- (previously inlined in tracking/database.py::SCHEMA_SQL). Fresh DBs run
-- this; DBs that predate the migrator are picked up by 0002 which is a
-- no-op if the columns it adds are already present.

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

CREATE TABLE IF NOT EXISTS audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL,
    action TEXT NOT NULL,
    operator TEXT DEFAULT '',
    client_ip TEXT DEFAULT '',
    details TEXT DEFAULT '',
    resource TEXT DEFAULT ''
);

CREATE INDEX IF NOT EXISTS idx_audit_log_timestamp ON audit_log(timestamp);
CREATE INDEX IF NOT EXISTS idx_audit_log_action ON audit_log(action);

CREATE TABLE IF NOT EXISTS replay_tokens (
    hash TEXT PRIMARY KEY,
    seen_at INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_replay_tokens_seen_at ON replay_tokens(seen_at);

CREATE TABLE IF NOT EXISTS payload_tokens (
    token TEXT PRIMARY KEY,
    beacon_ip TEXT NOT NULL,
    route_path TEXT NOT NULL,
    issued_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    max_uses INTEGER NOT NULL DEFAULT 1,
    used_count INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_payload_tokens_expires ON payload_tokens(expires_at);

CREATE TABLE IF NOT EXISTS api_keys (
    key_id TEXT PRIMARY KEY,
    key_hash TEXT NOT NULL UNIQUE,
    name TEXT NOT NULL,
    created_at TEXT NOT NULL,
    created_by TEXT NOT NULL,
    last_used_at TEXT,
    revoked INTEGER NOT NULL DEFAULT 0,
    revoked_at TEXT,
    revoked_by TEXT,
    rate_limit_capacity REAL,
    rate_limit_refill_rate REAL,
    quota_limit INTEGER,
    quota_window_seconds INTEGER
);

CREATE INDEX IF NOT EXISTS idx_api_keys_hash ON api_keys(key_hash);
CREATE INDEX IF NOT EXISTS idx_api_keys_revoked ON api_keys(revoked);

CREATE TABLE IF NOT EXISTS api_usage (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    key_id TEXT NOT NULL,
    timestamp TEXT NOT NULL,
    endpoint TEXT NOT NULL,
    status_code INTEGER DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_api_usage_key_id ON api_usage(key_id);
CREATE INDEX IF NOT EXISTS idx_api_usage_timestamp ON api_usage(timestamp);
