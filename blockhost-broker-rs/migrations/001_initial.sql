-- Initial schema for blockhost-broker IPAM

-- Allocations table
CREATE TABLE IF NOT EXISTS allocations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    prefix TEXT UNIQUE NOT NULL,
    prefix_index INTEGER UNIQUE NOT NULL,
    pubkey TEXT NOT NULL,
    endpoint TEXT,
    nft_contract TEXT NOT NULL,
    allocated_at TEXT NOT NULL,
    last_seen_at TEXT
);

CREATE INDEX IF NOT EXISTS idx_allocations_nft_contract ON allocations(nft_contract);
CREATE INDEX IF NOT EXISTS idx_allocations_pubkey ON allocations(pubkey);

-- Tokens table (for REST API auth, maintained for backwards compatibility)
CREATE TABLE IF NOT EXISTS tokens (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    token_hash TEXT UNIQUE NOT NULL,
    name TEXT,
    max_allocations INTEGER DEFAULT 1,
    is_admin BOOLEAN DEFAULT FALSE,
    created_at TEXT NOT NULL,
    expires_at TEXT,
    revoked BOOLEAN DEFAULT FALSE
);

CREATE INDEX IF NOT EXISTS idx_tokens_hash ON tokens(token_hash);

-- Audit log
CREATE TABLE IF NOT EXISTS audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL,
    action TEXT NOT NULL,
    nft_contract TEXT,
    prefix TEXT,
    details TEXT
);

-- State table for persisting monitor state
CREATE TABLE IF NOT EXISTS state (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

-- Insert initial state
INSERT OR IGNORE INTO state (key, value, updated_at)
VALUES ('last_processed_id', '0', datetime('now'));
