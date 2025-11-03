-- DNA Messenger Keyserver - SQLite Schema
-- Date: 2025-11-03
-- Migrated from PostgreSQL to SQLite for decentralization

-- Drop existing table if exists
DROP TABLE IF EXISTS keyserver_identities;

-- Main identities table
CREATE TABLE keyserver_identities (
    id INTEGER PRIMARY KEY AUTOINCREMENT,

    -- Identity (single DNA handle)
    dna TEXT UNIQUE NOT NULL CHECK(length(dna) >= 3 AND length(dna) <= 32),

    -- Public keys (base64 encoded)
    dilithium_pub TEXT NOT NULL,     -- ~2605 bytes decoded
    kyber_pub TEXT NOT NULL,          -- ~1096 bytes decoded
    cf20pub TEXT NOT NULL DEFAULT '',  -- Cellframe address (empty for now)

    -- Versioning (monotonic counter)
    version INTEGER NOT NULL DEFAULT 1 CHECK(version > 0),
    updated_at INTEGER NOT NULL,      -- Unix timestamp from client

    -- Signature (Dilithium3)
    sig TEXT NOT NULL,                -- base64 signature of canonical JSON

    -- Schema version (payload format version)
    schema_version INTEGER NOT NULL DEFAULT 1,

    -- Server timestamps (Unix timestamps for SQLite)
    registered_at INTEGER DEFAULT (strftime('%s', 'now')),
    last_updated INTEGER DEFAULT (strftime('%s', 'now'))
);

-- Indexes for performance
CREATE INDEX idx_dna ON keyserver_identities(dna);
CREATE INDEX idx_registered_at ON keyserver_identities(registered_at DESC);
CREATE INDEX idx_last_updated ON keyserver_identities(last_updated DESC);

-- Trigger to auto-update last_updated (SQLite equivalent)
CREATE TRIGGER trigger_update_last_updated
    AFTER UPDATE ON keyserver_identities
    FOR EACH ROW
BEGIN
    UPDATE keyserver_identities
    SET last_updated = strftime('%s', 'now')
    WHERE id = NEW.id;
END;
