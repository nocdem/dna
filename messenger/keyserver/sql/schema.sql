-- DNA Messenger Keyserver - PostgreSQL Schema
-- Date: 2025-10-16

-- Drop existing table if exists
DROP TABLE IF EXISTS keyserver_identities CASCADE;

-- Main identities table
CREATE TABLE keyserver_identities (
    id SERIAL PRIMARY KEY,

    -- Identity (single DNA handle)
    dna VARCHAR(32) UNIQUE NOT NULL,

    -- Public keys (base64 encoded)
    dilithium_pub TEXT NOT NULL,     -- ~2605 bytes decoded
    kyber_pub TEXT NOT NULL,          -- ~1096 bytes decoded
    cf20pub VARCHAR(103) NOT NULL DEFAULT '',  -- Cellframe address (empty for now)

    -- Versioning (monotonic counter)
    version INTEGER NOT NULL DEFAULT 1,
    updated_at INTEGER NOT NULL,      -- Unix timestamp from client

    -- Signature (Dilithium3)
    sig TEXT NOT NULL,                -- base64 signature of canonical JSON

    -- Schema version (payload format version)
    schema_version INTEGER NOT NULL DEFAULT 1,

    -- Server timestamps
    registered_at TIMESTAMP DEFAULT NOW(),
    last_updated TIMESTAMP DEFAULT NOW(),

    -- Constraints
    CONSTRAINT positive_version CHECK (version > 0)
);

-- Indexes for performance
CREATE INDEX idx_dna ON keyserver_identities(dna);
CREATE INDEX idx_registered_at ON keyserver_identities(registered_at DESC);
CREATE INDEX idx_last_updated ON keyserver_identities(last_updated DESC);

-- Function to update last_updated timestamp
CREATE OR REPLACE FUNCTION update_last_updated()
RETURNS TRIGGER AS $$
BEGIN
    NEW.last_updated = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Trigger to auto-update last_updated
CREATE TRIGGER trigger_update_last_updated
    BEFORE UPDATE ON keyserver_identities
    FOR EACH ROW
    EXECUTE FUNCTION update_last_updated();

-- Comments
COMMENT ON TABLE keyserver_identities IS 'DNA Messenger public key registry';
COMMENT ON COLUMN keyserver_identities.dna IS 'DNA handle (3-32 alphanumeric + underscore)';
COMMENT ON COLUMN keyserver_identities.dilithium_pub IS 'Dilithium3 public key (base64)';
COMMENT ON COLUMN keyserver_identities.kyber_pub IS 'Kyber512 public key (base64)';
COMMENT ON COLUMN keyserver_identities.cf20pub IS 'Cellframe address (empty for now, for future blockchain proof)';
COMMENT ON COLUMN keyserver_identities.version IS 'Monotonic version number (prevents replay)';
COMMENT ON COLUMN keyserver_identities.updated_at IS 'Client-provided Unix timestamp';
COMMENT ON COLUMN keyserver_identities.sig IS 'Dilithium3 signature of JSON payload';
COMMENT ON COLUMN keyserver_identities.schema_version IS 'Payload format version (v field in JSON)';

-- Grant permissions (adjust user as needed)
-- GRANT SELECT, INSERT, UPDATE ON keyserver_identities TO keyserver_user;
-- GRANT USAGE, SELECT ON SEQUENCE keyserver_identities_id_seq TO keyserver_user;
