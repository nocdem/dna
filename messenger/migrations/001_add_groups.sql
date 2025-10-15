-- DNA Messenger: Groups Feature Migration
-- Created: 2025-10-15
-- Description: Add support for persistent groups with membership management

-- ============================================================================
-- GROUPS TABLE
-- ============================================================================
-- Stores group metadata (name, creator, timestamps)
CREATE TABLE IF NOT EXISTS groups (
    id SERIAL PRIMARY KEY,
    name TEXT NOT NULL,
    description TEXT,
    creator TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT groups_name_not_empty CHECK (char_length(name) > 0)
);

CREATE INDEX IF NOT EXISTS idx_groups_creator ON groups(creator);
CREATE INDEX IF NOT EXISTS idx_groups_created_at ON groups(created_at DESC);

-- ============================================================================
-- GROUP_MEMBERS TABLE
-- ============================================================================
-- Stores group membership (which identities belong to which groups)
CREATE TABLE IF NOT EXISTS group_members (
    group_id INTEGER NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
    member TEXT NOT NULL,
    joined_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    role TEXT DEFAULT 'member',  -- 'creator', 'admin', 'member'
    PRIMARY KEY (group_id, member),
    CONSTRAINT group_members_role_valid CHECK (role IN ('creator', 'admin', 'member'))
);

CREATE INDEX IF NOT EXISTS idx_group_members_member ON group_members(member);
CREATE INDEX IF NOT EXISTS idx_group_members_group_id ON group_members(group_id);

-- ============================================================================
-- MESSAGES TABLE EXTENSION
-- ============================================================================
-- Add group_id column to existing messages table
-- This allows linking messages to groups (optional - message_group_id might suffice)
DO $$
BEGIN
    -- Only add column if it doesn't exist
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'messages' AND column_name = 'group_id'
    ) THEN
        ALTER TABLE messages ADD COLUMN group_id INTEGER REFERENCES groups(id) ON DELETE SET NULL;
        CREATE INDEX idx_messages_group_id ON messages(group_id);
    END IF;
END $$;

-- ============================================================================
-- HELPER FUNCTIONS
-- ============================================================================

-- Function to update group updated_at timestamp on member changes
CREATE OR REPLACE FUNCTION update_group_timestamp()
RETURNS TRIGGER AS $$
BEGIN
    UPDATE groups SET updated_at = CURRENT_TIMESTAMP WHERE id = NEW.group_id;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Trigger to auto-update group timestamp when members change
DROP TRIGGER IF EXISTS trigger_update_group_timestamp ON group_members;
CREATE TRIGGER trigger_update_group_timestamp
    AFTER INSERT OR UPDATE OR DELETE ON group_members
    FOR EACH ROW EXECUTE FUNCTION update_group_timestamp();

-- ============================================================================
-- SAMPLE DATA (for testing - can be removed in production)
-- ============================================================================
-- Uncomment to create sample groups for testing:
-- INSERT INTO groups (name, description, creator) VALUES
--     ('DNA Developers', 'Core development team', 'alice'),
--     ('Crypto Enthusiasts', 'Post-quantum cryptography discussion', 'bob');
--
-- INSERT INTO group_members (group_id, member, role) VALUES
--     (1, 'alice', 'creator'),
--     (1, 'bob', 'admin'),
--     (1, 'charlie', 'member'),
--     (2, 'bob', 'creator'),
--     (2, 'alice', 'member');

-- ============================================================================
-- MIGRATION COMPLETE
-- ============================================================================
