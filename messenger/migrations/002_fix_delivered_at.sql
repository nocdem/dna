-- DNA Messenger: Fix NULL delivered_at for read messages
-- Created: 2025-10-15
-- Description: Set delivered_at = read_at for messages marked as read without delivery timestamp

-- This migration fixes messages that were marked as read before the
-- COALESCE fix was implemented in messenger_mark_conversation_read()

UPDATE messages
SET delivered_at = read_at
WHERE status = 'read'
  AND delivered_at IS NULL
  AND read_at IS NOT NULL;

-- Verify the fix
SELECT COUNT(*) as fixed_messages
FROM messages
WHERE status = 'read'
  AND delivered_at IS NOT NULL
  AND read_at IS NOT NULL;
