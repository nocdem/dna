# Message Deletion Design

**Date:** 2026-03-11
**Status:** Approved

## Overview

Add message deletion capability with cross-device sync and sender notification.
Three deletion scopes: single message, contact purge, purge everything.

## Deletion Scopes

1. **Single message delete** — any message (sent or received) can be deleted
2. **Contact purge** — delete all messages with a specific contact
3. **Purge everything** — delete all messages across all contacts

## UI Trigger Points

- **Chat screen**: single message delete (context menu) + contact purge (top menu)
- **Settings**: contact purge + purge everything

## Deletion Flow (same mechanism for all scopes)

### Step 1: Local Delete
- Delete message(s) from local SQLite via existing `message_backup_delete()`
- For purge: batch delete all messages for contact/all contacts

### Step 2: Outbox Rebuild (sender only)
- If the deleted message was sent by me, rebuild my outbox for that contact
- Re-read remaining messages from SQLite, re-encrypt, PUT to DHT
- Deleted message is physically removed from DHT outbox

### Step 3: Send DELETE Notice to Recipient
- Send a DELETE message via existing outbox mechanism (special message type)
- DELETE message contains: content_hash(es) of deleted message(s)
- For purge: send a PURGE_CONVERSATION or PURGE_ALL type
- Recipient receives this during normal offline sync

### Step 4: Cross-Device Sync (self-notification)
- Send DELETE message to own outbox (self-addressed)
- Other devices pick this up during offline sync
- On receipt: delete matching messages from local SQLite

## Recipient Behavior

When recipient receives a DELETE notice:
- **Message content stays intact** (not deleted from recipient's local DB)
- **Visual indicator added**: "Sender deleted this" marker shown next to message
- **Recipient can choose** to delete the message themselves if they want
- For purge: all messages in conversation get the indicator

## Received Message Deletion

When user deletes a message they received:
- Local delete + cross-device sync (tombstone to own devices)
- Notice sent to sender (indicator only)
- Sender's outbox is NOT modified (user has no control over sender's DHT data)

## Technical Details

### DELETE Message Type
New message type in the outbox protocol:
```
type: MSG_TYPE_DELETE
payload: {
    action: DELETE_SINGLE | DELETE_CONVERSATION | DELETE_ALL
    content_hashes: [hash1, hash2, ...]  // for single/conversation
    contact_fp: "..."                     // for conversation delete
}
```

### Message Identification
- Uses existing `content_hash` (SHA3-256 of sender+recipient+plaintext+timestamp)
- Already stored in SQLite (DB v16 migration)

### DHT Behavior
- DELETE notices travel as regular outbox messages (encrypted, signed)
- 7-day TTL (same as regular messages)
- Cross-device sync uses self-addressed outbox messages

### Database Changes
- Add `deleted_by_sender` boolean column to messages table
- When DELETE notice received: set flag, UI shows indicator
- No new tables needed

### Edge Cases
- **Recipient offline > 7 days**: DELETE notice expires from DHT. Message stays as-is on recipient device (no indicator). Acceptable — 7-day window matches message TTL.
- **Old client version**: Ignores unknown message type. No crash, no effect. Message stays as-is.
- **Multiple devices, partial sync**: Each device processes DELETE independently. Eventually consistent.
- **Purge everything while offline**: Queued locally, DELETE notices sent when back online.

## Security Considerations
- DELETE notices are encrypted and signed (same as regular messages)
- Cannot forge deletion — Dilithium5 signature required
- Recipient retains full control of their local data
- No one can force-delete messages from another user's device
