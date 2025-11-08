# Multi-Device Synchronization Protocol

**Component:** Local Cache + DHT Synchronization
**Status:** Research & Planning Phase
**Dependencies:** DHT Storage Layer, P2P Transport Layer

---

## OVERVIEW

The sync protocol enables seamless multi-device support, allowing users to access messages from desktop, mobile, and web clients simultaneously. It combines local SQLite cache (fast) with DHT storage (distributed) for optimal performance and availability.

**Use Case:**
```
User "alice" has:
- Desktop (primary)
- Mobile phone
- Web browser

Alice sends message from Desktop
  → Message appears on Mobile and Web automatically
```

---

## ARCHITECTURE

```
┌─────────────────────────────────────────────────────────────┐
│                 Multi-Device Architecture                    │
│                                                               │
│   Desktop                 Mobile                 Web         │
│   ┌──────────┐           ┌──────────┐          ┌──────────┐ │
│   │  SQLite  │           │  SQLite  │          │ IndexedDB│ │
│   │  Cache   │           │  Cache   │          │  Cache   │ │
│   └────┬─────┘           └────┬─────┘          └────┬─────┘ │
│        │                      │                      │       │
│        └──────────────────────┼──────────────────────┘       │
│                               │                              │
│                               ▼                              │
│                    ┌────────────────────┐                    │
│                    │   DHT Network      │                    │
│                    │  (Synchronized)    │                    │
│                    └────────────────────┘                    │
│                                                               │
│  All devices sync through DHT (single source of truth)       │
└─────────────────────────────────────────────────────────────┘
```

**Hybrid Model:**
- **Local cache (SQLite):** Fast reads, offline access, search/filter
- **DHT storage:** Distributed, multi-device sync, backup

---

## SYNC PROTOCOL OVERVIEW

### Key Concepts

**1. Local-First Design**
- Read from local cache (instant)
- Write to local cache immediately (responsive UI)
- Sync to DHT in background (eventual consistency)

**2. Conflict-Free**
- Messages are immutable (never edited)
- Deletions are soft (tombstones)
- Timestamps resolve ordering

**3. Bidirectional Sync**
- Upload: Local changes → DHT
- Download: DHT changes → Local cache

---

## LOCAL CACHE (SQLITE)

### Purpose

**Performance:**
- Instant message list (no DHT query)
- Fast search/filter (SQL queries)
- Offline access (read cached messages)

**Privacy:**
- Conversation patterns hidden from DHT (less metadata leakage)
- Encrypted with DNA's PQ crypto (Kyber512 + AES-256-GCM AEAD)

### Schema

```sql
-- Messages (cached from DHT + local state)
CREATE TABLE messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    message_id TEXT UNIQUE NOT NULL,  -- Global ID (SHA256 hash)
    conversation_id TEXT NOT NULL,
    sender TEXT NOT NULL,
    recipient TEXT NOT NULL,
    ciphertext BLOB NOT NULL,
    status TEXT DEFAULT 'sent',        -- 'sent', 'delivered', 'read'
    created_at INTEGER NOT NULL,       -- Unix timestamp
    delivered_at INTEGER,
    read_at INTEGER,
    synced_to_dht BOOLEAN DEFAULT 0,  -- Sync state
    deleted BOOLEAN DEFAULT 0,         -- Soft delete (tombstone)
    group_id INTEGER
);

-- Conversations (metadata)
CREATE TABLE conversations (
    id TEXT PRIMARY KEY,               -- SHA256(participants)
    type TEXT NOT NULL,                -- 'direct', 'group'
    participants TEXT NOT NULL,        -- JSON array
    last_message_at INTEGER,
    unread_count INTEGER DEFAULT 0,
    last_sync_time INTEGER DEFAULT 0   -- Last DHT sync timestamp
);

-- Sync state (tracking)
CREATE TABLE sync_state (
    device_id TEXT PRIMARY KEY,        -- This device's unique ID
    last_upload_time INTEGER,          -- Last successful upload to DHT
    last_download_time INTEGER,        -- Last successful download from DHT
    pending_uploads INTEGER DEFAULT 0, -- Count of messages waiting to sync
    pending_downloads INTEGER DEFAULT 0
);

-- Tombstones (deleted messages)
CREATE TABLE tombstones (
    message_id TEXT PRIMARY KEY,       -- ID of deleted message
    deleted_at INTEGER NOT NULL,       -- Unix timestamp
    synced_to_dht BOOLEAN DEFAULT 0
);
```

---

## SYNC OPERATIONS

### 1. UPLOAD (Local → DHT)

**Trigger:** After sending message or marking message read

**Process:**

```c
int sync_upload_message(sync_context_t *ctx, const message_info_t *msg) {
    // 1. Check if already synced
    if (msg->synced_to_dht) {
        return 0; // Already uploaded
    }

    // 2. Store in DHT
    uint8_t storage_key[32];
    int result = dht_storage_put_message(
        ctx->dht_ctx,
        msg->sender,
        msg->recipient,
        msg->ciphertext,
        msg->ciphertext_len,
        30, // 30 days TTL
        storage_key
    );

    if (result != 0) {
        return -1; // Upload failed, retry later
    }

    // 3. Mark as synced in local cache
    const char *sql = "UPDATE messages SET synced_to_dht = 1 WHERE message_id = ?";
    sqlite3_stmt *stmt;
    sqlite3_prepare_v2(ctx->db, sql, -1, &stmt, NULL);
    sqlite3_bind_text(stmt, 1, msg->message_id, -1, SQLITE_TRANSIENT);
    sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    printf("✓ Uploaded message %s to DHT\n", msg->message_id);
    return 0;
}
```

**Batch Upload (Periodic Background Sync):**

```c
void sync_upload_pending(sync_context_t *ctx) {
    // Find all messages not yet synced to DHT
    const char *sql = "SELECT * FROM messages WHERE synced_to_dht = 0 LIMIT 100";

    sqlite3_stmt *stmt;
    sqlite3_prepare_v2(ctx->db, sql, -1, &stmt, NULL);

    while (sqlite3_step(stmt) == SQLITE_ROW) {
        message_info_t msg;
        // Parse row into msg structure
        ...

        // Upload to DHT
        sync_upload_message(ctx, &msg);
    }

    sqlite3_finalize(stmt);
}
```

---

### 2. DOWNLOAD (DHT → Local)

**Trigger:**
- Device comes online
- Periodic background sync (every 5 minutes)
- User pulls to refresh

**Process:**

```c
int sync_download_messages(sync_context_t *ctx, const char *identity) {
    // 1. Get last sync time for this conversation
    uint64_t last_sync = get_last_sync_time(ctx->db, identity);

    // 2. Query DHT for new messages since last_sync
    dht_message_t *messages;
    size_t count;
    int result = dht_storage_get_messages_since(
        ctx->dht_ctx,
        identity,
        last_sync,
        &messages,
        &count
    );

    if (result != 0 || count == 0) {
        return 0; // No new messages
    }

    // 3. Insert into local cache
    for (size_t i = 0; i < count; i++) {
        dht_message_t *msg = &messages[i];

        // Check if already exists (idempotent)
        if (message_exists_local(ctx->db, msg->message_id)) {
            continue;
        }

        // Insert into messages table
        const char *sql =
            "INSERT INTO messages (message_id, sender, recipient, "
            "ciphertext, created_at, synced_to_dht) "
            "VALUES (?, ?, ?, ?, ?, 1)";

        sqlite3_stmt *stmt;
        sqlite3_prepare_v2(ctx->db, sql, -1, &stmt, NULL);
        sqlite3_bind_text(stmt, 1, msg->message_id, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 2, msg->sender, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 3, msg->recipient, -1, SQLITE_TRANSIENT);
        sqlite3_bind_blob(stmt, 4, msg->ciphertext, msg->ciphertext_len, SQLITE_TRANSIENT);
        sqlite3_bind_int64(stmt, 5, msg->timestamp);
        sqlite3_step(stmt);
        sqlite3_finalize(stmt);

        printf("✓ Downloaded message %s from DHT\n", msg->message_id);
    }

    // 4. Update last sync time
    update_last_sync_time(ctx->db, identity, time(NULL));

    // 5. Free DHT results
    free(messages);

    return count; // Number of new messages
}
```

---

### 3. DELETION SYNC (Tombstones)

**Problem:** User deletes message on Desktop, must delete on Mobile too

**Solution:** Tombstone replication

**Process:**

```c
int sync_delete_message(sync_context_t *ctx, const char *message_id) {
    // 1. Soft delete in local cache (don't actually delete row)
    const char *sql = "UPDATE messages SET deleted = 1 WHERE message_id = ?";
    sqlite3_stmt *stmt;
    sqlite3_prepare_v2(ctx->db, sql, -1, &stmt, NULL);
    sqlite3_bind_text(stmt, 1, message_id, -1, SQLITE_TRANSIENT);
    sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    // 2. Create tombstone
    sql = "INSERT INTO tombstones (message_id, deleted_at) VALUES (?, ?)";
    sqlite3_prepare_v2(ctx->db, sql, -1, &stmt, NULL);
    sqlite3_bind_text(stmt, 1, message_id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(stmt, 2, time(NULL));
    sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    // 3. Upload tombstone to DHT (special key)
    char tombstone_key[512];
    snprintf(tombstone_key, sizeof(tombstone_key), "tombstone:%s", message_id);

    uint8_t tombstone_data[128];
    // Serialize tombstone
    ...

    dht_put(ctx->dht_ctx, tombstone_key, strlen(tombstone_key),
            tombstone_data, sizeof(tombstone_data), 5);

    // 4. Delete original message from DHT
    uint8_t storage_key[32];
    derive_storage_key(message_id, storage_key);
    dht_storage_delete_message(ctx->dht_ctx, storage_key);

    return 0;
}
```

**Download tombstones (other devices apply deletions):**

```c
void sync_download_tombstones(sync_context_t *ctx, const char *identity) {
    // Query DHT for tombstones
    char query[256];
    snprintf(query, sizeof(query), "tombstone:%s:*", identity);

    // For each tombstone:
    //   1. Mark message as deleted locally
    //   2. Remove from UI
    //   3. Mark tombstone as synced
}
```

---

## CONFLICT RESOLUTION

### No Conflicts by Design

**Messages are immutable:**
- Never edited after creation
- Each message has unique ID (SHA256 hash)
- Timestamp determines ordering

**Deletions are soft:**
- Tombstones replicate deletions
- Last-write-wins (latest tombstone timestamp)

**Read receipts:**
- Each device tracks separately (local-only state)
- Or: Upload read receipt to DHT (optional, privacy tradeoff)

### Edge Cases

**Case 1: Same message sent from two devices simultaneously**
```
Desktop: Send "Hello" at t=1000
Mobile:  Send "Hello" at t=1000

Result: Two separate messages (different message IDs)
        Both appear in conversation
```

**Case 2: Device offline for weeks, comes back online**
```
Device queries DHT for all messages since last_sync (30 days ago)
Downloads all pending messages (batched)
Updates local cache
```

**Case 3: Message deleted on Desktop, Mobile offline**
```
Desktop uploads tombstone to DHT
Mobile comes online later, downloads tombstones
Mobile applies deletion locally
```

---

## SYNC STRATEGIES

### Strategy 1: Periodic Sync (Simple)

**Implementation:**
```c
// Every 5 minutes
void sync_periodic(sync_context_t *ctx) {
    sync_upload_pending(ctx);        // Upload unsent messages
    sync_download_messages(ctx);     // Download new messages
    sync_download_tombstones(ctx);   // Download deletions
}
```

**Pros:**
- Simple implementation
- Predictable network usage

**Cons:**
- Up to 5-minute delay for cross-device updates

---

### Strategy 2: Push Notifications (Real-Time)

**Implementation:**

```c
// DHT listen for new messages
dht_listen(ctx->dht_ctx, "alice:msg:*", on_new_message_callback);

void on_new_message_callback(const uint8_t *key, const uint8_t *value) {
    // New message arrived in DHT
    // Download immediately
    sync_download_message_by_key(ctx, key);

    // Show notification
    show_notification("New message from bob");
}
```

**Pros:**
- Real-time synchronization
- No polling delay

**Cons:**
- Requires persistent DHT connection
- Higher battery usage (mobile)

---

### Strategy 3: Hybrid (Recommended)

**Desktop/Web:** Push notifications (always online)
**Mobile:** Periodic sync (battery-efficient)

```c
#ifdef MOBILE
    // Periodic sync every 5 minutes
    sync_periodic(ctx);
#else
    // Real-time push notifications
    dht_listen(ctx->dht_ctx, "alice:msg:*", on_new_message_callback);
#endif
```

---

## MESSAGE ID GENERATION

**Purpose:** Globally unique message ID for deduplication

**Formula:**
```c
message_id = SHA256(sender + recipient + timestamp + ciphertext[:64])
```

**Example:**
```c
void generate_message_id(const char *sender, const char *recipient,
                         uint64_t timestamp, const uint8_t *ciphertext,
                         size_t ciphertext_len, char *message_id_out) {
    uint8_t hash_input[4096];
    size_t offset = 0;

    // Append sender
    memcpy(hash_input + offset, sender, strlen(sender));
    offset += strlen(sender);

    // Append recipient
    memcpy(hash_input + offset, recipient, strlen(recipient));
    offset += strlen(recipient);

    // Append timestamp
    memcpy(hash_input + offset, &timestamp, sizeof(timestamp));
    offset += sizeof(timestamp);

    // Append first 64 bytes of ciphertext
    size_t ctext_len = (ciphertext_len < 64) ? ciphertext_len : 64;
    memcpy(hash_input + offset, ciphertext, ctext_len);
    offset += ctext_len;

    // SHA256 hash
    uint8_t hash[32];
    SHA256(hash_input, offset, hash);

    // Convert to hex string
    bytes_to_hex(hash, 32, message_id_out);
}
```

**Result:** `message_id = "9d4f7e2a..."`  (64-character hex string)

---

## API DESIGN

```c
// Sync Context
typedef struct sync_context_t sync_context_t;

// Initialize sync manager
sync_context_t* sync_init(
    sqlite3 *db,                    // Local SQLite cache
    dht_storage_context_t *dht_ctx, // DHT storage
    const char *identity            // User's identity
);

// Upload operations
int sync_upload_message(sync_context_t *ctx, const message_info_t *msg);
int sync_upload_pending(sync_context_t *ctx); // Batch upload all unsent

// Download operations
int sync_download_messages(sync_context_t *ctx, const char *conversation_id);
int sync_download_all(sync_context_t *ctx); // All conversations

// Deletion sync
int sync_delete_message(sync_context_t *ctx, const char *message_id);
int sync_download_tombstones(sync_context_t *ctx);

// Background sync (periodic)
void sync_run_background(sync_context_t *ctx); // Every 5 minutes

// Real-time sync (push notifications)
int sync_enable_realtime(sync_context_t *ctx);
int sync_disable_realtime(sync_context_t *ctx);

// Sync status
typedef struct {
    uint64_t last_upload_time;
    uint64_t last_download_time;
    size_t pending_uploads;
    size_t pending_downloads;
    bool realtime_enabled;
} sync_status_t;

int sync_get_status(sync_context_t *ctx, sync_status_t *status_out);

// Cleanup
void sync_free(sync_context_t *ctx);
```

---

## DEVICE MANAGEMENT

### Device Identifier

**Purpose:** Distinguish messages from different devices

**Generation:**
```c
// Generate once per device, store in ~/.dna/device_id
void generate_device_id(char *device_id_out) {
    uint8_t random[16];
    qgp_randombytes(random, 16);
    bytes_to_hex(random, 16, device_id_out);
    // Result: "7a3f2c1b..." (32-character hex string)
}
```

**Storage:** `~/.dna/device_id` (persistent across app restarts)

### Multi-Device Inbox

**Query:** "Show messages from all my devices"

```sql
SELECT * FROM messages
WHERE recipient = 'alice'
ORDER BY created_at DESC;
```

**No need to distinguish** devices at application level (all sync via DHT)

---

## STORAGE OPTIMIZATION

### Pruning Old Messages

**Problem:** Local cache grows unbounded

**Solution:** Prune messages older than 90 days (keep in DHT, delete from local cache)

```c
void sync_prune_old_messages(sync_context_t *ctx, uint32_t days) {
    uint64_t cutoff = time(NULL) - (days * 86400);

    const char *sql = "DELETE FROM messages WHERE created_at < ?";
    sqlite3_stmt *stmt;
    sqlite3_prepare_v2(ctx->db, sql, -1, &stmt, NULL);
    sqlite3_bind_int64(stmt, 1, cutoff);
    sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    printf("✓ Pruned messages older than %u days\n", days);
}
```

**User can still access** old messages by querying DHT (slower, but available)

### Compression

**Problem:** Large conversation history consumes space

**Solution:** Compress ciphertext in local cache

```c
// Before storing in SQLite:
uint8_t *compressed;
size_t compressed_len;
zlib_compress(ciphertext, ciphertext_len, &compressed, &compressed_len);

// Store compressed_len and compressed in database
```

**Typical compression:** 30-50% size reduction

---

## PRIVACY CONSIDERATIONS

### What's Visible in DHT?

**With sync protocol:**
- **DHT nodes see:** Sender, recipient, timestamps, message sizes (same as without sync)
- **DHT nodes do NOT see:** Plaintext, conversation patterns (if using local cache for frequent queries)

### Metadata Leakage Mitigation

**Problem:** DHT queries reveal conversation patterns

**Example:** Alice queries DHT every 5 minutes for "bob:msg:*" → reveals Alice-Bob communication

**Solution:** Use local cache for frequent queries, only sync periodically

```
Query DHT: Every 5 minutes (background, not per-message)
Query SQLite: Every time user opens conversation (instant, private)
```

**Result:** DHT sees 1 query per 5 minutes instead of 1 query per message

---

## IMPLEMENTATION FILES

```c
sync_protocol.h         // Public API
sync_protocol.c         // Core sync logic
sync_upload.c           // Upload manager
sync_download.c         // Download manager
sync_tombstone.c        // Deletion sync
```

---

## TESTING PLAN

### Unit Tests
- Message ID generation
- Upload/download operations
- Tombstone replication
- Conflict resolution

### Integration Tests
- Two devices sync messages
- Device offline, comes back online
- Message deleted on one device, synced to others
- Large message history sync

### Performance Tests
- Sync 10,000 messages
- Initial sync time (new device)
- Background sync overhead
- Battery usage (mobile)

---

## FUTURE ENHANCEMENTS

1. **Selective sync** - Download only recent messages (last 7 days)
2. **Message archiving** - Move old messages to archive nodes
3. **End-to-end encrypted sync** - Encrypt message metadata in DHT
4. **Group message sync** - Multi-recipient synchronization optimization
5. **Bandwidth optimization** - Delta sync (only changed fields)

---

**Document Version:** 1.0
**Last Updated:** 2025-10-16
**Status:** Research & Planning Phase
