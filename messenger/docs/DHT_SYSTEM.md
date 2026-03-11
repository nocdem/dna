# DHT System Documentation

**Last Updated:** 2026-03-01
**Phase:** 14 (DHT-Only Messaging)
**Version:** 0.7.10

Comprehensive documentation of the DNA Messenger DHT (Distributed Hash Table) system. The DHT layer is powered by Nodus, a pure C Kademlia DHT with PBFT consensus. OpenDHT has been completely removed.

**Migration Note:** Many API function signatures in this document still show `dht_context_t *ctx` as the first parameter. As of the Nodus migration, the `dht_context_t` type no longer exists. All DHT functions now use the Nodus singleton internally (via `nodus_ops.c`) and no longer require an explicit context parameter. Consult the header files in `dht/` for current signatures.

---

## Table of Contents

1. [Overview](#1-overview)
2. [Architecture](#2-architecture)
3. [DHT Core (`dht/core/`)](#3-dht-core-dhtcore)
4. [DHT Client (`dht/client/`)](#4-dht-client-dhtclient)
5. [DHT Shared (`dht/shared/`)](#5-dht-shared-dhtshared)
6. [Keyserver (`dht/keyserver/`)](#6-keyserver-dhtkeyserver)
7. [dna-nodus Bootstrap Server](#7-dna-nodus-bootstrap-server)
8. [Data Types & TTLs](#8-data-types--ttls)
9. [Cryptography](#9-cryptography)
10. [File Reference](#10-file-reference)

---

## 1. Overview

### What is DHT in DNA Messenger?

The DHT is a distributed key-value store powered by Nodus (pure C, Kademlia + PBFT consensus). It provides:

- **Decentralized storage** - No central server; data replicated across nodes
- **Post-quantum security** - Dilithium5 (ML-DSA-87) signatures, NIST Category 5
- **Offline messaging** - Messages stored in DHT when recipients are offline
- **Identity resolution** - Fingerprint-to-name lookups via keyserver
- **Contact list backup** - Encrypted contact lists stored in DHT

### Production Bootstrap Nodes

Three production bootstrap servers run `dna-nodus`:

| Node | IP Address | Port | Location |
|------|-----------|------|----------|
| US-1 | 154.38.182.161 | 4000 | United States |
| EU-1 | 164.68.105.227 | 4000 | Europe |
| EU-2 | 164.68.116.180 | 4000 | Europe |

---

## 2. Architecture

```
+-------------------------------------------------------------+
|                    DNA Messenger Clients                     |
|  (Desktop GUI, future mobile/web)                           |
+-------------------------------------------------------------+
                              |
                              v
+-------------------------------------------------------------+
|                  Nodus Operations Layer                      |
|  dht/shared/nodus_ops.c + nodus_init.c                      |
|  - Convenience wrappers (nodus_ops_put, _get, _listen)      |
|  - Lifecycle management (init, connect, cleanup)            |
|  - Direct integration with Nodus client SDK              |
+-------------------------------------------------------------+
                              |
                              v
+-------------------------------------------------------------+
|                  Nodus Client SDK                         |
|  nodus/src/client/nodus_client.c                            |
|  - TCP connection to Nodus server cluster                   |
|  - CBOR wire protocol (7-byte frame header)                 |
|  - Tier 2 protocol: auth, dht_put, dht_get, listen         |
|  - Dilithium5 challenge/response authentication             |
+-------------------------------------------------------------+
                              |
                              v
+-------------------------------------------------------------+
|                  Nodus Server Cluster                     |
|  nodus/src/server/nodus_server.c                            |
|  - Test: 161.97.85.25, 156.67.24.125, 156.67.25.251       |
|  - Kademlia DHT (UDP 4000) + Client/Replication (TCP 4001) |
|  - PBFT consensus for cross-node replication                |
|  - SQLite persistence for stored values                     |
+-------------------------------------------------------------+
```

### Bootstrap Flow

1. **Cold Start**: Client bootstraps to hardcoded seed node (US-1)
2. **Registry Query**: Fetches bootstrap registry from well-known DHT key
3. **Dynamic Discovery**: Filters active nodes (last_seen < 15 min)
4. **Multi-Node Bootstrap**: Connects to all discovered nodes for resilience

---

## 3. DHT Core (`dht/core/` and `dht/shared/nodus_*`)

**Note:** The old `dht_context.h/cpp` (OpenDHT wrapper) and related files (`dht_listen.cpp`, `dht_stats.cpp`, `dht_identity.cpp`, `dht_value_storage.cpp`) have been removed. DHT operations now go through the Nodus client SDK via `nodus_ops.c`.

### 3.1 Nodus Operations (nodus_ops.h/c)

The DHT interface layer wrapping the Nodus client singleton. All functions use the nodus singleton internally — no explicit context parameter needed. The client supports concurrent requests (up to 16 in-flight), so multiple threads can call nodus_ops functions simultaneously without external locking.

#### Callback Types

```c
typedef bool (*nodus_ops_listen_cb_t)(const uint8_t *data, size_t data_len,
                                      bool expired, void *user_data);
typedef void (*nodus_ops_listen_cleanup_t)(void *user_data);
```

#### PUT Operations

```c
// Store a signed ephemeral value (key hashed to SHA3-512 internally)
int nodus_ops_put(const uint8_t *key, size_t key_len,
                  const uint8_t *data, size_t data_len,
                  uint32_t ttl, uint64_t vid);

// Store using a string key (hashed to SHA3-512)
int nodus_ops_put_str(const char *str_key,
                      const uint8_t *data, size_t data_len,
                      uint32_t ttl, uint64_t vid);

// Store a permanent (never-expiring) value
int nodus_ops_put_permanent(const uint8_t *key, size_t key_len,
                            const uint8_t *data, size_t data_len,
                            uint64_t vid);
```

#### GET Operations

```c
// Retrieve latest value for a key (caller must free *data_out)
int nodus_ops_get(const uint8_t *key, size_t key_len,
                  uint8_t **data_out, size_t *len_out);

// Retrieve using a string key
int nodus_ops_get_str(const char *str_key,
                      uint8_t **data_out, size_t *len_out);

// Retrieve all values for a key (all writers)
int nodus_ops_get_all(const uint8_t *key, size_t key_len,
                      uint8_t ***values_out, size_t **lens_out,
                      size_t *count_out);

// Retrieve all values with their value IDs
int nodus_ops_get_all_with_ids(const uint8_t *key, size_t key_len,
                               uint8_t ***values_out, size_t **lens_out,
                               uint64_t **vids_out, size_t *count_out);
```

#### LISTEN Operations

```c
// Subscribe to changes on a DHT key
size_t nodus_ops_listen(const uint8_t *key, size_t key_len,
                        nodus_ops_listen_cb_t callback,
                        void *user_data,
                        nodus_ops_listen_cleanup_t cleanup);

// Cancel a listener by token
void nodus_ops_cancel_listen(size_t token);

// Cancel all active listeners
void nodus_ops_cancel_all(void);

// Get count of active listeners
size_t nodus_ops_listen_count(void);
```

#### Utility

```c
// Check if the Nodus singleton is connected and authenticated
bool nodus_ops_is_ready(void);

// Get the value_id for the current identity
uint64_t nodus_ops_value_id(void);

// Get the hex fingerprint of the current identity
const char *nodus_ops_fingerprint(void);
```

#### TTL Values

| TTL | Use Case |
|-----|----------|
| 7 days (604800s) | Messages, offline queue, contact lists |
| 30 days (2592000s) | Group metadata, message walls |
| 365 days (31536000s) | Profiles |
| 0 (permanent) | Name registrations (v0.3.0+) |

**Note:** Nodus supports values up to 1MB natively. No chunking abstraction is needed at the nodus_ops level.

---

### 3.2 dht_bootstrap_registry.h/c

Distributed discovery system for bootstrap nodes.

#### Registry Key Derivation

```c
void dht_bootstrap_registry_get_key(char *key_out);
// Returns: SHA3-512("dna:bootstrap:registry") as 128-char hex string
```

#### Node Entry Structure

```c
typedef struct {
    char ip[64];               // IPv4 or IPv6 address
    uint16_t port;             // DHT port (usually 4000)
    char node_id[129];         // SHA3-512(public_key) as hex string
    char version[32];          // dna-nodus version (e.g., "v0.2")
    uint64_t last_seen;        // Unix timestamp of last registration
    uint64_t uptime;           // Seconds since node started
} bootstrap_node_entry_t;
```

#### Registration (Bootstrap Nodes)

```c
// Called on startup and every 5 minutes
int dht_bootstrap_registry_register(
    dht_context_t *dht_ctx,
    const char *my_ip,
    uint16_t my_port,
    const char *node_id,
    const char *version,
    uint64_t uptime
);
```

Flow:
1. Fetch existing registry from DHT
2. Update or add this node's entry
3. Serialize registry to JSON
4. Publish with `dht_put_signed(value_id=1, ttl=7days)`

#### Discovery (Clients)

```c
// Fetch and merge registries from all owners
int dht_bootstrap_registry_fetch(dht_context_t *dht_ctx,
                                  bootstrap_registry_t *registry_out);

// Filter out stale nodes (last_seen > 15 minutes)
void dht_bootstrap_registry_filter_active(bootstrap_registry_t *registry);
```

---

### 3.3 DHT Listeners (via nodus_ops)

Real-time notifications when DHT values change. The listener API is provided by `nodus_ops.h` (see section 3.1 LISTEN Operations above).

#### Callback Behavior

The callback is triggered when:
- New value published (`expired=false`)
- Existing value updated (content changed, `expired=false`)
- Value expired/removed (`expired=true`, `data=NULL`)

#### Example: Listen with Cleanup

```c
#include "dht/shared/nodus_ops.h"

// Context structure for listener
typedef struct {
    char contact_fp[129];
    dna_engine_t *engine;
} listener_ctx_t;

// Cleanup function - free resources when listener is cancelled
void my_cleanup(void *user_data) {
    listener_ctx_t *lctx = (listener_ctx_t *)user_data;
    free(lctx);
}

// Create listener with cleanup
listener_ctx_t *lctx = malloc(sizeof(listener_ctx_t));
strncpy(lctx->contact_fp, contact_fp, 128);
lctx->engine = engine;

size_t token = nodus_ops_listen(key, 64, my_callback, lctx, my_cleanup);
if (token == 0) {
    // Failure - cleanup was already called, do NOT free lctx here
    return;
}

// Cancel specific listener (cleanup called automatically)
nodus_ops_cancel_listen(token);

// Or cancel all listeners at once (during shutdown)
nodus_ops_cancel_all();
```

**Note:** The callback is triggered for both new values AND updates to existing values.
This enables real-time notifications for offline messaging where contacts update
the same outbox key with new messages.

---

## 4. DHT Client (`dht/client/`)

### 4.1 Nodus Integration (nodus_init.h/c)

**Nodus replaced the old `dht_singleton` / `dht_context` / `dht_identity` layer entirely.** The old files (`dht_singleton.c`, `dht_context.cpp`, `dht_identity.cpp`) have been deleted. Lifecycle is now managed through `nodus_init.c`.

```
┌─────────────────────────────────────────────────────────────┐
│               IDENTITY (persistent storage)                  │
│  - fingerprint (SharedPreferences)                          │
│  - mnemonic → derives DHT keys on demand                    │
└───────────────────────────┬─────────────────────────────────┘
                            │
            ┌───────────────┴───────────────┐
            ▼                               ▼
┌───────────────────────┐       ┌───────────────────────┐
│   FLUTTER (foreground)│       │   SERVICE (background)│
│                       │       │                       │
│   dna_engine_create() │       │   dna_engine_create() │
│   ↓                   │       │   ↓                   │
│   nodus_init()        │       │   nodus_init()        │
│   nodus_ops_*()       │       │   nodus_ops_*()       │
└───────────────────────┘       └───────────────────────┘

    Only ONE can hold the identity lock at a time.
    File-based mutex prevents race conditions.
```

#### Nodus Seed Nodes

The messenger connects to the Nodus test cluster:

| Node | IP | TCP Port |
|------|-----|----------|
| nodus-01 | 161.97.85.25 | 4001 |
| nodus-02 | 156.67.24.125 | 4001 |
| nodus-03 | 156.67.25.251 | 4001 |

#### Initialization Flow

1. Engine acquires identity lock (file-based mutex)
2. Engine loads identity from encrypted backup
3. Engine calls `nodus_init()` to connect to Nodus cluster
4. Nodus client authenticates via Dilithium5 challenge/response
5. DHT operations available via `nodus_ops_*()` convenience functions
6. On engine destroy: `nodus_cleanup()`, release lock

### 4.2 DHT Identity (Deterministic)

DHT identity is derived deterministically from the BIP39 master seed:

```
BIP39 mnemonic → master_seed (64 bytes)
                    │
                    └─> dht_seed = SHA3-512(master_seed + "dht_identity")[0:32]
                              │
                              └─> crypto_sign_keypair_from_seed(pk, sk, dht_seed)
                                        │
                                        └─> DHT Dilithium5 identity
```

**Benefits:**
- Same mnemonic = same DHT identity (always recoverable)
- No network dependency for recovery
- No encrypted backup needed

---

### 4.3 dht_contactlist.h/c

Self-encrypted contact list storage in DHT for multi-device sync.

- **DHT Key**: `SHA3-512(identity + ":contactlist")`
- **TTL**: 365 days (stored via chunked layer)
- **Encryption**: Self-encrypted using identity's own Kyber1024 pubkey
- **Signature**: Dilithium5 signed for authenticity

**Sync Behavior:**
- **Push (to DHT)**: Automatic on every contact add/remove
- **Pull (from DHT)**: Automatic during `dna_engine_load_identity()` (v0.2.14+)

This enables seamless contact list restore when logging in on a new device.

---

### 4.4 dht_message_backup.h/c

Manual message backup/restore for multi-device sync via DHT.

- **DHT Key**: `SHA3-512(fingerprint + ":message_backup")`
- **TTL**: 7 days (`DHT_CHUNK_TTL_7DAY`)
- **Encryption**: Self-encrypted using identity's own Kyber1024 pubkey
- **Signature**: Dilithium5 signed for authenticity
- **Storage**: Uses chunked layer for large backups

#### Binary Blob Format

```
[4B magic "MSGB"][1B version][8B timestamp][8B expiry]
[4B payload_len][encrypted_payload][4B sig_len][signature]
```

#### JSON Payload (before encryption)

```json
{
  "version": 1,
  "fingerprint": "abc123...",
  "timestamp": 1703894400,
  "message_count": 150,
  "messages": [
    {
      "sender": "abc...",
      "recipient": "def...",
      "encrypted_message_base64": "...",
      "encrypted_len": 1234,
      "timestamp": 1703894000,
      "is_outgoing": true,
      "status": 1,
      "group_id": 0,
      "message_type": 0
    }
  ]
}
```

#### API

```c
// Backup all messages to DHT (self-encrypted)
int dht_message_backup_publish(
    dht_context_t *dht_ctx,
    message_backup_context_t *msg_ctx,
    const char *fingerprint,
    const uint8_t *kyber_pubkey,
    const uint8_t *kyber_privkey,
    const uint8_t *dilithium_pubkey,
    const uint8_t *dilithium_privkey,
    int *message_count_out
);

// Restore messages from DHT backup
int dht_message_backup_restore(
    dht_context_t *dht_ctx,
    message_backup_context_t *msg_ctx,
    const char *fingerprint,
    const uint8_t *kyber_privkey,
    const uint8_t *dilithium_pubkey,
    int *restored_count_out,
    int *skipped_count_out
);
```

#### Usage Notes

- **Backup triggers**: Manual only (Settings → Data → Backup Messages)
- **Restore triggers**: Manual only (Settings → Data → Restore Messages)
- **Duplicate handling**: Uses `message_backup_exists_ciphertext()` to skip existing messages
- **Expiry**: User must restore within 7 days of backup

### 4.5 dna_channels.h/c (Channel Post Daily Buckets)

Channel posts use daily bucket storage for scalable retrieval. Instead of a single DHT key per channel, posts are partitioned by date.

#### Key Format

```
Posts key:  SHA256("dna:channels:posts:" + uuid + ":" + YYYYMMDD)
Legacy key: SHA256("dna:channels:posts:" + uuid)  (no date suffix, pre-v0.7.5)
```

Each day's posts are stored under a separate DHT key. This prevents unbounded growth on a single key and enables efficient pagination.

#### Fetch Pattern (Newest First)

When fetching posts, the client iterates daily buckets from today backwards:

```
Day 0: today        (e.g., "20260226")
Day 1: yesterday    (e.g., "20260225")
Day 2: 2 days ago   (e.g., "20260224")
...up to days_back
```

- Default `days_back`: 3 (fetches today + 2 previous days)
- Maximum `days_back`: 30
- Posts within each day are sorted by timestamp (newest first)

#### Legacy Fallback (Migration)

During the transition from single-key to daily-bucket storage, the old undated key is also fetched:

```
Legacy: SHA256("dna:channels:posts:" + uuid)  -- no date suffix
```

This ensures posts published before the daily bucket migration are still visible. The legacy key will naturally expire after 30 days (DHT TTL), at which point only daily buckets will be queried.

#### Daily Listener Rotation

Channel post listeners are set up per daily bucket key. At midnight UTC, the heartbeat worker detects the date change and:

1. Cancels the listener on yesterday's bucket key
2. Creates a new listener on today's bucket key

This ensures real-time notifications always point to the current day's posts.

#### Constants

```c
#define DNA_CHANNEL_POSTS_DAYS_DEFAULT 3
#define DNA_CHANNEL_POSTS_DAYS_MAX     30
#define DNA_CHANNEL_TTL_SECONDS        (30 * 24 * 60 * 60)  // 30 days
```

---

## 5. DHT Shared (`dht/shared/`)

### 5.1 Value Persistence

**Note:** The old `dht_value_storage.h/cpp` (SQLite persistence for OpenDHT bootstrap nodes) has been removed. Value persistence is now handled natively by Nodus servers (SQLite in `/var/lib/nodus/`).

The following statistics and persistence concepts still apply at the Nodus server level:

#### Statistics Structure

```c
typedef struct {
    uint64_t total_values;        // Total values currently stored
    uint64_t storage_size_bytes;  // Database file size in bytes
    uint64_t put_count;           // Total PUT operations
    uint64_t get_count;           // Total GET operations
    uint64_t republish_count;     // Total values republished on startup
    uint64_t error_count;         // Total errors encountered
    uint64_t last_cleanup_time;   // Unix timestamp of last cleanup
    bool republish_in_progress;   // Is background republish still running?
} dht_storage_stats_t;
```

#### Selective Persistence

```c
// Only persist PERMANENT and 365-day values
bool dht_value_storage_should_persist(uint32_t value_type, uint64_t expires_at);
// Returns true for:
// - value_type == 0x1002 (365-day)
// - expires_at == 0 (permanent)
// Returns false for 7-day and 30-day values
```

#### Key Functions

```c
// Create storage (opens/creates SQLite database)
dht_value_storage_t* dht_value_storage_new(const char *db_path);

// Store value (filters non-critical values)
int dht_value_storage_put(dht_value_storage_t *storage,
                           const dht_value_metadata_t *metadata);

// Async republish all values on startup
int dht_value_storage_restore_async(dht_value_storage_t *storage,
                                     struct dht_context *ctx);

// Cleanup expired values
int dht_value_storage_cleanup(dht_value_storage_t *storage);

// Free storage
void dht_value_storage_free(dht_value_storage_t *storage);
```

---

### 5.2 dht_dm_outbox.h/c (v0.5.0+)

**Daily bucket system** for 1-1 direct messages - replaces static key outbox.

#### Key Format
```
sender_fp:outbox:recipient_fp:DAY_BUCKET
where DAY_BUCKET = unix_timestamp / 86400
```

#### Features
- **TTL-based cleanup**: 7-day auto-expire, no pruning needed
- **Day rotation**: Listeners rotate at midnight UTC
- **3-day sync**: Yesterday + today + tomorrow (clock skew tolerance)
- **8-day full sync**: Complete DHT retention window for recovery
- **Chunked storage**: Supports large message lists per day
- **Smart sync (v0.5.22)**: Auto-detects when full sync is needed

#### Unified Smart Sync (v0.5.22+)

Both DMs and Groups use the same smart sync strategy for efficient message retrieval:

| Condition | Sync Mode | Days Fetched |
|-----------|-----------|--------------|
| Regular sync (last sync < 3 days) | RECENT | 3 (yesterday, today, tomorrow) |
| Extended offline (last sync > 3 days) | FULL | 8 (today-6 to today+1) |
| Never synced (timestamp = 0) | FULL | 8 |

**Key principle:** Always include tomorrow for clock skew tolerance (+/- 1 day).

**DM Implementation:**
- `contacts.last_dm_sync` column tracks per-contact sync timestamps
- `transport_check_offline_messages(..., force_full_sync)` checks oldest timestamp
- If `force_full_sync=true` (startup) → always full 8-day sync
- If any contact > 3 days since sync OR never synced → full 8-day sync
- Timestamps updated on successful sync
- **Startup sync (v0.6.97):** `dna_engine_listen_all_contacts()` calls with `force_full_sync=true` to catch messages received by other devices

**Group Implementation:**
- `group_sync_state.last_sync_timestamp` column tracks per-group sync timestamps
- `dna_group_outbox_sync_all()` checks each group's timestamp
- Calls `dna_group_outbox_sync_full()` or `dna_group_outbox_sync_recent()` per group
- Timestamps updated on successful sync

**GET Timeout:** DHT GET operations use 30-second timeout (v0.5.22+) for reliable retrieval.

**Benefits:**
- Users offline for 4+ days now receive all messages within DHT retention window
- Recent syncs are 3x faster (3 days vs 8 days)
- Clock skew between devices handled automatically

#### API
```c
// Key generation
uint64_t dht_dm_outbox_get_day_bucket(void);
int dht_dm_outbox_make_key(const char *sender_fp, const char *recipient_fp,
                           uint64_t day_bucket, char *key_out, size_t key_out_size);

// Send
int dht_dm_queue_message(dht_context_t *ctx, const char *sender, const char *recipient,
                         const uint8_t *ciphertext, size_t ciphertext_len,
                         uint64_t seq_num, uint32_t ttl_seconds);

// Receive (single contact)
int dht_dm_outbox_sync_recent(dht_context_t *ctx, const char *my_fp, const char *contact_fp,
                              dht_offline_message_t **messages_out, size_t *count_out);
int dht_dm_outbox_sync_full(dht_context_t *ctx, const char *my_fp, const char *contact_fp,
                            dht_offline_message_t **messages_out, size_t *count_out);

// Receive (all contacts - used by transport layer)
int dht_dm_outbox_sync_all_contacts_recent(dht_context_t *ctx, const char *my_fp,
                                           const char **contact_list, size_t contact_count,
                                           dht_offline_message_t **messages_out, size_t *count_out);
int dht_dm_outbox_sync_all_contacts_full(dht_context_t *ctx, const char *my_fp,
                                         const char **contact_list, size_t contact_count,
                                         dht_offline_message_t **messages_out, size_t *count_out);

// Listen with day rotation
int dht_dm_outbox_subscribe(dht_context_t *ctx, const char *my_fp, const char *contact_fp,
                            dht_listen_callback_t callback, void *user_data,
                            dht_dm_listen_ctx_t **listen_ctx_out);
void dht_dm_outbox_unsubscribe(dht_context_t *ctx, dht_dm_listen_ctx_t *listen_ctx);
int dht_dm_outbox_check_day_rotation(dht_context_t *ctx, dht_dm_listen_ctx_t *listen_ctx);
```

---

### 5.2.1 dht_offline_queue.h/c (Legacy API)

**Note:** As of v0.4.81, `dht_queue_message()` redirects to `dht_dm_queue_message()` (daily buckets).
The legacy API is preserved for backward compatibility. ACK functions (v15) are used for delivery confirmation.

Sender-based outbox for offline message delivery (Spillway Protocol).

#### Architecture (Current: Daily Buckets)

- **Storage Key**: `sender:outbox:recipient:DAY_BUCKET` (unsalted, legacy) or `sender:outbox:recipient:DAY_BUCKET:SALT_HEX` (salted, v0.8.5+)
  - `DAY_BUCKET` = unix_time / 86400
  - `SALT_HEX` = 64-char hex of 32-byte per-contact salt (exchanged during contact request)
- **TTL**: 7 days (auto-expire, **no pruning needed**)
- **Put Type**: Signed chunked with `value_id=1`
- **Max**: 500 messages per day bucket (DoS prevention)
- **Cleanup**: DHT TTL handles expiration automatically

#### ACK System (v15: Replaces Watermarks)

Simple per-contact ACK timestamps for delivery confirmation.

- **ACK Key**: `SHA3-512(recipient + ":ack:" + sender)` (unsalted) or `SHA3-512(recipient + ":ack:" + sender + ":" + SALT_HEX)` (salted, v0.8.5+)
- **ACK TTL**: 30 days
- **Value**: 8-byte big-endian Unix timestamp (when recipient last synced)
- **Purpose**: Update message status from SENT → RECEIVED

**Flow:**
1. Alice sends messages to Bob (status: PENDING → SENT)
2. Bob syncs messages from Alice's outbox
3. Bob publishes ACK timestamp to DHT
4. Alice's ACK listener fires with timestamp
5. Alice marks ALL sent messages to Bob as RECEIVED
6. UI shows double checkmark (✓✓)

**v15 Changes:** Replaced per-message seq_num tracking with simple per-contact timestamp. Simpler, fewer DHT operations.

#### Benefits

- **No accumulation**: Daily buckets with TTL auto-expire
- **Bounded storage**: Max 500 msgs/day × 7 days = 3500 max per contact
- **Spam prevention**: Recipients only query known contacts' outboxes
- **Sender control**: Senders can edit/unsend within 7-day TTL
- **Automatic retrieval**: `dna_engine_load_identity()` checks all contacts' outboxes on login
- **DHT listen (push)**: Real-time notifications via `dht_listen()` on contacts' outbox keys
- **No race conditions**: No read-modify-write for pruning

#### Message Format (v2)

```
[4-byte magic "DNA "][1-byte version (2)]
[8-byte seq_num][8-byte timestamp][8-byte expiry]
[2-byte sender_len][2-byte recipient_len][4-byte ciphertext_len]
[sender string][recipient string][ciphertext bytes]
```

Note: `seq_num` is monotonic per sender-recipient pair (for ordering and delivery confirmation).
`timestamp` is kept for display purposes only.

#### API

```c
// Queue message in sender's outbox (redirects to daily bucket API)
int dht_queue_message(
    const char *sender,           // 128-char fingerprint
    const char *recipient,        // 128-char fingerprint
    const uint8_t *ciphertext,    // Encrypted message
    size_t ciphertext_len,
    uint64_t seq_num,             // From message_backup_get_next_seq()
    uint32_t ttl_seconds,         // 0 = default 7 days
    const uint8_t *salt           // 32-byte per-contact salt (NULL = unsalted)
);

// ACK API (v15, salt-aware v0.8.5+)
void dht_generate_ack_key(const char *recipient, const char *sender,
                          const uint8_t *salt, uint8_t *key_out);
int dht_publish_ack(const char *my_fp, const char *sender_fp, const uint8_t *salt);
size_t dht_listen_ack(const char *my_fp, const char *recipient_fp,
                      const uint8_t *salt,
                      dht_ack_callback_t callback, void *user_data);
void dht_cancel_ack_listener(dht_context_t *ctx, size_t token);

// Retrieve messages from all contacts (sequential)
int dht_retrieve_queued_messages_from_contacts(
    dht_context_t *ctx,
    const char *recipient,
    const char **sender_list,     // Contact fingerprints
    size_t sender_count,
    dht_offline_message_t **messages_out,
    size_t *count_out
);

// Retrieve messages from all contacts (parallel - 10-100x faster)
int dht_retrieve_queued_messages_from_contacts_parallel(
    dht_context_t *ctx,
    const char *recipient,
    const char **sender_list,
    size_t sender_count,
    dht_offline_message_t **messages_out,
    size_t *count_out
);

// Generate outbox base key hash (legacy - for backward compatibility)
// NOTE: For listening to outbox updates, use dht_chunked_make_key() instead
// because chunked storage writes to chunk[0] key, not this raw hash.
void dht_generate_outbox_key(
    const char *sender,
    const char *recipient,
    uint8_t *key_out              // 64 bytes for SHA3-512
);
```

---

### 5.3 dht_groups.h/c

Group metadata storage in DHT.

- DHT key based on group UUID
- 30-day TTL
- Local SQLite cache for fast lookups
- Member management operations

---

### 5.4 dht_gsk_storage.h/c

Chunked storage for large GEK (Group Symmetric Key) packets.

- 50KB chunk size
- Maximum 4 chunks (~200KB total)
- Used for large group key rotation packets

---

### 5.5 dht_profile.h/c

User profile storage in DHT.

- **TTL**: 365 days
- **DHT Key**: Based on fingerprint
- Unified identity structure with avatar, bio, etc.

---

### 5.6 dht_chunked.h/c (Chunked Storage Layer)

Transparent chunking for large data storage in DHT with ZSTD compression.

#### Chunk Format

**v1 (25-byte header):**
```
[4B magic "DNAC"][1B version=1][4B total_chunks][4B chunk_index]
[4B chunk_data_size][4B original_size][4B crc32][payload...]
```

**v2 (57-byte header for chunk 0 only, v0.5.25+):**
```
[4B magic "DNAC"][1B version=2][4B total_chunks][4B chunk_index]
[4B chunk_data_size][4B original_size][4B crc32]
[32B content_hash (SHA3-256 of original uncompressed data)]
[payload...]
```

Non-chunk-0 in v2 uses same 25-byte format as v1 (no hash needed).

#### Content Hash (v0.5.25+)

The content hash enables **smart sync optimization**:

1. Fetch chunk 0 only (metadata)
2. Compare SHA3-256 hash with locally cached hash
3. If match → skip (data unchanged)
4. If mismatch → fetch all chunks

**Why SHA3-256 of original data?**
- Hash computed BEFORE compression ensures content identity
- Same data = same hash, regardless of compression timing
- 32 bytes is compact yet collision-resistant

#### DHT Version Consistency (v0.6.76+)

**Problem**: When publishing multi-chunk data, chunks are written sequentially (1, 2, ..., N-1, 0). Different DHT nodes may cache different versions of chunks. A fetch may retrieve chunk 0 from version 2 but chunk 1 from version 1, mixing ZSTD compressed streams and causing decompression failures.

**Solution**: Content hash verification after successful ZSTD decompression:
1. Decompress reassembled chunks
2. Compute SHA3-256 of decompressed data
3. Compare with content hash from chunk 0 header
4. If mismatch → return `DHT_CHUNK_ERR_HASH_MISMATCH`

**Caller handling**:
- On `DHT_CHUNK_ERR_HASH_MISMATCH`, retry the fetch after a brief delay (e.g., 1 second)
- DHT nodes eventually sync to consistent versions
- Up to 2 retries is typically sufficient

#### Backward Compatibility

| Client | Reading v1 | Reading v2 | Writing |
|--------|------------|------------|---------|
| Old (v1) | ✅ Works | ❌ Rejects | v1 |
| New (v2) | ✅ Works | ✅ Works | v2 |

After 7-day TTL, all DHT data becomes v2 as old clients update.

#### Key Functions

**Thread Safety (v0.6.79+):** `dht_chunked_publish()` uses per-key locking to prevent
concurrent publishes to the same `base_key` from interleaving chunks. Concurrent
publishes to different keys run in parallel normally.

```c
// Publish data with chunking + compression + content hash
int dht_chunked_publish(dht_context_t *ctx, const char *base_key,
                        const uint8_t *data, size_t data_len, uint32_t ttl);

// Fetch and decompress data
int dht_chunked_fetch(dht_context_t *ctx, const char *base_key,
                      uint8_t **data_out, size_t *data_len_out);

// Fetch metadata only (for hash comparison, v0.5.25+)
int dht_chunked_fetch_metadata(dht_context_t *ctx, const char *base_key,
                               uint8_t hash_out[32], uint32_t *original_size_out,
                               uint32_t *total_chunks_out, bool *is_v2_out);

// Batch fetch multiple keys in parallel
int dht_chunked_fetch_batch(dht_context_t *ctx, const char **base_keys,
                            size_t key_count, dht_chunked_batch_result_t **results_out);
```

#### Constants

| Constant | Value | Description |
|----------|-------|-------------|
| `DHT_CHUNK_MAGIC` | 0x444E4143 | "DNAC" in hex |
| `DHT_CHUNK_VERSION` | 2 | Current write version |
| `DHT_CHUNK_HEADER_SIZE_V1` | 25 | v1 header size |
| `DHT_CHUNK_HEADER_SIZE_V2` | 57 | v2 chunk 0 header size |
| `DHT_CHUNK_HASH_SIZE` | 32 | SHA3-256 output size |
| `DHT_CHUNK_DATA_SIZE` | 44975 | Payload per chunk |

#### Error Codes (`dht_chunk_error_t`)

| Code | Value | Description |
|------|-------|-------------|
| `DHT_CHUNK_OK` | 0 | Success |
| `DHT_CHUNK_ERR_NULL_PARAM` | -1 | NULL parameter |
| `DHT_CHUNK_ERR_COMPRESS` | -2 | Compression failed |
| `DHT_CHUNK_ERR_DECOMPRESS` | -3 | Decompression failed |
| `DHT_CHUNK_ERR_DHT_PUT` | -4 | DHT put failed |
| `DHT_CHUNK_ERR_DHT_GET` | -5 | DHT get failed |
| `DHT_CHUNK_ERR_INVALID_FORMAT` | -6 | Invalid chunk format |
| `DHT_CHUNK_ERR_CHECKSUM` | -7 | CRC32 checksum mismatch |
| `DHT_CHUNK_ERR_INCOMPLETE` | -8 | Missing chunks |
| `DHT_CHUNK_ERR_TIMEOUT` | -9 | Fetch timeout |
| `DHT_CHUNK_ERR_ALLOC` | -10 | Memory allocation failed |
| `DHT_CHUNK_ERR_NOT_CONNECTED` | -11 | DHT not connected |
| `DHT_CHUNK_ERR_HASH_MISMATCH` | -12 | Content hash mismatch (DHT version inconsistency - caller should retry) |

---

### 5.7 dht_publish_queue.h/c (Async Publish Queue - v0.6.80+)

Non-blocking publish queue for DHT chunked storage operations. Prevents UI freezes
during profile, contact list, and group list publishes (which can block 30-60s).

#### Problem Solved

`dht_chunked_publish()` blocks for 30-60 seconds per operation. This freezes UI
when updating profile, syncing contacts, or publishing group changes. The publish
queue provides a non-blocking alternative.

#### Architecture

```
Callers (Profile, Contacts, Groups, etc.)
         │
         ▼ dht_chunked_publish_async()
┌─────────────────────────────────────────┐
│         DHT Publish Queue               │
│                                         │
│  FIFO Queue (linked list)               │
│  ┌─────┐ → ┌─────┐ → ┌─────┐ → ...     │
│  │item1│   │item2│   │item3│           │
│  └─────┘   └─────┘   └─────┘           │
│                                         │
│  Single Worker Thread                   │
│  1. Dequeue item                        │
│  2. dht_chunked_publish() (sync)        │
│  3. If fail → retry (max 3x, backoff)   │
│  4. Invoke callback                     │
│  5. Next item                           │
└─────────────────────────────────────────┘
         │
         ▼ dht_chunked_publish() (sync)
      DHT Network
```

#### Key Features

- **Non-blocking**: Callers return immediately
- **Automatic retry**: 3 retries with exponential backoff (1s, 2s, 4s)
- **Per-key serialization**: Relies on existing per-key mutex in `dht_chunked_publish()`
- **Callback notification**: Optional callback when complete (success/fail/cancelled)
- **Queue limit**: 256 items max to prevent unbounded memory growth
- **Fire-and-forget**: Callback can be NULL if caller doesn't need notification

#### API

```c
// Lifecycle
dht_publish_queue_t* dht_publish_queue_create(void);
void dht_publish_queue_destroy(dht_publish_queue_t *queue);

// Submit (non-blocking, data copied internally)
dht_publish_request_id_t dht_chunked_publish_async(
    dht_publish_queue_t *queue,
    dht_context_t *ctx,
    const char *base_key,
    const uint8_t *data,
    size_t data_len,
    uint32_t ttl_seconds,
    dht_publish_callback_t callback,  // NULL = fire-and-forget
    void *user_data
);

// Control
int dht_publish_queue_cancel(dht_publish_queue_t *queue, dht_publish_request_id_t id);
size_t dht_publish_queue_pending_count(dht_publish_queue_t *queue);
bool dht_publish_queue_is_running(dht_publish_queue_t *queue);
```

#### Callback

```c
typedef void (*dht_publish_callback_t)(
    dht_publish_request_id_t request_id,
    const char *base_key,
    int status,      // DHT_PUBLISH_STATUS_OK / _FAILED / _CANCELLED
    int error_code,  // DHT_CHUNK_* error (only if status != OK)
    void *user_data
);
```

#### Status Codes

| Code | Value | Description |
|------|-------|-------------|
| `DHT_PUBLISH_STATUS_OK` | 0 | Publish completed successfully |
| `DHT_PUBLISH_STATUS_FAILED` | -1 | Failed after all retries |
| `DHT_PUBLISH_STATUS_CANCELLED` | -2 | Cancelled before completion |
| `DHT_PUBLISH_STATUS_QUEUE_FULL` | -3 | Queue at capacity (256 items) |

#### Engine Events

- `DNA_EVENT_DHT_PUBLISH_COMPLETE` - Fired when async publish succeeds
- `DNA_EVENT_DHT_PUBLISH_FAILED` - Fired when async publish fails after retries

---

## 6. Keyserver (`dht/keyserver/`)

### Architecture

**NAME-FIRST architecture** - DNA name required for all identities.

Only 2 DHT keys are used:
- **`fingerprint:profile`** → Full `dna_unified_identity_t` (keys + name + profile data)
- **`name:lookup`** → Fingerprint (128 hex chars) for name-based resolution

All entries are self-signed with the owner's Dilithium5 key.

### DHT Key Structure

| DHT Key | Content | TTL |
|---------|---------|-----|
| `SHA3-512(fingerprint + ":profile")` | `dna_unified_identity_t` JSON | 365 days |
| `SHA3-512(name + ":lookup")` | Fingerprint (128 hex) | 365 days |

### Data Type: `dna_unified_identity_t`

```c
typedef struct {
    char fingerprint[129];                    // SHA3-512 of Dilithium5 pubkey
    uint8_t dilithium_pubkey[2592];          // Dilithium5 public key
    uint8_t kyber_pubkey[1568];              // Kyber1024 public key
    bool has_registered_name;
    char registered_name[64];                 // DNA name (3-20 chars)
    uint64_t name_registered_at;
    uint64_t name_expires_at;
    char registration_tx_hash[128];           // Blockchain tx hash
    char registration_network[32];            // e.g., "Backbone"
    uint32_t name_version;
    dna_wallet_list_t wallets;                // Linked wallet addresses
    dna_social_list_t socials;                // Social links
    char bio[512];
    uint64_t timestamp;
    uint32_t version;
    uint8_t signature[4627];                  // Dilithium5 signature over JSON
} dna_unified_identity_t;
```

### Signature Method (JSON-based)

The signature is computed over the **JSON representation** of the identity (without the signature field), NOT the raw struct bytes. This ensures forward compatibility when struct fields change.

```
Sign:   struct → JSON(no sig) → Dilithium5_sign → store sig in struct → JSON(with sig) → DHT
Verify: DHT → JSON → parse → struct → JSON(no sig) → Dilithium5_verify
```

**Benefits:**
- Adding new wallet networks doesn't break old profiles
- Adding new social platforms doesn't break old profiles
- Field order changes are handled by JSON serialization

**Auto-Republish (v0.6.27):** When profile schema changes (e.g., field removal like `display_name` in v0.6.24), old profiles in DHT may fail signature verification because the signed JSON no longer matches. When this happens for the user's own profile, the engine automatically:
1. Detects signature verification failure for own fingerprint
2. Loads cached profile data locally
3. Re-signs and publishes with current schema
4. Logs: `[AUTO-REPUBLISH] Profile republished successfully`

This ensures users don't need to manually re-publish after updates.

**Source:** `keyserver_profiles.c` (dna_update_profile, dna_load_identity), `dna_engine.c` (dna_auto_republish_own_profile)

### Operations

| File | Purpose |
|------|---------|
| `keyserver_publish.c` | Publish identity to `:profile`, create `:lookup` alias |
| `keyserver_lookup.c` | Lookup by fingerprint or name, returns `dna_unified_identity_t` |
| `keyserver_names.c` | Name validation and availability checking |
| `keyserver_profiles.c` | Profile update operations |

### API

```c
// Publish identity (name required, wallet optional)
int dht_keyserver_publish(
    dht_context_t *dht_ctx,
    const char *fingerprint,
    const char *name,              // REQUIRED
    const uint8_t *dilithium_pubkey,
    const uint8_t *kyber_pubkey,
    const uint8_t *dilithium_privkey,
    const char *wallet_address     // Optional - Cellframe wallet address
);

// Lookup identity (returns full unified identity)
int dht_keyserver_lookup(
    dht_context_t *dht_ctx,
    const char *name_or_fingerprint,
    dna_unified_identity_t **identity_out  // Caller must call dna_identity_free()
);

// Reverse lookup: fingerprint → name
int dht_keyserver_reverse_lookup(
    dht_context_t *dht_ctx,
    const char *fingerprint,
    char **name_out                // Caller must free()
);
```

---

## 7. Nodus Server

### 7.1 Overview

Nodus is a pure C post-quantum DHT server with PBFT consensus:

- **UDP Port**: 4000 (Kademlia peer discovery)
- **TCP Port**: 4001 (client connections + replication)
- **Crypto**: Dilithium5 (ML-DSA-87) mandatory
- **Storage**: SQLite persistence in `/var/lib/nodus/`
- **Source**: `/opt/dna/nodus/` (top-level in monorepo)
- **Protocol**: CBOR over wire frames (7-byte header: magic `0x4E44` + version + length)

**Note:** The old `dna-nodus` (OpenDHT-based, `vendor/opendht-pq/tools/dna-nodus.cpp`) has been removed from the codebase. Production servers still run the legacy v0.4.5 binary from `/opt/dna-messenger/`.

### 7.2 Protocol Tiers

| Tier | Transport | Messages | Purpose |
|------|-----------|----------|---------|
| Tier 1 | UDP | ping, find_node, put, get | Kademlia inter-node operations |
| Tier 2 | TCP | auth, dht_put, dht_get, listen, channels | Client-facing operations |

### 7.3 Deployment

**Nodus Test Cluster (3 nodes, v0.5.0):**

| Node | IP | Config |
|------|-----|--------|
| nodus-01 | 161.97.85.25 | `/etc/nodus.conf` |
| nodus-02 | 156.67.24.125 | `/etc/nodus.conf` |
| nodus-03 | 156.67.25.251 | `/etc/nodus.conf` |

```bash
# Build
cd /opt/dna/nodus/build && cmake .. && make -j$(nproc)

# Deploy to a server
ssh root@<IP> 'bash /tmp/nodus-redeploy.sh'

# Check status
ssh root@<IP> 'systemctl status nodus'
```

**Legacy Production Servers (v0.4.5, still running):**

| Server | IP | Port |
|--------|-----|------|
| US-1 | 154.38.182.161 | 4000 |
| EU-1 | 164.68.105.227 | 4000 |
| EU-2 | 164.68.116.180 | 4000 |

### 7.4 Persistence

Nodus stores data in `/var/lib/nodus/`:
- Identity files (Dilithium5 keypair)
- SQLite database for DHT values

### 7.5 Monitoring

```bash
# Service status
ssh root@<IP> 'systemctl status nodus'

# Live logs
ssh root@<IP> 'journalctl -u nodus -f'
```

---

## 8. Data Types & TTLs

> **Detailed storage model documentation:** See **[DHT_STORAGE_MODEL.md](DHT_STORAGE_MODEL.md)** for comprehensive coverage of daily bucket patterns, serialization formats, sync strategies, and multi-owner patterns for each data type.

| Data Type | TTL | DHT Key Format | Persisted | Notes |
|-----------|-----|----------------|-----------|-------|
| **Presence** | N/A | N/A (Nodus-native, v0.9.0+) | No | Server-side tracking, batch TCP query |
| Offline Messages | 7 days | `sender:outbox:recipient:DAY:SALT_HEX` | No | Spillway outbox (salt optional) |
| **ACK (v15)** | 30 days | `SHA3-512(recipient:ack:sender:SALT_HEX)` | No | Delivery ack (salt optional) |
| Contact Lists | 7 days | `SHA3-512(identity:contactlist)` | No | Self-encrypted |
| **Message Backup** | 7 days | `SHA3-512(fingerprint:message_backup)` | No | Self-encrypted, manual sync |
| **Contact Requests** | 7 days | `SHA3-512(fingerprint:requests)` | No | ICQ-style contact request inbox |
| **Identity** | PERMANENT | `SHA3-512(fingerprint:profile)` | Yes | Unified: keys + name + profile (v0.3.0+) |
| **Name Lookup** | PERMANENT | `SHA3-512(name:lookup)` | Yes | Name → fingerprint (v0.3.0+) |
| Group Metadata | 30 days | `SHA3-512(group_uuid)` | Yes | |
| **Group Outbox** | 7 days | `dna:group:<uuid>:out:<day>:<sender_fp>` | No | Per-sender, day buckets, chunked ZSTD |
| Message Wall | 30 days | `SHA3-512(fingerprint:message_wall)` | Yes | DNA Board |
| Bootstrap Registry | 7 days | `SHA3-512("dna:bootstrap:registry")` | Special | Self-healing |

### 8.1 Presence Data (Nodus-Native, v0.9.0+)

Presence is tracked natively by the Nodus server. Connected clients are registered server-side via `nodus_presence_add_local`/`nodus_presence_remove_local`. Presence is broadcast between Nodus nodes via the `p_sync` protocol.

**No DHT PUT/GET for presence.** The old DHT-based presence system (publishing IP:port:timestamp to DHT key = fingerprint) has been removed.

**How it works:**
1. When a client connects to a Nodus server, the server tracks it as "present"
2. The C heartbeat thread runs every 10s, calling `dna_presence_batch_query()` which sends a single `pq` (presence query) TCP message to the Nodus server with all contact fingerprints
3. The server responds with online/offline status + last_seen timestamps for each queried fingerprint
4. Results are stored in the local `presence_cache`; status transitions fire `DNA_EVENT_CONTACT_ONLINE`/`DNA_EVENT_CONTACT_OFFLINE` events
5. Flutter UI receives these events directly — no Dart-side polling needed (v0.101.29+)

**Cache update rules (v0.9.10+):**
- Online contacts: cache updated with current time
- Offline contacts with server last_seen: cache updated with server timestamp
- Offline contacts with no server data (last_seen=0): existing cached timestamp preserved (not overwritten with `now`)

**Lookup API:**
```c
// High-level API (reads from local cache, populated by batch query)
int dna_engine_lookup_presence(
    dna_engine_t *engine,
    const char *fingerprint,
    dna_presence_cb callback,
    void *user_data
);
```

**Flutter Usage:**
```dart
// Online/offline status driven by C events (CONTACT_ONLINE/CONTACT_OFFLINE)
// No Dart-side polling — C heartbeat handles everything (10s interval)
```

### 8.2 Contact Requests

ICQ-style mutual contact request system. Requests are stored in recipient's DHT inbox.

**DHT Key:** `SHA3-512(recipient_fingerprint + ":requests")` (binary, 64 bytes)

**Request Structure (v2 — with DHT salt):**
```c
typedef struct {
    uint32_t magic;                      // 0x444E4152 ("DNAR")
    uint8_t version;                     // 1 (legacy) or 2 (with salt)
    uint64_t timestamp;                  // Unix timestamp
    uint64_t expiry;                     // timestamp + 7 days
    char sender_fingerprint[129];        // Sender's fingerprint
    char sender_name[64];               // Sender's display name
    uint8_t sender_dilithium_pubkey[2592]; // Sender's Dilithium5 public key
    char message[256];                   // Optional "Hey, add me!"
    uint8_t dht_salt[32];               // v2: per-contact DHT key salt
    bool has_dht_salt;                   // true for v2 requests
    uint8_t signature[4627];             // Dilithium5 signature (includes salt for v2)
    size_t signature_len;
} dht_contact_request_t;
```

**Salt Exchange Flow:**
1. Alice generates 32 random bytes → sends v2 request to Bob (includes salt)
2. Bob receives → stores Alice's salt in `contact_requests` table
3. Bob approves → moves salt to `contacts` table, sends reciprocal v2 with same salt
4. Alice receives reciprocal → stores salt in `contacts` table
5. Both have identical salt → salted DHT keys work for outbox + ACK

**C API:**
```c
// Send a contact request (v2 with salt)
int dht_send_contact_request(
    const char *sender_fingerprint, const char *sender_name,
    const uint8_t *sender_dilithium_pubkey, const uint8_t *sender_dilithium_privkey,
    const char *recipient_fingerprint, const char *optional_message,
    const uint8_t *dht_salt);  // 32-byte salt (NULL for v1 legacy)

// Fetch all requests from my inbox
int dht_fetch_contact_requests(dht_context_t *ctx,
    const char *my_fingerprint,
    dht_contact_request_t **requests_out, size_t *count_out);

// Verify request signature
int dht_verify_contact_request(const dht_contact_request_t *request);
```

**Flutter Usage:**
```dart
// Send request
await engine.sendContactRequest(recipientFingerprint, "Hey, let's connect!");

// Get pending requests
final requests = await engine.getContactRequests();

// Approve (creates mutual contact)
await engine.approveContactRequest(fingerprint);

// Deny (can retry later)
await engine.denyContactRequest(fingerprint);

// Block permanently
await engine.blockUser(fingerprint, "spam");
```

**Flow:**
1. Alice sends request → DHT puts to Bob's inbox key
2. Bob polls inbox → fetches Alice's signed request
3. Bob verifies signature, checks not blocked
4. Bob approves → Alice added as mutual contact
5. Bob sends reciprocal request so Alice knows

---

## 9. Cryptography

| Algorithm | Standard | NIST Level | Use |
|-----------|----------|------------|-----|
| Dilithium5 | ML-DSA-87 (FIPS 204) | Category 5 | Signing, Node Identity |
| Kyber1024 | ML-KEM-1024 (FIPS 203) | Category 5 | Key Encapsulation |
| AES-256-GCM | FIPS 197 | - | Message Encryption |
| SHA3-512 | FIPS 202 | - | Key Derivation, Hashing |

### Key Sizes

- **Dilithium5 Public Key**: 2592 bytes
- **Dilithium5 Private Key**: 4864 bytes
- **Dilithium5 Signature**: 4627 bytes
- **Kyber1024 Public Key**: 1568 bytes
- **SHA3-512 Hash**: 64 bytes

---

## 10. File Reference

| Directory | Key Files | Purpose |
|-----------|-----------|---------|
| `dht/shared/` | `nodus_ops.c`, `nodus_ops.h` | Nodus convenience wrappers (put, get, listen) |
| `dht/shared/` | `nodus_init.c`, `nodus_init.h` | Nodus lifecycle (init, connect, cleanup) |
| `dht/core/` | `dht_bootstrap_registry.c`, `dht_bootstrap_registry.h` | Bootstrap discovery |
| `dht/core/` | `dht_keyserver.c`, `dht_keyserver.h` | Keyserver operations |
| `dht/client/` | `dht_contactlist.c`, `dht_contactlist.h` | Contact list storage |
| `dht/client/` | `dht_message_backup.c`, `dht_message_backup.h` | Message backup/restore |
| `dht/shared/` | `dht_offline_queue.c`, `dht_offline_queue.h` | Offline messaging |
| `dht/shared/` | `dht_dm_outbox.c`, `dht_dm_outbox.h` | Daily bucket DM outbox |
| `dht/shared/` | `dht_publish_queue.c`, `dht_publish_queue.h` | Async publish queue |
| `dht/shared/` | `dht_groups.c`, `dht_groups.h` | Group metadata |
| `dht/shared/` | `dht_profile.c`, `dht_profile.h` | User profiles |
| `dht/shared/` | `dht_contact_request.c`, `dht_contact_request.h` | Contact request DHT operations |
| `dht/shared/` | `dht_gek_storage.c`, `dht_gek_storage.h` | GEK chunked storage |
| `dht/keyserver/` | `keyserver_*.c`, `keyserver_*.h` | Name/key resolution |
| `nodus/` | `include/nodus/nodus.h` | Nodus client SDK public API |
| `nodus/` | `include/nodus/nodus_types.h` | Nodus constants, version |
| `nodus/` | `src/server/nodus_server.c` | Nodus server (epoll event loop) |
| `nodus/` | `src/client/nodus_client.c` | Nodus client SDK |

---

## Quick Reference

### Initialize DHT (via Nodus)

```c
#include "dht/shared/nodus_init.h"
#include "dht/shared/nodus_ops.h"

// Initialize Nodus connection (called by engine)
nodus_init();

// DHT operations via nodus_ops convenience wrappers
nodus_ops_put(key, key_len, value, value_len, ttl);
nodus_ops_get(key, key_len, &value_out, &value_len_out);
nodus_ops_listen(key, key_len, callback, user_data);
```

### Store Value

```c
uint8_t key[64];
// Generate key (e.g., SHA3-512 of some identifier)

uint8_t *value = "Hello DHT";
size_t value_len = strlen(value);

// Store via nodus_ops
nodus_ops_put(key, 64, value, value_len, 7 * 24 * 3600);  // 7-day TTL
```

### Retrieve Value

```c
uint8_t *value_out;
size_t value_len_out;

if (nodus_ops_get(key, 64, &value_out, &value_len_out) == 0) {
    // Use value
    free(value_out);
}
```

### Cleanup

```c
nodus_cleanup();
```
