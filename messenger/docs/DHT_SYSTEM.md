# DHT System Documentation

**Last Updated:** 2026-01-23
**Phase:** 14 (DHT-Only Messaging)
**Version:** 0.6.27

Comprehensive documentation of the DNA Messenger DHT (Distributed Hash Table) system, covering both client operations and the dna-nodus bootstrap server.

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

The DHT is a distributed key-value store built on OpenDHT-PQ (post-quantum fork). It provides:

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
|                     DHT Singleton                           |
|  dht/client/dht_singleton.c                                 |
|  - Single shared DHT instance per app                       |
|  - Bootstraps to seed node -> discovers registry            |
|  - Memory-only mode (no persistence)                        |
+-------------------------------------------------------------+
                              |
                              v
+-------------------------------------------------------------+
|                     DHT Context                              |
|  dht/core/dht_context.cpp                                   |
|  - OpenDHT-PQ wrapper (C API over C++)                      |
|  - 3 ValueTypes: 7-day, 30-day, 365-day                     |
|  - PUT/GET/Listen operations                                 |
+-------------------------------------------------------------+
                              |
                              v
+-------------------------------------------------------------+
|                  Bootstrap Registry                          |
|  dht/core/dht_bootstrap_registry.c                          |
|  - Well-known key: SHA3-512("dna:bootstrap:registry")       |
|  - Self-healing distributed discovery                        |
|  - 15-minute stale timeout, 5-minute refresh                |
+-------------------------------------------------------------+
                              |
                              v
+-------------------------------------------------------------+
|                  dna-nodus Bootstrap Nodes                   |
|  vendor/opendht-pq/tools/dna-nodus.cpp                      |
|  - US-1: 154.38.182.161:4000                                |
|  - EU-1: 164.68.105.227:4000                                |
|  - EU-2: 164.68.116.180:4000                                |
|  - SQLite persistence for PERMANENT/365-day values          |
|  - Self-registers every 5 minutes                            |
+-------------------------------------------------------------+
```

### Bootstrap Flow

1. **Cold Start**: Client bootstraps to hardcoded seed node (US-1)
2. **Registry Query**: Fetches bootstrap registry from well-known DHT key
3. **Dynamic Discovery**: Filters active nodes (last_seen < 15 min)
4. **Multi-Node Bootstrap**: Connects to all discovered nodes for resilience

---

## 3. DHT Core (`dht/core/`)

### 3.1 dht_context.h/cpp

The core DHT wrapper around OpenDHT's `DhtRunner` class.

#### Configuration Structure

```c
typedef struct {
    uint16_t port;                    // DHT port (default: 4000)
    bool is_bootstrap;                // Is this a bootstrap node?
    char identity[256];               // Node identity name
    char bootstrap_nodes[5][256];     // Up to 5 bootstrap nodes (IP:port)
    size_t bootstrap_count;           // Number of bootstrap nodes
    char persistence_path[512];       // Disk persistence path (empty = memory-only)
} dht_config_t;
```

#### Lifecycle Functions

```c
// Create context
dht_context_t* dht_context_new(const dht_config_t *config);

// Start node (generates Dilithium5 identity)
int dht_context_start(dht_context_t *ctx);

// Start with user-provided identity
int dht_context_start_with_identity(dht_context_t *ctx, dht_identity_t *identity);

// Check if connected to network
bool dht_context_is_ready(dht_context_t *ctx);

// Stop and cleanup
void dht_context_stop(dht_context_t *ctx);
void dht_context_free(dht_context_t *ctx);
```

#### PUT Operations

```c
// Default 7-day TTL
int dht_put(dht_context_t *ctx,
            const uint8_t *key, size_t key_len,
            const uint8_t *value, size_t value_len);

// Custom TTL (seconds)
int dht_put_ttl(dht_context_t *ctx,
                const uint8_t *key, size_t key_len,
                const uint8_t *value, size_t value_len,
                unsigned int ttl_seconds);

// Permanent storage (never expires)
int dht_put_permanent(dht_context_t *ctx,
                      const uint8_t *key, size_t key_len,
                      const uint8_t *value, size_t value_len);

// Signed PUT with fixed value_id (enables replacement)
int dht_put_signed(dht_context_t *ctx,
                   const uint8_t *key, size_t key_len,
                   const uint8_t *value, size_t value_len,
                   uint64_t value_id,
                   unsigned int ttl_seconds);

// Republish packed value (preserves original signature)
int dht_republish_packed(dht_context_t *ctx,
                         const char *key_hex,
                         const uint8_t *packed_data,
                         size_t packed_len);
```

#### GET Operations

```c
// Synchronous GET (returns first value)
int dht_get(dht_context_t *ctx,
            const uint8_t *key, size_t key_len,
            uint8_t **value_out, size_t *value_len_out);

// Get all values for key
int dht_get_all(dht_context_t *ctx,
                const uint8_t *key, size_t key_len,
                uint8_t ***values_out, size_t **values_len_out,
                size_t *count_out);

// Asynchronous GET with callback
void dht_get_async(dht_context_t *ctx,
                   const uint8_t *key, size_t key_len,
                   void (*callback)(uint8_t *value, size_t value_len, void *userdata),
                   void *userdata);
```

#### ValueTypes

Three custom ValueTypes with specific TTLs:

| Type ID | Name | TTL | Use Case |
|---------|------|-----|----------|
| 0x1001 | DNA_7DAY | 7 days | Messages, offline queue, contact lists |
| 0x1002 | DNA_365DAY | 365 days | Profiles (legacy) |
| 0x1003 | DNA_30DAY | 30 days | Group metadata, message walls |
| PERMANENT | DHT_CHUNK_TTL_PERMANENT | ~136 years | Name registrations, profiles (v0.3.0+) |

**v0.3.0 Change:** Name registrations and profiles now use `DHT_CHUNK_TTL_PERMANENT` (UINT32_MAX = 4294967295 seconds ≈ 136 years). Once a name is registered (with blockchain tx verification), it never expires.

ValueTypes are registered on startup and handle automatic persistence to SQLite on bootstrap nodes.

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

### 3.3 dht_listen.h

Real-time notifications when DHT values change.

#### Constants (Phase 14)

```c
// Maximum number of simultaneous listeners
#define DHT_MAX_LISTENERS 1024
```

#### Basic API

```c
// Callback type
typedef bool (*dht_listen_callback_t)(
    const uint8_t *value,      // NULL if expired
    size_t value_len,
    bool expired,              // true = value expired, false = new/updated value
    void *user_data
);

// Callback is triggered when:
// - New value published (expired=false)
// - Existing value updated (content changed + seq incremented, expired=false)
// - Value expired/removed (expired=true, value=NULL)

// Start listening (returns token > 0 on success)
size_t dht_listen(dht_context_t *ctx,
                  const uint8_t *key, size_t key_len,
                  dht_listen_callback_t callback,
                  void *user_data);

// Cancel subscription
void dht_cancel_listen(dht_context_t *ctx, size_t token);

// Get active subscription count
size_t dht_get_active_listen_count(dht_context_t *ctx);
```

#### Extended API (Phase 14)

Phase 14 added extended API with cleanup callbacks, auto-resubscription, and
listener limits for reliable Android background operation.

```c
// Cleanup callback - invoked when listener is cancelled
typedef void (*dht_listen_cleanup_t)(void *user_data);

// Start listening with cleanup callback support
// Also stores key data for auto-resubscription after network loss
// Returns 0 if DHT_MAX_LISTENERS limit is reached
size_t dht_listen_ex(dht_context_t *ctx,
                     const uint8_t *key, size_t key_len,
                     dht_listen_callback_t callback,
                     void *user_data,
                     dht_listen_cleanup_t cleanup);  // may be NULL

// Cancel all active listeners and invoke their cleanup callbacks
// Useful for shutdown or DHT reconnection
void dht_cancel_all_listeners(dht_context_t *ctx);

// Re-register all active listeners with OpenDHT
// Call when DHT connection is restored after network loss
// Only works for listeners created with dht_listen_ex()
size_t dht_resubscribe_all_listeners(dht_context_t *ctx);
```

#### Example: Basic Usage

```c
// Listen for messages from a contact's outbox
// Callback fires when contact sends NEW message (updates their outbox)
//
// IMPORTANT: Outbox uses chunked storage, so listen to chunk[0] key:
// - Base key: "contact_fp:outbox:my_fp"
// - Chunk[0] key: SHA3-512(base_key + ":chunk:0")[0:32]
#include "dht/shared/dht_chunked.h"

char base_key[512];
snprintf(base_key, sizeof(base_key), "%s:outbox:%s", contact_fp, my_fp);

uint8_t chunk0_key[DHT_CHUNK_KEY_SIZE];  // 32 bytes
dht_chunked_make_key(base_key, 0, chunk0_key);

size_t token = dht_listen(ctx, chunk0_key, DHT_CHUNK_KEY_SIZE, my_callback, my_context);
if (token == 0) {
    fprintf(stderr, "Failed to start listening\n");
}

// Later, stop listening:
dht_cancel_listen(ctx, token);
```

#### Example: Extended API with Cleanup (Phase 14)

```c
// Context structure for listener
typedef struct {
    char contact_fp[129];
    dna_engine_t *engine;
} listener_ctx_t;

// Cleanup function - free resources when listener is cancelled
void my_cleanup(void *user_data) {
    listener_ctx_t *ctx = (listener_ctx_t *)user_data;
    free(ctx);
}

// Create listener with cleanup
listener_ctx_t *ctx = malloc(sizeof(listener_ctx_t));
strncpy(ctx->contact_fp, contact_fp, 128);
ctx->engine = engine;

size_t token = dht_listen_ex(dht_ctx, key, 64, my_callback, ctx, my_cleanup);
if (token == 0) {
    // Failure - cleanup was already called by dht_listen_ex, do NOT free ctx here
    return;
}

// When cancelled, my_cleanup is called automatically
dht_cancel_listen(dht_ctx, token);  // calls my_cleanup(ctx)

// Or cancel all listeners at once (during shutdown)
dht_cancel_all_listeners(dht_ctx);  // calls cleanup for each
```

**Important:** `dht_listen_ex()` calls the cleanup function on ALL failure paths (timeout,
exception, max listeners). Do NOT manually free user_data if the function returns 0.

**Note:** The callback is triggered for both new values AND updates to existing values
(when content changes and sequence number increases). This enables real-time notifications
for offline messaging where contacts update the same outbox key with new messages.

---

### 3.4 dht_errors.h

Standardized error codes for all DHT operations.

```c
typedef enum {
    DHT_SUCCESS           =  0,   // Operation completed successfully
    DHT_ERROR_GENERAL     = -1,   // General/unspecified error
    DHT_ERROR_NOT_FOUND   = -2,   // Key/value not found in DHT
    DHT_ERROR_AUTH_FAILED = -3,   // Signature verification failed
    DHT_ERROR_TIMEOUT     = -4,   // Operation timed out
    DHT_ERROR_INVALID_PARAM = -5, // Invalid parameter (NULL or malformed)
    DHT_ERROR_MEMORY      = -6,   // Memory allocation failed
    DHT_ERROR_NETWORK     = -7,   // Network/DHT communication error
    DHT_ERROR_SERIALIZE   = -8,   // Serialization/deserialization failed
    DHT_ERROR_CRYPTO      = -9,   // Cryptographic operation failed
    DHT_ERROR_NOT_INIT    = -10,  // DHT context not initialized
    DHT_ERROR_ALREADY_EXISTS = -11, // Item already exists (duplicate)
    DHT_ERROR_STORAGE     = -12,  // Storage/persistence error
} dht_error_t;

// Get human-readable error message
const char* dht_strerror(int error_code);
```

---

## 4. DHT Client (`dht/client/`)

### 4.1 dht_singleton.h/c

**v0.6.0+: Engine-Owned DHT Context**

As of v0.6.0, each engine instance owns its own DHT context. The singleton pattern
is kept for backwards compatibility but now uses a "borrowed context" model:

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
│   engine owns DHT ctx │       │   engine owns DHT ctx │
│   (via identity lock) │       │   (via identity lock) │
└───────────────────────┘       └───────────────────────┘

    Only ONE can hold the identity lock at a time.
    File-based mutex prevents race conditions.
```

#### Bootstrap Configuration

```c
// Hardcoded seed node for cold start
static const char *SEED_NODE = "154.38.182.161:4000";

// Fallback nodes if registry unavailable
static const char *FALLBACK_NODES[] = {
    "154.38.182.161:4000",  // US-1
    "164.68.105.227:4000",  // EU-1
    "164.68.116.180:4000"   // EU-2
};
```

#### API

```c
// DEPRECATED: Use engine-owned context instead
int dht_singleton_init(void);
int dht_singleton_init_with_identity(dht_identity_t *user_identity);

// Get DHT context (returns borrowed context from engine, or NULL)
dht_context_t* dht_singleton_get(void);

// Check if initialized
bool dht_singleton_is_initialized(void);

// Cleanup on shutdown
void dht_singleton_cleanup(void);

// v0.6.0+: Create engine-owned DHT context
dht_context_t* dht_create_context_with_identity(dht_identity_t *user_identity);

// v0.6.0+: Set borrowed context (engine lends its context to singleton)
void dht_singleton_set_borrowed_context(dht_context_t *ctx);
```

#### Initialization Flow (v0.6.0+)

1. Engine acquires identity lock (file-based mutex)
2. Engine loads DHT identity from encrypted backup
3. Engine creates its own DHT context via `dht_create_context_with_identity()`
4. Engine lends context to singleton via `dht_singleton_set_borrowed_context()`
5. DHT bootstraps to seed nodes (async)
6. On engine destroy: clear borrowed context, stop/free DHT, release lock

---

### 4.2 dht_identity.h/cpp

Dilithium5 identity management for DHT operations.

**v0.3.0 Change: Deterministic DHT Identity**

As of v0.3.0, DHT identity is derived deterministically from the BIP39 master seed:

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
- Eliminates `dht_identity_backup.c/h` (removed in v0.3.0)

```c
// Opaque identity structure (wraps dht::crypto::Identity)
typedef struct dht_identity dht_identity_t;

// Generate new Dilithium5 identity (random)
dht_identity_t* dht_identity_generate(const char *name);

// Generate deterministically from 32-byte seed (v0.3.0+)
int dht_identity_generate_from_seed(const uint8_t *seed, dht_identity_t **out);

// Load from binary files (.dsa, .pub, .cert)
dht_identity_t* dht_identity_load(const char *base_path);

// Save to binary files
int dht_identity_save(dht_identity_t *id, const char *base_path);

// Export to binary blob
int dht_identity_export(dht_identity_t *id, uint8_t **data_out, size_t *len_out);

// Import from binary blob
dht_identity_t* dht_identity_import(const uint8_t *data, size_t len);

// Free identity
void dht_identity_free(dht_identity_t *id);
```

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

---

## 5. DHT Shared (`dht/shared/`)

### 5.1 dht_value_storage.h/cpp

SQLite persistence for bootstrap nodes only.

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
- **TTL-based cleanup**: 7-day auto-expire, no watermark pruning needed
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
- `transport_check_offline_messages()` checks oldest timestamp
- If any contact > 3 days since sync OR never synced → full 8-day sync
- Timestamps updated on successful sync

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

### 5.2.1 dht_offline_queue.h/c (Legacy)

**Note:** As of v0.5.0, `dht_queue_message()` redirects to `dht_dm_queue_message()`.
Watermark functions are kept for delivery report notifications.

Sender-based outbox for offline message delivery (Spillway Protocol) with watermark pruning.

#### Architecture

- **Storage Key**: `SHA3-512(sender + ":outbox:" + recipient)`
- **TTL**: 7 days default
- **Put Type**: Signed with `value_id=1` (enables replacement)
- **Approach**: Each sender controls their outbox to each recipient

#### Watermark Pruning

To prevent unbounded outbox growth, recipients publish delivery acknowledgments ("watermarks"):

- **Watermark Key**: `SHA3-512(recipient + ":watermark:" + sender)`
- **Watermark TTL**: 30 days
- **Value**: 8-byte big-endian seq_num (latest message received from sender)

**Flow:**
1. Alice sends messages to Bob with monotonic seq_num (1, 2, 3...)
2. Bob receives messages, publishes watermark `seq=3` asynchronously
3. Alice sends new message (`seq=4`), fetches Bob's watermark (`seq=3`)
4. Alice prunes outbox: removes messages where `seq_num <= 3`
5. Alice publishes updated outbox with only `seq=4`

**Benefits:**
- **Bounded storage**: Delivered messages are pruned on next send
- **Clock-skew immune**: Uses monotonic seq_num, not timestamps
- **Async publish**: Watermark publishing is fire-and-forget (non-blocking)
- **Self-healing**: If watermark publish fails, retry happens on next receive

#### Benefits

- **No accumulation**: Signed puts replace old values (not append)
- **Spam prevention**: Recipients only query known contacts' outboxes
- **Sender control**: Senders can edit/unsend within 7-day TTL
- **Automatic retrieval**: `dna_engine_load_identity()` checks all contacts' outboxes on login
- **DHT listen (push)**: Real-time notifications via `dht_listen()` on contacts' outbox keys

#### Message Format (v2)

```
[4-byte magic "DNA "][1-byte version (2)]
[8-byte seq_num][8-byte timestamp][8-byte expiry]
[2-byte sender_len][2-byte recipient_len][4-byte ciphertext_len]
[sender string][recipient string][ciphertext bytes]
```

Note: `seq_num` is monotonic per sender-recipient pair (for watermark pruning).
`timestamp` is kept for display purposes only.

#### API

```c
// Queue message in sender's outbox (with watermark pruning)
int dht_queue_message(
    dht_context_t *ctx,
    const char *sender,           // 128-char fingerprint
    const char *recipient,        // 128-char fingerprint
    const uint8_t *ciphertext,    // Encrypted message
    size_t ciphertext_len,
    uint64_t seq_num,             // From message_backup_get_next_seq()
    uint32_t ttl_seconds          // 0 = default 7 days
);

// Watermark API
void dht_generate_watermark_key(const char *recipient, const char *sender, uint8_t *key_out);
void dht_publish_watermark_async(dht_context_t *ctx, const char *recipient, const char *sender, uint64_t seq_num);
int dht_get_watermark(dht_context_t *ctx, const char *recipient, const char *sender, uint64_t *seq_num_out);

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

#### Backward Compatibility

| Client | Reading v1 | Reading v2 | Writing |
|--------|------------|------------|---------|
| Old (v1) | ✅ Works | ❌ Rejects | v1 |
| New (v2) | ✅ Works | ✅ Works | v2 |

After 7-day TTL, all DHT data becomes v2 as old clients update.

#### Key Functions

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

## 7. dna-nodus Bootstrap Server

### 7.1 Overview

`dna-nodus` is a specialized post-quantum DHT bootstrap node:

- **Port**: 4000 (default)
- **Crypto**: Dilithium5 (ML-DSA-87) mandatory
- **Storage**: SQLite persistence for critical values
- **Binary**: `vendor/opendht-pq/tools/dna-nodus`

### 7.2 Command-Line Options

```
Usage: dna-nodus [options]

Options:
  -p <port>           Port to listen on (default: 4000)
  -i <path>           Identity name (default: dna-bootstrap-node)
  -s <path>           Persistence path (default: /var/lib/dna-dht/bootstrap.state)
  -b <host>:port      Bootstrap from host (can specify multiple, max 3)
  --public-ip <ip>    Public IP address
  -v                  Verbose logging
  -h, --help          Show help
```

### 7.3 Startup Sequence

```cpp
// From dna-nodus.cpp main()
1. Parse command-line arguments
2. Auto-detect public IP if not specified
3. Setup signal handlers (SIGINT, SIGTERM)
4. Configure DHT context (bootstrap mode)
5. Create DHT context with dht_context_new()
6. Start DHT node with dht_context_start()
7. Get node ID with dht_get_node_id()
8. Register in bootstrap registry (dht_bootstrap_registry_register)
9. Main loop:
   - Print stats every 60 seconds
   - Refresh registry every 5 minutes
```

### 7.4 Persistence

#### Database Location

```
Default: /var/lib/dna-dht/bootstrap.state.values.db
Override: -s <path> sets base path, database is <path>.values.db
```

#### Identity Files

```
<persistence_path>.identity.dsa   - Private key (Dilithium5)
<persistence_path>.identity.pub   - Public key
<persistence_path>.identity.cert  - Certificate
```

#### What Gets Persisted

| ValueType | TTL | Persisted |
|-----------|-----|-----------|
| 0x1001 | 7-day | No (ephemeral) |
| 0x1002 | 365-day | Yes |
| 0x1003 | 30-day | Yes |
| PERMANENT | Never | Yes |

### 7.5 Deployment

**CRITICAL: Always build on server, never deploy via scp**

```bash
# On each bootstrap server:
cd /opt/dna-messenger
git pull
rm -rf build && mkdir build && cd build
cmake -DBUILD_GUI=OFF .. && make -j$(nproc)

# Kill old nodus
killall -9 dna-nodus

# Start dna-nodus with all bootstrap nodes
./vendor/opendht-pq/tools/dna-nodus \
  -b 154.38.182.161:4000 \
  -b 164.68.105.227:4000 \
  -b 164.68.116.180:4000 \
  -v

# OR run in background:
nohup ./vendor/opendht-pq/tools/dna-nodus \
  -b 154.38.182.161:4000 \
  -b 164.68.105.227:4000 \
  -b 164.68.116.180:4000 \
  -v > /var/log/dna-nodus.log 2>&1 &
```

### 7.6 Monitoring

Stats printed every 60 seconds:
```
[1 min] [8 nodes] [42 values] | DB: 156 values
[2 min] [12 nodes] [67 values] | DB: 156 values (republishing...)
```

---

## 8. Data Types & TTLs

| Data Type | TTL | DHT Key Format | Persisted | Notes |
|-----------|-----|----------------|-----------|-------|
| **Presence** | 7 days | `SHA3-512(public_key)` = fingerprint | No | IP:port:timestamp |
| Offline Messages | 7 days | `SHA3-512(sender:outbox:recipient)` | No | Spillway outbox |
| **Watermarks** | 30 days | `SHA3-512(recipient:watermark:sender)` | No | Delivery ack (8-byte seq_num) |
| Contact Lists | 7 days | `SHA3-512(identity:contactlist)` | No | Self-encrypted |
| **Message Backup** | 7 days | `SHA3-512(fingerprint:message_backup)` | No | Self-encrypted, manual sync |
| **Contact Requests** | 7 days | `SHA3-512(fingerprint:requests)` | No | ICQ-style contact request inbox |
| **Identity** | PERMANENT | `SHA3-512(fingerprint:profile)` | Yes | Unified: keys + name + profile (v0.3.0+) |
| **Name Lookup** | PERMANENT | `SHA3-512(name:lookup)` | Yes | Name → fingerprint (v0.3.0+) |
| Group Metadata | 30 days | `SHA3-512(group_uuid)` | Yes | |
| **Group Outbox** | 7 days | `dna:group:<uuid>:out:<day>:<sender_fp>` | No | Per-sender, day buckets, chunked ZSTD |
| Message Wall | 30 days | `SHA3-512(fingerprint:message_wall)` | Yes | DNA Board |
| Bootstrap Registry | 7 days | `SHA3-512("dna:bootstrap:registry")` | Special | Self-healing |

### 8.1 Presence Data

Presence records are published when a user comes online and refreshed periodically.

**DHT Key:** `SHA3-512(Dilithium5_public_key)` = user's fingerprint (binary, 64 bytes)

**Value Format (JSON):**
```json
{"ips":"192.168.1.5,83.x.x.x","port":4001,"timestamp":1733234567}
```

| Field | Description |
|-------|-------------|
| `ips` | Comma-separated local + public IPs |
| `port` | TCP listen port (default 4001) |
| `timestamp` | Unix timestamp when presence was registered |

**Lookup API:**
```c
// C API - lookup presence by fingerprint
int p2p_lookup_presence_by_fingerprint(
    transport_t *ctx,
    const char *fingerprint,      // 128 hex chars
    uint64_t *last_seen_out       // Unix timestamp output
);

// High-level API
int dna_engine_lookup_presence(
    dna_engine_t *engine,
    const char *fingerprint,
    dna_presence_cb callback,
    void *user_data
);
```

**Flutter Usage:**
```dart
final lastSeen = await engine.lookupPresence(contact.fingerprint);
// Returns DateTime when peer last registered presence
```

### 8.2 Contact Requests

ICQ-style mutual contact request system. Requests are stored in recipient's DHT inbox.

**DHT Key:** `SHA3-512(recipient_fingerprint + ":requests")` (binary, 64 bytes)

**Request Structure:**
```c
typedef struct {
    uint32_t magic;                      // 0x444E4152 ("DNAR")
    uint8_t version;                     // 1
    uint64_t timestamp;                  // Unix timestamp
    uint64_t expiry;                     // timestamp + 7 days
    char sender_fingerprint[129];        // Sender's fingerprint
    char sender_name[64];                // Sender's display name
    uint8_t sender_dilithium_pubkey[2592]; // Sender's Dilithium5 public key
    char message[256];                   // Optional "Hey, add me!"
    uint8_t signature[4627];             // Dilithium5 signature
    size_t signature_len;
} dht_contact_request_t;
```

**C API:**
```c
// Send a contact request
int dht_send_contact_request(dht_context_t *ctx,
    const char *sender_fingerprint, const char *sender_name,
    const uint8_t *sender_dilithium_pubkey, const uint8_t *sender_dilithium_privkey,
    const char *recipient_fingerprint, const char *optional_message);

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
| `dht/core/` | `dht_context.cpp`, `dht_context.h` | Core DHT wrapper |
| `dht/core/` | `dht_bootstrap_registry.c`, `dht_bootstrap_registry.h` | Bootstrap discovery |
| `dht/core/` | `dht_listen.h`, `dht_listen.cpp` | Real-time notifications |
| `dht/core/` | `dht_errors.h` | Error codes |
| `dht/core/` | `dht_stats.h`, `dht_stats.cpp` | Statistics |
| `dht/client/` | `dht_singleton.c`, `dht_singleton.h` | Global singleton |
| `dht/client/` | `dht_identity.cpp`, `dht_identity.h` | Identity management |
| `dht/client/` | `dht_contactlist.c`, `dht_contactlist.h` | Contact list storage |
| `dht/client/` | `dht_message_backup.c`, `dht_message_backup.h` | Message backup/restore |
| `dht/shared/` | `dht_value_storage.cpp`, `dht_value_storage.h` | SQLite persistence |
| `dht/shared/` | `dht_offline_queue.c`, `dht_offline_queue.h` | Offline messaging |
| `dht/shared/` | `dht_groups.c`, `dht_groups.h` | Group metadata |
| `dht/shared/` | `dht_profile.c`, `dht_profile.h` | User profiles |
| `dht/shared/` | `dht_contact_request.c`, `dht_contact_request.h` | Contact request DHT operations |
| `dht/keyserver/` | `keyserver_*.c`, `keyserver_*.h` | Name/key resolution |
| `vendor/opendht-pq/tools/` | `dna-nodus.cpp` | Bootstrap server |

---

## Quick Reference

### Initialize DHT (Client)

```c
#include "dht/client/dht_singleton.h"

// Initialize global DHT
if (dht_singleton_init() != 0) {
    fprintf(stderr, "DHT init failed\n");
    return -1;
}

// Get context for operations
dht_context_t *ctx = dht_singleton_get();
```

### Store Value

```c
uint8_t key[64];
// Generate key (e.g., SHA3-512 of some identifier)

uint8_t *value = "Hello DHT";
size_t value_len = strlen(value);

// 7-day TTL
dht_put(ctx, key, 64, value, value_len);

// Custom TTL
dht_put_ttl(ctx, key, 64, value, value_len, 30 * 24 * 3600);  // 30 days

// Signed (enables replacement)
dht_put_signed(ctx, key, 64, value, value_len, 1, 7 * 24 * 3600);
```

### Retrieve Value

```c
uint8_t *value_out;
size_t value_len_out;

if (dht_get(ctx, key, 64, &value_out, &value_len_out) == 0) {
    printf("Got: %.*s\n", (int)value_len_out, value_out);
    free(value_out);
}
```

### Cleanup

```c
dht_singleton_cleanup();
```
