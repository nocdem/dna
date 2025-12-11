# DHT System Documentation

**Last Updated:** 2025-12-07

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
| 0x1002 | DNA_365DAY | 365 days | Name registrations, profiles |
| 0x1003 | DNA_30DAY | 30 days | Group metadata, message walls |

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

Example usage for offline message notifications:
```c
// Listen for messages from a contact's outbox
// Callback fires when contact sends NEW message (updates their outbox)
uint8_t outbox_key[64];
dht_generate_outbox_key(contact_fp, my_fp, outbox_key);

size_t token = dht_listen(ctx, outbox_key, 64, my_callback, my_context);
if (token == 0) {
    fprintf(stderr, "Failed to start listening\n");
}

// Later, stop listening:
dht_cancel_listen(ctx, token);
```

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

Global singleton pattern for application-wide DHT access.

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
// Initialize DHT (ephemeral identity)
int dht_singleton_init(void);

// Initialize with user-provided identity
int dht_singleton_init_with_identity(dht_identity_t *user_identity);

// Get DHT context
dht_context_t* dht_singleton_get(void);

// Check if initialized
bool dht_singleton_is_initialized(void);

// Cleanup on shutdown
void dht_singleton_cleanup(void);
```

#### Initialization Flow

1. Create DHT context (memory-only, no persistence)
2. Bootstrap to seed node
3. Wait for DHT ready (polling every 100ms, max 3 seconds)
4. Query bootstrap registry
5. Filter active nodes (last_seen < 15 minutes)
6. Bootstrap to discovered nodes
7. Wait 1 second for connections to stabilize

---

### 4.2 dht_identity.h/cpp

Dilithium5 identity management for DHT operations.

```c
// Opaque identity structure (wraps dht::crypto::Identity)
typedef struct dht_identity dht_identity_t;

// Generate new Dilithium5 identity
dht_identity_t* dht_identity_generate(const char *name);

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

Self-encrypted contact list storage in DHT.

- **DHT Key**: `SHA3-512(identity + ":contactlist")`
- **TTL**: 7 days
- **Auto-republish**: Every 6 days
- **Encryption**: Self-encrypted using identity's own key

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

### 5.2 dht_offline_queue.h/c

Sender-based outbox for offline message delivery (Model E).

#### Architecture

- **Storage Key**: `SHA3-512(sender + ":outbox:" + recipient)`
- **TTL**: 7 days default
- **Put Type**: Signed with `value_id=1` (enables replacement)
- **Approach**: Each sender controls their outbox to each recipient

#### Benefits

- **No accumulation**: Signed puts replace old values (not append)
- **Spam prevention**: Recipients only query known contacts' outboxes
- **Sender control**: Senders can edit/unsend within 7-day TTL
- **Automatic retrieval**: `dna_engine_load_identity()` checks all contacts' outboxes on login
- **Periodic polling**: Background task polls DHT queue every 2 minutes (catches messages when P2P fails)

#### Message Format

```
[4-byte magic "DNA "][1-byte version][8-byte timestamp][8-byte expiry]
[2-byte sender_len][2-byte recipient_len][4-byte ciphertext_len]
[sender string][recipient string][ciphertext bytes]
```

#### API

```c
// Queue message in sender's outbox
int dht_queue_message(
    dht_context_t *ctx,
    const char *sender,           // 128-char fingerprint
    const char *recipient,        // 128-char fingerprint
    const uint8_t *ciphertext,    // Encrypted message
    size_t ciphertext_len,
    uint32_t ttl_seconds          // 0 = default 7 days
);

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

// Generate outbox key
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

Chunked storage for large GSK (Group Symmetric Key) packets.

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
    char profile_picture_ipfs[128];
    uint64_t timestamp;
    uint32_t version;
    uint8_t signature[4627];                  // Dilithium5 signature
} dna_unified_identity_t;
```

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
| Offline Messages | 7 days | `SHA3-512(sender:outbox:recipient)` | No | Model E outbox |
| Contact Lists | 7 days | `SHA3-512(identity:contactlist)` | No | Self-encrypted |
| **Contact Requests** | 7 days | `SHA3-512(fingerprint:requests)` | No | ICQ-style contact request inbox |
| **Identity** | 365 days | `SHA3-512(fingerprint:profile)` | Yes | Unified: keys + name + profile |
| **Name Lookup** | 365 days | `SHA3-512(name:lookup)` | Yes | Name → fingerprint |
| Group Metadata | 30 days | `SHA3-512(group_uuid)` | Yes | |
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
    p2p_transport_t *ctx,
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
