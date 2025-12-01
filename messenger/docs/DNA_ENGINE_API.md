# DNA Engine API Reference

**Version:** 1.1.0
**Date:** 2025-11-27
**Location:** `include/dna/dna_engine.h`

**Changelog:**
- v1.1.0 (2025-11-27): Implemented `send_tokens` with full UTXO selection, tx building, Dilithium5 signing
- v1.0.0 (2025-11-26): Initial documentation

---

## Overview

The DNA Engine provides a unified async C API for DNA Messenger core functionality. It enables clean separation between the engine (backend) and UI layers (desktop, mobile, web).

### Key Features

- **Async operations** with callbacks (non-blocking)
- **Engine-managed threading** (4 worker threads, lock-free queue)
- **Event system** for pushed notifications
- **Post-quantum cryptography** (Kyber1024, Dilithium5)
- **Cellframe blockchain** wallet integration

### Architecture

```
┌─────────────────────────────────────────────────────────┐
│                     GUI Layer                           │
│  (ImGui Desktop / React Native / WebAssembly)           │
└─────────────────────────────────────────────────────────┘
                          │
                          ▼
┌─────────────────────────────────────────────────────────┐
│              DNA::EngineWrapper (C++)                   │
│  imgui_gui/helpers/engine_wrapper.h                     │
└─────────────────────────────────────────────────────────┘
                          │
                          ▼
┌─────────────────────────────────────────────────────────┐
│              DNA Engine API (C)                         │
│  include/dna/dna_engine.h                               │
│  - 4 worker threads (MPSC queue)                        │
│  - Request ID tracking                                  │
│  - Event dispatch system                                │
└─────────────────────────────────────────────────────────┘
                          │
                          ▼
┌─────────────────────────────────────────────────────────┐
│              Backend Services                           │
│  messenger.c │ DHT │ P2P │ crypto/ │ database/         │
└─────────────────────────────────────────────────────────┘
```

---

## Quick Start

### C Usage

```c
#include <dna/dna_engine.h>

// Callback for identity load completion
void on_identity_loaded(dna_request_id_t req_id, int error, void* user_data) {
    if (error == 0) {
        printf("Identity loaded successfully!\n");
    } else {
        printf("Error: %s\n", dna_engine_error_string(error));
    }
}

// Callback for identities list
void on_identities_listed(dna_request_id_t req_id, int error,
                          char** fingerprints, int count, void* user_data) {
    if (error == 0) {
        for (int i = 0; i < count; i++) {
            printf("Identity %d: %s\n", i, fingerprints[i]);
        }
    }
    dna_free_strings(fingerprints, count);
}

int main() {
    // Create engine (initializes DHT, starts worker threads)
    dna_engine_t* engine = dna_engine_create(NULL);  // NULL = default ~/.dna
    if (!engine) {
        fprintf(stderr, "Failed to create engine\n");
        return 1;
    }

    // List available identities
    dna_engine_list_identities(engine, on_identities_listed, NULL);

    // Load an identity (async)
    const char* fingerprint = "abc123...";  // 128 hex chars
    dna_engine_load_identity(engine, fingerprint, on_identity_loaded, NULL);

    // ... event loop here ...

    // Cleanup
    dna_engine_destroy(engine);
    return 0;
}
```

### C++ Usage (GUI)

```cpp
#include "helpers/engine_wrapper.h"

// Using the global engine singleton
void initApp() {
    // Initialize engine (called once at startup)
    if (!DNA::GetEngine().init()) {
        fprintf(stderr, "Failed to initialize engine\n");
        return;
    }

    // Async: List identities with lambda callback
    DNA::GetEngine().listIdentities([](int error, const std::vector<std::string>& fps) {
        if (error == 0) {
            for (const auto& fp : fps) {
                printf("Found identity: %s\n", fp.c_str());
            }
        }
    });

    // Async: Load identity
    DNA::GetEngine().loadIdentity("abc123...", [](int error) {
        if (error == 0) {
            printf("Identity loaded!\n");
        }
    });
}

// Synchronous usage (blocks until complete)
void syncExample() {
    // List identities synchronously (5 second timeout)
    auto identities = DNA::GetEngine().listIdentitiesSync(5000);

    if (!identities.empty()) {
        // Load first identity synchronously
        int error = DNA::GetEngine().loadIdentitySync(identities[0], 10000);
        if (error == 0) {
            printf("Loaded: %s\n", identities[0].c_str());
        }
    }
}
```

---

## API Categories

| Category | Functions | Description |
|----------|-----------|-------------|
| [Lifecycle](#1-lifecycle) | 4 | Create/destroy engine, set callbacks |
| [Identity](#2-identity) | 5 | List, create, load identities, register names |
| [Contacts](#3-contacts) | 3 | Get, add, remove contacts |
| [Messaging](#4-messaging) | 3 | Send messages, get conversations |
| [Groups](#5-groups) | 6 | Create groups, send group messages, invitations |
| [Wallet](#6-wallet) | 4 | Cellframe wallet operations |
| [P2P & Presence](#7-p2p--presence) | 7 | Online status, DHT sync |
| [Backward Compat](#8-backward-compatibility) | 2 | Access raw contexts |
| [Memory](#9-memory-management) | 8 | Free callback data |

---

## 1. Lifecycle

### dna_engine_create

```c
dna_engine_t* dna_engine_create(const char *data_dir);
```

Creates and initializes the DNA engine.

**Parameters:**
- `data_dir` - Path to data directory, or `NULL` for default `~/.dna`

**Returns:** Engine instance, or `NULL` on error

**What it does:**
1. Allocates engine structure
2. Creates data directory if needed
3. Initializes DHT singleton
4. Spawns 4 worker threads
5. Initializes lock-free task queue

**Example:**
```c
// Use default data directory
dna_engine_t* engine = dna_engine_create(NULL);

// Use custom directory
dna_engine_t* engine = dna_engine_create("/custom/path");
```

---

### dna_engine_set_event_callback

```c
void dna_engine_set_event_callback(
    dna_engine_t *engine,
    dna_event_cb callback,
    void *user_data
);
```

Sets callback for pushed events (messages received, status changes, etc.).

**Parameters:**
- `engine` - Engine instance
- `callback` - Event handler function (or `NULL` to disable)
- `user_data` - User data passed to callback

**Thread Safety:** Callback is called from engine worker thread - must be thread-safe!

**Example:**
```c
void on_event(const dna_event_t* event, void* user_data) {
    switch (event->type) {
        case DNA_EVENT_MESSAGE_RECEIVED:
            printf("New message from: %s\n",
                   event->data.message_received.message.sender);
            break;
        case DNA_EVENT_CONTACT_ONLINE:
            printf("Contact online: %s\n",
                   event->data.contact_status.fingerprint);
            break;
    }
}

dna_engine_set_event_callback(engine, on_event, NULL);
```

---

### dna_engine_destroy

```c
void dna_engine_destroy(dna_engine_t *engine);
```

Destroys engine and releases all resources.

**What it does:**
1. Stops all worker threads
2. Frees messenger context
3. Releases all allocated memory

**Note:** Does NOT call `dht_singleton_cleanup()` - DHT is global.

---

### dna_engine_get_fingerprint

```c
const char* dna_engine_get_fingerprint(dna_engine_t *engine);
```

Gets current identity fingerprint.

**Returns:** 128-char hex string, or `NULL` if no identity loaded

---

## 2. Identity

### dna_engine_list_identities

```c
dna_request_id_t dna_engine_list_identities(
    dna_engine_t *engine,
    dna_identities_cb callback,
    void *user_data
);
```

Lists available identities by scanning the engine's `data_dir` for `.dsa` key files.

**Callback signature:**
```c
typedef void (*dna_identities_cb)(
    dna_request_id_t request_id,
    int error,
    char **fingerprints,  // Array of 128-char hex strings
    int count,
    void *user_data
);
```

**Memory:** Caller must free with `dna_free_strings(fingerprints, count)`

---

### dna_engine_create_identity

```c
dna_request_id_t dna_engine_create_identity(
    dna_engine_t *engine,
    const uint8_t signing_seed[32],
    const uint8_t encryption_seed[32],
    dna_identity_created_cb callback,
    void *user_data
);
```

Creates new identity from BIP39 seeds.

**Parameters:**
- `signing_seed` - 32-byte seed for Dilithium5 keypair
- `encryption_seed` - 32-byte seed for Kyber1024 keypair

**Keys saved to:**
- `<data_dir>/<fingerprint>.dsa` (Dilithium5 signing key)
- `<data_dir>/<fingerprint>.kem` (Kyber1024 encryption key)

Where `data_dir` is the directory passed to `dna_engine_create()` (defaults to `~/.dna` on desktop).

**Example (from BIP39 mnemonic):**
```c
// Generate seeds from mnemonic
uint8_t signing_seed[32], encryption_seed[32];
bip39_mnemonic_to_seed(mnemonic, &signing_seed, &encryption_seed);

// Create identity
dna_engine_create_identity(engine, signing_seed, encryption_seed,
    [](dna_request_id_t id, int err, const char* fp, void* ud) {
        if (err == 0) {
            printf("Created identity: %s\n", fp);
        }
    }, NULL);
```

---

### dna_engine_load_identity

```c
dna_request_id_t dna_engine_load_identity(
    dna_engine_t *engine,
    const char *fingerprint,
    dna_completion_cb callback,
    void *user_data
);
```

Loads and activates an identity.

**What it does:**
1. Loads keypairs from disk
2. Initializes messenger context
3. Loads DHT identity
4. Dispatches `DNA_EVENT_IDENTITY_LOADED` event

**Example:**
```c
dna_engine_load_identity(engine, fingerprint,
    [](dna_request_id_t id, int err, void* ud) {
        if (err == 0) {
            printf("Identity loaded!\n");
        } else {
            printf("Error: %s\n", dna_engine_error_string(err));
        }
    }, NULL);
```

---

### dna_engine_register_name

```c
dna_request_id_t dna_engine_register_name(
    dna_engine_t *engine,
    const char *name,
    dna_completion_cb callback,
    void *user_data
);
```

Registers human-readable name in DHT for current identity.

**Name rules:**
- 3-20 characters
- Alphanumeric + underscore only
- Case-insensitive (stored lowercase)

---

### dna_engine_get_display_name

```c
dna_request_id_t dna_engine_get_display_name(
    dna_engine_t *engine,
    const char *fingerprint,
    dna_display_name_cb callback,
    void *user_data
);
```

Looks up display name for fingerprint (DHT lookup).

**Returns via callback:**
- Registered name if found
- Shortened fingerprint (`abc12...xyz89`) if not registered

---

## 3. Contacts

### dna_engine_get_contacts

```c
dna_request_id_t dna_engine_get_contacts(
    dna_engine_t *engine,
    dna_contacts_cb callback,
    void *user_data
);
```

Gets contact list from local database.

**Callback data structure:**
```c
typedef struct {
    char fingerprint[129];      // 128 hex chars + null
    char display_name[256];     // Registered name or shortened fingerprint
    bool is_online;             // Current online status
    uint64_t last_seen;         // Unix timestamp
} dna_contact_t;
```

**Memory:** Free with `dna_free_contacts(contacts, count)`

---

### dna_engine_add_contact

```c
dna_request_id_t dna_engine_add_contact(
    dna_engine_t *engine,
    const char *identifier,     // Fingerprint OR registered name
    dna_completion_cb callback,
    void *user_data
);
```

Adds contact by fingerprint or registered name. Looks up public keys in DHT if needed.

---

### dna_engine_remove_contact

```c
dna_request_id_t dna_engine_remove_contact(
    dna_engine_t *engine,
    const char *fingerprint,
    dna_completion_cb callback,
    void *user_data
);
```

Removes contact from database.

---

## 4. Messaging

### dna_engine_send_message

```c
dna_request_id_t dna_engine_send_message(
    dna_engine_t *engine,
    const char *recipient_fingerprint,
    const char *message,
    dna_completion_cb callback,
    void *user_data
);
```

Sends end-to-end encrypted message.

**Encryption:**
1. Generate ephemeral Kyber1024 keypair
2. Encapsulate shared secret with recipient's public key
3. Encrypt message with AES-256-GCM
4. Sign with sender's Dilithium5 key

**Delivery:**
1. Try P2P direct (if recipient online)
2. Fall back to DHT offline queue (7-day TTL)

---

### dna_engine_get_conversation

```c
dna_request_id_t dna_engine_get_conversation(
    dna_engine_t *engine,
    const char *contact_fingerprint,
    dna_messages_cb callback,
    void *user_data
);
```

Gets all messages exchanged with a contact.

**Message structure:**
```c
typedef struct {
    int id;                     // Local message ID
    char sender[129];           // Sender fingerprint
    char recipient[129];        // Recipient fingerprint
    char *plaintext;            // Decrypted message text
    uint64_t timestamp;         // Unix timestamp
    bool is_outgoing;           // true if sent by current identity
    int status;                 // 0=pending, 1=sent, 2=delivered, 3=read
    int message_type;           // 0=chat, 1=group_invitation
} dna_message_t;
```

**Memory:** Free with `dna_free_messages(messages, count)`

---

### dna_engine_check_offline_messages

```c
dna_request_id_t dna_engine_check_offline_messages(
    dna_engine_t *engine,
    dna_completion_cb callback,
    void *user_data
);
```

Force check for offline messages in DHT queue.

**Note:** Normally automatic - only use for immediate check.

---

## 5. Groups

### dna_engine_create_group

```c
dna_request_id_t dna_engine_create_group(
    dna_engine_t *engine,
    const char *name,
    const char **member_fingerprints,
    int member_count,
    dna_group_created_cb callback,
    void *user_data
);
```

Creates group with GSK (Group Symmetric Key) encryption.

**GSK Encryption:**
- 200x faster than individual PQ encryption
- Single AES-256 key shared by all members
- Key wrapped with Kyber1024 for each member

---

### dna_engine_send_group_message

```c
dna_request_id_t dna_engine_send_group_message(
    dna_engine_t *engine,
    const char *group_uuid,
    const char *message,
    dna_completion_cb callback,
    void *user_data
);
```

Sends message to group using GSK encryption.

---

### dna_engine_get_invitations / accept / reject

```c
dna_request_id_t dna_engine_get_invitations(engine, callback, user_data);
dna_request_id_t dna_engine_accept_invitation(engine, group_uuid, callback, user_data);
dna_request_id_t dna_engine_reject_invitation(engine, group_uuid, callback, user_data);
```

Manage pending group invitations.

---

## 6. Wallet

### dna_engine_list_wallets

```c
dna_request_id_t dna_engine_list_wallets(
    dna_engine_t *engine,
    dna_wallets_cb callback,
    void *user_data
);
```

Lists Cellframe wallets from `/opt/cellframe-node/var/lib/wallet`.

**Wallet structure:**
```c
typedef struct {
    char name[256];             // Wallet name
    char address[120];          // Primary address
    int sig_type;               // 0=Dilithium, 1=Picnic, 2=Bliss, 3=Tesla
    bool is_protected;          // Password protected
} dna_wallet_t;
```

---

### dna_engine_get_balances

```c
dna_request_id_t dna_engine_get_balances(
    dna_engine_t *engine,
    int wallet_index,
    dna_balances_cb callback,
    void *user_data
);
```

Gets token balances via Cellframe RPC.

**Supported tokens:** CPUNK, CELL, KEL, and others on Backbone/KelVPN networks.

---

### dna_engine_send_tokens

```c
dna_request_id_t dna_engine_send_tokens(
    dna_engine_t *engine,
    int wallet_index,
    const char *recipient_address,
    const char *amount,
    const char *token,
    const char *network,
    dna_completion_cb callback,
    void *user_data
);
```

Sends tokens via Cellframe transaction with Dilithium5 signature.

**Parameters:**
- `wallet_index` - Index of wallet in list (from `dna_engine_list_wallets`)
- `recipient_address` - Base58 Cellframe address
- `amount` - Amount as string (e.g., "1.5" for 1.5 CELL)
- `token` - Token ticker (e.g., "CELL", "CPUNK")
- `network` - Network name (e.g., "Backbone", "KelVPN")

**Implementation Details:**
1. Queries UTXOs from RPC (`cellframe_rpc_get_utxo`)
2. Builds transaction with inputs/outputs
3. Signs with wallet's Dilithium5 private key
4. Submits to mempool via RPC (`cellframe_rpc_submit_tx`)

**Fees:**
- Network fee: 0.002 CELL (fixed, goes to network collector)
- Validator fee: 0.0001 CELL (default, configurable)

**Example:**
```c
dna_engine_send_tokens(engine,
    0,                      // First wallet
    "Rj7J7MiX2bWy...",     // Recipient address
    "10.5",                 // Amount
    "CELL",                 // Token
    "Backbone",             // Network
    on_send_complete,
    NULL);

void on_send_complete(dna_request_id_t id, int error, void* ud) {
    if (error == 0) {
        printf("Transaction submitted!\n");
    } else {
        printf("Error: %s\n", dna_engine_error_string(error));
    }
}
```

**Error codes:**
- `DNA_ENGINE_ERROR_NOT_INITIALIZED` - Wallet not loaded
- `DNA_ERROR_INVALID_ARG` - Invalid address or amount
- `DNA_ERROR_NOT_FOUND` - No UTXOs available (insufficient funds)
- `DNA_ENGINE_ERROR_NETWORK` - RPC communication failed
- `DNA_ERROR_CRYPTO` - Transaction signing failed

---

## 7. P2P & Presence

### dna_engine_refresh_presence

```c
dna_request_id_t dna_engine_refresh_presence(
    dna_engine_t *engine,
    dna_completion_cb callback,
    void *user_data
);
```

Announces presence in DHT. Call periodically (~5 min) to stay visible.

---

### dna_engine_is_peer_online

```c
bool dna_engine_is_peer_online(dna_engine_t *engine, const char *fingerprint);
```

**Synchronous** check if peer is online (from presence cache).

---

### dna_engine_sync_contacts_to_dht / from_dht

```c
dna_request_id_t dna_engine_sync_contacts_to_dht(engine, callback, user_data);
dna_request_id_t dna_engine_sync_contacts_from_dht(engine, callback, user_data);
```

Sync contacts between local database and DHT for multi-device support.

---

### dna_engine_subscribe_to_contacts

```c
dna_request_id_t dna_engine_subscribe_to_contacts(
    dna_engine_t *engine,
    dna_completion_cb callback,
    void *user_data
);
```

Enables real-time push notifications via DHT listen().

---

## 8. Backward Compatibility

For gradual GUI migration from direct API calls:

```c
// Get messenger context (cast to messenger_context_t*)
void* ctx = dna_engine_get_messenger_context(engine);

// Get DHT context (cast to dht_context_t*)
void* dht = dna_engine_get_dht_context(engine);
```

**Warning:** Prefer engine API functions. These are for transitional use only.

---

## 9. Memory Management

Always free callback data:

```c
dna_free_strings(fingerprints, count);      // For identities list
dna_free_contacts(contacts, count);         // For contacts list
dna_free_messages(messages, count);         // For messages list
dna_free_groups(groups, count);             // For groups list
dna_free_invitations(invitations, count);   // For invitations list
dna_free_wallets(wallets, count);           // For wallets list
dna_free_balances(balances, count);         // For balances list
dna_free_transactions(transactions, count); // For transactions list
```

---

## Error Codes

| Code | Name | Description |
|------|------|-------------|
| 0 | `DNA_OK` | Success |
| -100 | `DNA_ENGINE_ERROR_INIT` | Initialization failed |
| -101 | `DNA_ENGINE_ERROR_NOT_INITIALIZED` | Engine not initialized |
| -102 | `DNA_ENGINE_ERROR_NETWORK` | Network error |
| -103 | `DNA_ENGINE_ERROR_DATABASE` | Database error |
| -104 | `DNA_ENGINE_ERROR_TIMEOUT` | Operation timed out |
| -105 | `DNA_ENGINE_ERROR_BUSY` | Engine busy |
| -106 | `DNA_ENGINE_ERROR_NO_IDENTITY` | No identity loaded |
| -107 | `DNA_ENGINE_ERROR_ALREADY_EXISTS` | Already exists |
| -108 | `DNA_ENGINE_ERROR_PERMISSION` | Permission denied |

Use `dna_engine_error_string(error)` for human-readable messages.

---

## Event Types

| Event | Data | Description |
|-------|------|-------------|
| `DNA_EVENT_DHT_CONNECTED` | - | DHT network connected |
| `DNA_EVENT_DHT_DISCONNECTED` | - | DHT network disconnected |
| `DNA_EVENT_MESSAGE_RECEIVED` | `message_received.message` | New message received |
| `DNA_EVENT_MESSAGE_SENT` | `message_status.*` | Message sent |
| `DNA_EVENT_MESSAGE_DELIVERED` | `message_status.*` | Message delivered |
| `DNA_EVENT_MESSAGE_READ` | `message_status.*` | Message read |
| `DNA_EVENT_CONTACT_ONLINE` | `contact_status.fingerprint` | Contact came online |
| `DNA_EVENT_CONTACT_OFFLINE` | `contact_status.fingerprint` | Contact went offline |
| `DNA_EVENT_GROUP_INVITATION_RECEIVED` | `group_invitation.*` | Group invitation |
| `DNA_EVENT_IDENTITY_LOADED` | `identity_loaded.fingerprint` | Identity loaded |
| `DNA_EVENT_ERROR` | `error.code`, `error.message` | Error occurred |

---

## Thread Safety

- All async functions are thread-safe
- Event callback is called from worker thread - **must be thread-safe**
- C++ wrapper's sync methods block the calling thread
- Request IDs are atomically generated

---

## Files

| File | Description |
|------|-------------|
| `include/dna/dna_engine.h` | Public C API header |
| `src/api/dna_engine.c` | Engine implementation |
| `src/api/dna_engine_internal.h` | Internal structures |
| `imgui_gui/helpers/engine_wrapper.h` | C++ wrapper header |
| `imgui_gui/helpers/engine_wrapper.cpp` | C++ wrapper implementation |

---

## See Also

- [ARCHITECTURE.md](ARCHITECTURE.md) - System architecture
- [MESSAGE_FORMATS.md](MESSAGE_FORMATS.md) - Wire protocol
- [GSK_IMPLEMENTATION.md](GSK_IMPLEMENTATION.md) - Group encryption
