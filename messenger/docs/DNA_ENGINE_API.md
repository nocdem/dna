# DNA Engine API Reference

**Version:** 1.11.0
**Date:** 2026-01-22
**Location:** `include/dna/dna_engine.h`

**Changelog:**
- v1.11.0 (2026-01-22): Added centralized thread pool for parallel I/O, `dna_engine_check_offline_messages_cached()` for background polling without watermarks, removed `dna_engine_listen_all_contacts_minimal()` (replaced by polling)
- v1.10.0 (2026-01-09): Made DHT PUT synchronous for accurate status, added DNA_ENGINE_ERROR_KEY_UNAVAILABLE (-116) for offline key lookup failures
- v1.9.0 (2026-01-09): Added Bulletproof Message Delivery - `dna_engine_retry_pending_messages()` for auto-retry of failed messages on network reconnect/identity load
- v1.8.0 (2025-12-24): Added Debug Logging API (section 10) - ring buffer log storage, `dna_engine_debug_log_*()` functions for in-app log viewing on mobile
- v1.7.0 (2025-12-15): Added password protection for identity keys - `dna_engine_change_password_sync()`, password parameter in `dna_engine_load_identity()`, on-demand wallet derivation from mnemonic
- v1.6.0 (2025-12-10): Added ICQ-style Contact Request API (section 3a) - send/approve/deny requests, block/unblock users
- v1.5.0 (2025-12-10): Added `dna_engine_lookup_profile()` to lookup any user's profile by fingerprint (for wallet address resolution)
- v1.4.0 (2025-12-10): Added `dna_engine_restore_identity_sync()` for restoring identity from seed without DHT registration
- v1.3.0 (2025-12-09): Made `dna_engine_create_identity_sync()` atomic - now registers name on DHT and rolls back on failure
- v1.2.0 (2025-12-03): Added Profile API (`dna_engine_get_profile`, `dna_engine_update_profile`)
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
│  (Flutter / WebAssembly)                                │
└─────────────────────────────────────────────────────────┘
                          │
                          ▼
┌─────────────────────────────────────────────────────────┐
│              DNA Engine Dart FFI Wrapper                │
│  dna_messenger_flutter/lib/ffi/dna_engine.dart          │
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

### CLI Tool

For interactive testing without a GUI, use the `dna-messenger-cli` tool:

```bash
# Build
cd build && cmake .. && make dna-messenger-cli

# Run
./cli/dna-messenger-cli

# Commands:
> help           # Show commands
> create alice   # Create identity with BIP39 mnemonic
> list           # List identities
> load <fp>      # Load identity by fingerprint
> send <fp> msg  # Send message
> whoami         # Show current identity
> quit           # Exit
```

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
    dna_engine_t* engine = dna_engine_create(NULL);  // NULL = platform default
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
| [Profile](#2a-profile) | 2 | Get/update user profile (wallets, socials, bio, avatar) |
| [Contacts](#3-contacts) | 3 | Get, add, remove contacts |
| [Contact Requests](#3a-contact-requests) | 9 | ICQ-style contact requests, block/unblock |
| [Messaging](#4-messaging) | 3 | Send messages, get conversations |
| [Groups](#5-groups) | 6 | Create groups, send group messages, invitations |
| [Wallet](#6-wallet) | 4 | Cellframe wallet operations |
| [P2P & Presence](#7-p2p--presence) | 7 | Online status, DHT sync |
| [Backward Compat](#8-backward-compatibility) | 2 | Access raw contexts |
| [Memory](#9-memory-management) | 9 | Free callback data |

---

## 1. Lifecycle

### dna_engine_create

```c
dna_engine_t* dna_engine_create(const char *data_dir);
```

Creates and initializes the DNA engine.

**Parameters:**
- `data_dir` - Path to data directory, or `NULL` for platform default:
  - **Linux:** `~/.dna`
  - **Windows:** `%USERPROFILE%\.dna`
  - **Android/iOS:** App-specific directory (requires `qgp_platform_set_app_dirs()` first)

**Returns:** Engine instance, or `NULL` on error

**What it does:**
1. Allocates engine structure
2. Sets data directory via `qgp_platform_set_app_dirs()` (if `data_dir` is provided)
3. Creates data directory if needed
4. Initializes DHT singleton
5. Spawns 4 worker threads
6. Initializes lock-free task queue

**Example:**
```c
// Desktop: Use platform default data directory
dna_engine_t* engine = dna_engine_create(NULL);

// Mobile: Use app-specific directory
dna_engine_t* engine = dna_engine_create("/data/user/0/io.cpunk.dna_messenger/app_flutter");
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

### dna_engine_has_identity (v0.3.0+)

```c
bool dna_engine_has_identity(dna_engine_t *engine);
```

Checks if an identity exists in the flat storage structure.

**Returns:** `true` if `keys/identity.dsa` exists, `false` otherwise.

**Usage:** Use this to determine if onboarding is needed at app startup.

```c
if (dna_engine_has_identity(engine)) {
    // Auto-load identity
    dna_engine_load_identity(engine, NULL, NULL, callback, user_data);
} else {
    // Show onboarding screen
}
```

---

### dna_engine_list_identities (deprecated in v0.3.0)

```c
dna_request_id_t dna_engine_list_identities(
    dna_engine_t *engine,
    dna_identities_cb callback,
    void *user_data
);
```

> **v0.3.0:** In single-user model, this returns at most 1 identity.
> Use `dna_engine_has_identity()` instead for checking identity existence.

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

**Keys saved to (v0.3.0+ flat structure):**
- `<data_dir>/keys/identity.dsa` (Dilithium5 signing key)
- `<data_dir>/keys/identity.kem` (Kyber1024 encryption key)

Where `data_dir` is the platform-specific data directory (see `dna_engine_create()`).

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

### dna_engine_create_identity_sync

```c
int dna_engine_create_identity_sync(
    dna_engine_t *engine,
    const char *name,
    const uint8_t signing_seed[32],
    const uint8_t encryption_seed[32],
    const uint8_t master_seed[64],
    const char *mnemonic,
    char fingerprint_out[129]
);
```

**Atomic** synchronous identity creation. Creates identity keys AND registers the name on DHT in one atomic operation. If name registration fails (e.g., name already taken), the locally created keys are automatically deleted.

**Parameters:**
- `name` - Display name to register (3-20 chars, alphanumeric + underscore)
- `signing_seed` - 32-byte seed for Dilithium5 keypair
- `encryption_seed` - 32-byte seed for Kyber1024 keypair
- `master_seed` - 64-byte BIP39 master seed for multi-chain wallets (can be NULL)
- `mnemonic` - BIP39 mnemonic for Cellframe wallet creation (can be NULL)
- `fingerprint_out` - Buffer for 128-char hex fingerprint + null terminator

**Returns:**
- `DNA_OK` (0) on success
- `DNA_ERROR_INVALID_ARG` if required parameters are NULL
- `DNA_ERROR_CRYPTO` if key generation fails
- `DNA_ERROR_INTERNAL` if messenger context creation fails
- `DNA_ENGINE_ERROR_NETWORK` if name registration fails (name may be taken)

**Atomic Behavior:**
This function is atomic - if name registration fails, the identity directory is automatically removed using `qgp_platform_rmdir_recursive()`. This prevents orphaned identities that exist locally but aren't discoverable on the DHT.

**Example:**
```c
char fingerprint[129];
int rc = dna_engine_create_identity_sync(engine, "alice",
    signing_seed, encryption_seed, master_seed, mnemonic, fingerprint);
if (rc == DNA_OK) {
    printf("Identity created: %s\n", fingerprint);
} else if (rc == DNA_ENGINE_ERROR_NETWORK) {
    printf("Name 'alice' may already be taken\n");
}
```

---

### dna_engine_restore_identity_sync

```c
int dna_engine_restore_identity_sync(
    dna_engine_t *engine,
    const uint8_t signing_seed[32],
    const uint8_t encryption_seed[32],
    const uint8_t master_seed[64],
    const char *mnemonic,
    char fingerprint_out[129]
);
```

Synchronous identity restoration from BIP39 seeds. Creates keys and wallets locally **without DHT name registration**. Use this when restoring an existing identity from seed phrase - the identity's name/profile can be looked up from DHT after restore.

**Parameters:**
- `signing_seed` - 32-byte seed for Dilithium5 keypair
- `encryption_seed` - 32-byte seed for Kyber1024 keypair
- `master_seed` - 64-byte BIP39 master seed for multi-chain wallets (can be NULL)
- `mnemonic` - BIP39 mnemonic for Cellframe wallet creation (can be NULL)
- `fingerprint_out` - Buffer for 128-char hex fingerprint + null terminator

**Returns:**
- `DNA_OK` (0) on success
- `DNA_ERROR_INVALID_ARG` if required parameters are NULL
- `DNA_ERROR_CRYPTO` if key generation fails

**Example (restore flow):**
```c
char fingerprint[129];
int rc = dna_engine_restore_identity_sync(engine,
    signing_seed, encryption_seed, master_seed, mnemonic, fingerprint);
if (rc == DNA_OK) {
    printf("Identity restored: %s\n", fingerprint);
    // Now lookup name/profile from DHT using fingerprint
}
```

---

### dna_engine_load_identity

```c
dna_request_id_t dna_engine_load_identity(
    dna_engine_t *engine,
    const char *fingerprint,
    const char *password,
    dna_completion_cb callback,
    void *user_data
);
```

Loads and activates an identity.

**Parameters:**
- `engine` - Engine instance
- `fingerprint` - Identity fingerprint (128 hex chars, or prefix)
- `password` - Password for encrypted keys (NULL if keys are unencrypted)
- `callback` - Called on completion
- `user_data` - User data for callback

**What it does:**
1. Decrypts and loads keypairs from disk (using password if encrypted)
2. Stores session password in engine (for subsequent operations)
3. Initializes messenger context
4. Loads DHT identity
5. Initializes contacts database, profile cache, and profile manager
6. **Syncs contacts from DHT** (restores contact list on new device, v0.2.14+)
7. Initializes P2P transport
8. Registers presence in DHT (announces user is online)
9. Subscribes to contacts for push notifications
10. Checks for offline messages from contacts' DHT outboxes
11. Dispatches `DNA_EVENT_IDENTITY_LOADED` event

**Error Codes:**
- `DNA_ENGINE_ERROR_WRONG_PASSWORD` - Password incorrect for encrypted keys
- `DNA_ENGINE_ERROR_PASSWORD_REQUIRED` - Keys are encrypted but no password provided

**Note:** Steps 8-10 happen automatically after P2P initialization succeeds.
This ensures offline messages are retrieved without additional API calls.
Step 6 enables multi-device sync by fetching the encrypted contact list from DHT.

**Example:**
```c
// Load identity with password
dna_engine_load_identity(engine, fingerprint, "my_password",
    [](dna_request_id_t id, int err, void* ud) {
        if (err == 0) {
            printf("Identity loaded!\n");
        } else if (err == DNA_ENGINE_ERROR_WRONG_PASSWORD) {
            printf("Wrong password!\n");
        } else {
            printf("Error: %s\n", dna_engine_error_string(err));
        }
    }, NULL);

// Load identity without password (unencrypted keys)
dna_engine_load_identity(engine, fingerprint, NULL, callback, NULL);
```

---

### dna_engine_is_identity_loaded (v0.5.24+)

```c
bool dna_engine_is_identity_loaded(dna_engine_t *engine);
```

Checks if an identity is currently loaded on the engine.

**Parameters:**
- `engine` - Engine instance

**Returns:** `true` if identity is loaded, `false` otherwise

**Use Case:** Android ForegroundService checks if identity is already loaded
before attempting to load it. Part of single-owner model where Flutter and
Service never share the engine simultaneously.

---

### dna_engine_is_transport_ready (v0.5.26+)

```c
bool dna_engine_is_transport_ready(dna_engine_t *engine);
```

Checks if the transport layer is initialized. Returns false if identity was
loaded in minimal mode (DHT only, no transport).

**Parameters:**
- `engine` - Engine instance

**Returns:** `true` if transport is ready, `false` otherwise

**Use Case:** Flutter checks if transport is ready after identity load. If
identity was loaded by Android ForegroundService in minimal mode before Flutter
started, transport won't be initialized. Flutter detects this and reloads
identity in full mode to enable offline message fetching.

---

### dna_engine_load_identity_minimal (v0.5.24+, updated v0.6.15)

```c
dna_request_id_t dna_engine_load_identity_minimal(
    dna_engine_t *engine,
    const char *fingerprint,
    const char *password,
    dna_completion_cb callback,
    void *user_data
);
```

Lightweight version for background services. Initializes DHT connection and
transport for polling-based message retrieval. No listeners, no presence.

**Skips (to save resources when app is closed):**
- Presence registration and heartbeat
- DHT listeners (uses polling instead, v0.6.15+)
- Contact sync from DHT
- Pending message retry
- Wallet creation

**Parameters:**
- `engine` - Engine instance
- `fingerprint` - Identity fingerprint to load
- `password` - Password for encrypted keys (NULL if unencrypted)
- `callback` - Completion callback
- `user_data` - User data for callback

**Returns:** Request ID (0 on immediate error)

**Use Case:** Android ForegroundService uses this when the app is closed.
The service periodically calls `checkOfflineMessages()` to poll for new
messages. When messages are found, it shows a notification.

**v0.6.15 Changes:** Minimal mode now uses polling instead of DHT listeners
for better battery efficiency. Use `dna_engine_check_offline_messages_cached()`
for background polling without publishing watermarks.

---

### dna_engine_change_password_sync

```c
int dna_engine_change_password_sync(
    dna_engine_t *engine,
    const char *old_password,
    const char *new_password
);
```

Changes the password for the current identity's encrypted keys.

**Parameters:**
- `engine` - Engine instance
- `old_password` - Current password (NULL if keys are unencrypted)
- `new_password` - New password (NULL to remove encryption - not recommended)

**Returns:** 0 on success, error code on failure

**What it does:**
1. Verifies old password is correct
2. Re-encrypts `.dsa` key with new password
3. Re-encrypts `.kem` key with new password
4. Re-encrypts `mnemonic.enc` with new password
5. Updates session password in engine
6. Rolls back on failure (atomic operation)

**Error Codes:**
- `DNA_ENGINE_ERROR_WRONG_PASSWORD` - Old password is incorrect
- `DNA_ENGINE_ERROR_NO_IDENTITY` - No identity loaded
- `DNA_ERROR_CRYPTO` - Encryption/decryption failure

**Example:**
```c
// Change password
int rc = dna_engine_change_password_sync(engine, "old_password", "new_password");
if (rc == 0) {
    printf("Password changed successfully!\n");
} else if (rc == DNA_ENGINE_ERROR_WRONG_PASSWORD) {
    printf("Current password is incorrect!\n");
}

// Add password to unencrypted identity
int rc = dna_engine_change_password_sync(engine, NULL, "new_password");

// Remove password (not recommended)
int rc = dna_engine_change_password_sync(engine, "old_password", NULL);
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

## 2a. Profile

### dna_engine_get_profile

```c
dna_request_id_t dna_engine_get_profile(
    dna_engine_t *engine,
    dna_profile_cb callback,
    void *user_data
);
```

Gets current identity's profile from DHT.

**Callback signature:**
```c
typedef void (*dna_profile_cb)(
    dna_request_id_t request_id,
    int error,
    dna_profile_t *profile,
    void *user_data
);
```

**Profile structure:**
```c
typedef struct {
    /* Cellframe wallet addresses */
    char backbone[120];
    char kelvpn[120];
    char subzero[120];
    char cpunk_testnet[120];

    /* External wallet addresses */
    char btc[128];
    char eth[128];
    char sol[128];

    /* Social links */
    char telegram[128];
    char twitter[128];
    char github[128];

    /* Bio and avatar */
    char bio[512];
    char avatar_base64[20484];  /* Base64-encoded 64x64 PNG/JPEG */
} dna_profile_t;
```

**Memory:** Free with `dna_free_profile(profile)`

---

### dna_engine_lookup_profile

```c
dna_request_id_t dna_engine_lookup_profile(
    dna_engine_t *engine,
    const char *fingerprint,
    dna_profile_cb callback,
    void *user_data
);
```

Looks up any user's profile by fingerprint from DHT. Use this to resolve a DNA fingerprint to their wallet address for sending tokens.

**Parameters:**
- `engine` - Engine instance
- `fingerprint` - User's fingerprint (128 hex chars)
- `callback` - Called with profile data (NULL if not found)
- `user_data` - User data for callback

**Errors:**
- `DNA_ENGINE_ERROR_NOT_FOUND` - Profile not found in DHT
- `DNA_ENGINE_ERROR_NETWORK` - DHT lookup failed
- `DNA_ENGINE_ERROR_INVALID_PARAM` - Invalid fingerprint format

**Memory:** Free with `dna_free_profile(profile)`

---

### dna_engine_update_profile

```c
dna_request_id_t dna_engine_update_profile(
    dna_engine_t *engine,
    const dna_profile_t *profile,
    dna_completion_cb callback,
    void *user_data
);
```

Updates current identity's profile in DHT.

**Parameters:**
- `engine` - Engine instance
- `profile` - Profile data to save (wallet addresses, socials, bio, avatar)
- `callback` - Called on completion
- `user_data` - User data for callback

**What it does:**
1. Builds `dna_profile_data_t` from input
2. Loads Dilithium5 private key for signing
3. Loads Kyber1024 public key
4. Calls `dna_update_profile()` to publish to DHT

**Example:**
```c
dna_profile_t profile = {0};
strcpy(profile.backbone, "Rj7J7MiX2bWy...");
strcpy(profile.telegram, "@myusername");
strcpy(profile.bio, "Hello, I'm using DNA Messenger!");

dna_engine_update_profile(engine, &profile,
    [](dna_request_id_t id, int err, void* ud) {
        if (err == 0) {
            printf("Profile updated!\n");
        }
    }, NULL);
```

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

## 3a. Contact Requests

ICQ-style mutual contact request system. Users must approve each other before messaging.

### Data Structures

```c
typedef struct {
    char fingerprint[129];      // Requester's fingerprint (128 hex + null)
    char display_name[64];      // Requester's display name
    char message[256];          // Optional message ("Hey, add me!")
    uint64_t requested_at;      // Unix timestamp when request was sent
    int status;                 // 0=pending, 1=approved, 2=denied
} dna_contact_request_t;

typedef struct {
    char fingerprint[129];      // Blocked user's fingerprint
    uint64_t blocked_at;        // Unix timestamp when blocked
    char reason[256];           // Optional reason for blocking
} dna_blocked_user_t;
```

### Callbacks

```c
// Contact requests callback
typedef void (*dna_contact_requests_cb)(
    dna_request_id_t request_id,
    int error,
    dna_contact_request_t *requests,
    int count,
    void *user_data
);

// Blocked users callback
typedef void (*dna_blocked_users_cb)(
    dna_request_id_t request_id,
    int error,
    dna_blocked_user_t *blocked,
    int count,
    void *user_data
);
```

---

### dna_engine_send_contact_request

```c
dna_request_id_t dna_engine_send_contact_request(
    dna_engine_t *engine,
    const char *recipient_fingerprint,
    const char *message,           // Optional, can be NULL
    dna_completion_cb callback,
    void *user_data
);
```

Sends a contact request to another user via DHT. The request is signed with Dilithium5 and stored in the recipient's DHT inbox key.

---

### dna_engine_get_contact_requests

```c
dna_request_id_t dna_engine_get_contact_requests(
    dna_engine_t *engine,
    dna_contact_requests_cb callback,
    void *user_data
);
```

Gets all incoming contact requests from the local database.

**Memory:** Free with `dna_free_contact_requests(requests, count)`

---

### dna_engine_get_contact_request_count

```c
int dna_engine_get_contact_request_count(dna_engine_t *engine);
```

Returns the count of pending contact requests (synchronous).

---

### dna_engine_approve_contact_request

```c
dna_request_id_t dna_engine_approve_contact_request(
    dna_engine_t *engine,
    const char *fingerprint,
    dna_completion_cb callback,
    void *user_data
);
```

Approves a contact request. This:
1. Adds the requester as a mutual contact
2. Sends a reciprocal request so they know approval happened

---

### dna_engine_deny_contact_request

```c
dna_request_id_t dna_engine_deny_contact_request(
    dna_engine_t *engine,
    const char *fingerprint,
    dna_completion_cb callback,
    void *user_data
);
```

Denies a contact request. The requester can send another request later.

---

### dna_engine_block_user

```c
dna_request_id_t dna_engine_block_user(
    dna_engine_t *engine,
    const char *fingerprint,
    const char *reason,            // Optional, can be NULL
    dna_completion_cb callback,
    void *user_data
);
```

Permanently blocks a user. They cannot send contact requests or messages.

---

### dna_engine_unblock_user

```c
dna_request_id_t dna_engine_unblock_user(
    dna_engine_t *engine,
    const char *fingerprint,
    dna_completion_cb callback,
    void *user_data
);
```

Removes a user from the blocked list.

---

### dna_engine_get_blocked_users

```c
dna_request_id_t dna_engine_get_blocked_users(
    dna_engine_t *engine,
    dna_blocked_users_cb callback,
    void *user_data
);
```

Gets all blocked users from the local database.

**Memory:** Free with `dna_free_blocked_users(blocked, count)`

---

### dna_engine_is_user_blocked

```c
bool dna_engine_is_user_blocked(
    dna_engine_t *engine,
    const char *fingerprint
);
```

Checks if a user is blocked (synchronous).

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

### dna_engine_queue_message

```c
int dna_engine_queue_message(
    dna_engine_t *engine,
    const char *recipient_fingerprint,
    const char *message
);
```

Queues message for async sending (returns immediately).

Adds message to internal send queue for background delivery via worker threads.
Use this for fire-and-forget messaging with optimistic UI patterns.

**Parameters:**
- `engine` - Engine instance
- `recipient_fingerprint` - Recipient fingerprint
- `message` - Message text

**Returns:**
- `>= 0` - Queue slot ID (success)
- `-1` - Queue full
- `-2` - Invalid args or not initialized

**Usage (Optimistic UI):**
```c
// Add message to UI immediately with "pending" status
// Then queue for background send
int slot = dna_engine_queue_message(engine, recipient, text);
if (slot < 0) {
    // Handle error (remove from UI, show notification)
}
// Worker thread sends message, clears queue slot when done
```

---

### dna_engine_get_message_queue_capacity

```c
int dna_engine_get_message_queue_capacity(dna_engine_t *engine);
```

Returns maximum number of messages that can be queued (default: 20).

---

### dna_engine_get_message_queue_size

```c
int dna_engine_get_message_queue_size(dna_engine_t *engine);
```

Returns number of messages currently in queue.

---

### dna_engine_set_message_queue_capacity

```c
int dna_engine_set_message_queue_capacity(dna_engine_t *engine, int capacity);
```

Sets message queue capacity (1-100).

**Parameters:**
- `engine` - Engine instance
- `capacity` - New capacity (1-100)

**Returns:** 0 on success, -1 on invalid capacity or if shrinking below current size.

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

Force check for offline messages in DHT queue (Spillway Protocol: queries contacts' outboxes).
Publishes watermarks to senders indicating messages have been received.

**Note:** Called automatically by `dna_engine_load_identity()` on startup.
Use this only for manual refresh (e.g., pull-to-refresh in UI).

---

### dna_engine_check_offline_messages_cached (v0.6.15+)

```c
dna_request_id_t dna_engine_check_offline_messages_cached(
    dna_engine_t *engine,
    dna_completion_cb callback,
    void *user_data
);
```

Check for offline messages without publishing watermarks. Messages are cached
locally but senders are NOT notified that messages were received.

**Use Case:** Android ForegroundService background polling. Messages are cached
for notification display, but watermarks are only published when the user
actually opens the app and views messages. This prevents incorrectly marking
messages as "delivered" when the user hasn't actually read them.

**Parameters:**
- `engine` - Engine instance
- `callback` - Completion callback
- `user_data` - User data for callback

**Returns:** Request ID (0 on immediate error)

---

### dna_engine_retry_pending_messages

```c
int dna_engine_retry_pending_messages(dna_engine_t *engine);
```

Retry all pending/failed messages (bulletproof delivery).

Queries the message database for all outgoing messages with status PENDING (0) or FAILED (2) and `retry_count < 10`, then attempts to re-queue each to DHT.

**Automatic Triggers:**
- Identity load (app startup)
- DHT reconnect (network restored)
- Network state change (WiFi/mobile switch)

**Returns:**
- Number of messages successfully retried (>= 0)
- `-1` on error

**Retry Logic:**
```c
// Pseudocode
for each message in pending_messages:
    if (dht_queue(message) == success):
        message.status = SENT
        retried_count++
    else:
        message.retry_count++
        // Stays FAILED, will retry on next trigger
```

**Max Retries:** 10 attempts per message. After 10 failures, message remains FAILED and requires manual retry via UI.

**Source:** `src/api/dna_engine.c:4862-4920`, `message_backup.c:644-721`

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

Creates group with GEK (Group Symmetric Key) encryption.

**GEK Encryption:**
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

Sends message to group using GEK encryption.

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
dna_free_profile(profile);                  // For profile
```

---

## 10. Debug Logging API

In-app debug log viewer for mobile debugging (no terminal access on Android).

### Enable/Disable Ring Buffer

```c
// Enable debug log capture (ring buffer stores last 200 entries)
void dna_engine_debug_log_enable(bool enabled);

// Check if debug logging is enabled
bool dna_engine_debug_log_is_enabled(void);
```

### Log Entry Structure

```c
typedef struct {
    uint64_t timestamp_ms;  // Unix timestamp in milliseconds
    int level;              // 0=DEBUG, 1=INFO, 2=WARN, 3=ERROR
    char tag[32];           // Module/tag name
    char message[256];      // Log message
} dna_debug_log_entry_t;
```

### Retrieve Log Entries

```c
// Get all log entries (up to max_entries)
// Returns: number of entries written to array
int dna_engine_debug_log_get_entries(dna_debug_log_entry_t *entries, int max_entries);

// Get current entry count
int dna_engine_debug_log_count(void);

// Clear all entries
void dna_engine_debug_log_clear(void);
```

### Usage (Flutter)

```dart
// Enable debug logging
engine.debugLogEnable(true);

// Get entries
final entries = engine.debugLogGetEntries();
for (final entry in entries) {
  print('[${entry.levelString}] ${entry.tag}: ${entry.message}');
}

// Clear logs
engine.debugLogClear();
```

**Note:** Ring buffer is thread-safe. Logs are automatically captured when enabled.

---

## Error Codes

| Code | Name | Description |
|------|------|-------------|
| 0 | `DNA_OK` | Success |
| -100 | `DNA_ENGINE_ERROR_INIT` | Initialization failed |
| -101 | `DNA_ENGINE_ERROR_NOT_INITIALIZED` | Engine not initialized |
| -102 | `DNA_ENGINE_ERROR_NETWORK` | Network error |
| -103 | `DNA_ENGINE_ERROR_DATABASE` | Database error |
| -106 | `DNA_ENGINE_ERROR_NO_IDENTITY` | No identity loaded |
| -107 | `DNA_ENGINE_ERROR_ALREADY_EXISTS` | Already exists |
| -108 | `DNA_ENGINE_ERROR_PERMISSION` | Permission denied |
| -116 | `DNA_ENGINE_ERROR_KEY_UNAVAILABLE` | Recipient public key not cached and DHT lookup failed (offline) |

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
| `DNA_EVENT_CONTACT_REQUEST_RECEIVED` | `contact_request.*` | New contact request |
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
| `dna_messenger_flutter/lib/ffi/dna_engine.dart` | Flutter FFI wrapper |
| `dna_messenger_flutter/lib/ffi/dna_bindings.dart` | Generated FFI bindings |

---

## See Also

- [ARCHITECTURE.md](ARCHITECTURE.md) - System architecture
- [MESSAGE_FORMATS.md](MESSAGE_FORMATS.md) - Wire protocol
- [GEK_IMPLEMENTATION.md](GEK_IMPLEMENTATION.md) - Group encryption
