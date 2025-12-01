# DNA Messenger - Comprehensive Architecture Documentation

**Version:** 0.1.x | **Last Updated:** 2025-11-26 | **Phase:** 13 (GSK v0.09)

This document provides a complete technical architecture reference for DNA Messenger, derived entirely from source code analysis.

---

## Table of Contents

1. [Executive Summary](#1-executive-summary)
2. [Directory Structure](#2-directory-structure)
3. [Build System](#3-build-system)
4. [Cryptographic Layer](#4-cryptographic-layer)
5. [DHT Layer](#5-dht-layer)
6. [P2P Transport Layer](#6-p2p-transport-layer)
7. [Messaging Core](#7-messaging-core)
8. [Database Layer](#8-database-layer)
9. [Blockchain Integration](#9-blockchain-integration)
10. [Public API](#10-public-api)
11. [GUI Application](#11-gui-application)
12. [Data Flow Diagrams](#12-data-flow-diagrams)
13. [Security Architecture](#13-security-architecture)
14. [Deployment](#14-deployment)

---

## 1. Executive Summary

### Overview

DNA Messenger is a post-quantum end-to-end encrypted messenger with integrated cryptocurrency wallet functionality. The system achieves **NIST Category 5 security** (256-bit quantum security level) using lattice-based cryptography.

### Technology Stack

| Layer | Technology |
|-------|------------|
| **Key Encapsulation** | Kyber1024 (ML-KEM-1024) |
| **Digital Signatures** | Dilithium5 (ML-DSA-87) |
| **Symmetric Encryption** | AES-256-GCM |
| **Hash Function** | SHA3-512 |
| **DHT Network** | OpenDHT-PQ (post-quantum modified) |
| **NAT Traversal** | libjuice (ICE/STUN) |
| **Local Storage** | SQLite3 |
| **GUI Framework** | ImGui (OpenGL3 + GLFW3) |
| **Blockchain** | Cellframe (cpunk wallet) |

### Security Model

```
┌─────────────────────────────────────────────────────────────────┐
│                     NIST Category 5 Security                     │
│                    (256-bit quantum security)                    │
├─────────────────────────────────────────────────────────────────┤
│  Kyber1024 (KEM)          │  Dilithium5 (DSA)                   │
│  - Session key exchange   │  - Message signing                  │
│  - 1568B public key       │  - Identity authentication          │
│  - 3168B private key      │  - 2592B public key                 │
│  - 1568B ciphertext       │  - 4896B private key                │
│  - 32B shared secret      │  - 4627B signature                  │
├─────────────────────────────────────────────────────────────────┤
│  AES-256-GCM              │  SHA3-512                           │
│  - Message encryption     │  - Fingerprint computation          │
│  - Authenticated          │  - DHT key derivation               │
│  - 256-bit key            │  - 512-bit output                   │
└─────────────────────────────────────────────────────────────────┘
```

### Key Features

- **E2E Encryption**: Per-message Kyber1024 encapsulation + AES-256-GCM
- **GSK Groups**: Group Symmetric Key for 200x faster group encryption
- **DHT-based**: Decentralized key storage, presence, offline queuing
- **P2P Messaging**: Direct TCP with DHT fallback
- **Fingerprint Identity**: SHA3-512(Dilithium_pubkey) = 128 hex chars
- **BIP39 Recovery**: Deterministic key generation from mnemonic
- **Offline Queue**: 7-day TTL for messages to offline recipients
- **cpunk Wallet**: Cellframe blockchain integration

---

## 2. Directory Structure

### Top-Level Layout

```
/opt/dna-messenger/
│
├── include/dna/              # Public API headers
│   └── dna_engine.h          # Unified async engine API (v1.0.0)
│
├── src/api/                  # Internal API implementation
│   └── dna_engine.c          # Engine implementation
│
├── crypto/                   # Post-quantum cryptography
│   ├── kem/                  # Kyber1024 (ML-KEM-1024)
│   ├── dsa/                  # Dilithium5 (ML-DSA-87)
│   ├── cellframe_dilithium/  # Cellframe-compatible DSA
│   ├── bip39/                # BIP39 mnemonic/seed
│   └── utils/                # AES, SHA3, random, keys
│
├── dht/                      # Distributed Hash Table
│   ├── core/                 # DHT context, keyserver, bootstrap
│   ├── client/               # Identity, profile, wall, contacts
│   ├── keyserver/            # Public key storage
│   └── shared/               # Groups, offline queue, GSK storage
│
├── p2p/                      # Peer-to-peer transport
│   └── transport/            # TCP connections, ICE/NAT
│
├── messenger/                # Messaging core
│   ├── identity.c            # Identity management
│   ├── keys.c                # Key operations
│   ├── messages.c            # Message handling
│   ├── contacts.c            # Contact management
│   ├── gsk.c                 # Group Symmetric Key
│   └── gsk_packet.c          # GSK packet builder
│
├── database/                 # SQLite persistence
│   ├── contacts_db.c/h       # Per-identity contacts
│   ├── keyserver_cache.c/h   # Key cache (7-day TTL)
│   ├── profile_cache.c/h     # Profile cache (7-day TTL)
│   ├── profile_manager.c/h   # Smart profile fetching
│   ├── presence_cache.c/h    # Online status cache
│   ├── group_invitations.c/h # Invitation tracking
│   └── cache_manager.c/h     # Unified cache lifecycle
│
├── blockchain/               # Cellframe wallet
│   ├── wallet.c/h            # Wallet management
│   ├── blockchain_rpc.c/h    # RPC client
│   ├── blockchain_addr.c/h   # Address utilities
│   ├── blockchain_tx_builder_minimal.c/h
│   └── blockchain_sign_minimal.c/h
│
├── imgui_gui/                # GUI application
│   ├── main.cpp              # Entry point
│   ├── app.cpp/h             # Application logic
│   ├── core/                 # AppState, engine wrapper
│   ├── screens/              # UI screens/dialogs
│   ├── helpers/              # DataLoader, async tasks
│   └── vendor/               # ImGui, qrcodegen
│
├── vendor/                   # Third-party libraries
│   ├── opendht-pq/           # OpenDHT with Dilithium5
│   └── nativefiledialog-extended/
│
├── bootstrap/                # Bootstrap server
├── tests/                    # Unit tests
├── win32/                    # Windows compatibility
│
├── messenger.c/h             # Messenger facade
├── messenger_p2p.c/h         # P2P integration
├── message_backup.c/h        # SQLite message storage
├── dna_api.c/h               # Core DNA API
├── dna_config.c/h            # Configuration
│
├── CMakeLists.txt            # Build configuration
├── build-cross-compile.sh    # Windows cross-compile
└── push_both.sh              # Dual-repo push script
```

### Module Organization Philosophy

1. **Layered Architecture**: Public API → Engine → Core Modules → Crypto/Network
2. **Per-Identity Databases**: Each identity has isolated storage
3. **Modular Messenger**: Components in `messenger/` with facade pattern
4. **Vendor Isolation**: Third-party code in `vendor/` subdirectories
5. **Platform Abstraction**: `win32/` for Windows, `crypto/utils/qgp_platform_*.c`

---

## 3. Build System

### CMake Targets

```cmake
# Main library
dna_lib (STATIC)          # Core DNA Messenger library

# Support libraries
cellframe_minimal (STATIC) # Blockchain transaction building
kem (STATIC)              # Kyber1024 implementation
dsa (STATIC)              # Dilithium5 implementation
dht_lib (STATIC)          # DHT integration
p2p_transport (STATIC)    # P2P layer

# Executables
dna-messenger             # GUI application (imgui_gui/)

# Vendor
opendht (STATIC)          # OpenDHT-PQ
libjuice (EXTERNAL)       # NAT traversal (v1.7.0)
```

### Build Options

```cmake
-DBUILD_GUI=ON            # Build ImGui GUI (default: ON)
-DBUILD_TESTS=ON          # Build unit tests (default: ON)
-DBUILD_DNA_SEND=OFF      # CLI send tool (default: OFF)
-DCMAKE_BUILD_TYPE=Release # Release/Debug
```

### Dependencies

| Library | Purpose | Link Type |
|---------|---------|-----------|
| OpenSSL | AES-256, SHA256, random | System |
| CURL | Blockchain RPC | System |
| SQLite3 | Local storage | System |
| json-c | JSON parsing | System |
| libjuice | ICE/STUN NAT traversal | Vendored |
| OpenDHT-PQ | DHT with Dilithium5 | Vendored |
| ImGui | GUI framework | Vendored |
| GLFW3 | Window management | System |
| FreeType | Font rendering | System |

### Cross-Compilation (Windows)

```bash
./build-cross-compile.sh windows-x64
```

Uses MinGW with static linking for all dependencies.

---

## 4. Cryptographic Layer

### 4.1 Kyber1024 (ML-KEM-1024)

**Location:** `crypto/kem/`

**Parameters** (from `params.h`):
```c
KYBER_K = 4                    // Security parameter
KYBER_N = 256                  // Polynomial degree
KYBER_Q = 3329                 // Modulus

KYBER_PUBLICKEYBYTES  = 1568   // Public key size
KYBER_SECRETKEYBYTES  = 3168   // Private key size
KYBER_CIPHERTEXTBYTES = 1568   // Ciphertext size
KYBER_SSBYTES         = 32     // Shared secret size
```

**API** (`kem.h`):
```c
int crypto_kem_keypair(uint8_t *pk, uint8_t *sk);
int crypto_kem_enc(uint8_t *ct, uint8_t *ss, const uint8_t *pk);
int crypto_kem_dec(uint8_t *ss, const uint8_t *ct, const uint8_t *sk);
```

**Usage**: Per-message session key encapsulation. Each message generates a fresh shared secret.

### 4.2 Dilithium5 (ML-DSA-87)

**Location:** `crypto/dsa/`

**Parameters** (from `params.h`):
```c
DILITHIUM_MODE = 5             // Category 5 security
K = 8, L = 7                   // Matrix dimensions
ETA = 2                        // Noise parameter
GAMMA1 = (1 << 19)             // Challenge bound
GAMMA2 = (Q-1)/32              // Hint bound

CRYPTO_PUBLICKEYBYTES = 2592   // Public key size
CRYPTO_SECRETKEYBYTES = 4896   // Private key size
CRYPTO_BYTES          = 4627   // Signature size
```

**API** (`sign.h`):
```c
int crypto_sign_keypair(uint8_t *pk, uint8_t *sk);
int crypto_sign_signature(uint8_t *sig, size_t *siglen,
                          const uint8_t *m, size_t mlen,
                          const uint8_t *ctx, size_t ctxlen,
                          const uint8_t *sk);
int crypto_sign_verify(const uint8_t *sig, size_t siglen,
                       const uint8_t *m, size_t mlen,
                       const uint8_t *ctx, size_t ctxlen,
                       const uint8_t *pk);
```

**Usage**: Message signing, identity authentication, DHT value signing.

### 4.3 AES-256-GCM

**Location:** `crypto/utils/qgp_aes.c`

**Key Size:** 256 bits (32 bytes)
**Nonce Size:** 96 bits (12 bytes)
**Tag Size:** 128 bits (16 bytes)

**Usage**: Symmetric encryption of message payloads after Kyber key exchange.

### 4.4 SHA3-512

**Location:** `crypto/utils/qgp_sha3.c`

**Output Size:** 512 bits (64 bytes) = 128 hex characters

**Usage**:
- Fingerprint computation: `SHA3-512(Dilithium_pubkey)`
- DHT key derivation: `SHA3-512(fingerprint + ":profile")`

### 4.5 BIP39 Seed Derivation

**Location:** `crypto/bip39/`

**Files:**
- `bip39.c` - Mnemonic generation/validation
- `bip39_pbkdf2.c` - Seed derivation
- `seed_derivation.c` - Mnemonic to keypair

**Process:**
```
24-word mnemonic + optional passphrase
           ↓
    PBKDF2-SHA512 (2048 rounds)
           ↓
      512-bit seed
           ↓
   Split into two 256-bit seeds
           ↓
   ┌───────┴───────┐
   ↓               ↓
Signing Seed   Encryption Seed
   ↓               ↓
Dilithium5    Kyber1024
```

### Key Storage

**Location:** `~/.dna/`

| File | Contents |
|------|----------|
| `<fingerprint>.dsa` | Dilithium5 private key (4896 bytes) |
| `<fingerprint>.kem` | Kyber1024 private key (3168 bytes) |

---

## 5. DHT Layer

### 5.1 DHT Context

**Location:** `dht/core/dht_context.h`

**Configuration:**
```c
typedef struct {
    uint16_t port;                    // UDP 4000 (default)
    bool is_bootstrap;                // Bootstrap node flag
    char identity[256];               // Node identity
    char bootstrap_nodes[5][256];     // Up to 5 bootstrap nodes
    size_t bootstrap_count;
    char persistence_path[512];       // SQLite persistence
} dht_config_t;
```

**Operations:**
```c
// Lifecycle
dht_context_t* dht_context_new(const dht_config_t *config);
int dht_context_start(dht_context_t *ctx);
void dht_context_stop(dht_context_t *ctx);
void dht_context_free(dht_context_t *ctx);

// Put operations
int dht_put(ctx, key, key_len, value, value_len);           // 7-day TTL
int dht_put_ttl(ctx, key, key_len, value, value_len, ttl);  // Custom TTL
int dht_put_permanent(ctx, key, key_len, value, value_len); // Never expires
int dht_put_signed(ctx, key, key_len, value, value_len,
                   value_id, ttl);                           // Signed, replaceable

// Get operations
int dht_get(ctx, key, key_len, value_out, value_len_out);   // First value
int dht_get_all(ctx, key, key_len, values_out, lens_out, count_out);
void dht_get_async(ctx, key, key_len, callback, userdata);  // Non-blocking
```

**Value TTLs:**
- **Permanent**: Identity keys, contact lists (never expire)
- **365 days**: Name registrations
- **7 days**: Profiles, groups, offline queue (default)

### 5.2 DHT Keyserver

**Location:** `dht/core/dht_keyserver.h`

**Key Format:** `SHA3-512(fingerprint + ":profile")` → 128 hex chars

**Public Key Entry:**
```c
typedef struct {
    char identity[256];
    uint8_t dilithium_pubkey[2592];   // Dilithium5 public key
    uint8_t kyber_pubkey[1568];       // Kyber1024 public key
    uint64_t timestamp;               // Unix timestamp
    uint32_t version;                 // Version number
    char fingerprint[129];            // SHA3-512 hex
    uint8_t signature[4627];          // Self-signature
} dht_pubkey_entry_t;
```

**Operations:**
```c
// Publish keys
int dht_keyserver_publish(dht_ctx, fingerprint, display_name,
                          dilithium_pubkey, kyber_pubkey, dilithium_privkey);

// Lookup (supports fingerprint or name)
int dht_keyserver_lookup(dht_ctx, identity_or_fingerprint, entry_out);

// Reverse lookup (fingerprint → name)
int dht_keyserver_reverse_lookup(dht_ctx, fingerprint, identity_out);
void dht_keyserver_reverse_lookup_async(dht_ctx, fingerprint, callback, userdata);
```

### 5.3 DNA Name System

**Location:** `dht/core/dht_keyserver.h`

**Name Rules:**
- Length: 3-36 characters
- Characters: alphanumeric + `.` `_` `-`
- Cost: 0.01 CPUNK (blockchain tx required)
- TTL: 365 days (renewable)

**Operations:**
```c
// Compute fingerprint from public key
void dna_compute_fingerprint(const uint8_t *dilithium_pubkey, char *fingerprint_out);

// Register name (requires blockchain tx proof)
int dna_register_name(dht_ctx, fingerprint, name, tx_hash, network, dilithium_privkey);

// Lookup by name
int dna_lookup_by_name(dht_ctx, name, fingerprint_out);

// Get display name (name or shortened fingerprint)
int dna_get_display_name(dht_ctx, fingerprint, display_name_out);

// Resolve name to wallet address
int dna_resolve_address(dht_ctx, name, network, address_out);

// Update profile data
int dna_update_profile(dht_ctx, fingerprint, profile, dilithium_privkey,
                       dilithium_pubkey, kyber_pubkey);
```

### 5.4 Bootstrap Nodes

**Production Servers:**
```
US-1: 154.38.182.161:4000
EU-1: 164.68.105.227:4000
EU-2: 164.68.116.180:4000
```

**Runtime Bootstrap:**
```c
int dht_context_bootstrap_runtime(dht_context_t *ctx, const char *ip, uint16_t port);
```

---

## 6. P2P Transport Layer

### 6.1 Architecture

**Location:** `p2p/p2p_transport.h`

```
┌─────────────────────────────────────────────────────────────────┐
│                      P2P Transport Layer                        │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  ┌─────────────┐      ┌─────────────┐      ┌─────────────┐     │
│  │  DHT-based  │      │    TCP      │      │   Offline   │     │
│  │  Discovery  │ ──── │ Connections │ ──── │   Queue     │     │
│  │  (UDP 4000) │      │ (TCP 4001)  │      │  (DHT TTL)  │     │
│  └─────────────┘      └─────────────┘      └─────────────┘     │
│                                                                 │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │                  libjuice (ICE/STUN)                     │   │
│  │              NAT Traversal & Hole Punching               │   │
│  └─────────────────────────────────────────────────────────┘   │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

**Port Usage:**
- **UDP 4000**: DHT network
- **TCP 4001**: P2P messaging

### 6.2 Configuration

```c
typedef struct {
    uint16_t listen_port;           // TCP 4001 (default)
    uint16_t dht_port;              // UDP 4000 (default)
    char bootstrap_nodes[5][256];   // DHT bootstrap addresses
    size_t bootstrap_count;
    char identity[256];
    bool enable_offline_queue;      // DHT fallback
    uint32_t offline_ttl_seconds;   // 7 days (default)
} p2p_config_t;
```

### 6.3 Peer Information

```c
typedef struct {
    char ip[64];                    // IPv4 or IPv6
    uint16_t port;                  // TCP port
    uint64_t last_seen;             // Unix timestamp
    uint8_t public_key[2592];       // Dilithium5 public key
    bool is_online;
} peer_info_t;
```

### 6.4 Core Operations

```c
// Initialize with cryptographic keys
p2p_transport_t* p2p_transport_init(
    const p2p_config_t *config,
    const uint8_t *my_privkey_dilithium,    // 4896 bytes
    const uint8_t *my_pubkey_dilithium,     // 2592 bytes
    const uint8_t *my_kyber_key,            // 3168 bytes
    p2p_message_callback_t message_callback,
    p2p_connection_callback_t connection_callback,
    void *callback_user_data
);

// Lifecycle
int p2p_transport_start(p2p_transport_t *ctx);
void p2p_transport_stop(p2p_transport_t *ctx);
void p2p_transport_free(p2p_transport_t *ctx);

// Discovery
int p2p_register_presence(p2p_transport_t *ctx);  // Periodic (5-10 min)
int p2p_lookup_peer(p2p_transport_t *ctx, const uint8_t *peer_pubkey, peer_info_t *out);

// Messaging
int p2p_send_message(p2p_transport_t *ctx, const uint8_t *peer_pubkey,
                     const uint8_t *message, size_t message_len);
int p2p_check_offline_messages(p2p_transport_t *ctx, size_t *messages_received);
int p2p_queue_offline_message(p2p_transport_t *ctx, const char *sender,
                              const char *recipient, const uint8_t *message, size_t len);

// Connection management
int p2p_get_connected_peers(p2p_transport_t *ctx, uint8_t (*pubkeys)[2592],
                            size_t max_peers, size_t *count);
int p2p_disconnect_peer(p2p_transport_t *ctx, const uint8_t *peer_pubkey);
```

### 6.5 Message Flow

```
Sender                                                    Recipient
   │                                                          │
   │  1. Encrypt (Kyber1024 + AES-256-GCM)                   │
   │  2. Sign (Dilithium5)                                   │
   │                                                          │
   ├──────────────────── TCP 4001 ────────────────────────────┤
   │                     (if online)                          │
   │                                                          │
   │  ─ OR ─                                                  │
   │                                                          │
   ├──────────────────── DHT Queue ───────────────────────────┤
   │                   (7-day TTL)                            │
   │                                                          │
   │                                                   Poll   │
   │                                              (1-5 min)   │
```

---

## 7. Messaging Core

### 7.1 Messenger Context

**Location:** `messenger.h`

```c
typedef struct {
    char *identity;                      // User identity
    char *fingerprint;                   // SHA3-512 (128 hex)
    message_backup_context_t *backup_ctx; // SQLite messages
    dna_context_t *dna_ctx;              // DNA API context
    p2p_transport_t *p2p_transport;      // P2P layer
    bool p2p_enabled;

    // Public key cache
    pubkey_cache_entry_t cache[100];
    int cache_count;
} messenger_context_t;
```

### 7.2 Message Info

```c
typedef struct {
    int id;
    char *sender;
    char *recipient;
    char *timestamp;
    char *status;           // "sent", "delivered", "read"
    char *delivered_at;
    char *read_at;
    char *plaintext;        // Decrypted text
    int message_type;       // 0=chat, 1=group_invitation
} message_info_t;
```

### 7.3 Key Operations

**Location:** `messenger/keys.c`

```c
// Store keys in DHT keyserver
int messenger_store_pubkey(ctx, fingerprint, display_name,
                           signing_pubkey, signing_pubkey_len,
                           encryption_pubkey, encryption_pubkey_len);

// Load keys (cache → DHT)
int messenger_load_pubkey(ctx, identity,
                          signing_pubkey_out, signing_pubkey_len_out,
                          encryption_pubkey_out, encryption_pubkey_len_out,
                          fingerprint_out);

// Contact list
int messenger_get_contact_list(ctx, identities_out, count_out);

// DHT sync
int messenger_sync_contacts_to_dht(ctx);
int messenger_sync_contacts_from_dht(ctx);
```

### 7.4 Message Operations

**Location:** `messenger/messages.c`

```c
// Send message (multi-recipient support)
int messenger_send_message(ctx, recipients, recipient_count, message,
                           group_id, message_type);

// List messages
int messenger_list_messages(ctx);
int messenger_list_sent_messages(ctx);

// Read/decrypt
int messenger_read_message(ctx, message_id);
int messenger_decrypt_message(ctx, message_id, plaintext_out, plaintext_len_out);

// Conversation
int messenger_show_conversation(ctx, other_identity);
int messenger_get_conversation(ctx, other_identity, messages_out, count_out);

// Status
int messenger_mark_delivered(ctx, message_id);
int messenger_mark_conversation_read(ctx, sender_identity);
```

### 7.5 Group Symmetric Key (GSK)

**Location:** `messenger/gsk.h`

**Purpose:** 200x faster group encryption than per-member Kyber encapsulation.

**Parameters:**
```c
#define GSK_KEY_SIZE 32            // AES-256 (32 bytes)
#define GSK_DEFAULT_EXPIRY (7 * 24 * 3600)  // 7 days
```

**GSK Entry:**
```c
typedef struct {
    char group_uuid[37];       // UUID v4
    uint32_t gsk_version;      // Rotation counter
    uint8_t gsk[32];           // AES-256 key
    uint64_t created_at;
    uint64_t expires_at;
} gsk_entry_t;
```

**Operations:**
```c
int gsk_init(void *backup_ctx);
int gsk_generate(const char *group_uuid, uint32_t version, uint8_t gsk_out[32]);
int gsk_store(const char *group_uuid, uint32_t version, const uint8_t gsk[32]);
int gsk_load(const char *group_uuid, uint32_t version, uint8_t gsk_out[32]);
int gsk_load_active(const char *group_uuid, uint8_t gsk_out[32], uint32_t *version_out);
int gsk_rotate(const char *group_uuid, uint32_t *new_version_out, uint8_t new_gsk_out[32]);
int gsk_get_current_version(const char *group_uuid, uint32_t *version_out);
int gsk_cleanup_expired(void);

// Automatic rotation on membership changes
int gsk_rotate_on_member_add(void *dht_ctx, const char *group_uuid, const char *owner);
int gsk_rotate_on_member_remove(void *dht_ctx, const char *group_uuid, const char *owner);
```

### 7.6 Group Management

```c
typedef struct {
    int id;
    char *name;
    char *description;
    char *creator;
    char *created_at;
    int member_count;
} group_info_t;

int messenger_create_group(ctx, name, description, members, member_count, group_id_out);
int messenger_get_groups(ctx, groups_out, count_out);
int messenger_get_group_info(ctx, group_id, group_out);
int messenger_get_group_members(ctx, group_id, members_out, count_out);
int messenger_add_group_member(ctx, group_id, member);
int messenger_remove_group_member(ctx, group_id, member);
int messenger_leave_group(ctx, group_id);
int messenger_delete_group(ctx, group_id);
int messenger_send_group_message(ctx, group_uuid, message);
int messenger_send_group_invitation(ctx, group_uuid, recipient, group_name, member_count);
int messenger_accept_group_invitation(ctx, group_uuid);
int messenger_reject_group_invitation(ctx, group_uuid);
```

---

## 8. Database Layer

### 8.1 Storage Architecture

**Location:** `~/.dna/`

```
~/.dna/
├── messages.db                        # All messages (encrypted)
├── <fingerprint>.dsa                  # Dilithium5 private key
├── <fingerprint>.kem                  # Kyber1024 private key
├── <fingerprint>_contacts.db          # Per-identity contacts
├── <fingerprint>_profiles.db          # Profile cache (7-day TTL)
├── <fingerprint>_keyserver.db         # Public key cache (7-day TTL)
├── <fingerprint>_groups.db            # Group GSK storage
└── <fingerprint>_invitations.db       # Pending invitations
```

### 8.2 Message Backup

**Location:** `message_backup.h`

```c
typedef struct {
    int id;
    char sender[256];
    char recipient[256];
    uint8_t *encrypted_message;    // Stored encrypted
    size_t encrypted_len;
    time_t timestamp;
    bool delivered;
    bool read;
    int status;                    // 0=PENDING, 1=SENT, 2=FAILED
    int group_id;                  // 0 for direct, >0 for group
    int message_type;              // 0=chat, 1=group_invitation
    int invitation_status;         // 0=pending, 1=accepted, 2=declined
} backup_message_t;

message_backup_context_t* message_backup_init(const char *identity);
int message_backup_save(ctx, sender, recipient, encrypted_msg, len,
                        timestamp, is_outgoing, group_id, message_type);
int message_backup_get_conversation(ctx, contact, messages_out, count_out);
int message_backup_get_group_conversation(ctx, group_id, messages_out, count_out);
int message_backup_update_status(ctx, message_id, status);
int message_backup_mark_delivered(ctx, message_id);
int message_backup_mark_read(ctx, message_id);
int message_backup_export_json(ctx, output_path);
```

### 8.3 Contacts Database

**Location:** `database/contacts_db.h`

**Schema:**
```sql
CREATE TABLE contacts (
    identity TEXT PRIMARY KEY,
    added_timestamp INTEGER,
    notes TEXT
);
```

```c
typedef struct {
    char identity[256];
    uint64_t added_timestamp;
    char notes[512];
} contact_entry_t;

int contacts_db_init(const char *owner_identity);
int contacts_db_add(const char *identity, const char *notes);
int contacts_db_remove(const char *identity);
int contacts_db_update_notes(const char *identity, const char *notes);
bool contacts_db_exists(const char *identity);
int contacts_db_list(contact_list_t **list_out);
int contacts_db_count(void);
int contacts_db_clear_all(void);
```

### 8.4 Cache Systems

**Keyserver Cache** (`database/keyserver_cache.h`):
- Caches DHT public key lookups
- 7-day TTL
- Stores Dilithium + Kyber keys + signatures

**Profile Cache** (`database/profile_cache.h`):
- Caches user profiles from DHT
- 7-day TTL
- Stores full `dna_unified_identity_t` as JSON

**Presence Cache** (`database/presence_cache.h`):
- O(1) online status lookup
- In-memory with periodic persistence

---

## 9. Blockchain Integration

### 9.1 Wallet Management

**Location:** `blockchain/wallet.h`

**Wallet Directory:** `/opt/cellframe-node/var/lib/wallet/`

**Signature Types:**
```c
typedef enum {
    SIG_TYPE_DILITHIUM = 0,
    SIG_TYPE_PICNIC = 1,
    SIG_TYPE_BLISS = 2,
    SIG_TYPE_TESLA = 3
} sig_type_t;
```

### 9.2 RPC Client

**Location:** `blockchain/blockchain_rpc.h`

Communicates with Cellframe node via JSON-RPC.

### 9.3 Transaction Building

**Location:** `blockchain/blockchain_tx_builder_minimal.h`

Minimal transaction builder for DNA name registration and token transfers.

### 9.4 Supported Networks

| Network | Token |
|---------|-------|
| Backbone | CPUNK, CELL |
| KelVPN | KEL |
| SubZero | Various |
| Millixt | Various |

---

## 10. Public API

### 10.1 DNA Engine API

**Location:** `include/dna/dna_engine.h`

**Version:** 1.0.0

**Design Principles:**
- Async operations with callbacks (non-blocking)
- Engine-managed threading (DHT, P2P, RPC)
- Event system for pushed notifications
- Clean separation between engine and UI

### 10.2 Data Types

```c
typedef struct dna_engine dna_engine_t;
typedef uint64_t dna_request_id_t;

// Contact
typedef struct {
    char fingerprint[129];
    char display_name[256];
    bool is_online;
    uint64_t last_seen;
} dna_contact_t;

// Message
typedef struct {
    int id;
    char sender[129];
    char recipient[129];
    char *plaintext;
    uint64_t timestamp;
    bool is_outgoing;
    int status;        // 0=pending, 1=sent, 2=delivered, 3=read
    int message_type;  // 0=chat, 1=group_invitation
} dna_message_t;

// Group
typedef struct {
    char uuid[37];
    char name[256];
    char creator[129];
    int member_count;
    uint64_t created_at;
} dna_group_t;

// Wallet
typedef struct {
    char name[256];
    char address[120];
    int sig_type;
    bool is_protected;
} dna_wallet_t;
```

### 10.3 Event System

```c
typedef enum {
    DNA_EVENT_DHT_CONNECTED,
    DNA_EVENT_DHT_DISCONNECTED,
    DNA_EVENT_MESSAGE_RECEIVED,
    DNA_EVENT_MESSAGE_SENT,
    DNA_EVENT_MESSAGE_DELIVERED,
    DNA_EVENT_MESSAGE_READ,
    DNA_EVENT_CONTACT_ONLINE,
    DNA_EVENT_CONTACT_OFFLINE,
    DNA_EVENT_GROUP_INVITATION_RECEIVED,
    DNA_EVENT_GROUP_MEMBER_JOINED,
    DNA_EVENT_GROUP_MEMBER_LEFT,
    DNA_EVENT_IDENTITY_LOADED,
    DNA_EVENT_ERROR
} dna_event_type_t;

typedef void (*dna_event_cb)(const dna_event_t *event, void *user_data);
```

### 10.4 API Categories

**Lifecycle (4 functions):**
```c
dna_engine_t* dna_engine_create(const char *data_dir);
void dna_engine_set_event_callback(engine, callback, user_data);
void dna_engine_destroy(dna_engine_t *engine);
const char* dna_engine_get_fingerprint(dna_engine_t *engine);
```

**Identity (5 async functions):**
```c
dna_request_id_t dna_engine_list_identities(engine, callback, user_data);
dna_request_id_t dna_engine_create_identity(engine, signing_seed, encryption_seed, callback, user_data);
dna_request_id_t dna_engine_load_identity(engine, fingerprint, callback, user_data);
dna_request_id_t dna_engine_register_name(engine, name, callback, user_data);
dna_request_id_t dna_engine_get_display_name(engine, fingerprint, callback, user_data);
```

**Contacts (3 async functions):**
```c
dna_request_id_t dna_engine_get_contacts(engine, callback, user_data);
dna_request_id_t dna_engine_add_contact(engine, identifier, callback, user_data);
dna_request_id_t dna_engine_remove_contact(engine, fingerprint, callback, user_data);
```

**Messaging (3 async functions):**
```c
dna_request_id_t dna_engine_send_message(engine, recipient_fingerprint, message, callback, user_data);
dna_request_id_t dna_engine_get_conversation(engine, contact_fingerprint, callback, user_data);
dna_request_id_t dna_engine_check_offline_messages(engine, callback, user_data);
```

**Groups (6 async functions):**
```c
dna_request_id_t dna_engine_get_groups(engine, callback, user_data);
dna_request_id_t dna_engine_create_group(engine, name, member_fingerprints, member_count, callback, user_data);
dna_request_id_t dna_engine_send_group_message(engine, group_uuid, message, callback, user_data);
dna_request_id_t dna_engine_get_invitations(engine, callback, user_data);
dna_request_id_t dna_engine_accept_invitation(engine, group_uuid, callback, user_data);
dna_request_id_t dna_engine_reject_invitation(engine, group_uuid, callback, user_data);
```

**Wallet (4 async functions):**
```c
dna_request_id_t dna_engine_list_wallets(engine, callback, user_data);
dna_request_id_t dna_engine_get_balances(engine, wallet_index, callback, user_data);
dna_request_id_t dna_engine_send_tokens(engine, wallet_index, recipient_address, amount, token, network, callback, user_data);
dna_request_id_t dna_engine_get_transactions(engine, wallet_index, network, callback, user_data);
```

**P2P & Presence (6 async functions):**
```c
dna_request_id_t dna_engine_refresh_presence(engine, callback, user_data);
bool dna_engine_is_peer_online(engine, fingerprint);
dna_request_id_t dna_engine_sync_contacts_to_dht(engine, callback, user_data);
dna_request_id_t dna_engine_sync_contacts_from_dht(engine, callback, user_data);
dna_request_id_t dna_engine_sync_groups(engine, callback, user_data);
dna_request_id_t dna_engine_get_registered_name(engine, callback, user_data);
```

---

## 11. GUI Application

### 11.1 Framework

**Location:** `imgui_gui/`

**Stack:**
- ImGui (Immediate Mode GUI)
- OpenGL 3.0+ (rendering)
- GLFW3 (window/input)
- FreeType (fonts + emoji)

### 11.2 State Management

**Centralized State:** `AppState` in `core/app_state.h`

**Categories:**
- View state (current_view, selected_contact/group)
- Identity state (fingerprint, identities list)
- Data (contacts, groups, messages)
- Async tasks (DHT operations, message sends)
- Dialog visibility flags
- Wallet state
- Profile editor state

### 11.3 Screens

| Screen | File | Purpose |
|--------|------|---------|
| Contacts | `contacts_sidebar.h` | Contact list, recent chats |
| Chat | `chat_screen.h` | Message history, input |
| Wallet | `wallet_screen.h` | Balances, transactions |
| Settings | `settings_screen.h` | Theme, preferences |
| Identity Selection | `identity_selection_screen.h` | Create/select identity |
| Add Contact | `add_contact_dialog.h` | DHT lookup, add |
| Create Group | `create_group_dialog.h` | Group creation |
| Group Invitation | `group_invitation_dialog.h` | Accept/reject |
| Message Wall | `message_wall_screen.h` | Public posts |
| Profile Editor | `profile_editor_screen.h` | Edit profile |
| Register Name | `register_name_screen.h` | DNA name registration |
| Wallet Send | `wallet_send_dialog.h` | Token transfer |
| Wallet Receive | `wallet_receive_dialog.h` | QR code, address |

### 11.4 Async Pattern

```cpp
// Single task
state.dht_publish_task.start([](AsyncTask* task) {
    // Background work
    task->addMessage("Status update");
});

// Task queue
state.message_send_queue.enqueue(
    []() { messenger_p2p_send(...); },
    message_index
);
```

### 11.5 Theming

**Two Themes:**
1. **DNA Theme** (default) - Dark blue/cyan
2. **Club Theme** - Dark brown/orange

**Settings persistence:** `dna_messenger.ini`

---

## 12. Data Flow Diagrams

### 12.1 Message Send Flow

```
┌─────────────────────────────────────────────────────────────────┐
│                        MESSAGE SEND FLOW                         │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  User clicks Send                                               │
│         │                                                       │
│         ▼                                                       │
│  ┌─────────────────┐                                           │
│  │ Enqueue to      │                                           │
│  │ AsyncTaskQueue  │                                           │
│  └────────┬────────┘                                           │
│           │                                                     │
│           ▼                                                     │
│  ┌─────────────────┐    ┌─────────────────┐                    │
│  │ Fetch recipient │───▶│ keyserver_cache │                    │
│  │ public keys     │    │ (7-day TTL)     │                    │
│  └────────┬────────┘    └─────────────────┘                    │
│           │                      │                              │
│           │  Cache miss          ▼                              │
│           │             ┌─────────────────┐                    │
│           │             │ DHT Keyserver   │                    │
│           │             │ Lookup          │                    │
│           │             └────────┬────────┘                    │
│           │◀─────────────────────┘                             │
│           ▼                                                     │
│  ┌─────────────────┐                                           │
│  │ Kyber1024       │  Generate random shared secret            │
│  │ Encapsulate     │  Encrypt with recipient's pubkey          │
│  └────────┬────────┘                                           │
│           │                                                     │
│           ▼                                                     │
│  ┌─────────────────┐                                           │
│  │ AES-256-GCM     │  Encrypt message with shared secret       │
│  │ Encrypt         │                                           │
│  └────────┬────────┘                                           │
│           │                                                     │
│           ▼                                                     │
│  ┌─────────────────┐                                           │
│  │ Dilithium5      │  Sign ciphertext                          │
│  │ Sign            │                                           │
│  └────────┬────────┘                                           │
│           │                                                     │
│           ▼                                                     │
│  ┌─────────────────┐                                           │
│  │ Save to SQLite  │  Store encrypted in messages.db           │
│  │ (messages.db)   │  status = PENDING                         │
│  └────────┬────────┘                                           │
│           │                                                     │
│           ▼                                                     │
│  ┌─────────────────┐                                           │
│  │ Try P2P Send    │  TCP 4001                                 │
│  │ (TCP direct)    │                                           │
│  └────────┬────────┘                                           │
│           │                                                     │
│     ┌─────┴─────┐                                              │
│     │           │                                               │
│  Success     Failure                                            │
│     │           │                                               │
│     ▼           ▼                                               │
│  ┌──────┐   ┌─────────────────┐                                │
│  │ SENT │   │ Queue to DHT    │  7-day TTL                     │
│  └──────┘   │ Offline Queue   │                                │
│             └─────────────────┘                                │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

### 12.2 Identity Creation Flow

```
┌─────────────────────────────────────────────────────────────────┐
│                     IDENTITY CREATION FLOW                       │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  User requests new identity                                     │
│         │                                                       │
│         ▼                                                       │
│  ┌─────────────────┐                                           │
│  │ Generate 24-word│                                           │
│  │ BIP39 mnemonic  │                                           │
│  └────────┬────────┘                                           │
│           │                                                     │
│           ▼                                                     │
│  ┌─────────────────┐                                           │
│  │ PBKDF2-SHA512   │  2048 rounds                              │
│  │ Derive 512-bit  │  Optional passphrase                      │
│  │ master seed     │                                           │
│  └────────┬────────┘                                           │
│           │                                                     │
│     ┌─────┴─────┐                                              │
│     │           │                                               │
│     ▼           ▼                                               │
│  ┌──────┐   ┌──────┐                                           │
│  │ 256  │   │ 256  │  Split into two seeds                     │
│  │ bits │   │ bits │                                           │
│  └──┬───┘   └──┬───┘                                           │
│     │          │                                                │
│     ▼          ▼                                                │
│  ┌──────────────────┐   ┌──────────────────┐                   │
│  │ Dilithium5       │   │ Kyber1024        │                   │
│  │ KeyGen           │   │ KeyGen           │                   │
│  │ (deterministic)  │   │ (deterministic)  │                   │
│  └────────┬─────────┘   └────────┬─────────┘                   │
│           │                      │                              │
│           ▼                      │                              │
│  ┌─────────────────┐             │                              │
│  │ SHA3-512        │             │                              │
│  │ (dilithium_pk)  │             │                              │
│  │ = fingerprint   │             │                              │
│  └────────┬────────┘             │                              │
│           │                      │                              │
│     ┌─────┴─────┬────────────────┘                             │
│     │           │                                               │
│     ▼           ▼                                               │
│  ┌──────────────────────────────────┐                          │
│  │ Save to ~/.dna/                  │                          │
│  │ <fingerprint>.dsa (4896 bytes)   │                          │
│  │ <fingerprint>.kem (3168 bytes)   │                          │
│  └────────┬─────────────────────────┘                          │
│           │                                                     │
│           ▼                                                     │
│  ┌─────────────────┐                                           │
│  │ Publish to DHT  │  Public keys + self-signature             │
│  │ Keyserver       │                                           │
│  └─────────────────┘                                           │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

### 12.3 DHT Lookup Flow

```
┌─────────────────────────────────────────────────────────────────┐
│                       DHT LOOKUP FLOW                            │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  Input: fingerprint or name                                     │
│         │                                                       │
│         ▼                                                       │
│  ┌─────────────────┐                                           │
│  │ Is 128 hex      │                                           │
│  │ chars?          │                                           │
│  └────────┬────────┘                                           │
│           │                                                     │
│     ┌─────┴─────┐                                              │
│     │           │                                               │
│   Yes          No (name)                                        │
│     │           │                                               │
│     │           ▼                                               │
│     │    ┌─────────────────┐                                   │
│     │    │ dna_lookup_by_  │                                   │
│     │    │ name()          │                                   │
│     │    │ name → fp       │                                   │
│     │    └────────┬────────┘                                   │
│     │             │                                             │
│     │◀────────────┘                                            │
│     │                                                           │
│     ▼                                                           │
│  ┌─────────────────┐                                           │
│  │ Check local     │                                           │
│  │ keyserver_cache │                                           │
│  └────────┬────────┘                                           │
│           │                                                     │
│     ┌─────┴─────┐                                              │
│     │           │                                               │
│  Cache hit   Cache miss                                         │
│     │           │                                               │
│     │           ▼                                               │
│     │    ┌─────────────────┐                                   │
│     │    │ DHT Get         │                                   │
│     │    │ SHA3-512(fp +   │                                   │
│     │    │ ":profile")     │                                   │
│     │    └────────┬────────┘                                   │
│     │             │                                             │
│     │             ▼                                             │
│     │    ┌─────────────────┐                                   │
│     │    │ Verify          │                                   │
│     │    │ Dilithium5      │                                   │
│     │    │ signature       │                                   │
│     │    └────────┬────────┘                                   │
│     │             │                                             │
│     │             ▼                                             │
│     │    ┌─────────────────┐                                   │
│     │    │ Cache result    │  7-day TTL                        │
│     │    │ locally         │                                   │
│     │    └────────┬────────┘                                   │
│     │             │                                             │
│     │◀────────────┘                                            │
│     │                                                           │
│     ▼                                                           │
│  Return: dilithium_pubkey, kyber_pubkey, fingerprint            │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

---

## 13. Security Architecture

### 13.1 End-to-End Encryption Model

```
┌─────────────────────────────────────────────────────────────────┐
│                    E2E ENCRYPTION MODEL                          │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  SENDER                                RECIPIENT                │
│                                                                 │
│  plaintext                             ciphertext               │
│      │                                      │                   │
│      ▼                                      │                   │
│  ┌─────────┐                               │                   │
│  │ Kyber   │──── ciphertext ────────────────┼───────┐          │
│  │ Encap   │                               │       │          │
│  │ (pk_r)  │                               │       ▼          │
│  └────┬────┘                               │   ┌─────────┐    │
│       │                                    │   │ Kyber   │    │
│       │ shared_secret (32B)                │   │ Decap   │    │
│       │                                    │   │ (sk_r)  │    │
│       ▼                                    │   └────┬────┘    │
│  ┌─────────┐                               │        │          │
│  │ AES-256 │                               │        │          │
│  │ GCM     │                               │        │          │
│  │ Encrypt │                               │        ▼          │
│  └────┬────┘                               │   ┌─────────┐    │
│       │                                    │   │ AES-256 │    │
│       │ ciphertext                         │   │ GCM     │    │
│       │                                    │   │ Decrypt │    │
│       ▼                                    │   └────┬────┘    │
│  ┌─────────┐                               │        │          │
│  │ Dilith  │                               │        │          │
│  │ Sign    │                               │        │          │
│  │ (sk_s)  │                               │        ▼          │
│  └────┬────┘                               │   ┌─────────┐    │
│       │                                    │   │ Dilith  │    │
│       │ signature (4627B)                  │   │ Verify  │    │
│       │                                    │   │ (pk_s)  │    │
│       ▼                                    │   └────┬────┘    │
│                                            │        │          │
│  [kyber_ct | aes_ct | sig] ────────────────┼────────┘          │
│                                            │        │          │
│                                            │        ▼          │
│                                            │   plaintext       │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

### 13.2 Key Hierarchy

```
BIP39 Mnemonic (24 words)
         │
         ▼
    PBKDF2-SHA512
         │
    512-bit seed
         │
    ┌────┴────┐
    │         │
256 bits   256 bits
    │         │
    ▼         ▼
Dilithium5  Kyber1024
(signing)   (encryption)
    │         │
    ▼         │
 SHA3-512    │
    │         │
    ▼         │
fingerprint  │
(128 hex)    │
    │         │
    └────┬────┘
         │
    Identity
```

### 13.3 Forward Secrecy

Each message uses a fresh Kyber1024 encapsulation, generating a unique shared secret. Compromise of a past session key does not compromise future messages.

### 13.4 Message Authentication

All messages are signed with Dilithium5 before transmission:
1. Sender signs ciphertext with private key
2. Recipient verifies signature with sender's public key from DHT
3. Signature binds message to sender's identity

### 13.5 Storage Security

| Data | Encryption | Location |
|------|------------|----------|
| Private keys | None (file permissions) | `<data_dir>/*.dsa`, `<data_dir>/*.kem` |
| Messages | AES-256-GCM (encrypted at rest) | `<data_dir>/messages.db` |
| Contacts | Plaintext | Per-identity SQLite |
| Cache | Plaintext | Per-identity SQLite |

**Note:** `data_dir` defaults to `~/.dna` on desktop, app-specific directory on mobile.

---

## 14. Deployment

### 14.1 Client Installation

**Linux Build:**
```bash
mkdir build && cd build
cmake .. && make -j$(nproc)
./imgui_gui/dna_messenger_imgui
```

**Windows Cross-Compile:**
```bash
./build-cross-compile.sh windows-x64
```

### 14.2 Bootstrap Server Deployment

**Build (no GUI):**
```bash
cd /opt/dna-messenger
git pull
rm -rf build && mkdir build && cd build
cmake -DBUILD_GUI=OFF .. && make -j$(nproc)
```

**Run:**
```bash
# Foreground with verbose logging
./vendor/opendht-pq/tools/dna-nodus \
    -b 154.38.182.161:4000 \
    -b 164.68.105.227:4000 \
    -b 164.68.116.180:4000 \
    -v

# Background with persistence
nohup ./vendor/opendht-pq/tools/dna-nodus \
    -b 154.38.182.161:4000 \
    -b 164.68.105.227:4000 \
    -b 164.68.116.180:4000 \
    -s /var/lib/dna-dht/bootstrap.state \
    -v > /var/log/dna-nodus.log 2>&1 &
```

**Persistence:**
- Default path: `/var/lib/dna-dht/bootstrap.state`
- SQLite database: `bootstrap.state.values.db`
- Use `-s <path>` to override

### 14.3 Configuration Files

| File | Purpose |
|------|---------|
| `dna_messenger.ini` | GUI window layout, theme |
| `~/.dna/` | All user data |

### 14.4 Network Ports

| Port | Protocol | Purpose |
|------|----------|---------|
| 4000 | UDP | DHT network |
| 4001 | TCP | P2P messaging |

---

## Appendix A: Key Sizes Reference

| Algorithm | Component | Size |
|-----------|-----------|------|
| **Kyber1024** | Public key | 1568 bytes |
| | Private key | 3168 bytes |
| | Ciphertext | 1568 bytes |
| | Shared secret | 32 bytes |
| **Dilithium5** | Public key | 2592 bytes |
| | Private key | 4896 bytes |
| | Signature | 4627 bytes |
| **AES-256-GCM** | Key | 32 bytes |
| | Nonce | 12 bytes |
| | Tag | 16 bytes |
| **SHA3-512** | Output | 64 bytes (128 hex) |
| **GSK** | Key | 32 bytes |

## Appendix B: Error Codes

```c
// Engine-specific errors (start at -100)
DNA_ENGINE_ERROR_INIT           = -100
DNA_ENGINE_ERROR_NOT_INITIALIZED = -101
DNA_ENGINE_ERROR_NETWORK        = -102
DNA_ENGINE_ERROR_DATABASE       = -103
DNA_ENGINE_ERROR_TIMEOUT        = -104
DNA_ENGINE_ERROR_BUSY           = -105
DNA_ENGINE_ERROR_NO_IDENTITY    = -106
DNA_ENGINE_ERROR_ALREADY_EXISTS = -107
DNA_ENGINE_ERROR_PERMISSION     = -108
```

## Appendix C: DHT TTL Values

| Data Type | TTL |
|-----------|-----|
| Identity keys | Permanent |
| Contact lists | Permanent |
| Name registrations | 365 days |
| Profiles | 7 days |
| Groups | 7 days |
| Offline messages | 7 days |
| GSK | 7 days |
