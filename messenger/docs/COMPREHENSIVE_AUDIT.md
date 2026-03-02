# DNA Messenger - Comprehensive Audit Documentation

**C Library Version:** 0.8.0
**Flutter Version:** 0.101.24+10324
**Audit Date:** 2026-03-01
**Audit Depth:** Exhaustive (all source files verified)

---

## Table of Contents

1. [Executive Summary](#1-executive-summary)
2. [Project Structure](#2-project-structure)
3. [C Library Public API](#3-c-library-public-api)
4. [Engine Module Architecture](#4-engine-module-architecture)
5. [Domain Layers](#5-domain-layers)
6. [DHT Integration (Nodus v5)](#6-dht-integration-nodus-v5)
7. [Flutter App](#7-flutter-app)
8. [Build System](#8-build-system)
9. [CLI Tool](#9-cli-tool)
10. [Tests](#10-tests)
11. [Wire Protocols](#11-wire-protocols)
12. [Security](#12-security)
13. [Known Issues & Status](#13-known-issues--status)

---

## 1. Executive Summary

DNA Messenger is a fully decentralized post-quantum encrypted messenger with integrated multi-chain cryptocurrency wallet. The codebase is production-ready, well-architected, and extensively documented.

| Metric | Value |
|--------|-------|
| C source files | 147 |
| Header files | 189 |
| Engine core lines | ~1,970 (dispatcher) |
| Engine modules | 17 components |
| Engine module total lines | 11,547 |
| DHT integration lines | 16,999 |
| Flutter Dart files | 108 |
| Unit tests | 13 passing |
| Fuzz targets | 6 |
| Security level | NIST Category 5 (256-bit quantum) |

---

## 2. Project Structure

```
/opt/dna/messenger/
├── include/dna/              Public API headers
│   ├── dna_engine.h          Main engine API (3,367 lines)
│   └── version.h             Version constants (v0.8.0)
├── src/api/                  Core engine
│   ├── dna_engine.c          Task dispatcher (1,970 lines)
│   ├── dna_engine_internal.h Internal types, 90+ task definitions
│   └── engine/               17 modular components (11,547 lines)
├── dht/                      DHT integration (Nodus v5)
│   ├── shared/               Shared DHT operations (199 KB)
│   ├── client/               DHT client operations
│   ├── core/                 DHT core (bootstrap, keyserver)
│   └── keyserver/            Keyserver implementation
├── messenger/                Messaging core (167 KB)
├── database/                 SQLite persistence (180 KB, 12 modules)
├── transport/                P2P transport layer
├── blockchain/               Multi-chain wallet (412 KB, 4 chains)
├── cli/                      Command-line testing tool
├── tests/                    Unit tests (13) + fuzz tests (6)
├── dna_messenger_flutter/    Flutter mobile/desktop app
├── docs/                     50+ documentation files
└── CMakeLists.txt            Main build config (550+ lines)
```

---

## 3. C Library Public API

### dna_engine.h (3,367 lines) - Complete Function Reference

#### Engine Lifecycle (9 functions)

| Function | Return | Purpose |
|----------|--------|---------|
| `dna_engine_create(data_dir)` | `dna_engine_t*` | Create engine (sync) |
| `dna_engine_create_async(data_dir, cb, user_data)` | void | Create engine (async) |
| `dna_engine_destroy(engine)` | void | Cleanup engine |
| `dna_engine_request_shutdown(engine)` | void | Graceful shutdown |
| `dna_engine_is_shutdown_requested(engine)` | bool | Check shutdown state |
| `dna_engine_pause(engine)` | int | Pause for mobile background |
| `dna_engine_resume(engine)` | int | Resume from pause |
| `dna_engine_is_paused(engine)` | bool | Check pause state |
| `dna_engine_get_fingerprint(engine)` | `const char*` | Current identity fingerprint |

#### Identity Management (13 functions)

| Function | Purpose |
|----------|---------|
| `dna_engine_create_identity(engine, name, password, cb, ud)` | Create new identity (async) |
| `dna_engine_create_identity_sync(engine, name, password)` | Create new identity (sync) |
| `dna_engine_restore_identity_sync(engine, mnemonic, name, pw)` | Restore from BIP39 mnemonic |
| `dna_engine_delete_identity_sync(engine, fingerprint)` | Delete identity |
| `dna_engine_has_identity(engine)` | Check if identity exists |
| `dna_engine_load_identity(engine, password, cb, ud)` | Load identity (async) |
| `dna_engine_load_identity_minimal(engine, password, cb, ud)` | Load DHT-only mode |
| `dna_engine_is_identity_loaded(engine)` | Check if loaded |
| `dna_engine_register_name(engine, name, cb, ud)` | Register name on DHT |
| `dna_engine_get_display_name(engine, fp, cb, ud)` | Get contact display name |
| `dna_engine_change_password_sync(engine, old, new)` | Change password |
| `dna_engine_get_mnemonic(engine, password, buf, len)` | Get recovery phrase |
| `dna_engine_prepare_dht_from_mnemonic(engine, mnemonic, pw)` | Prepare DHT keys |

#### Contacts & Contact Requests (15 functions)

| Function | Purpose |
|----------|---------|
| `dna_engine_get_contacts(engine, cb, ud)` | List all contacts |
| `dna_engine_add_contact(engine, name_or_fp, cb, ud)` | Add contact |
| `dna_engine_remove_contact(engine, fp, cb, ud)` | Remove contact |
| `dna_engine_set_contact_nickname_sync(engine, fp, nick)` | Set local nickname |
| `dna_engine_send_contact_request(engine, fp, msg, cb, ud)` | Send contact request |
| `dna_engine_get_contact_requests(engine, cb, ud)` | Get pending requests |
| `dna_engine_get_contact_request_count(engine, count)` | Unread count |
| `dna_engine_approve_contact_request(engine, fp, cb, ud)` | Approve request |
| `dna_engine_deny_contact_request(engine, fp, cb, ud)` | Deny request |
| `dna_engine_block_user(engine, fp, reason, cb, ud)` | Block user |
| `dna_engine_unblock_user(engine, fp, cb, ud)` | Unblock user |
| `dna_engine_get_blocked_users(engine, cb, ud)` | Get blocked list |
| `dna_engine_is_user_blocked(engine, fp)` | Check if blocked |
| `dna_engine_lookup_presence(engine, fp, cb, ud)` | Online status |
| `dna_engine_refresh_contact_profile(engine, fp, cb, ud)` | Fetch profile from DHT |

#### Messaging (7 functions)

| Function | Purpose |
|----------|---------|
| `dna_engine_send_message(engine, recipient, msg, cb, ud)` | Send message (async) |
| `dna_engine_get_conversation(engine, fp, cb, ud)` | Get all messages |
| `dna_engine_get_conversation_page(engine, fp, offset, limit, cb, ud)` | Paginated messages |
| `dna_engine_check_offline_messages(engine, cb, ud)` | Fetch offline queue |
| `dna_engine_check_offline_messages_from(engine, fp, cb, ud)` | Fetch from contact |
| `dna_engine_is_transport_ready(engine)` | Check DHT connection |
| `dna_engine_refresh_presence(engine, cb, ud)` | Publish online status |

#### Groups (11 functions)

| Function | Purpose |
|----------|---------|
| `dna_engine_get_groups(engine, cb, ud)` | List all groups |
| `dna_engine_get_group_info(engine, uuid, cb, ud)` | Group metadata + GEK |
| `dna_engine_get_group_members(engine, uuid, cb, ud)` | Member list |
| `dna_engine_create_group(engine, name, cb, ud)` | Create new group |
| `dna_engine_send_group_message(engine, uuid, msg, cb, ud)` | Send group message |
| `dna_engine_get_group_conversation(engine, uuid, cb, ud)` | Group history |
| `dna_engine_add_group_member(engine, uuid, fp, cb, ud)` | Add member |
| `dna_engine_remove_group_member(engine, uuid, fp, cb, ud)` | Remove member |
| `dna_engine_get_invitations(engine, cb, ud)` | Pending invitations |
| `dna_engine_accept_invitation(engine, uuid, cb, ud)` | Accept invitation |
| `dna_engine_reject_invitation(engine, uuid, cb, ud)` | Reject invitation |

#### Wallet (10 functions)

| Function | Purpose |
|----------|---------|
| `dna_engine_list_wallets(engine, cb, ud)` | List available wallets |
| `dna_engine_get_balances(engine, cb, ud)` | Token balances (live) |
| `dna_engine_get_cached_balances(engine, cb, ud)` | Cached balances |
| `dna_engine_send_tokens(engine, chain, to, amount, cb, ud)` | Send crypto |
| `dna_engine_get_transactions(engine, chain, cb, ud)` | TX history |
| `dna_engine_estimate_gas(engine, chain, to, amount, cb, ud)` | Gas estimate |
| `dna_engine_get_addressbook(engine, cb, ud)` | Address book |
| `dna_engine_save_addressbook_entry(engine, entry, cb, ud)` | Save address |
| `dna_engine_delete_addressbook_entry(engine, id, cb, ud)` | Delete address |
| `dna_engine_lookup_addressbook(engine, label, cb, ud)` | Lookup address |

#### Profiles (3 functions)

| Function | Purpose |
|----------|---------|
| `dna_engine_get_profile(engine, cb, ud)` | Own profile |
| `dna_engine_lookup_profile(engine, fp, cb, ud)` | Contact profile |
| `dna_engine_update_profile(engine, json, cb, ud)` | Update profile |

#### Wall / Social Posts (6 functions)

| Function | Purpose |
|----------|---------|
| `dna_engine_wall_post(engine, text, image, cb, ud)` | Create post |
| `dna_engine_wall_delete(engine, uuid, cb, ud)` | Delete post |
| `dna_engine_wall_load(engine, fp, cb, ud)` | Load user's wall |
| `dna_engine_wall_timeline(engine, cb, ud)` | Timeline from contacts |
| `dna_engine_wall_add_comment(engine, post_uuid, text, cb, ud)` | Comment |
| `dna_engine_wall_get_comments(engine, post_uuid, cb, ud)` | Get comments |

#### Channels / RSS (9 functions)

| Function | Purpose |
|----------|---------|
| `dna_engine_channel_create(engine, name, desc, public, cb, ud)` | Create channel |
| `dna_engine_channel_get(engine, uuid, cb, ud)` | Channel info |
| `dna_engine_channel_delete(engine, uuid, cb, ud)` | Delete channel |
| `dna_engine_channel_post(engine, uuid, text, cb, ud)` | Post to channel |
| `dna_engine_channel_get_posts(engine, uuid, cb, ud)` | Get posts |
| `dna_engine_channel_discover(engine, cb, ud)` | Discover channels |
| `dna_engine_channel_get_subscriptions(engine, cb, ud)` | List subs |
| `dna_engine_channel_subscribe(engine, uuid, cb, ud)` | Subscribe |
| `dna_engine_channel_unsubscribe(engine, uuid, cb, ud)` | Unsubscribe |

### Async Pattern

All operations return `dna_request_id_t` (uint64_t). Operations are non-blocking. Completion via callback:

```c
typedef void (*dna_completion_cb)(dna_request_id_t request_id, int error, void *user_data);
```

---

## 4. Engine Module Architecture

### Task Dispatch System

- **Queue:** Lock-free MPSC queue (size=256 tasks)
- **Workers:** 4-24 threads (CPU-dependent)
- **Pattern:** Task -> Queue -> Worker -> Handler -> Callback
- **Task Types:** 90+ in `dna_engine_internal.h`

### 17 Engine Modules

| Module | Size | Tasks | Responsibilities |
|--------|------|-------|-----------------|
| identity | 61 KB | 10 | Create/load identity, name registration, profiles |
| messaging | 34 KB | 5 | Send/receive, conversations, offline queue, retry |
| contacts | 31 KB | 15 | Add/remove, requests, blocking, auto-approval |
| groups | 27 KB | 11 | Group CRUD, invitations, GEK rotation |
| wallet | 45 KB | 10 | Multi-chain (Cellframe, Eth, Solana, TRON) |
| listeners | 73 KB | 14 | DHT listeners (outbox, presence, ACK, wall, channel) |
| backup | 26 KB | 14 | DHT sync (messages, contacts, groups, addressbook) |
| channels | 38 KB | 9 | Channel CRUD, discovery, subscriptions |
| wall | 28 KB | 6 | Social posts, timeline, comments |
| presence | 12 KB | 7 | Online status, 4-min heartbeat |
| addressbook | 12 KB | 10 | Wallet address book CRUD |
| lifecycle | 8.4 KB | 5 | Pause/resume for mobile |
| logging | 7.7 KB | 13 | Debug log control |
| version | 8.6 KB | 4 | Version DHT operations |
| helpers | 3.3 KB | 4 | DHT context, key loading |
| workers | 3.9 KB | 3 | Thread pool management |
| signing | 3.5 KB | 2 | Dilithium5 signing (QR auth) |

---

## 5. Domain Layers

### Messenger Core (`messenger/` - 167 KB)

| File | Size | Purpose |
|------|------|---------|
| gek.c | 57 KB | Group Encryption Key system (200x faster than per-recipient) |
| messages.c | 46 KB | Message encryption/decryption (Kyber1024 + AES-256-GCM) |
| keygen.c | 36 KB | Key generation from BIP39 mnemonic |
| init.c | 18 KB | Engine initialization |
| contacts.c | 12 KB | Contact database |
| group_database.c | 11 KB | Persistent group storage |
| keys.c | 10 KB | Key management |
| groups.c | 8.4 KB | Group membership |
| identity.c | 3.7 KB | Identity fingerprinting (SHA3-512) |

### Database Layer (`database/` - 180 KB)

| Module | Size | Purpose |
|--------|------|---------|
| contacts_db.c | 46 KB | Contact metadata |
| wall_cache.c | 27 KB | Wall posts cache |
| addressbook_db.c | 27 KB | Wallet address book |
| keyserver_cache.c | 19 KB | Cached name lookups |
| profile_cache.c | 15 KB | Profile cache (7-day TTL) |
| channel_cache.c | 14 KB | Channel metadata |
| group_invitations.c | 14 KB | Pending invitations |
| profile_manager.c | 14 KB | Smart profile fetching |
| channel_subscriptions_db.c | 13 KB | Subscribed channels |
| cache_manager.c | 8.3 KB | Lifecycle management |
| presence_cache.c | 7.7 KB | Online status cache |
| wallet_cache.c | 7.1 KB | Balance cache |

### Blockchain Layer (`blockchain/` - 412 KB)

| Chain | Features | Key Files |
|-------|----------|-----------|
| Cellframe (CF20/KelVPN) | Dilithium5 signing, JSON-RPC | cellframe_wallet.c, cellframe_tx_builder.c |
| Ethereum | BIP-44 HD, ERC-20 tokens (USDT/USDC) | eth_wallet_create.c, eth_tx.c, eth_erc20.c |
| Solana | SLIP-10 Ed25519, SPL tokens | sol_wallet.c, sol_tx.c, sol_spl.c |
| TRON | BIP-44 HD, TRC-20 tokens (USDT/USDC) | trx_wallet_create.c, trx_tx.c, trx_trc20.c |

Common interface: `blockchain_wallet.c` + `blockchain_registry.c` (modular registry)

---

## 6. DHT Integration (Nodus v5)

### Wrapper API (`nodus_ops.c/h` - 13 KB)

```c
int nodus_ops_put(const uint8_t *key, size_t key_len,
                  const uint8_t *data, size_t data_len,
                  uint32_t ttl, uint64_t vid);
int nodus_ops_get(const uint8_t *key, size_t key_len,
                  uint8_t **data_out, size_t *len_out);
int nodus_ops_get_all(const uint8_t *key, size_t key_len,
                      uint8_t ***values_out, size_t **lens_out, size_t *count_out);
size_t nodus_ops_listen(const uint8_t *key, size_t key_len,
                        nodus_ops_listen_cb_t callback, void *user_data,
                        nodus_ops_listen_cleanup_t cleanup);
bool nodus_ops_is_ready(void);
```

### Lifecycle (`nodus_init.c/h` - 7.2 KB)

Singleton pattern. One Nodus client per engine. Connected to configured cluster.

### DHT Data Modules

| Module | Size | Purpose |
|--------|------|---------|
| dht_offline_queue.c | 38 KB | 7-day offline message queue with daily buckets |
| dht_dm_outbox.c | 31 KB | DM delivery with day rotation (v0.4.81+) |
| dht_groups.c | 39 KB | Group data structures (members, GEK, invitations) |
| dht_contact_request.c | 24 KB | Contact request inbox |
| dht_profile.c | 14 KB | User profile storage |
| dht_publish_queue.c | 14 KB | Async publish queue with retry |
| dht_gek_storage.c | 9.3 KB | Encrypted group encryption keys |
| dht_channel_subscriptions.c | 11 KB | Channel subscription sync |

---

## 7. Flutter App

### Version & Config

- **Version:** 0.101.24+10324
- **Dart SDK:** ^3.10.0
- **State Management:** Riverpod 2.6.1
- **FFI:** Direct C library binding via dart:ffi

### Screen Categories (11 categories, 30+ screens)

| Category | Key Screens |
|----------|-------------|
| Chat | ChatScreen, MessageBubble, MessageContextMenu |
| Messages | MessageListScreen, MessageDetailScreen |
| Contacts | ContactListScreen, ContactProfileDialog, ContactRequestDialog |
| Groups | GroupListScreen, GroupDetailScreen, GroupMemberDialog |
| Channels | ChannelListScreen, ChannelDetailScreen, DiscoverChannelsScreen |
| Wallet | WalletScreen, SendTokenScreen, TransactionHistoryScreen, AddressBookScreen |
| Profile | ProfileEditorScreen, AvatarCropScreen |
| Wall | WallScreen (timeline), UserWallScreen, WallPostDetailScreen |
| Settings | SettingsScreen, BlockedUsersScreen, AppLockSettingsScreen |
| Identity | IdentitySelectionScreen, IdentityCreateScreen, IdentityRestoreScreen |
| QR/Lock | QRScannerScreen, QRGeneratorScreen, AppLockScreen |

### State Providers (20+)

engine_provider, identity_provider, contacts_provider, messages_provider, groups_provider, channel_provider, profile_provider, wallet_provider, notification_settings_provider, app_lock_provider, foreground_service_provider, starred_messages_provider, event_handler, name_resolver_provider, price_provider

### Platform Support

| Platform | Status |
|----------|--------|
| Android | Fully functional (foreground service, biometric lock) |
| Linux | Fully functional |
| Windows | Supported |
| macOS | Planned |
| iOS | Planned (Phase 17) |

---

## 8. Build System

### CMakeLists.txt (550+ lines)

**Main Targets:**
- `dna_lib` (SHARED or STATIC) - 180+ source files
- `dna-messenger-cli` (optional) - CLI debugging tool
- `dna-send` (optional) - Cellframe TX sender

**External Dependencies:**

| Library | Purpose |
|---------|---------|
| OpenSSL 1.1+ | TLS, crypto utilities |
| SQLite3 3.24+ | Database persistence |
| json-c 0.13+ | JSON parsing (blockchain RPC) |
| CURL 7.50+ | HTTP(S) client |
| Nodus v5 | DHT (built in-tree) |
| secp256k1 | Bitcoin key derivation |

**Security Hardening:**
```
-fstack-protector-strong
-Wformat -Wformat-security
-D_FORTIFY_SOURCE=2
-fPIE (ASLR)
-Wl,-z,relro,-z,now (Full RELRO)
```

**Build Commands:**
```bash
cd messenger/build && cmake .. && make -j$(nproc)
# Flutter:
cd messenger/dna_messenger_flutter && flutter build linux
```

---

## 9. CLI Tool

### Commands (`dna-messenger-cli`)

| Command | Purpose |
|---------|---------|
| `whoami` | Show identity (fingerprint, name) |
| `contacts` | List contacts with online status |
| `send <name> "message"` | Send message |
| `messages <fp>` | Conversation history |
| `check-offline` | Poll DHT for missed messages |
| `listen` | Subscribe to push events |
| `lookup-profile <name/fp>` | View DHT profile |
| `lookup <name>` | Check name registration |
| `profile` | Show own profile |
| `groups` | List groups |

---

## 10. Tests

### Unit Tests (13 passing)

| Test | Purpose |
|------|---------|
| test_kyber1024 | Kyber1024 KEM operations |
| test_dilithium5_signature | Dilithium5 sign/verify |
| test_key_encryption | Key encryption with password |
| test_bip39_bip32 | BIP39 mnemonic + BIP32 HD derivation |
| test_aes256_gcm | AES-256-GCM encrypt/decrypt |
| test_dna_profile | Profile JSON serialization |
| test_simple | Basic functionality |
| test_timestamp_v08 | Message format v0.08 timestamp parsing |

### Fuzz Tests (6 targets)

| Target | Purpose |
|--------|---------|
| fuzz_base58 | Base58 encoding robustness |
| fuzz_common | Common function parsing |
| fuzz_contact_request | Contact request JSON parsing |
| fuzz_message_decrypt | Message decryption with garbage |
| fuzz_offline_queue | Offline queue deserialization |
| fuzz_profile_json | Profile JSON parsing |

---

## 11. Wire Protocols

### Seal Protocol (1:1 Message)

```
+-------------------------------------+
| Kyber1024 Ciphertext (1568 bytes)   |  Encapsulated shared secret
+-------------------------------------+
| AES-256-GCM Ciphertext (variable)   |  Encrypted plaintext
+-------------------------------------+
| Dilithium5 Signature (4627 bytes)   |  Author verification
+-------------------------------------+
```

Size: ~6,200 bytes per message.

### Spillway Protocol (Offline Messages)

- Daily buckets (UTC date boundary)
- 7-day retention
- Per-contact outbox key
- Automatic rotation at midnight UTC

### Anchor Protocol (Group Messaging)

- Per-group outbox by date
- GEK (Group Encryption Key) for encryption
- Automatic GEK rotation on member changes

### Atlas Protocol (Profile Storage)

- Key: hash("dna:profile:" + fingerprint)
- JSON data (wallets, socials, bio, avatar)
- 7-day TTL, Dilithium5 signed

### Nexus Protocol (Wall Posts)

- UUID-based DHT keys
- Post text + optional image JSON
- Dilithium5 signed
- Single-level threaded comments (v0.7.0+)

---

## 12. Security

### Cryptography Suite (NIST Category 5)

| Algorithm | Standard | Purpose | Status |
|-----------|----------|---------|--------|
| Kyber1024 | ML-KEM-1024 (FIPS 203) | Key encapsulation | NIST approved |
| Dilithium5 | ML-DSA-87 (FIPS 204) | Digital signatures | NIST approved |
| AES-256-GCM | NIST SP 800-38D | Symmetric encryption | NIST approved |
| SHA3-512 | FIPS 202 | Hashing | NIST approved |
| BIP39 | Electrum standard | Mnemonic seed | Industry standard |
| BIP32/44 | SLIP-10 | HD key derivation | Industry standard |

### Key Management

- Keys stored in `~/.dna/identity/<fingerprint>/`
- Optional password encryption (Argon2 + AES-256)
- File permissions: 0600 (user only)
- BIP39 mnemonic for recovery (never transmitted)

### Message Privacy Flow

```
Plaintext -> SHA3-512 hash -> Message ID
          -> Kyber1024 KEM -> Shared secret + ciphertext
          -> AES-256-GCM -> Encrypted message
          -> Dilithium5 sign -> Signature
          -> DHT: hash("dna:outbox:" + recipient_fp + day)
```

### Privacy Properties

- No IP exposure (messages via DHT keys only)
- Key derivation via SHA3-512 (privacy)
- Profile signatures verified with Dilithium5
- No metadata logging (DHT is stateless)

---

## 13. Known Issues & Status

### Feature Completeness

| Feature | Status |
|---------|--------|
| Post-Quantum Crypto | COMPLETE |
| 1:1 Messaging | COMPLETE (offline queue, delivery ACKs) |
| Group Messaging | COMPLETE (GEK rotation) |
| DHT Integration | COMPLETE (Nodus v5) |
| Multi-Chain Wallet | COMPLETE (4 networks, 9+ tokens) |
| User Profiles | COMPLETE (avatar, bio, socials) |
| Wall/Timeline | COMPLETE (with comments) |
| Channels (RSS) | COMPLETE (discovery, posts, subs) |
| Mobile UI (Android) | COMPLETE (Flutter) |
| Desktop UI (Linux/Windows) | COMPLETE (Flutter) |
| iOS App | PLANNED (Phase 17) |
| Web Messenger | PLANNED (Phase 15, prototype exists) |
| Voice/Video | PLANNED (Phase 16) |

### Code Quality

- Zero TODOs/FIXMEs in core engine code
- All 13 unit tests passing
- ASAN verified (Debug builds)
- 50+ documentation files
