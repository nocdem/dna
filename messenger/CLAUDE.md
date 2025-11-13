# DNA Messenger - Development Guidelines for Claude AI

**Last Updated:** 2025-11-13 | **Phase:** 10 (DNA Board Alpha) | **Complete:** 4, 8, 9.1-9.6, 10.1, **Messenger Core Modularization**

**Recent Updates (2025-11-13):**
- **Messenger Core Modularization COMPLETE:** Extracted 3,352 LOC from monolithic `messenger.c` (4,248 LOC) into 7 focused modules. Reduced messenger.c by 85.4% (3,230 → 473 lines). Enables parallel team development.
- **ImGui GUI Modularization COMPLETE:** Extracted 4,100+ LOC from monolithic `app.cpp` into 16 focused screen modules (screens/ and helpers/ directories)
- **Phase 9.6 COMPLETE:** Encrypted DHT identity backup system (Kyber1024 + AES-256-GCM, BIP39 recovery, permanent DHT storage)
- **Phase 10.1 COMPLETE:** Profile system with DHT storage + 7-day cache (dht_profile.c, profile_cache.c, profile_manager.c)
- **Phase 10.2 IN PROGRESS:** Wall posts (censorship-resistant social media) - Alpha version (free, no validators)
- **Contact sync migrated:** Unsigned puts → signed puts (dht_put_signed_permanent) for proper deletion
- **CRITICAL FIX (2025-11-10):** Offline message queue - `resolve_identity_to_fingerprint()` ensures DHT queue keys use fingerprints
- **GUI:** Qt5 deprecated → ImGui active (`imgui_gui/`), Qt preserved in `gui/` for reference

---

## Project Overview

Post-quantum E2E encrypted messenger with cpunk wallet. **NIST Category 5 security** (256-bit quantum).

**Crypto:** Kyber1024 (ML-KEM-1024), Dilithium5 (ML-DSA-87), AES-256-GCM, SHA3-512

**Key Features:** E2E encrypted messaging • DHT-based groups • Per-identity contacts with DHT sync • User profiles (display name, bio, avatar) with 7-day cache • Wall posts (censorship-resistant social media) • cpunk wallet (CPUNK/CELL/KEL) • P2P + DHT peer discovery • Offline queueing (7-day) • Encrypted DHT identity backup (BIP39 recovery) • Local SQLite (no centralized DB) • Cross-platform (Linux/Windows) • ImGui GUI

---

## Architecture

| Component | Description |
|-----------|-------------|
| **Core Library** (`libdna.a`) | PQ crypto (Kyber1024, Dilithium5) • Memory-based enc/dec API • Multi-recipient • Keyserver cache (SQLite, 7d TTL) |
| **GUI** (`dna_messenger_imgui`) | ImGui (OpenGL3+GLFW3) • Responsive UI • Theme system • Wallet integration • SQLite storage • Async tasks • **Qt5 deprecated** |
| **Wallet** | Cellframe .dwallet files • RPC integration • TX builder/signing • Balance/history queries |
| **P2P Transport** | OpenDHT peer discovery • TCP (port 4001) • Offline queueing (7d) • DHT groups (UUID v4) • 3 bootstrap nodes (US/EU) • 2-min polling |

### Directory Structure
```
/opt/dna-messenger/
├── crypto/                  # PQ cryptography
│   ├── dsa/                 # Dilithium5 (ML-DSA-87)
│   ├── kem/                 # Kyber1024 (ML-KEM-1024)
│   └── cellframe_dilithium/ # Cellframe Dilithium
├── dht/                     # DHT layer
│   ├── dht_context.*        # OpenDHT integration
│   ├── dht_offline_queue.*  # Offline queueing
│   ├── dht_groups.*         # DHT groups
│   ├── dht_contactlist.*    # Contact sync
│   ├── dht_keyserver.*      # Identity/name system
│   ├── dht_profile.*        # User profiles (DHT storage)
│   ├── dht_wall.*           # Wall posts (social media)
│   ├── dht_identity_backup.* # Encrypted DHT identity backup (Kyber1024 + AES-256-GCM)
│   ├── deploy-bootstrap.sh  # VPS deployment
│   └── monitor-bootstrap.sh # Health monitoring
├── p2p/                     # P2P transport
│   └── p2p_transport.*      # TCP + DHT
├── messenger/               # Messenger Core (MODULAR) - 7 focused modules
│   ├── messenger_core.h     # Shared type definitions
│   ├── identity.*           # Fingerprint utilities (111 LOC)
│   ├── init.*               # Context management (255 LOC)
│   ├── status.*             # Message status tracking (58 LOC)
│   ├── keys.*               # Public key management (443 LOC)
│   ├── contacts.*           # DHT contact sync (288 LOC)
│   ├── keygen.*             # Key generation (1,078 LOC)
│   └── messages.*           # Message operations (1,119 LOC)
├── imgui_gui/               # ImGui GUI (ACTIVE) - Modular architecture
│   ├── app.cpp              # Main application (simplified to 324 LOC)
│   ├── core/                # Core data structures
│   │   └── app_state.*      # Centralized application state
│   ├── screens/             # Screen modules (16 modules)
│   │   ├── identity_selection_screen.*  # Identity wizard (849 LOC)
│   │   ├── chat_screen.*                # Chat UI + emoji picker (690 LOC)
│   │   ├── wallet_send_dialog.*         # TX building (509 LOC)
│   │   ├── wallet_screen.*              # Wallet overview (282 LOC)
│   │   ├── contacts_sidebar.*           # Contact list (291 LOC)
│   │   ├── layout_manager.*             # Mobile/desktop layouts (260 LOC)
│   │   ├── message_wall_screen.*        # Wall posts (324 LOC)
│   │   ├── wallet_transaction_history_dialog.*  # TX history (304 LOC)
│   │   ├── add_contact_dialog.*         # Add contact (232 LOC)
│   │   ├── profile_editor_screen.*      # Profile editor (229 LOC)
│   │   ├── register_name_screen.*       # DHT name registration (184 LOC)
│   │   ├── settings_screen.*            # Settings (164 LOC)
│   │   └── wallet_receive_dialog.*      # Receive UI (94 LOC)
│   ├── helpers/             # Helper modules
│   │   └── data_loader.*    # Async data loading (447 LOC)
│   └── vendor/imgui/        # ImGui library
├── gui/                     # Qt5 GUI (DEPRECATED)
├── messenger.c              # Messenger facade (473 LOC, was 3,230)
├── wallet.*                 # Cellframe wallet integration
├── cellframe_rpc.*          # RPC client
├── cellframe_tx_builder_*   # TX builder
├── messenger_p2p.*          # P2P messaging
├── messenger_stubs.c        # DHT group functions
├── keyserver_cache.*        # Local key cache
├── contacts_db.*            # Per-identity contacts
├── profile_cache.*          # Profile cache (7-day TTL)
├── profile_manager.*        # Smart profile fetching
└── dna_api.h                # Public API
```

---

## Messenger Core Modular Architecture

**Completed:** 2025-11-13 | **Total Reduction:** 2,757 LOC from monolithic messenger.c (85.4% reduction)

### Module Pattern

All messenger modules follow a consistent C API pattern:

```c
// messenger/module_name.h
#ifndef MESSENGER_MODULE_NAME_H
#define MESSENGER_MODULE_NAME_H
#include "messenger_core.h"

/**
 * Function description
 * @param ctx: Messenger context
 * @return: 0 on success, -1 on error
 */
int messenger_function_name(messenger_context_t *ctx, ...);

#endif
```

**Key principles:**
- **C API:** Pure C with `messenger_context_t` first parameter pattern
- **Focused responsibilities:** Each module handles one core domain (identity, keys, messages, etc.)
- **Zero compiler warnings:** Especially critical for cryptographic code - all includes must be explicit
- **SQLite storage:** Local databases in `~/.dna/` (per-identity isolation)
- **DHT integration:** All modules use DHT via `p2p_transport_get_dht_context()`
- **Error propagation:** Return 0 on success, -1 on error with stderr logging

### Messenger Modules

**Core modules** (`messenger/`)

1. **identity** (111 LOC) - Identity creation and validation
   - `messenger_create_identity()` - Generate fingerprint-first identity from BIP39
   - `messenger_load_identity()` - Load existing identity from disk
   - Fingerprint computation (SHA3-512 of Dilithium5 pubkey)
   - Display name fallback (first10...last10 of fingerprint)

2. **init** (255 LOC) - Messenger context initialization
   - `messenger_init()` - Initialize messenger context with identity
   - Database initialization (messages.db, contacts.db, profiles.db)
   - DHT identity recovery (encrypted backup with Kyber1024)
   - P2P transport startup

3. **status** (58 LOC) - Status and info queries
   - `messenger_show_status()` - Display current identity and contact count
   - `messenger_get_current_identity()` - Get active identity string

4. **keys** (443 LOC) - Public key management
   - `messenger_load_pubkey()` - Load key from DHT keyserver (7d cache)
   - `messenger_load_pubkey_raw()` - Return raw Kyber1024 pubkey bytes
   - `messenger_publish_pubkey()` - Publish to DHT with Dilithium5 signature
   - Cache-first with DHT fallback, BLOB storage in keyserver_cache.db

5. **contacts** (288 LOC) - Contact list management
   - `messenger_add_contact()` / `messenger_remove_contact()` - Local CRUD
   - `messenger_list_contacts()` - Display contacts with profile info
   - `messenger_sync_contacts_to_dht()` / `messenger_fetch_contacts_from_dht()` - Multi-device sync
   - Per-identity SQLite (`~/.dna/<identity>_contacts.db`), Kyber1024 self-encrypted DHT sync

6. **keygen** (1,078 LOC) - Key generation and restoration
   - `messenger_generate_keys()` - Generate BIP39 + derive Dilithium5 + Kyber1024
   - `messenger_generate_keys_from_seeds()` - Restore from existing seeds
   - `messenger_register_name()` - DHT name registration (365d TTL)
   - `messenger_restore_keys()` / `messenger_restore_keys_from_file()` - BIP39 recovery
   - Encrypted DHT identity backup (permanent storage)

7. **messages** (1,119 LOC) - Message operations
   - `messenger_send_message()` - Multi-recipient E2E encryption (Kyber1024 + AES-256-GCM)
   - `messenger_list_messages()` / `messenger_list_sent_messages()` - Message listing
   - `messenger_decrypt_message()` - Decrypt with Kyber1024
   - `messenger_get_conversation()` - Threaded conversation API (for GUI)
   - `messenger_search_by_sender()` / `messenger_search_by_date()` - Search queries
   - P2P delivery with DHT offline queue fallback (7d TTL)

**Total extracted:** 3,352 LOC across 7 modules
**Remaining messenger.c:** 473 LOC (high-level orchestration only)

### Adding New Messenger Features

1. **Determine scope:** Does it fit existing module or need new one?
2. **Create module files:** `messenger/new_module.{h,c}` following pattern above
3. **Add to build:** Update `CMakeLists.txt` with new .c file in `dna_lib` sources
4. **Include in messenger.c:** Add `#include "messenger/new_module.h"`
5. **Zero warnings:** Explicitly include ALL dependency headers (crypto, platform, SQLite)
6. **Test cryptographic code:** Any crypto function MUST have proper declarations (no implicit)
7. **Document API:** Add detailed comments to .h file (parameters, return values, behavior)

**Example: Adding message search by keyword**

```c
// 1. Add to messenger/messages.h
int messenger_search_by_keyword(messenger_context_t *ctx, const char *keyword);

// 2. Implement in messenger/messages.c
int messenger_search_by_keyword(messenger_context_t *ctx, const char *keyword) {
    // SQLite query with LIKE pattern
    // ...
}

// 3. No CMakeLists.txt change (already in build)
// 4. Already included in messenger.c
```

---

## ImGui GUI Modular Architecture

**Completed:** 2025-11-13 | **Total Reduction:** 4,100+ LOC from monolithic app.cpp

### Module Pattern

All screen modules follow a consistent namespace-based pattern:

```cpp
// screen_name.h
#ifndef SCREEN_NAME_H
#define SCREEN_NAME_H
#include "../core/app_state.h"

namespace ScreenName {
    void render(AppState& state);
    // Additional helper functions...
}
#endif
```

**Key principles:**
- **Centralized state:** All UI state lives in `AppState` struct (no class members)
- **Namespace modules:** Use C++ namespaces (not classes) for screen logic
- **Stateless functions:** All functions accept `AppState&` as first parameter
- **No circular dependencies:** Screens never include other screens
- **Async tasks:** Use `state.task_queue` for background operations
- **Theme-aware:** Use `g_app_settings.theme` with `DNATheme::` / `ClubTheme::` helpers

### Module Categories

**1. Screen Modules** (`imgui_gui/screens/`)
- Identity Selection (849 LOC) - Multi-step wizard with async DHT lookups
- Chat Screen (690 LOC) - Message UI with emoji picker and retry logic
- Wallet Send Dialog (509 LOC) - TX builder with UTXO selection
- Wallet Screen (282 LOC) - Token cards with RPC balance queries
- Contacts Sidebar (291 LOC) - Contact list with add/sync controls
- Layout Manager (260 LOC) - Mobile/desktop responsive layouts
- Message Wall Screen (324 LOC) - Wall post viewing/posting
- Transaction History Dialog (304 LOC) - Paginated TX history
- Add Contact Dialog (232 LOC) - Contact adding with DHT validation
- Profile Editor (229 LOC) - Profile editing with DHT sync
- Register Name (184 LOC) - DHT name registration wizard
- Settings Screen (164 LOC) - Theme and sync settings
- Wallet Receive (94 LOC) - QR codes and address display

**2. Helper Modules** (`imgui_gui/helpers/`)
- Data Loader (447 LOC) - Async database loading with callbacks

**3. Core** (`imgui_gui/core/`)
- App State - Centralized state structure with all UI data

### Adding New Screens

1. Create `screens/new_screen.{h,cpp}` following namespace pattern
2. Include `../core/app_state.h` and required UI helpers
3. Add `render(AppState& state)` as primary entry point
4. Use `AppState&` captures in lambdas (not `DNAMessengerApp*`)
5. Add to `CMakeLists.txt` in `add_executable()` sources
6. Call from `app.cpp` via `NewScreen::render(state)`

---

## Development Guidelines

| Area | Guidelines |
|------|-----------|
| **Code Style** | C: K&R, 4-space • C++ ImGui: C++17, camelCase, STL • Qt: deprecated (reference) • Clear comments • Always free memory, check NULL |
| **Cryptography** | **DO NOT modify primitives** without expert review • Use `dna_api.h` API • Memory-based ops only • Never log keys/plaintext |
| **Database** | **SQLite only** (no PostgreSQL) • Messages: `~/.dna/messages.db` • Contacts: `~/.dna/<identity>_contacts.db` (per-identity, DHT sync, Kyber1024 self-encrypted, SHA3-512 keys, auto-migrated) • Profiles: `~/.dna/<identity>_profiles.db` (per-identity, 7d TTL, cache-first) • Groups: DHT + local cache (UUID v4, SHA256 keys, JSON) • Keyserver: `~/.dna/keyserver_cache.db` (7d TTL, BLOB) • Use prepared statements (`sqlite3_prepare_v2`, `sqlite3_bind_*`), check returns |
| **GUI** | **ImGui (ACTIVE)**: Modular namespace-based screens (`screens/` + `helpers/`), centralized `AppState` struct, async tasks via `state.task_queue`, theme-aware colors, mobile-responsive • **Qt5 (DEPRECATED)**: signals/slots, reference only |
| **Wallet** | Read from `~/.dna/` or system dir • Use `cellframe_rpc.h` API • Amounts as strings (preserve precision) • Smart decimals (8 for tiny, 2 normal) • Minimal TX builder (no JSON-C) |
| **Cross-Platform** | Linux (primary) • Windows (MXE cross-compile) • CMake build • Avoid platform-specific code • Test both before commit |

### DHT Storage TTL Settings

| Data Type | TTL | DHT Key | Rationale |
|-----------|-----|---------|-----------|
| **Identity Keys** | **PERMANENT** | `SHA3-512(fingerprint + ":pubkey")` | Core crypto identity persists indefinitely |
| **Name Registration** | **365 days** | `SHA3-512(name + ":lookup")` | Annual renewal prevents squatting (FREE in alpha) |
| **Reverse Mapping** | **365 days** | `SHA3-512(fingerprint + ":reverse")` | Sender ID without pre-adding contact |
| **Contact Lists** | **PERMANENT** | `SHA3-512(identity + ":contactlist")` | Multi-device sync (Kyber1024 self-encrypted, signed) |
| **User Profiles** | **7 days** | `SHA3-512(fingerprint + ":profile")` | Display name, bio, avatar (cached locally) |
| **Offline Queue** | **7 days** | `SHA256(sender + ":outbox:" + recipient)` | Sender outbox model (Model E), signed |
| **Groups** | **7 days** | `SHA256(group_uuid)` | Active groups update frequently |
| **Wall Posts** | **7 days** | `SHA3-512(post_id)` | Social media posts (FREE in alpha) |

**API:** `dht_put_permanent()` (never expires), `dht_put_signed_permanent()` (signed+permanent), `dht_put_ttl(ctx, key, val, 365*24*3600)` (365d), `dht_put()` (7d default) • Custom ValueTypes: `DNA_TYPE_7DAY` (0x1001), `DNA_TYPE_365DAY` (0x1002)

---

## Phase 8: cpunk Wallet Integration ✅ (2025-10-23)

**Implemented:** WalletDialog (card-based token display, RPC balance queries, recent 3 TX, Send/Receive/DEX/History) • SendTokensDialog (TX builder, UTXO selection, 0.002 CELL fee, Dilithium sigs, RPC submit) • ReceiveDialog (addresses per network, QR codes, copy-to-clipboard) • TransactionHistoryDialog (pagination, color-coded arrows, status display) • ThemeManager (singleton, signal-based, cpunk.io cyan/cpunk.club orange)

**Decisions:** No wallet selection (already in context) • Smart decimals (8 for tiny, 2 normal) • Direct RPC (no external utils) • Theme-aware dialogs • Minimal TX serialization (cross-platform)

---

## Phase 9.1 & 9.2: P2P Transport & Offline Queue ✅ (2025-11-02, fixed 2025-11-10)

**9.1 - P2P Transport:** OpenDHT integration (3 bootstrap nodes US/EU, peer registration/lookup, SHA256 keys) • TCP port 4001 (Kyber512 + AES-256-GCM) • Hybrid delivery (P2P → DHT queue → SQLite fallback)

**9.2 - Offline Queue:** `dht/dht_offline_queue.c/h` (binary serialization, magic bytes, 7d TTL, SHA256 queue keys, single-queue-per-recipient) • Encrypted DHT storage, auto-append, network byte order • 2-min polling (ImGui `app.cpp`), auto-deliver to SQLite • Integration: `p2p_transport.c` (queue/retrieve API), `messenger_p2p.c` (hybrid send)

**Critical Bug Fix (2025-11-10):** Queue key mismatch - sender used display name ("alice"), receiver used fingerprint → keys didn't match. **Solution:** `resolve_identity_to_fingerprint()` in `messenger_p2p.c:155-178` ensures all queue ops use fingerprints (leverages `messenger_load_pubkey()` + DHT keyserver lookup)

**Model E Migration (2025-11-11):** Solved DHT value accumulation problem (8-40 values per user) by migrating from recipient-based inbox to sender-based outbox architecture.

**Problem:** Unsigned `dht_put()` with auto-generated random IDs → every message created new DHT value → quadratic accumulation (8-40 values observed).

**Solution (Model E - Sender Outbox):**
- **DHT Key:** Changed from `SHA3-512(recipient + ":offline_queue")` to `SHA3-512(sender + ":outbox:" + recipient)`
- **Put Type:** Uses `dht_put_signed()` with fixed `value_id=1` → old values REPLACED (not accumulated)
- **Retrieval:** Recipient queries all contacts' outboxes (N queries per login) instead of single inbox query
- **Polling:** Removed continuous 5-second polling → check once on login only
- **Security:** Only queries known contacts (spam prevention), Dilithium5 signed puts

**Test Results:** `dht/test_signed_put.c` verified signed puts with same `value_id` reliably replace old values (3 consecutive PUTs → always 1 DHT value, never accumulation).

**Implementation:** Updated 9 files (~353 lines changed): `dht_offline_queue.[ch]` (renamed functions, multi-contact retrieval), `p2p_transport.c` (contact list integration), `imgui_gui/app.cpp` (removed polling, added login-time check), `imgui_gui/core/app_state.[ch]` (removed polling state). **Migration:** Old messages ignored (7-day TTL expiry), no backward compatibility (breaking change).

**Result:** Zero accumulation (1 value per sender outbox), 99.9% reduction in DHT queries (login-only vs continuous polling), spam prevention (contact allow-list). **Docs:** `/opt/dna-messenger/docs/MODEL_E_MIGRATION.md` (18,000+ words comprehensive analysis).

## Phase 9.3: PostgreSQL → SQLite Migration ✅ (2025-11-03)

**Implemented:** Removed PostgreSQL, migrated to `~/.dna/messages.db` • DHT Groups `dht/dht_groups.c/h` (882 lines, NO STUBS - UUID v4, SHA256 keys, JSON, local cache, 8 CRUD ops) • Keyserver Cache `keyserver_cache.c/h` (7d TTL, cache-first, BLOB storage, cross-platform, integrated into `messenger_load_pubkey()`) • 11 group functions in `messenger_stubs.c` (uses DHT via `p2p_transport_get_dht_context()`) • Bootstrap scripts: `deploy-bootstrap.sh` (automated VPS deployment), `monitor-bootstrap.sh` (10 checks, color-coded)

**Files:** `dht/dht_groups.[ch]` (237+882), `keyserver_cache.[ch]` (130+428), `deploy-bootstrap.sh` (130+), `monitor-bootstrap.sh` (200+)

## Phase 9.4: DHT Keyserver + Signed Reverse Mapping ✅ (2025-11-04)

**Implemented:** Forward mapping (existing): `SHA256(identity + ":pubkey")` → signed pubkey • Reverse mapping (NEW): `SHA256(fingerprint + ":reverse")` → signed identity (dilithium_pubkey, identity, timestamp, fingerprint, signature over pubkey||identity||timestamp) • `dht_keyserver_reverse_lookup()` (verifies fingerprint + Dilithium5 sig, returns 0/-1/-2/-3) • P2P sender ID in `messenger_p2p.c` `extract_sender_from_encrypted()` (two-tier: contacts cache → DHT reverse mapping)

**Security:** Signed reverse mappings prevent spoofing • Fingerprint verification prevents pubkey substitution • Cross-platform network byte order

**Use Case:** Bob sends to Alice WITHOUT pre-adding contact → Alice extracts fingerprint → DHT reverse lookup → displays "Bob" instead of "unknown"

**Files:** `dht/dht_keyserver.[ch]` (+150), `messenger_p2p.c` (+40)

---

## Phase 9.5: Per-Identity Contacts + DHT Sync ✅ (2025-11-05)

**Implemented:** Per-identity SQLite `~/.dna/<identity>_contacts.db` (isolated, auto-migrated from global, 170+ lines) • DHT sync `dht/dht_contactlist.c/h` (820 lines - SHA3-512 keys, JSON, Kyber1024 self-encryption, Dilithium5 sigs, 7d TTL, binary format) • Multi-device via BIP39 (same seed → same keys → decrypt own contacts) • Messenger API: `messenger_sync_contacts_to_dht()`, `messenger_fetch_contacts_from_dht()` (240+ lines) • GUI: ImGui sync UI (10-min auto-sync)

**Security:** Kyber1024 self-encryption (owner-only decrypt) • Dilithium5 sig (tamper-proof) • No plaintext in DHT • Multi-device without compromise

**Files:** `dht/dht_contactlist.[ch]` (207+820), `contacts_db.[ch]` (+170), `messenger.[ch]` (+240), `imgui_gui/app.cpp` (sync UI) • **Total:** 1,469+ lines

---

## Phase 9.6: Encrypted DHT Identity Backup ✅ (2025-11-13)

**Problem:** OpenDHT requires permanent RSA-2048 identity for signing DHT operations. Ephemeral identities cause DHT value accumulation (can't replace old values). BIP39 seed recovery needs to restore DHT identity across devices.

**Solution:** Encrypted DHT identity backup system using Kyber1024 + AES-256-GCM. Random RSA-2048 identity is generated once, encrypted with user's Kyber1024 public key, stored locally and in DHT with PERMANENT TTL. BIP39 seed recovery restores Kyber1024 keys → decrypts DHT identity → seamless cross-device sync.

**Implementation:**

**1. Encrypted Backup System** (`dht/dht_identity_backup.[ch]` - 595 lines):
- `dht_identity_create_and_backup()`: Generate random RSA-2048, encrypt with Kyber1024+AES-256-GCM
- `dht_identity_load_from_local()`: Load from `~/.dna/<fingerprint>_dht_identity.enc`
- `dht_identity_fetch_from_dht()`: Fetch from DHT (recovery on new device)
- `dht_identity_publish_backup()`: Publish encrypted backup to DHT
- Encryption format: `[kyber_ct(1568)][iv(12)][tag(16)][encrypted_pem]`

**2. DHT Integration** (`dht_context.cpp` +327 lines):
- `dht_context_start_with_identity()`: Start DHT with user-provided permanent identity
- `dht_identity_generate_random()`: Generate random RSA-2048 OpenDHT identity
- `dht_identity_export_to_buffer()`: Export identity to PEM format (key + cert)
- `dht_identity_import_from_buffer()`: Import identity from PEM buffer
- Opaque handle pattern: C wrapper for C++ `dht::crypto::Identity`

**3. Singleton Pattern** (`dht_singleton.[ch]` +61 lines):
- `dht_singleton_init_with_identity()`: Initialize DHT singleton with permanent identity
- Replaces ephemeral identity with user's permanent identity on login

**4. Messenger Integration**:
- **First-time user** (`messenger.c:541-562`): Auto-create DHT identity after Kyber1024+Dilithium5 key generation
- **Subsequent logins** (`messenger.c:220-299`): `messenger_load_dht_identity()` loads from local file or DHT
- **ImGui integration** (`app.cpp:1219-1230`): Load DHT identity after messenger init, reinitialize DHT singleton

**Storage:**
- **Local:** `~/.dna/<fingerprint>_dht_identity.enc` (6770 bytes)
- **DHT Key:** `SHA3-512(fingerprint + ":dht_identity")`
- **DHT TTL:** PERMANENT (never expires)

**Security:**
- Kyber1024 KEM (Category 5 post-quantum)
- AES-256-GCM authenticated encryption
- Only user with Kyber1024 private key can decrypt
- Permanent DHT identity prevents value accumulation bug

**Workflow:**

**First-time user (create identity):**
1. User enters BIP39 seed → generates Kyber1024 + Dilithium5 keys
2. System generates random RSA-2048 DHT identity
3. Encrypts identity with Kyber1024 public key
4. Saves to `~/.dna/<fingerprint>_dht_identity.enc`
5. Publishes encrypted backup to DHT (PERMANENT TTL)

**Subsequent login (same device):**
1. Load Kyber1024 private key from `~/.dna/<fingerprint>.kem`
2. Load encrypted DHT identity from local file
3. Decrypt with Kyber1024 private key
4. Reinitialize DHT singleton with permanent identity

**Recovery (new device with BIP39 seed):**
1. Restore Kyber1024 + Dilithium5 keys from BIP39 seed
2. Fetch encrypted DHT identity from DHT
3. Decrypt with restored Kyber1024 private key
4. Reinitialize DHT with recovered identity

**Testing:**
- `test_identity_backup.c` (300 lines): 4 comprehensive tests
- ✅ Test 1: Create DHT identity and backup
- ✅ Test 2: Load from local file
- ✅ Test 3: Reinitialize DHT with permanent identity
- ✅ Test 4: Check local file existence
- **All tests passed** with zero errors/warnings

**Files:**
- **Created:** `dht/dht_identity_backup.[ch]` (130+465), `test_identity_backup.c` (300)
- **Modified:** `dht_context.[ch]` (+327), `dht_singleton.[ch]` (+61), `messenger.[ch]` (+89), `imgui_gui/app.cpp` (+12), `dht/CMakeLists.txt` (added platform/AES sources), `CMakeLists.txt` (test target)
- **Total:** 1,484+ new lines

**Result:** Seamless BIP39 recovery with permanent DHT identity. Zero DHT value accumulation. Multi-device sync without centralized server.

---

## Phase 4: Fingerprint-First Identity Creation ✅ (2025-11-05)

**Problem:** Old flow created human-readable filenames (`alice.dsa`) then migrated to fingerprints - redundant

**Solution:** New identities use fingerprint filenames from start: `~/.dna/<fingerprint>.dsa/.kem` (SHA3-512 = 128 hex = 64 bytes) • `messenger.c:365-474` computes fingerprint after Dilithium5 keygen, saves with fingerprint names • `CreateIdentityDialog` validates via DHT (not local files) • `IdentitySelectionDialog` scans fingerprint files, uses DHT reverse lookup for display names, falls back to shortened (first10...last10)

**Files:** `messenger.c`, `gui/CreateIdentityDialog.cpp`, `gui/IdentitySelectionDialog.cpp` • **Note:** `MigrateIdentityDialog` still needed for pre-Phase4 identities

---

## Category 5 Cryptography Upgrade ✅ (2025-11-04)

**Upgrade:** Cat 3 (192-bit) → Cat 5 (256-bit) • Kyber 512→1024 (ML-KEM-768→ML-KEM-1024) • Dilithium 3→5 (ML-DSA-65→ML-DSA-87) • SHA-256→SHA3-512 (32→64 bytes)

**Key Sizes:** Kyber pub 800→1568 (+768), sec 1632→3168 (+1536), cipher 768→1568 (+800) • Dilithium pub 1952→2592 (+640), sec 4032→4896 (+864), sig 3309→4627 (+1318) • Fingerprint 32→64 (+32)

**Implemented:** Vendored `pq-crystals/dilithium` w/ `DILITHIUM_MODE=5` • SHA3-512 utils • 12 files, 122+ hardcoded size updates • Msg format versions: `DNA_ENC_VERSION` 0x05→0x06, `PQSIGNUM_PUBKEY_VERSION` 0x01→0x02 • DB schemas (BLOB/TEXT, no migration) • Build fixes • Keyserver updates

**⚠️ BREAKING:** v0.06 messages ≠ v0.05 • SHA3-512 DHT keys ≠ SHA-256 • All keys must regenerate • **Migration:** Backup wallet → upgrade binary → create new identity → auto-publish to DHT

**Security:** Cat 5 = secure beyond 2050+ • NIST FIPS 204 (ML-DSA) + FIPS 203 (ML-KEM) • AES-256 equivalent

---

## Phase 5: Web Messenger 🚧 (branch: `feature/web-messenger`)

**Done:** ✅ DNA API → WebAssembly (dna_wasm.js/wasm) • ✅ JavaScript wrappers • ✅ Emscripten toolchain

**Todo:** ⬜ HTML5/CSS3 responsive UI • ⬜ Browser messaging interface • ⬜ IndexedDB key storage • ⬜ Real-time updates (WebSocket)

---

## Phase 10.1: User Profiles ✅ (2025-11-12)

**Implemented:** DHT profile storage (`dht_profile.c`, 470 lines) • Profile cache database (`profile_cache.c`, 550 lines) • Smart fetch manager (`profile_manager.c`, 235 lines) • Auto-integration (contact add, message receive, app startup) • 7-day TTL with stale fallback

**Profile Fields:** Display name (64 chars) • Bio (512 chars) • Avatar hash (SHA3-512) • Location (64 chars) • Website (256 chars) • Timestamps (created_at, updated_at)

**Architecture:** Cache-first (instant) → DHT fallback (if expired) → Stale fallback (if DHT fails) • Per-identity SQLite (`~/.dna/<identity>_profiles.db`) • Dilithium5 signatures • Background refresh on startup

**Files:** `dht/dht_profile.[ch]` (140+470), `profile_cache.[ch]` (165+550), `profile_manager.[ch]` (100+235), integration in `app.cpp` + `messenger_p2p.c`

---

## Phase 10.2: DNA Board Alpha - Censorship-Resistant Social Media 🚧 (2025-11-12)

**Overview:** Censorship-resistant wall posts • NO DELETION (7-day TTL auto-expire) • FREE posting (no CPUNK costs in alpha) • No PoH requirements (alpha) • Dilithium5 signatures for authenticity

**Alpha Features:** Text posts (5K chars) • Comment threading (reply_to) • DHT storage (7-day TTL) • Free posting/commenting • No validators (DHT-only)

**Status:**
- ✅ Wall posting system (legacy `dna_message_wall.c` - 18,717 lines, working)
- ✅ Wall viewing from message window ("Wall" button exists, fully functional)
- ✅ Profile editor (edit own profile: display name, bio, location, website)
- ✅ API design (`dht/dht_wall.h` - new alpha architecture, not yet implemented)

**Pending Implementation:**

1. **Profile Viewing** (view others' profiles):
   - Add "Profile" button next to "Wall" button in message window header (`app.cpp:2320`)
   - Implement `renderContactProfileDialog()` to display contact profiles
   - Show: display name, bio, location, website, social links, crypto addresses
   - "Refresh" button to force DHT fetch (ignore cache)

2. **Profile Schema Extensions**:
   - Add social links: Telegram, Twitter, GitHub, Discord handles (`dht_profile.h`)
   - Add crypto address field: CPUNK/CELL addresses for tipping
   - Update profile editor with new input fields
   - Update JSON serialization (`dht_profile.c`)

3. **Comment Threading**:
   - Add `reply_to` field to wall posts (`dna_message_wall.c`)
   - Build thread tree client-side (no parent post updates - avoids DHT conflicts)
   - Add "Reply" button below wall posts
   - Implement nested comment UI with indentation
   - Show "Replying to: [parent text]" above input when replying

**Implementation Strategy:** Keep simple for alpha - use existing legacy wall system (`dna_message_wall.c`), add profile viewing and basic comment threading. Full social features (feed aggregation, avatars, voting) planned post-alpha.

**Future Enhancements:**
- Social feed window (aggregated contacts' posts)
- Avatar display (IPFS/DHT storage)
- Migration to new `dht_wall.c` system (individual posts vs aggregated array)
- Post voting/reactions
- Media uploads (images, videos)

**Note:** Validators, PoH, payments, media uploads will be added post-alpha (v1.0). Current focus: core functionality and UX.

**Spec:** `/DNA_BOARD_PHASE10_PLAN.md` (original plan - full features planned for v1.0)

---

## Phase 11: Post-Quantum Voice/Video Calls 📋 (~20 weeks, requires Phase 9.1)

**Overview:** Quantum-safe voice/video via Kyber1024 + SRTP (bypasses WebRTC's quantum-vulnerable DTLS)

**Tech:** libnice, libsrtp2, libopus, libvpx/libx264, PortAudio • Kyber1024 key exchange • Dilithium5 sigs • Forward secrecy • SAS verification

**Spec:** `/futuredesign/VOICE-VIDEO-DESIGN.md`

---

## Common Tasks

**Add Feature:** Check ROADMAP.md → Follow code patterns → Update CMakeLists.txt → Test Linux → Test Windows → Update docs

**Build:** `mkdir build && cd build && cmake .. && make -j$(nproc)` (Linux) • `./build-cross-compile.sh windows-x64` (Windows cross-compile)

**Run:** `./build/imgui_gui/dna_messenger_imgui` (active) • `./build/gui/dna_messenger_gui` (Qt deprecated)

---

## API Quick Reference

```c
// DNA Core (dna_api.h)
dna_context_t* dna_context_new(void);
int dna_encrypt_message(const uint8_t *plaintext, size_t len, const public_key_t *key, dna_buffer_t *out);
int dna_decrypt_message(const uint8_t *ciphertext, size_t len, const private_key_t *key, dna_buffer_t *out);

// Cellframe RPC (cellframe_rpc.h)
int cellframe_rpc_call(cellframe_rpc_request_t *req, cellframe_rpc_response_t **resp);

// Wallet (wallet.h)
int wallet_list_cellframe(wallet_list_t **list);
int wallet_get_address(const cellframe_wallet_t *wallet, const char *network, char *out);
```

---

## Testing & Troubleshooting

**Manual Test:** Messaging (send between users, verify enc/dec, check receipts) • Groups (create, send, add/remove members) • Wallet (balances match CLI, send TX + verify on explorer, check history)

**Debug:** Use `printf("[DEBUG] ...")` w/ prefixes `[DEBUG TX]`, `[DEBUG RPC]` • Remove before commit

**Common Issues:** Wallet 0.00 (check Cellframe node port 8079, RPC enabled, wallet file exists) • TX fails (check balance+fee, UTXO query, fee address, signature) • Theme (init ThemeManager before dialog, connect `themeChanged` signal, call `applyTheme()`) • Windows cross-compile (check MXE `~/.cache/mxe/`, deps, toolchain path)

---

## Security

**Model:** Kyber1024 + AES-256-GCM (Cat 5) • Dilithium5 sigs (Cat 5) • E2E encryption • Keys local (`~/.dna/`)

**Limitations:** No forward secrecy (planned Phase 7) • Metadata not protected • No multi-device sync yet • No disappearing messages

**Best Practices:** Never log keys/plaintext • Validate all inputs • Check crypto return codes • Secure memory (mlock future)

---

## Git Workflow

**Branches:** `main` (stable), `feature/*` (new features), `fix/*` (bug fixes)

**Commits:** Short summary (<50 chars) + details (what/why/breaking) + `🤖 Generated with Claude Code\nCo-Authored-By: Claude <noreply@anthropic.com>`

**Pre-Commit:** Test Linux → Cross-compile Windows → Remove debug → Update docs → Check leaks (valgrind)

**⚠️ PUSH TO BOTH REPOS (MANDATORY):**
```bash
git add . && git commit -m "msg"
git push gitlab main    # GitLab (primary: CI/CD, builds)
git push origin main    # GitHub (mirror: public, community)
```

**Or use:** `./push_both.sh` (checks uncommitted, verifies remotes, pushes both, color-coded output)

**Setup remotes (if needed):**
```bash
git remote add gitlab ssh://git@gitlab.cpunk.io:10000/cpunk/dna-messenger.git
git remote add origin git@github.com:nocdem/dna-messenger.git
```

---

## Resources

**Docs:** `README.md`, `ROADMAP.md`, `dna_api.h` (inline), `docs/` (specs/logs/guides)

**Links:** [Cellframe](https://wiki.cellframe.net) • [Cellframe Dev](https://dev-wiki.cellframe.net) • [Qt5](https://doc.qt.io/qt-5/) • [Kyber](https://pq-crystals.org/kyber/) • [Dilithium](https://pq-crystals.org/dilithium/)

**Repos:** [GitLab (primary)](https://gitlab.cpunk.io/cpunk/dna-messenger) • [GitHub (mirror)](https://github.com/nocdem/dna-messenger)

**Contact:** [cpunk.io](https://cpunk.io) • [cpunk.club](https://cpunk.club) • [Telegram @chippunk_official](https://web.telegram.org/k/#@chippunk_official)

---

## Version History

| Version | Date | Milestone |
|---------|------|-----------|
| 0.1.0 | 2025-10-14 | Fork from QGP |
| 0.2.0 | 2025-10-15 | Library API |
| 0.4.0 | 2025-10-17 | GUI + groups |
| 0.8.0 | 2025-10-23 | Wallet |
| 0.5.0 | TBD | Web messenger |

**Current:** 0.1.120+ (auto-incremented) • **Note:** CLI (0.3.0) removed 2025-11-05 (use GUI)

---

**When in doubt:** Check code patterns, follow conventions. Priority: simplicity, security, cross-platform.
