# DNA Messenger - Development Guidelines for Claude AI

**Last Updated:** 2025-11-14 | **Phase:** 10 (DNA Board Alpha) | **Complete:** 4, 8, 9.1-9.6, 10.1, Full Modularization

**Recent Updates:**
- ✅ Directory reorganization: 59 files → 8 core files in root
- ✅ Modularization: 10,110 LOC extracted into 39 focused modules (91.2% reduction)
- ✅ Phase 9.6: Encrypted DHT identity backup (Kyber1024 + AES-256-GCM, BIP39 recovery)
- ✅ Phase 10.1: Profile system (DHT storage + 7-day cache)
- ✅ Contact Profile Viewer (chat screen, displays bio/addresses/social links)
- 🚧 Phase 10.2: Wall posts (censorship-resistant social media - alpha)

---

## Project Overview

Post-quantum E2E encrypted messenger with cpunk wallet. **NIST Category 5 security** (256-bit quantum).

**Crypto:** Kyber1024 (ML-KEM-1024), Dilithium5 (ML-DSA-87), AES-256-GCM, SHA3-512

**Key Features:** E2E encrypted messaging • DHT groups • Per-identity contacts with DHT sync • User profiles • Wall posts • cpunk wallet (CPUNK/CELL/KEL) • P2P + DHT peer discovery • Offline queueing (7d) • Encrypted DHT identity backup (BIP39) • Local SQLite • Cross-platform (Linux/Windows) • ImGui GUI

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
├── crypto/                  # PQ cryptography (ORGANIZED)
│   ├── dsa/                 # Dilithium5 (ML-DSA-87) - vendored pq-crystals
│   ├── kem/                 # Kyber1024 (ML-KEM-1024) - vendored pq-crystals
│   ├── cellframe_dilithium/ # Cellframe Dilithium (compatibility)
│   ├── utils/               # Crypto utilities (24 files)
│   │   ├── qgp_*.{c,h}      # QGP crypto wrappers (dilithium, kyber, aes, sha3, random, platform)
│   │   ├── aes_keywrap.*    # AES key wrapping (RFC 3394)
│   │   ├── armor.*          # ASCII armor encoding/decoding
│   │   ├── base58.*         # Base58 encoding (blockchain addresses)
│   │   └── kyber_deterministic.* # Deterministic Kyber key generation from seed
│   └── bip39/               # BIP39 implementation (5 files)
│       ├── bip39.*          # Mnemonic generation/validation
│       ├── bip39_pbkdf2.*   # PBKDF2 key derivation
│       ├── bip39_wordlist.h # 2048-word English wordlist
│       └── seed_derivation.* # Master seed derivation
├── blockchain/              # Blockchain integration (13 files)
│   ├── wallet.*             # Cellframe .dwallet file handling
│   ├── blockchain_rpc.*     # RPC client (balance, TX history, submit)
│   ├── blockchain_addr.*    # Address utilities (base58, network prefixes)
│   ├── blockchain_tx_builder_minimal.* # Minimal TX builder (no JSON-C dependency)
│   ├── blockchain_sign_minimal.*       # TX signing with Dilithium
│   ├── blockchain_json_minimal.*       # Minimal JSON serialization
│   ├── blockchain_minimal.h # TSD type definitions
│   └── dna-send.c           # CLI tool for sending transactions
├── database/                # Local SQLite storage (10 files)
│   ├── contacts_db.*        # Per-identity contacts (~/.dna/<identity>_contacts.db)
│   ├── keyserver_cache.*    # Public key cache (7-day TTL)
│   ├── presence_cache.*     # User presence tracking
│   ├── profile_cache.*      # Profile cache (7-day TTL)
│   └── profile_manager.*    # Smart profile fetching (cache-first + DHT fallback)
├── dht/                     # DHT layer (MODULAR)
│   ├── keyserver/           # DHT keyserver (6 modules, 1,953 LOC extracted)
│   │   ├── keyserver_core.h # Shared types and declarations
│   │   ├── keyserver_publish.c    # Key publishing (345 LOC)
│   │   ├── keyserver_lookup.c     # Key lookup (442 LOC)
│   │   ├── keyserver_names.c      # Name registration/lookup (337 LOC)
│   │   ├── keyserver_profiles.c   # Profile publishing/fetching (430 LOC)
│   │   ├── keyserver_addresses.c  # Address lookup (75 LOC)
│   │   └── keyserver_helpers.c    # Shared utilities (325 LOC)
│   ├── dht_context.*        # OpenDHT C++ wrapper (singleton pattern)
│   ├── dht_singleton.*      # Global DHT instance management
│   ├── dht_offline_queue.*  # Offline message queueing (7-day TTL, Model E)
│   ├── dht_groups.*         # DHT groups (UUID v4, JSON, local cache)
│   ├── dht_contactlist.*    # Contact list sync (Kyber1024 self-encrypted)
│   ├── dht_profile.*        # User profiles (DHT storage, 7-day TTL)
│   ├── dht_wall.*           # Wall posts (censorship-resistant social media)
│   ├── dht_identity_backup.* # Encrypted DHT identity backup (Kyber1024 + AES-256-GCM)
│   ├── deploy-bootstrap.sh  # Automated VPS deployment (3 bootstrap nodes)
│   └── monitor-bootstrap.sh # Health monitoring (10 checks, color-coded)
├── p2p/                     # P2P transport (MODULAR)
│   ├── transport/           # P2P transport modules (4 modules, 992 LOC extracted)
│   │   ├── transport_core.h # Shared types and declarations (189 LOC)
│   │   ├── transport_tcp.c  # TCP connections (port 4001, Kyber512 + AES-256-GCM, 239 LOC)
│   │   ├── transport_discovery.c # DHT peer registration/lookup (230 LOC)
│   │   ├── transport_offline.c   # Offline queue integration (169 LOC)
│   │   └── transport_helpers.c   # Utility functions (159 LOC)
│   └── p2p_transport.*      # High-level P2P API (165 LOC, was 992)
├── messenger/               # Messenger core (MODULAR) - 7 focused modules
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
│   ├── screens/             # Screen modules (16 modules, 4,100+ LOC extracted)
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
├── legacy-tools/            # Legacy CLI tools (9 files)
│   ├── keygen.c             # QGP key generation CLI
│   ├── sign.c               # File signing CLI
│   ├── verify.c             # Signature verification CLI
│   ├── encrypt.c            # File encryption CLI
│   ├── decrypt.c            # File decryption CLI
│   ├── export.c             # Public key export CLI
│   ├── keyring.c            # Keyring management CLI
│   ├── lookup_name.c        # DHT name lookup CLI
│   └── utils.c              # Utility functions
├── gui/                     # Qt5 GUI (DEPRECATED - preserved for reference)
├── messenger.c              # Messenger facade (473 LOC, was 3,230)
├── messenger_p2p.*          # P2P messaging integration
├── messenger_stubs.c        # DHT group function stubs
├── message_backup.*         # Message backup utilities
├── dna_api.*                # Public API (core crypto library)
├── dna_config.*             # Configuration management
└── qgp.h                    # Main QGP header
```

**Root Directory (Cleaned):**
- Reduced from **59 files** to **8 core files**
- Core files: dna_api.{c,h}, dna_config.{c,h}, messenger.{c,h}, messenger_p2p.{c,h}, messenger_stubs.c, message_backup.{c,h}, qgp.h
- All utility files moved to organized subdirectories

---

## Codebase Modularization Overview

**Completed:** 2025-11-14 | **Total:** 10,110 LOC extracted into 39 modules (91.2% reduction)

| Component | Before → After | Modules | Reduction |
|-----------|----------------|---------|-----------|
| **DHT Keyserver** | 1,967 → 14 LOC | 6 (keyserver/) | 99.3% |
| **P2P Transport** | 992 → 165 LOC | 4 (transport/) | 83.4% |
| **Messenger Core** | 3,703 → 473 LOC | 7 (messenger/) | 87.2% |
| **ImGui GUI** | 4,424 → 324 LOC | 17 (screens/ + helpers/) | 92.7% |
| **Root Directory** | 59 → 8 files | 5 subdirs | 86.4% |

### Module Patterns

**C Modules:** Shared core header • Function prefix matching module name • Error: 0=success, -1=error • Explicit includes • Context-passing

**C++ Modules:** Namespace-based • Centralized `AppState` • Stateless functions • No circular deps • Theme-aware

---

## Module Details

### DHT Keyserver (6 modules, 1,953 LOC extracted)

**Location:** `dht/keyserver/`

- `keyserver_publish.c` (345 LOC) - Key publishing, permanent DHT storage
- `keyserver_lookup.c` (442 LOC) - Key lookup, cache-first (7d TTL)
- `keyserver_names.c` (337 LOC) - Name registration/lookup (365d TTL)
- `keyserver_profiles.c` (430 LOC) - Profile publish/fetch
- `keyserver_addresses.c` (75 LOC) - Blockchain address lookup
- `keyserver_helpers.c` (325 LOC) - Shared utilities

### P2P Transport (4 modules, 827 LOC extracted)

**Location:** `p2p/transport/`

- `transport_tcp.c` (239 LOC) - TCP connections (port 4001, Kyber512 + AES-256-GCM)
- `transport_discovery.c` (230 LOC) - DHT peer registration/lookup
- `transport_offline.c` (169 LOC) - Offline queue (Model E, 7d TTL)
- `transport_helpers.c` (159 LOC) - Utilities

### Messenger Core (7 modules, 3,230 LOC extracted)

**Location:** `messenger/`

- `identity.*` (111 LOC) - Fingerprint utilities
- `init.*` (255 LOC) - Context initialization, DB setup
- `status.*` (58 LOC) - Status queries
- `keys.*` (443 LOC) - Key management, cache-first
- `contacts.*` (288 LOC) - Contact CRUD, DHT sync
- `keygen.*` (1,078 LOC) - Key generation, BIP39 recovery
- `messages.*` (1,119 LOC) - E2E encryption, P2P delivery

### ImGui GUI (17 modules, 4,100 LOC extracted)

**Location:** `imgui_gui/screens/` and `imgui_gui/helpers/`

**Top screens:** Identity Selection (849 LOC), Chat (690 LOC), Wallet Send (509 LOC), Wallet (282 LOC), Contacts (291 LOC), Layout Manager (260 LOC), Message Wall (324 LOC), TX History (304 LOC)

### Adding Features

**Messenger:**
```c
// 1. Create messenger/new_module.{h,c}
// 2. Add to CMakeLists.txt
// 3. Include in messenger.c
```

**ImGui:**
```cpp
// 1. Create screens/new_screen.{h,cpp}
// 2. Add render(AppState& state) entry point
// 3. Add to CMakeLists.txt
// 4. Call from app.cpp
```

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

Card-based UI • TX builder • UTXO selection • RPC integration • QR codes • Theme system

---

## Phase 9.1 & 9.2: P2P Transport & Offline Queue ✅ (2025-11-02)

**9.1:** OpenDHT (3 bootstrap nodes) • TCP port 4001 (Kyber512 + AES-256-GCM) • Hybrid delivery

**9.2:** Offline queue (7d TTL) • Binary serialization • Encrypted DHT storage

**Critical Fix (2025-11-10):** Queue key mismatch fixed - `resolve_identity_to_fingerprint()` ensures fingerprint-based keys

**Model E Migration (2025-11-11):** Sender outbox model → Zero DHT accumulation (was 8-40 values), 99.9% query reduction, spam prevention. Docs: `/opt/dna-messenger/docs/MODEL_E_MIGRATION.md`

## Phase 9.3: PostgreSQL → SQLite Migration ✅ (2025-11-03)

Removed PostgreSQL • DHT Groups (882 lines) • Keyserver Cache (7d TTL) • Bootstrap scripts

## Phase 9.4: DHT Keyserver + Signed Reverse Mapping ✅ (2025-11-04)

Reverse mapping: `SHA256(fingerprint + ":reverse")` → signed identity • Sender ID without pre-adding contact

## Phase 9.5: Per-Identity Contacts + DHT Sync ✅ (2025-11-05)

Per-identity SQLite `~/.dna/<identity>_contacts.db` • DHT sync (Kyber1024 self-encrypted) • Multi-device via BIP39

---

## Phase 9.6: Encrypted DHT Identity Backup ✅ (2025-11-13)

**Problem:** OpenDHT needs permanent RSA-2048 identity. BIP39 recovery must restore DHT identity.

**Solution:** Encrypted backup (Kyber1024 + AES-256-GCM). Random RSA-2048 generated once, encrypted, stored locally + DHT (PERMANENT TTL).

**Implementation:**
- `dht/dht_identity_backup.[ch]` (595 lines) - Create/load/fetch/publish
- `dht_context.cpp` (+327) - Start with identity, generate/export/import
- `dht_singleton.[ch]` (+61) - Init with permanent identity
- Encryption: `[kyber_ct(1568)][iv(12)][tag(16)][encrypted_pem]`

**Workflow:**
1. **First-time:** Generate keys → encrypt RSA-2048 → save + publish
2. **Login:** Load local → decrypt → reinit DHT
3. **Recovery:** Restore keys → fetch DHT → decrypt → reinit

**Total:** 1,484+ lines • **Result:** Seamless BIP39 recovery, zero DHT accumulation

---

## Phase 4: Fingerprint-First Identity Creation ✅ (2025-11-05)

Fingerprint filenames from start: `~/.dna/<fingerprint>.{dsa,kem}` • SHA3-512 (128 hex) • DHT validation

---

## Category 5 Cryptography Upgrade ✅ (2025-11-04)

**Cat 3 → Cat 5:** Kyber 512→1024 • Dilithium 3→5 • SHA-256→SHA3-512

⚠️ **BREAKING:** All keys must regenerate • v0.06 ≠ v0.05

**Security:** Secure beyond 2050+ • NIST FIPS 203/204 compliant

---

## Phase 5: Web Messenger 🚧 (branch: `feature/web-messenger`)

✅ WebAssembly • JS wrappers • Emscripten
⬜ HTML5 UI • Browser interface • IndexedDB • WebSocket

---

## Phase 10.1: User Profiles ✅ (2025-11-12)

DHT storage (470 lines) • Cache DB (550 lines) • Smart fetch (235 lines) • 7d TTL with stale fallback

**Fields:** Display name, bio, avatar hash, location, website, timestamps

**Architecture:** Cache-first → DHT fallback → Stale fallback • Per-identity SQLite • Dilithium5 sigs

---

## Phase 10.2: DNA Board Alpha 🚧 (2025-11-12)

**Overview:** Censorship-resistant wall posts • NO DELETION (7d TTL) • FREE (alpha) • Dilithium5 sigs

**Status:**
- ✅ Wall posting (`dna_message_wall.c` - 18,717 lines, working)
- ✅ Wall viewing ("Wall" button functional)
- ✅ Profile editor (own profile)

**Pending:**
1. Profile viewing (others' profiles) - "Profile" button + dialog
2. Profile schema extensions - Social links (Telegram, Twitter, GitHub, Discord), crypto addresses (tipping)
3. Comment threading - `reply_to` field, nested UI, "Reply" buttons

**Future:** Social feed • Avatars (IPFS) • Voting • Media uploads

**Spec:** `/DNA_BOARD_PHASE10_PLAN.md`

---

## Phase 11: Post-Quantum Voice/Video Calls 📋 (~20 weeks)

Kyber1024 + SRTP • libnice, libsrtp2, libopus • Forward secrecy • SAS verification

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
