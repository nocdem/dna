# DNA Messenger - Development Guidelines for Claude AI

**Last Updated:** 2025-11-10 | **Phase:** 5 (Web Messenger) | **Complete:** 4, 8, 9.1-9.5

**Recent Updates (2025-11-10):**
- **CRITICAL FIX:** Offline message queue - `resolve_identity_to_fingerprint()` ensures DHT queue keys use fingerprints (was using display names)
- **GUI:** Qt5 deprecated → ImGui active (`imgui_gui/`), Qt preserved in `gui/` for reference

---

## Project Overview

Post-quantum E2E encrypted messenger with cpunk wallet. **NIST Category 5 security** (256-bit quantum).

**Crypto:** Kyber1024 (ML-KEM-1024), Dilithium5 (ML-DSA-87), AES-256-GCM, SHA3-512

**Key Features:** E2E encrypted messaging • DHT-based groups • Per-identity contacts with DHT sync • cpunk wallet (CPUNK/CELL/KEL) • P2P + DHT peer discovery • Offline queueing (7-day) • Local SQLite (no centralized DB) • Cross-platform (Linux/Windows) • ImGui GUI • BIP39 recovery

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
│   ├── deploy-bootstrap.sh  # VPS deployment
│   └── monitor-bootstrap.sh # Health monitoring
├── p2p/                     # P2P transport
│   └── p2p_transport.*      # TCP + DHT
├── imgui_gui/               # ImGui GUI (ACTIVE)
│   ├── app.cpp              # Main UI
│   ├── core/                # Data structures
│   └── imgui/               # ImGui library
├── gui/                     # Qt5 GUI (DEPRECATED)
├── wallet.*                 # Cellframe wallet integration
├── cellframe_rpc.*          # RPC client
├── cellframe_tx_builder_*   # TX builder
├── messenger_p2p.*          # P2P messaging
├── messenger_stubs.c        # Group functions
├── keyserver_cache.*        # Local key cache
├── contacts_db.*            # Per-identity contacts
└── dna_api.h                # Public API
```

---

## Development Guidelines

| Area | Guidelines |
|------|-----------|
| **Code Style** | C: K&R, 4-space • C++ ImGui: C++17, camelCase, STL • Qt: deprecated (reference) • Clear comments • Always free memory, check NULL |
| **Cryptography** | **DO NOT modify primitives** without expert review • Use `dna_api.h` API • Memory-based ops only • Never log keys/plaintext |
| **Database** | **SQLite only** (no PostgreSQL) • Messages: `~/.dna/messages.db` • Contacts: `~/.dna/<identity>_contacts.db` (per-identity, DHT sync, Kyber1024 self-encrypted, SHA3-512 keys, auto-migrated) • Groups: DHT + local cache (UUID v4, SHA256 keys, JSON) • Keyserver: `~/.dna/keyserver_cache.db` (7d TTL, BLOB) • Use prepared statements (`sqlite3_prepare_v2`, `sqlite3_bind_*`), check returns |
| **GUI** | **ImGui (ACTIVE)**: Immediate mode, `AppState` struct, `task_queue` async, `apply_theme()`, cross-platform • **Qt5 (DEPRECATED)**: signals/slots, `ThemeManager::instance()`, reference only |
| **Wallet** | Read from `~/.dna/` or system dir • Use `cellframe_rpc.h` API • Amounts as strings (preserve precision) • Smart decimals (8 for tiny, 2 normal) • Minimal TX builder (no JSON-C) |
| **Cross-Platform** | Linux (primary) • Windows (MXE cross-compile) • CMake build • Avoid platform-specific code • Test both before commit |

### DHT Storage TTL Settings

| Data Type | TTL | DHT Key | Rationale |
|-----------|-----|---------|-----------|
| **Identity Keys** | **PERMANENT** | `SHA3-512(fingerprint + ":pubkey")` | Core crypto identity persists indefinitely |
| **Name Registration** | **365 days** | `SHA3-512(name + ":lookup")` | Annual renewal prevents squatting |
| **Reverse Mapping** | **365 days** | `SHA3-512(fingerprint + ":reverse")` | Sender ID without pre-adding contact |
| **Contact Lists** | **PERMANENT** | `SHA3-512(identity + ":contactlist")` | Multi-device sync (Kyber1024 self-encrypted) |
| **Offline Queue** | **7 days** | `SHA256(recipient + ":offline_queue")` | Ephemeral, delivered to SQLite when retrieved |
| **Groups** | **7 days** | `SHA256(group_uuid)` | Active groups update frequently |
| **Social Posts** | **7 days** | `SHA256(post_id)` | Ephemeral social content |

**API:** `dht_put_permanent()` (never expires), `dht_put_ttl(ctx, key, val, 365*24*3600)` (365d), `dht_put()` (7d default) • Custom ValueTypes: `DNA_TYPE_7DAY` (0x1001), `DNA_TYPE_365DAY` (0x1002)

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

## Phase 10: DNA Board - Censorship-Resistant Social Media 📋 (12 weeks, post-Phases 7-9)

**Overview:** Censorship-resistant platform on cpunk validator network • NO CENSORSHIP (no deletion) • PoH ≥70 to post • Open replies • Free voting • Burn economics • 3-replica validator network (self-healing, 30s heartbeat)

**Economics:** Post (1 CPUNK, PoH ≥70, 5K chars) • Image (2 CPUNK, 5MB) • Video (5 CPUNK, 50MB) • Reply (0.5 CPUNK, no PoH, 2K) • Vote (FREE) • **Burn:** ~16M CPUNK/year

**PoH Tiers:** Auto (75-89: behavioral) • Staked (90-94: +100 CPUNK) • DAO-Vouched (95-99: 3 vouches) • Celebrity (100: public figure)

**Implementation:** W1-2: Validator+PoH • W3-4: Gossip+3-replica • W5-6: Voting+ranking • W7-8: Qt GUI • W9-10: Media+wallet • W11-12: Testing+launch

**Spec:** `/DNA_BOARD_PHASE10_PLAN.md`

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
