# DNA Messenger - Development Guidelines for Claude AI

**Last Updated:** 2025-11-03
**Project:** DNA Messenger (Post-Quantum Encrypted Messenger)
**Current Phase:** Phase 5 (Web Messenger) - Phase 4, 8, 9.1, 9.2, 9.3 (PostgreSQL Migration) Complete

---

## Project Overview

DNA Messenger is a post-quantum end-to-end encrypted messaging platform with cpunk wallet integration. It uses Kyber512 for key encapsulation, Dilithium3 for signatures, and AES-256-GCM for symmetric encryption.

**Key Features:**
- End-to-end encrypted messaging
- Group chats with member management (DHT-based, decentralized)
- cpunk wallet integration (CPUNK, CELL, KEL tokens)
- P2P messaging with DHT-based peer discovery (OpenDHT)
- Offline message queueing (7-day DHT storage)
- Local SQLite storage (NO centralized database dependencies)
- Keyserver cache (7-day TTL, local SQLite)
- Cross-platform (Linux, Windows)
- Qt5 GUI with theme support
- BIP39 recovery phrases

---

## Current Architecture

### Components
1. **Core Library** (`libdna.a`)
   - Post-quantum cryptography (Kyber512, Dilithium3)
   - Memory-based encryption/decryption API
   - Multi-recipient support
   - Keyserver cache (SQLite with 7-day TTL)

2. **CLI Client** (`dna_messenger`)
   - Command-line interface
   - ~~PostgreSQL message storage~~ → **Local SQLite** (Phase 9.3 migration)
   - Contact management

3. **GUI Client** (`dna_messenger_gui`)
   - Qt5 desktop application
   - Modern card-based UI
   - Theme system (cpunk.io cyan, cpunk.club orange)
   - Integrated wallet with transaction history
   - Local SQLite message storage (`~/.dna/messages.db`)

4. **Wallet Integration**
   - Cellframe wallet file support (.dwallet format)
   - RPC integration with Cellframe node
   - Transaction builder and signing
   - Balance and history queries

5. **P2P Transport Layer** (Phase 9.1, 9.2, 9.3)
   - OpenDHT for peer discovery and storage
   - Direct peer-to-peer TCP connections (port 4001)
   - DHT-based offline message queueing
   - DHT-based groups (UUID v4 + SHA256 keys)
   - 3 public bootstrap nodes (US/EU)
   - Automatic message delivery with 2-minute polling
   - Bootstrap deployment scripts (automated VPS deployment)

### Directory Structure
```
/opt/dna-messenger/
├── crypto/                  # Cryptography libraries
│   ├── dilithium/          # Dilithium3 signatures
│   └── kyber512/           # Kyber512 key encapsulation
├── dht/                     # DHT layer (Phase 9.1, 9.2, 9.3)
│   ├── dht_context.*       # OpenDHT integration
│   ├── dht_offline_queue.* # Offline message queueing
│   ├── dht_groups.*        # DHT-based groups (NEW - Phase 9.3)
│   ├── deploy-bootstrap.sh # Automated bootstrap deployment (NEW)
│   ├── monitor-bootstrap.sh# Bootstrap health monitoring (NEW)
│   ├── dna-dht-bootstrap.service # Systemd service
│   └── persistent_bootstrap# DHT bootstrap server binary
├── p2p/                     # P2P transport layer (Phase 9.1)
│   ├── p2p_transport.*     # TCP connections + DHT
│   └── test_p2p_basic.c    # P2P transport tests
├── gui/                     # Qt5 GUI application
│   ├── MainWindow.*        # Main chat window
│   ├── WalletDialog.*      # Wallet balance & transactions
│   ├── SendTokensDialog.*  # Send tokens form
│   ├── ReceiveDialog.*     # Receive with QR codes
│   ├── TransactionHistoryDialog.* # Full transaction list
│   └── ThemeManager.*      # Global theme management
├── wallet.c/h              # Cellframe wallet integration
├── cellframe_rpc.c/h       # Cellframe RPC client
├── cellframe_tx_builder_minimal.c/h # Transaction builder
├── messenger_p2p.*         # P2P messaging integration
├── messenger_stubs.c       # DHT-based group functions (Phase 9.3)
├── keyserver_cache.*       # Local SQLite cache for public keys (NEW)
├── dna_api.h               # Public library API
└── CMakeLists.txt          # Build configuration
```

---

## Development Guidelines

### 1. Code Style
- **C Code:** Follow existing style (K&R-ish with 4-space indentation)
- **C++ Code (Qt):** Qt coding conventions, camelCase for methods
- **Comments:** Use clear, concise comments for complex logic
- **Memory Management:** Always free allocated memory, check for NULL

### 2. Cryptography
- **DO NOT modify crypto primitives** without expert review
- Use existing API functions from `dna_api.h`
- All encryption/decryption must use memory-based operations
- Never log or print keys or decrypted messages

### 3. Database (Migrated to SQLite - Phase 9.3)
- **Messages:** Local SQLite database (`~/.dna/messages.db`)
- **Groups:** DHT-based storage with local SQLite cache
  - UUID v4 for group identification
  - SHA256-based DHT keys
  - JSON serialization for metadata
  - Local cache for offline access
- **Keyserver Cache:** Local SQLite (`~/.dna/keyserver_cache.db`)
  - 7-day TTL with automatic expiry
  - BLOB storage for public keys
- Use prepared statements to prevent SQL injection (`sqlite3_prepare_v2`, `sqlite3_bind_*`)
- Always check return codes from SQLite operations
- NO PostgreSQL dependencies (fully decentralized)

### 4. GUI Development (Qt5)
- Use Qt signals/slots for event handling
- Apply themes via `ThemeManager::instance()`
- All dialogs should be theme-aware
- Use `setAttribute(Qt::WA_DeleteOnClose)` for modal dialogs
- Handle window focus and activation properly

### 5. Wallet Integration
- Read Cellframe wallet files from `~/.dna/` or system wallet dir
- Use `cellframe_rpc.h` API for RPC calls
- All token amounts are strings to preserve precision
- Use smart decimal formatting (8 decimals for tiny amounts)
- Transaction builder uses minimal serialization (no JSON-C in builder)

### 6. Cross-Platform Support
- **Linux:** Primary development platform
- **Windows:** Cross-compile using MXE (M cross environment)
- Use CMake for build configuration
- Avoid platform-specific code when possible
- Test on both platforms before committing

---

## Phase 8: cpunk Wallet Integration (COMPLETE)

**Status:** ✅ Complete (2025-10-23)

### What Was Implemented
1. **WalletDialog** - Main wallet view
   - Card-based token display (CPUNK, CELL, KEL)
   - Balance queries via Cellframe RPC
   - Recent 3 transactions display
   - 4-button layout: Send, Receive, DEX, History

2. **SendTokensDialog** - Send tokens
   - Transaction builder integration
   - UTXO query and selection
   - Network fee handling (0.002 CELL)
   - Dilithium signature generation
   - RPC transaction submission

3. **ReceiveDialog** - Receive tokens
   - Display wallet addresses per network
   - QR code generation
   - Easy copy-to-clipboard

4. **TransactionHistoryDialog** - Full transaction list
   - All transactions with pagination
   - Color-coded arrows (green incoming, red outgoing)
   - Status display (ACCEPTED in green, DECLINED in red)
   - Smart timestamp formatting

5. **ThemeManager** - Global theme system
   - Singleton pattern for theme management
   - Signal-based theme updates
   - Support for cpunk.io (cyan) and cpunk.club (orange)

### Key Technical Decisions
- **No wallet selection in send dialog:** Already in that wallet context
- **Smart decimal formatting:** 8 decimals for tiny amounts, 2 for normal
- **Direct RPC integration:** No external wallet utilities needed
- **Theme-aware:** All wallet dialogs respond to theme changes
- **Transaction builder:** Minimal serialization for cross-platform compatibility

---

## Phase 9.1 & 9.2: P2P Transport & Offline Message Queue (COMPLETE)

**Status:** ✅ Complete (2025-11-02)

### Phase 9.1: P2P Transport Layer (COMPLETE)
**What Was Implemented:**
1. **OpenDHT Integration** - DHT-based peer discovery
   - 3 public bootstrap nodes (US/EU)
   - Peer registration and lookup via DHT
   - SHA256-based peer keys

2. **P2P Transport** - Direct peer-to-peer messaging
   - TCP connections on port 4001
   - Post-quantum encryption (Kyber512 + AES-256-GCM)
   - Connection management and presence updates

3. **Hybrid Delivery** - Multi-tier message delivery
   - Primary: Direct P2P (if peer online)
   - Secondary: DHT queue (if peer offline)
   - Tertiary: SQLite fallback (Phase 9.3 migration)

### Phase 9.2: Offline Message Queueing (COMPLETE)
**What Was Implemented:**
1. **DHT Offline Queue** (`dht/dht_offline_queue.c/h`)
   - Binary message serialization with magic bytes
   - 7-day TTL with configurable expiry
   - SHA256-based queue keys: `hash(recipient + ":offline_queue")`
   - Single-queue-per-recipient architecture

2. **Message Storage Protocol**
   - Encrypted message storage in DHT
   - Automatic append to existing queue
   - Platform-independent network byte order (htonl/ntohl)
   - Cross-platform support (Windows/Linux)

3. **Automatic Retrieval**
   - 2-minute polling timer in GUI (`MainWindow.cpp`)
   - Automatic delivery to local SQLite when retrieved
   - Queue clearing after successful delivery
   - Message expiry handling

4. **Integration**
   - `p2p_transport.c` - Queue/retrieve API
   - `messenger_p2p.c` - Hybrid send flow
   - `gui/MainWindow.cpp` - Automatic polling

### Phase 9.3: PostgreSQL → SQLite Migration (COMPLETE)
**Status:** ✅ Complete (2025-11-03)

**What Was Implemented:**
1. **Message Storage Migration**
   - Removed all PostgreSQL dependencies from CMakeLists.txt
   - Migrated to local SQLite (`~/.dna/messages.db`)
   - Updated messenger.c to use SQLite instead of PostgreSQL

2. **DHT-Based Groups** (`dht/dht_groups.c/h`)
   - 882 lines of complete implementation (NO STUBS)
   - UUID v4 group identification (36-character format)
   - SHA256-based DHT keys for decentralized storage
   - JSON serialization for group metadata
   - Local SQLite cache for offline access
   - Full CRUD operations:
     - `dht_groups_create()` - Create group with members
     - `dht_groups_get()` - Fetch from DHT
     - `dht_groups_update()` - Update metadata
     - `dht_groups_add_member()` - Add member to group
     - `dht_groups_remove_member()` - Remove member
     - `dht_groups_delete()` - Delete group (creator only)
     - `dht_groups_list_for_user()` - List user's groups
     - `dht_groups_sync_from_dht()` - Sync local cache

3. **Keyserver Cache** (`keyserver_cache.c/h`)
   - Local SQLite cache for public keys (`~/.dna/keyserver_cache.db`)
   - 7-day TTL with automatic expiry
   - Cache-first strategy (check cache → on miss fetch API → store)
   - BLOB storage for Dilithium (1952 bytes) and Kyber (800 bytes) keys
   - Cross-platform Windows/Linux support (#ifdef _WIN32 for mkdir)
   - Integrated into `messenger_load_pubkey()` function

4. **Group Functions Migration** (`messenger_stubs.c`)
   - Completely rewrote all 11 group functions (NO STUBS):
     - `messenger_create_group()`
     - `messenger_get_group_members()`
     - `messenger_add_group_member()`
     - `messenger_remove_group_member()`
     - `messenger_list_groups()`
     - `messenger_get_group_info()`
     - `messenger_update_group()`
     - `messenger_delete_group()`
     - `messenger_leave_group()`
     - `messenger_is_group_member()`
     - `messenger_get_group_creator()`
   - All functions now use DHT via `p2p_transport_get_dht_context()`
   - Proper error handling and authorization checks

5. **Bootstrap Deployment Scripts**
   - `dht/deploy-bootstrap.sh` (130+ lines) - Automated deployment:
     - Build binary locally
     - Test SSH connectivity
     - Set hostname
     - Install dependencies
     - Stop old processes
     - Upload binary to /opt/dna-messenger/dht/build/
     - Deploy systemd service
     - Start and verify
   - `dht/monitor-bootstrap.sh` (200+ lines) - Health monitoring:
     - 10 checks per node (SSH, service, process, ports, resources, errors)
     - Color-coded output (RED/GREEN/YELLOW)
     - Summary report for all nodes

**Technical Decisions:**
- UUID v4 for globally unique group IDs
- SHA256(group_uuid) for DHT keys
- JSON for group metadata serialization
- Single-queue-per-recipient for offline messages
- 7-day cache TTL for public keys
- Opaque pointer pattern with getter functions

**Files Created:**
- `dht/dht_groups.h` (237 lines)
- `dht/dht_groups.c` (882 lines)
- `keyserver_cache.h` (130 lines)
- `keyserver_cache.c` (428 lines)
- `dht/deploy-bootstrap.sh` (130+ lines)
- `dht/monitor-bootstrap.sh` (200+ lines)

**Files Modified:**
- `CMakeLists.txt` - Removed PostgreSQL, added keyserver_cache.c
- `dht/CMakeLists.txt` - Added dht_groups.c
- `messenger.c` - Integrated keyserver cache
- `messenger_stubs.c` - Completely rewritten (570 lines)
- `p2p/p2p_transport.h` - Added getter for DHT context
- `p2p/p2p_transport.c` - Implemented getter

**Result:** DNA Messenger is now fully decentralized with NO PostgreSQL dependencies.

### Key Technical Decisions
- **Single queue per recipient:** Append all messages to one DHT entry (workaround for OpenDHT C wrapper limitations)
- **Binary serialization:** Custom format with magic bytes (0x444E4120 = "DNA ")
- **7-day TTL:** Configurable via `offline_ttl_seconds` parameter
- **2-minute polling:** Balance between responsiveness and DHT load
- **Hybrid delivery:** Ensures no message loss across all failure scenarios

### Files Modified/Created
- `dht/dht_offline_queue.h` (NEW - 170 lines)
- `dht/dht_offline_queue.c` (NEW - 650 lines)
- `dht/CMakeLists.txt` (MODIFIED)
- `p2p/p2p_transport.h` (MODIFIED - added queue API)
- `p2p/p2p_transport.c` (MODIFIED - implemented queue/retrieve)
- `messenger_p2p.h` (MODIFIED - added check API)
- `messenger_p2p.c` (MODIFIED - hybrid send flow)
- `gui/MainWindow.h` (MODIFIED - added timer)
- `gui/MainWindow.cpp` (MODIFIED - polling callback)

---

## Phase 5: Web Messenger (IN PROGRESS)

**Status:** 🚧 Active development on `feature/web-messenger` branch

### What's Done
- [x] DNA API compiled to WebAssembly (dna_wasm.js/wasm)
- [x] JavaScript wrapper functions
- [x] Emscripten toolchain setup

### What's Next
- [ ] HTML5/CSS3 responsive UI
- [ ] Browser-based messaging interface
- [ ] IndexedDB for key storage
- [ ] Real-time updates (WebSocket)

---

## Phase 10: DNA Board - Censorship-Resistant Social Media (PLANNED)

**Status:** 📋 Planning (Post-Phases 7-9)
**Timeline:** 12 weeks
**Prerequisites:** Distributed validator storage, DNA-Keyserver merge, Offline messaging

### Overview

DNA Board is a **censorship-resistant social media platform** built on cpunk validator network:

**Core Principles:**
1. **NO CENSORSHIP** - Content cannot be removed (no deletion endpoint)
2. **PoH Required to Post** - Only verified humans (PoH ≥70) can create posts
3. **Open Responses** - Anyone can reply (no PoH for replies)
4. **Community Voting** - Thumbs up/down (FREE) to surface quality
5. **Burn Economics** - All fees burned (deflationary)
6. **Validator Rewards** - DAO pool distribution

### Architecture

```
Self-Healing Validator Network (3-Replica)
┌─────────────────────────────────────┐
│  Post → Primary Validator           │
│  ↓ Replicate to 2 more (lowest GB)  │
│  ↓ 3 Validators store content       │
│  ↓ Heartbeat monitoring (30s)       │
│  ↓ Auto-heal if validator offline   │
│  ↓ Back to 3 replicas               │
└─────────────────────────────────────┘
```

### Content & Economics

| Type | Burn Fee | PoH Required | Max Size |
|------|----------|--------------|----------|
| Post | 1 CPUNK | Yes (≥70) | 5,000 chars |
| Image | 2 CPUNK | Yes | 5 MB |
| Video | 5 CPUNK | Yes | 50 MB |
| Reply | 0.5 CPUNK | **No** | 2,000 chars |
| Vote | **FREE** | No | N/A |

**Estimated burn:** 16M CPUNK/year (deflationary pressure)

### Proof of Humanity (PoH)

**Who Can Post:** humanity_score ≥ 70

**Verification Tiers:**
- Auto-Verified (75-89): Behavioral algorithm
- Staked-Verified (90-94): Auto + 100 CPUNK stake
- DAO-Vouched (95-99): 3 human vouches + DAO
- Celebrity (100): Public figure + DAO

**Bot Detection:** Single-destination sends, mechanical timing
**Human Patterns:** Multiple services, irregular timing, staking

### Implementation (12 Weeks)

- **Weeks 1-2:** Validator backend + PoH scoring
- **Weeks 3-4:** Gossip protocol + 3-replica replication
- **Weeks 5-6:** Voting system + feed ranking
- **Weeks 7-8:** Qt GUI (DNABoardTab, ComposeDialog, PostWidget)
- **Weeks 9-10:** Media upload + wallet integration
- **Weeks 11-12:** Testing + mainnet launch

### Key Features

**Censorship Resistance:**
- No deletion endpoint (content permanent)
- 3-validator replication across jurisdictions
- No central authority
- Gossip protocol ensures propagation

**Quality Control:**
- PoH prevents bot spam
- Community voting surfaces quality
- Ranking algorithm (votes × humanity × time)

**Economic Model:**
- All fees burned (deflationary)
- Validators funded by DAO pool (100M Year 1, halvening)

### Design Document

Full specification: `/DNA_BOARD_PHASE10_PLAN.md`

---

## Phase 11: Post-Quantum Voice/Video Calls (PLANNED)

**Status:** 📋 Research & Planning
**Timeline:** ~20 weeks (5 months)
**Prerequisites:** Phase 9.1 (P2P Transport Layer)
**Design Doc:** `/futuredesign/VOICE-VIDEO-DESIGN.md`

### Overview

Fully quantum-safe voice/video calls using Kyber512 via DNA messaging + SRTP (bypasses WebRTC's quantum-vulnerable DTLS).

**Technology:** libnice, libsrtp2, libopus, libvpx/libx264, PortAudio
**Security:** Kyber512 key exchange, Dilithium3 signatures, forward secrecy, SAS verification

See design doc for complete technical specification

---

## Common Tasks

### Adding a New Feature
1. Check current phase in ROADMAP.md
2. Follow existing code patterns
3. Update CMakeLists.txt if adding new files
4. Test on Linux first, then Windows
5. Update documentation (README.md, ROADMAP.md)

### Building the Project
**Linux:**
```bash
mkdir build && cd build
cmake ..
make -j$(nproc)
```

**Windows (cross-compile from Linux):**
```bash
./build-cross-compile.sh windows-x64
```

### Running Tests
```bash
# CLI messenger
./build/dna_messenger --help

# GUI messenger
./build/gui/dna_messenger_gui
```

---

## API Documentation

### DNA Core API (`dna_api.h`)
```c
// Context management
dna_context_t* dna_context_new(void);
void dna_context_free(dna_context_t *ctx);

// Encryption
int dna_encrypt_message(
    const uint8_t *plaintext, size_t len,
    const public_key_t *recipient_key,
    dna_buffer_t *output);

// Decryption
int dna_decrypt_message(
    const uint8_t *ciphertext, size_t len,
    const private_key_t *my_key,
    dna_buffer_t *output);
```

### Cellframe RPC API (`cellframe_rpc.h`)
```c
// RPC request structure
typedef struct {
    const char *method;
    const char *subcommand;
    json_object *arguments;
    int id;
} cellframe_rpc_request_t;

// Make RPC call
int cellframe_rpc_call(
    cellframe_rpc_request_t *req,
    cellframe_rpc_response_t **response);

// Free response
void cellframe_rpc_response_free(cellframe_rpc_response_t *resp);
```

### Wallet API (`wallet.h`)
```c
// Load Cellframe wallets
int wallet_list_cellframe(wallet_list_t **list);

// Get wallet address
int wallet_get_address(
    const cellframe_wallet_t *wallet,
    const char *network,
    char *address_out);

// Free wallet list
void wallet_list_free(wallet_list_t *list);
```

---

## Testing Guidelines

### Manual Testing
1. **Messaging:**
   - Send message between two users
   - Verify encryption/decryption
   - Check delivery receipts

2. **Groups:**
   - Create group with multiple members
   - Send messages to group
   - Add/remove members

3. **Wallet:**
   - View balances (should match Cellframe CLI)
   - Send transaction (verify on blockchain explorer)
   - Check transaction history

### Debug Output
- Use `printf("[DEBUG] ...")` for development
- Remove debug output before committing
- Use descriptive prefixes: `[DEBUG TX]`, `[DEBUG RPC]`

---

## Common Issues and Solutions

### Wallet Balance Shows 0.00
- Check Cellframe node is running (port 8079)
- Verify RPC is enabled in Cellframe config
- Check wallet file exists in `~/.dna/` or `/opt/cellframe-node/var/lib/wallet/`

### Transaction Fails to Send
- Ensure sufficient balance + fee
- Check UTXO query returns results
- Verify network fee address is correct
- Check signature is generated correctly

### Theme Not Applied
- Ensure ThemeManager is initialized before dialog
- Connect to `themeChanged` signal
- Call `applyTheme()` in constructor

### Windows Cross-Compile Fails
- Check MXE is installed (`~/.cache/mxe/`)
- Verify MXE dependencies are built
- Check CMake toolchain file path

---

## Security Considerations

### Current Security Model
- Post-quantum encryption (Kyber512 + AES-256-GCM)
- Message signatures (Dilithium3)
- End-to-end encryption (server cannot read)
- Private keys stored locally (`~/.dna/`)

### Known Limitations
- No forward secrecy (planned Phase 7)
- Metadata not protected (server sees sender/receiver)
- No multi-device sync yet
- No disappearing messages

### Best Practices
- Never log private keys or decrypted messages
- Validate all inputs (addresses, amounts, signatures)
- Check return codes from crypto functions
- Use secure memory management (mlock in future)

---

## Git Workflow

### Branching
- `main` - Stable releases
- `feature/*` - New features (e.g., `feature/web-messenger`)
- `fix/*` - Bug fixes

### Commit Messages
```bash
# Good commit message format:
Short summary (50 chars or less)

Detailed explanation if needed:
- What changed
- Why it changed
- Any breaking changes

🤖 Generated with Claude Code
Co-Authored-By: Claude <noreply@anthropic.com>
```

### Before Committing
1. Test on Linux
2. Cross-compile for Windows
3. Remove debug output
4. Update documentation if needed
5. Check for memory leaks (valgrind)

---

## Resources

### Documentation
- **Main README:** `/opt/dna-messenger/README.md`
- **Roadmap:** `/opt/dna-messenger/ROADMAP.md`
- **API Docs:** `/opt/dna-messenger/dna_api.h` (inline comments)

### External Links
- **Cellframe Docs:** https://wiki.cellframe.net
- **Cellframe Dev Wiki:** https://dev-wiki.cellframe.net
- **Qt5 Docs:** https://doc.qt.io/qt-5/
- **Kyber:** https://pq-crystals.org/kyber/
- **Dilithium:** https://pq-crystals.org/dilithium/

### Repositories
- **GitLab (Primary):** https://gitlab.cpunk.io/cpunk/dna-messenger
- **GitHub (Mirror):** https://github.com/nocdem/dna-messenger

---

## Contact and Support

- **cpunk.io:** https://cpunk.io
- **cpunk.club:** https://cpunk.club
- **Telegram:** https://web.telegram.org/k/#@chippunk_official

---

## Version History

| Version | Date | Description |
|---------|------|-------------|
| 0.1.0 | 2025-10-14 | Initial fork from QGP |
| 0.2.0 | 2025-10-15 | Library API complete |
| 0.3.0 | 2025-10-16 | CLI messenger complete |
| 0.4.0 | 2025-10-17 | Desktop GUI with groups |
| 0.8.0 | 2025-10-23 | cpunk Wallet integration |
| 0.5.0 | TBD | Web messenger (in progress) |

**Current Version:** 0.1.120+ (auto-incremented)

---

**Happy Coding!**

When in doubt, check existing code patterns and follow the established conventions. The project prioritizes simplicity, security, and cross-platform compatibility.
