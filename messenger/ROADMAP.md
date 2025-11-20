# DNA Messenger - Development Roadmap

**Version:** 0.1.120+
**Last Updated:** 2025-11-17
**Project Status:** Phase 6 (DNA Board) - Phase 4, 5.1-5.6, 6.1-6.3 Complete, ImGui GUI Active

---

## Overview

DNA Messenger is a post-quantum end-to-end encrypted messaging platform forked from QGP (file encryption tool). This roadmap outlines the development phases from initial fork to production-ready messenger application.

**Philosophy:** Simple first, secure later. Focus on core functionality before adding advanced security features.

---

## Phase 1: Fork Preparation ✅ COMPLETE

**Timeline:** 1-2 days
**Status:** Complete

### Objectives
- Fork QGP repository
- Update branding and documentation
- Verify build system works
- Initialize git repository

### Completed Tasks
- [x] Create fork at `/opt/dna-messenger`
- [x] Clean up build artifacts
- [x] Update `README.md` with DNA Messenger branding
- [x] Update `CLAUDE.md` with messenger development guidelines
- [x] Create `ROADMAP.md` (this file)
- [x] Update `CMakeLists.txt` (project name, version)
- [x] Update `main.c` (help text, version info)
- [x] Verify build works (`make` runs successfully)
- [x] Initialize git repository
- [x] Create initial commit

### Deliverables
- ✅ Forked repository with DNA branding
- ✅ Updated documentation
- ✅ Working build system
- ✅ Initial git commit

---

## Phase 2: Library API Design ✅ COMPLETE

**Timeline:** 1-2 weeks
**Status:** Complete

### Objectives
- Design memory-based API for messenger operations
- Refactor file-based operations to memory-based
- Create public API header (`dna_api.h`)
- Write API documentation

### Completed Tasks
- [x] Design `dna_api.h` (public API header)
- [x] Define error codes (`dna_error_t`)
- [x] Define context structure (`dna_context_t`)
- [x] Define buffer structure (`dna_buffer_t`)
- [x] Context management (`dna_context_new`, `dna_context_free`)
- [x] Key generation (`dna_keygen_signing`, `dna_keygen_encryption`)
- [x] Message encryption (`dna_encrypt_message`)
- [x] Message decryption (`dna_decrypt_message`)
- [x] Signature functions (`dna_sign`, `dna_verify`)
- [x] Multi-recipient encryption support
- [x] Refactor for memory-based operations
- [x] Buffer management utilities
- [x] API documentation

### Deliverables
- ✅ `dna_api.h` - Public API header
- ✅ `libdna.a` - Static library
- ✅ API documentation
- ✅ Integration examples

---

## Phase 3: CLI Messenger Client ✅ COMPLETE (PostgreSQL → SQLite Migration ✅)

**Timeline:** 2-3 weeks
**Status:** Complete (PostgreSQL removed 2025-11-03)

### Objectives
- Build reference messenger implementation
- Command-line chat interface
- ~~PostgreSQL message storage~~ → **Migrated to local SQLite** (2025-11-03)
- Contact management

### Completed Tasks
- [x] Command-line argument parsing
- [x] Interactive chat mode
- [x] Contact list commands
- [x] Message history commands
- [x] PostgreSQL database integration
- [x] Message persistence
- [x] Contact database
- [x] Key storage integration (`~/.dna/`)
- [x] Send message (encrypt for recipient)
- [x] Receive message (decrypt from sender)
- [x] List conversations
- [x] Search message history
- [x] Add contact (import public key)
- [x] List contacts
- [x] Delete contact
- [x] BIP39 mnemonic key generation (24 words)
- [x] File-based seed phrase restore
- [x] Keyserver verification for restored keys
- [x] Auto-login for existing identities
- [x] Windows support (cross-platform)
- [x] Message deletion
- [x] Message search/filtering by date and sender

### Deliverables
- ✅ `dna_messenger` - CLI messenger client
- ✅ PostgreSQL message database
- ✅ Contact management system
- ✅ User documentation

---

## Phase 4: Desktop Application & Wallet Integration ✅ COMPLETE

**Timeline:** 6-8 weeks (including wallet integration)
**Status:** Complete

### Objectives
- Qt-based desktop GUI (now migrated to ImGui)
- Cross-platform (Linux, Windows, macOS)
- Rich messaging features
- System notifications
- Integrated cpunk wallet

### Completed Tasks

#### GUI Development
- [x] Qt5 application framework (now deprecated, migrated to ImGui 2025-11-10)
- [x] ImGui desktop application (OpenGL3 + GLFW3)
- [x] Conversation list view (contacts and groups)
- [x] Chat window interface
- [x] Contact management UI
- [x] Settings panel (themes, font scaling)
- [x] Modern responsive UI

#### Messaging Features
- [x] Real-time message display
- [x] Message timestamps
- [x] Delivery and read receipts (✓✓ checkmarks)
- [x] Desktop notifications (system tray)
- [x] System tray integration
- [x] Auto-update mechanism
- [x] Theme switching (cpunk.io cyan, cpunk.club orange)
- [x] Dynamic font scaling (1x, 2x, 3x, 4x)
- [x] Multi-recipient encryption
- [x] Message decryption (sent and received)
- [x] Auto-detect local identity from ~/.dna/
- [x] Notification sound effects
- [x] Public key caching (100-entry cache)
- [x] Inline keyserver registration (no external utilities)

#### Group Messaging
- [x] Create groups with member selection
- [x] Group conversation display
- [x] Send messages to groups
- [x] Manage group members (add/remove)
- [x] Edit group name and description
- [x] Delete group (creator only)
- [x] Leave group (members only)
- [x] Creator marked with crown icon (👑)
- [x] Contextual Group Settings button
- [x] DHT-based groups (migrated from PostgreSQL)

#### Wallet Integration (Complete - 2025-10-23)
- [x] Read local Cellframe wallet files (.dwallet format)
- [x] Connect via RPC to Cellframe node
- [x] Display CPUNK, CELL, and KEL token balances
- [x] Send tokens directly in messenger via transaction builder
- [x] Receive tokens with QR code generation
- [x] Full transaction history with status tracking
- [x] Color-coded transaction display (green incoming, red outgoing)
- [x] Wallet address management with easy copy-to-clipboard
- [x] Transaction status notifications (ACCEPTED/DECLINED)
- [x] Theme support across all wallet dialogs
- [x] Integrated into GUI with dedicated wallet button

#### Platform Support
- [x] Linux build
- [x] Windows build (MXE cross-compilation)
- [ ] macOS build (future)
- [x] Cross-platform compilation

### Deliverables
- ✅ `dna_messenger_imgui` - ImGui desktop application (active)
- ✅ `dna_messenger_gui` - Qt5 desktop application (deprecated, reference only)
- ✅ WalletDialog - View balances and recent transactions
- ✅ SendTokensDialog - Send tokens with transaction builder
- ✅ ReceiveDialog - Display addresses with QR codes
- ✅ TransactionHistoryDialog - Full transaction history
- ✅ ThemeManager - Global theme support
- ✅ Cellframe RPC integration for balance and transaction queries
- ✅ Installation guide
- ✅ User manual (README.md)
- ✅ Platform-specific builds (Linux, Windows)
- ✅ Full group messaging feature

---

## Phase 7: Web-Based Messenger 📋 PLANNED

**Timeline:** 3-4 weeks
**Status:** Research & Planning (branch: `feature/web-messenger`)
**Prerequisites:** Phase 2 complete

### Objectives
- WebAssembly-based cryptography
- Browser-based messaging client
- No native dependencies (pure web)
- Cross-platform compatibility

### Tasks

#### WebAssembly Build
- [x] Emscripten toolchain setup
- [x] DNA API compilation to WASM
- [x] JavaScript wrapper functions
- [x] Browser crypto module export

#### Web Frontend
- [ ] HTML5/CSS3 responsive UI
- [ ] JavaScript messaging interface
- [ ] Contact list management
- [ ] Message display and composition
- [ ] Local storage for keys (IndexedDB)

#### Features
- [ ] Client-side encryption/decryption
- [ ] Message persistence (browser storage)
- [ ] Real-time updates (WebSocket)
- [ ] Responsive design (mobile-friendly)
- [ ] Progressive Web App (PWA) support

#### Platform Support
- [ ] Chrome/Chromium
- [ ] Firefox
- [ ] Safari
- [ ] Edge
- [ ] Mobile browsers

### Deliverables
- `dna_wasm.js` / `dna_wasm.wasm` - WebAssembly crypto module
- `index.html` - Web messenger interface
- Browser extension (future)
- PWA manifest and service worker

**Branch:** `feature/web-messenger`

---

_(Phase 6 (Mobile Applications) and Phase 7 (Advanced Security) merged into Phase 8+ Future Enhancements)_

---

## Phase 5: Distributed P2P Architecture ✅ COMPLETE

**Timeline:** ~6 months (long-term vision)
**Status:** COMPLETE - P2P Transport, DHT, and Offline Queue operational
**Prerequisites:** Phase 4 complete
**Design Docs:** See `/futuredesign/` folder for detailed specifications

### Objectives
- Fully peer-to-peer serverless architecture
- Distributed DHT-based keyserver
- Store-and-forward offline message delivery
- Zero-knowledge storage (storage nodes cannot read messages)
- Multi-device synchronization via DHT
- No centralized dependencies

### Tasks

#### Phase 5.1: P2P Transport Layer ✅ COMPLETE
- [x] ~~Integrate libp2p~~ **Used OpenDHT instead (C++ library for DHT)**
- [x] Implement DHT for peer discovery (OpenDHT 3.5.5)
- [x] P2P transport layer with TCP + DHT (`p2p_transport.c`)
- [x] Direct peer-to-peer messaging capability
- [x] Bootstrap node infrastructure (3 public VPS nodes):
  - US-1: dna-bootstrap-us-1 @ 154.38.182.161:4000
  - EU-1: dna-bootstrap-eu-1 @ 164.68.105.227:4000
  - EU-2: dna-bootstrap-eu-2 @ 164.68.116.180:4000
- [x] Auto-start systemd services on all bootstrap nodes
- [x] Connection management and DHT presence registration
- [x] NAT traversal using libjuice (ICE/STUN) - **COMPLETE** (Phase 11, 2025-11-19)

#### Phase 5.2: Offline Message Queueing ✅ COMPLETE
**Completed:** 2025-11-02 | **Bug Fix:** 2025-11-10

- [x] Integrate OpenDHT for offline message storage
- [x] Binary message serialization (magic bytes, timestamps, expiry)
- [x] Store-and-forward protocol for offline users
- [x] Automatic expiry (7-day TTL with configurable timeout)
- [x] Message retrieval via DHT queries
- [x] Automatic polling (2-minute timer in GUI)
- [x] Queue clearing after successful delivery
- [x] SHA256-based DHT keys (recipient + ":offline_queue")
- [x] Single-queue-per-recipient architecture
- [x] Cross-platform support (Windows/Linux network byte order)
- [x] Hybrid delivery: P2P direct → DHT queue → ~~PostgreSQL~~ SQLite fallback
- [x] **CRITICAL BUG FIX (2025-11-10):** Fixed offline queue key mismatch
  - Problem: Messages sent to display names couldn't be retrieved by fingerprints
  - Solution: Added `resolve_identity_to_fingerprint()` in `messenger_p2p.c`
  - Impact: Offline messages now work reliably across all scenarios

#### Phase 5.3: PostgreSQL → SQLite Migration ✅ COMPLETE
**Completed:** 2025-11-03

Complete migration from centralized PostgreSQL to local SQLite storage:

- [x] **Messages:** Migrated from PostgreSQL to local SQLite (`~/.dna/messages.db`)
- [x] **Groups:** Migrated from PostgreSQL to DHT-based storage with local SQLite cache
  - UUID v4 group identification (36-character format)
  - SHA256-based DHT keys for decentralized group metadata
  - JSON serialization for group data
  - Local SQLite cache for offline access
  - Full CRUD operations (create, get, update, add/remove members, delete)
  - 11 group functions completely rewritten (NO STUBS)
- [x] **Keyserver Cache:** Implemented local SQLite cache for public keys
  - 7-day TTL with automatic expiry
  - Cache-first strategy (check cache → on miss fetch API → store result)
  - BLOB storage for Dilithium (1952 bytes) and Kyber (800 bytes) keys
  - Cross-platform Windows/Linux support
- [x] **Build System:** Removed all PostgreSQL dependencies from CMakeLists.txt
- [x] **Bootstrap Deployment:** Created automated deployment scripts
  - `dht/deploy-bootstrap.sh` - Complete automated deployment (8 steps)
  - `dht/monitor-bootstrap.sh` - Comprehensive health monitoring (10 checks per node)
  - 3 public bootstrap nodes (US/EU) operational

**Result:** DNA Messenger is now fully decentralized with NO centralized database dependencies.

#### Phase 5.4: DHT-based Keyserver with Signed Reverse Mapping ✅ COMPLETE
**Completed:** 2025-11-04

Implemented cryptographically signed reverse mappings for sender identification without requiring pre-added contacts:

- [x] **Forward Mapping:** `SHA256(identity + ":pubkey")` → signed public key entry
- [x] **Reverse Mapping:** `SHA256(fingerprint + ":reverse")` → signed identity entry
  - Stores: dilithium_pubkey, identity, timestamp, fingerprint, signature
  - Signature covers: dilithium_pubkey || identity || timestamp
  - Prevents identity spoofing attacks
- [x] **dht_keyserver_reverse_lookup():** Fetches and verifies reverse mappings
  - Verifies fingerprint matches pubkey (prevents substitution)
  - Verifies Dilithium3 signature (prevents spoofing)
  - Returns: 0 (success), -1 (error), -2 (not found), -3 (verification failed)
- [x] **Sender Identification:** Integrated into P2P message receive flow
  - Two-tier lookup: contacts cache first, then DHT reverse mapping
  - Extracts fingerprint from message signature
  - Queries DHT when sender not in contacts
  - Displays actual identity instead of "unknown"
- [x] **Cross-platform Compatibility:** Network byte order for timestamps
- [x] **Security:** Signed mappings prevent identity spoofing and pubkey substitution

**Use Case:** Alice publishes keys (forward + reverse). Bob sends message to Alice WITHOUT adding her as contact. Alice receives message and DHT reverse lookup identifies "Bob" from message signature.

**Files Modified:**
- `dht/dht_keyserver.c` - Added signed reverse mapping storage and lookup (150+ lines)
- `dht/dht_keyserver.h` - Added reverse lookup function declaration
- `messenger_p2p.c` - Integrated reverse lookup into message receive flow (40+ lines)

#### Phase 5.5: Per-Identity Contact Lists with DHT Sync ✅ COMPLETE
**Completed:** 2025-11-05

Implemented per-identity contact lists with DHT synchronization for multi-device support:

#### Phase 5.6: P2P Group Invitations ✅ COMPLETE
**Completed:** 2025-11-17

Implemented P2P invitation delivery system for group membership:

- [x] **Database Schema Evolution:** Messages table extended to v5
  - Added `message_type` field (0=chat, 1=group_invitation)
  - Added `invitation_status` field (0=pending, 1=accepted, 2=rejected)
  - Backward compatible via ALTER TABLE with DEFAULT values
- [x] **JSON Invitation Format:** Standardized invitation message structure
  - `type`: "group_invite" (message type discriminator)
  - `group_uuid`: UUID v4 group identifier (36 chars)
  - `group_name`: Display name of the group
  - `inviter`: SHA3-512 fingerprint (128 chars) of inviter
  - `member_count`: Current number of group members
- [x] **Backend Detection:** Automatic invitation recognition (`messenger_p2p.c`)
  - Decrypt incoming messages with Kyber1024 + AES-256-GCM
  - Parse JSON and detect `"type": "group_invite"`
  - Extract group details and store in `group_invitations` database
  - Store message with `message_type=1` for UI rendering
- [x] **UI Rendering:** Rich invitation display (`chat_screen.cpp`)
  - Blue invitation box with rounded border (8px radius)
  - Group icon (Font Awesome ICON_FA_USERS)
  - Group name and invitation details
  - Inviter name and member count display
  - Accept button (green check icon) - triggers DHT sync
  - Decline button (red X icon) - marks as rejected
- [x] **Accept Workflow:** DHT group synchronization (`messenger_groups.c`)
  - Fetch group metadata from DHT via UUID
  - Store group in local cache (`~/.dna/groups_cache.db`)
  - Update invitation status to ACCEPTED
  - Group appears in user's groups list
- [x] **Reject Workflow:** Invitation state management
  - Mark invitation as rejected in database
  - Allow re-acceptance (invitation UI persists)
  - No DHT sync for rejected invitations

**Use Case:** User A creates "Team Chat" group and adds User B. User B receives invitation message in chat with User A, sees blue box with Accept/Decline buttons. Clicking Accept syncs group from DHT and adds it to groups list.

**Files Modified:**
- `message_backup.h/c` - Schema v4→v5 (message_type, invitation_status fields)
- `messenger.h` - Added `message_type` to `message_info_t` struct
- `messenger/messages.c` - Updated `messenger_send_message()` signature
- `messenger_p2p.c` - Invitation detection logic (~80 LOC)
- `messenger_groups.c` - Accept/reject handlers (~40 LOC)
- `chat_screen.cpp` - Invitation rendering UI (~80 LOC)
- `data_loader.cpp` - Populate `message_type` when loading messages
- `imgui_gui/core/data_types.h` - Added `message_type` to Message struct

**Total Changes:** ~300 LOC
**Documentation:** `/docs/GROUP_INVITATIONS_GUIDE.md` (comprehensive 500+ line guide)

#### Phase 5.7: Local Cache & Sync (Future)
- [ ] SQLite encrypted with DNA's PQ crypto (Kyber512 + AES-256-GCM)
- [ ] Background sync protocol (local ↔ DHT)
- [ ] Multi-device message synchronization
- [ ] Offline mode with automatic sync on reconnect
- [ ] Incremental sync for large histories

#### Phase 5.8: DHT Keyserver Enhancements (Future)
- [ ] Key rotation and update protocol
- [ ] Optional: Blockchain anchoring for tamper-proofing
- [ ] DHT replication monitoring

#### Phase 5.9: Integration & Testing (Future)
- [ ] End-to-end testing with 5-10 peers
- [ ] Network resilience testing (peer churn)
- [ ] Performance optimization
- [ ] Security audit
- [ ] Documentation and migration guide

### Technology Stack

| Component | Technology | Purpose |
|-----------|-----------|---------|
| **P2P Networking** | libp2p (C++) | Peer connections, multiplexing |
| **DHT** | OpenDHT or Kad-DHT | Distributed storage & discovery |
| **NAT Traversal** | libjuice (C) | ICE/STUN hole punching |
| **Local Cache** | SQLite + DNA PQ crypto | Encrypted offline storage |
| **Crypto** | Kyber512 + Dilithium3 + AES-256-GCM | Post-quantum (existing) |

### Deliverables
- Fully decentralized serverless messenger
- Distributed DHT keyserver (no central authority)
- Store-and-forward offline message delivery
- Multi-device synchronization via DHT
- P2P network protocol specification
- Migration tools (PostgreSQL → DHT)

**Design Documents:**
- `/futuredesign/ARCHITECTURE-OVERVIEW.md` - Complete system design
- `/futuredesign/P2P-TRANSPORT-DESIGN.md` - libp2p integration
- `/futuredesign/DHT-STORAGE-DESIGN.md` - Message storage protocol
- `/futuredesign/DHT-KEYSERVER-DESIGN.md` - Distributed public keys
- `/futuredesign/SYNC-PROTOCOL-DESIGN.md` - Multi-device sync

**Note:** This represents a fundamental architectural shift from client-server to peer-to-peer. Implementation details are actively being researched. See futuredesign/ folder for complete specifications.

---

## Phase 6: DNA Board - Censorship-Resistant Social Media 🚧 IN PROGRESS (Alpha)

**Timeline:** 8 weeks (alpha) | 12-16 weeks (full v1.0)
**Status:** Phase 6.1 ✅ Complete | Phase 6.2 ✅ Complete | Phase 6.3 ✅ Complete (Alpha)
**Prerequisites:** P2P architecture, DHT storage, User profiles
**Design Document:** `/DNA_BOARD_PHASE10_PLAN.md`

### Alpha Implementation

**Phase 6.1 ✅ Complete (2025-11-12 to 2025-11-16):**
- [x] User profiles with DHT storage (display name, bio, location, website)
- [x] Profile cache system (7-day TTL, cache-first architecture)
- [x] Profile editor screen (edit own profile) - `profile_editor_screen.cpp` (229 lines)
- [x] Contact profile viewer (view others' profiles) - `contact_profile_viewer.cpp` (232 lines)
- [x] Auto-integration (contact add, message receive, app startup)
- [x] Wall post backend - `dna_message_wall.c/h` (614 lines)
- [x] Wall post GUI screen - `message_wall_screen.cpp` (291 lines)
- [x] Wall viewing ("Wall" button functional in chat)
- [x] Dilithium5 signatures for wall posts
- [x] 30-day TTL with rotation (100 messages max)

**Phase 6.2 ✅ Complete (2025-11-17 - Avatar System):**
- [x] Avatar support (Base64 encoding, 64x64 PNG, 20KB limit)
- [x] Avatar upload with auto-resize (stb_image integration)
- [x] OpenGL texture loading (TextureManager singleton)
- [x] Circular avatar clipping (ImDrawList::AddImageRounded)
- [x] Avatar display in profiles (64x64 preview)
- [x] Avatar display in wall posts (24px circular)
- [x] Avatar display in chat messages (20px circular)
- [x] Wall poster identification fix (post_id uses poster fingerprint)
- [x] Comment threading (reply-to field, collapsed/expandable UI, Twitter-style)
- [x] Thread sorting (forum bump - latest activity first)

**Phase 6.3 ✅ Complete (2025-11-17 - Community Voting):**
- [x] Community voting system (thumbs up/down on wall posts)
- [x] Vote backend with Dilithium5 signatures (dna_wall_votes.c/h - 650 lines)
- [x] Separate DHT storage per post (SHA256 key derivation)
- [x] Aggregated vote counts (upvote_count, downvote_count)
- [x] One vote per fingerprint enforcement (permanent votes)
- [x] Vote UI with emoji buttons (👍 👎) and real-time counts
- [x] Net score display with color coding (green/red/gray)
- [x] User vote highlighting (blue=upvoted, red=downvoted)
- [x] Vote verification with post-quantum cryptography

**Phase 6.4 📋 Next (Alpha - Profile Extensions):**
- [ ] Profile schema extensions (social links: Telegram, Twitter, GitHub, Discord)
- [ ] Crypto addresses for tipping (BTC, ETH, CPUNK)
- [ ] Feed sorting (Recent, Top, Controversial)

**Alpha Approach:** FREE posting (no CPUNK costs). Using DHT storage with 7-day TTL. Full anti-spam measures and economics planned for v1.0 post-alpha.

---

### Full Features (v1.0 - Planned)

DNA Board is a **censorship-resistant social media platform** built on DNA Messenger's DHT network.

**Core Principles:**
1. **Decentralized Storage** - DHT-based content distribution
2. **Community Voting** - Thumbs up/down to surface quality content
3. **Comment Threading** - Nested discussions with reply support
4. **Profile Integration** - Rich user profiles with social links
5. **Client-Side Control** - Users control their own feed (blocking, filtering)

### Implementation Status

#### ✅ Completed (Phase 6.1 - Base System):
- [x] User profiles with DHT storage (dna_profile.c/h - 470 lines)
- [x] Profile cache system (profile_cache.c/h - 550 lines)
- [x] Profile manager (profile_manager.c/h - 235 lines)
- [x] Profile editor screen (profile_editor_screen.cpp - 229 lines)
- [x] Contact profile viewer (contact_profile_viewer.cpp - 232 lines)
- [x] Wall posting backend (dna_message_wall.c/h - 614 lines)
- [x] Wall post GUI screen (message_wall_screen.cpp - 291 lines)
- [x] Wall viewing button in chat interface
- [x] Dilithium5 signatures for posts
- [x] 30-day TTL with 100 message rotation

#### ✅ Completed (Phase 6.2 - Avatar & Threading):
- [x] Avatar support (Base64 encoding, 64x64 PNG, 20KB limit)
- [x] Avatar upload/resize (avatar_utils.c - stb_image integration)
- [x] OpenGL texture loading (TextureManager singleton)
- [x] Circular avatar display (profiles, wall, chat)
- [x] Comment threading (collapsed/expandable UI, Twitter-style)
- [x] Thread sorting (forum bump - latest activity)
- [x] Wall poster identification fix (post_id fingerprint)

#### 🚧 In Progress (Phase 6.3):
- [ ] Community voting (thumbs up/down UI)
- [ ] Profile schema extensions (social links)
- [ ] Crypto addresses for tipping
- [ ] Feed sorting and filtering

#### 📋 Planned (Phase 6.4):
- [ ] Image/video embedding
- [ ] Feed rendering with pagination
- [ ] Client-side blocking/filtering
- [ ] Post composer dialog improvements
- [ ] Thread viewer with nesting
- [ ] Mobile-responsive wall feed

### Key Features

**Decentralization:**
- ✅ DHT-based storage (no central server)
- ✅ 7-day TTL in alpha, permanent storage in v1.0
- ✅ Content replicated across DHT network
- ✅ Client-side blocking only (no server-side censorship)

**User Experience:**
- ✅ Rich profiles with social links
- ✅ Community voting system
- ✅ Nested comment threads
- ✅ Feed customization (sorting, filtering)

### Deliverables

- Wall posts with DHT storage
- Comment threading system
- Community voting interface
- Profile extensions (social links, avatars)
- ImGui integration (wall feed, composer, profile viewer)

---

## Phase 8: Post-Quantum Voice/Video Calls 📋 PLANNED

**Timeline:** ~20 weeks (5 months)
**Status:** Research & Planning
**Prerequisites:** Phase 5.1 (P2P Transport Layer)
**Design Document:** `/futuredesign/VOICE-VIDEO-DESIGN.md`

### Overview

Fully **quantum-safe voice and video calls** using custom architecture that bypasses WebRTC's quantum-vulnerable DTLS handshake.

**Key Innovation:** Kyber512 key exchange via DNA messaging + standard SRTP media = Post-quantum calls today

### Architecture

```
Signaling (DNA Messaging) → NAT Traversal (libjuice) → Media (SRTP + AES-256-GCM)
    ↓                           ↓                         ↓
Kyber512 + Dilithium3     ICE/STUN/TURN           Opus audio / VP8 video
```

### Key Features

**Quantum-Resistant Security:**
- Kyber512 (NIST FIPS 203) for key exchange
- Dilithium3 (NIST FIPS 204) for signatures
- AES-256-GCM for media encryption
- Forward secrecy (ephemeral keys per call)
- SAS verification for MITM protection

**Technology Stack:**
- **libjuice** - ICE/STUN (NAT traversal)
- **libsrtp2** - Secure RTP with AES-256-GCM
- **libopus** - Audio codec (48kHz stereo)
- **libvpx/libx264** - Video codec (VP8 or H.264)
- **PortAudio** - Microphone/speaker I/O
- **V4L2/DirectShow** - Camera capture

### Why This is Better

1. **Full Quantum Resistance** - No quantum-vulnerable components
2. **Uses Existing Crypto** - Same Kyber/Dilithium as messaging
3. **Independent of Standards** - Don't wait for WebRTC PQ support (3-5 years away)
4. **Better Privacy** - Signaling through DNA's E2E encrypted channel
5. **Forward Secrecy** - Ephemeral keys per call
6. **Available Today** - Can deploy immediately (desktop/mobile)

### Implementation Sub-Phases

- **Weeks 1-4:** Signaling via DNA messaging
- **Weeks 5-8:** NAT traversal (libjuice integration)
- **Weeks 9-12:** Audio calls (Opus + PortAudio + SRTP)
- **Weeks 13-16:** Video calls (VP8/H.264 + camera)
- **Weeks 17-20:** Polish & testing

### Future Enhancements

- Group calls (mesh topology, 8 participants)
- Screen sharing (H.264 high-profile)
- Call recording (local only, preserves E2E)
- SFU for large conferences (100+ participants)

---

## Phase 9+: Future Enhancements 📋 PLANNED

### Advanced Features
- [ ] Stickers and GIFs
- [ ] Bots and automation
- [ ] Channels (broadcast mode)
- [ ] Stories/Status updates
- [ ] Rich text formatting
- [ ] File transfer

### Infrastructure
- [ ] Tor integration (metadata protection)
- [ ] Bridge to other platforms (Signal, WhatsApp)

### Enterprise Features
- [ ] Organization management
- [ ] Compliance tools
- [ ] Audit logging
- [ ] SSO integration

---

## Success Criteria

### Phase 1-2 (Foundation) ✅
- ✅ Repository forked and branded
- ✅ Library API compiles without errors
- ✅ Memory-based operations working
- ✅ API documentation complete

### Phase 3 (CLI Messenger) ✅
- ✅ Alice can send message to Bob via CLI
- ✅ Bob can decrypt and read message
- ✅ Messages persist across sessions
- ✅ Contact list works
- ❌ Removed - unmaintained (functionality moved to GUI)

### Phase 4 (Desktop & Wallet) ✅
- ✅ GUI application working on Linux and Windows
- ✅ Contacts and groups displayed
- ✅ Message send/receive functional
- ✅ Delivery/read receipts working
- ✅ Group messaging with full UI
- ✅ Desktop notifications working
- ✅ Theme system functional
- ✅ Auto-update mechanism working
- ✅ cpunk wallet integration complete

### Phase 5 (P2P Architecture) ✅
- ✅ P2P transport layer (OpenDHT + TCP)
- ✅ Offline message queueing (7-day TTL)
- ✅ DHT-based keyserver with reverse mapping
- ✅ Per-identity contact lists with DHT sync
- ✅ PostgreSQL → SQLite migration complete

### Phase 6 (DNA Board) 🚧
- ✅ User profiles with DHT storage
- ✅ Profile editor and viewer screens
- ✅ Wall posts backend and GUI
- ✅ Dilithium5 signatures
- 🚧 Comment threading
- ⏳ Community voting
- ⏳ Profile extensions (social links, avatars)

### Phase 7 (Web Messenger) 📋
- ✅ WebAssembly crypto module
- ⏳ HTML5 responsive UI
- ⏳ Browser-based client
- ⏳ PWA support

### Phase 8-9+ (Future) 📋
- ⏳ Post-quantum voice/video calls
- ⏳ Mobile apps (Android/iOS)
- ⏳ Forward secrecy
- ⏳ Advanced security features

---

## Version Milestones

| Version | Phase | Status | Description |
|---------|-------|--------|-------------|
| 0.1.0 | Phase 1 | ✅ Complete | Fork preparation |
| 0.2.0 | Phase 2 | ✅ Complete | Library API |
| 0.3.0 | Phase 3 | ✅ Complete | CLI messenger (removed) |
| 0.4.0 | Phase 4 | ✅ Complete | Desktop app + wallet integration |
| 0.5.0 | Phase 5 | ✅ Complete | P2P architecture (DHT, offline queue, contacts sync) |
| 0.6.0 | Phase 6 | 🚧 In Progress | DNA Board (profiles, wall posts, social media) |
| 0.7.0 | Phase 7 | 📋 Planned | Web messenger (WebAssembly) |
| 1.0.0 | Phase 8 | 📋 Planned | Voice/Video calls (first stable release) |
| 1.1.0 | Phase 9+ | 📋 Planned | Advanced features (mobile, security, etc.) |

**Current Version:** 0.1.120+ (auto-incremented with each commit)

---

## Risk Management

### Technical Risks
- **Cryptographic bugs**: Mitigated with extensive testing, code review, and use of proven algorithms
- **Network complexity**: Start with simple relay server, add P2P later
- **Cross-platform issues**: Continuous testing on all platforms

### Resource Risks
- **Development time**: Phases can be extended if needed
- **Testing effort**: Automated testing where possible
- **Documentation**: Write docs as features are developed

### Security Risks
- **Quantum attacks**: Already mitigated (post-quantum algorithms)
- **Implementation bugs**: Code review + security audit planned
- **Side-channel attacks**: To be addressed in Phase 7 (secure memory)

---

## Current Status Summary

### ✅ Completed
- **Phase 1:** Fork Preparation
- **Phase 2:** Library API Design
- **Phase 3:** CLI Messenger Client (Removed - unmaintained)
- **Phase 4:** Desktop Application & Wallet Integration (ImGui + cpunk wallet)
- **Phase 5.1:** P2P Transport Layer (OpenDHT + TCP)
- **Phase 5.2:** Offline Message Queueing (DHT storage with 7-day TTL)
- **Phase 5.3:** PostgreSQL → SQLite Migration (Fully decentralized storage)
- **Phase 5.4:** DHT-based Keyserver with Signed Reverse Mapping
- **Phase 5.5:** Per-Identity Contact Lists with DHT Sync
- **Phase 5.6:** P2P Group Invitations
- **Phase 6.1:** User Profiles, Profile Editor/Viewer, Wall Posts (backend + GUI)
- **Phase 6.2:** Avatar System (Base64 encoding, circular display, OpenGL textures)
- **Phase 6.3:** Community Voting (Dilithium5 signatures, permanent votes)

### 🚧 In Progress
- **Phase 6.4:** DNA Board enhancements (profile extensions, feed sorting)

### 📋 Planned
- **Phase 5.7-5.9:** Multi-device message sync, DHT keyserver enhancements, integration testing
- **Phase 7:** Web-Based Messenger (HTML5 UI, PWA, IndexedDB)
- **Phase 8:** Post-Quantum Voice/Video Calls
- **Phase 9+:** Future Enhancements (mobile apps, advanced security, etc.)

---

## Contributing

DNA Messenger is in active development. Contributions welcome!

**Current Phase:** DNA Board Social Features (Phase 6.2)
**How to Contribute:**
- Check `CLAUDE.md` for development guidelines
- Pick tasks from current phase
- Submit pull requests to `main` branch
- Follow existing code style

---

**Project Start:** 2025-10-14
**Current Version:** 0.1.120+
**Next Milestone:** DNA Board Profile Extensions (Phase 6.4)
**Recent Achievements:**
- ✅ **P2P Group Invitations!** (Phase 5.6 - 2025-11-17)
  - Encrypted JSON invitation messages (Kyber1024 + AES-256-GCM)
  - Rich UI with blue invitation box, Accept/Decline buttons
  - Automatic DHT group synchronization on acceptance
  - Database schema v5 with message_type and invitation_status fields
  - Comprehensive guide: `/docs/GROUP_INVITATIONS_GUIDE.md`
- ✅ **Community Voting System!** (Phase 6.3 - 2025-11-17)
  - Thumbs up/down voting on wall posts with Dilithium5 signatures
  - Permanent votes (one per fingerprint, cannot be changed)
  - Net score display with color coding (green/red/gray)
  - Vote backend: 650 lines with full cryptographic verification
- ✅ **Avatar System!** (Phase 6.2 - 2025-11-17)
  - Base64-encoded PNG avatars (64x64, 20KB limit)
  - OpenGL texture loading with TextureManager singleton
  - Circular display in profiles (64px), wall posts (24px), chat (20px)
  - Auto-resize via stb_image integration
- ✅ **DHT Refactoring Complete!** (2025-11-16)
  - Phase 7: Unified cache manager implementation
  - Phase 5: Profile system unification (dna_unified_identity_t)
  - Phase 4: DHT directory reorganization (core/client/shared)
  - Phase 3: dht_context.cpp modularization
  - 100% backward compatible migration
- ✅ **DNA Board Phase 6.1 Complete!** (2025-11-12 to 2025-11-16)
  - User profiles with DHT storage (7-day cache, cache-first)
  - Profile editor and contact profile viewer
  - Wall posts backend (614 lines) + GUI (291 lines)
  - Dilithium5 signatures, 30-day TTL, 100 message rotation
- ✅ **GUI Migration: Qt → ImGui!** (2025-11-10)
  - Modern immediate-mode rendering (OpenGL3 + GLFW3)
  - Async task system for non-blocking operations
  - Qt code preserved in `gui/` for reference
- ✅ **CRITICAL BUG FIX: Offline Message Queue Key Mismatch!** (2025-11-10)
  - Fixed bug where messages sent to display names couldn't be retrieved
  - All DHT queue operations now use fingerprints consistently
- ✅ **Per-Identity Contact Lists with DHT Sync!** (Phase 5.5 - 2025-11-05)
  - Isolated contact databases per identity
  - Kyber1024 self-encryption for DHT storage
  - Multi-device sync via BIP39 seed phrase
- ✅ **DHT-based Keyserver with Signed Reverse Mapping!** (Phase 5.4 - 2025-11-04)
  - Cryptographically signed reverse mappings
  - Sender identification without pre-added contacts
- ✅ **PostgreSQL → SQLite Migration Complete!** (Phase 5.3 - 2025-11-03)
  - Fully decentralized storage (NO centralized database)
  - DHT-based groups with UUID v4 + SHA256 keys
- ✅ **Offline Message Queueing** (Phase 5.2 - 2025-11-02)
  - 7-day DHT storage for offline recipients
  - Automatic 2-minute polling
- ✅ **cpunk Wallet Integration** (Phase 4 - 2025-10-23)
  - View CPUNK, CELL, KEL balances
  - Send/receive tokens with QR codes
  - Full transaction history
