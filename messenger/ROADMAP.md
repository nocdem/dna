# DNA Messenger - Development Roadmap

**Version:** 0.1.120+
**Last Updated:** 2025-11-03
**Project Status:** Phase 5 (Web-Based Messenger) - Phase 4, 8, 9.1, 9.2, PostgreSQL Migration Complete

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

## Phase 4: Desktop Application ✅ COMPLETE

**Timeline:** 4-6 weeks
**Status:** Complete

### Objectives
- Qt-based desktop GUI
- Cross-platform (Linux, Windows, macOS)
- Rich messaging features
- System notifications

### Completed Tasks

#### GUI Development
- [x] Qt5 application framework
- [x] Conversation list view (contacts and groups)
- [x] Chat window interface
- [x] Contact management UI
- [x] Settings panel (themes, font scaling)
- [x] Custom title bar (frameless window)

#### Features
- [x] Real-time message display
- [x] Message timestamps
- [x] Delivery and read receipts (✓✓ checkmarks)
- [x] Desktop notifications (system tray)
- [x] System tray integration
- [x] Auto-update mechanism (Windows batch script)
- [x] Theme switching (cpunk.io cyan, cpunk.club orange)
- [x] Dynamic font scaling (1x, 2x, 3x, 4x)
- [x] Multi-recipient encryption
- [x] Message decryption (sent and received)
- [x] Auto-detect local identity from ~/.dna/
- [x] Notification sound effects
- [x] Public key caching (100-entry cache)
- [x] Inline keyserver registration (no external utilities)
- [x] Windows curl JSON parsing fixes

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
- [x] PostgreSQL groups tables (migration)

#### Platform Support
- [x] Linux build
- [x] Windows build
- [ ] macOS build (future)
- [x] Cross-platform compilation

### Deliverables
- ✅ `dna_messenger_gui` - Desktop application
- ✅ Installation guide
- ✅ User manual (README.md)
- ✅ Platform-specific builds (Linux, Windows)
- ✅ Full group messaging feature

---

## Phase 5: Web-Based Messenger 🚧 IN PROGRESS

**Timeline:** 3-4 weeks
**Status:** Active development (branch: `feature/web-messenger`)
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

## Phase 6: Mobile Applications 📋 PLANNED

**Timeline:** 6-8 weeks
**Status:** Not started
**Prerequisites:** Phase 4 complete

### Objectives
- Flutter cross-platform mobile app
- Android and iOS support
- Push notifications
- Background sync

### Tasks

#### Mobile App Development
- [ ] Flutter application framework
- [ ] Mobile-optimized UI
- [ ] Contact list interface
- [ ] Chat interface
- [ ] Media handling (photos, videos)

#### Platform Integration
- [ ] Android build
- [ ] iOS build
- [ ] Push notifications (FCM, APNS)
- [ ] Background message sync
- [ ] Biometric authentication

#### App Store Preparation
- [ ] App store listings
- [ ] Screenshots and marketing materials
- [ ] Privacy policy
- [ ] Terms of service

### Deliverables
- `dna-mobile` - Flutter mobile app
- Android APK / iOS IPA
- App store submissions
- Mobile user guide

---

## Phase 7: Advanced Security Features 📋 PLANNED

**Timeline:** 4-6 weeks
**Status:** Not started
**Prerequisites:** Phase 4 complete

### Objectives
- Forward secrecy (session keys)
- Multi-device synchronization
- Enhanced security features

### Tasks

#### Forward Secrecy
- [ ] Session key generation
- [ ] Automatic session rotation
- [ ] Session key storage
- [ ] Backward compatibility

#### Multi-Device Support
- [ ] Device registration
- [ ] Session key synchronization
- [ ] Device management UI
- [ ] Device revocation

#### Security Enhancements
- [ ] Secure memory management (mlock, secure wiping)
- [ ] Key verification (QR codes, safety numbers)
- [ ] Disappearing messages
- [ ] Screenshot protection (mobile)

### Deliverables
- Forward secrecy implementation
- Multi-device support
- Enhanced security documentation

---

## Phase 8: cpunk Wallet Integration ✅ COMPLETE

**Timeline:** 2 weeks
**Status:** Complete
**Completed:** 2025-10-23

### cpunk Wallet Integration (Cellframe Backbone Network)
- [x] Read local Cellframe wallet files (.dwallet format)
- [x] Connect via RPC to Cellframe node
- [x] Display CPUNK, CELL, and KEL token balances
- [x] Send tokens directly in messenger via transaction builder
- [x] Receive tokens with QR code generation
- [x] Full transaction history with status tracking
- [x] Color-coded transaction display (green incoming, red outgoing)
- [x] Wallet address management with easy copy-to-clipboard
- [x] Transaction status notifications (ACCEPTED/DECLINED in red)
- [x] Theme support across all wallet dialogs
- [x] Integrated into GUI with dedicated wallet button

### Deliverables
- ✅ WalletDialog - View balances and recent transactions
- ✅ SendTokensDialog - Send tokens with transaction builder
- ✅ ReceiveDialog - Display addresses with QR codes
- ✅ TransactionHistoryDialog - Full transaction history
- ✅ ThemeManager - Global theme support
- ✅ Cellframe RPC integration for balance and transaction queries

---

## Phase 9: Distributed P2P Architecture 🚧 IN PROGRESS

**Timeline:** ~6 months (long-term vision)
**Status:** Phase 9.1 & 9.2 COMPLETE - P2P Transport, DHT, and Offline Queue operational
**Prerequisites:** Phase 5-7 complete
**Design Docs:** See `/futuredesign/` folder for detailed specifications

### Objectives
- Fully peer-to-peer serverless architecture
- Distributed DHT-based keyserver
- Store-and-forward offline message delivery
- Zero-knowledge storage (storage nodes cannot read messages)
- Multi-device synchronization via DHT
- No centralized dependencies

### Tasks

#### Phase 9.1: P2P Transport Layer ✅ COMPLETE
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
- [ ] NAT traversal using libnice (ICE/STUN/TURN) - **Deferred to Phase 9.2**

#### Phase 9.2: Offline Message Queueing ✅ COMPLETE
**Completed:** 2025-11-02

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

#### Phase 9.3: PostgreSQL → SQLite Migration ✅ COMPLETE
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

#### Phase 9.4: DHT-based Keyserver with Signed Reverse Mapping ✅ COMPLETE
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

#### Phase 9.5: Local Cache & Sync (Planned)
- [ ] SQLite encrypted with DNA's PQ crypto (Kyber512 + AES-256-GCM)
- [ ] Background sync protocol (local ↔ DHT)
- [ ] Multi-device message synchronization
- [ ] Offline mode with automatic sync on reconnect
- [ ] Incremental sync for large histories

#### Phase 9.6: DHT Keyserver Enhancements (Planned)
- [ ] Key rotation and update protocol
- [ ] Optional: Blockchain anchoring for tamper-proofing
- [ ] DHT replication monitoring

#### Phase 9.7: Integration & Testing (Planned)
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
| **NAT Traversal** | libnice (C) | ICE/STUN/TURN hole punching |
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

## Phase 10: DNA Board - Censorship-Resistant Social Media 📋 PLANNED

**Timeline:** 12 weeks
**Status:** Planning (Post-Phases 7-9)
**Prerequisites:** Distributed validator storage, DNA-Keyserver merge, Offline messaging system
**Design Document:** `/DNA_BOARD_PHASE10_PLAN.md`

### Overview

DNA Board is a **censorship-resistant social media platform** built on cpunk validator network. Content cannot be removed once posted, creating a true free speech platform with built-in spam protection.

**Core Principles:**
1. **NO CENSORSHIP** - Content cannot be removed (no deletion endpoint)
2. **PoH Required to Post** - Only human-verified users (PoH ≥70) can create posts
3. **Open Responses** - Anyone can reply/comment (no PoH requirement for replies)
4. **Community Voting** - Thumbs up/down to surface quality content
5. **Burn Economics** - All storage fees permanently burned (deflationary)
6. **Validator Rewards** - DAO pool distribution (no payment from users)

### Architecture

```
Self-Healing Validator Network (3-Replica)
┌─────────────────────────────────────────────┐
│  Post → Primary Validator                   │
│    ↓                                         │
│  Replicate to 2 more (lowest storage)       │
│    ↓                                         │
│  3 Validators store content                 │
│    ↓                                         │
│  Heartbeat monitoring (30s intervals)       │
│    ↓                                         │
│  If validator offline → Auto-heal           │
│    ↓                                         │
│  Re-replicate to new validator              │
│    ↓                                         │
│  Back to 3 replicas (maintained)            │
└─────────────────────────────────────────────┘
```

### Content & Economics

| Type | Burn Fee | PoH Required | Max Size | Replication |
|------|----------|--------------|----------|-------------|
| Text Post | 1 CPUNK | Yes (≥70) | 5,000 chars | 3 validators |
| Image | 2 CPUNK | Yes (with post) | 5 MB | 3 validators |
| Video | 5 CPUNK | Yes (with post) | 50 MB | 3 validators |
| Reply | 0.5 CPUNK | **No** | 2,000 chars | 3 validators |
| Vote | **FREE** | No | N/A | Aggregated |

**All fees BURNED** → Deflationary pressure (estimated 16M CPUNK/year burned)

### Proof of Humanity (PoH) System

**Who Can Post:** Only verified humans with `humanity_score >= 70`

**Verification Tiers:**
- **Auto-Verified** (75-89): Behavioral algorithm (most users)
- **Staked-Verified** (90-94): Auto + 100 CPUNK stake
- **DAO-Vouched** (95-99): 3 human vouches + DAO review
- **Celebrity** (100): Public figure + DAO verification

**Bot Detection:** Single-destination sends, mechanical timing, no staking
**Human Patterns:** Multiple services, irregular timing, social verification, staking

### Who Can Respond

**ANYONE can reply** to existing posts:
- No PoH requirement for replies
- Still requires 0.5 CPUNK burn (prevents pure spam)
- Enables free discussion and debate
- Bot responses downvoted by community

**Balance:** Spam prevention at post level + free speech at reply level

### Implementation Phases

#### Weeks 1-2: Validator Backend Infrastructure
- [ ] Implement PoH scoring algorithm
- [ ] Create post/reply data structures (PostgreSQL)
- [ ] Build `/dna_board/post` endpoint with PoH check
- [ ] Build `/dna_board/reply` endpoint (no PoH check)
- [ ] Add burn transaction verification

#### Weeks 3-4: Gossip Protocol & Replication
- [ ] Implement heartbeat monitoring (30s intervals)
- [ ] Build gossip protocol for content replication
- [ ] Create 3-validator replication logic
- [ ] Implement auto-healing (detect offline, re-replicate)
- [ ] Build graceful exit protocol

#### Weeks 5-6: Voting System
- [ ] Create vote storage and aggregation
- [ ] Build `/dna_board/vote` endpoint
- [ ] Implement one-vote-per-wallet enforcement
- [ ] Add vote signature verification
- [ ] Build feed ranking algorithm

#### Weeks 7-8: Client GUI (Qt)
- [ ] Create DNABoardTab main widget
- [ ] Build ComposeDialog with PoH verification
- [ ] Implement PostWidget with voting UI
- [ ] Create ThreadView for nested replies
- [ ] Build DNABoardAPI client

#### Weeks 9-10: Media & Integration
- [ ] Add image/video upload to validators
- [ ] Integrate wallet for burn transactions
- [ ] Implement client-side blocking/muting
- [ ] Add feed filters (sort, humanity min)
- [ ] Build user profile view

#### Weeks 11-12: Testing & Launch
- [ ] Deploy to testnet validators
- [ ] Community beta testing (100+ users)
- [ ] Security audit (signatures, burn verification)
- [ ] Performance optimization
- [ ] DAO vote on Year 1 pool (100M CPUNK)
- [ ] Mainnet launch

### Key Features

**Censorship Resistance:**
- ✅ No deletion endpoint (content permanent)
- ✅ 3-validator replication across jurisdictions
- ✅ No central authority or single point of control
- ✅ Client-side blocking only (no server-side)
- ✅ Gossip protocol ensures propagation

**Quality Control:**
- ✅ PoH requirement prevents bot spam
- ✅ Community voting surfaces quality content
- ✅ Ranking algorithm (votes × humanity × time × engagement)
- ✅ Multiple feed views (Ranked, Recent, Top, Controversial)

**Economic Model:**
- ✅ All fees burned (deflationary)
- ✅ Validator rewards from DAO pool (100M Year 1, halvening)
- ✅ Stake + storage formula for validator rewards
- ✅ No payment from users to validators

### Deliverables

- Fully censorship-resistant social media platform
- 3-validator self-healing replication
- PoH verification system (behavioral + staking)
- Qt GUI integration (DNABoardTab)
- Burn economics (CPUNK deflationary pressure)
- DAO-governed validator rewards

---

## Phase 11: Post-Quantum Voice/Video Calls 📋 PLANNED

**Timeline:** ~20 weeks (5 months)
**Status:** Research & Planning
**Prerequisites:** Phase 9.1 (P2P Transport Layer)
**Design Document:** `/futuredesign/VOICE-VIDEO-DESIGN.md`

### Overview

Fully **quantum-safe voice and video calls** using custom architecture that bypasses WebRTC's quantum-vulnerable DTLS handshake.

**Key Innovation:** Kyber512 key exchange via DNA messaging + standard SRTP media = Post-quantum calls today

### Architecture

```
Signaling (DNA Messaging) → NAT Traversal (libnice) → Media (SRTP + AES-256-GCM)
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
- **libnice** - ICE/STUN/TURN (NAT traversal)
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
- **Weeks 5-8:** NAT traversal (libnice integration)
- **Weeks 9-12:** Audio calls (Opus + PortAudio + SRTP)
- **Weeks 13-16:** Video calls (VP8/H.264 + camera)
- **Weeks 17-20:** Polish & testing

### Future Enhancements

- Group calls (mesh topology, 8 participants)
- Screen sharing (H.264 high-profile)
- Call recording (local only, preserves E2E)
- SFU for large conferences (100+ participants)

---

## Phase 12+: Future Enhancements 📋 PLANNED

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

### Phase 4 (Desktop) ✅
- ✅ GUI application working on Linux and Windows
- ✅ Contacts and groups displayed
- ✅ Message send/receive functional
- ✅ Delivery/read receipts working
- ✅ Group messaging with full UI
- ✅ Desktop notifications working
- ✅ Theme system functional
- ✅ Auto-update mechanism working

### Phase 6 (Mobile) 📋
- ⏳ Mobile app working on Android and iOS
- ⏳ Push notifications working
- ⏳ Biometric authentication
- ⏳ User onboarding smooth

### Phase 7-8 (Advanced Features) 📋
- ⏳ Forward secrecy working
- ⏳ Multi-device sync functional
- ⏳ Security audit passed

---

## Version Milestones

| Version | Phase | Status | Description |
|---------|-------|--------|-------------|
| 0.1.0 | Phase 1 | ✅ Complete | Fork preparation |
| 0.2.0 | Phase 2 | ✅ Complete | Library API |
| 0.3.0 | Phase 3 | ✅ Complete | CLI messenger |
| 0.4.0 | Phase 4 | ✅ Complete | Desktop app with groups |
| 0.5.0 | Phase 5 | 🚧 In Progress | Web messenger (WebAssembly) |
| 0.8.0 | Phase 8 | ✅ Complete | cpunk Wallet integration |
| 1.0.0 | Phase 6-7 | 📋 Planned | Mobile + Advanced Security (first stable release) |
| 1.1.0 | Phase 6 | 📋 Planned | Mobile apps |
| 1.2.0 | Phase 7 | 📋 Planned | Advanced security |
| 2.0.0 | Phase 9 | 📋 Planned | P2P architecture |

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
- **Phase 3:** CLI Messenger Client (PostgreSQL → SQLite migration complete)
- **Phase 4:** Desktop Application (with groups!)
- **Phase 8:** cpunk Wallet Integration (Cellframe Backbone)
- **Phase 9.1:** P2P Transport Layer (OpenDHT + TCP)
- **Phase 9.2:** Offline Message Queueing (DHT storage with 7-day TTL)
- **Phase 9.3:** PostgreSQL → SQLite Migration (Fully decentralized storage)
- **Phase 9.4:** DHT-based Keyserver with Signed Reverse Mapping

### 🚧 In Progress
- **Phase 5:** Web-Based Messenger (active on `feature/web-messenger` branch)

### 📋 Planned
- **Phase 6:** Mobile Applications
- **Phase 7:** Advanced Security Features
- **Phase 9.5-9.7:** Multi-device sync, DHT keyserver enhancements, integration testing
- **Phase 10:** DNA Board (Censorship-resistant social media)
- **Phase 11:** Post-Quantum Voice/Video Calls
- **Phase 12+:** Future Enhancements

---

## Contributing

DNA Messenger is in active development. Contributions welcome!

**Current Phase:** Web-Based Messenger (Phase 5)
**How to Contribute:**
- Check `CLAUDE.md` for development guidelines
- Pick tasks from current phase
- Submit pull requests to `main` branch
- Follow existing code style

---

**Project Start:** 2025-10-14
**Current Version:** 0.1.120+
**Next Milestone:** Web Messenger (Phase 5)
**Recent Achievements:**
- ✅ **DHT-based Keyserver with Signed Reverse Mapping!** (Phase 9.4 - 2025-11-04)
  - Cryptographically signed reverse mappings (fingerprint → identity)
  - Sender identification without pre-added contacts
  - Prevents identity spoofing attacks
  - Cross-platform signature verification
- ✅ **PostgreSQL → SQLite Migration Complete!** (Phase 9.3 - 2025-11-03)
  - Fully decentralized storage (NO centralized database)
  - DHT-based groups with UUID v4 + SHA256 keys
  - Keyserver cache with 7-day TTL
  - Bootstrap deployment automation
- ✅ **Offline Message Queueing** (Phase 9.2 - 2025-11-02)
  - 7-day DHT storage for offline recipients
  - Automatic 2-minute polling
  - Binary serialization with magic bytes
- ✅ **cpunk Wallet Integration** (Phase 8)
  - View CPUNK, CELL, KEL balances
  - Send/receive tokens with QR codes
  - Full transaction history with color-coded status
  - Theme-aware wallet UI
- ✅ Full group messaging feature complete!
- ✅ Public key caching (100x API call reduction)
