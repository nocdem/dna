# DNA Messenger - Development Roadmap

**Version:** 0.1.110-alpha
**Last Updated:** 2025-10-17
**Project Status:** Phase 5 (Web-Based Messenger) - Phase 4 Complete

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

## Phase 3: CLI Messenger Client ✅ COMPLETE

**Timeline:** 2-3 weeks
**Status:** Complete

### Objectives
- Build reference messenger implementation
- Command-line chat interface
- PostgreSQL message storage
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

## Phase 8: Advanced Features 📋 PLANNED

**Timeline:** 4-6 weeks
**Status:** Not started
**Prerequisites:** Phase 5 complete

### CF20 Wallet Integration (Cellframe cpunk Network)
- [ ] Read local Cellframe wallet files
- [ ] Connect via public RPC to cpunk network
- [ ] Display CF20 token balances
- [ ] Send CF20 tokens directly in messenger
- [ ] Receive CF20 tokens with QR codes
- [ ] Transaction history and tracking
- [ ] Wallet address management
- [ ] Payment notifications and confirmations

---

## Phase 9: Distributed P2P Architecture 📋 FUTURE PLANS

**Timeline:** ~6 months (long-term vision)
**Status:** Research & Design phase
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

#### Phase 9.1: P2P Transport Layer (6-8 weeks)
- [ ] Integrate libp2p (C++) or libdatachannel (C)
- [ ] Implement Kademlia DHT for peer discovery
- [ ] NAT traversal using libnice (ICE/STUN/TURN)
- [ ] Direct peer-to-peer messaging
- [ ] Bootstrap node infrastructure (3-5 public nodes)
- [ ] Connection management and reconnection

#### Phase 9.2: Distributed Storage Layer (6-8 weeks)
- [ ] Integrate OpenDHT for distributed message storage
- [ ] Encrypted blob storage in DHT (k=5 replication)
- [ ] Store-and-forward protocol for offline users
- [ ] Automatic garbage collection (30-day expiry)
- [ ] Message retrieval and deletion protocol

#### Phase 9.3: Local Cache & Sync (4 weeks)
- [ ] SQLite encrypted with DNA's PQ crypto (Kyber512 + AES-256-GCM)
- [ ] Background sync protocol (local ↔ DHT)
- [ ] Multi-device message synchronization
- [ ] Offline mode with automatic sync on reconnect
- [ ] Incremental sync for large histories

#### Phase 9.4: Distributed DHT Keyserver (4 weeks)
- [ ] Store public keys in DHT (replicated)
- [ ] Replace centralized HTTP keyserver
- [ ] Self-signed key verification (TOFU model)
- [ ] Key rotation and update protocol
- [ ] Optional: Blockchain anchoring for tamper-proofing

#### Phase 9.5: Integration & Testing (4 weeks)
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

## Phase 10+: Future Enhancements 📋 PLANNED

### Voice/Video Calls (Post-Quantum)
- [ ] Kyber512-based session key exchange via DNA messaging
- [ ] Dilithium3 signatures for call authentication
- [ ] Custom SRTP with PQ-derived keys (AES-256-GCM)
- [ ] libnice NAT traversal (ICE/STUN/TURN - reuse from Phase 9)
- [ ] libopus audio codec integration
- [ ] libvpx video codec (VP8) integration
- [ ] PortAudio for microphone/speaker I/O
- [ ] Short Authentication String (SAS) verification
- [ ] Screen sharing (H.264 codec)
- [ ] Call quality monitoring and statistics
- [ ] Group voice/video calls (mesh topology)

**Design Document:** `/futuredesign/VOICE-VIDEO-DESIGN.md`

**Key Advantage:** Full post-quantum security (bypasses WebRTC's quantum-vulnerable DTLS handshake)

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
| 0.4.0 | Phase 4 | ✅ Complete | Desktop app |
| 0.5.0 | Phase 5 | 🚧 In Progress | Web messenger (WebAssembly) |
| 1.0.0 | Phase 6-7 | 📋 Planned | Mobile + Advanced Security (first stable release) |
| 1.1.0 | Phase 6 | 📋 Planned | Mobile apps |
| 1.2.0 | Phase 7 | 📋 Planned | Advanced security |
| 1.3.0 | Phase 8 | 📋 Planned | Future enhancements |

**Current Version:** 0.1.110-alpha (auto-incremented with each commit)

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
- **Phase 3:** CLI Messenger Client
- **Phase 4:** Desktop Application (with groups!)

### 🚧 In Progress
- **Phase 5:** Web-Based Messenger (active on `feature/web-messenger` branch)

### 📋 Planned
- **Phase 6:** Mobile Applications
- **Phase 7:** Advanced Security Features
- **Phase 8:** CF20 Wallet Integration
- **Phase 9:** Distributed P2P Architecture (libp2p + OpenDHT)
- **Phase 10+:** Future Enhancements

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
**Current Version:** 0.1.110-alpha
**Next Milestone:** Web Messenger (Phase 5)
**Recent Achievements:**
- ✅ Full group messaging feature complete!
- ✅ Public key caching (100x API call reduction)
- ✅ Inline keyserver registration (no external utilities)
