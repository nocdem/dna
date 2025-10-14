# DNA Messenger - Development Roadmap

**Version:** 0.1.0-alpha
**Last Updated:** 2025-10-14
**Project Status:** Fork Preparation Phase

---

## Overview

DNA Messenger is a post-quantum end-to-end encrypted messaging platform forked from QGP (file encryption tool). This roadmap outlines the development phases from initial fork to production-ready messenger application.

**Philosophy:** Simple first, secure later. Focus on core functionality before adding advanced security features.

---

## Phase 1: Fork Preparation ✅ IN PROGRESS

**Timeline:** 1-2 days
**Status:** 90% complete

### Objectives
- Fork QGP repository
- Update branding and documentation
- Verify build system works
- Initialize git repository

### Tasks
- [x] Create fork at `/opt/dna-messenger`
- [x] Clean up build artifacts
- [x] Update `README.md` with DNA Messenger branding
- [x] Update `CLAUDE.md` with messenger development guidelines
- [x] Create `ROADMAP.md` (this file)
- [ ] Update `CMakeLists.txt` (project name, version)
- [ ] Update `main.c` (help text, version info)
- [ ] Verify build works (`make` runs successfully)
- [ ] Initialize git repository
- [ ] Create initial commit

### Deliverables
- Forked repository with DNA branding
- Updated documentation
- Working build system
- Initial git commit

---

## Phase 2: Library API Design

**Timeline:** 1-2 weeks
**Status:** Not started
**Prerequisites:** Phase 1 complete

### Objectives
- Design memory-based API for messenger operations
- Refactor file-based operations to memory-based
- Create public API header (`dna_api.h`)
- Write API documentation

### Tasks

#### API Design
- [ ] Design `dna_api.h` (public API header)
- [ ] Define error codes (`dna_error_t`)
- [ ] Define context structure (`dna_context_t`)
- [ ] Define buffer structure (`dna_buffer_t`)

#### Core Functions
- [ ] Context management (`dna_context_new`, `dna_context_free`)
- [ ] Key generation (`dna_keygen_signing`, `dna_keygen_encryption`)
- [ ] Message encryption (`dna_encrypt_message`)
- [ ] Message decryption (`dna_decrypt_message`)
- [ ] Signature functions (`dna_sign`, `dna_verify`)

#### Refactoring
- [ ] Refactor `encrypt.c` for memory-based operations
- [ ] Refactor `decrypt.c` for memory-based operations
- [ ] Refactor `sign.c` and `verify.c` for memory-based operations
- [ ] Create buffer management utilities

#### Documentation
- [ ] API reference documentation (`docs/API.md`)
- [ ] Integration examples (`examples/basic_usage.c`)
- [ ] Memory management guidelines

### Deliverables
- `dna_api.h` - Public API header
- `libdna.so` / `dna.dll` - Shared library
- `libdna.a` - Static library
- API documentation
- Integration examples

---

## Phase 3: CLI Messenger Client

**Timeline:** 2-3 weeks
**Status:** Not started
**Prerequisites:** Phase 2 complete

### Objectives
- Build reference messenger implementation
- Command-line chat interface
- Local message storage
- Contact management

### Tasks

#### CLI Interface
- [ ] Command-line argument parsing
- [ ] Interactive chat mode
- [ ] Contact list commands
- [ ] Message history commands

#### Message Storage
- [ ] Design local storage format (SQLite)
- [ ] Message persistence
- [ ] Contact database
- [ ] Key storage integration

#### Messaging Operations
- [ ] Send message (encrypt for recipient)
- [ ] Receive message (decrypt from sender)
- [ ] List conversations
- [ ] Search message history

#### Contact Management
- [ ] Add contact (import public key)
- [ ] List contacts
- [ ] Delete contact
- [ ] Key fingerprint verification

### Deliverables
- `dna` - CLI messenger client
- Local message database
- Contact management system
- User documentation

---

## Phase 4: Network Layer

**Timeline:** 3-4 weeks
**Status:** Not started
**Prerequisites:** Phase 3 complete

### Objectives
- Network transport implementation
- Message routing
- Offline message queue
- P2P discovery (optional)

### Tasks

#### Transport Layer
- [ ] WebSocket client/server
- [ ] Message serialization (Protocol Buffers / JSON)
- [ ] Connection management
- [ ] Reconnection handling

#### Message Routing
- [ ] User addressing scheme (username@server or pubkey hash)
- [ ] Message delivery confirmation
- [ ] Offline message storage
- [ ] Message sync on reconnect

#### P2P Discovery (Optional)
- [ ] mDNS local discovery
- [ ] DHT for peer discovery
- [ ] NAT traversal (STUN/TURN)

#### Server Implementation
- [ ] Message relay server (optional, for initial testing)
- [ ] User registration
- [ ] Message queueing for offline users

### Deliverables
- Network-enabled CLI client
- Message relay server (reference implementation)
- Network protocol specification
- Deployment documentation

---

## Phase 5: Desktop Application

**Timeline:** 4-6 weeks
**Status:** Not started
**Prerequisites:** Phase 4 complete

### Objectives
- Qt-based desktop GUI
- Cross-platform (Linux, Windows, macOS)
- Rich messaging features
- System notifications

### Tasks

#### GUI Development
- [ ] Qt application framework
- [ ] Conversation list view
- [ ] Chat window interface
- [ ] Contact management UI
- [ ] Settings panel

#### Features
- [ ] Rich text formatting
- [ ] File transfer
- [ ] Image previews
- [ ] Emoji support
- [ ] System tray integration

#### Platform Support
- [ ] Linux build
- [ ] Windows build
- [ ] macOS build
- [ ] Application packaging (AppImage, MSI, DMG)

### Deliverables
- `dna-desktop` - Desktop application
- Installation packages
- User manual
- Platform-specific builds

---

## Phase 6: Mobile Applications

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

## Phase 7: Advanced Security Features

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

## Phase 8: Group Messaging

**Timeline:** 4-5 weeks
**Status:** Not started
**Prerequisites:** Phase 7 complete

### Objectives
- Group chat support
- Group key management
- Group administration

### Tasks

#### Group Implementation
- [ ] Group creation
- [ ] Member management
- [ ] Group encryption (sender keys)
- [ ] Group message history

#### Group Administration
- [ ] Add/remove members
- [ ] Admin permissions
- [ ] Group settings
- [ ] Group invitations

### Deliverables
- Group messaging feature
- Group administration tools
- Group security documentation

---

## Future Enhancements (Phase 9+)

### Voice/Video Calls
- WebRTC integration
- TURN server infrastructure
- Call encryption
- Screen sharing

### Advanced Features
- Stickers and GIFs
- Bots and automation
- Channels (broadcast mode)
- Stories/Status updates

### Infrastructure
- Decentralized architecture (Matrix-style federation)
- Tor integration (metadata protection)
- Bridge to other platforms (Signal, WhatsApp)

### Enterprise Features
- Organization management
- Compliance tools
- Audit logging
- SSO integration

---

## Success Criteria

### Phase 1-2 (Foundation)
- ✅ Repository forked and branded
- ✅ Library API compiles without errors
- ✅ Memory-based operations working
- ✅ API documentation complete

### Phase 3 (CLI Messenger)
- ✅ Alice can send message to Bob via CLI
- ✅ Bob can decrypt and read message
- ✅ Messages persist across sessions
- ✅ Contact list works

### Phase 4 (Network)
- ✅ Messages delivered over network
- ✅ Offline messages queued and delivered
- ✅ Connection resilience tested
- ✅ Multi-client support

### Phase 5-6 (Desktop/Mobile)
- ✅ GUI applications working on all platforms
- ✅ File transfer functional
- ✅ Push notifications working (mobile)
- ✅ User onboarding smooth

### Phase 7-8 (Advanced Features)
- ✅ Forward secrecy working
- ✅ Multi-device sync functional
- ✅ Group messaging working
- ✅ Security audit passed

---

## Risk Management

### Technical Risks
- **Cryptographic bugs**: Mitigate with extensive testing and code review
- **Network complexity**: Start with simple relay server, add P2P later
- **Cross-platform issues**: Test on all platforms continuously

### Resource Risks
- **Development time**: Phases can be extended if needed
- **Testing effort**: Automate testing where possible
- **Documentation**: Write docs as features are developed

### Security Risks
- **Quantum attacks**: Already mitigated (post-quantum algorithms)
- **Implementation bugs**: Code review + security audit
- **Side-channel attacks**: Address in Phase 7 (secure memory)

---

## Version Milestones

| Version | Phase | Status | Description |
|---------|-------|--------|-------------|
| 0.1.0 | Phase 1 | In Progress | Fork preparation |
| 0.2.0 | Phase 2 | Planned | Library API |
| 0.3.0 | Phase 3 | Planned | CLI messenger |
| 0.4.0 | Phase 4 | Planned | Network layer |
| 1.0.0 | Phase 5 | Planned | Desktop app (first stable release) |
| 1.1.0 | Phase 6 | Planned | Mobile apps |
| 1.2.0 | Phase 7 | Planned | Advanced security |
| 1.3.0 | Phase 8 | Planned | Group messaging |

---

## Contributing

DNA Messenger is in early development. Contributions welcome!

**Current Phase:** Fork Preparation
**How to Contribute:**
- Check `CLAUDE.md` for development guidelines
- Pick tasks from current phase
- Submit pull requests to `develop` branch
- Follow existing code style

---

**Project Start:** 2025-10-14
**Current Version:** 0.1.0-alpha
**Next Milestone:** Library API Design (v0.2.0)
