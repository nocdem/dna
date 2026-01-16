# DNA Messenger - Roadmap

**DNA = Decentralized Network Applications**

**Version:** 0.5.x | **Last Updated:** 2026-01-16

---

## Current Status

**Active Development:** Phase 7 (Flutter UI - Cross-Platform)

| Component | Status |
|-----------|--------|
| Core Messaging | Production Ready |
| Group Encryption (GSK) | Production Ready |
| DHT-Only Transport | Production Ready |
| Spillway Protocol v2 | Production Ready |
| User Profiles & Avatars | Production Ready |
| DNA Board (Social) | Alpha |
| DNA Wallet | Production Ready |
| Android SDK (JNI) | Production Ready |
| Flutter App (Android/Linux/Windows) | Beta |

---

## Completed Features

### Core Infrastructure
- Post-quantum cryptography (Kyber1024 + Dilithium5 - NIST Category 5)
- OpenDHT-PQ fork (RSA-2048 → Dilithium5)
- Local SQLite storage (no centralized database)
- BIP39 24-word recovery phrases
- Cross-platform (Linux, Windows via MXE)

### Messaging
- End-to-end encrypted 1:1 messaging
- Message format v0.08 (fingerprint privacy, 28% size reduction)
- Delivery and read receipts
- Desktop notifications
- Offline message queueing (7-day DHT TTL)

### Groups
- DHT-based decentralized groups
- GSK (Group Symmetric Key) encryption - 200x performance improvement
- Automatic key rotation on member changes
- Group ownership transfer with liveness checks
- P2P group invitations

### Networking
- DHT-only transport layer (privacy-first, no IP leakage)
- Spillway Protocol v2: daily bucket message architecture
- Multi-device message sync (v0.4.60)
- Bootstrap node infrastructure (3 public nodes)
- DHT value persistence (SQLite-backed)

### Identity & Contacts
- Per-identity contact lists
- DHT sync with Kyber1024 self-encryption
- Signed reverse mappings (fingerprint → identity)
- Multi-device support via BIP39

### User Profiles
- Display name, bio, location, website
- Avatar system (128x128 JPEG, circular display with crop/pan/zoom)
- DHT storage with 7-day cache
- Profile editor and viewer

### DNA Board (Alpha)
- Decentralized message wall
- Community voting (thumbs up/down)
- Comment threading
- Dilithium5 signed posts
- 30-day TTL, 100 messages max

### DNA Wallet
- Multi-chain: CF20 (Cellframe), ERC20, TRC20, SPL networks
- Tokens: CPUNK, CELL, KEL, NYS, QEVM, ETH, SOL, TRX, USDT
- Send tokens directly from chat (auto-resolves contact wallet)
- Address book for saved recipients
- Send/receive with QR codes
- Transaction history

### Android SDK (Phase 6)
- JNI bindings for all dna_engine.h functions
- Java SDK classes (DNAEngine, Contact, Message, Group, etc.)
- Android Gradle library project
- Pre-built libdna_jni.so (16MB arm64-v8a)
- All dependencies statically linked (no external .so)
- 26 native methods exposed

---

## In Progress

### Phase 7: Flutter UI (Cross-Platform)
- Flutter/Dart UI for Android, Linux, Windows
- Chat list and conversation screens
- Contact and group management
- Wallet integration (balances, send)
- Profile and settings screens
- Debug log viewer (in-app)
- Biometric + PIN app lock

---

## Planned

### Phase 8: Web Messenger
- WebAssembly crypto module (Emscripten)
- Browser-based client (HTML5/CSS3)
- Progressive Web App (PWA)
- IndexedDB for local storage

### Phase 9: Voice/Video Calls
- Post-quantum key exchange via DNA messaging
- Kyber1024 session keys (bypasses WebRTC's quantum-vulnerable DTLS)
- libsrtp2 + AES-256-GCM media encryption
- libopus audio, libvpx video
- DHT-based signaling (privacy-preserving, no ICE)

### Phase 10+: Future
- iOS application
- Forward secrecy (ephemeral session keys)
- File transfer
- Tor integration (metadata protection)
- Enterprise features (SSO, audit logging)

---

## Version History

| Version | Date | Highlights |
|---------|------|------------|
| 0.5.2 | 2026-01-16 | Memory leak fix in outbox listeners |
| 0.5.0 | 2026-01-15 | Spillway Protocol v2: daily bucket architecture |
| 0.4.61 | 2026-01-10 | **ICE/STUN/TURN removal** - DHT-only privacy architecture |
| 0.4.60 | 2026-01-08 | Multi-device message sync |
| 0.4.50 | 2025-12-20 | Flutter UI beta (Android/Linux/Windows) |
| 0.4.0 | 2025-12-15 | Major DM outbox architecture refactor |
| 0.3.50 | 2025-12-10 | Debug log viewer, app lock (biometric + PIN) |
| 0.2.0 | 2025-12-01 | Flutter migration begins (ImGui → Flutter) |
| 0.1.130+ | 2025-11-28 | Android SDK (JNI bindings, Java classes, Gradle project) |
| 0.1.120+ | 2025-11-21 | GSK group encryption (200x speedup) |
| 0.1.115 | 2025-11-18 | Message format v0.08 (fingerprint privacy) |
| 0.1.100 | 2025-11-16 | DHT refactoring complete, profile system unification |
| 0.1.80 | 2025-11-10 | ImGui GUI migration (Qt → ImGui) |
| 0.1.50 | 2025-11-03 | PostgreSQL → SQLite migration complete |
| 0.1.30 | 2025-10-23 | DNA Wallet integration |
| 0.1.0 | 2025-10-14 | Initial fork from QGP |

---

## Technical Debt

- [ ] Forward secrecy implementation
- [x] Multi-device message sync (v0.4.60)
- [ ] Security audit
- [ ] Performance optimization for large groups (100+ members)

---

## Major Architecture Changes

### v0.5.0: Spillway Protocol v2 (2026-01-15)
Daily bucket architecture for offline message retrieval:
- Messages organized by UTC day buckets instead of individual keys
- Significantly reduced DHT lookups for offline sync
- Improved multi-device message consistency

### v0.4.61: DHT-Only Architecture (2026-01-10)
Removed ICE/STUN/TURN for privacy:
- No IP address leakage to peers or third parties
- All messaging via DHT (no direct peer connections)
- Bootstrap nodes provide discovery only, not relay
- Privacy-first design principle

### v0.2.0: Flutter Migration (2025-12-01)
UI framework migration:
- ImGui (C++) → Flutter (Dart)
- Single codebase for Android, Linux, Windows
- Native platform integration via FFI

---

## Contributing

- Check `CLAUDE.md` for development guidelines
- Follow existing code patterns
- Submit PRs to `main` branch
- Test on Linux and Windows before committing

---

**Project Start:** 2025-10-14 | **Current Phase:** 7 | **Next Milestone:** Flutter UI completion + iOS
