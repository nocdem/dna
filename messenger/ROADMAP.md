# DNA Messenger - Development Roadmap

**Version:** 0.6.x | **Last Updated:** 2026-02-22

---

## Project Timeline

```
Oct 2025                              Jan 2026
   │                                     │
   ▼                                     ▼
   ┌─────┬─────┬─────┬─────┬─────┬─────┬─────┐
   │ P2  │ P3  │ P4  │ P5  │ P6  │ P7  │ NOW │
   │ API │ CLI │ DHT │ GUI │ SDK │ App │     │
   └─────┴─────┴─────┴─────┴─────┴─────┴─────┘
     │     │     │     │     │     │
     │     │     │     │     │     └─ Flutter cross-platform
     │     │     │     │     └─ Android JNI SDK
     │     │     │     └─ Qt → ImGui → Flutter
     │     │     └─ P2P Transport, DHT, GEK
     │     └─ PostgreSQL → SQLite
     └─ Core library API
```

---

## Current Status

**Active:** Phase 7 (Flutter UI - Cross-Platform)

| Component | Status | Version |
|-----------|--------|---------|
| C Library (libdna_engine) | Production | v0.6.121 |
| Flutter App | Beta | v0.100.91 |
| Android SDK (JNI) | Production | v0.6.121 |
| DNA Nodus (Bootstrap) | Production | v0.4.5 |

---

## Development History

### Phase 1: Foundation (October 2025)
**Fork from QGP (Quantum Good Privacy)**

- Forked QGP codebase as starting point
- Post-quantum cryptography foundation (Kyber1024 + Dilithium5)
- NIST Category 5 security level (256-bit quantum resistance)
- Basic key generation and encryption primitives

### Phase 2: Library API (October 2025)
**Core messenger library development**

- `dna_engine.h` - Public C API design
- Kyber1024 key encapsulation
- Dilithium5 digital signatures
- AES-256-GCM symmetric encryption
- SHA3-512 hashing
- BIP39 24-word seed phrase generation
- Key derivation from mnemonic

### Phase 3: CLI Messenger (October 2025)
**PostgreSQL-based command-line messenger**

- PostgreSQL keyserver for public key distribution
- CLI interface for sending/receiving messages
- Multi-recipient encryption
- Message decryption with sender verification
- Server configuration system
- Cross-platform build (Linux, Windows)

### Phase 4: P2P Network (October-November 2025)
**Decentralized transport layer**

- OpenDHT-PQ fork (RSA → Dilithium5)
- DHT-based message routing
- Offline message queueing (7-day TTL)
- Bootstrap node infrastructure
- NAT traversal with ICE/STUN *(later removed)*
- Presence system for online status

### Phase 5: Desktop GUI (November 2025)
**Qt5 → ImGui migration**

```
Qt5 GUI (v0.1.60)
    │
    │  Too heavy, complex deployment
    ▼
ImGui GUI (v0.1.80)
    │
    │  C++ only, no mobile support
    ▼
Flutter UI (v0.2.0+)
```

- Initial Qt5 GUI with theming (cpunk.io cyan, cpunk.club orange)
- Auto-update mechanism
- Message search and filtering
- **Migration to ImGui** - Lighter, embedded in C++
- Custom styling and font scaling
- Push notifications with sound alerts

### Phase 5.5: Database Migration (November 2025)
**PostgreSQL → SQLite**

- Removed centralized PostgreSQL dependency
- Local SQLite storage per user
- Per-identity contact databases
- DHT keyserver with signed reverse mappings
- Encrypted DHT identity backup

### Phase 6: Android SDK (November 2025)
**JNI bindings for mobile**

- Complete JNI bindings for `dna_engine.h`
- Java SDK classes:
  - `DNAEngine` - Main API wrapper
  - `Contact`, `Message`, `Group`
  - `Wallet`, `Transaction`
- Android Gradle library project
- Pre-built `libdna_jni.so` (arm64-v8a)
- 26 native methods exposed
- All dependencies statically linked (16MB)

### Phase 7: Flutter UI (December 2025 - Present)
**Cross-platform mobile & desktop**

- **Flutter/Dart** single codebase
- Platforms: Android, Linux, Windows (iOS planned)
- dart:ffi bindings to C library
- Riverpod state management
- Features implemented:
  - Chat list and conversations
  - Contact management
  - Group creation and messaging
  - DNA Wallet (multi-chain)
  - User profiles with avatars
  - Settings and debug log viewer
  - Biometric + PIN app lock
  - QR code scanning

---

## Architecture Evolution

### v0.1.x: Centralized Era (Oct-Nov 2025)
```
Client → PostgreSQL Server → Client
```
- Central keyserver for public keys
- Direct database queries
- Simple but not scalable

### v0.2.x-v0.3.x: Hybrid Era (Nov-Dec 2025)
```
Client → DHT ←→ Client
           ↓
    Bootstrap Nodes
           ↓
    ICE/STUN/TURN
```
- DHT for decentralized storage
- ICE for NAT traversal
- 3-tier fallback: LAN → ICE → DHT

### v0.4.x: Privacy Era (Dec 2025 - Jan 2026)
```
Client → DHT ←→ Client
           ↓
    Bootstrap Nodes (discovery only)
```
- **ICE/STUN/TURN removed** (v0.4.61)
- DHT-only transport
- No IP leakage to peers
- Privacy-first architecture

### v0.5.x: Efficiency Era (Jan 2026)
```
Client → DHT (daily buckets) ←→ Client
```
- **Spillway Protocol v2**
- Daily bucket message organization
- Reduced DHT lookups for offline sync
- Multi-device message consistency

### v0.6.x: Stability & Cache Era (Jan-Feb 2026)
```
Client → DHT (cached) ←→ Client
         ↓
    Local Feed Cache (SQLite)
```
- **Android lifecycle** overhaul (destroy/create pattern)
- Feed system rewrite with chunked DHT storage
- **Feed cache** with stale-while-revalidate strategy
- Group message status tracking
- Major Android stability sprint (crash/freeze fixes)

---

## Key Milestones

| Version | Date | Milestone |
|---------|------|-----------|
| v0.1.0 | 2025-10-14 | Initial fork from QGP |
| v0.1.30 | 2025-10-23 | DNA Wallet integration |
| v0.1.50 | 2025-11-03 | PostgreSQL → SQLite migration |
| v0.1.80 | 2025-11-10 | Qt → ImGui GUI migration |
| v0.1.100 | 2025-11-16 | DHT refactoring, profile unification |
| v0.1.115 | 2025-11-18 | Message format v0.08 (fingerprint privacy) |
| v0.1.120+ | 2025-11-21 | GEK group encryption (200x speedup) |
| v0.1.130+ | 2025-11-28 | Android SDK complete |
| v0.2.0 | 2025-12-01 | Flutter migration begins |
| v0.3.50 | 2025-12-10 | Debug log viewer, app lock |
| v0.3.162 | 2025-12-18 | QR authentication with Dilithium5 |
| v0.4.0 | 2025-12-15 | DM outbox architecture refactor |
| v0.4.50 | 2025-12-20 | Flutter UI beta |
| v0.4.60 | 2026-01-08 | Multi-device message sync |
| v0.4.61 | 2026-01-10 | **ICE/STUN/TURN removal** - DHT-only |
| v0.5.0 | 2026-01-15 | Spillway Protocol v2 |
| v0.5.2 | 2026-01-16 | Memory leak fixes, stability |
| v0.5.5 | 2026-01-17 | Android lightweight background mode |
| v0.6.101 | 2026-01-28 | Group message status tracking |
| v0.6.104 | 2026-01-30 | Feed system rewrite with chunked DHT |
| v0.6.108 | 2026-02-03 | Android lifecycle race condition fixes |
| v0.6.113 | 2026-02-10 | Replace busy-wait polling with condition variables |
| v0.6.117 | 2026-02-15 | Global DB singleton cleanup |
| v0.6.119 | 2026-02-19 | Non-fatal presence registration |
| v0.6.121 | 2026-02-22 | **Feed cache system** (stale-while-revalidate) |

---

## Features Completed

### Messaging
- [x] End-to-end encryption (Kyber1024 + AES-256-GCM)
- [x] 1:1 direct messaging
- [x] Group messaging with GEK encryption
- [x] Delivery and read receipts
- [x] Offline message queue (7-day TTL)
- [x] Message format v0.08 (fingerprint privacy)
- [x] Multi-device sync

### Groups
- [x] DHT-based decentralized groups
- [x] GEK (Group Symmetric Key) - 200x faster
- [x] Automatic key rotation on member changes
- [x] Group ownership transfer
- [x] P2P group invitations
- [x] GEK (Group Encryption Key) versioning

### Network
- [x] OpenDHT-PQ (Dilithium5 signatures)
- [x] DHT-only transport (no ICE)
- [x] Spillway Protocol v2 (daily buckets)
- [x] Bootstrap node infrastructure
- [x] "Never Give Up" retry system
- [x] Chunked DHT storage for large values

### Identity
- [x] BIP39 24-word recovery
- [x] Per-identity contact lists
- [x] DHT contact sync (Kyber1024 encrypted)
- [x] Signed reverse mappings
- [x] Multi-device via seed phrase

### Profiles
- [x] Display name, bio, location, website
- [x] Avatar (128x128 JPEG, crop/pan/zoom)
- [x] DHT storage with 7-day cache
- [x] Profile editor

### DNA Board
- [x] Decentralized message wall
- [x] Community voting
- [x] Comment threading
- [x] Dilithium5 signed posts

### DNA Wallet
- [x] Multi-chain: CF20, ERC20, TRC20, SPL
- [x] 9+ tokens supported
- [x] Send from chat (auto wallet resolve)
- [x] Address book
- [x] QR codes
- [x] Transaction history

### Security
- [x] NIST Category 5 quantum resistance
- [x] Biometric + PIN app lock
- [x] No IP leakage (DHT-only)
- [x] No metadata collection

---

## In Progress

### Phase 7 Completion
- [x] Feed cache system (stale-while-revalidate)
- [x] Android lifecycle stability
- [x] Group message status tracking
- [x] Feed subscription management
- [ ] iOS build support
- [ ] Desktop notifications (Linux/Windows)
- [ ] File/image sharing
- [ ] Message search
- [ ] Chat export

---

## Planned

### Phase 15: Web Messenger
- WebAssembly crypto module
- Browser-based client
- Progressive Web App (PWA)
- IndexedDB storage

### Phase 16: Voice/Video
- Post-quantum key exchange
- Kyber1024 session keys
- AES-256-GCM media encryption
- DHT-based signaling

### Phase 17+: Future
- iOS native app
- Forward secrecy
- Tor integration
- Enterprise features

---

## Technical Debt

- [ ] Forward secrecy (ephemeral keys)
- [x] ~~Security audit~~ (completed 2026-01-25)
- [ ] Large group optimization (100+ members)
- [ ] Desktop notification system
- [x] ~~Multi-device sync~~ (v0.4.60)
- [x] ~~ICE complexity~~ (removed v0.4.61)

---

## Contributing

1. Check `CLAUDE.md` for guidelines
2. Follow existing code patterns
3. Test on Linux and Windows
4. Submit PRs to `main` branch

---

## Links

- **GitLab:** https://gitlab.cpunk.io/cpunk/dna-messenger
- **GitHub:** https://github.com/nocdem/dna-messenger
- **Website:** https://cpunk.io
- **Community:** https://cpunk.club

---

**Project Start:** 2025-10-14 | **Current Phase:** 7 | **Library:** v0.6.121 | **App:** v0.100.91
