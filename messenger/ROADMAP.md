# DNA Messenger - Roadmap

**Version:** 0.1.x | **Last Updated:** 2025-11-26

---

## Current Status

**Active Development:** Phase 6.4 (DNA Board - Profile Extensions)

| Component | Status |
|-----------|--------|
| Core Messaging | Production Ready |
| Group Encryption (GSK) | Production Ready |
| ICE NAT Traversal | Production Ready |
| User Profiles & Avatars | Production Ready |
| DNA Board (Social) | Alpha |
| cpunk Wallet | Production Ready |

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
- P2P transport layer (OpenDHT + TCP)
- ICE NAT traversal (libjuice + STUN)
- 3-tier fallback: LAN → ICE → DHT queue
- Bootstrap node infrastructure (3 public nodes)
- DHT value persistence (SQLite-backed)

### Identity & Contacts
- Per-identity contact lists
- DHT sync with Kyber1024 self-encryption
- Signed reverse mappings (fingerprint → identity)
- Multi-device support via BIP39

### User Profiles
- Display name, bio, location, website
- Avatar system (64x64 JPEG, circular display)
- DHT storage with 7-day cache
- Profile editor and viewer

### DNA Board (Alpha)
- Decentralized message wall
- Community voting (thumbs up/down)
- Comment threading
- Dilithium5 signed posts
- 30-day TTL, 100 messages max

### cpunk Wallet
- CPUNK, CELL, KEL token balances
- Send/receive via Cellframe RPC
- QR code generation
- Transaction history

---

## In Progress

### Phase 6.4: DNA Board Enhancements
- Profile extensions (social links: Telegram, Twitter, GitHub)
- Crypto addresses for tipping (BTC, ETH, CPUNK)
- Feed sorting (Recent, Top, Controversial)

---

## Planned

### Phase 7: Web Messenger
- WebAssembly crypto module (Emscripten)
- Browser-based client (HTML5/CSS3)
- Progressive Web App (PWA)
- IndexedDB for local storage

### Phase 8: Voice/Video Calls
- Post-quantum key exchange via DNA messaging
- Kyber1024 session keys (bypasses WebRTC's quantum-vulnerable DTLS)
- libsrtp2 + AES-256-GCM media encryption
- libopus audio, libvpx video
- ICE NAT traversal via libjuice

### Phase 9+: Future
- Mobile applications (Flutter)
- Forward secrecy (ephemeral session keys)
- File transfer
- Tor integration (metadata protection)
- Enterprise features (SSO, audit logging)

---

## Version History

| Version | Date | Highlights |
|---------|------|------------|
| 0.1.120+ | 2025-11-21 | GSK group encryption (200x speedup) |
| 0.1.115 | 2025-11-18 | Message format v0.08, ICE NAT traversal production-ready |
| 0.1.110 | 2025-11-17 | P2P group invitations, community voting, avatar system |
| 0.1.100 | 2025-11-16 | DHT refactoring complete, profile system unification |
| 0.1.90 | 2025-11-13 | Encrypted DHT identity backup |
| 0.1.80 | 2025-11-10 | ImGui GUI migration (Qt → ImGui) |
| 0.1.70 | 2025-11-05 | Per-identity contact lists with DHT sync |
| 0.1.60 | 2025-11-04 | DHT keyserver with signed reverse mappings |
| 0.1.50 | 2025-11-03 | PostgreSQL → SQLite migration complete |
| 0.1.40 | 2025-11-02 | Offline message queueing |
| 0.1.30 | 2025-10-23 | cpunk wallet integration |
| 0.1.0 | 2025-10-14 | Initial fork from QGP |

---

## Technical Debt

- [ ] Forward secrecy implementation
- [ ] Multi-device message sync
- [ ] Security audit
- [ ] Performance optimization for large groups (100+ members)

---

## Contributing

- Check `CLAUDE.md` for development guidelines
- Follow existing code patterns
- Submit PRs to `main` branch
- Test on Linux and Windows before committing

---

**Project Start:** 2025-10-14 | **Current Phase:** 6.4 | **Next Milestone:** Web Messenger (Phase 7)
