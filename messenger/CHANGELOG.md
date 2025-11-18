# Changelog

All notable changes to DNA Messenger will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.121] - 2025-11-18

### Security Fixes ✅ CRITICAL

This release fixes **3 critical security vulnerabilities** identified in comprehensive security audit.

#### Fixed

- **CRITICAL:** Fixed weak UUID generation using insecure `rand()` fallback (VULN-002, CWE-330)
  - Replaced `rand()` with cryptographically secure `qgp_randombytes()`
  - Fail securely if randomness unavailable (no fallback)
  - Prevents predictable group UUIDs and unauthorized access
  - Files: `dht/shared/dht_groups.c`

- **CRITICAL:** Fixed path traversal vulnerability on Windows (VULN-003, CWE-22)
  - Added explicit validation for backslash (`\`), colon (`:`), and dot (`.`)
  - Prevents arbitrary file writes via crafted identity strings
  - Files: `database/contacts_db.c`

- **CRITICAL:** Fixed command injection risk via `popen()` (VULN-001, CWE-78)
  - Replaced `popen()` with libcurl for HTTP requests
  - Added HTTPS-only protocol whitelist
  - Added timeout (30s) and redirect limits (3)
  - Files: `messenger/keys.c`

#### Added

- **SECURITY.md** - Comprehensive security advisory and best practices guide
- **CHANGELOG.md** - Version history and change log

#### Changed

- Improved security posture from **B+** (Good) to **A-** (Excellent)
- All critical vulnerabilities patched and production-ready

### Notes

- **Breaking Changes:** None
- **Database Migration:** None required
- **API Changes:** None (internal fixes only)

---

## [0.1.120] - 2025-11-18

### Added

- **Phase 12:** Message Format v0.07 - Fingerprint privacy upgrade
  - Sender fingerprint encrypted inside payload (64 bytes)
  - Public key removed from signature block (2592 bytes saved)
  - 28.5% message size reduction (8,951 → 6,418 bytes for 100-byte message)
  - Breaking change from v0.06

- **Phase 11:** ICE NAT Traversal - Production-ready
  - Fixed 7 critical architectural bugs
  - Persistent ICE connections with caching
  - Connection reuse (150x speedup: 15s → 100ms)
  - Bidirectional communication
  - ~1,350 LOC total implementation

- **Phase 10.4:** Community voting system
  - Thumbs up/down voting on wall posts
  - Dilithium5 signatures (Category 5 security)
  - Permanent votes (one per fingerprint)
  - Net score display with color coding

### Fixed

- ICE connections now persistent (not created per-message)
- ICE context stays alive (not destroyed after candidate publish)
- ICE connections cached in connections[] array
- ICE receive thread for bidirectional communication
- ICE initialization at startup (no race conditions)
- Per-peer ICE contexts with clean resource management
- Unified TCP/ICE architecture (persistent lifecycle)

---

## [0.1.119] - 2025-11-17

### Added

- **Phase 10.3:** Avatar system
  - User avatars with DHT storage
  - Base64 encoding/decoding
  - 64x64 PNG auto-resize via stb_image
  - OpenGL texture loading with TextureManager singleton
  - Circular clipping (ImDrawList::AddImageRounded)
  - 20KB buffer size (up from 12KB)
  - Display in profile editor, contact viewer, wall posts, chat messages

- **Phase 5.6:** P2P group invitations
  - Encrypted invitation messages (Kyber1024 + AES-256-GCM)
  - Rich UI with group details and member count
  - Accept/Decline workflow
  - DHT group sync on acceptance
  - Invitations persist in message history
  - ~300 LOC implementation

### Changed

- Database schema v4 → v5 (message_type, invitation_status fields)
- Wall post identification fix (post_id uses poster fingerprint)

---

## [0.1.118] - 2025-11-16

### Added

- **Phase 10.2:** DNA Board Alpha
  - Wall posting (dna_message_wall.c - 18,717 lines)
  - Wall viewing ("Wall" button)
  - Profile editor (own profile)
  - Contact profile viewer ("View Details" context menu)
  - DHT contact sync ("Refresh" button)
  - Create Group Dialog (Phase 1.3)
  - Backend stub implementations

### Changed

- Windows cross-compile fixed (platform-specific network headers)

---

## [0.1.117] - 2025-11-13

### Added

- **Phase 9.6:** Encrypted DHT identity backup
  - Random RSA-2048 generated once
  - Encrypted with Kyber1024 + AES-256-GCM
  - Stored locally + DHT (PERMANENT TTL)
  - Seamless BIP39 recovery
  - 1,484+ lines of code

### Changed

- `dht/dht_identity_backup.[ch]` (595 lines) - Create/load/fetch/publish
- `dht_context.cpp` (+327) - Identity export/import
- `dht_singleton.[ch]` (+61) - Init with permanent identity

---

## [0.1.116] - 2025-11-12

### Added

- **Phase 10.1:** User profiles
  - DHT storage (470 lines)
  - Cache DB (550 lines)
  - Smart fetch (235 lines)
  - 7-day TTL with stale fallback
  - Fields: display name, bio, avatar hash, location, website, timestamps

---

## [0.1.115] - 2025-11-11

### Changed

- **Model E Migration:** Sender outbox model
  - Zero DHT accumulation (was 8-40 values)
  - 99.9% query reduction
  - Spam prevention
  - Documentation: `/opt/dna-messenger/docs/MODEL_E_MIGRATION.md`

---

## [0.1.114] - 2025-11-10

### Fixed

- **Critical:** Queue key mismatch fixed
  - `resolve_identity_to_fingerprint()` ensures fingerprint-based keys
  - Offline message delivery now working correctly

---

## [0.1.110] - 2025-11-05

### Added

- **Phase 9.5:** Per-identity contacts + DHT sync
  - Per-identity SQLite: `~/.dna/<identity>_contacts.db`
  - DHT sync (Kyber1024 self-encrypted)
  - Multi-device via BIP39

### Changed

- **Phase 4:** Fingerprint-first identity creation
  - Filenames: `~/.dna/<fingerprint>.{dsa,kem}`
  - SHA3-512 (128 hex chars)
  - DHT validation

---

## [0.1.109] - 2025-11-04

### Added

- **Phase 9.4:** DHT keyserver + signed reverse mapping
  - Reverse mapping: `SHA256(fingerprint + ":reverse")` → signed identity
  - Sender ID without pre-adding contact

### Changed

- **Category 5 Cryptography Upgrade** ⚠️ BREAKING
  - Kyber 512 → 1024
  - Dilithium 3 → 5
  - SHA-256 → SHA3-512
  - All keys must regenerate
  - v0.06 ≠ v0.05

---

## [0.1.108] - 2025-11-03

### Changed

- **Phase 9.3:** PostgreSQL → SQLite migration
  - Removed PostgreSQL dependency
  - DHT Groups (882 lines)
  - Keyserver cache (7-day TTL)
  - Bootstrap scripts

---

## [0.1.107] - 2025-11-02

### Added

- **Phase 9.1 & 9.2:** P2P transport & offline queue
  - OpenDHT (3 bootstrap nodes)
  - TCP port 4001 (Kyber512 + AES-256-GCM)
  - Hybrid delivery
  - Offline queue (7-day TTL)
  - Binary serialization
  - Encrypted DHT storage

---

## [0.1.100] - 2025-10-23

### Added

- **Phase 8:** cpunk wallet integration
  - Card-based UI
  - TX builder
  - UTXO selection
  - RPC integration
  - QR codes
  - Theme system

---

## [0.1.50] - 2025-10-17

### Added

- **Phase 4:** GUI + Groups
  - Qt5 GUI (deprecated in later versions)
  - Group chat functionality

---

## [0.1.20] - 2025-10-15

### Added

- **Phase 2:** Library API
  - Core DNA messaging API
  - Post-quantum cryptography integration

---

## [0.1.0] - 2025-10-14

### Added

- Initial fork from QGP
- Basic messenger functionality
- Kyber and Dilithium integration

---

## Version Numbering

- **Major.Minor.Patch** format
- Major: Breaking changes
- Minor: New features (backward compatible)
- Patch: Bug fixes and security patches

Current: **v0.1.121** (auto-incremented)

---

## Security Advisories

For security vulnerabilities and responsible disclosure, see [SECURITY.md](SECURITY.md).

**Security Contact:** security@cpunk.io

---

## Links

- **GitLab (primary):** https://gitlab.cpunk.io/cpunk/dna-messenger
- **GitHub (mirror):** https://github.com/nocdem/dna-messenger
- **Website:** https://cpunk.io
- **Telegram:** @chippunk_official

---

**Last Updated:** 2025-11-18
