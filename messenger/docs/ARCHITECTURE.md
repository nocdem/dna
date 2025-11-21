# DNA Messenger - Architecture Documentation

**Last Updated:** 2025-11-21

---

## Project Overview

Post-quantum E2E encrypted messenger with cpunk wallet. **NIST Category 5 security** (256-bit quantum).

**Crypto:** Kyber1024 (ML-KEM-1024), Dilithium5 (ML-DSA-87), AES-256-GCM, SHA3-512

**Key Features:** E2E encrypted messaging • **GSK group encryption (200x faster)** • DHT groups • Per-identity contacts with DHT sync • User profiles • Wall posts • cpunk wallet (CPUNK/CELL/KEL) • P2P + DHT peer discovery • ICE NAT traversal (STUN+3-tier fallback) • Offline queueing (7d) • Encrypted DHT identity backup (BIP39) • Local SQLite • Cross-platform (Linux/Windows) • ImGui GUI

---

## System Architecture

| Component | Description |
|-----------|-------------|
| **Core Library** (`libdna.a`) | PQ crypto (Kyber1024, Dilithium5) • Memory-based enc/dec API • Multi-recipient • Keyserver cache (SQLite, 7d TTL) |
| **GUI** (`dna_messenger_imgui`) | ImGui (OpenGL3+GLFW3) • Responsive UI • Theme system • Wallet integration • SQLite storage • Async tasks • **Qt5 deprecated** |
| **Wallet** | Cellframe .dwallet files • RPC integration • TX builder/signing • Balance/history queries |
| **P2P Transport** | OpenDHT peer discovery • TCP (port 4001) • ICE NAT traversal (libnice+STUN) • 3-tier fallback (LAN→ICE→DHT queue) • Offline queueing (7d) • DHT groups (UUID v4) • 3 bootstrap nodes (US/EU) • 2-min polling |

---

## Directory Structure

```
/opt/dna-messenger/
├── crypto/                  # PQ cryptography (ORGANIZED)
│   ├── dsa/                 # Dilithium5 (ML-DSA-87) - vendored pq-crystals
│   ├── kem/                 # Kyber1024 (ML-KEM-1024) - vendored pq-crystals
│   ├── cellframe_dilithium/ # Cellframe Dilithium (compatibility)
│   ├── utils/               # Crypto utilities (24 files)
│   │   ├── qgp_*.{c,h}      # QGP crypto wrappers (dilithium, kyber, aes, sha3, random, platform)
│   │   ├── aes_keywrap.*    # AES key wrapping (RFC 3394)
│   │   ├── armor.*          # ASCII armor encoding/decoding
│   │   ├── base58.*         # Base58 encoding (blockchain addresses)
│   │   └── kyber_deterministic.* # Deterministic Kyber key generation from seed
│   └── bip39/               # BIP39 implementation (5 files)
│       ├── bip39.*          # Mnemonic generation/validation
│       ├── bip39_pbkdf2.*   # PBKDF2 key derivation
│       ├── bip39_wordlist.h # 2048-word English wordlist
│       └── seed_derivation.* # Master seed derivation
├── blockchain/              # Blockchain integration (13 files)
│   ├── wallet.*             # Cellframe .dwallet file handling
│   ├── blockchain_rpc.*     # RPC client (balance, TX history, submit)
│   ├── blockchain_addr.*    # Address utilities (base58, network prefixes)
│   ├── blockchain_tx_builder_minimal.* # Minimal TX builder (no JSON-C dependency)
│   ├── blockchain_sign_minimal.*       # TX signing with Dilithium
│   ├── blockchain_json_minimal.*       # Minimal JSON serialization
│   ├── blockchain_minimal.h # TSD type definitions
│   └── dna-send.c           # CLI tool for sending transactions
├── database/                # Local SQLite storage (11 files)
│   ├── contacts_db.*        # Per-identity contacts (~/.dna/<identity>_contacts.db)
│   ├── keyserver_cache.*    # Public key cache (7-day TTL)
│   ├── presence_cache.*     # User presence tracking
│   ├── profile_cache.*      # Profile cache (7-day TTL)
│   ├── profile_manager.*    # Smart profile fetching (cache-first + DHT fallback)
│   └── cache_manager.*      # Unified cache lifecycle coordinator (237 LOC)
├── dht/                     # DHT layer (MODULAR)
│   ├── core/                # Core DHT functionality
│   │   ├── dht_context.*    # OpenDHT C++ wrapper (1,043 LOC, was 1,282)
│   │   ├── dht_keyserver.*  # Keyserver API (delegates to keyserver/ modules)
│   │   └── dht_stats.*      # DHT statistics API (59 LOC, extracted Phase 3)
│   ├── client/              # Client-side modules
│   │   ├── dht_singleton.*      # Global DHT instance management
│   │   ├── dht_contactlist.*    # Contact list sync (Kyber1024 self-encrypted)
│   │   ├── dht_identity_backup.* # Encrypted DHT identity backup (Kyber1024 + AES-256-GCM)
│   │   ├── dht_identity.*       # RSA-2048 identity management (218 LOC, extracted Phase 3)
│   │   ├── dna_profile.*        # Unified profiles (extended identity with display fields)
│   │   └── dna_message_wall.*   # Wall posts (censorship-resistant social media)
│   ├── shared/              # Shared data structures
│   │   ├── dht_offline_queue.*  # Offline message queueing (7-day TTL, Model E)
│   │   ├── dht_groups.*         # DHT groups (UUID v4, JSON, local cache)
│   │   ├── dht_gsk_storage.*    # GSK chunked storage (50KB chunks, 765 LOC)
│   │   ├── dht_profile.*        # DEPRECATED: Legacy profile (use dna_profile.h)
│   │   └── dht_value_storage.*  # Persistent DHT value storage (SQLite)
│   └── keyserver/           # DHT keyserver (6 modules, 1,953 LOC extracted)
│       ├── keyserver_core.h # Shared types and declarations
│       ├── keyserver_publish.c    # Key publishing (345 LOC)
│       ├── keyserver_lookup.c     # Key lookup (442 LOC)
│       ├── keyserver_names.c      # Name registration/lookup (337 LOC)
│       ├── keyserver_profiles.c   # Profile publishing/fetching (430 LOC)
│       ├── keyserver_addresses.c  # Address lookup (75 LOC)
│       └── keyserver_helpers.c    # Shared utilities (325 LOC)
├── p2p/                     # P2P transport (MODULAR)
│   ├── transport/           # P2P transport modules (5 modules, ~1600 LOC total)
│   │   ├── transport_core.h # Shared types and declarations (189 LOC)
│   │   ├── transport_tcp.c  # TCP connections (port 4001, Kyber512 + AES-256-GCM, 239 LOC)
│   │   ├── transport_discovery.c # DHT peer registration/lookup + ICE candidates (~330 LOC)
│   │   ├── transport_offline.c   # Offline queue integration (169 LOC)
│   │   ├── transport_ice.c  # ICE NAT traversal (STUN+libnice, ~600 LOC)
│   │   └── transport_helpers.c   # Utility functions (159 LOC)
│   └── p2p_transport.*      # High-level P2P API (165 LOC, was 992)
├── messenger/               # Messenger core (MODULAR) - 10 focused modules
│   ├── messenger_core.h     # Shared type definitions
│   ├── identity.*           # Fingerprint utilities (111 LOC)
│   ├── init.*               # Context management (255 LOC)
│   ├── status.*             # Message status tracking (58 LOC)
│   ├── keys.*               # Public key management (443 LOC)
│   ├── contacts.*           # DHT contact sync (288 LOC)
│   ├── keygen.*             # Key generation (1,078 LOC)
│   ├── messages.*           # Message operations (1,119 LOC)
│   ├── gsk.*                # GSK manager (AES-256 keys, rotation, storage, 658 LOC)
│   ├── gsk_packet.*         # Initial Key Packets (Kyber1024+Dilithium5, 782 LOC)
│   └── group_ownership.*    # Ownership transfer (7d liveness, deterministic, 595 LOC)
├── imgui_gui/               # ImGui GUI (ACTIVE) - Modular architecture
│   ├── app.cpp              # Main application (simplified to 324 LOC)
│   ├── core/                # Core data structures
│   │   └── app_state.*      # Centralized application state
│   ├── screens/             # Screen modules (16 modules, 4,100+ LOC extracted)
│   │   ├── identity_selection_screen.*  # Identity wizard (849 LOC)
│   │   ├── chat_screen.*                # Chat UI + emoji picker (690 LOC)
│   │   ├── wallet_send_dialog.*         # TX building (509 LOC)
│   │   ├── wallet_screen.*              # Wallet overview (282 LOC)
│   │   ├── contacts_sidebar.*           # Contact list (291 LOC)
│   │   ├── layout_manager.*             # Mobile/desktop layouts (260 LOC)
│   │   ├── message_wall_screen.*        # Wall posts (324 LOC)
│   │   ├── wallet_transaction_history_dialog.*  # TX history (304 LOC)
│   │   ├── add_contact_dialog.*         # Add contact (232 LOC)
│   │   ├── profile_editor_screen.*      # Profile editor (229 LOC)
│   │   ├── register_name_screen.*       # DHT name registration (184 LOC)
│   │   ├── settings_screen.*            # Settings (164 LOC)
│   │   └── wallet_receive_dialog.*      # Receive UI (94 LOC)
│   ├── helpers/             # Helper modules
│   │   └── data_loader.*    # Async data loading (447 LOC)
│   └── vendor/imgui/        # ImGui library
├── archive/                 # Archived legacy code (deprecated, not maintained)
│   ├── legacy-tools/        # Legacy CLI tools (9 files)
│   │   ├── keygen.c         # QGP key generation CLI
│   │   ├── sign.c           # File signing CLI
│   │   ├── verify.c         # Signature verification CLI
│   │   ├── encrypt.c        # File encryption CLI
│   │   ├── decrypt.c        # File decryption CLI
│   │   ├── export.c         # Public key export CLI
│   │   ├── keyring.c        # Keyring management CLI
│   │   ├── lookup_name.c    # DHT name lookup CLI
│   │   └── utils.c          # Utility functions
│   └── legacy-gui/          # Qt5 GUI (DEPRECATED - archived, not maintained)
├── messenger.c              # Messenger facade (473 LOC, was 3,230)
├── messenger_p2p.*          # P2P messaging integration
├── messenger_groups.c       # DHT group messaging (complete)
├── message_backup.*         # Message backup utilities
├── dna_api.*                # Public API (core crypto library)
├── dna_config.*             # Configuration management
└── qgp.h                    # Main QGP header
```

**Root Directory (Cleaned):**
- Reduced from **59 files** to **8 core files**
- Core files: dna_api.{c,h}, dna_config.{c,h}, messenger.{c,h}, messenger_p2p.{c,h}, messenger_groups.c, message_backup.{c,h}, qgp.h
- All utility files moved to organized subdirectories

---

**See also:**
- [Module Details](MODULES.md) - Detailed breakdown of all modules
- [Development Guidelines](DEVELOPMENT.md) - Code style, patterns, and best practices
- [DHT Refactoring Progress](DHT_REFACTORING_PROGRESS.md) - Historical refactoring information
