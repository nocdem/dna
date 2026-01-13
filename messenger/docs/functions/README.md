# DNA Messenger Function Reference

**Version:** 0.3.0
**Generated:** 2025-12-30
**Scope:** All functions (public + static/internal)

This directory provides a comprehensive reference for all functions in the DNA Messenger codebase, organized by module.

---

## Quick Navigation

| Module | File | Description |
|--------|------|-------------|
| **Public API** | [public-api.md](public-api.md) | Main engine API (`dna_engine.h`) - all UI/FFI bindings |
| **DNA API** | [dna-api.md](dna-api.md) | Low-level cryptographic API (`dna_api.h`) |
| **Messenger** | [messenger.md](messenger.md) | Core messenger + message backup |
| **Cryptography** | [crypto.md](crypto.md) | Utils, KEM (Kyber), DSA (Dilithium), BIP39/BIP32 |
| **DHT** | [dht.md](dht.md) | Core, Shared, and Client DHT operations |
| **P2P** | [p2p.md](p2p.md) | Peer-to-peer transport layer |
| **Database** | [database.md](database.md) | SQLite databases (contacts, cache, profiles) |
| **Blockchain** | [blockchain.md](blockchain.md) | Multi-chain wallet (Cellframe, ETH, Solana, TRON) |
| **Engine** | [engine.md](engine.md) | Internal engine implementation |
| **Key Sizes** | [key-sizes.md](key-sizes.md) | Cryptographic key size reference |

---

## Module Overview

### 1. Public API ([public-api.md](public-api.md))
The main public API for DNA Messenger. All UI/FFI bindings use these functions.
- Lifecycle management
- Identity management
- Contacts and contact requests
- Messaging (P2P + DHT)
- Groups (GEK encryption)
- Wallet (multi-chain)
- P2P & Presence
- Listeners (outbox, presence, delivery)
- Feed (DNA Board)
- Debug logging

### 2. DNA API ([dna-api.md](dna-api.md))
Low-level cryptographic API for message encryption/decryption.
- Context and buffer management
- Message encryption/decryption
- Signature operations
- GEK group messaging

### 3. Messenger ([messenger.md](messenger.md))
Core messenger functionality.
- Initialization and key generation
- Public key management
- Message operations and status
- Group management and GEK

### 4. Cryptography ([crypto.md](crypto.md))
All cryptographic primitives and utilities.
- AES-256-GCM, SHA3-512
- Kyber1024 KEM, Dilithium5 DSA
- Key encryption, seed storage
- Platform abstraction
- BIP39/BIP32 key derivation
- Internal Kyber and Dilithium implementations

### 5. DHT ([dht.md](dht.md))
Distributed Hash Table operations.
- Core context and operations
- Keyserver and name system
- Offline queue and watermarks
- Groups, profiles, and feeds
- Contact requests
- Message backup

### 6. P2P ([p2p.md](p2p.md))
Peer-to-peer transport layer.
- Transport initialization
- Peer discovery
- Direct messaging
- Connection management

### 7. Database ([database.md](database.md))
Local SQLite databases.
- Contacts database
- Profile manager and cache
- Keyserver cache
- Presence cache
- Group invitations
- Bootstrap cache

### 8. Blockchain ([blockchain.md](blockchain.md))
Multi-chain wallet operations.
- Common interface
- Cellframe (Dilithium PQ signatures)
- Ethereum (secp256k1)
- Solana (Ed25519)
- TRON (secp256k1)

### 9. Engine ([engine.md](engine.md))
Internal engine implementation.
- Task queue
- Worker threading
- Task handlers (identity, contacts, messaging, groups, wallet, P2P, feed)

### 10. Key Sizes ([key-sizes.md](key-sizes.md))
Quick reference for cryptographic algorithm sizes.
- Post-quantum (Kyber, Dilithium)
- Symmetric (AES-256-GCM)
- Hash functions (SHA3)
- Key derivation (BIP39)
- Classical (Ed25519, secp256k1)

---

## Usage Guidelines

**ALWAYS check these files when:**
- Writing new code that calls existing functions
- Modifying existing function signatures
- Debugging issues (to understand available APIs)
- Adding new features (to find relevant functions)

**ALWAYS update these files when:**
- Adding new functions (public or internal)
- Changing function signatures
- Removing functions
- Adding new header files

**Format:** Each function entry follows table format:
```
| `return_type function_name(params)` | Brief one-line description |
```
