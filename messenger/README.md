# DNA Messenger

<p align="center">
  <strong>Decentralized Network Applications</strong><br>
  Quantum-Proof Encrypted Messenger with Integrated Multi-Chain Wallet
</p>

<p align="center">
  <a href="#status"><img src="https://img.shields.io/badge/Status-RC%20v1.0.0--rc21-blue" alt="RC"></a>
  <a href="#license"><img src="https://img.shields.io/badge/License-Apache%202.0-green" alt="Apache 2.0"></a>
  <a href="#platforms"><img src="https://img.shields.io/badge/Platforms-Android%20|%20Linux%20|%20Windows-orange" alt="Platforms"></a>
  <a href="#security"><img src="https://img.shields.io/badge/Security-NIST%20Category%205-red" alt="NIST Cat 5"></a>
</p>

<p align="center">
  <em>Your messages and crypto stay private — even against future quantum computers.</em>
</p>

---

## What is DNA Messenger?

DNA Messenger is a **fully decentralized** messenger and **multi-chain crypto wallet** built with **NIST-approved post-quantum cryptography**.

- **No central servers** — Messages travel through a distributed hash table (DHT)
- **No IP leakage** — Your real IP is never exposed to contacts or third parties
- **No metadata collection** — We can't see who talks to whom
- **Quantum-resistant** — Protected against both current and future quantum attacks

---

## Key Features

### Secure Messaging
- **End-to-end encryption** with Kyber1024 + AES-256-GCM
- **1:1 and group chats** with delivery/read receipts
- **Offline message queue** — Messages wait up to 7 days if you're offline
- **Group encryption (GEK)** — 200x faster than encrypting per-recipient
- **Cross-device sync** — Messages and groups sync across all your devices

### User Profiles
- **Customizable profiles** — Avatar, bio, location, website
- **Social links** — Telegram, Twitter/X, GitHub, and more
- **Social wall** — Public posts visible to anyone who views your profile
- **Name registration** — Reserve your unique username on the DHT

### Integrated Multi-Chain Wallet
- **4 Networks:** Cellframe (CF20), Ethereum (ERC20), TRON (TRC20), Solana (SPL)
- **9+ Tokens:** CPUNK, CELL, KEL, NYS, QEVM, ETH, SOL, TRX, USDT
- **Send crypto from chat** — Auto-resolves contact's wallet address
- **Token swaps** — DEX integration with MEV protection
- **QR codes** — Easy send/receive
- **Full transaction history**

### Privacy-First Architecture
- **DHT-only transport** — No relay servers that can log traffic
- **Nodus DHT network** — Post-quantum Kademlia with cluster replication
- **Dilithium5 signatures** — All DHT data cryptographically signed
- **BIP39 recovery** — 24-word seed phrase backup
- **Native presence** — Server-side presence tracking

---

## Security

**NIST Category 5** — Maximum quantum resistance (256-bit security level)

| Algorithm | Standard | Purpose |
|-----------|----------|---------|
| **Kyber1024** | ML-KEM-1024 (FIPS 203) | Key encapsulation |
| **Dilithium5** | ML-DSA-87 (FIPS 204) | Digital signatures |
| **AES-256-GCM** | NIST | Symmetric encryption |
| **SHA3-512** | NIST | Hashing |

Your keys never leave your device. Recovery via BIP39 seed phrase.

---

## Quick Start

### Download

Pre-built binaries: **[GitLab Releases](https://gitlab.cpunk.io/cpunk/dna/-/releases)**

### Build from Source

DNA Messenger is part of the [DNA monorepo](https://github.com/nocdem/dna).

```bash
# Dependencies (Debian/Ubuntu)
sudo apt install git cmake gcc g++ libssl-dev libsqlite3-dev \
                 libcurl4-openssl-dev libjson-c-dev libargon2-dev \
                 libreadline-dev

# Clone
git clone https://github.com/nocdem/dna.git
cd dna

# Build C library
cd messenger/build && cmake .. && make -j$(nproc)

# Run Flutter app
cd ../dna_messenger_flutter
flutter pub get && flutter run
```

### Android

```bash
cd messenger
./build-cross-compile.sh android-arm64
cd dna_messenger_flutter && flutter build apk
```

### Windows (Cross-compile)

```bash
cd messenger
./build-cross-compile.sh windows-x64
```

---

## Architecture

```
┌─────────────┐                                     ┌─────────────┐
│ DNA Client  │                                     │ DNA Client  │
│  (You)      │                                     │  (Contact)  │
└──────┬──────┘                                     └──────┬──────┘
       │                                                   │
       │              Nodus DHT Network                    │
       │    ┌────────────────────────────────────┐         │
       │    │    P2P Distributed Hash Table      │         │
       └───►│  ┌────┐   ┌────┐   ┌────┐   ┌────┐│◄────────┘
            │  │node│◄─►│node│◄─►│node│◄─►│node││
            │  └────┘   └────┘   └────┘   └────┘│
            │                                    │
            │  All values signed with Dilithium5 │
            └────────────────────────────────────┘
```

**Components:**
- **Flutter App** — Cross-platform UI (Android, Linux, Windows)
- **C Library** — Core engine with 17 modular handlers (`libdna_lib.so`)
- **Nodus** — Pure C Kademlia DHT with cluster replication ([details](../nodus/README.md))

**Engine Modules** (`src/api/engine/`):

| Module | Domain |
|--------|--------|
| `dna_engine_messaging.c` | Send/receive, conversations, retry |
| `dna_engine_contacts.c` | Contact requests, blocking |
| `dna_engine_groups.c` | Group CRUD, GEK encryption, invitations |
| `dna_engine_identity.c` | Identity create/load, profiles |
| `dna_engine_presence.c` | Heartbeat, presence lookup |
| `dna_engine_wallet.c` | Multi-chain wallet, balances, swaps |
| `dna_engine_backup.c` | DHT sync for all data types |
| `dna_engine_lifecycle.c` | Engine pause/resume (mobile) |
| `dna_engine_version.c` | Version info and OTA checking |

**Local Storage:**
- Messages: `~/.dna/messages.db`
- Keys: `~/.dna/<fingerprint>/keys/`
- Logs: `~/.dna/logs/`

---

## Versions

| Component | Version |
|-----------|---------|
| C Library | v0.9.54 |
| Flutter App | v1.0.0-rc21 |
| Nodus DHT | v0.6.3 |

---

## Documentation

| Doc | Description |
|-----|-------------|
| [Architecture](docs/ARCHITECTURE_DETAILED.md) | System design |
| [Flutter UI](docs/FLUTTER_UI.md) | App documentation |
| [CLI Testing](docs/CLI_TESTING.md) | Command-line tool |
| [DNA Engine API](docs/DNA_ENGINE_API.md) | Core API reference |
| [DHT System](docs/DHT_SYSTEM.md) | DHT architecture |
| [Message System](docs/MESSAGE_SYSTEM.md) | Message handling |
| [Protocol Specs](docs/PROTOCOL.md) | Wire formats |
| [Nodus](../nodus/README.md) | DHT server |

---

## Links

- **GitLab (Primary):** https://gitlab.cpunk.io/cpunk/dna
- **GitHub (Mirror):** https://github.com/nocdem/dna
- **Website:** https://cpunk.io
- **Telegram:** [@chippunk_official](https://t.me/chippunk_official)

---

## License

The DNA Messenger C library is licensed under the [Apache License 2.0](LICENSE).

The Flutter application is [source-available (proprietary)](dna_messenger_flutter/LICENSE).

---

<p align="center">
  <strong>Release Candidate.</strong> Use with appropriate caution for sensitive communications.
</p>
