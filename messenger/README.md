# DNA Connect

<p align="center">
  <strong>Decentralized Network Applications</strong><br>
  Post-Quantum Encrypted Communication with Integrated Multi-Chain Wallet
</p>

<p align="center">
  <a href="#status"><img src="https://img.shields.io/badge/Status-RC%20v1.0.0--rc240-blue" alt="RC"></a>
  <a href="#license"><img src="https://img.shields.io/badge/License-Apache%202.0-green" alt="Apache 2.0"></a>
  <a href="#platforms"><img src="https://img.shields.io/badge/Platforms-Android%20|%20Linux%20|%20Windows-orange" alt="Platforms"></a>
  <a href="#security"><img src="https://img.shields.io/badge/Cryptography-Post--quantum-red" alt="Post-quantum cryptography"></a>
</p>

<p align="center">
  <em>Encrypted communication built with post-quantum cryptographic primitives.</em>
</p>

---

## What is DNA Connect?

DNA Connect is a communication platform and multi-chain crypto wallet built on
an operator-run DHT network with post-quantum cryptographic primitives.

- **No single central message server** — Messages travel through a distributed hash table (DHT)
- **End-to-end encrypted content** — DHT nodes cannot decrypt message bodies
- **Explicit metadata boundary** — Entry nodes can observe IP addresses, timing and traffic volume; nodes process routing and storage metadata
- **Post-quantum design** — Uses Dilithium5 signatures and round-3 Kyber1024 key encapsulation

---

## Key Features

### Secure Messaging
- **End-to-end encryption** with Kyber1024 + AES-256-GCM
- **1:1 and group chats** with delivery/read receipts
- **Offline message queue** — Messages wait up to 7 days if you're offline
- **Group encryption (GEK)** — Shared group keys avoid repeating a full
  per-recipient KEM operation for every message; no universal performance
  multiplier is claimed
- **Cross-device sync** — Messages and groups sync across all your devices
- **Voice messages** with waveform visualization
- **Video and image sharing** via DHT media storage
- **Media outbox** with persistent upload queue and resume

### User Profiles
- **Customizable profiles** — Avatar, bio, location, website
- **Social links** — Telegram, Twitter/X, GitHub, and more
- **Social wall** — Public posts visible to anyone who views your profile
- **Name registration** — Reserve your unique username on the DHT
- **Follow/unfollow system** with DHT sync
- **Profile stats** — Likes and tips
- **Boost system** — 1 per day limit

### Integrated Multi-Chain Wallet
- **5 external networks + DNAC native:** Cellframe (CF20), Ethereum (ERC20), BNB Smart Chain (BEP20), TRON (TRC20), Solana (SPL), plus **DNAC** (post-quantum native chain, see bullet below)
- **9+ Tokens:** CPUNK, CELL, KEL, NYS, QEVM, ETH, BNB, SOL, TRX, USDT
- **DNAC (DNA Chain)** — Post-quantum native UTXO blockchain with BFT witness consensus
- **Send crypto from chat** — Auto-resolves contact's wallet address
- **Token swaps** — DEX integrations; the Ethereum submission path includes a
  Flashbots Protect option, while protection varies by chain and route
- **QR codes** — Easy send/receive
- **Full transaction history**

### Privacy-First Architecture
- **DHT transport** — No single central message relay; participating nodes still observe the metadata needed to operate the network
- **Nodus DHT network** — Post-quantum Kademlia with cluster replication
- **Dilithium5 signatures** — All DHT data cryptographically signed
- **BIP39 recovery** — 24-word seed phrase backup
- **Native presence** — Server-side presence tracking
- **SQLCipher database encryption** — 9 encrypted databases at rest
- **TEE key wrapping** on Android (AES-256-GCM via Android Keystore)
- **Kyber1024 TCP channel encryption** — Authenticated TCP client/inter-node
  payloads use Kyber round-3 + AES-256-GCM; UDP Kademlia datagrams are not
  covered by that channel
- **Debug log system** with hybrid encryption (Kyber1024 + AES-256-GCM)

---

## Security

The selected parameter sets target NIST security category 5. That target is not
a security certification, and the Kyber implementation in this tree predates
the final ML-KEM/FIPS 203 standard.

| Algorithm | Standard | Purpose |
|-----------|----------|---------|
| **Kyber1024** | Kyber round-3 (NIST Level 5) — *not* ML-KEM/FIPS 203, see `shared/crypto/enc/qgp_kyber.h` | Key encapsulation |
| **Dilithium5** | ML-DSA-87 (FIPS 204) | Digital signatures |
| **AES-256-GCM** | NIST | Symmetric encryption |
| **SHA3-512** | NIST | Hashing |

Private/secret key operations are performed locally. Recovery is available via
the BIP39 seed phrase; public keys and fingerprints are intentionally shared as
protocol identity material.

The repository does not claim an independently validated cryptographic module.

**Additional protections:**
- Signed Kyber handshake with TOFU cache for known nodes

---

## Quick Start

### Download

Pre-built binaries: **[GitLab Releases](https://gitlab.cpunk.io/cpunk/dna/-/releases)**

### Build from Source

DNA Connect is part of the [DNA monorepo](https://github.com/nocdem/dna).

```bash
# Dependencies (Debian/Ubuntu)
sudo apt install git cmake gcc g++ libssl-dev libsqlite3-dev \
                 libcurl4-openssl-dev libjson-c-dev libargon2-dev \
                 libreadline-dev
sudo apt install -t bookworm-backports libsqlcipher-dev

# Clone
git clone https://github.com/nocdem/dna.git
cd dna

# Build C library
cmake -S messenger -B messenger/build -DCMAKE_BUILD_TYPE=Release
cmake --build messenger/build -j"$(nproc)"

# Run Flutter app
cd messenger/dna_messenger_flutter
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
- **C Library** — Core engine with 23 modular handlers (`libdna.so`)
- **Nodus** — Pure C Kademlia DHT with cluster replication ([details](../nodus/README.md))

**Engine Modules** (`src/api/engine/`):

| Module | Domain |
|--------|--------|
| `dna_engine_addressbook.c` | Address book management |
| `dna_engine_backup.c` | DHT sync for all data types |
| `dna_engine_calls.c` | Voice-call signalling and orchestration |
| `dna_engine_channels.c` | Channel CRUD, posts, subscriptions |
| `dna_engine_contacts.c` | Contact requests, blocking |
| `dna_engine_debug_log.c` | Debug log send/receive |
| `dna_engine_dnac.c` | DNA Chain operations (balance, send, sync, history) |
| `dna_engine_follow.c` | Follow/unfollow, list, DHT sync |
| `dna_engine_groups.c` | Group CRUD, GEK encryption, invitations |
| `dna_engine_helpers.c` | Shared utility functions |
| `dna_engine_identity.c` | Identity create/load, profiles |
| `dna_engine_lifecycle.c` | Engine pause/resume (mobile) |
| `dna_engine_listeners.c` | DHT key subscriptions |
| `dna_engine_logging.c` | Debug log control |
| `dna_engine_media.c` | Media upload/download, outbox queue |
| `dna_engine_messaging.c` | Send/receive, conversations, retry |
| `dna_engine_presence.c` | Heartbeat, presence lookup |
| `dna_engine_signing.c` | Data signing operations |
| `dna_engine_version.c` | Version info and OTA checking |
| `dna_engine_wall.c` | Personal wall posts |
| `dna_engine_wall_poll.c` | Wall feed polling |
| `dna_engine_wallet.c` | Multi-chain wallet, balances, swaps |
| `dna_engine_workers.c` | Background thread pool |

**Local Storage:**
- Messages: `~/.dna/messages.db`
- Keys: `~/.dna/<fingerprint>/keys/`
- Logs: `~/.dna/logs/`

---

## Versions

| Component | Version |
|-----------|---------|
| C Library | v0.11.13 |
| Flutter App | v1.0.0-rc240 |
| Nodus | v0.18.22 |
| DNAC | v0.17.8-stake.wip |

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
| [DNAC](../dnac/README.md) | Native UTXO blockchain |

---

## Links

- **GitLab (Primary):** https://gitlab.cpunk.io/cpunk/dna
- **GitHub (Mirror):** https://github.com/nocdem/dna
- **Website:** https://cpunk.io
- **Telegram:** [@chippunk_official](https://t.me/chippunk_official)

---

## License

The DNA Connect C library is licensed under the [Apache License 2.0](LICENSE).

The Flutter application is [source-available (proprietary)](dna_messenger_flutter/LICENSE).

---

<p align="center">
  <strong>Release Candidate.</strong> This label is not a security certification.
  Use with appropriate caution for sensitive communications.
</p>
