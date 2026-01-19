# DNA Messenger

<p align="center">
  <strong>Decentralized Network Applications</strong><br>
  Quantum-Proof Encrypted Messenger with Integrated Multi-Chain Wallet
</p>

<p align="center">
  <a href="#status"><img src="https://img.shields.io/badge/Status-Beta-blue" alt="Beta"></a>
  <a href="#license"><img src="https://img.shields.io/badge/License-GPLv3-green" alt="GPL v3"></a>
  <a href="#platforms"><img src="https://img.shields.io/badge/Platforms-Android%20|%20Linux%20|%20Windows-orange" alt="Platforms"></a>
  <a href="#security"><img src="https://img.shields.io/badge/Security-NIST%20Category%205-red" alt="NIST Cat 5"></a>
</p>

<p align="center">
  <em>Your messages and crypto stay private—even against future quantum computers.</em>
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
- **User profiles** with avatars, bio, and social wall

### Integrated Multi-Chain Wallet
- **4 Networks:** Cellframe (CF20), Ethereum (ERC20), TRON (TRC20), Solana (SPL)
- **9+ Tokens:** CPUNK, CELL, KEL, NYS, QEVM, ETH, SOL, TRX, USDT
- **Send crypto from chat** — Auto-resolves contact's wallet address
- **Address book** — Save frequently used addresses
- **QR codes** — Easy send/receive
- **Full transaction history**

### Privacy-First Architecture
- **DHT-only transport** — No relay servers that can log traffic
- **Spillway Protocol v2** — Efficient offline message retrieval
- **Dilithium5 signatures** — All DHT data cryptographically signed
- **BIP39 recovery** — 24-word seed phrase backup

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

Pre-built binaries: **[GitLab Releases](https://gitlab.cpunk.io/cpunk/dna-messenger/-/releases)**

### Build from Source

```bash
# Dependencies (Debian/Ubuntu)
sudo apt install git cmake g++ libssl-dev libsqlite3-dev libcurl4-openssl-dev \
                 libjson-c-dev libargon2-dev libfmt-dev libreadline-dev \
                 libasio-dev libmsgpack-cxx-dev

# Build
git clone https://github.com/nocdem/dna-messenger.git
cd dna-messenger && mkdir build && cd build
cmake .. && make -j$(nproc)

# Run Flutter app
cd ../dna_messenger_flutter
flutter pub get && flutter run
```

### Android

```bash
./build-cross-compile.sh android-arm64
cd dna_messenger_flutter && flutter build apk
```

---

## Architecture

```
┌─────────────┐                                     ┌─────────────┐
│ DNA Client  │                                     │ DNA Client  │
│  (You)      │                                     │  (Contact)  │
└──────┬──────┘                                     └──────┬──────┘
       │                                                   │
       │              OpenDHT-PQ Network                   │
       │    ┌────────────────────────────────────┐        │
       │    │    P2P Distributed Hash Table      │        │
       │    │                                    │        │
       └───►│  ┌────┐   ┌────┐   ┌────┐   ┌────┐│◄───────┘
            │  │peer│◄─►│peer│◄─►│peer│◄─►│peer││
            │  └─┬──┘   └─┬──┘   └─┬──┘   └─┬──┘│
            │    │        │        │        │   │
            │  ┌─▼──┐   ┌─▼──┐   ┌─▼──┐   ┌─▼──┐│
            │  │peer│◄─►│peer│◄─►│peer│◄─►│peer││
            │  └────┘   └────┘   └────┘   └────┘│
            │                                    │
            │  All values signed with Dilithium5 │
            └────────────────────────────────────┘
```

**Components:**
- **Flutter App** — Cross-platform UI (Android, Linux, Windows)
- **C Library** — Core crypto, DHT, database (`libdna_engine.so`)
- **OpenDHT-PQ** — Forked OpenDHT with post-quantum crypto

**Local Storage:**
- Messages: `~/.dna/messages.db`
- Keys: `~/.dna/<fingerprint>/keys/`
- Logs: `~/.dna/logs/`

---

## Network Infrastructure

### OpenDHT-PQ

DNA Messenger uses a **forked version of OpenDHT** with post-quantum cryptography:

- **Dilithium5 signatures** replace RSA-2048 (FIPS 204 compliant)
- **Mandatory signing** — All DHT values must be cryptographically signed
- **Binary identity format** — `.dsa`, `.pub`, `.cert` key files
- Source: `vendor/opendht-pq/`

### DNA Nodus (Bootstrap Server)

Lightweight DHT bootstrap nodes that help peers discover each other:

- **Purpose:** Peer discovery and DHT entry point only
- **No message relay** — Messages go peer-to-peer via DHT, not through servers
- **No logging** — Bootstrap nodes never see message content or metadata
- **Persistence:** SQLite-backed DHT state survives restarts
- **Config:** `/etc/dna-nodus.conf` (JSON)
- **Port:** 4000/UDP

Public bootstrap nodes are operated by cpunk.io — see [docs/DNA_NODUS.md](docs/DNA_NODUS.md) for deployment info.

---

## Versions

| Component | Version |
|-----------|---------|
| C Library | v0.6.3 |
| Flutter App | v0.100.7 |
| DNA Nodus | v0.4.5 |

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
| [DNA Nodus](docs/DNA_NODUS.md) | Bootstrap server |
| [Roadmap](ROADMAP.md) | Development phases |

---

## Links

- **GitLab (Primary):** https://gitlab.cpunk.io/cpunk/dna-messenger
- **GitHub (Mirror):** https://github.com/nocdem/dna-messenger
- **Website:** https://cpunk.io
- **Community:** https://cpunk.club
- **Telegram:** [@chippunk_official](https://t.me/chippunk_official)

---

## License

**GNU General Public License v3.0**

Forked from [QGP (Quantum Good Privacy)](https://github.com/nocdem/qgp)

---

<p align="center">
  <strong>Beta software.</strong> Use with appropriate caution for sensitive communications.
</p>
