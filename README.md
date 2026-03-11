# DNA — Decentralized Network Applications

<p align="center">
  <strong>Post-quantum encrypted communication and decentralized infrastructure</strong>
</p>

<p align="center">
  <a href="#license"><img src="https://img.shields.io/badge/License-Apache%202.0-blue" alt="Apache 2.0"></a>
  <a href="#status"><img src="https://img.shields.io/badge/Status-Beta-orange" alt="Beta"></a>
  <a href="#security"><img src="https://img.shields.io/badge/Security-NIST%20Category%205-red" alt="NIST Cat 5"></a>
  <a href="#platforms"><img src="https://img.shields.io/badge/Platforms-Android%20|%20Linux%20|%20Windows-green" alt="Platforms"></a>
</p>

---

## What is DNA?

DNA is a suite of decentralized applications built on **NIST-approved post-quantum cryptography**. No central servers, no metadata collection, no IP leakage — and protected against both current and future quantum computers.

| Project | Description | Status |
|---------|-------------|--------|
| [**DNA Messenger**](messenger/) | End-to-end encrypted messenger with multi-chain crypto wallet | Beta |
| [**Nodus**](nodus/) | Post-quantum Kademlia DHT server with PBFT consensus | Beta |
| [**CPUNK Platform**](cpunk/) | Quantum-safe community platform on Cellframe blockchain | Live |
| **shared/crypto/** | Post-quantum cryptographic primitives | Stable |

---

## Architecture

```
┌──────────────────────────────────────────────────────┐
│  Flutter App (Android, Linux, Windows)               │
│  messenger/dna_messenger_flutter/                    │
└──────────┬───────────────────────────────────────────┘
           │ FFI (dart:ffi)
┌──────────▼───────────────────────────────────────────┐
│  DNA Messenger C Library                             │
│  messenger/src/api/ — 17 modular engine handlers     │
├──────────────────────────────────────────────────────┤
│  messenger/  dht/  transport/  database/  blockchain/│
└──────┬───────┬───────────────────────────────────────┘
       │       │
       │  ┌────▼──────────────────────────────────┐
       │  │  Nodus — DHT Infrastructure            │
       │  │  Kademlia routing + PBFT consensus     │
       │  │  TCP client SDK ←→ Nodus server nodes  │
       │  └───────────────────────────────────────┘
       │
  ┌────▼──────────────────────┐
  │  shared/crypto/           │
  │  sign/ enc/ hash/ key/    │
  │  utils/                   │
  └───────────────────────────┘
```

---

## Security

**NIST Category 5** — Maximum quantum resistance (256-bit security level).

| Algorithm | Standard | Purpose |
|-----------|----------|---------|
| **Kyber1024** | ML-KEM-1024 (FIPS 203) | Key encapsulation |
| **Dilithium5** | ML-DSA-87 (FIPS 204) | Digital signatures |
| **AES-256-GCM** | NIST | Symmetric encryption |
| **SHA3-512** | NIST | Hashing |

---

## Quick Start

### Prerequisites (Debian/Ubuntu)

```bash
sudo apt install git cmake gcc g++ libssl-dev libsqlite3-dev \
                 libcurl4-openssl-dev libjson-c-dev libargon2-dev \
                 libreadline-dev
```

### Clone & Build

```bash
git clone https://github.com/nocdem/dna.git
cd dna

# Messenger C library (build first)
cd messenger/build && cmake .. && make -j$(nproc)

# Nodus DHT server
cd ../../nodus/build && cmake .. && make -j$(nproc)

# Flutter app (requires C library)
cd ../../messenger/dna_messenger_flutter
flutter pub get && flutter build linux
```

---

## Repository Structure

```
dna/
├── messenger/                 # DNA Messenger
│   ├── src/api/               #   DNA Engine (17 modular handlers)
│   ├── messenger/             #   Messaging core (identity, keys, contacts)
│   ├── dht/                   #   DHT operations
│   ├── transport/             #   P2P transport layer
│   ├── database/              #   SQLite persistence
│   ├── blockchain/            #   Multi-chain wallet (ETH, SOL, TRON, Cellframe)
│   ├── cli/                   #   Command-line tool
│   ├── include/               #   Public C headers
│   ├── tests/                 #   Unit tests
│   ├── dna_messenger_flutter/ #   Flutter cross-platform app
│   └── docs/                  #   Documentation
├── nodus/                     # Nodus DHT Server
│   ├── src/                   #   Server, client SDK, protocol, consensus
│   ├── include/               #   Public headers
│   └── tests/                 #   Unit + integration tests
├── shared/
│   └── crypto/                # Post-quantum crypto primitives
│       ├── sign/              #   Dilithium5, secp256k1, Ed25519
│       ├── enc/               #   Kyber1024, AES-256-GCM
│       ├── hash/              #   SHA3-512, Keccak-256
│       ├── key/               #   BIP32, BIP39, PBKDF2
│       └── utils/             #   Logging, platform abstraction, CSPRNG
├── cpunk/                     # cpunk.io web platform
└── docs/                      # Top-level project documentation
```

---

## Versions

| Component | Version |
|-----------|---------|
| Messenger C Library | v0.9.44 |
| Flutter App | v0.101.50 |
| Nodus DHT | v0.6.3 |

---

## Documentation

| Document | Description |
|----------|-------------|
| [Messenger README](messenger/README.md) | Messenger overview, features, build |
| [Nodus README](nodus/README.md) | DHT server architecture and deployment |
| [Architecture](messenger/docs/ARCHITECTURE_DETAILED.md) | Detailed system design |
| [Protocol Specs](messenger/docs/PROTOCOL.md) | Wire formats (Seal, Spillway, Anchor, Atlas, Nexus) |
| [DNA Engine API](messenger/docs/DNA_ENGINE_API.md) | Core C API reference |
| [CLI Reference](messenger/docs/CLI_TESTING.md) | Command-line tool usage |
| [Flutter UI](messenger/docs/FLUTTER_UI.md) | Flutter app documentation |

---

## Network

DNA uses the Nodus DHT network — no central servers:

| Node | Location | UDP | TCP |
|------|----------|-----|-----|
| US-1 | 154.38.182.161 | 4000 | 4001 |
| EU-1 | 164.68.105.227 | 4000 | 4001 |
| EU-2 | 164.68.116.180 | 4000 | 4001 |

---

## Links

- **Website:** https://cpunk.io
- **GitLab (Primary):** https://gitlab.cpunk.io/cpunk/dna
- **GitHub (Mirror):** https://github.com/nocdem/dna
- **Telegram:** [@chippunk_official](https://t.me/chippunk_official)

---

## License

| Component | License |
|-----------|---------|
| Messenger C Library | [Apache License 2.0](messenger/LICENSE) |
| Nodus DHT Server | [Apache License 2.0](nodus/LICENSE) |
| Shared Crypto | [Apache License 2.0](LICENSE) |
| CPUNK Platform | [Apache License 2.0](cpunk/LICENSE) |
| Flutter App | [Source-Available (Proprietary)](messenger/dna_messenger_flutter/LICENSE) |

---

<p align="center">
  <strong>Beta software.</strong> Use with appropriate caution for sensitive communications.
</p>
