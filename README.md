# DNA — Decentralized Network Applications

<p align="center">
  <strong>Post-quantum encrypted communication and decentralized infrastructure</strong>
</p>

<p align="center">
  <a href="#license"><img src="https://img.shields.io/badge/License-Apache%202.0-blue" alt="Apache 2.0"></a>
  <a href="#status"><img src="https://img.shields.io/badge/Status-Mixed%20maturity-orange" alt="Mixed maturity"></a>
  <a href="#security"><img src="https://img.shields.io/badge/Cryptography-Post--quantum-red" alt="Post-quantum cryptography"></a>
  <a href="#platforms"><img src="https://img.shields.io/badge/Platforms-Android%20|%20Linux%20|%20Windows-green" alt="Platforms"></a>
</p>

---

## What is DNA?

DNA is a suite of decentralized applications that combines post-quantum
cryptography with an operator-run DHT network. Message content is
end-to-end encrypted and the application does not depend on one central message
server.

DNA is **not an anonymity network**. A node that accepts a connection can
observe network metadata such as an IP address, timing and traffic volume, and
nodes process the protocol metadata required to route, store and expire records.
The cryptographic boundary protects message content; it does not make transport
metadata disappear.

| Project | Description | Status |
|---------|-------------|--------|
| [**DNA Connect**](messenger/) | End-to-end encrypted communication with multi-chain crypto wallet | RC |
| [**Nodus**](nodus/) | Post-quantum Kademlia DHT server with cluster management | RC |
| [**DNAC**](dnac/) | Post-quantum digital cash with BFT witness consensus | Development |
| [**CPUNK Platform**](cpunk/) | Quantum-safe community platform | Source included |

---

## Architecture

### DNA Connect

```
┌──────────────────────────────────────────────────────┐
│  Flutter App (Android, Linux, Windows)               │
└──────────┬───────────────────────────────────────────┘
           │ dart:ffi
┌──────────▼───────────────────────────────────────────┐
│  DNA Engine (C) — 23 engine modules                  │
│  messaging · contacts · groups · wallet · presence   │
│  identity · backup · lifecycle · version · signing   │
│  wall · media · follow · dnac · channels + more      │
├──────────────────────────────────────────────────────┤
│  Post-Quantum Crypto    │  Wallet (5 external + DNAC native) │
│  Kyber1024 · Dilithium5 │  ETH · BSC · SOL · TRON · Cell · DNAC │
│  AES-256 · SHA3-512     │  ERC20 · BEP20 · SPL · TRC20 · native │
└──────────┬───────────────────────────────────────────┘
           │ Nodus Client SDK
┌──────────▼───────────────────────────────────────────┐
│  Nodus DHT Network                                   │
│  Distributed storage · Real-time subscriptions       │
└──────────────────────────────────────────────────────┘

┌──────────────────────────────────────────────────────┐
│  DNAC (C) — Links against libdna                     │
│  UTXO wallet · BFT witness consensus · Nullifiers    │
└──────────────────────────────────────────────────────┘
```

### Nodus DHT Network

```
    Client A          Client B          Client C
       │                 │                 │
       ▼                 ▼                 ▼
┌──────────┐  UDP  ┌──────────┐  UDP  ┌──────────┐
│  US-1    │◄─────►│  EU-1    │◄─────►│  EU-2    │
└────┬─────┘       └────┬─────┘       └────┬─────┘
     │    Kademlia      │                  │
     │    Replication   │                  │
┌────▼─────┐       ┌────▼─────┐       ┌────▼─────┐
│  EU-3    │◄─────►│  EU-4    │◄─────►│  EU-5    │
└────┬─────┘       └──────────┘       └──────────┘
     │
┌────▼─────┐
│  EU-6    │
└──────────┘

    Signed DHT values · 7-day default TTL (permanent types do not expire)
    Tier 1 (UDP 4000): Kademlia — ping, find_node, store, find_value
    Tier 2 (TCP 4001): Client — auth, put, get, listen, presence
```

---

## Cryptography and security scope

Kyber1024 round-3 targets the NIST Category 5 parameter level. This is a
security-strength target, not a FIPS 203 compliance claim: the KEM in this tree
is the pre-standard round-3 Kyber construction and does not interoperate with
ML-KEM-1024.

| Algorithm | Standard | Purpose |
|-----------|----------|---------|
| **Kyber1024** | Kyber round-3 (Category 5 target) — **not** ML-KEM/FIPS 203; see `shared/crypto/enc/qgp_kyber.h` | Key encapsulation |
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
# SQLCipher is required for the messenger C library (database encryption)
sudo apt install -t bookworm-backports libsqlcipher-dev
```

### Clone & Build

```bash
git clone https://github.com/nocdem/dna.git
cd dna

# Messenger C library (build first)
cmake -S messenger -B messenger/build -DCMAKE_BUILD_TYPE=Release
cmake --build messenger/build -j"$(nproc)"

# Nodus DHT server
cmake -S nodus -B nodus/build -DCMAKE_BUILD_TYPE=Release
cmake --build nodus/build -j"$(nproc)"

# DNAC (requires messenger C library built first)
cmake -S dnac -B dnac/build -DCMAKE_BUILD_TYPE=Release
cmake --build dnac/build -j"$(nproc)"

# Flutter app (requires C library)
cd messenger/dna_messenger_flutter
flutter pub get && flutter build linux
```

---

## Repository Structure

```
dna/
├── messenger/                 # DNA Connect
│   ├── src/api/               #   DNA Engine (23 engine modules)
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
├── dnac/                      # DNA Cash
│   ├── src/                   #   Wallet, transactions, witness client, CLI
│   ├── include/               #   Public headers
│   └── tests/                 #   Unit tests
├── explorer/                  # DNAC block explorer daemon (scan.cpunk.io) — read-only indexer + JSON API
├── cpunk/                     # cpunk.io web platform
└── docs/                      # Top-level project documentation
```

---

## Versions

| Component | Version |
|-----------|---------|
| Messenger C Library | v0.11.13 |
| Flutter App | v1.0.0-rc240 |
| Nodus | v0.18.22 |
| DNAC | v0.17.8-stake.wip |

These versions describe the current public source tree. Ledger V2 is under
development and is not active on the consensus path documented here. A future
Ledger V2 documentation pass must follow implementation, integration and
activation testing; this README is not evidence that Ledger V2 is complete or
deployed.

---

## Documentation

| Document | Description |
|----------|-------------|
| [Messenger README](messenger/README.md) | Messenger overview, features, build |
| [Nodus README](nodus/README.md) | DHT server architecture and deployment |
| [DNAC README](dnac/README.md) | Digital cash architecture, CLI commands, transaction format |
| [Architecture](messenger/docs/ARCHITECTURE_DETAILED.md) | Detailed system design |
| [Protocol Specs](messenger/docs/PROTOCOL.md) | Wire formats (Seal, Spillway, Anchor, Atlas, Nexus) |
| [DNA Engine API](messenger/docs/DNA_ENGINE_API.md) | Core C API reference |
| [CLI Reference](messenger/docs/CLI_TESTING.md) | Command-line tool usage |
| [Flutter UI](messenger/docs/FLUTTER_UI.md) | Flutter app documentation |

---

## Network

DNA uses the Nodus DHT network. Nodus is designed for independently operated
nodes. Nodes store and
replicate encrypted records and cannot decrypt end-to-end encrypted message
content. They can observe the network and protocol metadata required to accept
connections and operate the DHT; deployments that require transport anonymity
need an additional anonymity layer.

### Documented network endpoints

The repository contains the following operational endpoint list. Source code
cannot prove that an endpoint is currently reachable or running the version in
this checkout; verify live network state before relying on it.

| Node | Location | IP | UDP | TCP |
|------|----------|----|-----|-----|
| US-1 | USA | 154.38.182.161 | 4000 | 4001 |
| EU-1 | Europe | 161.97.85.25 | 4000 | 4001 |
| EU-2 | Europe | 156.67.24.125 | 4000 | 4001 |
| EU-3 | Europe | 156.67.25.251 | 4000 | 4001 |
| EU-4 | Europe | 164.68.105.227 | 4000 | 4001 |
| EU-5 | Europe | 164.68.116.180 | 4000 | 4001 |
| EU-6 | Europe | 75.119.141.51 | 4000 | 4001 |

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
| DNAC | [Apache License 2.0](dnac/LICENSE) |
| Shared Crypto | [Apache License 2.0](LICENSE) |
| Flutter App | [Source-Available (Proprietary)](messenger/dna_messenger_flutter/LICENSE) |

---

<p align="center">
  <strong>Mixed maturity.</strong> DNA Connect and Nodus are release candidates;
  DNAC is a development/testnet component. “Release candidate” is not a security
  certification. Use with appropriate caution for sensitive communications.
</p>
