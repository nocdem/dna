# DNA — Decentralized Network Applications

<p align="center">
  <strong>Post-quantum encrypted communication and decentralized infrastructure</strong>
</p>

<p align="center">
  <a href="#license"><img src="https://img.shields.io/badge/License-Apache%202.0-blue" alt="Apache 2.0"></a>
  <a href="#status"><img src="https://img.shields.io/badge/Status-Mixed%20maturity-orange" alt="Mixed maturity"></a>
  <a href="#cryptography-and-security-scope"><img src="https://img.shields.io/badge/Cryptography-Post--quantum-red" alt="Post-quantum cryptography"></a>
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
| [**Nodus**](nodus/) | Post-quantum Kademlia DHT server with embedded BFT witness | RC |
| [**DNAC**](dnac/) | DNA Chain — post-quantum UTXO blockchain with BFT witness consensus | Testnet |
| [**Nodus Web Wallet**](web-wallet/) | Accountless browser multichain wallet and temporary CPUNK balance reader | Development preview |
| [**Nodus Website**](website/) | nodusnetwork.io with its Wiki and Scan subdomains | Live |

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
│  DNAC / DNA Chain (C) — client library in libdna     │
│  UTXO wallet · TX builder · witness RPC client       │
│  Consensus itself runs in Nodus (nodus/src/witness/) │
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

    All values signed with Dilithium5 · 7-day TTL
    Tier 1 (UDP 4000): Kademlia — ping, find_node, store, find_value
    Tier 2 (TCP 4001): Client — auth, put, get, listen, presence
```

---

## Cryptography and security scope

The key-encapsulation and signature parameter sets target NIST security
category 5. That is a security-strength target, not a certification: the
implementations are ports of the pq-crystals references, not an independently
validated cryptographic module.

| Algorithm | Standard | Purpose |
|-----------|----------|---------|
| **ML-KEM-1024** | FIPS 203 (pq-crystals `standard` reference) — see `shared/crypto/enc/qgp_mlkem.h` | Key encapsulation, used whenever the peer has published an ML-KEM key |
| **Kyber1024 round-3** | pre-FIPS-203, *not* interoperable with ML-KEM — see `shared/crypto/enc/qgp_kyber.h` | Legacy key encapsulation, kept as the fallback for peers without an ML-KEM key |
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
cd messenger/build && cmake .. && make -j$(nproc)

# Nodus DHT server
cd ../../nodus/build && cmake .. && make -j$(nproc)

# DNAC client library (requires messenger C library built first)
cd ../../dnac/build && cmake .. && make -j$(nproc)

# Re-run the messenger build so dna-connect-cli picks up libdnac.a
# (the CLI's DNA Chain command group is enabled at configure time)
cd ../../messenger/build && cmake .. && make -j$(nproc)

# Flutter app (requires C library)
cd ../dna_messenger_flutter
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
│   ├── src/                   #   Server, client SDK, protocol, cluster consensus
│   ├── src/witness/           #   Embedded DNA Chain witness (BFT consensus)
│   ├── include/               #   Public headers
│   └── tests/                 #   Unit + integration tests (Genesis Protocol harness)
├── shared/
│   ├── crypto/                # Post-quantum crypto primitives
│   │   ├── sign/              #   Dilithium5, secp256k1, Ed25519
│   │   ├── enc/               #   Kyber1024, AES-256-GCM
│   │   ├── hash/              #   SHA3-512, Keccak-256
│   │   ├── key/               #   BIP32, BIP39, PBKDF2
│   │   ├── utils/             #   Logging, platform abstraction, CSPRNG
│   │   └── zk/                #   STARK proof stack (Plonky3-grounded C ports)
│   └── dnac/                  # Canonical DNA Chain wire codecs (client + witness)
├── dnac/                      # DNA Chain client library
│   ├── src/                   #   Wallet, TX builders, witness RPC client, client-side verify
│   ├── include/               #   Public headers
│   └── tests/                 #   Unit tests
├── explorer/                  # DNA Chain block explorer daemon (scan.cpunk.io) — read-only indexer + JSON API
├── website/                   # nodusnetwork.io, wiki.nodusnetwork.io, scan.nodusnetwork.io (static)
├── web-wallet/                # Nodus Web Wallet (wallet.nodusnetwork.io, separate origin)
├── scripts/                   # Operational scripts (determinism checks, reporting)
└── docs/                      # Top-level project documentation
```

---

## Versions

| Component | Version |
|-----------|---------|
| Messenger C Library | v0.11.18 |
| Flutter App | v1.0.0-rc241 |
| Nodus | v0.19.16 |
| DNAC | v0.18.6-ledgerv2-o15b |

---

## Documentation

| Document | Description |
|----------|-------------|
| [Messenger README](messenger/README.md) | Messenger overview, features, build |
| [Nodus README](nodus/README.md) | DHT server architecture and deployment |
| [DNAC README](dnac/README.md) | DNA Chain client library, CLI commands, transaction format |
| [Architecture](messenger/docs/ARCHITECTURE_DETAILED.md) | Detailed system design |
| [Protocol Specs](messenger/docs/PROTOCOL.md) | Wire formats (Seal, Spillway, Anchor, Atlas, Nexus) |
| [DNA Engine API](messenger/docs/DNA_ENGINE_API.md) | Core C API reference |
| [CLI Reference](messenger/docs/CLI_TESTING.md) | Command-line tool usage |
| [Flutter UI](messenger/docs/FLUTTER_UI.md) | Flutter app documentation |

---

## Network

DNA uses the Nodus DHT network. Anyone can run a Nodus node. Nodes store and
replicate encrypted records and cannot decrypt end-to-end encrypted message
content. They can observe the network and protocol metadata required to accept
connections and operate the DHT; deployments that require transport anonymity
need an additional anonymity layer.

### Current Nodes

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

- **Website:** https://nodusnetwork.io
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
