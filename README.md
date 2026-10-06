# Nodus

<p align="center">
  <strong>Post-quantum network: a DHT, a blockchain, a wallet and a messenger on one node</strong>
</p>

<p align="center">
  <a href="#license"><img src="https://img.shields.io/badge/License-Apache%202.0-blue" alt="Apache 2.0"></a>
  <a href="#status"><img src="https://img.shields.io/badge/Nodus%20Chain-Testnet-orange" alt="Nodus Chain testnet"></a>
  <a href="#cryptography-and-security-scope"><img src="https://img.shields.io/badge/Cryptography-Post--quantum-red" alt="Post-quantum cryptography"></a>
</p>

---

## What is Nodus?

Nodus is a post-quantum network built from one pure-C server, `nodus-server`.
Every node carries two things at once:

- a **Kademlia DHT** that stores and replicates signed records, and
- a **validator** of **Nodus Chain**, a UTXO blockchain whose coin is **NODUS**.

On top of the network sit the **Nodus Web Wallet** and, next, **Nodus Connect**
(end-to-end encrypted messaging, web first).

Nodus is **not an anonymity network**. A node that accepts a connection can
observe network metadata such as an IP address, timing and traffic volume, and
nodes process the protocol metadata required to route, store and expire records.
The cryptographic boundary protects content; it does not make transport
metadata disappear.

| Project | What it is | Status |
|---------|------------|--------|
| [**Nodus**](nodus/) | `nodus-server`: post-quantum Kademlia DHT + embedded Nodus Chain validator | Testnet |
| **Nodus Chain** — [`dnac/`](dnac/), `shared/dnac/`, `nodus/src/witness/` | Post-quantum UTXO chain, coin NODUS, CometBFT consensus | **Testnet since 30 September 2026** |
| [**Nodus Web Wallet**](web-wallet/) | Accountless browser wallet: NODUS balance, send and staking on the testnet, plus ETH, BSC, Solana and TRON | Development preview |
| **Nodus Connect** — `web-wallet/connect/`, `messenger/codec/` | End-to-end encrypted messaging, built into the web wallet first; mobile and desktop later | In development, not released |
| [**Scan**](explorer/) | Block explorer daemon: read-only indexer + JSON API | Live |
| [**Website**](website/) | nodusnetwork.io with its Wiki and Scan frontends | Live |
| [**QGP**](qgp/) | `qgp`: post-quantum (ML-DSA-87) signing of validator packages and their trust state | In development, not released |
| [**DNA Connect**](messenger/) | The earlier Flutter messenger + wallet and its C library (`libdna`) | **Frozen** (see below) |

### DNA Connect is frozen

As of 29 September 2026 DNA Connect gets **no new releases**. It is not shut
down: no forced update is published, the nodes keep serving its data, and
existing installations keep working. The next user product is **Nodus Connect**,
web first. The same 24-word recovery phrase opens the same identity in both.
The C library under `messenger/` stays in the tree: Nodus Connect is built on
its message codecs (`messenger/codec/`).

---

## Architecture

### One node

```
┌──────────────────────────────────────────────────────────────────┐
│                          nodus-server                            │
├────────────┬────────────┬────────────┬────────────┬──────────────┤
│  UDP 4000  │  TCP 4001  │  TCP 4002  │  TCP 4004  │  ws (local)  │
│  Kademlia  │  Clients   │ Inter-node │ Chain p2p  │  Browsers,   │
│  discovery │  DHT + RPC │ replication│ (CometBFT) │  off by      │
│            │            │            │            │  default     │
├────────────┴────────────┴────────────┼────────────┴──────────────┤
│  DHT: 512-bit keyspace, k = 8,       │  Nodus Chain validator:   │
│  Dilithium5-signed values, 7-day TTL │  CometBFT v0.38.26 port,  │
│  SQLite storage, media blobs         │  Ledger V2 engine         │
└──────────────────────────────────────┴───────────────────────────┘
```

- Client connections (TCP 4001) are encrypted with AES-256-GCM after a KEM key
  exchange: ML-KEM-1024 when the other side advertises a signed ML-KEM key,
  Kyber1024 round-3 otherwise.
- The WebSocket entry listens on `127.0.0.1` only; a local TLS proxy serves it
  to browsers (`nodus/README.md`, "Configuration").
- TCP 4003 (channels) is defined but the channel server is compiled out.

### Nodus Chain

- **Consensus** — a literal C port of **CometBFT v0.38.26** (`shared/dnac/cmt_*`),
  with SHA3-512 hashes and ML-DSA-87 (Dilithium5) votes. Every validator must
  reach a byte-identical state for every block.
- **Block pace** — a compiled node setting, not a governed parameter: a 4 s
  commit timeout, and an empty block every 60 s when there are no transactions
  (`nodus/src/witness/nodus_witness_cmt_node.c`).
- **Transactions** — multi-leg envelopes executed by the Ledger V2 engine
  (`nodus/src/witness/`).
- **Supply** — 1,000,000,000 NODUS, fixed; no coin is ever minted. Genesis sets
  aside a 200M reward pool and every fee goes back into it. Rewards are
  reckoned each epoch and paid out to the stakers every 24 epochs by default.
- **Staking** — validator self-stake exactly 10M NODUS, up to 32 seated
  validators, minimum delegation 100 NODUS, commission capped at 50%.
- **Upgrades** — the testnet is not wiped any more. A change to the chain's
  rules is a hard fork that takes effect at an agreed block height
  (`nodus/docs/DEPLOY_RUNBOOK.md`).

Details: [`nodus/README.md`](nodus/README.md) and [`dnac/README.md`](dnac/README.md).

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
| **Dilithium5** | ML-DSA-87 (FIPS 204) | Digital signatures, chain votes |
| **AES-256-GCM** | NIST | Symmetric encryption |
| **SHA3-512** | NIST | Hashing, chain hashes |

---

## Quick Start

### Prerequisites (Debian/Ubuntu)

```bash
sudo apt install git cmake gcc g++ libssl-dev libsqlite3-dev \
                 libcurl4-openssl-dev libjson-c-dev libargon2-dev \
                 libreadline-dev
# SQLCipher is required for the C library (database encryption)
sudo apt install -t bookworm-backports libsqlcipher-dev
```

### Clone & Build

```bash
git clone https://github.com/nocdem/dna.git
cd dna

# Nodus server + nodus-cli (independent build)
cmake -S nodus -B nodus/build && cmake --build nodus/build -j$(nproc)

# C library (libdna.so) — compiles the Nodus Chain client sources in dnac/src too
cmake -S messenger -B messenger/build && cmake --build messenger/build -j$(nproc)

# ZK proof stack (standalone Makefile)
make -C shared/crypto/zk test

# Web wallet (Node.js 22.12+)
(cd web-wallet && npm ci && npm run build)
```

`dna-connect-cli`'s `dna` command group is compiled in only when a
`dnac/build/libdnac.a` is already present; a default build leaves it out. On
the testnet, NODUS transfers are made with the web wallet or with
`nodus-cli v2-envelope spend` (`nodus/README.md`).

The frozen DNA Connect Flutter app still builds against the C library:
`(cd messenger/dna_messenger_flutter && flutter pub get && flutter build linux)`.

---

## Repository Structure

```
dna/
├── nodus/                     # nodus-server, nodus-cli, client SDK
│   ├── src/                   #   Server, client SDK, protocol, routing, storage
│   ├── src/witness/           #   Embedded Nodus Chain validator (Ledger V2 engine + CometBFT host)
│   ├── include/               #   Public headers
│   ├── tools/                 #   nodus-server, nodus-cli, nodus-circ sources; genesis ceremony template
│   └── tests/                 #   Unit + integration tests (Genesis Protocol harness)
├── shared/
│   ├── crypto/                # Post-quantum crypto primitives
│   │   ├── sign/              #   Dilithium5, secp256k1, Ed25519
│   │   ├── enc/               #   ML-KEM-1024, Kyber1024 round-3 (legacy), AES-256-GCM
│   │   ├── hash/              #   SHA3-512, Keccak-256
│   │   ├── key/               #   BIP32, BIP39, PBKDF2
│   │   ├── utils/             #   Logging, platform abstraction, CSPRNG
│   │   └── zk/                #   STARK proof stack (Plonky3-grounded C ports)
│   └── dnac/                  # Nodus Chain wire codecs + the CometBFT port (cmt_*)
├── dnac/                      # Nodus Chain client library (compiled into libdna)
├── web-wallet/                # Nodus Web Wallet (wallet.nodusnetwork.io); connect/ = Nodus Connect core
├── sdk/js/                    # Nodus EVM SDK for Node.js scripts (in-repo only, not on npm; sdk/js/README.md)
├── explorer/                  # Scan: block explorer daemon — read-only indexer + JSON API
├── website/                   # nodusnetwork.io, wiki.nodusnetwork.io, scan.nodusnetwork.io (static)
├── messenger/                 # DNA Connect (frozen): C library + Flutter app
│   ├── src/api/               #   DNA Engine (23 engine modules)
│   ├── codec/                 #   Message codecs shared with Nodus Connect
│   ├── messenger/ dht/ transport/ database/ blockchain/ cli/ include/ tests/
│   ├── dna_messenger_flutter/ #   Flutter app
│   └── docs/                  #   Documentation
├── scripts/                   # Operational scripts
└── docs/                      # Top-level project documentation
```

Source identifiers keep their older `dna` / `dnac` names (`libdna`,
`DNAC_*`, `dna-connect-cli`); the product names above are the current ones.

---

## Versions

| Component | Version | Version file |
|-----------|---------|--------------|
| Nodus | v0.23.5 | `nodus/include/nodus/nodus_types.h` |
| Nodus Chain client (DNAC) | v0.19.3 | `dnac/include/dnac/version.h` |
| C library (libdna) | v0.11.32 | `messenger/include/dna/version.h` |
| Nodus Web Wallet | v0.1.35 | `web-wallet/package.json` |
| DNA Connect Flutter app (frozen) | v1.0.0-rc241 | `messenger/dna_messenger_flutter/pubspec.yaml` |

---

## Documentation

| Document | Description |
|----------|-------------|
| [Nodus README](nodus/README.md) | Server, ports, configuration, chain commands, tests |
| [Nodus Architecture](nodus/docs/ARCHITECTURE.md) | Server layers, protocol, consensus, storage |
| [Deploy Runbook](nodus/docs/DEPLOY_RUNBOOK.md) | Deploy procedure, height-activated upgrades |
| [Genesis Protocol harness](nodus/tests/integration/stagef/README.md) | 7-node localhost chain tests |
| [Nodus Chain client (DNAC) README](dnac/README.md) | Client library, staking and reward rules |
| [Web Wallet README](web-wallet/README.md) | Browser wallet and the Nodus Connect core |
| [Scan README](explorer/README.md) | Explorer daemon and its JSON API |
| [DNA Connect README](messenger/README.md) | The frozen messenger |
| [Protocol Specs](messenger/docs/PROTOCOL.md) | Message wire formats (Seal, Spillway, Anchor, Atlas, Nexus) |

---

## Network

Anyone can run a Nodus DHT node. Nodes store and replicate signed records and
cannot decrypt end-to-end encrypted content; they can observe the network and
protocol metadata required to accept connections and operate the DHT.
Deployments that require transport anonymity need an additional anonymity layer.

The Nodus Chain testnet started on seven validator nodes. Becoming a validator
takes a self-stake of exactly 10M NODUS.

---

## Links

- **Website:** https://nodusnetwork.io
- **Web Wallet:** https://wallet.nodusnetwork.io
- **Scan:** https://scan.nodusnetwork.io
- **Wiki:** https://wiki.nodusnetwork.io
- **GitLab (Primary):** https://gitlab.cpunk.io/cpunk/dna
- **GitHub (Mirror):** https://github.com/nocdem/dna
- **Telegram:** [@chippunk_official](https://t.me/chippunk_official)

---

## License

| Component | License |
|-----------|---------|
| Nodus | [Apache License 2.0](nodus/LICENSE) |
| Nodus Chain client (DNAC) | [Apache License 2.0](dnac/LICENSE) |
| C library (libdna) | [Apache License 2.0](messenger/LICENSE) |
| Shared Crypto | [Apache License 2.0](LICENSE) |
| DNA Connect Flutter app | [Source-Available (Proprietary)](messenger/dna_messenger_flutter/LICENSE) |

---

<p align="center" id="status">
  <strong>Testnet.</strong> Nodus Chain is a public testnet; the web wallet is a
  development preview and not an audited custody product. Nothing here is a
  security certification.
</p>
