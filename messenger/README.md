# DNA Messenger

**Post-quantum encrypted messenger with cpunk wallet**

Secure messaging using **NIST Category 5 post-quantum cryptography** (Kyber1024 + Dilithium5) that remains secure against future quantum computer attacks.

## Status

**Alpha v0.1.x** - Breaking changes expected

- **Version:** 0.1.x (x = git commit count)
- **Security:** NIST Category 5 (256-bit quantum resistance)
- **Platforms:** Linux, Windows (cross-compiled)

---

## Binaries

DNA Messenger builds **two binaries only**:

### dna-messenger

Desktop GUI application for end-to-end encrypted messaging.

- **UI:** ImGui (OpenGL3 + GLFW3)
- **Features:** E2E messaging, groups, user profiles, cpunk wallet, DNA Board
- **Crypto:** Kyber1024 encryption + Dilithium5 signatures + AES-256-GCM
- **Storage:** Local SQLite (no centralized server)
- **Network:** P2P via DHT with ICE NAT traversal

```bash
./build/imgui_gui/dna-messenger
```

### dna-nodus (v0.3)

DHT bootstrap + STUN/TURN server for the DNA network infrastructure.

- **Purpose:** Bootstrap peer discovery, DHT persistence, NAT relay
- **Security:** Mandatory Dilithium5 signatures on all DHT values
- **Persistence:** SQLite database survives restarts
- **Config:** JSON file at `/etc/dna-nodus.conf` (no CLI args)
- **Ports:**
  - 4000 (UDP) - DHT operations
  - 3478 (UDP) - STUN/TURN relay

```bash
# Build and deploy
bash /opt/dna-messenger/build-nodus.sh
```

**Public Bootstrap Nodes:**
| Server | IP | DHT | TURN |
|--------|-----|-----|------|
| US-1 | 154.38.182.161 | :4000 | :3478 |
| EU-1 | 164.68.105.227 | :4000 | :3478 |
| EU-2 | 164.68.116.180 | :4000 | :3478 |

See [docs/DNA_NODUS.md](docs/DNA_NODUS.md) for full documentation.

---

## Features

### Messaging
- End-to-end encryption (Kyber1024 + AES-256-GCM)
- 1:1 direct messaging with delivery/read receipts
- Group chats with GSK encryption (200x faster than per-recipient)
- Offline message queueing (7-day DHT storage)
- Message threading and comments

### Groups
- DHT-based decentralized groups
- Group Symmetric Key (GSK) for efficient encryption
- Automatic key rotation on member changes
- Group ownership transfer with 7-day liveness check
- P2P group invitations

### Networking
- P2P transport via OpenDHT
- ICE NAT traversal (libjuice + STUN)
- 3-tier fallback: LAN direct → ICE → DHT queue
- ~85-90% direct connection success rate
- No relay servers required

### User Profiles
- Display name, bio, location, website, avatar
- DHT storage with 7-day cache
- Avatar system (64x64 JPEG, circular display)

### DNA Board (Social)
- Decentralized message wall per user
- Community voting (thumbs up/down)
- Dilithium5 signed posts
- 30-day TTL, 100 messages max

### cpunk Wallet
- CPUNK, CELL, KEL token balances
- Send/receive via Cellframe RPC
- QR code generation
- Transaction history

### Security
- BIP39 24-word recovery phrases
- Per-identity contact lists with DHT sync
- Cryptographically signed reverse mappings
- No centralized message storage

---

## Quick Start

### Pre-Built Binaries

Download from GitLab CI/CD:
- https://gitlab.cpunk.io/cpunk/dna-messenger/-/artifacts

### Build from Source (Linux)

```bash
# Install dependencies (Debian/Ubuntu)
sudo apt install git cmake g++ libssl-dev libsqlite3-dev libcurl4-openssl-dev \
                 libjson-c-dev libargon2-dev libfmt-dev libreadline-dev \
                 libasio-dev libmsgpack-cxx-dev

# For GUI (optional): add OpenGL/GLFW
sudo apt install libglfw3-dev libgl1-mesa-dev libglu1-mesa-dev

# Clone and build
git clone https://github.com/nocdem/dna-messenger.git
cd dna-messenger
mkdir build && cd build
cmake .. && make -j$(nproc)

# Run GUI
./imgui_gui/dna-messenger

# Or CLI only (no GUI deps needed)
make dna-messenger-cli
./cli/dna-messenger-cli --help
```

### Cross-Compile for Windows

```bash
# Requires MXE (M cross environment)
./build-cross-compile.sh windows-x64

# Output: dist/windows-x64/dna-messenger.exe
```

---

## Cryptography

**NIST Category 5** - Maximum quantum resistance (256-bit security)

| Algorithm | Standard | Purpose | Size |
|-----------|----------|---------|------|
| **Kyber1024** | ML-KEM-1024 (FIPS 203) | Key encapsulation | 1568-byte ciphertext |
| **Dilithium5** | ML-DSA-87 (FIPS 204) | Digital signatures | 4627-byte signatures |
| **AES-256-GCM** | NIST | Symmetric encryption | 256-bit keys |
| **SHA3-512** | NIST | Hashing | 512-bit output |

### OpenDHT-PQ Fork

DNA Messenger includes a **forked OpenDHT** with post-quantum cryptography:

- Replaced RSA-2048 with Dilithium5 (FIPS 204)
- All DHT values require mandatory signatures
- Binary identity files (.dsa, .pub, .cert)
- Location: `vendor/opendht-pq/`

---

## Recovery

**Backup Your Keys:**
1. Write down your 24-word BIP39 recovery phrase during identity creation
2. Store it safely offline (never digitally)
3. Optional: Add passphrase for extra security

**Restore:**
1. Choose "Restore from seed phrase" at startup
2. Enter your 24 words
3. Keys regenerated and verified

---

## Architecture

```
┌─────────────────┐     ┌─────────────────┐
│  dna-messenger  │────▶│   dna-nodus     │
│   (GUI Client)  │     │ (Bootstrap Node)│
└────────┬────────┘     └────────┬────────┘
         │                       │
         ▼                       ▼
┌─────────────────────────────────────────┐
│              OpenDHT-PQ Network         │
│   (Post-Quantum Distributed Hash Table) │
└─────────────────────────────────────────┘
```

**Data Storage:**
- Messages: Local SQLite (`~/.dna/messages.db`)
- Contacts: Per-identity SQLite (`~/.dna/<identity>_contacts.db`)
- Keys: Local encrypted (`~/.dna/<fingerprint>/keys/*.dsa`, `*.kem`)
- Public data: DHT with local cache

---

## Documentation

- **[Architecture](docs/ARCHITECTURE.md)** - System design
- **[Development](docs/DEVELOPMENT.md)** - Code guidelines
- **[API Reference](docs/API.md)** - Quick API reference
- **[Roadmap](ROADMAP.md)** - Development phases
- **[GSK Implementation](docs/GSK_IMPLEMENTATION.md)** - Group encryption
- **[ICE NAT Traversal](docs/ICE_NAT_TRAVERSAL_FIXES.md)** - NAT traversal

---

## Links

- **GitLab (Primary):** https://gitlab.cpunk.io/cpunk/dna-messenger
- **GitHub (Mirror):** https://github.com/nocdem/dna-messenger
- **cpunk.io:** https://cpunk.io
- **cpunk.club:** https://cpunk.club
- **Telegram:** https://web.telegram.org/k/#@chippunk_official

---

## License

GNU General Public License v3.0

Forked from [QGP (Quantum Good Privacy)](https://github.com/nocdem/qgp)

---

**Warning:** Alpha software. Do not use for sensitive communications yet.
