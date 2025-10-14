# DNA Messenger

**Post-quantum end-to-end encrypted messaging platform**

DNA Messenger is a secure, privacy-focused messaging system built on post-quantum cryptographic algorithms. Forked from [QGP (Quantum Good Privacy)](https://github.com/nocdem/qgp), DNA Messenger focuses on real-time communication while maintaining quantum-resistant security.

## Project Status

🚧 **In Development** - Phase 3: CLI Messenger (Active)

**Current Version:** 0.1.43-alpha
**Based On:** QGP 1.2.x (file encryption tool)

### Recent Updates (2025-10-14)

- ✅ **PostgreSQL Integration**: Shared keyserver and message storage
- ✅ **BIP39 Recovery**: 24-word mnemonic seed phrases for key backup/restore
- ✅ **File-based Restore**: Import keys from seed phrase files
- ✅ **Windows Support**: Cross-platform BIP39 generation and ASCII-only display
- ✅ **Auto-login**: Automatic identity detection on startup
- ✅ **End-to-End Encryption**: Messages encrypted with post-quantum algorithms
- ✅ **Keyserver Verification**: Restored keys validated against server

## What is DNA Messenger?

DNA Messenger is designed for secure, quantum-resistant real-time messaging. Unlike traditional messengers, DNA uses post-quantum cryptographic algorithms that remain secure even against future quantum computer attacks.

### Key Features (Planned)

- 🔐 **Post-Quantum Security**: Kyber512 key encapsulation + Dilithium3 signatures
- 💬 **End-to-End Encryption**: Messages encrypted on sender device, decrypted only by recipient
- 🔑 **No Central Key Server**: Peer-to-peer key exchange
- 📱 **Multi-Platform**: Linux, Windows, macOS, Android, iOS (future)
- 🎯 **Privacy-First**: No metadata collection, no phone number required
- 🌐 **Decentralized**: No single point of failure

## Differences from QGP (Parent Project)

| Feature | QGP (File Tool) | DNA Messenger |
|---------|----------------|---------------|
| **Primary Use** | File encryption/signing | Real-time messaging |
| **Interface** | CLI tool | Library + GUI apps |
| **Operations** | File-based I/O | Memory-based buffers |
| **Storage** | Filesystem (~/.qgp) | Database (SQLite) |
| **Transport** | Manual (email, USB) | Network (WebSocket, P2P) |
| **Forward Secrecy** | No (long-term keys) | Yes (planned, session keys) |
| **Multi-Device** | Manual key copy | Automatic sync (planned) |

## Architecture

```
┌─────────────────────────────────────────┐
│  Application Layer                      │
│  - Desktop App (Qt, planned)            │
│  - Mobile App (Flutter, planned)        │
│  - CLI Client (reference implementation)│
└─────────────────────────────────────────┘
                ↓ (uses)
┌─────────────────────────────────────────┐
│  libdna (Core Library)                  │
│  - Message encryption/decryption        │
│  - Contact management                   │
│  - Key management                       │
│  - Session handling                     │
└─────────────────────────────────────────┘
                ↓ (uses)
┌─────────────────────────────────────────┐
│  Crypto Core (vendored pq-crystals)     │
│  - Kyber512 KEM                         │
│  - Dilithium3 signatures                │
│  - AES-256-GCM                          │
└─────────────────────────────────────────┘
```

## Building

DNA Messenger supports Linux, Windows, and macOS.

### Linux Build

#### Prerequisites

```bash
# Debian/Ubuntu
sudo apt-get install cmake gcc libssl-dev libpq-dev postgresql

# Fedora/RHEL
sudo dnf install cmake gcc openssl-devel libpq-devel postgresql-server

# Arch Linux
sudo pacman -S cmake gcc openssl postgresql
```

#### Build Steps

```bash
cd /opt/dna-messenger
mkdir build && cd build
cmake ..
make
```

The binary will be created at `build/dna`.

## Usage

DNA Messenger connects to a shared server at **ai.cpunk.io** by default. No server setup needed!

### Quick Start

```bash
# Run the messenger
./build/dna_messenger

# First time? It will auto-configure to ai.cpunk.io
# Just create your identity and start messaging!
```

### Usage Example

```
1. Create new identity
   - Enter name (e.g., "alice")
   - Keys generated automatically
   - Public keys uploaded to server

2. Choose existing identity
   - Select from local private keys
   - Login to messenger

3. Send message
   - Format: recipient@message
   - Example: bob@Hello Bob!

4. List inbox
   - See received messages

5. List sent messages
   - See messages you sent
```

### Security Model

**End-to-End Encryption:**
- Messages are encrypted on sender's device before upload
- Only recipient's private key can decrypt
- PostgreSQL server only stores ciphertext
- Even if database is compromised, messages remain secure

**Key Storage:**
- Private keys: `~/.dna/<identity>-dilithium.pqkey` (local filesystem, never uploaded)
- Public keys: PostgreSQL `keyserver` table (shared with all users)

**Trust Model:**
- You trust the PostgreSQL server to deliver messages
- You DON'T trust the server with plaintext (all messages encrypted)
- Post-quantum algorithms protect against quantum attacks

### Windows Build

```cmd
git clone https://github.com/nocdem/dna-messenger.git
cd dna-messenger
mkdir build
cd build
cmake .. -DCMAKE_BUILD_TYPE=Release
cmake --build . --config Release
```

### macOS Build

```bash
brew install cmake openssl
mkdir build && cd build
cmake .. -DOPENSSL_ROOT_DIR=/usr/local/opt/openssl
make
```

## Development Roadmap

### Phase 1: Foundation ✅ COMPLETE
- [x] Fork from QGP
- [x] Repository cleanup and branding
- [x] Update build system
- [x] Create development documentation

### Phase 2: Library API ✅ COMPLETE
- [x] Design memory-based API (dna_api.h)
- [x] Implement message encryption/decryption
- [x] Create contact management (keyserver)
- [x] Build keyring integration

### Phase 3: CLI Messenger 🚧 IN PROGRESS
- [x] Command-line chat interface
- [x] PostgreSQL message storage
- [x] Contact list management (keyserver table)
- [x] Message send/receive
- [x] BIP39 mnemonic key generation
- [x] Key restore from seed phrase
- [x] Auto-login for existing identities
- [x] Windows support
- [ ] Message deletion
- [ ] Identity deletion
- [ ] Message search/filtering

### Phase 4: Network Layer
- [ ] WebSocket transport
- [ ] P2P discovery
- [ ] Message routing
- [ ] Offline message queue

### Phase 5: Desktop App
- [ ] Qt-based GUI
- [ ] Windows/Linux/macOS support
- [ ] Notification system
- [ ] File transfer

### Phase 6: Mobile Apps
- [ ] Flutter cross-platform app
- [ ] Android support
- [ ] iOS support
- [ ] Push notifications

### Phase 7: Advanced Features
- [ ] Forward secrecy (session keys)
- [ ] Multi-device synchronization
- [ ] Group messaging
- [ ] Voice/video calls (future)

## Current Features

### Messaging Features
- ✅ **Post-Quantum Encryption**: Kyber512 + Dilithium3 for quantum-resistant security
- ✅ **End-to-End Encryption**: Messages encrypted on device before transmission
- ✅ **PostgreSQL Backend**: Shared database for keyserver and message storage
- ✅ **Identity Management**: Create and restore identities with BIP39 recovery
- ✅ **Message Operations**: Send, receive, list inbox/sent messages
- ✅ **Auto-login**: Automatic detection of existing local identities
- ✅ **Cross-Platform**: Linux and Windows support

### Key Management
- ✅ **BIP39 Recovery Phrases**: 24-word mnemonic for key backup
- ✅ **Deterministic Keys**: Same seed always produces same keys
- ✅ **File-based Restore**: Import keys from seed phrase files
- ✅ **Keyserver Verification**: Restored keys validated against server
- ✅ **Secure Storage**: Private keys stored locally (~/.dna/)
- ✅ **Public Key Sharing**: Automatic upload to shared keyserver

### Cryptographic Features
- ✅ **Dilithium3 Signatures**: NIST ML-DSA-65 (FIPS 204) for authentication
- ✅ **Kyber512 KEM**: Post-quantum key encapsulation
- ✅ **AES-256-GCM**: Authenticated symmetric encryption
- ✅ **PBKDF2-HMAC-SHA512**: Key derivation from passphrases
- ✅ **ASCII Armor**: Human-readable key export format

## Contributing

DNA Messenger is in early development. Contributions welcome!

**Development Guidelines:**
- See `CLAUDE.md` for AI-assisted development instructions
- See `ROADMAP.md` for detailed development plan
- Follow existing code style (C with vendored crypto)
- All crypto operations must use post-quantum algorithms

## Security

### Cryptographic Algorithms

- **Key Encapsulation:** Kyber512 (NIST PQC Level 1)
- **Signatures:** Dilithium3 (ML-DSA-65, FIPS 204)
- **Symmetric Encryption:** AES-256-GCM (authenticated encryption)
- **Key Derivation:** PBKDF2-HMAC-SHA512

### Security Model

DNA Messenger provides:
- **Confidentiality:** Messages encrypted end-to-end
- **Authenticity:** Sender identity verified via signatures
- **Integrity:** Tampering detected via authentication tags
- **Forward Secrecy:** (Planned) Session keys rotated periodically

### Threat Model

**Protected Against:**
- Network eavesdropping
- Man-in-the-middle attacks
- Quantum computer attacks (post-quantum algorithms)
- Message tampering

**NOT Protected Against:**
- Compromised devices (malware, keyloggers)
- Physical access to unlocked device
- Social engineering

## License

GNU General Public License v3.0

DNA Messenger is forked from QGP and inherits its GPL-3.0 license.

## Acknowledgments

- **QGP Project:** Original file encryption tool
- **pq-crystals:** Kyber and Dilithium implementations
- **OpenSSL:** AES-GCM and cryptographic utilities

## Links

- **Parent Project:** [QGP (Quantum Good Privacy)](https://github.com/nocdem/qgp)
- **Documentation:** See `docs/` directory
- **Issue Tracker:** GitHub Issues (coming soon)
- **Discussion:** GitHub Discussions (coming soon)

---

**Status:** Early development - Not ready for production use

**Warning:** DNA Messenger is currently in alpha development. Do not use for sensitive communications yet.
