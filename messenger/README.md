# DNA Messenger

**Post-quantum end-to-end encrypted messaging platform**

DNA Messenger is a secure, privacy-focused messaging system built on post-quantum cryptographic algorithms. Forked from [QGP (Quantum Good Privacy)](https://github.com/nocdem/qgp), DNA Messenger focuses on real-time communication while maintaining quantum-resistant security.

## Project Status

🚧 **In Development** - Fork preparation phase

**Current Version:** 0.1.0-alpha
**Based On:** QGP 1.2.x (file encryption tool)

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
sudo apt-get install cmake gcc libssl-dev

# Fedora/RHEL
sudo dnf install cmake gcc openssl-devel

# Arch Linux
sudo pacman -S cmake gcc openssl
```

#### Build Steps

```bash
cd /opt/dna-messenger
mkdir build && cd build
cmake ..
make
```

The binary will be created at `build/dna`.

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

### Phase 1: Foundation (Current)
- [x] Fork from QGP
- [ ] Repository cleanup and branding
- [ ] Update build system
- [ ] Create development documentation

### Phase 2: Library API (Next)
- [ ] Design memory-based API
- [ ] Implement message encryption/decryption
- [ ] Create contact management
- [ ] Build keyring integration

### Phase 3: CLI Messenger (Reference Implementation)
- [ ] Command-line chat interface
- [ ] Local message storage
- [ ] Contact list management
- [ ] Message send/receive

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

## Current Features (Inherited from QGP)

Since DNA Messenger is newly forked, it currently has all QGP features:

- Post-quantum key generation (Dilithium3, Kyber512)
- File signing and verification
- File encryption/decryption
- Multi-recipient encryption
- ASCII armor support
- Keyring management
- BIP39 mnemonic key recovery

These will be adapted for messenger use in upcoming development phases.

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
