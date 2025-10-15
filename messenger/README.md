# DNA Messenger

**Post-quantum encrypted messaging platform**

Secure messaging using post-quantum cryptography (Kyber512 + Dilithium3) that remains secure against future quantum computer attacks.

## Status

🚧 **Alpha Development**

**Version:** 0.1.x (x = git commit count)
- **Major:** 0 (Alpha - breaking changes expected)
- **Minor:** 1 (Current feature set)
- **Patch:** Auto-incremented with each commit

**Available in two versions:**
- **GUI:** Qt5 graphical interface with theme support and auto-updates
- **CLI:** Command-line interface for terminal users

## Quick Start

### Linux

```bash
# Install dependencies
sudo apt install cmake gcc libssl-dev libpq-dev qtbase5-dev qtmultimedia5-dev

# Build
git clone https://github.com/nocdem/dna-messenger.git
cd dna-messenger
mkdir build && cd build
cmake ..
make

# Run GUI
./gui/dna_messenger_gui

# Or run CLI
./dna_messenger
```

### Windows

```cmd
git clone https://github.com/nocdem/dna-messenger.git
cd dna-messenger
mkdir build
cd build
cmake .. -DCMAKE_BUILD_TYPE=Release
cmake --build . --config Release

REM Run GUI
gui\Release\dna_messenger_gui.exe

REM Or run CLI
Release\dna_messenger.exe
```

## Features

**Current:**
- ✅ End-to-end encryption with post-quantum algorithms
- ✅ Multi-recipient messaging (broadcast to multiple users)
- ✅ Persistent group chats with member management
- ✅ 24-word BIP39 recovery phrases
- ✅ Cross-platform (Linux & Windows)
- ✅ Shared keyserver at ai.cpunk.io
- ✅ Auto-update mechanism
- ✅ Theme switching (cpunk.io cyan / cpunk.club orange)
- ✅ Dynamic font scaling (1x - 4x)
- ✅ Message delivery and read receipts
- ✅ Desktop notifications

**Coming Soon:**
- 🚧 Hypercore Protocol P2P networking (Phase 5)
- 🚧 Distributed keyserver with Hyperbee (Phase 5)
- 🚧 Web-based messenger (Phase 5.5)
- 📋 CF20 Wallet for cpunk network payments
- 📋 Mobile applications (Flutter)
- 📋 Forward secrecy (ephemeral session keys)
- 📋 Voice/video calls

## Roadmap

### ✅ Phase 1: Fork Preparation (Complete)
- Repository forked from QGP
- DNA Messenger branding applied
- Build system configured

### ✅ Phase 2: Library API (Complete)
- Memory-based encryption/decryption API
- Public API header (`dna_api.h`)
- Multi-recipient encryption support
- Contact management (keyserver)

### ✅ Phase 3: CLI Messenger Client (Complete)
- Command-line chat interface
- PostgreSQL message storage
- Contact list management
- Message send/receive/search
- BIP39 mnemonic key generation
- File-based seed phrase restore
- Auto-login for existing identities
- Cross-platform support (Linux & Windows)

### ✅ Phase 4: Qt Desktop App (Complete)
- Qt5 GUI with contact list and chat area
- Message send/receive functionality
- Real contacts from keyserver
- Real conversations from database
- Message decryption (sent and received)
- Multi-recipient encryption support
- Auto-update mechanism
- Message timestamps
- Auto-detect local identity
- Delivery/read receipts
- Desktop notifications
- Theme system (2 themes)
- Font scaling (1x-4x)
- **Group messaging with full UI**
- **CF20 Wallet integration (planned)**

### 🚧 Phase 5: Network Layer - Hypercore Protocol (Planned)
- [ ] Hyperswarm P2P networking with DHT
- [ ] Distributed keyserver using Hyperbee
- [ ] Hypercore append-only message logs
- [ ] Real-time message replication
- [ ] NAT traversal (works behind firewalls)
- [ ] Offline-first with automatic sync
- [ ] Node.js bridge daemon (IPC layer)

### 🚧 Phase 5.5: Web-Based Messenger (In Progress - branch: feature/web-messenger)
- [x] WebAssembly crypto module (Emscripten compilation)
- [x] DNA API compiled to WASM (dna_wasm.js/wasm)
- [x] JavaScript wrapper functions
- [ ] HTML5/CSS3 responsive UI
- [ ] Browser-based client (no native dependencies)
- [ ] Progressive Web App (PWA) support
- [ ] Cross-browser compatibility (Chrome, Firefox, Safari, Edge)
- [ ] Client-side encryption/decryption
- [ ] IndexedDB for local key storage

### 📋 Phase 6: Advanced Security (Planned)
- Forward secrecy (session keys)
- Multi-device synchronization
- Secure memory management
- Key verification (QR codes)
- Disappearing messages

### 📋 Phase 7: Mobile Apps (Planned)
- Flutter mobile app
- Android and iOS support
- Push notifications
- Background sync
- Biometric authentication

### 📋 Phase 8+: Future Enhancements (Planned)
- CF20 Wallet integration (Cellframe cpunk network)
- Voice/video calls (WebRTC)
- Stickers and rich media
- Channels (broadcast mode)
- Decentralized architecture
- Tor integration

**For detailed roadmap, see [ROADMAP.md](./ROADMAP.md)**

## Architecture

**Current (Phase 4):**
- Client application (GUI or CLI)
- PostgreSQL message storage (ai.cpunk.io:5432)
- Centralized keyserver for public key distribution
- Your private keys stay on your device (`~/.dna/`)

**Future (Phase 5 - Hypercore Protocol):**
- Fully peer-to-peer (no centralized servers)
- Hyperswarm for P2P networking and NAT traversal
- Distributed keyserver using Hyperbee
- Hypercore append-only logs for message storage
- Each user maintains their own Hyperbee (OUTBOX)
- Users replicate contacts' Hyperbees (INBOX)
- Node.js bridge daemon for Hypercore Protocol integration

**Security:**
- Messages encrypted on your device before sending
- Only recipient can decrypt (end-to-end encryption)
- Post-quantum algorithms (Kyber512 + Dilithium3)
- Append-only logs are cryptographically signed and immutable
- Transport layer encrypted with Noise protocol (Hypercore native)

## Cryptography

- **Key Encapsulation:** Kyber512 (NIST PQC Level 1)
- **Signatures:** Dilithium3 (ML-DSA-65, FIPS 204)
- **Symmetric:** AES-256-GCM (AEAD)
- **Key Derivation:** PBKDF2-HMAC-SHA512

## Recovery

**Backup Your Keys:**
1. Write down your 24-word recovery phrase during identity creation
2. Store it safely offline (never digitally)
3. Optional: Add passphrase for extra security

**Restore Your Keys:**
1. Choose "Restore from seed phrase" at startup
2. Enter your 24 words
3. Keys regenerated and verified against keyserver

## License

GNU General Public License v3.0

Forked from [QGP (Quantum Good Privacy)](https://github.com/nocdem/qgp)

## Links

- **GitHub:** https://github.com/nocdem/dna-messenger
- **Parent Project:** https://github.com/nocdem/qgp
- **Server:** ai.cpunk.io:5432
- **Roadmap:** [ROADMAP.md](./ROADMAP.md)
- **Development Guide:** [CLAUDE.md](./CLAUDE.md)
- **cpunk.io:** https://cpunk.io
- **cpunk.club:** https://cpunk.club

### About cpunk

cpunk is the **world's first meme coin** on the Cellframe Network. CF20 wallet integration (Phase 8+) will enable payment operations directly within DNA Messenger, allowing users to send/receive cpunk tokens for services, tips, and peer-to-peer transactions on the cpunk network.

---

⚠️ **Warning:** Alpha software. Do not use for sensitive communications yet.
