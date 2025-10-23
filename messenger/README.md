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

⚠️ **Important Notes:**
- Pre-built binaries available via GitLab CI/CD artifacts (see below)
- Build instructions may be slightly outdated - we iterate rapidly
- **Windows builds are complex** and may take significant time to set up for local development

### Pre-Built Binaries

Binaries from the latest builds are available on GitLab CI/CD artifacts:
- **Download:** https://gitlab.cpunk.io/cpunk/dna-messenger/-/artifacts

Available platforms:
- **Linux x86_64:** CLI and GUI binaries
- **Linux ARM64:** CLI and GUI binaries
- **Windows x64:** CLI and GUI executables (statically linked)

Note: Builds are generated on every push to main branch.

### Automated Installation Scripts (Recommended)

**For Linux (Easy - One Command):**
```bash
# Download and run the install script
curl -sSL https://raw.githubusercontent.com/nocdem/dna-messenger/main/install.sh | bash

# Or if already cloned:
cd dna-messenger
./install.sh
```

The `install.sh` script will:
- Auto-detect your Linux distribution (Ubuntu/Debian, Fedora, Arch)
- Install all required dependencies
- Clone or update the repository
- Build from scratch
- Show you where the binaries are located

**For Windows (Cross-Compilation from Linux):**

Windows builds are now created via cross-compilation using MXE (M cross environment).

Prerequisites (Linux system):
- MXE cross-compilation environment

```bash
# Install or clone MXE (one time setup - takes 1-2 hours)
git clone https://github.com/mxe/mxe.git ~/.cache/mxe
# Or install to /opt/buildtools/mxe

# Build for Windows
./build-cross-compile.sh windows-x64

# Binaries will be in dist/windows-x64/
```

⏱️ **First run may take 1-2 hours** for MXE dependency compilation

### Linux (Manual Build from Source)

```bash
# Install dependencies
sudo apt install cmake gcc libssl-dev libpq-dev libcurl4-openssl-dev qtbase5-dev qtmultimedia5-dev

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

### Windows (Cross-Compilation from Linux)

⚠️ **Windows builds are now cross-compiled from Linux using MXE.**
Native Windows builds with vcpkg are no longer supported.

**Prerequisites:**
- Linux build environment (native or WSL2)
- MXE (M cross environment) installed

**Build Steps:**
```bash
# Clone repository
git clone https://github.com/nocdem/dna-messenger.git
cd dna-messenger

# Set MXE directory (if not in default location)
export MXE_DIR=/path/to/mxe  # e.g., /opt/buildtools/mxe or ~/.cache/mxe

# Build for Windows
./build-cross-compile.sh windows-x64

# Output:
# - dist/dna-messenger-VERSION-windows-x64.zip
# - build-release/windows-x64/dna_messenger.exe (CLI)
# - build-release/windows-x64/gui/dna_messenger_gui.exe (GUI)
```

**MXE Setup (First Time Only):**
```bash
# Clone MXE
git clone https://github.com/mxe/mxe.git ~/.cache/mxe
cd ~/.cache/mxe

# Build dependencies (takes 1-2 hours on first run)
make MXE_TARGETS=x86_64-w64-mingw32.static qtbase qtmultimedia postgresql openssl json-c curl -j$(nproc)
```

**Tip:** Wait for official Windows installer releases if you're not comfortable with cross-compilation.

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
- ✅ cpunk Wallet integration (view balances, send/receive CPUNK/CELL/KEL tokens)

**Coming Soon:**
- 🚧 Web-based messenger (Phase 5 - in progress)
- 📋 Mobile applications (Flutter)
- 📋 Forward secrecy (ephemeral session keys)
- 📋 Post-quantum voice/video calls

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
- **cpunk Wallet integration (COMPLETE)**
  - View CPUNK, CELL, and KEL token balances
  - Send tokens with transaction builder
  - Receive tokens with QR codes and wallet addresses
  - Transaction history with color-coded status
  - Theme-aware wallet UI
  - Direct integration with Cellframe node RPC

### 🚧 Phase 5: Web-Based Messenger (In Progress - branch: feature/web-messenger)
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

### ✅ Phase 8: cpunk Wallet Integration (Complete)
- ✅ cpunk Wallet integration for Cellframe Backbone network
  - View CPUNK, CELL, and KEL token balances from Cellframe wallets
  - Send tokens via Cellframe RPC (tx_create, tx_sign, tx_send)
  - Receive tokens with QR code generation
  - Full transaction history with status tracking
  - Color-coded transaction display (green incoming, red outgoing)
  - Theme support across all wallet dialogs
  - Direct integration with local Cellframe node via RPC

### 📋 Phase 9: Advanced Features (Planned)
- Stickers and rich media
- Channels (broadcast mode)
- Tor integration

### 📋 Phase 10: Post-Quantum Voice/Video Calls (Planned)
**Full quantum-safe voice and video calls** with custom architecture:
- **Key Exchange:** Kyber512 via DNA messaging (bypasses WebRTC's quantum-vulnerable DTLS)
- **Signatures:** Dilithium3 for call authentication
- **Media:** SRTP with AES-256-GCM (PQ-derived keys)
- **NAT Traversal:** libnice (ICE/STUN/TURN) reused from Phase 9.1
- **Audio:** Opus codec with PortAudio I/O
- **Video:** VP8/H.264 with camera capture (V4L2/DirectShow)
- **Security:** Forward secrecy, SAS verification, full E2E encryption
- **Timeline:** ~20 weeks (5 months)
- **Design Doc:** `/futuredesign/VOICE-VIDEO-DESIGN.md`

**Key Innovation:** Uses DNA's existing Kyber/Dilithium for signaling + standard SRTP = quantum-safe calls today (no waiting for WebRTC standards)

### 📋 Phase 11: Distributed P2P Architecture (Future Plans)
Transform into fully decentralized serverless messenger:
- **libp2p** (C++) for peer-to-peer networking
- **OpenDHT** or Kad-DHT for distributed storage
- Distributed DHT-based keyserver (no central server)
- Store-and-forward offline message delivery
- **libnice** NAT traversal (ICE/STUN/TURN)
- Multi-device sync via DHT
- SQLite encrypted with DNA's PQ crypto (Kyber512 + AES-256-GCM)
- Zero-knowledge storage (nodes cannot read messages)

**See `/futuredesign/` folder for complete architecture specifications**

**For detailed roadmap, see [ROADMAP.md](./ROADMAP.md)**

## Architecture

**Current (Phase 4):**
- Client application (GUI, CLI, or Web)
- PostgreSQL message storage (ai.cpunk.io:5432)
- Centralized keyserver API for public key distribution
- Your private keys stay on your device (`~/.dna/`)

**Security:**
- Messages encrypted on your device before sending
- Only recipient can decrypt (end-to-end encryption)
- Post-quantum algorithms (Kyber512 + Dilithium3)
- Cryptographically signed messages (tamper-proof)
- Future: P2P transport with libp2p (encrypted multiplexing)

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

- **GitLab (Primary):** https://gitlab.cpunk.io/cpunk/dna-messenger
- **GitHub (Backup):** https://github.com/nocdem/dna-messenger
- **Parent Project:** https://github.com/nocdem/qgp
- **Server:** ai.cpunk.io:5432
- **cpunk.io:** https://cpunk.io
- **cpunk.club:** https://cpunk.club
- **Telegram:** https://web.telegram.org/k/#@chippunk_official

### About cpunk

cpunk is the **world's first meme coin** on the Cellframe Network. DNA Messenger now includes a full cpunk wallet integration (Phase 8 complete), enabling payment operations directly within the app. Users can view balances, send/receive CPUNK, CELL, and KEL tokens for services, tips, and peer-to-peer transactions on the Cellframe Backbone network.

---

⚠️ **Warning:** Alpha software. Do not use for sensitive communications yet.
