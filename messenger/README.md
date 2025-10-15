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
sudo apt install cmake gcc libssl-dev libpq-dev qt5-default

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

## How to Use

### GUI Version

1. **Launch** the app - auto-detects your identity from `~/.dna/`
2. **Select a contact** from the left panel
3. **Type and send** messages - encrypted automatically
4. **Customize** via Settings menu (themes, font sizes)
5. **Update** via Help menu → Check for Updates

### CLI Version

```
First run: Create new identity or restore from 24-word recovery phrase

Main menu:
1. Send message              - Encrypt and send to recipient
2. List inbox               - View received messages
3. Read message             - Decrypt and display
4. List sent messages       - View your sent messages
5. List keyserver           - See all users
6. Check for updates        - Update to latest version
7. Logout
```

## Roadmap

### ✅ Completed

- **Phase 1:** Foundation (forked from QGP)
- **Phase 2:** Library API (memory-based encryption)
- **Phase 3:** CLI Messenger (PostgreSQL storage, BIP39 recovery)
- **Phase 5:** Desktop GUI (Qt5, themes, auto-updates, font scaling)

### 🚧 In Progress

- **Phase 4:** Network Layer (WebSocket transport, P2P discovery, offline queue)

### 📋 Planned

- **Phase 6:** Mobile Apps (Flutter for iOS/Android)
- **Phase 7:** Advanced Features (forward secrecy, multi-device sync, group messaging)

## Features

**Current:**
- ✅ End-to-end encryption with post-quantum algorithms
- ✅ Multi-recipient messaging (group messages)
- ✅ 24-word BIP39 recovery phrases
- ✅ Cross-platform (Linux & Windows)
- ✅ Shared keyserver at ai.cpunk.io
- ✅ Auto-update mechanism
- ✅ Theme switching (cpunk.io cyan / cpunk.club orange)
- ✅ Dynamic font scaling (1x - 4x)

**Coming Soon:**
- 🚧 Real-time WebSocket messaging
- 🚧 P2P message routing
- 📋 Forward secrecy (ephemeral session keys)
- 📋 Multi-device synchronization
- 📋 Mobile applications

## Architecture

**Components:**
- Client application (GUI or CLI)
- Shared PostgreSQL server (ai.cpunk.io:5432)
- Keyserver for public key distribution
- Your private keys stay on your device (`~/.dna/`)

**Security:**
- Messages encrypted on your device before sending
- Only recipient can decrypt (end-to-end encryption)
- Server only stores encrypted ciphertext
- Post-quantum algorithms protect against quantum computers

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

---

⚠️ **Warning:** Alpha software. Do not use for sensitive communications yet.
