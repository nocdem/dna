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
2. **Select a contact or group** from the left panel
3. **Type and send** messages - encrypted automatically
4. **Create groups** via ➕ Create Group button
5. **Manage groups** via ⚙️ Group Settings button (when group selected)
6. **Customize** via Settings menu (themes, font sizes)
7. **Update** via Help menu → Check for Updates

### CLI Version

```
First run: Create new identity or restore from 24-word recovery phrase

Main menu:
1. Send message              - Encrypt and send to recipient(s)
2. List inbox               - View received messages
3. Read message             - Decrypt and display
4. List sent messages       - View your sent messages
5. List keyserver           - See all users
6. Create group             - Create new group chat
7. Manage groups            - Add/remove members, settings
8. Check for updates        - Update to latest version
9. Logout
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
- 🚧 Real-time WebSocket messaging
- 🚧 P2P message routing
- 📋 Forward secrecy (ephemeral session keys)
- 📋 Multi-device synchronization
- 📋 Mobile applications (Flutter)
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

### 🚧 Phase 4: Network Layer (In Progress)
- [ ] WebSocket transport
- [ ] P2P discovery
- [ ] Real-time message routing
- [ ] Offline message queue
- [ ] Connection resilience

### ✅ Phase 5: Qt Desktop App (Complete)
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

### 📋 Phase 6: Mobile Apps (Planned)
- Flutter mobile app
- Android and iOS support
- Push notifications
- Background sync
- Biometric authentication

### 📋 Phase 7: Advanced Security (Planned)
- Forward secrecy (session keys)
- Multi-device synchronization
- Secure memory management
- Key verification (QR codes)
- Disappearing messages

### 📋 Phase 8+: Future Enhancements (Planned)
- Voice/video calls (WebRTC)
- Stickers and rich media
- Channels (broadcast mode)
- Decentralized architecture
- Tor integration

**For detailed roadmap, see [ROADMAP.md](./ROADMAP.md)**

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

## Groups

**Create Groups:**
- Click ➕ Create Group button
- Enter group name and description
- Select initial members
- You're automatically added as creator

**Manage Groups:**
- Select group from contact list
- Click ⚙️ Group Settings button
- Edit name/description
- Add/remove members
- Delete group (creator only)
- Leave group (members only)

**Group Messaging:**
- Messages automatically sent to all members
- End-to-end encrypted for each recipient
- Creator marked with 👑 icon
- Full member list visible to all

## License

GNU General Public License v3.0

Forked from [QGP (Quantum Good Privacy)](https://github.com/nocdem/qgp)

## Links

- **GitHub:** https://github.com/nocdem/dna-messenger
- **Parent Project:** https://github.com/nocdem/qgp
- **Server:** ai.cpunk.io:5432
- **Roadmap:** [ROADMAP.md](./ROADMAP.md)
- **Development Guide:** [CLAUDE.md](./CLAUDE.md)

---

⚠️ **Warning:** Alpha software. Do not use for sensitive communications yet.
