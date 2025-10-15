# DNA Messenger

**Post-quantum encrypted messaging platform**

DNA Messenger is a secure messaging system using post-quantum cryptographic algorithms (Kyber512 + Dilithium3) that remain secure even against future quantum computer attacks.

## Status

🚧 **Alpha Development**

**Version:** 0.1.x (x = git commit count)
- **Major:** 0 (Alpha - breaking changes expected)
- **Minor:** 1 (Current feature set)
- **Patch:** Auto-incremented with each commit

**Working Features:**
- ✅ End-to-end encryption with post-quantum algorithms
- ✅ Qt5 graphical interface (Windows & Linux)
- ✅ Multi-recipient messaging (group messages)
- ✅ 24-word BIP39 recovery phrases for key backup
- ✅ Cross-platform (Linux & Windows)
- ✅ Shared keyserver at ai.cpunk.io
- ✅ Auto-update mechanism

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
./dna_messenger_gui

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

### First Run

```
1. Create new identity
   - Choose a username
   - Write down your 24-word recovery phrase
   - Keys uploaded to ai.cpunk.io

2. Send a message
   - Enter recipient username
   - Type your message
   - Message encrypted and sent

3. Read messages
   - List your inbox
   - Messages decrypted locally
```

## How It Works

**Architecture:**
- Client application (this program)
- Shared PostgreSQL server (ai.cpunk.io:5432)
- Your private keys stay on your device

**Security:**
- Messages encrypted on your device before sending
- Only recipient can decrypt (end-to-end encryption)
- Server only stores encrypted ciphertext
- Post-quantum algorithms protect against quantum computers

**Key Management:**
- Private keys: `~/.dna/` (never leave your computer)
- Public keys: Shared keyserver (ai.cpunk.io)
- Recovery: 24-word BIP39 mnemonic phrase

## Commands

```
1. Create new identity       - Generate new keys
2. Restore from seed phrase  - Recover keys from backup
3. Lookup identity          - Find user on keyserver
4. Configure server         - Change server (default: ai.cpunk.io)
5. Exit

After login:
- Send message              - Encrypt and send
- List inbox               - View received messages
- Read message             - Decrypt and display
- List sent messages       - View sent messages
- List keyserver           - See all users
- Check for updates        - Update to latest version
```

## Cryptography

- **Key Encapsulation:** Kyber512 (NIST PQC)
- **Signatures:** Dilithium3 (NIST FIPS 204)
- **Symmetric:** AES-256-GCM
- **Key Derivation:** PBKDF2-HMAC-SHA512

## Recovery

**Backup Your Keys:**
1. Write down your 24-word recovery phrase
2. Store it safely (never digitally)
3. Optional: Add passphrase for extra security

**Restore Your Keys:**
1. Choose "Restore from seed phrase"
2. Enter your 24 words
3. Keys regenerated and verified against server

## Development

**Current Phase:** Phase 4 - Network Layer

**Roadmap:**
- Phase 1: Foundation ✅ Complete
- Phase 2: Library API ✅ Complete
- Phase 3: CLI Messenger ✅ Complete
- Phase 4: Network Layer 🚧 In Progress
- Phase 5: Desktop GUI (Qt) ✅ Complete
- Phase 6: Mobile Apps (Flutter) - Future

**Contributing:**
- Fork the repository
- See CLAUDE.md for development guidelines
- All crypto must use post-quantum algorithms

## License

GNU General Public License v3.0

Forked from [QGP (Quantum Good Privacy)](https://github.com/nocdem/qgp)

## Links

- **GitHub:** https://github.com/nocdem/dna-messenger
- **Parent Project:** https://github.com/nocdem/qgp
- **Server:** ai.cpunk.io:5432

---

⚠️ **Warning:** Alpha software. Do not use for sensitive communications yet.
