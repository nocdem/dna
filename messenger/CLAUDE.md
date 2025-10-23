# DNA Messenger - Development Guidelines for Claude AI

**Last Updated:** 2025-10-23
**Project:** DNA Messenger (Post-Quantum Encrypted Messenger)
**Current Phase:** Phase 5 (Web Messenger) - Phase 4 & 8 Complete

---

## Project Overview

DNA Messenger is a post-quantum end-to-end encrypted messaging platform with cpunk wallet integration. It uses Kyber512 for key encapsulation, Dilithium3 for signatures, and AES-256-GCM for symmetric encryption.

**Key Features:**
- End-to-end encrypted messaging
- Group chats with member management
- cpunk wallet integration (CPUNK, CELL, KEL tokens)
- Cross-platform (Linux, Windows)
- Qt5 GUI with theme support
- BIP39 recovery phrases

---

## Current Architecture

### Components
1. **Core Library** (`libdna.a`)
   - Post-quantum cryptography (Kyber512, Dilithium3)
   - Memory-based encryption/decryption API
   - Multi-recipient support

2. **CLI Client** (`dna_messenger`)
   - Command-line interface
   - PostgreSQL message storage
   - Contact management

3. **GUI Client** (`dna_messenger_gui`)
   - Qt5 desktop application
   - Modern card-based UI
   - Theme system (cpunk.io cyan, cpunk.club orange)
   - Integrated wallet with transaction history

4. **Wallet Integration**
   - Cellframe wallet file support (.dwallet format)
   - RPC integration with Cellframe node
   - Transaction builder and signing
   - Balance and history queries

### Directory Structure
```
/opt/dna-messenger/
├── crypto/                  # Cryptography libraries
│   ├── dilithium/          # Dilithium3 signatures
│   └── kyber512/           # Kyber512 key encapsulation
├── gui/                     # Qt5 GUI application
│   ├── MainWindow.*        # Main chat window
│   ├── WalletDialog.*      # Wallet balance & transactions
│   ├── SendTokensDialog.*  # Send tokens form
│   ├── ReceiveDialog.*     # Receive with QR codes
│   ├── TransactionHistoryDialog.* # Full transaction list
│   └── ThemeManager.*      # Global theme management
├── wallet.c/h              # Cellframe wallet integration
├── cellframe_rpc.c/h       # Cellframe RPC client
├── cellframe_tx_builder_minimal.c/h # Transaction builder
├── dna_api.h               # Public library API
└── CMakeLists.txt          # Build configuration
```

---

## Development Guidelines

### 1. Code Style
- **C Code:** Follow existing style (K&R-ish with 4-space indentation)
- **C++ Code (Qt):** Qt coding conventions, camelCase for methods
- **Comments:** Use clear, concise comments for complex logic
- **Memory Management:** Always free allocated memory, check for NULL

### 2. Cryptography
- **DO NOT modify crypto primitives** without expert review
- Use existing API functions from `dna_api.h`
- All encryption/decryption must use memory-based operations
- Never log or print keys or decrypted messages

### 3. Database
- PostgreSQL for message storage (ai.cpunk.io:5432)
- Schema: `messages`, `contacts`, `groups`, `group_members`
- Use prepared statements to prevent SQL injection
- Handle connection failures gracefully

### 4. GUI Development (Qt5)
- Use Qt signals/slots for event handling
- Apply themes via `ThemeManager::instance()`
- All dialogs should be theme-aware
- Use `setAttribute(Qt::WA_DeleteOnClose)` for modal dialogs
- Handle window focus and activation properly

### 5. Wallet Integration
- Read Cellframe wallet files from `~/.dna/` or system wallet dir
- Use `cellframe_rpc.h` API for RPC calls
- All token amounts are strings to preserve precision
- Use smart decimal formatting (8 decimals for tiny amounts)
- Transaction builder uses minimal serialization (no JSON-C in builder)

### 6. Cross-Platform Support
- **Linux:** Primary development platform
- **Windows:** Cross-compile using MXE (M cross environment)
- Use CMake for build configuration
- Avoid platform-specific code when possible
- Test on both platforms before committing

---

## Phase 8: cpunk Wallet Integration (COMPLETE)

**Status:** ✅ Complete (2025-10-23)

### What Was Implemented
1. **WalletDialog** - Main wallet view
   - Card-based token display (CPUNK, CELL, KEL)
   - Balance queries via Cellframe RPC
   - Recent 3 transactions display
   - 4-button layout: Send, Receive, DEX, History

2. **SendTokensDialog** - Send tokens
   - Transaction builder integration
   - UTXO query and selection
   - Network fee handling (0.002 CELL)
   - Dilithium signature generation
   - RPC transaction submission

3. **ReceiveDialog** - Receive tokens
   - Display wallet addresses per network
   - QR code generation
   - Easy copy-to-clipboard

4. **TransactionHistoryDialog** - Full transaction list
   - All transactions with pagination
   - Color-coded arrows (green incoming, red outgoing)
   - Status display (ACCEPTED in green, DECLINED in red)
   - Smart timestamp formatting

5. **ThemeManager** - Global theme system
   - Singleton pattern for theme management
   - Signal-based theme updates
   - Support for cpunk.io (cyan) and cpunk.club (orange)

### Key Technical Decisions
- **No wallet selection in send dialog:** Already in that wallet context
- **Smart decimal formatting:** 8 decimals for tiny amounts, 2 for normal
- **Direct RPC integration:** No external wallet utilities needed
- **Theme-aware:** All wallet dialogs respond to theme changes
- **Transaction builder:** Minimal serialization for cross-platform compatibility

---

## Phase 5: Web Messenger (IN PROGRESS)

**Status:** 🚧 Active development on `feature/web-messenger` branch

### What's Done
- [x] DNA API compiled to WebAssembly (dna_wasm.js/wasm)
- [x] JavaScript wrapper functions
- [x] Emscripten toolchain setup

### What's Next
- [ ] HTML5/CSS3 responsive UI
- [ ] Browser-based messaging interface
- [ ] IndexedDB for key storage
- [ ] Real-time updates (WebSocket)

---

## Phase 10: Post-Quantum Voice/Video Calls (PLANNED)

**Status:** 📋 Research & Planning
**Timeline:** ~20 weeks (5 months)
**Prerequisites:** Phase 9.1 (P2P Transport Layer)

### Overview

DNA Messenger will feature **fully quantum-safe voice and video calls** using a revolutionary approach that bypasses WebRTC's quantum-vulnerable DTLS handshake:

**The Problem:**
- Standard WebRTC uses ECDHE/ECDSA for key exchange (quantum-vulnerable)
- Quantum computers can break the handshake and decrypt media
- IETF post-quantum DTLS standards are 3-5 years away

**DNA's Solution:**
- Use Kyber512 for key exchange via DNA's encrypted messaging
- Use Dilithium3 for call authentication
- Stream media over SRTP with PQ-derived keys
- No quantum-vulnerable components

### Architecture

```
Signaling (DNA Encrypted Channel)
  ↓
  Kyber512 key exchange
  Dilithium3 signatures
  ↓
NAT Traversal (libnice)
  ↓
  ICE/STUN/TURN
  UDP hole punching
  ↓
Media Transport (SRTP)
  ↓
  AES-256-GCM (PQ-derived keys)
  Opus audio / VP8 video
```

### Key Features

**Quantum-Resistant Security:**
- Kyber512 (NIST FIPS 203 / ML-KEM) for key exchange
- Dilithium3 (NIST FIPS 204 / ML-DSA) for signatures
- AES-256-GCM for media encryption
- Forward secrecy (ephemeral keys per call)
- Short Authentication String (SAS) verification

**Media Capabilities:**
- Audio: Opus codec (48kHz, stereo)
- Video: VP8 or H.264 codec
- Adaptive bitrate and resolution
- Network resilience (jitter buffer, FEC)

**Platform Support:**
- Linux: ALSA/PulseAudio + V4L2
- Windows: DirectSound/WASAPI + DirectShow
- macOS: CoreAudio + AVFoundation

### Implementation Phases

1. **Signaling (4 weeks)** - Call invite/accept/reject via DNA messaging
2. **NAT Traversal (4 weeks)** - libnice integration (reuse from Phase 9.1)
3. **Audio Calls (4 weeks)** - libopus + PortAudio + SRTP
4. **Video Calls (4 weeks)** - libvpx/libx264 + camera capture
5. **Polish & Testing (4 weeks)** - Quality tuning, benchmarks, docs

### Technology Stack

- **libnice** - ICE/STUN/TURN (NAT traversal)
- **libsrtp2** - Secure RTP with AES-256-GCM
- **libopus** - Audio codec
- **libvpx** or **libx264** - Video codec
- **PortAudio** - Microphone/speaker I/O
- **V4L2** (Linux) / **DirectShow** (Windows) - Camera capture

### Why This is Better

1. **Full Quantum Resistance** - No quantum-vulnerable components
2. **Uses Existing Crypto** - Same Kyber/Dilithium as messaging
3. **Independent of Standards** - Don't wait for WebRTC PQ support
4. **Better Privacy** - Signaling through DNA's E2E encrypted channel
5. **Forward Secrecy** - Ephemeral keys per call
6. **Available Today** - Can deploy immediately (desktop/mobile)

### Future Enhancements

- Group calls (mesh topology, up to 8 participants)
- Screen sharing (H.264 high-profile)
- Call recording (local only, preserves E2E)
- SFU for large conferences (100+ participants)

### Design Document

Full technical specification: `/futuredesign/VOICE-VIDEO-DESIGN.md`

---

## Common Tasks

### Adding a New Feature
1. Check current phase in ROADMAP.md
2. Follow existing code patterns
3. Update CMakeLists.txt if adding new files
4. Test on Linux first, then Windows
5. Update documentation (README.md, ROADMAP.md)

### Building the Project
**Linux:**
```bash
mkdir build && cd build
cmake ..
make -j$(nproc)
```

**Windows (cross-compile from Linux):**
```bash
./build-cross-compile.sh windows-x64
```

### Running Tests
```bash
# CLI messenger
./build/dna_messenger --help

# GUI messenger
./build/gui/dna_messenger_gui
```

---

## API Documentation

### DNA Core API (`dna_api.h`)
```c
// Context management
dna_context_t* dna_context_new(void);
void dna_context_free(dna_context_t *ctx);

// Encryption
int dna_encrypt_message(
    const uint8_t *plaintext, size_t len,
    const public_key_t *recipient_key,
    dna_buffer_t *output);

// Decryption
int dna_decrypt_message(
    const uint8_t *ciphertext, size_t len,
    const private_key_t *my_key,
    dna_buffer_t *output);
```

### Cellframe RPC API (`cellframe_rpc.h`)
```c
// RPC request structure
typedef struct {
    const char *method;
    const char *subcommand;
    json_object *arguments;
    int id;
} cellframe_rpc_request_t;

// Make RPC call
int cellframe_rpc_call(
    cellframe_rpc_request_t *req,
    cellframe_rpc_response_t **response);

// Free response
void cellframe_rpc_response_free(cellframe_rpc_response_t *resp);
```

### Wallet API (`wallet.h`)
```c
// Load Cellframe wallets
int wallet_list_cellframe(wallet_list_t **list);

// Get wallet address
int wallet_get_address(
    const cellframe_wallet_t *wallet,
    const char *network,
    char *address_out);

// Free wallet list
void wallet_list_free(wallet_list_t *list);
```

---

## Testing Guidelines

### Manual Testing
1. **Messaging:**
   - Send message between two users
   - Verify encryption/decryption
   - Check delivery receipts

2. **Groups:**
   - Create group with multiple members
   - Send messages to group
   - Add/remove members

3. **Wallet:**
   - View balances (should match Cellframe CLI)
   - Send transaction (verify on blockchain explorer)
   - Check transaction history

### Debug Output
- Use `printf("[DEBUG] ...")` for development
- Remove debug output before committing
- Use descriptive prefixes: `[DEBUG TX]`, `[DEBUG RPC]`

---

## Common Issues and Solutions

### Wallet Balance Shows 0.00
- Check Cellframe node is running (port 8079)
- Verify RPC is enabled in Cellframe config
- Check wallet file exists in `~/.dna/` or `/opt/cellframe-node/var/lib/wallet/`

### Transaction Fails to Send
- Ensure sufficient balance + fee
- Check UTXO query returns results
- Verify network fee address is correct
- Check signature is generated correctly

### Theme Not Applied
- Ensure ThemeManager is initialized before dialog
- Connect to `themeChanged` signal
- Call `applyTheme()` in constructor

### Windows Cross-Compile Fails
- Check MXE is installed (`~/.cache/mxe/`)
- Verify MXE dependencies are built
- Check CMake toolchain file path

---

## Security Considerations

### Current Security Model
- Post-quantum encryption (Kyber512 + AES-256-GCM)
- Message signatures (Dilithium3)
- End-to-end encryption (server cannot read)
- Private keys stored locally (`~/.dna/`)

### Known Limitations
- No forward secrecy (planned Phase 7)
- Metadata not protected (server sees sender/receiver)
- No multi-device sync yet
- No disappearing messages

### Best Practices
- Never log private keys or decrypted messages
- Validate all inputs (addresses, amounts, signatures)
- Check return codes from crypto functions
- Use secure memory management (mlock in future)

---

## Git Workflow

### Branching
- `main` - Stable releases
- `feature/*` - New features (e.g., `feature/web-messenger`)
- `fix/*` - Bug fixes

### Commit Messages
```bash
# Good commit message format:
Short summary (50 chars or less)

Detailed explanation if needed:
- What changed
- Why it changed
- Any breaking changes

🤖 Generated with Claude Code
Co-Authored-By: Claude <noreply@anthropic.com>
```

### Before Committing
1. Test on Linux
2. Cross-compile for Windows
3. Remove debug output
4. Update documentation if needed
5. Check for memory leaks (valgrind)

---

## Resources

### Documentation
- **Main README:** `/opt/dna-messenger/README.md`
- **Roadmap:** `/opt/dna-messenger/ROADMAP.md`
- **API Docs:** `/opt/dna-messenger/dna_api.h` (inline comments)

### External Links
- **Cellframe Docs:** https://wiki.cellframe.net
- **Cellframe Dev Wiki:** https://dev-wiki.cellframe.net
- **Qt5 Docs:** https://doc.qt.io/qt-5/
- **Kyber:** https://pq-crystals.org/kyber/
- **Dilithium:** https://pq-crystals.org/dilithium/

### Repositories
- **GitLab (Primary):** https://gitlab.cpunk.io/cpunk/dna-messenger
- **GitHub (Mirror):** https://github.com/nocdem/dna-messenger

---

## Contact and Support

- **cpunk.io:** https://cpunk.io
- **cpunk.club:** https://cpunk.club
- **Telegram:** https://web.telegram.org/k/#@chippunk_official

---

## Version History

| Version | Date | Description |
|---------|------|-------------|
| 0.1.0 | 2025-10-14 | Initial fork from QGP |
| 0.2.0 | 2025-10-15 | Library API complete |
| 0.3.0 | 2025-10-16 | CLI messenger complete |
| 0.4.0 | 2025-10-17 | Desktop GUI with groups |
| 0.8.0 | 2025-10-23 | cpunk Wallet integration |
| 0.5.0 | TBD | Web messenger (in progress) |

**Current Version:** 0.1.120+ (auto-incremented)

---

**Happy Coding!**

When in doubt, check existing code patterns and follow the established conventions. The project prioritizes simplicity, security, and cross-platform compatibility.
