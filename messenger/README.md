# DNA Messenger

**Post-quantum encrypted messaging platform**

Secure messaging using **post-quantum cryptography** (Kyber1024 + Dilithium5 - NIST Category 5) that remains secure against future quantum computer attacks.

## Status

🚧 **Alpha Development**

**Version:** 0.1.x (x = git commit count)
- **Major:** 0 (Alpha - breaking changes expected)
- **Minor:** 1 (Current feature set)
- **Patch:** Auto-incremented with each commit

**Primary Application:**
- **GUI:** ImGui desktop application (OpenGL3 + GLFW3) with theme support, wallet integration, and async operations
  - **Active:** `dna_messenger_imgui` (ImGui - modern immediate-mode rendering)
  - **Deprecated:** `dna_messenger_gui` (Qt5 - preserved for reference only)

_Note: CLI messenger is no longer supported. The GUI application provides all functionality._

## Quick Start

⚠️ **Important Notes:**
- Pre-built binaries available via GitLab CI/CD artifacts (see below)
- Build instructions may be slightly outdated - we iterate rapidly
- **Windows builds are complex** and may take significant time to set up for local development

### Pre-Built Binaries

Binaries from the latest builds are available on GitLab CI/CD artifacts:
- **Download:** https://gitlab.cpunk.io/cpunk/dna-messenger/-/artifacts

Available platforms:
- **Linux x86_64:** ImGui GUI (dna_messenger_imgui), DHT bootstrap (persistent_bootstrap)
- **Linux ARM64:** ImGui GUI (dna_messenger_imgui), DHT bootstrap (persistent_bootstrap)
- **Windows x64:** ImGui GUI (dna_messenger_imgui.exe)

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
# Install dependencies (no PostgreSQL required - uses local SQLite)
# Core dependencies:
sudo apt install cmake gcc libssl-dev libsqlite3-dev libcurl4-openssl-dev libopendht-dev

# NAT traversal dependencies (Phase 11):
# libjuice v1.7.0 is built from source automatically (no extra packages needed)

# ImGui dependencies (active GUI):
sudo apt install libglfw3-dev libgl1-mesa-dev libglu1-mesa-dev

# Qt5 dependencies (deprecated GUI, optional):
sudo apt install qtbase5-dev qtmultimedia5-dev

# Build
git clone https://github.com/nocdem/dna-messenger.git
cd dna-messenger
mkdir build && cd build
cmake ..
make

# Run ImGui GUI
./imgui_gui/dna_messenger_imgui

# Optional: Run DHT bootstrap server (for running your own bootstrap node)
./dht/persistent_bootstrap
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
# - build-release/windows-x64/imgui_gui/dna_messenger_imgui.exe
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
- ✅ End-to-end encryption with post-quantum algorithms (Kyber1024 + Dilithium5 - NIST Category 5)
- ✅ Multi-recipient messaging (broadcast to multiple users)
- ✅ Persistent group chats with member management
- ✅ Per-identity contact lists with DHT sync (multi-device support via BIP39)
- ✅ User profiles with DHT storage (display name, bio, avatar, location, website)
- ✅ Avatar system (64x64 PNG upload, Base64 encoding, circular display)
- ✅ Profile cache system (7-day TTL, cache-first architecture)
- ✅ 24-word BIP39 recovery phrases
- ✅ Cross-platform (Linux & Windows)
- ✅ Local SQLite storage (no server required for messages)
- ✅ DHT-based decentralized groups (OpenDHT)
- ✅ Keyserver cache (7-day TTL, local SQLite)
- ✅ Auto-update mechanism
- ✅ Theme switching (cpunk.io cyan / cpunk.club orange)
- ✅ Dynamic font scaling (1x - 4x)
- ✅ Message delivery and read receipts
- ✅ Desktop notifications
- ✅ cpunk Wallet integration (view balances, send/receive CPUNK/CELL/KEL tokens)
- ✅ P2P messaging with DHT-based peer discovery (3 bootstrap nodes)
- ✅ ICE NAT traversal (libnice + STUN, 3-tier fallback: LAN → ICE → DHT queue)
- ✅ Offline message queueing (messages stored in DHT for 7 days)
- ✅ Free DNA name registration (no costs in alpha)
- ✅ DNA Board Alpha (decentralized censorship-resistant wall with community voting)

**Coming Soon:**
- 🚧 Web-based messenger (Phase 5)
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

### ❌ Phase 3: CLI Messenger Client (Removed - 2025-11-05)
_CLI messenger was removed as unmaintained. All functionality is available in the GUI application._

### ✅ Phase 4: Desktop GUI & Wallet Integration (Complete)

**Note:** Originally implemented with Qt5. Migrated to ImGui (2025-11-10). Qt code archived in `legacy-gui/` (deprecated, not maintained).

**GUI Features (Implemented):**
- GUI with contact list and chat area (ImGui)
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
- Theme system (2 themes: DNA cyan, Club orange)
- Font scaling (1x-4x)
- **Group messaging with full UI**

**Wallet Integration (Complete - 2025-10-23):**
- ✅ cpunk Wallet integration for Cellframe Backbone network
  - View CPUNK, CELL, and KEL token balances from Cellframe wallets
  - Send tokens via Cellframe RPC (tx_create, tx_sign, tx_send)
  - Receive tokens with QR code generation
  - Full transaction history with status tracking
  - Color-coded transaction display (green incoming, red outgoing)
  - Theme support across all wallet dialogs
  - Direct integration with local Cellframe node via RPC

### ✅ Phase 5: Distributed P2P Architecture (COMPLETE)
- ✅ **Phase 5.1:** P2P Transport Layer (COMPLETE)
  - OpenDHT integration for peer discovery
  - Direct peer-to-peer messaging via TCP
  - 3 public bootstrap nodes (US/EU)
  - `persistent_bootstrap` binary (Linux only) for running your own DHT bootstrap node

- ✅ **Phase 5.2:** Offline Message Queueing (COMPLETE - Bug Fix: 2025-11-10)
  - DHT-based message storage for offline recipients
  - 7-day message TTL with automatic retrieval
  - Binary serialization with SHA256 keys
  - 2-minute automatic polling in GUI
  - **Critical Bug Fix (2025-11-10):** Fixed queue key mismatch (display names vs fingerprints)

- ✅ **Phase 5.3:** PostgreSQL → SQLite Migration (COMPLETE)
  - Local SQLite message storage (no centralized DB)
  - DHT-based groups with UUID v4 + SHA256 keys
  - Local SQLite cache for offline access
  - Full CRUD operations for groups

- ✅ **Phase 5.4:** DHT-based Keyserver with Signed Reverse Mapping (COMPLETE)
  - Cryptographically signed reverse mappings (fingerprint → identity)
  - Sender identification without pre-added contacts
  - Cross-platform signature verification
  - Prevents identity spoofing attacks

- ✅ **Phase 5.5:** Per-Identity Contact Lists with DHT Sync (COMPLETE)
  - Per-identity SQLite databases (`~/.dna/<identity>_contacts.db`)
  - Automatic migration from global contacts.db
  - DHT synchronization with Kyber1024 self-encryption
  - Dilithium5 signatures for authenticity
  - Multi-device support via BIP39 seed phrase
  - Manual and automatic sync in GUI (10-minute timer)
  - SHA3-512 DHT key derivation for contact list storage

### 🚧 Phase 6: DNA Board - Censorship-Resistant Social Media (In Progress - Alpha)

**Completed (Phase 6.1 - Base System):**
- [x] User profiles with DHT storage (display name, bio, location, website)
- [x] Profile cache system (7-day TTL, cache-first architecture)
- [x] Profile editor screen (edit own profile)
- [x] Contact profile viewer (view others' profiles)
- [x] Wall post backend (`dna_message_wall.c` - 614 lines)
- [x] Wall post GUI screen (`message_wall_screen.cpp` - 291 lines)
- [x] Wall viewing ("Wall" button functional in chat)
- [x] Dilithium5 signatures for wall posts
- [x] 30-day TTL with rotation (100 messages max)

**Completed (Phase 6.2 - Avatar System):**
- [x] Avatar upload with auto-resize (64x64 PNG, 20KB limit)
- [x] Base64 encoding for DHT storage
- [x] OpenGL texture loading (TextureManager singleton)
- [x] Circular avatar clipping (profiles, wall, chat)
- [x] Comment threading (reply-to field, collapsed/expandable UI)
- [x] Thread sorting (forum bump - latest activity first)
- [x] Wall poster identification fix (post_id uses poster fingerprint)

**Completed (Phase 6.3 - Community Voting):**
- [x] Community voting system (thumbs up/down on wall posts)
- [x] Vote backend with Dilithium5 signatures (`dna_wall_votes.c/h` - 650 lines)
- [x] Separate DHT storage per post (SHA256 key derivation)
- [x] One vote per fingerprint enforcement (permanent votes)
- [x] Vote UI with emoji buttons (👍 👎) and real-time counts
- [x] Net score display with color coding (green/red/gray)
- [x] User vote highlighting (blue=upvoted, red=downvoted)

**Next (Phase 6.4):**
- [ ] Profile schema extensions (social links: Telegram, Twitter, GitHub, Discord)
- [ ] Crypto addresses for tipping (BTC, ETH, CPUNK)
- [ ] Feed sorting (Recent, Top, Controversial)

**Note:** Alpha version is FREE with no costs. Full economics and anti-spam measures planned for v1.0.

### 📋 Phase 7: Web-Based Messenger (Planned - branch: feature/web-messenger)
- [x] WebAssembly crypto module (Emscripten compilation)
- [x] DNA API compiled to WASM (dna_wasm.js/wasm)
- [x] JavaScript wrapper functions
- [ ] HTML5/CSS3 responsive UI
- [ ] Browser-based client (no native dependencies)
- [ ] Progressive Web App (PWA) support
- [ ] Cross-browser compatibility (Chrome, Firefox, Safari, Edge)
- [ ] Client-side encryption/decryption
- [ ] IndexedDB for local key storage

### ✅ Phase 11: Decentralized NAT Traversal (COMPLETE - 2025-11-18)
**Full decentralized NAT traversal without relays or signaling servers:**

**Implemented:**
- ✅ libnice integration (ICE RFC5245 compatibility)
- ✅ STUN-based server-reflexive candidate discovery
- ✅ DHT-based ICE candidate exchange (no signaling servers)
- ✅ 3-tier fallback system:
  - **Tier 1**: LAN DHT lookup + Direct TCP connection (fastest)
  - **Tier 2**: ICE NAT traversal via STUN (bypasses NAT)
  - **Tier 3**: DHT offline queue (7-day TTL)
- ✅ Public STUN servers (Google: stun.l.google.com, Cloudflare: stun.cloudflare.com)
- ✅ Automatic candidate gathering on presence registration
- ✅ ICE candidates published to DHT (7-day TTL, SHA3-512 keys)
- ✅ Cross-platform (Linux + Windows via MXE)

**Architecture:**
- No TURN relays (fully decentralized)
- No signaling servers (DHT for candidate exchange)
- Success rate: ~85-90% direct connection
- Fallback: DHT offline queue for remaining cases

**Code:**
- `p2p/transport/transport_ice.{c,h}` (~600 LOC) - ICE transport layer
- `p2p/transport/transport_discovery.c` - Presence registration with ICE candidates
- 3-tier fallback in `p2p_send_message()` - Automatic tier selection

### 📋 Phase 8: Post-Quantum Voice/Video Calls (Planned)
**Full quantum-safe voice and video calls:**
- Kyber1024 via DNA messaging (bypasses WebRTC's quantum-vulnerable DTLS)
- libsrtp2 + AES-256-GCM media encryption
- libopus audio, libvpx/libx264 video
- Timeline: ~20 weeks
- Design: `/futuredesign/VOICE-VIDEO-DESIGN.md`

### 📋 Phase 9+: Future Enhancements (Planned)
**Advanced Features:**
- Stickers and GIFs
- Rich text formatting
- File transfer
- Bots and automation
- Channels (broadcast mode)
- Stories/Status updates

**Infrastructure:**
- Tor integration (metadata protection)
- Bridge to other platforms (Signal, WhatsApp)

**Enterprise:**
- Organization management
- Compliance tools
- Audit logging
- SSO integration

**For detailed roadmap, see [ROADMAP.md](./ROADMAP.md)**

## Architecture

**Current (Post-Migration - Fully Decentralized):**

**Data Storage:**
- **Messages:** Local SQLite database (`~/.dna/messages.db`)
- **Contacts:** Per-identity SQLite databases (`~/.dna/<identity>_contacts.db`)
  - DHT sync with Kyber1024 self-encryption (SHA3-512 key derivation)
  - Multi-device support via BIP39 seed phrase
- **Groups:** DHT-based storage with local SQLite cache (UUID v4 + SHA256 keys)
- **Public Keys:** DHT-based keyserver with local SQLite cache (7-day TTL, SHA3-512 keys)
- **Private Keys:** Local encrypted storage (`~/.dna/`)

**P2P Transport Layer:**
- **Direct Messaging:** TCP connections on port 4001 (when peer online)
- **Offline Queue:** DHT storage with 7-day TTL (when peer offline)
- **Peer Discovery:** OpenDHT with 3 public bootstrap nodes:
  - dna-bootstrap-us-1 (154.38.182.161)
  - dna-bootstrap-eu-1 (164.68.105.227)
  - dna-bootstrap-eu-2 (164.68.116.180)
- **Group Management:** Decentralized DHT storage (no central server)

**Deployment Scripts:**
- `dht/deploy-bootstrap.sh` - Automated bootstrap node deployment
- `dht/monitor-bootstrap.sh` - Health monitoring for bootstrap network

**Security:**
- Messages encrypted on your device before sending
- Only recipient can decrypt (end-to-end encryption)
- Post-quantum algorithms (Kyber1024 + Dilithium5 - NIST Category 5)
- Cryptographically signed messages (tamper-proof)
- No centralized message storage (privacy by design)
- DHT replication for offline message resilience

## Cryptography

- **Key Encapsulation:** Kyber1024 (ML-KEM-1024, FIPS 203) - NIST Category 5
- **Signatures:** Dilithium5 (ML-DSA-87, FIPS 204) - NIST Category 5
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
- **cpunk.io:** https://cpunk.io
- **cpunk.club:** https://cpunk.club
- **Telegram:** https://web.telegram.org/k/#@chippunk_official

### About cpunk

cpunk is the **world's first meme coin** on the Cellframe Network. DNA Messenger now includes a full cpunk wallet integration (Phase 8 complete), enabling payment operations directly within the app. Users can view balances, send/receive CPUNK, CELL, and KEL tokens for services, tips, and peer-to-peer transactions on the Cellframe Backbone network.

---

⚠️ **Warning:** Alpha software. Do not use for sensitive communications yet.
