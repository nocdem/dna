# CLAUDE.md
## Project: DNA Messenger

**Purpose:** Post-quantum end-to-end encrypted messaging platform

**Forked From:** QGP (Quantum Good Privacy) - file encryption tool

**Implementation:** C library + CLI messenger client with vendored pq-crystals (Dilithium3, Kyber512) + OpenSSL

**Binary Location:** `/opt/dna-messenger/build/dna_messenger`

**Status:** 🚧 IN DEVELOPMENT - Phase 4: Network Layer (v0.1.105-alpha)

---

## PROJECT FOCUS

DNA Messenger is designed for **real-time encrypted messaging**, NOT file operations.

### Key Differences from Parent Project (QGP)

| Aspect | QGP (Parent) | DNA Messenger (This Project) |
|--------|--------------|------------------------------|
| **Purpose** | File encryption tool | Messaging platform |
| **Interface** | CLI only | Library API + CLI + GUI (future) |
| **Operations** | File-based I/O | Memory-based buffers |
| **Storage** | Filesystem (`~/.qgp/`) | Database (PostgreSQL) |
| **Transport** | Manual (email, USB) | Network (WebSocket, P2P, future) |
| **Forward Secrecy** | No | Yes (planned) |
| **Multi-Device** | Manual key copy | Automatic sync (planned) |

---

## CURRENT STATUS

### Phase 1: Fork Preparation ✅ COMPLETE
- [x] Repository forked from QGP
- [x] README.md updated with DNA Messenger branding
- [x] CLAUDE.md created (messenger development guidelines)
- [x] CMakeLists.txt updated (project name, version)
- [x] main.c updated (help text, version info)
- [x] Build verification
- [x] Git repository initialized
- [x] Initial commit created

### Phase 2: Library API ✅ COMPLETE
- [x] Design `dna_api.h` (public API header)
- [x] Implement memory-based encryption/decryption
- [x] Create contact management (keyserver)
- [x] Build keyring integration
- [x] Write API documentation

### Phase 3: CLI Messenger Client ✅ COMPLETE
- [x] Command-line chat interface
- [x] PostgreSQL message storage
- [x] Contact list management
- [x] Message send/receive
- [x] BIP39 mnemonic key generation
- [x] File-based seed phrase restore
- [x] Keyserver verification for restored keys
- [x] Auto-login for existing identities
- [x] Windows support (cross-platform)
- [x] Message deletion
- [x] Message search/filtering

### Phase 4: Network Layer (Future)
- [ ] WebSocket transport
- [ ] P2P discovery
- [ ] Message routing
- [ ] Offline message queue

### Phase 5: Qt Desktop App ✅ COMPLETE
- [x] Qt5 GUI builds (Windows + Linux)
- [x] Main window with contact list and chat area
- [x] Message send functionality
- [x] Load real contacts from keyserver
- [x] Load real conversations from database
- [x] Message decryption (received and sent messages)
- [x] Multi-recipient encryption support
- [x] Sender-as-first-recipient pattern (decrypt own sent messages)
- [x] Auto-update mechanism (Windows batch script)
- [x] Message timestamps display
- [x] Auto-detect local identity from ~/.dna/
- [x] Delivery and read receipts
- [x] Desktop notifications (system tray)
- [x] Theme system (cpunk.io cyan, cpunk.club orange)
- [x] Font scaling (1x-4x)
- [x] Group messaging with full UI (create, manage, send)

### Phase 6-7: Mobile & Advanced Features (Future)
- [ ] Flutter mobile app
- [ ] Forward secrecy (session keys)
- [ ] Multi-device synchronization

---

## DEVELOPMENT PHILOSOPHY

### Simple First, Secure Later

1. **Phase 1-3**: Focus on core functionality
   - Memory-based operations (simple, no complex locking)
   - Basic encryption/decryption
   - Working messenger client

2. **Phase 4+**: Add advanced security
   - Forward secrecy (session keys)
   - Secure memory management (mlock, secure wiping)
   - Multi-device synchronization

**Rationale:** Get a working messenger first, then incrementally add security features.

---

## INHERITED FEATURES FROM QGP

Since DNA Messenger is forked from QGP, it currently has:

- ✅ Post-quantum key generation (Dilithium3, Kyber512)
- ✅ File signing and verification
- ✅ File encryption/decryption
- ✅ Multi-recipient encryption
- ✅ ASCII armor support
- ✅ Keyring management
- ✅ BIP39 mnemonic key recovery
- ✅ AES-256-GCM authenticated encryption

**Note:** File operations will be adapted for messenger use (memory-based).

---

## PROTOCOL MODE RULES

Same as parent project (QGP), with messenger-specific additions:

### Core Principles
1. **No Assumptions**: Never assume missing information
2. **No Dummy Data**: Never use placeholders
3. **No Invention**: All outputs based on verified sources
4. **Tool Reliance**: Use tools to retrieve data
5. **Verification Required**: Every statement traceable

### Cryptographic Requirements
6. **No Custom Crypto**: Use only documented functions
7. **SDK Source Verification**: Consult source before crypto operations
8. **Key Security**: Never log or expose private keys
9. **Round-Trip Testing**: Every crypto operation verified
10. **Error Protocol**: Crypto failures halt execution

### Messenger-Specific Rules
11. **Memory-Based First**: Prioritize memory operations over file I/O
12. **Simple Security Initially**: No complex memory locking in early phases
13. **API-First Design**: All features accessible via library API
14. **Network-Ready**: Design for future network transport

---

## GIT COMMIT POLICY

### Files to Commit
✅ Source code (`.c`, `.h`)
✅ Build configuration (`CMakeLists.txt`)
✅ Scripts (`.sh`, `.py`)
✅ Required data files

### Files NOT to Commit (unless explicitly requested)
❌ `dev.md` - Development log (in .gitignore)
❌ `*.md` files - Documentation (local only)
❌ Build artifacts (`build/`)

**Exception:** User explicitly requests documentation commit

---

## DEVELOPMENT LOG FORMAT

**Location:** `dev.md` (in .gitignore, local only)

**Entry Template:**
```markdown
### YYYY-MM-DD HH:MM UTC - Brief Description
**User**: [username]
**Agent**: [Claude/Human]
**Developer**: [output of `whoami`]
**Branch**: [git branch --show-current]
**Project**: DNA Messenger

#### Files Created
- filename.ext - Description

#### Files Modified
- filename.ext - Changes made

#### Other Changes
- Description
```

---

## PRE-COMMIT CHECKLIST

Before every git commit:
- [ ] dev.md updated with change log
- [ ] CLAUDE.md status updated (local only)
- [ ] ROADMAP.md updated if phases change (local only)
- [ ] README.md updated if user-facing changes (local only)
- [ ] All tests passing
- [ ] No debug code remaining
- [ ] Only commit source + required files

---

## BRANCHING STRATEGY

- `main` - Stable releases only
- `develop` - Integration branch
- `feature/*` - New features
- `bugfix/*` - Bug fixes
- `docs/*` - Documentation updates

**Current Branch:** `main` (initial fork)

---

## FILE STRUCTURE

```
/opt/dna-messenger/
├── *.c (source files)
├── *.h (header files)
├── crypto/ (vendored pq-crystals)
├── build/ (binary: dna)
├── docs/ (documentation)
├── examples/ (integration examples, future)
├── CMakeLists.txt (build config)
├── README.md (project overview)
├── CLAUDE.md (this file)
├── ROADMAP.md (development plan)
└── LICENSE (GPL-3.0)
```

---

## TESTING REQUIREMENTS

### Phase 1-2 (Library API)
- **Message Encryption**: Encrypt → Decrypt → Match original
- **Signature Verification**: Sign → Verify → Valid
- **API Stability**: Functions don't crash on invalid input
- **Memory Management**: No leaks (valgrind clean)

### Phase 3+ (Messenger Client)
- **End-to-End**: Alice → Bob message delivery
- **Persistence**: Messages survive application restart
- **Multi-Device**: Same identity works on different machines
- **Network Resilience**: Handle disconnections gracefully

---

## CRYPTOGRAPHIC ALGORITHMS

**Inherited from QGP:**
- **Key Encapsulation:** Kyber512 (NIST PQC Level 1)
- **Signatures:** Dilithium3 (ML-DSA-65, FIPS 204)
- **Symmetric Encryption:** AES-256-GCM (AEAD)
- **Key Derivation:** PBKDF2-HMAC-SHA512

**Future Additions:**
- **Forward Secrecy:** Ephemeral session keys (Phase 4+)
- **Key Agreement:** X3DH-style prekeys (Phase 5+)

---

## API DESIGN PRINCIPLES

### Phase 2: Library API

**Goals:**
- Memory-based operations (no files)
- Simple error handling
- Thread-safe (future)
- Embeddable in any application

**Example API:**
```c
// Context management
dna_context_t* dna_context_new(void);
void dna_context_free(dna_context_t *ctx);

// Message encryption
dna_error_t dna_encrypt_message(
    dna_context_t *ctx,
    const uint8_t *plaintext, size_t plaintext_len,
    const uint8_t *recipient_pubkey, size_t pubkey_len,
    const uint8_t *sender_privkey, size_t privkey_len,
    uint8_t **ciphertext_out, size_t *ciphertext_len_out
);

// Message decryption
dna_error_t dna_decrypt_message(
    dna_context_t *ctx,
    const uint8_t *ciphertext, size_t ciphertext_len,
    const uint8_t *recipient_privkey, size_t privkey_len,
    uint8_t **plaintext_out, size_t *plaintext_len_out,
    uint8_t **sender_pubkey_out, size_t *sender_pubkey_len_out
);
```

---

## SECURITY CONSIDERATIONS

### Current Security Model (Inherited from QGP)
- ✅ Post-quantum algorithms (quantum-resistant)
- ✅ Authenticated encryption (AES-GCM)
- ✅ Multi-recipient support
- ✅ Tamper detection

### Future Security Enhancements
- 🔄 Forward secrecy (session keys) - Phase 4+
- 🔄 Secure memory management - Phase 4+
- 🔄 Multi-device sync - Phase 5+
- 🔄 Group messaging - Phase 6+

### NOT Implemented (Out of Scope)
- ❌ Metadata protection (future: Tor integration)
- ❌ Traffic analysis resistance
- ❌ Plausible deniability

---

## NEXT IMMEDIATE TASKS

### Current Phase: Network Layer (Phase 4)

**Phase 5 Completed:**
- ✅ Qt5 GUI with full messaging functionality
- ✅ Cross-platform support (Windows + Linux)
- ✅ Real contact list and conversation loading
- ✅ Multi-recipient encryption with sender-as-first-recipient
- ✅ Message persistence and decryption
- ✅ Auto-update mechanism
- ✅ Delivery and read receipts
- ✅ Desktop notifications
- ✅ Theme system (2 themes)
- ✅ Font scaling (1x-4x)
- ✅ Full group messaging feature (create, manage members, send messages)

**Phase 4 Tasks:**
1. Design WebSocket protocol for real-time messaging
2. Implement server relay for message delivery
3. Client-server connection management
4. Message routing and delivery confirmation
5. Offline message queue
6. Connection resilience and reconnection logic

**Design Decisions Needed:**
- Centralized relay vs P2P architecture
- Message delivery guarantees (at-most-once, at-least-once, exactly-once)
- Server discovery mechanism
- Authentication protocol for relay servers

### Future Phases

**Phase 6-7: Mobile & Advanced**
1. Flutter mobile app
2. Forward secrecy (session keys)
3. Multi-device synchronization
4. Voice/video calling (future)

---

## COLLABORATION NOTES

**Team:** cpunk-team (group ownership)

**Repository Ownership:**
- User: `nocdem`
- Group: `cpunk-team`
- Location: `/opt/dna-messenger`

**Development Style:**
- AI-assisted development (Claude Code)
- Protocol Mode for crypto operations
- Test-driven when possible
- Incremental feature addition

---

## REFERENCES

- **Parent Project:** QGP - https://github.com/nocdem/qgp
- **pq-crystals:** Kyber and Dilithium implementations
- **OpenSSL:** Cryptographic utilities
- **Signal Protocol:** Inspiration for forward secrecy (future)
- **Matrix Protocol:** Inspiration for decentralized messaging (future)

---

**Last Updated:** 2025-10-15
**Version:** 0.1.105-alpha
**Status:** Phase 4 - Network Layer (Active Development)
**Repository:** `/opt/dna-messenger`

**Recent Changes (v0.1.105):**
- Full group messaging feature (backend + GUI)
- Database migration for groups tables
- Create groups with member selection
- Manage group members (add/remove)
- Group settings (edit name/description, delete/leave)
- Delivery and read receipts with debugging
- Fixed notification system (respects read status)
- Theme system and font scaling improvements
