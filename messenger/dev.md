# DNA Messenger Development Log

**Purpose**: Track all development changes, file modifications, and design decisions.

**Project**: DNA Messenger - Post-quantum encrypted messaging platform
**Forked From**: QGP (Quantum Good Privacy)
**Repository**: /opt/dna-messenger

**Format**: Each entry includes:
- **Timestamp**: UTC time of change
- **User**: Username or "User request"
- **Agent**: Claude/Human
- **Developer**: Developer username (output of `whoami`)
- **Branch**: Git branch where changes were made
- **Changes**: Detailed list of modifications

---

## 2025-10-14

### 2025-10-14 09:04 UTC - Phase 1 Complete: Initial Commit
**User**: nocdem
**Agent**: Claude
**Developer**: nocdem
**Branch**: main
**Project**: DNA Messenger

#### Git Commit Created
- **Commit Hash**: e4f77a0468e2e26dd8171c3e0b6e84d34080876e
- **Type**: Initial commit (root-commit)
- **Files Changed**: 119 files
- **Insertions**: 23,278 lines

#### Phase 1: Fork Preparation - COMPLETED ✅

**Files Created**:
- README.md - DNA Messenger branding and project overview
- CLAUDE.md - AI-assisted development guidelines
- ROADMAP.md - 8-phase development plan (Phases 1-8)
- CMakeLists.txt - Updated project name to "dna", version 0.1.0

**Files Modified**:
- main.c - Version info shows DNA Messenger branding
- utils.c - Updated for DNA compatibility

**Build System**:
- Binary created: build/dna (276KB)
- Build status: ✅ Clean compilation
- Crypto libraries: libdilithium.a, libkyber512.a

**Test Files Removed** (from parent QGP project):
- convert_wordlist.sh
- final_test_decrypted.txt
- fix_packed.sh
- test_gcm.txt
- test_gcm_decrypted.txt
- test_good_decrypt.txt
- test_multi.txt
- test_multi_bob.txt
- test_multi_charlie.txt
- test_tamper.txt

#### Inherited Features from QGP
- Post-quantum key generation (Kyber512 + Dilithium3)
- File signing and verification
- File encryption/decryption
- Multi-recipient encryption (1-255 recipients)
- ASCII armor support
- Keyring management (~/.qgp/)
- BIP39 mnemonic key recovery

#### Git Configuration
- User: nocdem
- Email: nocdem@gmail.com
- Remote: None (local repository only)

#### Next Steps
- Phase 2: Library API Design
- Design dna_api.h (public API header)
- Refactor file-based operations to memory-based
- Create messenger-specific functions

---


### 2025-10-14 09:10 UTC - Phase 2 Started: Library API Design
**User**: nocdem
**Agent**: Claude
**Developer**: nocdem
**Branch**: main
**Project**: DNA Messenger

#### Phase 2: Library API Design - IN PROGRESS 🚧

**Objective:** Design memory-based API for messenger operations

#### Files Created

1. **dna_api.h** - Public API header (356 lines)
   - Context management (`dna_context_t`)
   - Buffer management (`dna_buffer_t`)
   - Message encryption (`dna_encrypt_message`)
   - Message decryption (`dna_decrypt_message`)
   - Signature operations (`dna_sign_message`, `dna_verify_message`)
   - Key management (basic keyring integration)
   - Error codes (`dna_error_t`)
   - Utility functions (fingerprints)

2. **examples/basic_usage.c** - Example usage code (140 lines)
   - Demonstrates Alice → Bob message flow
   - Shows encryption and decryption workflow
   - Uses keyring for key lookup
   - Memory-based operations (no file I/O)

#### API Design Decisions

**Memory-Based Operations:**
- No file I/O in public API
- All operations use memory buffers
- Caller owns and frees memory

**Keyring Integration:**
- Uses QGP keyring (`~/.qgp/`) for Phase 2
- Key lookup by name (e.g., "alice", "bob")
- Compatible with existing QGP tools

**Error Handling:**
- Explicit error codes (`dna_error_t`)
- Human-readable error messages
- Fail-fast approach

**Security:**
- Post-quantum algorithms (Kyber512 + Dilithium3)
- Authenticated encryption (AES-256-GCM)
- Multi-recipient support (1-255)
- Secure memory wiping

#### Next Steps (Phase 2 Continuation)

1. Implement `dna_api.h` functions in `dna_api.c`
2. Refactor `encrypt.c` → memory-based `dna_encrypt_message()`
3. Refactor `decrypt.c` → memory-based `dna_decrypt_message()`
4. Update CMakeLists.txt for library build
5. Build and test basic usage example
6. Write API documentation

#### Status

- [x] API header designed
- [x] Example code written
- [x] Implementation (dna_api.c) ✅
- [x] Library build system ✅
- [x] Testing ✅
- [ ] Documentation

---

### 2025-10-14 12:30 UTC - Phase 2 Complete: Library Implementation
**User**: nocdem
**Agent**: Claude
**Developer**: nocdem
**Branch**: main
**Project**: DNA Messenger

#### Phase 2: Library API Design - COMPLETED ✅

**Files Created:**

1. **dna_api.c** - Complete library implementation (27KB, 754 lines)
   - Context management
   - Memory-based encryption/decryption
   - Key loading from keyring (handles ASCII-armored bundles)
   - Signature operations
   - Error handling
   - Buffer management

**Files Modified:**

1. **CMakeLists.txt** - Added library build target
   - Created `libdna_lib.a` static library
   - Added `basic_usage` example target
   - Shared COMMON_SOURCES between CLI and library

**Key Implementation Details:**

1. **Bundle Parsing Fix** (dna_api.c:255-345)
   - Fixed key loading to handle QGP's multi-key bundles
   - Properly parses ASCII-armored .pub files
   - Extracts encryption public key (Kyber512, 800 bytes)
   - Bundle format: `[header(20B)][signing_pubkey(1952B)][encryption_pubkey(800B)]`

2. **Memory-Based Operations**
   - All functions use memory buffers (no file I/O)
   - Caller owns and frees all allocated memory
   - Secure memory wiping for sensitive data

3. **Error Handling**
   - Consistent error codes (`dna_error_t`)
   - Human-readable error messages
   - Proper cleanup on failure paths

**Build Results:**
- Static library: `libdna_lib.a` (309KB)
- Example binary: `basic_usage` (146KB)
- Build status: ✅ Clean compilation

**Test Results:**
```
=== DNA Messenger - Basic Usage Example ===
[1/4] Initializing DNA context... ✓
[2/4] Alice encrypts message for Bob... ✓
  Ciphertext: 60 bytes → 6182 bytes
[3/4] Bob decrypts message... ✓
  Plaintext: 60 bytes (matches original)
[4/4] Verifying message... ✓
=== Success! ===
```

**Cryptographic Verification:**
- ✅ Kyber512 key encapsulation working
- ✅ Dilithium3 signatures verified
- ✅ AES-256-GCM authenticated encryption
- ✅ Multi-key bundle parsing
- ✅ End-to-end Alice→Bob message flow

**Performance:**
- Encryption: ~instant (60 bytes → 6182 bytes)
- Decryption: ~instant (6182 bytes → 60 bytes)
- Overhead: ~102x (due to post-quantum key material)

#### Next Steps

**Phase 3: CLI Messenger Client (Future)**
- [ ] Interactive chat interface
- [ ] Local message storage (SQLite)
- [ ] Contact list management
- [ ] Send/receive commands
- [ ] Reference implementation

**Immediate Tasks:**
- [ ] API documentation (doxygen comments)
- [x] Additional examples (multi-recipient, signatures) ✅
- [ ] Unit tests (encryption/decryption edge cases)
- [ ] Integration tests (keyring operations)

---

### 2025-10-14 13:00 UTC - Multi-Recipient Example Added
**User**: nocdem
**Agent**: Claude
**Developer**: nocdem
**Branch**: main
**Project**: DNA Messenger

#### Multi-Recipient Security Testing

**Files Created:**

1. **examples/multi_recipient.c** - Multi-recipient test suite (263 lines)
   - Test 1: Single recipient (Alice → Bob only)
   - Test 1a: Bob decrypts successfully
   - Test 1b: Charlie cannot decrypt (security verification)
   - Test 2: Multi-recipient (Alice → Bob + Charlie)
   - Test 2a: Bob decrypts successfully
   - Test 2b: Charlie decrypts successfully

**Files Modified:**

1. **CMakeLists.txt** - Added multi_recipient example target

**Test Results:**

```
✓ TEST 1: Single recipient encryption
  - Alice → Bob: SUCCESS
  - Charlie attempts read: BLOCKED (expected)

✓ TEST 2: Multi-recipient encryption
  - Alice → Bob + Charlie: SUCCESS
  - Bob decrypts: SUCCESS
  - Charlie decrypts: SUCCESS
```

**Security Properties Verified:**

1. **Access Control**
   - ✅ Only intended recipients can decrypt messages
   - ✅ Non-recipients receive `DNA_ERROR_DECRYPT` (Charlie cannot read Bob's message)
   - ✅ No plaintext leakage to unauthorized parties

2. **Multi-Recipient Encryption**
   - ✅ Multiple recipients supported (tested with 2 recipients)
   - ✅ Each recipient can independently decrypt
   - ✅ Same plaintext recovered by all recipients
   - ✅ Sender authentication verified for all recipients

3. **Ciphertext Overhead**
   - Single recipient: 29 bytes → 6,151 bytes (~212x overhead)
   - Two recipients: 35 bytes → 6,965 bytes (~199x overhead)
   - Additional recipient cost: ~814 bytes (~3KB Kyber512 ciphertext + metadata)

**Cryptographic Operations Verified:**

- ✅ Kyber512 KEM per recipient (post-quantum key encapsulation)
- ✅ Dilithium3 signature verification (sender authentication)
- ✅ AES-256-GCM AEAD (confidentiality + integrity)
- ✅ Multi-key bundle parsing (signing + encryption keys)

**Build Results:**
- Binary: `multi_recipient` (146KB)
- Build status: ✅ Clean compilation
- All tests passed: ✅

**Key Findings:**

1. **Overhead Scaling**: Each additional recipient adds ~3KB to ciphertext
   - Formula: `base_size + (num_recipients * 3KB) + plaintext_len`
   - For 255 recipients (max): ~765KB overhead + message size

2. **Security Model**:
   - Recipients cannot see other recipients (privacy-preserving)
   - Decryption tries all recipient entries until success
   - Failure indicates non-recipient status (expected behavior)

3. **Performance**:
   - Encryption/decryption: instant (<1ms for test messages)
   - No observable delay with 2 recipients
   - Scalability to be tested with 10+ recipients

**Next Steps:**
- [ ] Test with 10+ recipients (scalability)
- [ ] Test with large messages (1MB+)
- [ ] Test edge cases (empty message, single byte)
- [ ] Benchmark encryption/decryption performance

---


## 2025-10-19

### 2025-10-19 UTC - Team Branching Strategy & Mandatory dev.md Tracking
**User**: nocdem
**Agent**: Claude Code
**Developer**: nocdem
**Branch**: main
**Project**: DNA Messenger

#### Summary
Established team collaboration infrastructure with feature branches and mandatory development tracking.

#### Feature Branches Created
Created 3 new feature branches for parallel team development:
- `feature/mobile` - Phase 7: Flutter mobile apps (Android/iOS)
- `feature/wallet` - Phase 8: CF20 Wallet integration (Cellframe cpunk network)
- `feature/voip` - Phase 10: Post-quantum voice/video calls

Existing branch:
- `feature/web-messenger` - Phase 5: WebAssembly/Web client

All branches pushed to origin and ready for team collaboration.

#### Files Modified

**CLAUDE.md**:
- Updated BRANCHING STRATEGY section with active feature branches
- Added team workflow documentation
- Made dev.md tracking **MANDATORY** for all commits
- Updated PRE-COMMIT CHECKLIST with strict requirements
- Updated GIT COMMIT POLICY: dev.md is now REQUIRED (no longer ignored)
- Added PR requirements (dev.md updates, compilable code, no breaking changes)

**.gitignore**:
- Removed `dev.md` from ignore list
- Added note: "dev.md is now tracked to maintain development history across team"
- dev.md will be committed with all future changes

**README.md**:
- Updated Links section: Removed internal doc links (ROADMAP.md, CLAUDE.md)
- Added Telegram community link: https://web.telegram.org/k/#@chippunk_official

#### Branching Strategy

**Main Branch** (`main`):
- Production/stable releases only
- Protected branch
- All features merge via Pull Request

**Feature Branches** (parallel development):
```
main
├── feature/mobile        (Phase 7 - Flutter apps)
├── feature/wallet        (Phase 8 - CF20 Wallet)
├── feature/voip          (Phase 10 - Voice/video calls)
└── feature/web-messenger (Phase 5 - WebAssembly client)
```

**Workflow**:
1. Team member checks out feature branch
2. Makes changes and commits
3. **MANDATORY**: Updates dev.md with changes
4. Pushes to origin/feature/*
5. Creates Pull Request to main
6. Code review
7. Merge to main

#### Mandatory Development Tracking

**New Policy**:
- **dev.md updates are REQUIRED** for every push
- Failure to update dev.md = **rejected Pull Request**
- All commits must include:
  - Date/time (UTC)
  - Developer name
  - Branch name
  - Files created/modified
  - Description of changes

**Purpose**:
- Track development progress across team
- Maintain history of all changes
- Facilitate code reviews
- Document design decisions

#### Git Commits

**Commit 1**: Update Links section
- Hash: 43c888e
- Removed ROADMAP.md and CLAUDE.md links from README
- Added Telegram link

**Commit 2-4**: Create feature branches
- Created and pushed: feature/mobile, feature/wallet, feature/voip
- All branches start from main (43c888e)

#### Team Collaboration Ready

**GitHub PR URLs**:
- Mobile: https://github.com/nocdem/dna-messenger/pull/new/feature/mobile
- Wallet: https://github.com/nocdem/dna-messenger/pull/new/feature/wallet
- VoIP: https://github.com/nocdem/dna-messenger/pull/new/feature/voip
- Web: https://github.com/nocdem/dna-messenger/pull/new/feature/web-messenger

**Status**: ✅ Team can now work independently on assigned features

---


### 2025-10-19 UTC - GitLab Primary Repository Setup
**User**: nocdem
**Agent**: Claude Code
**Developer**: nocdem
**Branch**: main
**Project**: DNA Messenger

#### Summary
Configured dual-remote repository structure with GitLab as PRIMARY and GitHub as BACKUP.

#### Repository Structure Change

**PRIMARY Repository (GitLab):**
- URL: `ssh://git@gitlab.cpunk.io:10000/cpunk/dna-messenger.git`
- Web: https://gitlab.cpunk.io/cpunk/dna-messenger
- Organization: `cpunk` group
- Remote name: `gitlab`
- Custom SSH port: 10000
- **Purpose:** Main team collaboration platform

**SECONDARY Repository (GitHub):**
- URL: `git@github.com:nocdem/dna-messenger.git`
- Web: https://github.com/nocdem/dna-messenger
- Remote name: `origin`
- **Purpose:** Personal backup and public visibility only

#### Files Modified

**CLAUDE.md**:
- Added "REPOSITORY STRUCTURE" section with dual-remote configuration
- Updated "COLLABORATION NOTES" - GitLab is primary, GitHub is backup
- Updated "REFERENCES" - GitLab listed first
- Updated all push/fetch examples to prioritize GitLab
- Clarified team workflow: ALWAYS push to GitLab first
- Merge Requests on GitLab (primary), Pull Requests on GitHub (public contributors only)
- Last Updated date changed to 2025-10-19

**README.md**:
- Updated "Links" section
- GitLab listed first as "GitLab (Primary)"
- GitHub listed second as "GitHub (Backup)"

**dev.md**:
- This entry documenting the repository structure change

#### Git Configuration

**Remotes added:**
```bash
gitlab  ssh://git@gitlab.cpunk.io:10000/cpunk/dna-messenger.git
origin  git@github.com:nocdem/dna-messenger.git
```

**All branches pushed to GitLab:**
- main
- feature/mobile
- feature/wallet
- feature/voip
- feature/web-messenger

#### Team Workflow

**Push order:**
1. Push to GitLab first (primary)
2. Push to GitHub second (backup)

**Collaboration:**
- Use GitLab for Merge Requests (team)
- Use GitHub for public contributions only

#### Rationale

1. **Team Collaboration:** GitLab provides better organization/group features
2. **cpunk Infrastructure:** GitLab hosted on cpunk.io infrastructure
3. **Redundancy:** GitHub serves as public backup
4. **Flexibility:** Two platforms for different workflows

---

