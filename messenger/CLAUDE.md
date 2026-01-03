# DNA Messenger - Development Guidelines for Claude AI

**Last Updated:** 2025-12-31 | **Phase:** 7 (Flutter UI) | **Complete:** 4, 5.1-5.9, 6 (Android SDK), 7.1-7.3 (Flutter Foundation + Core Screens + Full Features), 8, 9.1-9.6, 10.1-10.4, 11, 12, 13, 14 (DHT-Only Messaging)

**Versions:** Library v0.3.71 | Flutter v0.99.27 | Nodus v0.4.3

---

## PROTOCOL MODE
NO STUBS
NO ASSUMPTIONS
NO DUMMY DATA
Source of truth is the sourcecode and documentation
Always ask user what to do if unsure
Anything against protocol mode breaks the blockchain / encryption.

## NO ASSUMPTIONS - INVESTIGATE FIRST
**NEVER assume external libraries or dependencies are buggy without proof.**
- When something doesn't work as expected, investigate the ACTUAL cause
- Check our own code for bugs FIRST before blaming external libraries
- If you suspect an external library issue, find documentation or source code to confirm
- Don't make statements like "X library doesn't work reliably" without evidence
- When uncertain, say "I don't know" and investigate rather than guess

## BUG TRACKING
**ALWAYS check `BUGS.md`** at the start of a session for open bugs to fix.
- Open bugs are marked with `- [ ]`
- Fixed bugs are marked with `- [x]` and include version number
- Add new bugs reported by user to the Open Bugs section
- Mark bugs as fixed with version number when resolved

## FUNCTION REFERENCE
**`docs/FUNCTIONS.md`** is the authoritative source for all function signatures in the codebase.

**ALWAYS check `FUNCTIONS.md` when:**
- Writing new code that calls existing functions
- Modifying existing function signatures
- Debugging issues (to understand available APIs)
- Adding new features (to find relevant functions)

**ALWAYS update `FUNCTIONS.md` when:**
- Adding new functions (public or internal)
- Changing function signatures
- Removing functions
- Adding new header files

**Format:** Each function entry follows table format:
```
| `return_type function_name(params)` | Brief one-line description |
```

**Sections:** Public API → DNA API → Messenger → Crypto → DHT → P2P → Database → Blockchain → Engine

## LOGGING STANDARD
When adding debug/logging to C code, ALWAYS use QGP_LOG macros:
```c
#include "crypto/utils/qgp_log.h"

QGP_LOG_DEBUG(LOG_TAG, "Debug message: %s", variable);
QGP_LOG_INFO(LOG_TAG, "Info message: %d", number);
QGP_LOG_WARN(LOG_TAG, "Warning message");
QGP_LOG_ERROR(LOG_TAG, "Error message: %s", error_str);
```
- **NEVER** use `printf()`, `fprintf()`, or raw `stdout`/`stderr` for logging
- **ALWAYS** define `LOG_TAG` at top of file: `#define LOG_TAG "MODULE_NAME"`
- Log levels: DEBUG < INFO < WARN < ERROR

## ALPHA PROJECT - HARD CUTOFFS ONLY
This project is in ALPHA. We use hard cutoffs for all changes:
- NO backward compatibility
- NO migration scripts
- NO legacy support
- Breaking changes are expected and acceptable

## IMGUI IS DEPRECATED
The ImGui GUI (`imgui_gui/`) is **NO LONGER USED**. Do not modify or reference it.
- **Current UI**: Flutter (`user_interface/`)
- **Ignore**: `imgui_gui/` directory entirely
- All UI work should be done in Flutter only

## FLUTTER ICONS - FONT AWESOME ONLY
**ALWAYS use Font Awesome icons in Flutter code.** Do not use Material Icons.
- **Package**: `font_awesome_flutter` (already in pubspec.yaml)
- **Import**: `import 'package:font_awesome_flutter/font_awesome_flutter.dart';`
- **Widget**: Use `FaIcon(FontAwesomeIcons.xxx)` instead of `Icon(Icons.xxx)`
- **Solid variants**: Use `FontAwesomeIcons.solidXxx` for filled versions
- **Examples**:
  - `FaIcon(FontAwesomeIcons.bars)` - menu icon
  - `FaIcon(FontAwesomeIcons.arrowsRotate)` - refresh icon
  - `FaIcon(FontAwesomeIcons.user)` - user icon
  - `FaIcon(FontAwesomeIcons.solidUser)` - filled user icon

## MULTIPLATFORM PROJECT - ALL PLATFORMS ALWAYS
This is a multiplatform project targeting Linux, Windows, and Android (iOS planned).
When writing ANY code:
- **ALWAYS** consider all target platforms
- **NEVER** use platform-specific APIs without abstraction
- **ALWAYS** test/verify changes work on all platforms
- **USE** the platform abstraction layer (`crypto/utils/qgp_platform_*.c`)
- **CHECK** CMake platform modules (`cmake/*.cmake`) for platform differences
- Bug fixes must work on ALL platforms, not just the one where bug was found
- New features must be designed for ALL platforms from the start
- Use `#ifdef` guards only in platform abstraction files, not in business logic

**Platform Abstraction Layer (`qgp_platform_*.c`):**
When adding NEW functions to the platform layer:
- **MUST** implement in ALL THREE files: `qgp_platform_linux.c`, `qgp_platform_windows.c`, `qgp_platform_android.c`
- **MUST** declare in `qgp_platform.h`
- Missing implementations cause linker errors on that platform

**Windows-Specific Requirements:**
- **Format specifiers**: Use `%llu`/`%lld` with casts for `uint64_t`/`int64_t` (Windows `long` is 32-bit!)
  ```c
  QGP_LOG_INFO(TAG, "value=%llu", (unsigned long long)my_uint64);
  ```
- **MSVC pragmas**: Wrap in `#ifdef _MSC_VER` (MinGW doesn't support them)
  ```c
  #ifdef _MSC_VER
  #pragma comment(lib, "ws2_32.lib")
  #endif
  ```
- **Include order**: `winsock2.h` MUST come before `windows.h`
  ```c
  #ifdef _WIN32
  #include <winsock2.h>  // MUST be first!
  #endif
  ```
- **DLL exports**: Public API functions need proper export macros for shared library builds
- **Path separators**: Preserve original separator (`\` vs `/`) when manipulating paths

## LOCAL TESTING POLICY
- **BUILD ONLY**: Only verify that the build succeeds locally (`cmake .. && make`)
- **NO GUI TESTING**: Do NOT attempt to run or test the GUI application locally - this machine has no monitor
- **REMOTE TESTING**: All functional/GUI testing is performed on other machines by the user
- **NEVER** launch `dna-messenger`, Flutter app, or any GUI executable locally

## CLI FOR DEBUGGING AND TESTING
The CLI tool (`dna-messenger-cli`) is the primary tool for debugging and testing DNA Messenger features.

**Documentation:** [`docs/CLI_TESTING.md`](docs/CLI_TESTING.md) - Complete CLI reference

**Build:**
```bash
cd build && make dna-messenger-cli
```

**Key debugging commands:**
```bash
CLI=/opt/dna-messenger/build/cli/dna-messenger-cli

# DHT Profile debugging
$CLI lookup-profile <name|fp>    # View any user's full DHT profile
$CLI lookup <name>               # Check if name is registered

# Messaging (USE NAME or FULL 128-char fingerprint - partial fp does NOT work)
$CLI send <name> "message"       # Send message to contact by name
$CLI send <full-fp> "message"    # Send message using FULL 128-char fingerprint
$CLI messages <fp>               # Show conversation history
$CLI check-offline               # Poll DHT for offline messages
$CLI listen                      # Subscribe to push notifications

# Identity debugging
$CLI whoami                      # Show current identity
$CLI profile                     # Show own profile
$CLI contacts                    # List contacts with status (shows names + fingerprints)
```

**When to use CLI:**
- **Send test messages** to contacts (use registered name like `nox` or FULL fingerprint)
- Debug DHT profile registration issues
- Test offline message delivery
- Verify contact request flow
- Check name registration status
- Compare profile data between users

**IMPORTANT:** For `send` command, use the contact's **registered name** (e.g., `nox`) or the **full 128-character fingerprint**. Partial fingerprints will fail with "Network error".

## FUZZ TESTING REQUIREMENT
When implementing **new methods in dna_engine or dna_api** that parse external input (network data, user input, file formats), you **MUST** add a corresponding fuzz test.

**Documentation:** [`docs/FUZZING.md`](docs/FUZZING.md) - Complete fuzzing guide

**When to add fuzz tests:**
- New deserialization/parsing functions
- Functions that handle untrusted network data
- Cryptographic operations with external input
- Any function processing variable-length binary data

**How to add:**
1. Create `tests/fuzz/fuzz_<function>.c` with `LLVMFuzzerTestOneInput()`
2. Add target to `tests/CMakeLists.txt` using `add_fuzz_target()` macro
3. Create seed corpus in `tests/fuzz/corpus/<function>/`
4. Update `docs/FUZZING.md`

**Build & run:**
```bash
cd tests && mkdir build-fuzz && cd build-fuzz
CC=clang CXX=clang++ cmake -DENABLE_FUZZING=ON -DCMAKE_BUILD_TYPE=Debug ..
make && ./fuzz_<target> ../fuzz/corpus/<target>/ -max_total_time=60
```

## Protocol Mode

PROTOCOL MODE: ACTIVE                                  NO ASSUMPTIONS

  When this mode is active:
  1. Begin EVERY response with "PROTOCOL MODE ACTIVE. -- Model: [current model name]"
  2. Only follow explicit instructions
  3. Confirm understanding before taking action
  4. Never add features not explicitly requested
  5. Ask for clarification rather than making assumptions
  6. Report exactly what was done without elaboration
  7. Do not suggest improvements unless requested
  8. Keep all responses minimal and direct
  9. Keep it simple


## MANDATORY CHECKPOINT

**ABSOLUTE REQUIREMENT**: I CANNOT execute ANY action without completing ALL checkpoints. Skipping ANY checkpoint constitutes protocol violation.

### CHECKPOINT 1: STOP BARRIER
Before ANY action, I MUST:
1. **STOP** immediately - NO commands, NO tools, NO actions
2. **STATE**: "CHECKPOINT 1 COMPLETE - All actions halted for documentation review"

### CHECKPOINT 2: DOCUMENTATION RESEARCH
I MUST search and read relevant documentation:
1. **READ** relevant files in `docs/` directory
2. **READ** check for relevant functions in 'docs/FUNCTIONS.MD'
3. **STATE**: "CHECKPOINT 2 COMPLETE - Documentation reviewed: [list files read]"

### CHECKPOINT 3: PLAN CONFIRMATION
I MUST explicitly state my plan:
1. **CONFIRM** what I found in documentation
2. **CONFIRM** exactly what actions I plan to take
3. **CONFIRM** why these actions are necessary
4. **STATE**: "CHECKPOINT 3 COMPLETE - Plan confirmed and stated"

### CHECKPOINT 4: EXPLICIT APPROVAL GATE
I MUST wait for explicit user permission:
1. **WAIT** for user to type "APPROVED" or "PROCEED"
2. **NO ASSUMPTIONS** - only explicit approval words count
3. **STATE**: "CHECKPOINT 4 COMPLETE - Awaiting explicit approval"

**IMPORTANT:** "Dangerously skip permissions" mode in settings.json does NOT skip this checkpoint.
- Settings.json controls TOOL permissions (Read, Edit, Bash, etc.)
- CHECKPOINT 4 controls PLAN approval - ALWAYS requires user approval
- These are separate systems. Never conflate them.

### CHECKPOINT 5: ACTION EXECUTION
Only after ALL previous checkpoints:
1. **EXECUTE** approved actions only
2. **REPORT** exactly what was done
3. **STATE**: "CHECKPOINT 5 COMPLETE - Actions executed as approved"

### CHECKPOINT 6: MANDATORY REPORT
After ALL actions are complete, I MUST provide a final report:
1. **SUMMARY** - What was done (brief description)
2. **FILES CHANGED** - List all files modified/created/deleted
3. **ISSUES** - Any problems encountered (or "None")
4. **STATUS** - Final outcome (SUCCESS/PARTIAL/FAILED)
5. **STATE**: "CHECKPOINT 6 COMPLETE - Final report delivered"

### CHECKPOINT 7: DOCUMENTATION UPDATE
When changes are made to ANY of the following topics, I MUST update the relevant documentation:

**Documentation Files & Topics:**
| Topic | Documentation File | Update When... |
|-------|-------------------|----------------|
| Architecture | `docs/ARCHITECTURE_DETAILED.md` | Directory structure, components, build system, data flow changes |
| DHT System | `docs/DHT_SYSTEM.md` | DHT operations, bootstrap nodes, offline queue, key derivation changes |
| DNA Engine API | `docs/DNA_ENGINE_API.md` | Public API functions, data types, callbacks, error codes changes |
| DNA Nodus | `docs/DNA_NODUS.md` | Bootstrap server, STUN/TURN, config, deployment changes |
| Flutter UI | `docs/FLUTTER_UI.md` | Screens, FFI bindings, providers, widgets changes |
| Function Reference | `docs/FUNCTIONS.md` | Adding, modifying, or removing any function signatures |
| Git Workflow | `docs/GIT_WORKFLOW.md` | Commit guidelines, branch strategy, repo procedures changes |
| Message System | `docs/MESSAGE_SYSTEM.md` | Message format, encryption, GSK, database schema changes |
| Mobile Porting | `docs/MOBILE_PORTING.md` | Android SDK, JNI, iOS, platform abstraction changes |
| P2P Architecture | `docs/P2P_ARCHITECTURE.md` | Transport tiers, ICE/NAT, TCP, peer discovery changes |
| Security | `docs/SECURITY_AUDIT.md` | Crypto primitives, vulnerabilities, security fixes |

**Procedure:**
1. **IDENTIFY** which documentation files are affected by the changes
2. **UPDATE** each affected documentation file with accurate information
3. **VERIFY** the documentation matches the actual code changes
4. **STATE**: "CHECKPOINT 7 COMPLETE - Documentation updated: [list files updated]" OR "CHECKPOINT 7 COMPLETE - No documentation updates required (reason: [reason])"

**IMPORTANT:** Documentation is the source of truth. Code changes without documentation updates violate protocol mode.

### CHECKPOINT 8: VERSION UPDATE (MANDATORY ON EVERY PUSH)
**EVERY successful build that will be pushed MUST increment the appropriate version.**

**Version Files (INDEPENDENT - do NOT keep in sync):**
| Component | Version File | Current | Bump When |
|-----------|--------------|---------|-----------|
| C Library | `include/dna/version.h` | v0.3.69 | C code changes (src/, dht/, messenger/, p2p/, crypto/, include/) |
| Flutter App | `dna_messenger_flutter/pubspec.yaml` | v0.99.19+9919 | Flutter/Dart code changes (lib/, assets/) |
| Nodus Server | `vendor/opendht-pq/tools/nodus_version.h` | v0.4.3 | Nodus server changes (vendor/opendht-pq/tools/) |

**IMPORTANT: Versions are INDEPENDENT**
- Each component has its **own version number** - they do NOT need to match
- **C Library changes** → bump `version.h` only
- **Flutter/Dart changes** → bump `pubspec.yaml` only
- **Nodus server changes** → bump `nodus_version.h` only
- **Build scripts, CI, docs** → no version bump needed
- Flutter app displays **both versions** in Settings:
  - App version: from `pubspec.yaml`
  - Library version: via `dna_engine_get_version()` FFI call

**pubspec.yaml format:** `X.Y.Z+NNN` where NNN = versionCode for Android Play Store
- versionCode = MAJOR×10000 + MINOR×100 + PATCH (e.g., 0.99.12 → 9912)

**Which Number to Bump:**
- **PATCH** (0.3.X → 0.3.23): Bug fixes, small features, improvements
- **MINOR** (0.X.0 → 0.4.0): Major new features, significant API changes
- **MAJOR** (X.0.0 → 1.0.0): Breaking changes, production release

**Procedure:**
1. **IDENTIFY** which component(s) changed (C library, Flutter, or Nodus)
2. **BUMP** only the affected version file(s) - do NOT bump unrelated versions
3. **UPDATE** the "Current" column in this section
4. **UPDATE** the version in CLAUDE.md header line
5. **COMMIT** with version in commit message (e.g., "fix: Something (v0.3.39)")
6. **STATE**: "CHECKPOINT 8 COMPLETE - Version bumped: [component] [old] -> [new]"

**IMPORTANT:** Only bump versions for actual code changes to that component. Build scripts, CI configs, and documentation do NOT require version bumps.

**ENFORCEMENT**: Each checkpoint requires explicit completion statement. Missing ANY checkpoint statement indicates protocol violation and requires restart.



## Quick Links

### 📚 Core Documentation
- **[Architecture](docs/ARCHITECTURE_DETAILED.md)** - System architecture and directory structure
- **[Git Workflow](docs/GIT_WORKFLOW.md)** - Commit guidelines and dual-repo push
- **[Security Audit](docs/SECURITY_AUDIT.md)** - Security review and cryptographic analysis

### 📋 Project Planning
- **[ROADMAP.md](ROADMAP.md)** - Development roadmap and phase tracking
- **[README.md](README.md)** - Project overview and getting started

### 🔧 Technical Docs
- **[Functions Reference](docs/FUNCTIONS.md)** - All function signatures (authoritative source)
- **[Protocol Specs](docs/PROTOCOL.md)** - Wire formats (Seal, Spillway, Anchor, Atlas, Nexus)
- **[CLI Testing](docs/CLI_TESTING.md)** - CLI tool for debugging and testing
- **[Flutter UI](docs/FLUTTER_UI.md)** - Flutter migration (Phase 7)
- **[DNA Nodus](docs/DNA_NODUS.md)** - Bootstrap + STUN/TURN server (v0.4)
- **[DHT System](docs/DHT_SYSTEM.md)** - DHT architecture and operations
- **[Message System](docs/MESSAGE_SYSTEM.md)** - Message handling and encryption
- **[P2P Architecture](docs/P2P_ARCHITECTURE.md)** - Peer-to-peer transport layer
- **[DNA Engine API](docs/DNA_ENGINE_API.md)** - Core engine API reference
- **[Mobile Porting](docs/MOBILE_PORTING.md)** - Android/iOS porting guide

---

## Project Overview

Post-quantum E2E encrypted messenger with cpunk wallet. **NIST Category 5 security** (256-bit quantum).

**Crypto:** Kyber1024 (ML-KEM-1024), Dilithium5 (ML-DSA-87), AES-256-GCM, SHA3-512

**Key Features:** E2E encrypted messaging • GSK group encryption • DHT groups • Per-identity contacts • User profiles • Wall posts • cpunk wallet • P2P + DHT • ICE NAT traversal • Offline queueing (7d) • BIP39 recovery • SQLite • ImGui GUI • Android SDK (JNI)


---

## Quick Start

**Build:**
```bash
mkdir build && cd build
cmake .. && make -j$(nproc)
```

**Cross-compile Windows:**
```bash
./build-cross-compile.sh windows-x64
```

**Run:**
```bash
./build/imgui_gui/dna-messenger
```

---

## Team Development Approach

DNA Messenger is developed by a **collaborative team**. When working on this project:

1. **Security First** - Never modify crypto primitives without team review
2. **Team Communication** - Document changes, discuss architecture decisions
3. **Merge over Rebase** - Preserve commit history for team visibility
4. **Cross-Platform** - Test Linux and Windows before committing
5. **Documentation** - Update docs with all changes

---

## Development Priorities

1. **Security First** - Never modify crypto primitives without review
2. **Simplicity** - Keep code simple and focused
3. **Clean Code** - ALWAYS prefer modifying existing functions over adding new ones. Reuse existing code paths. Don't bloat the codebase with redundant methods.
4. **Cross-Platform** - Test Linux and Windows
5. **Documentation** - Update docs with changes
6. **Team Workflow** - Use merge commits, communicate changes

---

## Git Workflow (IMPORTANT)

**Team Workflow - Merge over Rebase:**
- **Prefer `git merge`** over `git rebase` to preserve team commit history
- Use `git pull --no-rebase` to merge remote changes
- Merge commits maintain context of feature development

**ALWAYS push to both repos:**
```bash
./push_both.sh
# OR manually:
git push gitlab main    # GitLab (primary)
git push origin main    # GitHub (mirror)
```

**NOTE:** If user is `mika` (check with `whoami`), only push to `origin main` - mika only has access to origin (which is GitLab for this user).

**Commit format:**
```
Short summary (<50 chars)

Details: what/why/breaking

```

**CI Build Trigger:**
- CI only runs when commit message contains `[BUILD]` or when triggered manually via web
- When user asks for a "build commit", include `[BUILD]` in the commit message
- Example: `feat: Add presence refresh (v0.2.45) [BUILD]`

---

## DNA Nodus Deployment

**Bootstrap Servers (dna-nodus v0.4):**
| Server | IP | DHT Port | TURN Port |
|--------|-----|----------|-----------|
| US-1 | 154.38.182.161 | 4000 | 3478 |
| EU-1 | 164.68.105.227 | 4000 | 3478 |
| EU-2 | 164.68.116.180 | 4000 | 3478 |

**Deployment Process (v0.4+):**
```bash
# Use the build script on each server:
ssh root@<server-ip> "bash /opt/dna-messenger/build-nodus.sh"

# The script will:
# 1. Pull latest code
# 2. Build dna-nodus
# 3. Install to /usr/local/bin/
# 4. Restart systemd service
```

**Configuration (v0.4+):**
- Config file: `/etc/dna-nodus.conf` (JSON format)
- No CLI arguments needed - pure config file
- See `vendor/opendht-pq/tools/dna-nodus.conf.example`

**Example config:**
```json
{
    "dht_port": 4000,
    "seed_nodes": ["154.38.182.161", "164.68.105.227"],
    "turn_port": 3478,
    "public_ip": "auto",
    "persistence_path": "/var/lib/dna-dht/bootstrap.state"
}
```

**Services:**
- DHT: UDP port 4000
- STUN/TURN: UDP port 3478 (libjuice)
- Credential TTL: 7 days

**Persistence:**
- Default path: `/var/lib/dna-dht/bootstrap.state`
- SQLite database: `bootstrap.state.values.db`
- Values persist across restarts automatically

**Documentation:** See [docs/DNA_NODUS.md](docs/DNA_NODUS.md) for full details.

---

## Phase Status

### ✅ Complete
- **Phase 4:** Desktop GUI (ImGui) + Wallet Integration
- **Phase 5.1-5.9:** P2P Architecture (DHT, ICE, GSK, Message Format v0.08)
- **Phase 6:** Android SDK (JNI bindings, Java classes, Gradle project)
- **Phase 8:** cpunk Wallet Integration
- **Phase 9.1-9.6:** P2P Transport, Offline Queue, DHT Migrations
- **Phase 10.1-10.4:** User Profiles, DNA Board, Avatars, Voting
- **Phase 11:** ICE NAT Traversal
- **Phase 12:** Message Format v0.08 - Fingerprint Privacy
- **Phase 13:** GSK Group Encryption
- **Phase 14:** DHT-Only Messaging (Android ForegroundService, DHT listen reliability) 

### 🚧 In Progress
- **Phase 7:** Mobile/Desktop UI (Flutter + Dart)

### 📋 Planned
- **Phase 8:** Web Messenger (WebAssembly)
- **Phase 9:** Voice/Video Calls (Post-Quantum)
- **Phase 10:** iOS Application

---

## Resources

**Repos:**
- [GitLab (primary)](https://gitlab.cpunk.io/cpunk/dna-messenger) - CI/CD, builds
- [GitHub (mirror)](https://github.com/nocdem/dna-messenger) - Public, community

**Links:**
- [Cellframe](https://wiki.cellframe.net)
- [Cellframe Dev](https://dev-wiki.cellframe.net)
- [Kyber](https://pq-crystals.org/kyber/)
- [Dilithium](https://pq-crystals.org/dilithium/)

**Contact:**
- [cpunk.io](https://cpunk.io)
- [cpunk.club](https://cpunk.club)
- [Telegram @chippunk_official](https://web.telegram.org/k/#@chippunk_official)

---

**When in doubt:** Check [Development Guidelines](docs/DEVELOPMENT.md), Then ask(critical).

**Priority:** Simplicity, security, cross-platform compatibility.
