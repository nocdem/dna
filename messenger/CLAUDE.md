# DNA Messenger - Development Guidelines for Claude AI

**Last Updated:** 2025-11-28 | **Phase:** 7 (Android UI) | **Complete:** 4, 5.1-5.9, 6 (Android SDK), 8, 9.1-9.6, 10.1-10.4, 11, 12, 13

---

## PROTOCOL MODE
NO STUBS
NO ASSUMPTIONS
NO DUMMY DATA
Souce of truth is the soucecode and documentation
Always ask user what to do if unsure
Anything aginst protcol mode breaks the blockchain / encryption . 


## Quick Links

### 📚 Core Documentation
- **[Architecture](docs/ARCHITECTURE.md)** - System architecture and directory structure
- **[Development Guidelines](docs/DEVELOPMENT.md)** - Code style, patterns, testing
- **[API Reference](docs/API.md)** - Quick API reference
- **[Git Workflow](docs/GIT_WORKFLOW.md)** - Commit guidelines and dual-repo push

### 📋 Project Planning
- **[ROADMAP.md](ROADMAP.md)** - Development roadmap and phase tracking
- **[README.md](README.md)** - Project overview and getting started

### 🔧 Technical Docs
- **[DHT Refactoring](docs/DHT_REFACTORING_PROGRESS.md)** - DHT modularization history
- **[Message Formats](docs/MESSAGE_FORMATS.md)** - v0.08 message format spec
- **[ICE NAT Traversal](docs/ICE_NAT_TRAVERSAL_FIXES.md)** - NAT traversal implementation
- **[GSK Implementation](docs/GSK_IMPLEMENTATION.md)** - Group Symmetric Key details
- **[Group Invitations](docs/GROUP_INVITATIONS_GUIDE.md)** - P2P invitation system

---

## Project Overview

Post-quantum E2E encrypted messenger with cpunk wallet. **NIST Category 5 security** (256-bit quantum).

**Crypto:** Kyber1024 (ML-KEM-1024), Dilithium5 (ML-DSA-87), AES-256-GCM, SHA3-512

**Key Features:** E2E encrypted messaging • GSK group encryption (200x faster) • DHT groups • Per-identity contacts • User profiles • Wall posts • cpunk wallet • P2P + DHT • ICE NAT traversal • Offline queueing (7d) • BIP39 recovery • SQLite • ImGui GUI • Android SDK (JNI)

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
3. **Cross-Platform** - Test Linux and Windows
4. **Documentation** - Update docs with changes
5. **Team Workflow** - Use merge commits, communicate changes

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

**Commit format:**
```
Short summary (<50 chars)

Details: what/why/breaking

🤖 Generated with [Claude Code](https://claude.com/claude-code)

Co-Authored-By: Claude <noreply@anthropic.com>
```

---

## Bootstrap Server Deployment (CRITICAL)

**IMPORTANT:** Use **dna-nodus** ONLY. Never build or use `dht-bootstrap` service.

**Bootstrap Servers:**
- US-1: 154.38.182.161:4000
- EU-1: 164.68.105.227:4000
- EU-2: 164.68.116.180:4000

**Deployment Process:**
```bash
# On each bootstrap server:
cd /opt/dna-messenger
git pull
rm -rf build && mkdir build && cd build
cmake -DBUILD_GUI=OFF .. && make -j$(nproc)

# Kill old nodus
killall -9 dna-nodus

# Start dna-nodus with persistence (runs in foreground)
./vendor/opendht-pq/tools/dna-nodus -b 154.38.182.161:4000 -b 164.68.105.227:4000 -b 164.68.116.180:4000 -v

# OR run in background:
nohup ./vendor/opendht-pq/tools/dna-nodus -b <bootstrap-nodes> -v > /var/log/dna-nodus.log 2>&1 &
```

**Persistence:**
- Default path: `/var/lib/dna-dht/bootstrap.state`
- SQLite database: `bootstrap.state.values.db`
- Use `-s <path>` to override
- Values persist across restarts automatically

**NEVER:**
- Build dht-bootstrap service
- Use dht-bootstrap systemd service
- Deploy binaries via scp (always pull + build on server)

---

## Phase Status

### ✅ Complete
- **Phase 4:** Desktop GUI (ImGui) + Wallet Integration
- **Phase 5.1-5.9:** P2P Architecture (DHT, ICE, GSK, Message Format v0.08)
- **Phase 6:** Android SDK (JNI bindings, Java classes, Gradle project)
- **Phase 8:** cpunk Wallet Integration
- **Phase 9.1-9.6:** P2P Transport, Offline Queue, DHT Migrations
- **Phase 10.1-10.4:** User Profiles, DNA Board, Avatars, Voting
- **Phase 11:** ICE NAT Traversal (PRODUCTION READY)
- **Phase 12:** Message Format v0.08 - Fingerprint Privacy
- **Phase 13:** GSK Group Encryption (200x speedup)

### 🚧 In Progress
- **Phase 7:** Android UI (Kotlin + Jetpack Compose)

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

**When in doubt:** Check [Development Guidelines](docs/DEVELOPMENT.md), follow code patterns, keep it simple.

**Priority:** Simplicity, security, cross-platform compatibility.
