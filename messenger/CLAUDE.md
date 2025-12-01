# DNA Messenger - Development Guidelines for Claude AI

**Last Updated:** 2025-12-01 | **Phase:** 7 (Flutter UI) | **Complete:** 4, 5.1-5.9, 6 (Android SDK), 7.1-7.3 (Flutter Foundation + Core Screens + Full Features), 8, 9.1-9.6, 10.1-10.4, 11, 12, 13

---

## PROTOCOL MODE
NO STUBS
NO ASSUMPTIONS
NO DUMMY DATA
Souce of truth is the soucecode and documentation
Always ask user what to do if unsure
Anything aginst protcol mode breaks the blockchain / encryption . 


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
2. **STATE**: "CHECKPOINT 2 COMPLETE - Documentation reviewed: [list files read]"

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

### CHECKPOINT 5: ACTION EXECUTION
Only after ALL previous checkpoints:
1. **EXECUTE** approved actions only
2. **REPORT** exactly what was done
3. **STATE**: "CHECKPOINT 5 COMPLETE - Actions executed as approved"

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
- **[Flutter UI](docs/FLUTTER_UI.md)** - Flutter migration (Phase 7)
- **[DNA Nodus](docs/DNA_NODUS.md)** - Bootstrap + STUN/TURN server (v0.3)
- **[DHT System](docs/DHT_SYSTEM.md)** - DHT architecture and operations
- **[Message System](docs/MESSAGE_SYSTEM.md)** - Message handling and encryption
- **[P2P Architecture](docs/P2P_ARCHITECTURE.md)** - Peer-to-peer transport layer
- **[DNA Engine API](docs/DNA_ENGINE_API.md)** - Core engine API reference
- **[Mobile Porting](docs/MOBILE_PORTING.md)** - Android/iOS porting guide

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

```

---

## DNA Nodus Deployment

**Bootstrap Servers (dna-nodus v0.3):**
| Server | IP | DHT Port | TURN Port |
|--------|-----|----------|-----------|
| US-1 | 154.38.182.161 | 4000 | 3478 |
| EU-1 | 164.68.105.227 | 4000 | 3478 |
| EU-2 | 164.68.116.180 | 4000 | 3478 |

**Deployment Process (v0.3+):**
```bash
# Use the build script on each server:
ssh root@<server-ip> "bash /opt/dna-messenger/nodus_build.sh"

# The script will:
# 1. Pull latest code
# 2. Build dna-nodus
# 3. Install to /usr/local/bin/
# 4. Restart systemd service
```

**Configuration (v0.3+):**
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
