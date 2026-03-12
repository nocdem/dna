# DNA Monorepo Restructure Design

**Date:** 2026-02-28
**Status:** DESIGN
**Author:** nocdem + EXECUTOR

---

## 1. Motivation

Three related projects currently live in separate repos with fragile cross-dependencies:

| Project | Current Location | Repo | Issues |
|---------|-----------------|------|--------|
| dna-messenger | `/opt/dna-messenger` | GitLab + GitHub | Main project |
| dnac | `/opt/dnac` | GitHub only | Hardcoded path to `/opt/dna-messenger` for crypto |
| cpunk | `/opt/cpunk` | GitHub only | No code dependency (web only, for now) |

**Problems:**
1. **dnac depends on dna-messenger via hardcoded absolute path** — breaks on any other machine
2. **Shared crypto code lives inside messenger** — not reusable cleanly
3. **Nodus (new)** will be used by both messenger and dnac — needs a shared home
4. **No unified build** — each project builds separately with fragile path references

**Goal:** Single monorepo (`dna`) with shared code properly extracted.

---

## 2. Target Structure

```
/opt/dna/                          ← single git repo (github.com/nocdem/dna)
│
├── shared/                        ← shared libraries (used by messenger, nodus, dnac)
│   ├── crypto/                    ← post-quantum crypto (from messenger/crypto/)
│   │   ├── kyber/                 ← ML-KEM-1024
│   │   ├── dilithium/             ← ML-DSA-87
│   │   ├── sha3/                  ← SHA3-512, SHA3-256
│   │   ├── aes/                   ← AES-256-GCM
│   │   ├── bip39/                 ← mnemonic seed phrases
│   │   └── utils/                 ← qgp_log, qgp_platform, qgp_compiler, threadpool
│   │
│   ├── database/                  ← SQLite helpers (from messenger/database/)
│   │   ├── cache_manager.c
│   │   └── ...
│   │
│   └── CMakeLists.txt             ← builds libdna-shared.a
│
├── nodus/                         ← Nodus server + client SDK (NEW)
│   ├── include/nodus/
│   ├── src/
│   │   ├── core/                  ← routing, storage, value
│   │   ├── protocol/              ← wire, cbor, tier1, tier2
│   │   ├── transport/             ← tcp, udp
│   │   ├── crypto/                ← sign/verify wrapper (uses shared/crypto)
│   │   ├── channel/               ← hashring, replication, channel ops
│   │   ├── consensus/             ← PBFT
│   │   ├── client/                ← client SDK (used by messenger + dnac)
│   │   └── server/                ← server main, discovery, auth
│   ├── tools/                     ← nodus-server binary, nodus-cli
│   ├── tests/
│   └── CMakeLists.txt
│
├── messenger/                     ← DNA Connect (from /opt/dna-messenger)
│   ├── include/dna/               ← public API headers
│   ├── src/                       ← engine, api modules
│   ├── dht/                       ← DHT client layer (uses nodus/client/)
│   ├── transport/                 ← P2P transport
│   ├── messenger/                 ← identity, keys, contacts core
│   ├── blockchain/                ← multi-chain wallet
│   ├── flutter/                   ← Flutter app (renamed from dna_messenger_flutter/)
│   ├── docs/
│   ├── tests/
│   └── CMakeLists.txt
│
├── dnac/                          ← DNAC blockchain (from /opt/dnac)
│   ├── include/
│   ├── src/
│   ├── tests/
│   └── CMakeLists.txt             ← uses shared/ and nodus/client/ (no more hardcoded paths)
│
├── cpunk/                         ← cpunk.io website (from /opt/cpunk)
│   ├── backend/
│   ├── cpunk.club/
│   └── ...
│
├── docs/                          ← top-level docs (cross-project)
│   └── plans/                     ← design documents (like this one)
│
├── CMakeLists.txt                 ← root CMake (orchestrates all sub-projects)
├── CLAUDE.md                      ← monorepo-level instructions
├── README.md
└── .gitignore
```

---

## 3. What Moves Where

### 3.1 Shared Code Extraction (from messenger)

These directories move from `messenger/` to `shared/`:

| Source (current) | Destination | Used By |
|-----------------|-------------|---------|
| `crypto/` | `shared/crypto/` | messenger, nodus, dnac |
| `crypto/utils/` | `shared/crypto/utils/` | all |
| `database/cache_manager.*` | `shared/database/` | messenger, nodus |

**Key files in shared/crypto/:**
- `qgp_dilithium.h/.c` — Dilithium5 sign/verify
- `qgp_sha3.h/.c` — SHA3-512/256
- `qgp_kyber.h/.c` — Kyber1024 KEM
- `qgp_aes256gcm.h/.c` — AES-256-GCM
- `qgp_platform.h` + `qgp_platform_linux.c`, `_windows.c`, `_android.c`
- `qgp_log.h/.c` — logging
- `threadpool.h/.c` — thread pool
- `qgp_compiler.h` — struct packing macros
- `bip39/` — mnemonic generation

### 3.2 Messenger (restructure in place)

| Current | New | Note |
|---------|-----|------|
| `/opt/dna-messenger/src/` | `messenger/src/` | Engine + API modules |
| `/opt/dna-messenger/include/` | `messenger/include/` | Public headers |
| `/opt/dna-messenger/dht/` | `messenger/dht/` | DHT client (will use nodus SDK) |
| `/opt/dna-messenger/transport/` | `messenger/transport/` | P2P transport |
| `/opt/dna-messenger/messenger/` | `messenger/messenger/` | Core identity/keys |
| `/opt/dna-messenger/blockchain/` | `messenger/blockchain/` | Wallet |
| `/opt/dna-messenger/dna_messenger_flutter/` | `messenger/flutter/` | Flutter app |
| `/opt/dna-messenger/docs/` | `messenger/docs/` | Messenger-specific docs |
| `/opt/dna-messenger/build-*` scripts | `messenger/` | Build scripts |

**NOT moved** (removed after Nodus rewrite):
- `vendor/opendht-pq/` — entire OpenDHT (37K lines C++)
- `dht/core/dht_context.cpp` — C++ bridge
- `dht/core/dht_listen.cpp` — C++ listen wrapper
- `dht/shared/dht_chunked.*` — chunking

### 3.3 DNAC (move as-is, fix paths)

| Current | New | Change |
|---------|-----|--------|
| `/opt/dnac/` | `dnac/` | Move entire directory |
| `CMakeLists.txt` hardcoded `/opt/dna-messenger` | `${CMAKE_SOURCE_DIR}/shared` | Fix path references |
| `src/nodus/` | Keep for now | Will migrate to shared nodus client SDK later |

### 3.4 Cpunk (move as-is)

| Current | New | Change |
|---------|-----|--------|
| `/opt/cpunk/` | `cpunk/` | Move entire directory, no code changes |

---

## 4. CMake Structure

### Root CMakeLists.txt
```cmake
cmake_minimum_required(VERSION 3.16)
project(dna VERSION 1.0.0 LANGUAGES C)

# Shared libraries (built first)
add_subdirectory(shared)

# Projects (depend on shared)
add_subdirectory(nodus)
add_subdirectory(messenger)
add_subdirectory(dnac)
# cpunk has no C build
```

### Dependency Graph
```
shared/crypto  ← messenger
shared/crypto  ← nodus
shared/crypto  ← dnac
nodus/client   ← messenger (after Nodus rewrite)
nodus/client   ← dnac (after migration)
```

### Include Paths (no more hardcoded absolute paths)
```cmake
# In dnac/CMakeLists.txt (AFTER restructure):
target_include_directories(dnac PRIVATE
    ${CMAKE_SOURCE_DIR}/shared/crypto
    ${CMAKE_SOURCE_DIR}/shared/crypto/utils
    ${CMAKE_SOURCE_DIR}/shared/database
    ${CMAKE_SOURCE_DIR}/nodus/include
)

# In messenger/CMakeLists.txt:
target_include_directories(messenger PRIVATE
    ${CMAKE_SOURCE_DIR}/shared/crypto
    ${CMAKE_SOURCE_DIR}/shared/crypto/utils
    ${CMAKE_SOURCE_DIR}/nodus/include
)
```

---

## 5. Git History Migration

**Strategy:** Use `git filter-repo` to rewrite history with path prefixes, then merge into new repo.

### Step-by-step:

```
1. Create new repo: github.com/nocdem/dna

2. Migrate dna-messenger (with history):
   a. Clone fresh: git clone dna-messenger dna-messenger-migrate
   b. Rewrite paths: git filter-repo --to-subdirectory-filter messenger/
   c. In dna repo: git remote add messenger-history ../dna-messenger-migrate
   d. git fetch messenger-history
   e. git merge messenger-history/main --allow-unrelated-histories

3. Migrate dnac (with history):
   a. Clone fresh: git clone dnac dnac-migrate
   b. Rewrite paths: git filter-repo --to-subdirectory-filter dnac/
   c. In dna repo: git remote add dnac-history ../dnac-migrate
   d. git fetch dnac-history
   e. git merge dnac-history/main --allow-unrelated-histories

4. Migrate cpunk (with history):
   a. Same pattern: filter-repo --to-subdirectory-filter cpunk/
   b. Merge into dna repo

5. Extract shared/ from messenger history:
   - Move shared files to shared/ directory
   - Update all include paths
   - Single commit: "refactor: extract shared crypto to shared/"

6. Create nodus/ skeleton:
   - Empty directory structure per design doc
   - Single commit: "feat: add nodus directory structure"
```

### History Result
After migration, `git log -- messenger/` shows full dna-messenger history.
`git log -- dnac/` shows full dnac history. All in one repo.

---

## 6. What Breaks (and fixes)

| What | Why it breaks | Fix |
|------|--------------|-----|
| dnac CMake paths | `/opt/dna-messenger` → gone | Use `${CMAKE_SOURCE_DIR}/shared` |
| messenger crypto includes | `crypto/utils/qgp_sha3.h` → moved | Update to `shared/crypto/utils/qgp_sha3.h` or adjust include paths |
| CI/CD pipelines | Repo URL changes | Update GitLab CI + GitHub Actions |
| CLAUDE.md | Paths, build commands | Rewrite for monorepo |
| Build scripts | `cd /opt/dna-messenger/build` | `cd /opt/dna/messenger/build` or `cd /opt/dna/build` |
| Systemd services (nodus servers) | Deploy paths | Update `build-nodus.sh` |
| Flutter pubspec | Relative paths may change | Verify `flutter/` rename |
| Android build | JNI library paths | Verify gradle config |

---

## 7. Remote Repos

### New
| Repo | URL | Purpose |
|------|-----|---------|
| dna | `github.com/nocdem/dna` | Monorepo (primary) |
| dna | `gitlab.cpunk.io/cpunk/dna` | Mirror (CI/CD) — later |

### Archived (after migration verified)
| Repo | Action |
|------|--------|
| `github.com/nocdem/dna-messenger` | Archive, add redirect note to README |
| `github.com/nocdem/dnac` | Archive, add redirect note to README |
| `github.com/nocdem/cpunk` | Archive, add redirect note to README |
| `gitlab.cpunk.io/cpunk/dna-messenger` | Archive, add redirect note to README |

---

## 8. Migration Order

| Step | Action | Risk |
|------|--------|------|
| 1 | Create `github.com/nocdem/dna` repo | None |
| 2 | Migrate dna-messenger with history → `messenger/` | Low — clone, no original modified |
| 3 | Migrate dnac with history → `dnac/` | Low |
| 4 | Migrate cpunk with history → `cpunk/` | Low |
| 5 | Extract `shared/` from messenger | Medium — many include path changes |
| 6 | Fix dnac CMake to use `shared/` | Low |
| 7 | Fix messenger CMake to use `shared/` | Medium — large project |
| 8 | Verify all builds pass | — |
| 9 | Create `nodus/` skeleton | None |
| 10 | Update CLAUDE.md, CI/CD, build scripts | Low |
| 11 | Archive old repos | None |

**Critical path:** Steps 5 + 7 (shared extraction + messenger CMake fix) are the riskiest. Everything else is mechanical.

---

## 9. Symlink Transition (Optional)

During migration, to avoid breaking existing workflows:

```bash
# After moving to /opt/dna/messenger:
ln -s /opt/dna/messenger /opt/dna-messenger
ln -s /opt/dna/dnac /opt/dnac
ln -s /opt/dna/cpunk /opt/cpunk
```

Remove symlinks once all scripts/tools updated.

---

## 10. Decisions Summary

| # | Decision | Choice |
|---|----------|--------|
| 1 | Repo structure | Monorepo (`dna`) |
| 2 | Remote | `github.com/nocdem/dna` (start here) |
| 3 | Git history | Preserved via `git filter-repo` |
| 4 | Shared code | Extracted to `shared/` (crypto, utils, database) |
| 5 | CMake | Root orchestrator + per-project sub-CMake |
| 6 | Old repos | Archived after migration verified |
| 7 | Transition | Symlinks for backward compat during migration |
