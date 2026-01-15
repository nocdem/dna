# DNA Monorepo Migration Guide

**Status:** PLANNED | **Target:** When ready to restructure | **Created:** 2026-01-13

This document provides step-by-step instructions for restructuring the `dna-messenger` repository into a multi-project monorepo called `dna`.

---

## Table of Contents
1. [Overview](#overview)
2. [Architecture](#architecture)
3. [Prerequisites](#prerequisites)
4. [Phase 1: Preparation](#phase-1-preparation)
5. [Phase 2: Create Directory Structure](#phase-2-create-directory-structure)
6. [Phase 3: Move Shared Crypto](#phase-3-move-shared-crypto)
7. [Phase 4: Move Messenger Code](#phase-4-move-messenger-code)
8. [Phase 5: Extract Nodus](#phase-5-extract-nodus)
9. [Phase 6: Create dnac Placeholder](#phase-6-create-dnac-placeholder)
10. [Phase 7: Reorganize Documentation](#phase-7-reorganize-documentation)
11. [Phase 8: Update CMake Build System](#phase-8-update-cmake-build-system)
12. [Phase 9: Update CI/CD](#phase-9-update-cicd)
13. [Phase 10: Update CLAUDE.md](#phase-10-update-claudemd)
14. [Phase 11: Verification](#phase-11-verification)
15. [Phase 12: Commit and Push](#phase-12-commit-and-push)
16. [Rollback Procedure](#rollback-procedure)
17. [Post-Migration Tasks](#post-migration-tasks)

---

## Overview

### Current Structure
```
dna-messenger/              # Root
├── crypto/                 # Crypto scattered in root
├── database/               # Database in root
├── dht/                    # DHT in root
├── messenger/              # Messenger core in root
├── p2p/                    # P2P in root
├── src/                    # Engine in root
├── cli/                    # CLI in root
├── dna_messenger_flutter/  # Flutter separate
├── android/                # Android separate
├── vendor/opendht-pq/tools/ # Nodus buried in vendor
└── docs/                   # Flat docs
```

### Target Structure
```
dna/                        # Renamed root
├── shared/crypto/          # Shared NIST crypto
├── messenger/              # All messenger code
│   ├── lib/                # C library
│   ├── cli/                # CLI tool
│   ├── flutter/            # Flutter UI
│   └── android/            # Android SDK
├── nodus/                  # Bootstrap server (extracted)
├── dnac/                   # New coin project (placeholder)
├── vendor/                 # Third-party deps
└── docs/                   # Organized by project
```

---

## Architecture

### Dependency Graph
```
                    ┌─────────────────────────────┐
                    │      shared/crypto/         │
                    │  (Kyber1024, Dilithium5)    │
                    │  (BIP39, BIP32, AES, SHA3)  │
                    └─────────────┬───────────────┘
                                  │
              ┌───────────────────┼───────────────────┐
              │                   │                   │
              ▼                   ▼                   ▼
    ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐
    │    messenger/   │  │     dnac/       │  │     nodus/      │
    │  (full app)     │  │  (ZK ledger)    │  │  (bootstrap)    │
    │                 │  │                 │  │                 │
    │ Links:          │  │ Links:          │  │ Links:          │
    │ - shared/crypto │  │ - shared/crypto │  │ - opendht-pq    │
    │ - opendht-pq    │  │ - opendht-pq    │  │                 │
    │                 │  │                 │  │                 │
    └─────────────────┘  └─────────────────┘  └─────────────────┘
              │                   │                   │
              └───────────────────┴───────────────────┘
                                  │
                          DHT Network (P2P)
```

### Key Principles
1. **dnac is STANDALONE** - does NOT depend on messenger or nodus code
2. **shared/crypto/** - Only NIST-compatible crypto (Kyber, Dilithium, BIP39)
3. **Each project has own DHT node** - joins same network via nodus bootstrap
4. **Future: dnac ↔ messenger RPC** - placeholder for later integration

---

## Prerequisites

Before starting migration:

1. **Backup the repository**
   ```bash
   cd /opt
   cp -r dna-messenger dna-messenger-backup-$(date +%Y%m%d)
   ```

2. **Ensure clean git state**
   ```bash
   cd /opt/dna-messenger
   git status  # Should show clean working tree
   git stash   # If needed
   ```

3. **Create migration branch**
   ```bash
   git checkout -b refactor/monorepo-structure
   ```

4. **Verify builds work before migration**
   ```bash
   cd build && cmake .. && make -j$(nproc)
   ```

---

## Phase 1: Preparation

### 1.1 Document Current Include Paths
Record all current include paths used in the codebase:

```bash
# Find all #include statements
grep -rh '#include' --include='*.c' --include='*.h' --include='*.cpp' \
  crypto/ database/ dht/ messenger/ p2p/ src/ | sort | uniq > /tmp/current_includes.txt
```

### 1.2 List All Files to Move
```bash
# Count files per directory
find crypto -type f -name '*.[ch]' | wc -l      # ~XX files
find database -type f -name '*.[ch]' | wc -l    # ~XX files
find dht -type f -name '*.[ch]' | wc -l         # ~XX files
find messenger -type f -name '*.[ch]' | wc -l   # ~XX files
find p2p -type f -name '*.[ch]' | wc -l         # ~XX files
find src -type f -name '*.[ch]' | wc -l         # ~XX files
find cli -type f -name '*.[ch]' | wc -l         # ~XX files
```

### 1.3 Identify External Dependencies
- `vendor/opendht-pq/` - DHT library
- ~~`vendor/libjuice/`~~ - Removed v0.4.61
- `vendor/sqlite3/` - SQLite (if vendored)

---

## Phase 2: Create Directory Structure

```bash
cd /opt/dna-messenger

# Create shared directory
mkdir -p shared/crypto/include

# Create messenger directory structure
mkdir -p messenger/lib/{engine,dht,p2p,messenger,database,blockchain,include}
mkdir -p messenger/cli
mkdir -p messenger/flutter
mkdir -p messenger/android/jni
mkdir -p messenger/web
mkdir -p messenger/tests

# Create nodus directory structure
mkdir -p nodus/src
mkdir -p nodus/config/systemd
mkdir -p nodus/tests

# Create dnac placeholder structure
mkdir -p dnac/lib/{ledger,node,dht,rpc,include}
mkdir -p dnac/cli
mkdir -p dnac/tests

# Create organized docs structure
mkdir -p docs/messenger/functions
mkdir -p docs/nodus
mkdir -p docs/dnac
mkdir -p docs/shared
```

---

## Phase 3: Move Shared Crypto

The crypto library is shared between messenger and dnac.

### 3.1 Move Crypto Source Files
```bash
cd /opt/dna-messenger

# Move KEM (Kyber)
git mv crypto/kem shared/crypto/kem

# Move DSA (Dilithium)
git mv crypto/dsa shared/crypto/dsa

# Move BIP39 (Mnemonic)
git mv crypto/bip39 shared/crypto/bip39

# Move BIP32 (HD Keys)
git mv crypto/bip32 shared/crypto/bip32

# Move utilities (AES, SHA3, platform)
git mv crypto/utils shared/crypto/utils

# Move Cellframe Dilithium (if separate)
git mv crypto/cellframe_dilithium shared/crypto/cellframe_dilithium
```

### 3.2 Move Crypto Headers
```bash
# Move main crypto header
git mv qgp.h shared/crypto/include/qgp.h
```

### 3.3 Create shared/crypto/CMakeLists.txt
```cmake
# shared/crypto/CMakeLists.txt
cmake_minimum_required(VERSION 3.16)
project(dna_crypto VERSION 1.0.0)

# Collect all crypto sources
file(GLOB_RECURSE CRYPTO_SOURCES
    "kem/*.c"
    "dsa/*.c"
    "bip39/*.c"
    "bip32/*.c"
    "utils/*.c"
)

# Build static library
add_library(dna_crypto STATIC ${CRYPTO_SOURCES})

target_include_directories(dna_crypto PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${CMAKE_CURRENT_SOURCE_DIR}/kem
    ${CMAKE_CURRENT_SOURCE_DIR}/dsa
    ${CMAKE_CURRENT_SOURCE_DIR}/bip39
    ${CMAKE_CURRENT_SOURCE_DIR}/bip32
    ${CMAKE_CURRENT_SOURCE_DIR}/utils
)

# Platform-specific settings
if(WIN32)
    target_compile_definitions(dna_crypto PRIVATE _CRT_SECURE_NO_WARNINGS)
endif()
```

---

## Phase 4: Move Messenger Code

### 4.1 Move Engine (from src/)
```bash
git mv src/api messenger/lib/engine
```

### 4.2 Move DHT
```bash
git mv dht/* messenger/lib/dht/
rmdir dht
```

### 4.3 Move P2P
```bash
git mv p2p/* messenger/lib/p2p/
rmdir p2p
```

### 4.4 Move Messenger Core
```bash
# Move directory contents
git mv messenger/* messenger/lib/messenger/

# Move root-level messenger files
git mv messenger.c messenger/lib/messenger/
git mv messenger.h messenger/lib/messenger/
git mv messenger_groups.c messenger/lib/messenger/
git mv messenger_p2p.c messenger/lib/messenger/
git mv messenger_p2p.h messenger/lib/messenger/
git mv message_backup.c messenger/lib/messenger/
git mv message_backup.h messenger/lib/messenger/
```

### 4.5 Move Database
```bash
git mv database/* messenger/lib/database/
rmdir database
```

### 4.6 Move Blockchain/Wallet
```bash
git mv blockchain/* messenger/lib/blockchain/
rmdir blockchain
```

### 4.7 Move Include Headers
```bash
git mv include/* messenger/lib/include/
rmdir include
```

### 4.8 Move Root-Level API Files
```bash
git mv dna_api.c messenger/lib/engine/
git mv dna_api.h messenger/lib/engine/
git mv dna_config.c messenger/lib/engine/
git mv dna_config.h messenger/lib/engine/
```

### 4.9 Move CLI
```bash
git mv cli/* messenger/cli/
```

### 4.10 Move Flutter
```bash
git mv dna_messenger_flutter/* messenger/flutter/
rmdir dna_messenger_flutter
```

### 4.11 Move Android
```bash
git mv android/* messenger/android/
git mv jni/* messenger/android/jni/
rmdir jni
```

### 4.12 Move Web
```bash
git mv web/* messenger/web/
```

### 4.13 Move Tests
```bash
git mv tests/* messenger/tests/
```

---

## Phase 5: Extract Nodus

Nodus is currently buried in `vendor/opendht-pq/tools/`. Extract to first-class project.

### 5.1 Move Nodus Source Files
```bash
cd /opt/dna-messenger

# Main source files
git mv vendor/opendht-pq/tools/dna-nodus.cpp nodus/src/
git mv vendor/opendht-pq/tools/nodus_config.cpp nodus/src/
git mv vendor/opendht-pq/tools/nodus_config.h nodus/src/
git mv vendor/opendht-pq/tools/nodus_version.h nodus/src/
git mv vendor/opendht-pq/tools/turn_server.cpp nodus/src/
git mv vendor/opendht-pq/tools/turn_server.h nodus/src/
git mv vendor/opendht-pq/tools/turn_credential_manager.cpp nodus/src/
git mv vendor/opendht-pq/tools/turn_credential_manager.h nodus/src/
git mv vendor/opendht-pq/tools/turn_credential_udp.cpp nodus/src/
git mv vendor/opendht-pq/tools/turn_credential_udp.h nodus/src/
git mv vendor/opendht-pq/tools/tools_common.h nodus/src/
```

### 5.2 Move Nodus Config Files
```bash
git mv vendor/opendht-pq/tools/dna-nodus.conf.example nodus/config/
git mv vendor/opendht-pq/tools/systemd/* nodus/config/systemd/
```

### 5.3 Create nodus/CMakeLists.txt
```cmake
# nodus/CMakeLists.txt
cmake_minimum_required(VERSION 3.16)
project(dna_nodus VERSION 0.4.5)

# Find dependencies
find_package(Threads REQUIRED)

# Source files
set(NODUS_SOURCES
    src/dna-nodus.cpp
    src/nodus_config.cpp
    src/turn_server.cpp
    src/turn_credential_manager.cpp
    src/turn_credential_udp.cpp
)

# Build executable
add_executable(dna-nodus ${NODUS_SOURCES})

target_include_directories(dna-nodus PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/src
    ${CMAKE_SOURCE_DIR}/vendor/opendht-pq/include
    # libjuice removed v0.4.61
)

target_link_libraries(dna-nodus PRIVATE
    opendht
    # juice removed v0.4.61
    Threads::Threads
)

# Install
install(TARGETS dna-nodus RUNTIME DESTINATION bin)
install(FILES config/dna-nodus.conf.example DESTINATION etc)
```

### 5.4 Update Include Paths in Nodus
Edit each nodus source file to update include paths:

**Before:**
```cpp
#include "../include/opendht.h"
#include "nodus_config.h"
```

**After:**
```cpp
#include <opendht.h>
#include "nodus_config.h"
```

---

## Phase 6: Create dnac Placeholder

Create the placeholder structure for DNA Coin.

### 6.1 Create dnac/README.md
```bash
cat > dnac/README.md << 'EOF'
# DNA Coin (dnac)

**Status:** PLANNED | **Version:** 0.0.1

Zero-knowledge post-quantum ledger using DHT as layer 0.

## Architecture

- **Standalone project** - does not depend on messenger or nodus code
- **Links to shared/crypto** - NIST-compatible Kyber/Dilithium
- **Own DHT node** - joins DNA network via nodus bootstrap
- **Future:** RPC interface to messenger

## Directory Structure

```
dnac/
├── lib/
│   ├── ledger/     # ZK ledger logic
│   ├── node/       # dnac daemon
│   ├── dht/        # DHT client (uses opendht-pq)
│   ├── rpc/        # Future messenger RPC
│   └── include/    # Public headers
├── cli/            # dnac CLI tool
└── tests/
```

## Building

```bash
cd build
cmake -DBUILD_DNAC=ON ..
make dnac
```

## TODO

- [ ] Define ledger data structures
- [ ] Implement ZK proof system
- [ ] Create DHT storage layer
- [ ] Build CLI interface
- [ ] Design messenger RPC protocol
EOF
```

### 6.2 Create dnac/CMakeLists.txt
```cmake
# dnac/CMakeLists.txt
cmake_minimum_required(VERSION 3.16)
project(dnac VERSION 0.0.1)

message(STATUS "dnac is a placeholder - not yet implemented")

# Future structure:
# add_subdirectory(lib)
# add_subdirectory(cli)

# Placeholder target
add_custom_target(dnac
    COMMAND ${CMAKE_COMMAND} -E echo "dnac not yet implemented"
)
```

### 6.3 Create Placeholder Source Files
```bash
# Create placeholder header
cat > dnac/lib/include/dnac.h << 'EOF'
/*
 * DNA Coin - Public API
 * Status: PLACEHOLDER
 */

#ifndef DNAC_H
#define DNAC_H

#ifdef __cplusplus
extern "C" {
#endif

// Version
#define DNAC_VERSION_MAJOR 0
#define DNAC_VERSION_MINOR 0
#define DNAC_VERSION_PATCH 1

// Future API will be defined here

#ifdef __cplusplus
}
#endif

#endif // DNAC_H
EOF
```

---

## Phase 7: Reorganize Documentation

### 7.1 Move Messenger Docs
```bash
cd /opt/dna-messenger

# Move main docs to messenger subdirectory
git mv docs/ARCHITECTURE_DETAILED.md docs/messenger/
git mv docs/DHT_SYSTEM.md docs/messenger/
git mv docs/MESSAGE_SYSTEM.md docs/messenger/
git mv docs/P2P_ARCHITECTURE.md docs/messenger/
git mv docs/DNA_ENGINE_API.md docs/messenger/
git mv docs/FLUTTER_UI.md docs/messenger/
git mv docs/MOBILE_PORTING.md docs/messenger/
git mv docs/CLI_TESTING.md docs/messenger/
git mv docs/FUZZING.md docs/messenger/
git mv docs/PROTOCOL.md docs/messenger/

# Move function reference
git mv docs/functions/* docs/messenger/functions/
```

### 7.2 Move Nodus Docs
```bash
git mv docs/DNA_NODUS.md docs/nodus/
```

### 7.3 Move Shared Docs
```bash
# Security audit applies to all projects
git mv docs/SECURITY_AUDIT.md docs/
```

### 7.4 Create docs/README.md (Index)
```bash
cat > docs/README.md << 'EOF'
# DNA Documentation

## Projects

| Project | Description | Docs |
|---------|-------------|------|
| [Messenger](messenger/) | E2E encrypted messenger | Architecture, DHT, P2P, API |
| [Nodus](nodus/) | DHT Bootstrap server | Deployment, Config |
| [dnac](dnac/) | ZK post-quantum ledger | (Planned) |
| [Shared](shared/) | Shared crypto library | Crypto reference |

## Cross-Project Docs

- [Security Audit](SECURITY_AUDIT.md) - Security review (all projects)
- [Git Workflow](GIT_WORKFLOW.md) - Commit guidelines
- [Development](DEVELOPMENT.md) - Development setup

## Quick Links

### Messenger
- [Architecture](messenger/ARCHITECTURE_DETAILED.md)
- [Function Reference](messenger/functions/README.md)
- [CLI Testing](messenger/CLI_TESTING.md)
- [Flutter UI](messenger/FLUTTER_UI.md)

### Nodus
- [Deployment Guide](nodus/DNA_NODUS.md)

### dnac
- [README](dnac/README.md) (placeholder)
EOF
```

---

## Phase 8: Update CMake Build System

### 8.1 Create Root CMakeLists.txt
```cmake
# CMakeLists.txt (root)
cmake_minimum_required(VERSION 3.16)
project(dna VERSION 1.0.0 LANGUAGES C CXX)

# Build options
option(BUILD_MESSENGER "Build DNA Messenger" ON)
option(BUILD_NODUS "Build DNA Nodus bootstrap server" ON)
option(BUILD_DNAC "Build DNA Coin (placeholder)" OFF)
option(BUILD_SHARED_LIBS "Build shared libraries" OFF)
option(BUILD_TESTS "Build test suite" ON)

# C/C++ Standards
set(CMAKE_C_STANDARD 11)
set(CMAKE_CXX_STANDARD 17)

# Include CMake modules
list(APPEND CMAKE_MODULE_PATH ${CMAKE_SOURCE_DIR}/cmake)
include(Platform)
include(Compiler)

# Build shared crypto library (always needed)
add_subdirectory(shared/crypto)

# Build vendor dependencies
add_subdirectory(vendor/opendht-pq)
# libjuice removed v0.4.61

# Build projects based on options
if(BUILD_MESSENGER)
    message(STATUS "Building DNA Messenger")
    add_subdirectory(messenger)
endif()

if(BUILD_NODUS)
    message(STATUS "Building DNA Nodus")
    add_subdirectory(nodus)
endif()

if(BUILD_DNAC)
    message(STATUS "Building DNA Coin (placeholder)")
    add_subdirectory(dnac)
endif()

# Summary
message(STATUS "")
message(STATUS "=== DNA Build Configuration ===")
message(STATUS "  Messenger: ${BUILD_MESSENGER}")
message(STATUS "  Nodus:     ${BUILD_NODUS}")
message(STATUS "  dnac:      ${BUILD_DNAC}")
message(STATUS "===============================")
```

### 8.2 Create messenger/CMakeLists.txt
```cmake
# messenger/CMakeLists.txt
cmake_minimum_required(VERSION 3.16)
project(dna_messenger VERSION 0.99.117)

# Subdirectories
add_subdirectory(lib)
add_subdirectory(cli)

# Flutter is built separately via flutter build
# Android is built via Gradle
```

### 8.3 Create messenger/lib/CMakeLists.txt
```cmake
# messenger/lib/CMakeLists.txt

# Collect sources from each module
file(GLOB_RECURSE ENGINE_SOURCES "engine/*.c")
file(GLOB_RECURSE DHT_SOURCES "dht/*.c")
file(GLOB_RECURSE P2P_SOURCES "p2p/*.c")
file(GLOB_RECURSE MESSENGER_SOURCES "messenger/*.c")
file(GLOB_RECURSE DATABASE_SOURCES "database/*.c")
file(GLOB_RECURSE BLOCKCHAIN_SOURCES "blockchain/*.c")

# Build main library
add_library(dna_messenger STATIC
    ${ENGINE_SOURCES}
    ${DHT_SOURCES}
    ${P2P_SOURCES}
    ${MESSENGER_SOURCES}
    ${DATABASE_SOURCES}
    ${BLOCKCHAIN_SOURCES}
)

target_include_directories(dna_messenger PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${CMAKE_CURRENT_SOURCE_DIR}/engine
    ${CMAKE_CURRENT_SOURCE_DIR}/dht
    ${CMAKE_CURRENT_SOURCE_DIR}/p2p
    ${CMAKE_CURRENT_SOURCE_DIR}/messenger
    ${CMAKE_CURRENT_SOURCE_DIR}/database
    ${CMAKE_CURRENT_SOURCE_DIR}/blockchain
)

# Link dependencies
target_link_libraries(dna_messenger PUBLIC
    dna_crypto
    opendht
    juice
    sqlite3
)
```

---

## Phase 9: Update CI/CD

### 9.1 Update .gitlab-ci.yml
```yaml
# .gitlab-ci.yml
stages:
  - build
  - test
  - deploy

variables:
  BUILD_DIR: build

# Build all projects
build:linux:
  stage: build
  script:
    - mkdir -p $BUILD_DIR && cd $BUILD_DIR
    - cmake -DBUILD_MESSENGER=ON -DBUILD_NODUS=ON ..
    - make -j$(nproc)
  artifacts:
    paths:
      - $BUILD_DIR/messenger/
      - $BUILD_DIR/nodus/

build:windows:
  stage: build
  script:
    - ./scripts/build-cross-compile.sh windows-x64
  artifacts:
    paths:
      - build-windows/

# Tests
test:messenger:
  stage: test
  script:
    - cd $BUILD_DIR && ctest --output-on-failure
  dependencies:
    - build:linux

# Deploy nodus
deploy:nodus:
  stage: deploy
  script:
    - ./scripts/deploy-nodus.sh
  only:
    - tags
  when: manual
```

### 9.2 Update Build Scripts
Update paths in:
- `scripts/build-android.sh`
- `scripts/build-cross-compile.sh`
- `scripts/build-nodus.sh`
- `scripts/push_both.sh`

---

## Phase 10: Update CLAUDE.md

Update CLAUDE.md to reflect new structure:

### Key Changes:
1. Update directory structure section
2. Update build commands
3. Update function reference paths
4. Update CLI paths
5. Add dnac section (placeholder)

### New Build Commands:
```bash
# Build messenger only
cmake -DBUILD_MESSENGER=ON -DBUILD_NODUS=OFF ..

# Build nodus only
cmake -DBUILD_MESSENGER=OFF -DBUILD_NODUS=ON ..

# Build everything
cmake -DBUILD_MESSENGER=ON -DBUILD_NODUS=ON ..

# Build with dnac (when ready)
cmake -DBUILD_DNAC=ON ..
```

---

## Phase 11: Verification

### 11.1 Verify Git Status
```bash
git status
# Should show many renames, no untracked files
```

### 11.2 Build Messenger
```bash
mkdir -p build && cd build
cmake -DBUILD_MESSENGER=ON ..
make -j$(nproc)
```

### 11.3 Build Nodus
```bash
cmake -DBUILD_NODUS=ON ..
make dna-nodus
```

### 11.4 Run Tests
```bash
ctest --output-on-failure
```

### 11.5 Verify CLI
```bash
./messenger/cli/dna-messenger-cli --help
```

### 11.6 Verify Flutter Builds
```bash
cd messenger/flutter
flutter pub get
flutter build linux --debug
```

---

## Phase 12: Commit and Push

### 12.1 Create Commit
```bash
git add -A
git commit -m "$(cat <<'EOF'
refactor: Restructure to multi-project monorepo

- Rename repo from dna-messenger to dna
- Create shared/crypto/ for NIST crypto (Kyber, Dilithium)
- Move messenger code to messenger/ subdirectory
- Extract nodus from vendor/opendht-pq/tools/ to nodus/
- Create dnac/ placeholder for DNA Coin
- Reorganize docs by project
- Update CMake for multi-project build

Structure:
- shared/crypto/ - Shared crypto library
- messenger/ - DNA Messenger (lib, cli, flutter, android)
- nodus/ - DHT Bootstrap server
- dnac/ - ZK ledger (placeholder)

Co-Authored-By: Claude Opus 4.5 <noreply@anthropic.com>
EOF
)"
```

### 12.2 Push
```bash
# Push to both remotes
git push gitlab main
git push origin main
```

---

## Rollback Procedure

If something goes wrong:

### Option 1: Git Reset (before push)
```bash
git reset --hard HEAD~1
```

### Option 2: Restore from Backup
```bash
cd /opt
rm -rf dna-messenger
mv dna-messenger-backup-YYYYMMDD dna-messenger
```

### Option 3: Git Revert (after push)
```bash
git revert HEAD
git push gitlab main
git push origin main
```

---

## Post-Migration Tasks

### Immediate
- [ ] Update all developer machines
- [ ] Update CI/CD server paths
- [ ] Update deployment scripts on nodus servers
- [ ] Update README badges/links

### Short-term
- [ ] Update external documentation
- [ ] Notify team of new structure
- [ ] Create migration notes for contributors

### Long-term
- [ ] Begin dnac development
- [ ] Consider splitting into separate repos if needed
- [ ] Set up per-project versioning

---

## File Movement Reference

### Complete File Map

| Source | Destination |
|--------|-------------|
| `crypto/kem/` | `shared/crypto/kem/` |
| `crypto/dsa/` | `shared/crypto/dsa/` |
| `crypto/bip39/` | `shared/crypto/bip39/` |
| `crypto/bip32/` | `shared/crypto/bip32/` |
| `crypto/utils/` | `shared/crypto/utils/` |
| `crypto/cellframe_dilithium/` | `shared/crypto/cellframe_dilithium/` |
| `qgp.h` | `shared/crypto/include/qgp.h` |
| `src/api/` | `messenger/lib/engine/` |
| `dht/` | `messenger/lib/dht/` |
| `p2p/` | `messenger/lib/p2p/` |
| `messenger/` | `messenger/lib/messenger/` |
| `messenger.c`, `messenger.h` | `messenger/lib/messenger/` |
| `messenger_*.c/h` | `messenger/lib/messenger/` |
| `message_backup.c/h` | `messenger/lib/messenger/` |
| `database/` | `messenger/lib/database/` |
| `blockchain/` | `messenger/lib/blockchain/` |
| `include/` | `messenger/lib/include/` |
| `dna_api.c/h` | `messenger/lib/engine/` |
| `dna_config.c/h` | `messenger/lib/engine/` |
| `cli/` | `messenger/cli/` |
| `dna_messenger_flutter/` | `messenger/flutter/` |
| `android/` | `messenger/android/` |
| `jni/` | `messenger/android/jni/` |
| `web/` | `messenger/web/` |
| `tests/` | `messenger/tests/` |
| `vendor/opendht-pq/tools/dna-nodus.cpp` | `nodus/src/` |
| `vendor/opendht-pq/tools/nodus_*.cpp/h` | `nodus/src/` |
| `vendor/opendht-pq/tools/turn_*.cpp/h` | `nodus/src/` |
| `vendor/opendht-pq/tools/tools_common.h` | `nodus/src/` |
| `vendor/opendht-pq/tools/dna-nodus.conf.*` | `nodus/config/` |
| `vendor/opendht-pq/tools/systemd/` | `nodus/config/systemd/` |
| `docs/*.md` (messenger) | `docs/messenger/` |
| `docs/functions/` | `docs/messenger/functions/` |
| `docs/DNA_NODUS.md` | `docs/nodus/` |

---

**Document Version:** 1.0.0
**Last Updated:** 2026-01-13
**Author:** Migration planned by Claude
