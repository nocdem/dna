# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Inherited Rules

**The full EXECUTOR protocol, checkpoints, and workflow rules are in `messenger/CLAUDE.md`.**
All rules from that file apply here. This file adds monorepo-wide context.

---

## Build Commands

All C projects use CMake. Build from each project's `build/` directory.

| Project | Build | Notes |
|---------|-------|-------|
| Messenger (C lib) | `cd messenger/build && cmake .. && make -j$(nproc)` | Must build first (dnac depends on it) |
| Nodus v5 | `cd nodus/build && cmake .. && make -j$(nproc)` | Independent build |
| DNAC | `cd dnac/build && cmake .. && make -j$(nproc)` | Links against `libdna_lib.so` from messenger |
| Flutter app | `cd messenger/dna_messenger_flutter && flutter build linux` | Requires messenger C lib built |
| Windows cross-compile | `cd messenger && ./build-cross-compile.sh windows-x64` | |
| cpunk | Web project, no C build | |

**Build order matters:** Messenger first, then dnac. Nodus is independent.

## Running Tests

| Project | Unit Tests | Integration Tests |
|---------|-----------|-------------------|
| Nodus | `cd nodus/build && ctest` (13 tests) | `bash nodus/tests/integration_test.sh` (SSH to 3-node cluster) |
| Messenger | `cd messenger/build && ctest` | CLI tool: `messenger/build/cli/dna-messenger-cli` |
| DNAC | `cd dnac/build && ./test_real`, `./test_gaps` (18 cases) | `./test_remote` (cross-machine) |

Run a single nodus test: `cd nodus/build && ./test_cbor` (or any `test_*` binary).

Run a single messenger test: `cd messenger/build && ./tests/test_kyber1024` (or any `test_*` binary).

## Git Identity

Git config is not set on this machine. Use env vars for commits:
```bash
GIT_AUTHOR_NAME="nocdem" GIT_AUTHOR_EMAIL="nocdem@cpunk.io" GIT_COMMITTER_NAME="nocdem" GIT_COMMITTER_EMAIL="nocdem@cpunk.io" git commit -m "message"
```

Push: `git push origin main` (GitHub only; GitLab mirror not yet configured for monorepo).

---

## Monorepo Architecture

```
/opt/dna/
├── shared/crypto/     # Post-quantum crypto (Kyber1024, Dilithium5, BIP39, SHA3)
├── messenger/         # DNA Messenger - C library + Flutter app
├── nodus/             # Nodus v5 - DHT server + client SDK (pure C)
├── dnac/              # DNA Cash - UTXO digital cash over DHT
└── cpunk/             # cpunk.io website
```

### How Projects Relate

```
┌──────────────────────────────────────────────────────┐
│  Flutter App (Dart)                                  │
│  messenger/dna_messenger_flutter/                    │
└──────────┬───────────────────────────────────────────┘
           │ FFI (dart:ffi)
┌──────────▼───────────────────────────────────────────┐
│  DNA Engine (C) - messenger/src/api/                 │
│  16 modular handlers + async task queue              │
├──────────────────────────────────────────────────────┤
│  Domain layers:                                      │
│  messenger/  dht/  transport/  database/  blockchain/│
└──────┬───────┬───────────────────────────────────────┘
       │       │ nodus_ops.c / nodus_init.c
       │  ┌────▼─────────────────────────────────┐
       │  │  Nodus v5 Client SDK (nodus/)        │
       │  │  Kademlia DHT + PBFT consensus       │
       │  │  TCP client ←→ Nodus server cluster  │
       │  └──────────────────────────────────────┘
       │
  ┌────▼──────────────────────┐    ┌──────────────────┐
  │  shared/crypto/           │    │  dnac/            │
  │  Kyber1024, Dilithium5,   │◄───│  UTXO cash system │
  │  SHA3-512, BIP39, AES-256 │    │  Links libdna_lib │
  └───────────────────────────┘    └──────────────────┘
```

### Messenger C Library Architecture

The DNA Engine (`messenger/src/api/dna_engine.c`) is a modular async C library with 16 domain modules in `messenger/src/api/engine/`:

| Module | Domain |
|--------|--------|
| `dna_engine_messaging.c` | Send/receive, conversations, retry |
| `dna_engine_contacts.c` | Contact requests, blocking |
| `dna_engine_groups.c` | Group CRUD, GEK encryption, invitations |
| `dna_engine_identity.c` | Identity create/load, profiles |
| `dna_engine_presence.c` | Heartbeat, presence lookup |
| `dna_engine_wallet.c` | Multi-chain wallet (Cellframe, ETH, SOL, TRON) |
| `dna_engine_backup.c` | DHT sync for all data types |
| `dna_engine_lifecycle.c` | Engine pause/resume (mobile) |
| `dna_engine_listeners.c` | DHT key subscriptions |
| `dna_engine_workers.c` | Background thread pool |

Public API: `messenger/include/dna/dna_engine.h` (async callbacks, opaque `dna_engine_t`).

New features follow the module pattern: add task type in `dna_engine_internal.h`, implement handler in module, add dispatch case in `dna_engine.c`, declare in `dna_engine.h`. See `messenger/src/api/engine/README.md`.

### Flutter FFI Pattern

Flutter connects to the C library via `dart:ffi`:
- **Binding generator config:** `messenger/dna_messenger_flutter/ffigen.yaml`
- **Generated bindings:** `lib/ffi/dna_bindings_generated.dart` (auto-generated, do not edit)
- **Dart wrapper:** `lib/ffi/dna_engine.dart` (converts C callbacks to Dart Futures/Streams)
- **State management:** Riverpod providers in `lib/providers/`

### Nodus v5 Architecture

Nodus is a post-quantum Kademlia DHT with PBFT consensus. Pure C, no C++ dependencies.

**Server layers:** UDP (Kademlia peer discovery) + TCP (client connections, replication)
**Protocol:** CBOR over wire frames (7-byte header: magic `0x4E44` + version + length)
**Two protocol tiers:** Tier 1 (Kademlia: ping/find_node/put/get) and Tier 2 (Client: auth/dht_put/dht_get/listen/channels)

**Key source files:**
- `nodus/include/nodus/nodus.h` — Client SDK public API
- `nodus/include/nodus/nodus_types.h` — Constants (512-bit keyspace, k=8, 7-day TTL, crypto sizes)
- `nodus/src/server/nodus_server.c` — Server event loop (epoll)
- `nodus/src/client/nodus_client.c` — Client SDK implementation
- `nodus/src/protocol/nodus_tier2.c` — Client protocol message dispatch

**Messenger integration:** `messenger/dht/shared/nodus_ops.c` wraps the nodus singleton with convenience functions (`nodus_ops_put`, `nodus_ops_get`, `nodus_ops_listen`). Lifecycle managed by `nodus_init.c`.

### DNAC Architecture

UTXO-based digital cash with BFT witness consensus:
- `dnac/src/wallet/` — UTXO management, coin selection, balance
- `dnac/src/transaction/` — TX building, verification, nullifiers, genesis
- `dnac/src/bft/` — PBFT consensus state machine, TCP mesh
- `dnac/src/witness/` — Witness server (nullifier DB, shared UTXO set, epoch/block management)
- Public API: `dnac/include/dnac/dnac.h`

---

## Shared Crypto (`shared/crypto/`)

All post-quantum crypto lives here. Used by messenger, nodus, and dnac.

**Include pattern in C source files:**
```c
#include "crypto/utils/qgp_sha3.h"       // Resolved via -I /opt/dna/shared
#include "crypto/utils/qgp_dilithium.h"
#include "crypto/utils/qgp_kyber.h"
```

**CMake pattern in each project:**
```cmake
set(SHARED_DIR "${CMAKE_SOURCE_DIR}/../shared")
target_include_directories(my_target PUBLIC ${SHARED_DIR})
```

**NEVER use relative includes** like `../crypto/`. Always use `crypto/...` resolved through include search paths.

**Key algorithms:**
| Algorithm | Header | Sizes |
|-----------|--------|-------|
| Dilithium5 (ML-DSA-87) | `crypto/utils/qgp_dilithium.h` | pubkey=2592B, secret=4896B, sig=4627B |
| Kyber1024 (ML-KEM-1024) | `crypto/utils/qgp_kyber.h` | pubkey=1568B, secret=3168B, ciphertext=1568B |
| SHA3-512 | `crypto/utils/qgp_sha3.h` | 64-byte digest |
| BIP39 | `crypto/bip39/bip39.h` | 12-24 word mnemonic phrases |

---

## Version Files (INDEPENDENT)

Each component has its own version. They do NOT need to match. Only bump the one that changed.

| Component | Version File | Bump When |
|-----------|-------------|-----------|
| C Library | `messenger/include/dna/version.h` | Messenger C code changes |
| Flutter App | `messenger/dna_messenger_flutter/pubspec.yaml` | Flutter/Dart changes |
| Nodus v5 | `nodus/include/nodus/nodus_types.h` (`NODUS_VERSION_*`) | Nodus code changes |
| DNAC | `dnac/include/dnac/version.h` | DNAC changes |

---

## Code Conventions

### Logging (C code)

Always use QGP_LOG macros. Never `printf()` or `fprintf()`.
```c
#include "crypto/utils/qgp_log.h"
#define LOG_TAG "MODULE_NAME"

QGP_LOG_DEBUG(LOG_TAG, "msg: %s", var);
QGP_LOG_INFO(LOG_TAG, "msg: %d", num);
QGP_LOG_WARN(LOG_TAG, "msg");
QGP_LOG_ERROR(LOG_TAG, "msg: %s", err);
```

### Logging (Flutter/Dart)

Always use `DnaLogger`. Never `print()` or `debugPrint()`.
```dart
import '../utils/logger.dart';
DnaLogger.log('TAG', 'Message');
DnaLogger.error('TAG', 'Error message');
```

### Platform Abstraction

C platform-specific code goes in `shared/crypto/utils/qgp_platform_*.c` (linux, windows, android). New platform functions must be implemented in all three files and declared in `qgp_platform.h`.

Flutter platform code uses the handler pattern: `lib/platform/platform_handler.dart` (abstract) with `android/` and `desktop/` implementations. Never use `Platform.isAndroid` in business logic.

### Flutter Icons

Always use Font Awesome (`FaIcon(FontAwesomeIcons.xxx)`), never Material Icons.

### Windows Portability

- `%llu`/`%lld` with casts for `uint64_t`/`int64_t` (Windows `long` is 32-bit)
- `#ifdef _MSC_VER` around MSVC pragmas
- `winsock2.h` before `windows.h`

---

## Local Testing Policy

- **BUILD ONLY**: Verify compilation succeeds. This machine has no monitor.
- **NEVER** launch GUI apps (Flutter, dna-messenger)
- **FULL BUILD OUTPUT**: Never pipe build output through `tail`/`grep`/`head`. Show everything (unless >30000 chars).
- CLI tool (`messenger/build/cli/dna-messenger-cli`) is available for non-GUI testing.

---

## Infrastructure

### Nodus v5 Test Cluster (running v0.5.0)
| Node | IP | Ports |
|------|-----|-------|
| nodus-01 | 161.97.85.25 | UDP 4000, TCP 4001 |
| nodus-02 | 156.67.24.125 | UDP 4000, TCP 4001 |
| nodus-03 | 156.67.25.251 | UDP 4000, TCP 4001 |

### Production Nodus Servers (v0.4.5)
| Node | IP |
|------|-----|
| US-1 | 154.38.182.161 |
| EU-1 | 164.68.105.227 |
| EU-2 | 164.68.116.180 |

### Old Repos (backup, DO NOT modify)
- `/opt/dna-messenger` — original messenger repo
- `/opt/dnac` — original dnac repo
- `/opt/cpunk` — original cpunk repo

---

## Key Documentation

- `messenger/docs/functions/` — Authoritative function signature reference (check before calling existing APIs)
- `messenger/docs/ARCHITECTURE_DETAILED.md` — Detailed system architecture
- `messenger/docs/PROTOCOL.md` — Wire formats (Seal, Spillway, Anchor, Atlas, Nexus)
- `messenger/docs/CLI_TESTING.md` — CLI tool reference
- `messenger/docs/FUZZING.md` — Fuzz testing guide
- `messenger/src/api/engine/README.md` — How to add new engine modules
- `nodus/docs/` — Nodus deployment documentation
- `dnac/README.md` — DNAC architecture, CLI commands, transaction format

**Priority:** Security, correctness, simplicity. When in doubt, ask.
