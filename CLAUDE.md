# DNA Monorepo - Development Guidelines

**Last Updated:** 2026-02-28

---

## IMPORTANT: Inherit Messenger Protocol

**The full EXECUTOR protocol, checkpoints, and development guidelines are in `messenger/CLAUDE.md`.**
All rules from that file apply here. This file only adds monorepo-specific context.

---

## Monorepo Structure

```
/opt/dna/
├── shared/          # Shared code (crypto libraries used by all projects)
│   └── crypto/      # Post-quantum crypto: Kyber, Dilithium, BIP39, utils
├── messenger/       # DNA Messenger (main project) - C library + Flutter app
├── dnac/            # DNA Cash - Post-quantum digital cash over DHT
├── cpunk/           # cpunk.io website (web project, no C build)
└── CLAUDE.md        # This file
```

## Git Repos

- **Monorepo**: `github.com/nocdem/dna` (new, all projects merged with preserved history)
- **Old repos** (kept as backup, DO NOT modify):
  - `/opt/dna-messenger` — original messenger repo (3027 commits)
  - `/opt/dnac` — original dnac repo (33 commits)
  - `/opt/cpunk` — original cpunk repo (17 commits)

## Build Commands

| Project | Build Command |
|---------|---------------|
| Messenger (C library) | `cd messenger/build && cmake .. && make -j$(nproc)` |
| dnac | `cd dnac/build && cmake .. && make -j$(nproc)` |
| Flutter app | `cd messenger/dna_messenger_flutter && flutter build linux` |
| cpunk | Web project — no C build |

**Build order matters:** Messenger must be built first (dnac links against `libdna_lib.so`).

## Shared Code (`shared/crypto/`)

All crypto code lives in `shared/crypto/` and is used by both messenger and dnac.

**Include pattern in source files:**
```c
#include "crypto/utils/qgp_sha3.h"    // Resolved via -I /opt/dna/shared
#include "crypto/utils/qgp_dilithium.h"
```

**CMake pattern in each project:**
```cmake
set(SHARED_DIR "${CMAKE_SOURCE_DIR}/../shared")
target_include_directories(my_target PUBLIC ${SHARED_DIR})
```

**NEVER use relative includes** like `../crypto/` or `../../crypto/`. Always use `crypto/...` resolved through include search paths.

## Version Files (INDEPENDENT)

| Component | Version File | Bump When |
|-----------|-------------|-----------|
| C Library | `messenger/include/dna/version.h` | Messenger C code changes |
| Flutter App | `messenger/dna_messenger_flutter/pubspec.yaml` | Flutter/Dart changes |
| Nodus Server | `messenger/vendor/opendht-pq/tools/nodus_version.h` | Nodus changes |
| DNAC | `dnac/CMakeLists.txt` (project VERSION) | DNAC changes |

## Push to Remote

```bash
cd /opt/dna
git push origin main
```

**Note:** GitLab mirror not yet configured for monorepo. Only GitHub for now.
