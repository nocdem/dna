# Dead Code Audit — DNA Messenger C Library
**Date:** 2026-02-23 | **Status:** DOUBLE-VERIFIED (manually, no agents)

Every claim verified TWICE by grepping all .c, .h, .cpp, .dart files across all source
directories: src/, dht/, messenger/, transport/, database/, crypto/, blockchain/, cli/,
jni/, tests/, dna_messenger_flutter/.
(Note: `vendor/opendht-pq/tools/` was also searched at audit time but has since been removed; OpenDHT replaced by Nodus.)

Zero false positives remain. All items below are confirmed dead code.

---

## 1. Unimplemented Public API Functions (2)

| Function | File | Line | Verdict |
|---|---|---|---|
| `dna_engine_start_watermark_listener()` | `include/dna/dna_engine.h` | 2485 | DEAD — declared, zero .c implementations |
| `dna_engine_cancel_all_watermark_listeners()` | `include/dna/dna_engine.h` | 2497 | DEAD — declared, zero .c implementations |

**Also in:** `docs/functions/public-api.md` lines 154-155
**Reason:** Watermark system superseded by ACK listeners (v15).

---

## 2. Dead Callback Typedef (1)

| Type | File | Line | Verdict |
|---|---|---|---|
| `dna_identities_cb` typedef | `include/dna/dna_engine.h` | 345-351 | DEAD — never assigned/invoked |
| `.identities` union member | `src/api/dna_engine_internal.h` | 406 | DEAD — struct field never written |

**Also excluded in:** `dna_messenger_flutter/ffigen.yaml` line 102
**Reason:** `dna_engine_list_identities()` removed in v0.3.0 (single-user model).

---

## 3. Compiled But Never Called — DHT Modules (4 modules, 8 files)

These are compiled into `dht_lib.a` (dht/CMakeLists.txt lines 27, 30, 44-45) but no function from them is ever called from outside their own .c file.

| Module | Files | CMake Line | Verdict |
|---|---|---|---|
| Message Wall (old) | `dht/client/dna_message_wall.c` + `.h` | 44 | DEAD — 0 external callers |
| Wall Votes (old) | `dht/client/dna_wall_votes.c` + `.h` | 45 | DEAD — 0 external callers |
| DHT Profile (old) | `dht/shared/dht_profile.c` + `.h` | 27 | DEAD — 0 external callers |
| DHT Publish Queue | `dht/shared/dht_publish_queue.c` + `.h` | 30 | DEAD — 0 external callers (only a comment in dna_engine.h:682) |

**Searched in:** src/, cli/, jni/, messenger/, transport/, database/, tests/
(Note: `vendor/opendht-pq/tools/` was also searched at audit time but has since been removed.)
**Reason:** Old wall/votes replaced by Feed system (`dna_engine_feed.c`). Old profile replaced by engine profile system. Publish queue never integrated.

---

## 4. Unused Header (1)

| Header | Verdict |
|---|---|
| `dht/core/dht_errors.h` | DEAD — 0 `#include` anywhere, enum values never used in any .c file |

**Reason:** Standardized error codes that were planned but never adopted.

---

## 5. Orphaned Source Files (3) — Not in any CMakeLists.txt

| File | What | Verdict |
|---|---|---|
| `crypto/kem/PQCgenKAT_kem.c` | NIST KAT test generator | DEAD — not compiled |
| `crypto/kem/speed_print.c` | Kyber benchmark | DEAD — not compiled |
| `crypto/dsa/test/speed_print.c` | Dilithium benchmark | DEAD — not compiled |

---

## 6. Unused Event Enum Values (5) — Never fired from C, never handled in Dart

| Enum Value | Header Line | Verdict |
|---|---|---|
| `DNA_EVENT_MESSAGE_READ` | 610 | DEAD — never assigned in .c, never handled in .dart |
| `DNA_EVENT_GROUP_MEMBER_JOINED` | 614 | DEAD — never assigned in .c, never handled in .dart |
| `DNA_EVENT_GROUP_MEMBER_LEFT` | 615 | DEAD — never assigned in .c, never handled in .dart |
| `DNA_EVENT_DHT_PUBLISH_COMPLETE` | 623 | DEAD — never assigned in .c, never handled in .dart |
| `DNA_EVENT_DHT_PUBLISH_FAILED` | 624 | DEAD — never assigned in .c, never handled in .dart |

**Note:** Defined in `dna_bindings.dart` lines 527, 531-532, 540-541 but never dispatched.
These are harmless reserved placeholders for planned features. Removal is optional.

---

## 7. Unused Enum Type (1)

| Type | File | Line | Verdict |
|---|---|---|---|
| `dna_gas_speed_t` | `include/dna/dna_engine.h` | 2121-2125 | DEAD — type never referenced, values never used by name |

Function signatures use `int gas_speed` instead of `dna_gas_speed_t`.

---

## 8. Stale install.sh Dependencies

| File | Lines | Dead Deps | Verdict |
|---|---|---|---|
| `install.sh` | 94-99 | `libglfw3-dev`, `libglew-dev`, `libfreetype6-dev`, `libgl1-mesa-dev` | DEAD — ImGui/OpenGL deps, not in any CMakeLists.txt or .cmake |

---

## 9. Stale Build Directories (~392 MB)

| Directory | Size | Last Modified | Verdict |
|---|---|---|---|
| `build-release/` | 99 MB | 2025-11-18 | EXISTS — 3 months old |
| `build-test/` | 2.6 MB | 2025-12-06 | EXISTS — 2.5 months old |
| `build-dna-send/` | 2.6 MB | 2025-12-06 | EXISTS — 2.5 months old |
| `build-asan/` | 213 MB | 2026-01-23 | EXISTS — 1 month old |
| `build_test/` | 75 MB | 2026-01-15 | EXISTS — 1.5 months old |

User decision required on which to delete.

---

## Summary

| # | Category | Items | Safe to Remove |
|---|---|---|---|
| 1 | Unimplemented API functions | 2 | Yes |
| 2 | Dead callback typedef | 1 (+1 union member) | Yes |
| 3 | Compiled-but-unused DHT modules | 4 modules (8 files, ~2,250 lines) | Yes |
| 4 | Unused header | 1 file (~87 lines) | Yes |
| 5 | Orphaned source files | 3 files | Yes |
| 6 | Unused event enum values | 5 values | Optional (reserved) |
| 7 | Unused enum type | 1 type | Optional |
| 8 | Stale install.sh deps | 4 packages | Yes |
| 9 | Stale build directories | 5 dirs (~392 MB) | User decision |
