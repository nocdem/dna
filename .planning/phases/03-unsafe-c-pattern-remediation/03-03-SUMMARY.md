---
phase: 03-unsafe-c-pattern-remediation
plan: 03
subsystem: security
tags: [c, poison-pragma, anti-regression, sprintf, hex-loop, nodus]

# Dependency graph
requires:
  - phase: 03-unsafe-c-pattern-remediation
    plan: 01
    provides: "shared/crypto/utils/qgp_safe_string.h poison header"
provides:
  - "Zero strcpy / zero sprintf in first-party nodus translation units"
  - "41 first-party nodus/src/ and nodus/tools/ .c files now carry the poison include — future strcpy/sprintf in nodus is a compile error"
  - "26 sprintf hex-loop sites replaced with the bounded keep-loop snprintf form"
affects: [03-04-messenger-blockchain-cli, 03-05-messenger-engine-dht]

# Tech tracking
tech-stack:
  added: []
  patterns:
    - "Keep-loop snprintf: `snprintf(&buf[i*2], sizeof(buf) - i*2, \"%02x\", bytes[i])` over fixed-size local arrays"
    - "For caller-provided pointer destinations, use the documented caller-side literal for the size arg (nodus_media_handler.c uses NODUS_KEY_HEX_LEN)"
    - "Poison include placed after last #include in each TU (plans 03-01/03-02 convention)"

key-files:
  created: []
  modified:
    - nodus/src/server/nodus_server.c           # 15 sprintf sites + poison include
    - nodus/src/core/nodus_value.c              # 4 sprintf sites + poison include
    - nodus/src/core/nodus_storage.c            # 3 sprintf sites + poison include
    - nodus/src/server/nodus_auth.c             # 2 sprintf sites + poison include
    - nodus/src/server/nodus_media_handler.c    # 1 sprintf site + poison include
    - nodus/tools/nodus-cli.c                   # 1 sprintf site + poison include
    - nodus/src/channel/nodus_channel_primary.c      # poison include
    - nodus/src/channel/nodus_channel_replication.c  # poison include
    - nodus/src/channel/nodus_channel_ring.c         # poison include
    - nodus/src/channel/nodus_channel_server.c       # poison include
    - nodus/src/channel/nodus_channel_store.c        # poison include
    - nodus/src/channel/nodus_hashring.c             # poison include
    - nodus/src/circuit/nodus_circuit.c              # poison include
    - nodus/src/circuit/nodus_inter_circuit.c        # poison include
    - nodus/src/client/nodus_client.c                # poison include
    - nodus/src/client/nodus_republish.c             # poison include
    - nodus/src/client/nodus_singleton.c             # poison include
    - nodus/src/consensus/nodus_cluster.c            # poison include
    - nodus/src/core/nodus_media_storage.c           # poison include
    - nodus/src/core/nodus_routing.c                 # poison include
    - nodus/src/crypto/nodus_channel_crypto.c        # poison include
    - nodus/src/crypto/nodus_identity.c              # poison include
    - nodus/src/crypto/nodus_sign.c                  # poison include
    - nodus/src/nodus_log_shim.c                     # poison include
    - nodus/src/protocol/nodus_cbor.c                # poison include
    - nodus/src/protocol/nodus_tier1.c               # poison include
    - nodus/src/protocol/nodus_tier2.c               # poison include
    - nodus/src/protocol/nodus_tier3.c               # poison include
    - nodus/src/protocol/nodus_wire.c                # poison include
    - nodus/src/server/nodus_presence.c              # poison include
    - nodus/src/transport/nodus_tcp.c                # poison include
    - nodus/src/transport/nodus_udp.c                # poison include
    - nodus/src/witness/nodus_witness.c              # poison include
    - nodus/src/witness/nodus_witness_bft.c          # poison include
    - nodus/src/witness/nodus_witness_db.c           # poison include
    - nodus/src/witness/nodus_witness_handlers.c     # poison include
    - nodus/src/witness/nodus_witness_mempool.c      # poison include
    - nodus/src/witness/nodus_witness_peer.c         # poison include
    - nodus/src/witness/nodus_witness_sync.c         # poison include
    - nodus/src/witness/nodus_witness_verify.c       # poison include
    - nodus/tools/nodus-server.c                     # poison include

key-decisions:
  - "All 26 nodus hex-loop sites use D-08 keep-loop variant (preserves loop structure, mechanical diff, easiest review)"
  - "nodus_media_handler.c fp_to_hex uses NODUS_KEY_HEX_LEN literal (129) instead of sizeof(hex_out) because hex_out is a function-parameter array that decays to a pointer"
  - "Poison include placed after existing includes (plans 03-01/03-02 convention) — nodus_server.c's two-segment include block honored by inserting after the trailing <fcntl.h>/<errno.h> block"

patterns-established:
  - "For function-parameter destinations declared with array-syntax (`char hex_out[MACRO]`), use the MACRO literal at the call site — sizeof(arr_param) is sizeof(char*) inside the function"

requirements-completed: []  # SAFE-01 remains open until 03-04 and 03-05 land

# Metrics
duration: ~6min
completed: 2026-04-14
---

# Phase 03 Plan 03: nodus/ sprintf Hex-Loop Sweep Summary

**Replaced all 26 sprintf hex-loop call sites in nodus first-party code with the bounded keep-loop snprintf form and deployed `qgp_safe_string.h` poison include across all 41 first-party .c files under `nodus/src/` and `nodus/tools/` — the nodus client + server + tools + witness subsystem are now locked against strcpy/sprintf regression at compile time on both Linux gcc 12.2 and llvm-mingw-20251118 clang. Zero new warnings on either toolchain. nodus has no vendor subtrees so every .c file is first-party.**

## Performance

- **Duration:** ~6 min
- **Tasks:** 3 (1 code-change commit for 26 sprintf replacements + 1 poison-include commit for 41 files + 1 build-matrix verification)
- **Files modified:** 41 nodus first-party .c files
- **Commits:** 2

## Accomplishments

- **All 26 sprintf sites replaced** with the D-08 keep-loop variant. Site counts match the research inventory exactly:
  - `nodus/src/server/nodus_server.c`: 15 sites (kh/fp_hex/rpl_kh/mkh/ga_kh/bfkh locals)
  - `nodus/src/core/nodus_value.c`: 4 sites (key_hex/comp_hex/stored_hex/owner_hex)
  - `nodus/src/core/nodus_storage.c`: 3 sites (kh/own_hex/new_hex)
  - `nodus/src/server/nodus_auth.c`: 2 sites (old_fp/fp_hex)
  - `nodus/src/server/nodus_media_handler.c`: 1 site (fp_to_hex helper — caller-provided pointer)
  - `nodus/tools/nodus-cli.c`: 1 site (node_id_hex)
- **41 first-party .c files** in nodus now include `#include "crypto/utils/qgp_safe_string.h"` as the last include in their include block. nodus has **zero vendor subtrees**, so all 41 .c files under `nodus/src/` and `nodus/tools/` are first-party per research, and all 41 got the poison include.
- **nodus Linux native build is clean** — 0 warnings, 0 errors (standalone + in-tree).
- **messenger Linux native build is clean** — 0 warnings, 0 errors (pulls in nodus via messenger/dht/shared/nodus_ops.c — validates in-tree build path).
- **dnac Linux native build is clean** — 0 warnings, 0 errors.
- **Windows cross-compile of `libdna.a`** including all 41 modified nodus TUs: clean. Zero new warnings from nodus under llvm-mingw clang. The only failures in the cross build are the pre-existing `messenger/cli/cli_commands.c` mkdir/gmtime_r errors (documented in Phase 1 deferred-items.md and carried into Phase 3 deferred-items.md). libdna.a + nodus objects build fine; only the final cli executable link is blocked, which is orthogonal to plan 03-03's scope.
- **messenger ctest:** 16/17 passing, `test_gek_ratchet` Not Run (pre-existing Phase 1 deferred link failure — baseline identical to 03-02).
- **nodus ctest:** 33/38 passing; the 5 failures (`test_identity`, `test_put_if_newer`, `test_hinted_handoff`, `test_fetch_batch`, `test_storage_cleanup`) were verified pre-existing — they fail identically on the pre-Phase-3 commit `787500ff` (see Deferred Issues below). Plan 03-03 introduced zero nodus-test regressions.
- **Zero public header diff** vs plan 03-02 end-state: `git diff d2ba4aae..HEAD -- 'nodus/include/**/*.h' 'messenger/include/**/*.h' 'dnac/include/**/*.h' 'shared/crypto/**/*.h' → 0 lines`. D-26 satisfied.

## Task Commits

1. **Task 1: Replace 26 sprintf hex-loop sites** — `62b1a8d4` (fix)
   - 15 × `nodus_server.c` sites converted to `snprintf(&<buf>[i*2], sizeof(<buf>) - i*2, "%02x", <bytes>[i])`
   - 4 × `nodus_value.c` sites (same pattern)
   - 3 × `nodus_storage.c` sites (same pattern)
   - 2 × `nodus_auth.c` sites (same pattern with `k` loop variable — preserved)
   - 1 × `nodus_media_handler.c:28` — used `NODUS_KEY_HEX_LEN - i*2` because `hex_out` is a function-parameter array that decays to pointer (sizeof would return 8)
   - 1 × `nodus-cli.c:287` — used `sizeof(node_id_hex)` (local fixed-size array)

2. **Task 2: Add poison include to 41 nodus first-party .c files** — `051d7aeb` (feat)
   - Every .c file under `nodus/src/` and `nodus/tools/` received `#include "crypto/utils/qgp_safe_string.h"   /* Phase 03: unsafe-string poison guard */` as the last include in its include block.
   - No .h files touched. No `nodus/CMakeLists.txt` changes — research verified `${SHARED_DIR}/crypto` already in include path.
   - Script-driven insertion (Python) to handle 41 files uniformly after verifying include-block convention in a handful of representative files.

3. **Task 3: Build matrix + ctest regression check** — no commit (verification only).
   - nodus Linux native: clean (0 warnings).
   - messenger Linux native + tests/build: clean, 16/17 tests pass (test_gek_ratchet Not Run, pre-existing).
   - dnac Linux native: clean.
   - llvm-mingw Windows cross: libdna.a + all nodus objects build cleanly; pre-existing cli_commands.c mkdir/gmtime_r cli-link failures remain (Phase-1 deferred).
   - Public header diff: 0 lines.

## Files Created/Modified

**Created:** None.

**Modified (41 nodus first-party .c files):**

Area: channel (6 files) — poison include only
- `nodus_channel_primary.c`, `nodus_channel_replication.c`, `nodus_channel_ring.c`, `nodus_channel_server.c`, `nodus_channel_store.c`, `nodus_hashring.c`

Area: circuit (2 files) — poison include only
- `nodus_circuit.c`, `nodus_inter_circuit.c`

Area: client (3 files) — poison include only
- `nodus_client.c`, `nodus_republish.c`, `nodus_singleton.c`

Area: consensus (1 file) — poison include only
- `nodus_cluster.c`

Area: core (4 files)
- `nodus_value.c` — 4 sprintf sites + poison include
- `nodus_storage.c` — 3 sprintf sites + poison include
- `nodus_media_storage.c`, `nodus_routing.c` — poison include only

Area: crypto (3 files) — poison include only
- `nodus_channel_crypto.c`, `nodus_identity.c`, `nodus_sign.c`

Area: protocol (5 files) — poison include only
- `nodus_cbor.c`, `nodus_tier1.c`, `nodus_tier2.c`, `nodus_tier3.c`, `nodus_wire.c`

Area: server (4 files)
- `nodus_server.c` — 15 sprintf sites + poison include
- `nodus_auth.c` — 2 sprintf sites + poison include
- `nodus_media_handler.c` — 1 sprintf site + poison include
- `nodus_presence.c` — poison include only

Area: transport (2 files) — poison include only
- `nodus_tcp.c`, `nodus_udp.c`

Area: witness (8 files) — poison include only
- `nodus_witness.c`, `nodus_witness_bft.c`, `nodus_witness_db.c`, `nodus_witness_handlers.c`, `nodus_witness_mempool.c`, `nodus_witness_peer.c`, `nodus_witness_sync.c`, `nodus_witness_verify.c`

Area: top-level (1 file) — poison include only
- `nodus_log_shim.c`

Area: tools (2 files)
- `nodus-cli.c` — 1 sprintf site + poison include
- `nodus-server.c` — poison include only

**Zero public header diff:** `git diff d2ba4aae..HEAD -- 'nodus/include/**/*.h' 'messenger/include/**/*.h' 'dnac/include/**/*.h' 'shared/crypto/**/*.h'` returns 0 lines.

## Decisions Made

- **D-08 keep-loop variant, uniform across all 26 sites.** Plan explicitly instructed this; no site was collapsed to a single snprintf. Rationale: smaller diff, mechanical uniformity, easier review.
- **`nodus_media_handler.c:28` caller-provided pointer special-case:** `hex_out` is declared as `char hex_out[NODUS_KEY_HEX_LEN]` in the function signature — but C decays array parameters to pointers, so `sizeof(hex_out)` would return `sizeof(char*)` = 8 (not 129). Used the `NODUS_KEY_HEX_LEN` macro directly as the size literal. This is the pattern for all future function-parameter array destinations.
- **Insertion placement in `nodus_server.c`:** the file has an unusual split include block (project headers → `#define LOG_TAG` → system headers → blank line → code). The poison include was placed after the trailing `<errno.h>` system header, in the blank line before the first function/#define — ensuring D-18 ordering constraint (after all system headers including `<stdio.h>`) is satisfied.

## Deviations from Plan

None. Plan 03-03 executed exactly as written:
- All 26 sprintf sites replaced at the exact line numbers specified in research.
- All 41 files got the poison include.
- Uniform keep-loop form with the one documented exception (media_handler's caller-pointer case).
- No file ordering or include convention changes.
- No CMake modifications.
- No public header touches.

## Verification Results

| Gate | Requirement | Result |
|------|-------------|--------|
| Zero strcpy/sprintf in nodus first-party | `grep -rn "\bstrcpy\s*(\|\bsprintf\s*(" nodus/src/ nodus/tools/ nodus/include/ --include="*.c" --include="*.h"` | PASS (0 lines) |
| nodus_server.c site count | `grep -c "snprintf(&" nodus/src/server/nodus_server.c` ≥ 15 | PASS (15 matches) |
| nodus_value.c site count | `grep -c "snprintf(&" nodus/src/core/nodus_value.c` ≥ 4 | PASS (4 matches) |
| nodus_storage.c site count | `grep -c "snprintf(&" nodus/src/core/nodus_storage.c` ≥ 3 | PASS (3 matches) |
| nodus_auth.c site count | `grep -c "snprintf(" nodus/src/server/nodus_auth.c` ≥ 2 | PASS |
| 41 first-party files have poison include | `grep -l "qgp_safe_string.h" nodus/src nodus/tools -r \| wc -l` | PASS (41/41) |
| nodus Linux native build clean | `cd nodus/build && make -j$(nproc)` | PASS (0 warnings, 0 errors) |
| messenger Linux native build clean | `cd messenger/build && make -j$(nproc)` | PASS (0 warnings, 0 errors) |
| dnac Linux native build clean | `cd dnac/build && make -j$(nproc)` | PASS (0 warnings, 0 errors) |
| messenger/tests/build ctest | `ctest --output-on-failure` | PASS — 16/17, test_gek_ratchet Not Run (Phase 1 deferred) |
| nodus ctest regression check | no new failures vs pre-Phase-3 | PASS (5 pre-existing failures, identical to commit 787500ff — see Deferred Issues) |
| Windows cross libdna.a + nodus objects | `./build-cross-compile.sh windows-x64` | PASS for libdna.a + all nodus objects (0 nodus warnings); only pre-existing cli_commands.c mkdir/gmtime_r cli-link failure remains |
| Zero public header diff vs 03-02 end | `git diff d2ba4aae..HEAD -- '**/include/**/*.h' 'shared/crypto/**/*.h'` | PASS (0 lines) |
| Orphan nodus_init.c diff untouched | `git status --short messenger/dht/shared/nodus_init.c` | PASS (still present as unstaged comment-only diff) |
| Orphan .gitignore diff untouched | `git status --short .gitignore` | PASS (still present) |

## Deferred Issues

The 5 nodus ctest failures observed during Task 3 verification (`test_identity`, `test_put_if_newer`, `test_hinted_handoff`, `test_fetch_batch`, `test_storage_cleanup`) were verified pre-existing by checking out the pre-Phase-3 commit `787500ff`, rebuilding nodus, and re-running the same ctest subset — all 5 fail identically on the pre-Phase-3 baseline. Symptoms are "readonly database", storage cleanup return = -1, and identity save-path failures, which look like persistent test-data/state issues in `nodus/build/` not caused by code changes. These are orthogonal to plan 03-03's scope and are logged here for tracking. They were NOT present in plan 03-02's SUMMARY because 03-02 did not run nodus ctest; the baseline existed before 03-03 discovered it.

Recommendation: a future focused plan should investigate whether these are test-data staleness (pre-existing .db files in build/), missing fixture reset, or actual regressions from earlier commits. For plan 03-03's purposes they are pre-existing and non-blocking.

## Authentication Gates

None.

## Next Plan Readiness

- `shared/crypto/utils/qgp_safe_string.h` is now included by 90 first-party .c files across dnac (20) + shared/crypto (29) + nodus (41). Plans 03-04 (messenger blockchain/config/cli) and 03-05 (messenger engine/dht) are the remaining Wave 2 plans before SAFE-01 can be marked complete.
- The keep-loop variant is the established pattern for hex-format loops; plans 03-04/03-05 should apply it uniformly to any sprintf hex loops they encounter in messenger.
- The caller-provided-pointer special case (use explicit literal from the caller's documented size macro) is now documented as a micro-pattern.
- nodus ctest has 5 pre-existing failures that future work should address; they are not regressions and not blocking any Phase 3 plan.

## Self-Check: PASSED

- FOUND: nodus/src/server/nodus_server.c contains 15 snprintf hex-loop sites (counted via `grep -c "snprintf(kh\|snprintf(fp_hex\|snprintf(rpl_kh\|snprintf(mkh\|snprintf(ga_kh\|snprintf(bfkh"`)
- FOUND: nodus/src/core/nodus_value.c contains 4 snprintf hex-loop sites
- FOUND: nodus/src/core/nodus_storage.c contains 3 snprintf hex-loop sites
- FOUND: nodus/src/server/nodus_auth.c contains 2 snprintf hex-loop sites
- FOUND: nodus/src/server/nodus_media_handler.c contains `snprintf(hex_out + i * 2, NODUS_KEY_HEX_LEN - i * 2`
- FOUND: nodus/tools/nodus-cli.c contains `snprintf(node_id_hex + b * 2, sizeof(node_id_hex)`
- FOUND: 41/41 first-party nodus .c files contain `crypto/utils/qgp_safe_string.h`
- FOUND: 0 first-party nodus files contain strcpy/sprintf in code
- FOUND: commit `62b1a8d4` (Task 1 — sprintf replacements)
- FOUND: commit `051d7aeb` (Task 2 — poison include deployment)
- FOUND: nodus native Linux build clean
- FOUND: messenger native Linux build clean
- FOUND: dnac native Linux build clean
- FOUND: messenger/tests/build ctest 16 pass, 1 Not Run (pre-existing)
- FOUND: zero public header diff vs plan 03-02 end-state

---
*Phase: 03-unsafe-c-pattern-remediation*
*Completed: 2026-04-14*
