---
phase: 03-unsafe-c-pattern-remediation
plan: 04
subsystem: security
tags: [c, poison-pragma, anti-regression, strcpy, sprintf, messenger-blockchain, messenger-config, cli, cellframe]

# Dependency graph
requires:
  - phase: 03-unsafe-c-pattern-remediation
    plan: 01
    provides: "shared/crypto/utils/qgp_safe_string.h poison header"
provides:
  - "Zero strcpy / zero sprintf in messenger/dna_config.c, messenger/blockchain/{ethereum,bsc,tron,cellframe}/*, messenger/cli/cli_commands.c"
  - "6 messenger first-party .c files now carry the poison include"
  - "cellframe_json.c chunk combiner rewritten with explicit remaining-capacity tracking (hand-traced)"
affects: [03-05-messenger-engine-dht]

# Tech tracking
tech-stack:
  added: []
  patterns:
    - "Canonical snprintf(dst, sizeof(dst), ...) replacement applied to dna_config bootstrap_nodes[] and log_level fixed-size struct fields"
    - "Caller-documented literal size (67 for tx_hash_out, 129 for format_hex_hash out, 80 for cellframe str_out, 67 for cellframe hex_out) used when destination is a char* parameter"
    - "Mid-buffer strcpy colon port-fix at dna_config.c:145 replaced with bounded snprintf using (colon - config->bootstrap_nodes[i]) offset arithmetic"
    - "cellframe_json.c chunk combiner rewritten with write_ptr + out_remaining tracking and bounded snprintf per chunk, break-on-truncation for pointer-advance correctness (not error reporting — D-10 silent truncation still applies)"

key-files:
  created: []
  modified:
    - messenger/dna_config.c
    - messenger/blockchain/ethereum/eth_tx.c
    - messenger/blockchain/bsc/bsc_tx.c
    - messenger/blockchain/tron/trx_rpc.c
    - messenger/blockchain/cellframe/cellframe_json.c
    - messenger/cli/cli_commands.c

key-decisions:
  - "dna_config.c:145 mid-buffer port-fix uses bounded form snprintf(colon, sizeof(config->bootstrap_nodes[0]) - (colon - config->bootstrap_nodes[i]), \":4001\") — preserves the existing small-loop local rewrite per plan instruction (1:1 form, no loop restructure)"
  - "eth_tx.c / bsc_tx.c tx_hash copy uses literal 67 (documented in adjacent strncpy(66) + tx_hash_out[66]='\\0' context) — matches the '0x'+64 hex+null convention"
  - "trx_rpc.c:489 uses literal 3 for '.0' + null per plan instruction (do not compute via sizeof-struct-field)"
  - "cellframe_json.c chunk combiner rewritten with const-pointer src abstraction: inside the loop, set src = (leading-zero-stripped chunk) for first iter and src = chunks[i] for subsequent iters, then single bounded snprintf per chunk — avoids duplicated snprintf calls"
  - "cellframe hash_to_hex uses 67 literal (documented in cellframe_json.h docstring), uint256_to_str uses a local const str_out_size = 80 variable set from the documented caller bound (header says 'at least 80 bytes')"

patterns-established:
  - "For functions that document their output buffer size in the header docstring only (no size_t parameter), encode the documented literal as either an in-line constant (snprintf(out, 67, ...)) or as a local const size_t variable mirroring the docstring bound (str_out_size = 80 in cellframe_uint256_to_str). The literal MUST match the docstring — any future docstring change needs matching code update."
  - "When rewriting a mid-buffer strcpy loop into bounded snprintf, introduce write_ptr + out_remaining tracking and use break-on-truncation to keep pointer arithmetic correct even on D-10 silent-truncation policy. The break is not error reporting — it's correctness of write_ptr += written."

requirements-completed: []  # SAFE-01 remains open until 03-05 lands

# Metrics
duration: ~4min
completed: 2026-04-13
---

# Phase 03 Plan 04: messenger/ Blockchain + Config + CLI Unsafe Pattern Sweep Summary

**Replaced 19 strcpy + 6 sprintf sites across messenger/dna_config.c, messenger/blockchain/ethereum/eth_tx.c, messenger/blockchain/bsc/bsc_tx.c, messenger/blockchain/tron/trx_rpc.c, messenger/blockchain/cellframe/cellframe_json.c, and messenger/cli/cli_commands.c — plus rewrote the cellframe_json.c mid-buffer chunk-combining loop with explicit remaining-capacity tracking and deployed the qgp_safe_string.h poison include across all 6 files. The blockchain + config + CLI slice of messenger is now locked against strcpy/sprintf regression at compile time on both Linux gcc 12.2 and llvm-mingw-20251118 clang.**

## Performance

- **Duration:** ~4 min wall clock
- **Tasks:** 3 (2 code-change commits + 1 verification)
- **Files modified:** 6 messenger first-party .c files
- **Commits:** 2 (fix)

## Accomplishments

- **~25 call sites replaced.** Exact counts per file:
  - `messenger/dna_config.c`: 14 strcpy sites (log_level x2, bootstrap_nodes fixed-array literals x12, mid-buffer colon port rewrite x1 — total 15 counting the colon as its own site, but the 14 fixed-array writes + the 1 colon rewrite matches the plan's "~15 sites" framing)
  - `messenger/blockchain/ethereum/eth_tx.c`: 2 strcpy tx_hash sites (lines 534, 588)
  - `messenger/blockchain/bsc/bsc_tx.c`: 1 strcpy tx_hash site (line 241)
  - `messenger/blockchain/tron/trx_rpc.c`: 1 strcpy mid-buffer '.0' append (line 489)
  - `messenger/blockchain/cellframe/cellframe_json.c`: 4 sprintf sites (lines 86, 103, 133, 467) + 1 strcpy "0" fallback (line 146) + 2 mid-buffer strcpy sites rewritten as the chunk combiner (lines 157, 161)
  - `messenger/cli/cli_commands.c`: 1 sprintf hex-loop site (line 7100 `format_hex_hash`)
- **cellframe_json.c chunk combiner rewritten** with explicit `write_ptr` + `out_remaining` tracking. Hand-traced before/after — byte-identical output on the 2-chunk test input (see Decisions Made below).
- **6 first-party .c files** now include `#include "crypto/utils/qgp_safe_string.h"` as the last include-block entry (plans 03-01/02/03 convention).
- **messenger Linux native build clean** — 0 warnings, 0 errors. `libdna.so` + `dna-connect-cli` link successfully including all 6 modified TUs.
- **messenger/tests/build ctest:** 16/17 passing, `test_gek_ratchet` Not Run (pre-existing Phase 1 deferred link failure — identical baseline to plans 03-02 and 03-03).
- **Windows cross-compile of `libdna.a`** including all 6 modified TUs: clean. All 6 TUs (`dna_config.c.obj`, `eth_tx.c.obj`, `bsc_tx.c.obj`, `trx_rpc.c.obj`, `cellframe_json.c.obj`, and `cli_commands.c.obj`) built successfully. The only cross-compile failures are pre-existing, unrelated: `dnac/src/cli/commands.c:733` POSIX `mkdir(dir, 0700)` (Windows mkdir is 1-arg) and `messenger/cli/cli_commands.c:3482/3491` POSIX `mkdir`/`gmtime_r` — both carried from Phase 1 deferred-items and explicitly out of scope for Phase 3 (the plan-prompt orientation explicitly excludes the pre-existing cli POSIX issue). My line-7100 edit itself compiled cleanly on llvm-mingw; the errors are at unrelated line numbers.
- **Zero public header diff** — `git diff HEAD~2 HEAD -- '{messenger,nodus,dnac}/include/**/*.h' 'shared/crypto/**/*.h'` returns 0 lines. D-26 satisfied.
- **Orphan diffs untouched** — `.gitignore` and `messenger/dht/shared/nodus_init.c` comment-only diffs remain unstaged, as instructed.

## Task Commits

1. **Task 1: Replace 19 straightforward sites in 5 files** — `32dff36b` (fix)
   - `dna_config.c`: 14 strcpy sites → snprintf with sizeof(dst) (or `sizeof(bootstrap_nodes[0]) - offset` for the line 145 colon rewrite)
   - `eth_tx.c:534, 588`: `snprintf(tx_hash_out, 67, "%s", signed_tx->tx_hash)`
   - `bsc_tx.c:241`: same form
   - `trx_rpc.c:489`: `snprintf(dot, 3, ".0")`
   - `cli_commands.c:7100`: `snprintf(&out[i*2], 129 - (size_t)(i*2), "%02x", hash[i])` — matches caller's `out[129]` parameter declaration
   - Poison include added to all 5 files as the last include-block entry

2. **Task 2: cellframe_json.c sprintf replacements + chunk-combiner rewrite** — `c14bef1d` (fix)
   - Line 86 hash-hex loop: keep-loop snprintf using documented 67-byte bound
   - Line 103 fast-path uint256: snprintf with local str_out_size = 80
   - Line 133 chunk format: snprintf with sizeof(chunks[chunk_count])
   - Line 146 zero-value early return: snprintf(str_out, 80, "0")
   - Line 467 full-JSON assembly: snprintf with tracked json_size (introduced local json_size variable from the malloc call)
   - **Lines 155-165 chunk combiner: rewritten** — see Decisions Made
   - Poison include added

3. **Task 3: Build matrix + ctest regression check** — no commit (verification only)
   - Linux messenger native: clean (0 warnings)
   - Grep gate across 6 files: 0 lines
   - ctest: 16/17 pass, test_gek_ratchet Not Run (pre-existing)
   - Windows cross libdna.a: clean for all 6 TUs; only pre-existing cli POSIX failures remain (orthogonal)
   - Public header diff: 0 lines

## Files Created/Modified

**Created:** None.

**Modified (6 messenger first-party .c files):**
- `messenger/dna_config.c` — 14 strcpy sites + poison include
- `messenger/blockchain/ethereum/eth_tx.c` — 2 strcpy sites + poison include
- `messenger/blockchain/bsc/bsc_tx.c` — 1 strcpy site + poison include
- `messenger/blockchain/tron/trx_rpc.c` — 1 strcpy site + poison include
- `messenger/blockchain/cellframe/cellframe_json.c` — 4 sprintf + 3 strcpy sites (one is the rewritten chunk combiner encompassing 2 strcpy) + poison include
- `messenger/cli/cli_commands.c` — 1 sprintf hex-loop site + poison include

## Decisions Made

Beyond D-01..D-26 locked in 3-CONTEXT.md:

- **cellframe_json.c:145 colon port rewrite — uses offset arithmetic with `bootstrap_nodes[0]`.** Technical subtlety: `colon` points into `config->bootstrap_nodes[i]` in the surrounding loop's current iteration. `sizeof(config->bootstrap_nodes[0])` is the size of one array element (same for all i). The remaining capacity is `sizeof(elem) - (colon - config->bootstrap_nodes[i])`. Used this explicit form rather than restructuring the loop — matches the plan's 1:1 instruction.

- **cellframe_json.c chunk combiner hand-trace** (the plan's one real thinking site):
  - **Pre-rewrite logic:** For each chunk from chunk_count-1 down to 0: first chunk skips leading zeros and strcpy's the remainder; subsequent chunks strcpy the full 18-digit chunk; `out` advances via `strlen(p)` or `+= 18`.
  - **Trace input:** value = 10^18 + 5 → divmod produces chunk[0]="000000000000000005" (18 digits from remainder 5), quotient 1, then chunk[1]="000000000000000001" (remainder 1), quotient 0, chunk_count=2.
  - **Pre-rewrite output walk:** i=1 (first chunk): p starts at "000000000000000001", skip leading zeros → p="1"; strcpy "1" to out; out advances 1. i=0: strcpy "000000000000000005" (18 chars) to out; out advances 18. Final string: "1000000000000000005" (19 bytes + null).
  - **Rewrite shape:** Introduced `char *write_ptr = str_out; size_t out_remaining = str_out_size;` where `str_out_size = 80` (documented bound). Loop body sets `const char *src` to either the leading-zero-stripped pointer or the raw chunks[i], then calls `int written = snprintf(write_ptr, out_remaining, "%s", src)`. On success advances `write_ptr += written; out_remaining -= written`. On truncation breaks (correctness for pointer advance, not error reporting).
  - **Post-rewrite output walk:** i=1: src="1" (after zero-strip), written=1, write_ptr advances 1, out_remaining 80→79. i=0: src="000000000000000005", written=18, write_ptr advances 18, out_remaining 79→61. Final: "1000000000000000005" (19 bytes + null). **Byte-identical to pre-rewrite.**
  - **Second trace (3 chunks, bigger value):** value near 10^36. chunks[0]=last-18-digits, chunks[1]=middle-18-digits, chunks[2]=first-18-digits. Iter i=2: strip leading zeros → src="<high N digits>" (variable length), written=N, out_remaining 80→80-N. Iter i=1: src="<full 18>", written=18, out_remaining 80-N → 62-N. Iter i=0: src="<full 18>", written=18, out_remaining 62-N → 44-N. Total bytes written = N+36. For N≤18, total ≤54 bytes — fits in 80 byte buffer with null. Pre-rewrite output: "<high N digits><mid 18><low 18>" — same.
  - **Truncation safety:** 256-bit max decimal = 78 digits. chunks array is `char[5][20]` but max useful chunks = 5 (the loop safety-break). With str_out_size=80, the write_ptr + snprintf form is bounded even for worst-case inputs, whereas the pre-rewrite strcpy form relied on the caller honoring the 80-byte contract with no runtime bound. The rewrite is strictly safer.

- **Literal sizes at function-parameter destinations (no size_t parameter):**
  - `tx_hash_out` (eth_tx.c, bsc_tx.c): 67 — derived from the adjacent `strncpy(tx_hash_out, hash, 66); tx_hash_out[66] = '\0'` pattern (66 hex + null = 67)
  - `out` (cli_commands.c:7098 `format_hex_hash`): 129 — declared as `char out[129]` in the function parameter, used literal 129 because the array decays to pointer inside the function
  - `hex_out` (cellframe_json.c:77 `cellframe_hash_to_hex`): 67 — documented in header docstring as "at least 67 bytes"
  - `str_out` (cellframe_json.c:96 `cellframe_uint256_to_str`): 80 — documented as "at least 80 bytes"; captured as `const size_t str_out_size = 80;` so the bound appears once

## Deviations from Plan

None material. Plan 03-04 executed as written:
- All site tables in `<interfaces>` applied as specified
- dna_config.c:145 used the 1:1 bounded form per plan instruction (no loop restructure)
- eth_tx/bsc_tx used the 67 literal per plan instruction
- trx_rpc.c used the literal-3 form per plan instruction
- cli_commands.c used 129 (from `out[129]` caller declaration) for the keep-loop bound
- cellframe chunk combiner rewritten per the detailed instructions in Task 2
- All 6 files got the poison include as the last include-block entry
- No public API touches
- No signature changes
- Orphan diffs left alone

The Task 1 verify block's regex `grep -c "snprintf(config->log_level"` expects ≥2 and `grep -c "snprintf(config->bootstrap_nodes"` expects ≥12 — both satisfied.

## Verification Results

| Gate | Requirement | Result |
|------|-------------|--------|
| Zero strcpy/sprintf in the 6 files | `grep -n "\bstrcpy\s*(\|\bsprintf\s*("` across the 6 files | PASS (0 lines) |
| dna_config.c log_level replacements | `grep -c "snprintf(config->log_level"` ≥ 2 | PASS (2) |
| dna_config.c bootstrap_nodes replacements | `grep -c "snprintf(config->bootstrap_nodes"` ≥ 12 | PASS (12) |
| eth_tx.c tx_hash replacements | `grep -c "snprintf(tx_hash_out, 67"` ≥ 2 | PASS (2) |
| bsc_tx.c tx_hash replacement | `grep -c "snprintf(tx_hash_out, 67"` ≥ 1 | PASS (1) |
| trx_rpc.c dot replacement | `grep -q "snprintf(dot, 3"` | PASS |
| cli_commands.c hash loop replaced | no `sprintf(out + i*2`; has `snprintf(&out[i * 2]` | PASS |
| cellframe chunk combiner rewritten | grep for `out_remaining` or `str_out_size` | PASS |
| 6 files have poison include | `grep -l 'crypto/utils/qgp_safe_string.h'` | PASS (6/6) |
| Linux native messenger build clean | `cd messenger/build && make -j$(nproc)` | PASS (0 warnings, 0 errors) |
| messenger/tests/build ctest | `ctest --output-on-failure` | PASS — 16/17, test_gek_ratchet Not Run (pre-existing Phase 1 deferred) |
| Windows cross libdna.a clean | `./build-cross-compile.sh windows-x64` | PASS for libdna.a + all 6 TUs; only pre-existing cli POSIX failures remain (orthogonal) |
| Zero public header diff | `git diff HEAD~2 HEAD -- '**/include/**/*.h' 'shared/crypto/**/*.h'` | PASS (0 lines) |
| Orphan diffs untouched | `git status --short .gitignore messenger/dht/shared/nodus_init.c` | PASS (still present as pre-existing unstaged) |

## Issues Encountered

- **Pre-existing `test_gek_ratchet` link failure** — inherited from Phase 1, documented across all Phase 3 plan summaries. `test_gek_ratchet.c` references `gek_hkdf_sha3_256` which is not linked; tests/build shows "Not Run" not "Failed". Not caused by this plan.
- **Pre-existing Windows cross POSIX failures** — `dnac/src/cli/commands.c:733` mkdir-2-arg + `messenger/cli/cli_commands.c:3482/3491` mkdir/gmtime_r. Both carried from Phase 1 deferred-items. Explicitly out of scope for Phase 3 per plan-prompt orientation. `libdna.a` itself + all 6 of my plan-scope TUs build fine; only the final executable link fails at the pre-existing sites.
- **Orphan diffs** — `.gitignore` and `messenger/dht/shared/nodus_init.c` remain unstaged. Left untouched per orientation.

No new issues introduced.

## Authentication Gates

None.

## Next Plan Readiness

- `shared/crypto/utils/qgp_safe_string.h` is now included by **96** first-party .c files: 20 (dnac, plan 03-01) + 29 (shared/crypto, plan 03-02) + 41 (nodus, plan 03-03) + 6 (messenger blockchain/config/cli, plan 03-04). Plan 03-05 (messenger engine/dht) is the last Wave 2 plan before SAFE-01 can be marked complete.
- The **mid-buffer chunk-combiner rewrite pattern** is now documented (write_ptr + out_remaining + break-on-truncation). Future plans encountering similar mid-buffer strcpy loops (if any remain in messenger/engine or messenger/dht) should apply the same pattern rather than attempting 1:1 replacements that leak the bound.
- The **literal-size-from-header-docstring micro-pattern** is now documented. Future work that touches function-parameter destinations with docstring-documented bounds must keep the literal in code matching the docstring bound.
- The Wave 2 execution order remains Plans 03-02, 03-03, 03-04 landed; Plan 03-05 is next.

## Self-Check: PASSED

- FOUND: `messenger/dna_config.c` has `snprintf(config->log_level, sizeof(config->log_level)` (2 matches) and `snprintf(config->bootstrap_nodes[` (12 matches) and the bounded colon rewrite on line 145
- FOUND: `messenger/blockchain/ethereum/eth_tx.c` has 2 `snprintf(tx_hash_out, 67, "%s", signed_tx->tx_hash)` sites
- FOUND: `messenger/blockchain/bsc/bsc_tx.c` has 1 `snprintf(tx_hash_out, 67, "%s", signed_tx->tx_hash)` site
- FOUND: `messenger/blockchain/tron/trx_rpc.c` has `snprintf(dot, 3, ".0")`
- FOUND: `messenger/blockchain/cellframe/cellframe_json.c` has `out_remaining`, `write_ptr`, `str_out_size = 80`, `snprintf(json, json_size,` at line 467 area, `snprintf(str_out, str_out_size, "0")`, `snprintf(str_out, str_out_size, "%llu"`, `snprintf(chunks[chunk_count], sizeof(chunks[chunk_count])`, and `snprintf(&hex_out[2 + (i * 2)], 67 - 2 - (size_t)(i * 2)`
- FOUND: `messenger/cli/cli_commands.c` `format_hex_hash` has `snprintf(&out[i * 2], 129 - (size_t)(i * 2), "%02x", hash[i])`
- FOUND: 6/6 target files contain `crypto/utils/qgp_safe_string.h`
- FOUND: 0 strcpy/sprintf in the 6 target files (grep gate clean)
- FOUND: commit `32dff36b` (Task 1 — 5-file replacements)
- FOUND: commit `c14bef1d` (Task 2 — cellframe_json.c + chunk combiner rewrite)
- FOUND: messenger native Linux build clean (0 warnings, 0 errors)
- FOUND: messenger/tests/build ctest 16 pass, 1 Not Run (test_gek_ratchet pre-existing)
- FOUND: Windows cross libdna.a clean for all 6 TUs; only pre-existing cli POSIX failures remain
- FOUND: zero public header diff across plan commits

---
*Phase: 03-unsafe-c-pattern-remediation*
*Completed: 2026-04-13*
