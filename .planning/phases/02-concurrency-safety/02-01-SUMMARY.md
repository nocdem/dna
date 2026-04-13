---
phase: 02-concurrency-safety
plan: 01
subsystem: gek
tags: [sec-04, gek, pthread-rwlock, concurrency, phase-02]
dependency_graph:
  requires:
    - "messenger/messenger/gek.c (static pointers gek_kem_pubkey / gek_kem_privkey)"
    - "messenger/messenger/gek.h (public API — MUST remain unchanged)"
    - "pthread (Linux + llvm-mingw winpthreads — both provide pthread_rwlock_t)"
  provides:
    - "pthread_rwlock_t gek_lock protecting the two static KEM-key pointers"
    - "Copy-under-lock pattern at every read site (5 sites)"
    - "Wrlock-wrapped mutation at every write site (2 sites)"
    - "test_gek_concurrent ctest — regression guard under AddressSanitizer"
    - "Level-2 entry payload for CONCURRENCY.md (handed to Plan 02-04)"
  affects:
    - "messenger/messenger/gek.c (gek_store, gek_load, gek_load_active, gek_export_plain_entries, gek_import_plain_entries, gek_set_kem_keys, gek_clear_kem_keys)"
    - "messenger/tests/CMakeLists.txt (new test_gek_concurrent executable + ctest)"
tech_stack:
  added:
    - "pthread_rwlock_t (POSIX rwlock, default policy)"
  patterns:
    - "Copy-under-lock: rdlock → memcpy to stack → unlock → work on local copy"
    - "Allocate-outside-lock: malloc new buffers before wrlock to shorten the critical section"
    - "Inlined clear in gek_set_kem_keys (avoids rwlock non-recursion pitfall)"
key_files:
  created:
    - "messenger/tests/test_gek_concurrent.c (179 lines)"
    - ".planning/phases/02-concurrency-safety/02-01-SUMMARY.md (this file)"
  modified:
    - "messenger/messenger/gek.c (+97 -24)"
    - "messenger/tests/CMakeLists.txt (+7 lines)"
decisions:
  - "D-05 applied: pthread_rwlock_t gek_lock with PTHREAD_RWLOCK_INITIALIZER"
  - "D-06 applied: lock annotated CONCURRENCY.md L2 at every site (Plan 02-04 will add the full ordering doc)"
  - "D-07 applied: gek.h public API unchanged — verified by git diff"
  - "C-04 applied: default POSIX rwlock policy (no pthread_rwlockattr_setkind_np)"
  - "Inlined clear sequence in gek_set_kem_keys to avoid recursive rwlock acquisition"
  - "Allocate + memcpy outside the wrlock in gek_set_kem_keys so the critical section is just pointer swap + free"
metrics:
  duration: "~45 minutes (single agent, no checkpoints)"
  completed: "2026-04-13"
  tasks: 3
  files_touched: 3
  tests_added: 1
requirements:
  - SEC-04
---

# Phase 02 Plan 01: SEC-04 — GEK KEM-key rwlock Summary

Protects the static `gek_kem_pubkey` / `gek_kem_privkey` pointers in
`messenger/messenger/gek.c` with a `pthread_rwlock_t gek_lock` so that
concurrent decrypt-path readers can never race against a writer swapping
or clearing the keys, closing SEC-04 without touching any public API.

## What Shipped

**Lock primitive:** A single static `pthread_rwlock_t gek_lock =
PTHREAD_RWLOCK_INITIALIZER` declared immediately after the two KEM-key
statics at gek.c line ~60. Default POSIX rwlock policy — no glibc-only
`pthread_rwlockattr_setkind_np` (portable to llvm-mingw winpthreads per
Phase 2 Correction C-04).

**Read sites (rdlock + copy-to-stack + release):**

| Site | Function | gek.c line (new) | Buffer | Size |
|------|----------|------------------|--------|------|
| 1 | `gek_store` | 241 | `pubkey_local[]` | 1568 |
| 2 | `gek_load` | 304 | `privkey_local[]` | 3168 |
| 3 | `gek_load_active` | 375 | `privkey_local[]` | 3168 |
| 4 | `gek_export_plain_entries` | 1609 | `privkey_local[]` | 3168 |
| 5 | `gek_import_plain_entries` | 1733 | `pubkey_local[]` | 1568 |

At every read site the critical section contains only the NULL-check and
a `memcpy` — zero calls into SQLite, nodus, or DHT modules, so the L2 →
L5 acquisition ordering is clean. All `privkey_local` buffers are
`qgp_secure_memzero`'d on every exit path.

**Write sites (wrlock-wrapped mutation):**

| Site | Function | gek.c line (new) | Pattern |
|------|----------|------------------|---------|
| 1 | `gek_set_kem_keys` | 615 | malloc new buffers outside the lock, memcpy into them, then wrlock → free-old → swap pointers → unlock |
| 2 | `gek_clear_kem_keys` | 639 | wrlock → zero + free + NULL both pointers → unlock |

`gek_set_kem_keys` no longer calls `gek_clear_kem_keys`; the clear is
inlined inside the wrlock to avoid re-entering a non-recursive POSIX
rwlock.

**Comment annotations:** 8 `CONCURRENCY.md L2` references in gek.c
(header block + one at every lock acquisition).

**Public API:** `messenger/messenger/gek.h` and
`messenger/include/dna/dna_engine.h` — `git diff` is empty (0 lines).

## Test Strategy (Strategy A)

`messenger/tests/test_gek_concurrent.c` — 8 worker threads, each in a
tight loop calling `gek_set_kem_keys` followed by `gek_clear_kem_keys`
on freshly-allocated 1568/3168 byte buffers. Every call goes through
the wrlock path. Any missing lock or incorrect scope would produce a
use-after-free or double-free, which the existing AddressSanitizer
build flag (`-fsanitize=address` in messenger/tests/CMakeLists.txt at
CMAKE_BUILD_TYPE=Debug) catches as a hard failure. Runs for 2s wall
clock, hard-capped at 10s.

Only `messenger/gek.h` is included — the same intra-repo surface
already consumed by the existing `test_gek_ratchet`. No private
headers (`engine_includes.h`, `dna_engine_internal.h`, `src/...`) are
referenced, satisfying D-24.

Strategy B (engine-level end-to-end driving decrypt from the public
engine API) was rejected because it requires full messenger/identity
bootstrapping with on-disk key material, adding fragility without
adding coverage — the rwlock exercise is identical. Strategy C
(positive-control only) was unnecessary because Strategy A produces a
real race harness.

## Verification Results

| Gate | Command | Result |
|------|---------|--------|
| Linux native build | `cd messenger/build && make -j$(nproc)` | 0 warnings, 0 errors |
| ctest full suite | `cd messenger/tests/build && ctest --output-on-failure` | 13/14 passed; only failure is pre-existing `test_gek_ratchet` (link error documented in `01/deferred-items.md`) |
| New `gek_concurrent` | `ctest -R gek_concurrent` | Passed in 2.09s under ASan |
| Windows cross-compile | `./build-cross-compile.sh windows-x64` | `libdna.a` built clean; `gek.c` compiled with 0 warnings; only failure is pre-existing `cli/cli_commands.c` POSIX dependencies (`mkdir`/`gmtime_r`) documented in `01/deferred-items.md` |
| Android cross-compile | `./build-cross-compile.sh android` | N/A — build script has no `android` target on this host (same situation as Phase 1) |
| Public header diff | `git diff messenger/messenger/gek.h messenger/include/dna/dna_engine.h` | 0 lines |
| `grep -c "pthread_rwlock_rdlock(&gek_lock)"` | gek.c | 5 |
| `grep -c "pthread_rwlock_wrlock(&gek_lock)"` | gek.c | 2 |
| `grep -c "pthread_rwlockattr_setkind_np"` | gek.c | 0 |
| `grep -c "CONCURRENCY.md L2"` | gek.c | 8 |

## Commits

| Task | Commit | Files |
|------|--------|-------|
| Task 1 — Add pthread_rwlock_t gek_lock + wrap all sites | `d5fb022c` | `messenger/messenger/gek.c` |
| Task 2 — Add test_gek_concurrent ctest | `acf64c21` | `messenger/tests/test_gek_concurrent.c`, `messenger/tests/CMakeLists.txt` |
| Task 3 — Build + ctest + cross-compile verification | (no commit — verification only) | — |

## Deviations from Plan

None — the plan was followed as written. Minor design choices that
the plan left to executor discretion:

1. **Inlined `gek_clear_kem_keys` body inside `gek_set_kem_keys`.** The
   original code called `gek_clear_kem_keys()` at the top of
   `gek_set_kem_keys`. After the rwlock was added, that would have
   re-entered a non-recursive rwlock (pitfall 1 from RESEARCH.md).
   Solution: inline the zero+free+NULL sequence inside the same wrlock
   acquisition, and change the execution order so the new allocation
   happens outside the lock first (fail-early on OOM before we touch
   the protected globals). Net effect: smaller critical section, one
   wrlock acquisition per call instead of two.

2. **`privkey_local` secure-zero on every return path of
   `gek_export_plain_entries`.** The export function has four distinct
   return paths (count==0, calloc failure, prepare failure, success
   after the loop). Each now calls `qgp_secure_memzero(privkey_local,
   sizeof(privkey_local))` before returning so a 3168-byte Kyber1024
   secret never leaks on the stack to subsequent frames.

3. **`pubkey_local` is not secure-zero'd** — the Kyber1024 public key
   is not secret, so zeroing it is harmless but not required. Omitted
   for clarity.

No CLAUDE.md directives were overridden.

## Deferred / Pre-existing Issues (Untouched)

- `test_gek_ratchet` link error — documented in
  `01/deferred-items.md`. Same failure mode, not introduced by this
  plan. 13 of 14 ctest pass; this is the 14th.
- `cli/cli_commands.c` Windows cross-compile failure (missing
  `mkdir(_, mode)` overload, implicit `gmtime_r`) — documented in
  `01/deferred-items.md`. `libdna.a` itself builds clean on Windows;
  only the CLI link target fails, and `gek.c` contributes zero
  warnings to the libdna build.
- Android cross-compile has no target in `build-cross-compile.sh` on
  this host — same situation as Phase 1. Documented N/A. Re-test on a
  host with NDK when Android cross becomes available.

## Hand-off to Plan 02-04 (CONCURRENCY.md L2 entry)

Plan 02-04 creates `messenger/docs/CONCURRENCY.md` with the full
L1..L5 ordering table. The L2 row should read:

```
| L2 | gek_lock | messenger/messenger/gek.c | pthread_rwlock_t (default policy) |
|    |          | reads = rdlock + copy-to-stack + release                       |
|    |          | writes = wrlock wrapping the mutation sequence                 |
|    |          | CRITICAL SECTION MUST NOT call: nodus_*, dht_*, sqlite3_*,     |
|    |          | contacts_db_*, any engine mutex, or any gek_* function that   |
|    |          | re-enters gek_lock (POSIX rwlock is non-recursive).           |
```

Seven lock-acquisition sites in gek.c; every one is annotated with
`/* CONCURRENCY.md L2: gek_lock */` so a `grep -n "CONCURRENCY.md L2"
messenger/messenger/gek.c` gives Plan 02-04 an exact inventory.

## Self-Check: PASSED

**Files verified to exist:**
- FOUND: messenger/messenger/gek.c (modified)
- FOUND: messenger/tests/test_gek_concurrent.c (new)
- FOUND: messenger/tests/CMakeLists.txt (modified, contains `test_gek_concurrent` and ctest `gek_concurrent`)
- FOUND: .planning/phases/02-concurrency-safety/02-01-SUMMARY.md (this file)

**Commits verified to exist:**
- FOUND: d5fb022c — `fix(02-01): protect GEK KEM keys with pthread_rwlock_t (SEC-04)`
- FOUND: acf64c21 — `test(02-01): concurrent GEK KEM-key rwlock race regression (SEC-04)`

**Acceptance greps verified on disk:**
- `pthread_rwlock_t gek_lock` occurrences in gek.c: 1
- `PTHREAD_RWLOCK_INITIALIZER` occurrences in gek.c: 1
- `pthread_rwlock_rdlock(&gek_lock)` occurrences: 5 (one per read site)
- `pthread_rwlock_wrlock(&gek_lock)` occurrences: 2 (one per write site)
- `pthread_rwlock_unlock(&gek_lock)` occurrences: 12 (covers all acquisitions + error-return paths)
- `CONCURRENCY.md L2` annotations: 8
- `pthread_rwlockattr_setkind_np` occurrences: 0
- `git diff messenger/messenger/gek.h messenger/include/dna/dna_engine.h`: 0 lines
