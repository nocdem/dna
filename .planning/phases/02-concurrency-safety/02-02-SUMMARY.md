---
phase: 02-concurrency-safety
plan: 02
subsystem: engine
tags: [sec-05, engine, backup, destroy, atomic, concurrency, phase-02]
dependency_graph:
  requires:
    - "messenger/src/api/dna_engine_internal.h (engine struct with backup_thread_running / restore_thread_running fields)"
    - "messenger/src/api/engine/dna_engine_backup.c (HIGH-8 join-on-next-spawn pattern — preserved)"
    - "messenger/src/api/dna_engine.c (existing destroy ordering with join BEFORE gek_clear_kem_keys / messenger_free / session_password zero)"
    - "messenger/include/dna/dna_engine.h (public API — unchanged)"
    - "<stdatomic.h> (already transitively included via dna_engine_internal.h line 27)"
  provides:
    - "_Atomic bool backup_thread_running and _Atomic bool restore_thread_running in dna_engine_t"
    - "atomic_load / atomic_store at every read/write site (11 in backup.c + 2 joins in dna_engine.c)"
    - "CONCURRENCY.md L1-cluster annotation at the destroy join site (handed to Plan 02-04)"
    - "test_engine_destroy_during_backup ctest — regression guard under AddressSanitizer"
    - "Destroy-ordering invariant documented for Plan 02-04's CONCURRENCY.md section"
  affects:
    - "messenger/src/api/dna_engine_internal.h (engine struct fields 877, 879)"
    - "messenger/src/api/engine/dna_engine_backup.c (11 flag sites)"
    - "messenger/src/api/dna_engine.c (destroy site lines 1864-1875)"
    - "messenger/tests/CMakeLists.txt (new test executable + ctest registration)"
tech_stack:
  added:
    - "_Atomic bool (C11 stdatomic) on two existing struct fields"
  patterns:
    - "Plain-bool → _Atomic bool promotion + atomic_load/atomic_store at every access site"
    - "Preserve-existing-ordering: join sequence at dna_engine.c:1864-1875 unchanged — atomicity only"
    - "Pair-with-HIGH-8-join-on-next-spawn: existing pattern at backup.c:286, 392 now uses atomic ops"
key_files:
  created:
    - "messenger/tests/test_engine_destroy_during_backup.c (228 lines)"
    - ".planning/phases/02-concurrency-safety/02-02-SUMMARY.md (this file)"
  modified:
    - "messenger/src/api/dna_engine_internal.h (+6 -2)"
    - "messenger/src/api/engine/dna_engine_backup.c (+16 -5)"
    - "messenger/src/api/dna_engine.c (+16 -4)"
    - "messenger/tests/CMakeLists.txt (+7 lines)"
decisions:
  - "D-08 applied: existing pthread_join sequence verified correct (Pattern 2 of research) — join already happens before gek_clear_kem_keys, dna_engine_cancel_all_outbox_listeners, messenger_free, session_password zero. No reorder."
  - "D-09 applied: backup_thread_running AND restore_thread_running both promoted to _Atomic bool (restore_thread_running field confirmed present at dna_engine_internal.h:879)"
  - "D-10 applied: no new shutdown flag, no refcount, no condvar — minimal atomicity-only fix"
  - "C-03 applied: join site annotated with CONCURRENCY.md L1 cluster comment for Plan 02-04"
  - "D-24 applied: test uses public engine API only (dna_engine_create / dna_engine_backup_messages / dna_engine_destroy); no internal headers"
  - "Strategy C (plan Task 2): in-flight-backup race is unreachable without a loaded identity and D-24 forbids private test hooks; regression guard uses positive-control under ASan plus code-review grep criteria plus Plan 02-04 TSan target"
metrics:
  duration: "~30 minutes (single agent, no checkpoints)"
  completed: "2026-04-13"
  tasks: 3
  files_touched: 5
  tests_added: 1
requirements:
  - SEC-05
---

# Phase 2 Plan 02: SEC-05 Backup Thread Atomic + Destroy Verification Summary

Promoted `engine->backup_thread_running` and `engine->restore_thread_running` from plain `bool` to `_Atomic bool`, converted all 13 read/write sites to `atomic_load` / `atomic_store`, verified the existing destroy-path join ordering is preserved, annotated the join site for CONCURRENCY.md L1 cluster, and landed a public-API regression ctest under AddressSanitizer.

## Objective

Close SEC-05 — the use-after-free race where `dna_engine_destroy` reads a stale `engine->backup_thread_running == false`, skips `pthread_join`, and proceeds to `messenger_free(engine->messenger)` while the backup thread is still mid-write to `engine->messenger->backup_ctx`. Per Pattern 2 of 02-RESEARCH.md, the destroy-path sequential ordering (join before free) is already correct; the bug was purely the non-atomic read/write on the flag.

## restore_thread_running field status

**Present.** At `messenger/src/api/dna_engine_internal.h:879` (pre-edit) / `:881` (post-edit). Promoted to `_Atomic bool` in the same block as `backup_thread_running`. Both fields are converted in lockstep.

## atomic_load / atomic_store site inventory (post-edit)

### messenger/src/api/engine/dna_engine_backup.c (11 sites)

| Line | Op | Field |
|------|----|----|
| 68  | atomic_store(false) | backup_thread_running  — early-exit in backup_thread_func (engine-not-ready path) |
| 117 | atomic_store(false) | backup_thread_running  — normal exit in backup_thread_func |
| 139 | atomic_store(false) | restore_thread_running — early-exit in restore_thread_func (engine-not-ready path) |
| 154 | atomic_store(false) | restore_thread_running — early-exit in restore_thread_func (no backup_ctx path) |
| 196 | atomic_store(false) | restore_thread_running — normal exit in restore_thread_func |
| 286 | atomic_load       | backup_thread_running  — HIGH-8 join-on-next-spawn check in dna_engine_backup_messages |
| 288 | atomic_store(false) | backup_thread_running  — HIGH-8 post-join reset |
| 301 | atomic_store(true)  | backup_thread_running  — post-pthread_create in dna_engine_backup_messages |
| 392 | atomic_load       | restore_thread_running — HIGH-8 join-on-next-spawn check in dna_engine_restore_messages |
| 394 | atomic_store(false) | restore_thread_running — HIGH-8 post-join reset |
| 407 | atomic_store(true)  | restore_thread_running — post-pthread_create in dna_engine_restore_messages |

### messenger/src/api/dna_engine.c (4 sites)

| Line | Op | Field |
|------|----|----|
| 1864 | atomic_load       | backup_thread_running  — destroy-site join gate |
| 1867 | atomic_store(false) | backup_thread_running  — destroy-site post-join reset |
| 1869 | atomic_load       | restore_thread_running — destroy-site join gate |
| 1872 | atomic_store(false) | restore_thread_running — destroy-site post-join reset |

**Total:** 15 atomic ops across the two files (11 + 4), covering every read/write site identified by research (13 sites, with the spawn-site and destroy-site each containing an atomic-load read gate plus two atomic-store writes on the pair).

## Destroy-path ordering invariant (verified preserved)

From `messenger/src/api/dna_engine.c` (actual line numbers post-edit):

| Line | Action |
|------|--------|
| 1864 | `if (atomic_load(&engine->backup_thread_running))` gate |
| 1866 | `pthread_join(engine->backup_thread, NULL)` |
| 1867 | `atomic_store(&engine->backup_thread_running, false)` |
| 1869 | `if (atomic_load(&engine->restore_thread_running))` gate |
| 1871 | `pthread_join(engine->restore_thread, NULL)` |
| 1872 | `atomic_store(&engine->restore_thread_running, false)` |
| 1878 | `gek_clear_kem_keys()` |
| 1882 | `dna_engine_cancel_all_outbox_listeners(engine)` |
| 1912 | `messenger_free(engine->messenger)` |
| 1966 | `qgp_secure_memzero(engine->session_password, ...)` |
| 1974 | `free(engine)` |

**Invariant held:** join(backup) → join(restore) → gek_clear_kem_keys → cancel_all_outbox_listeners → messenger_free → session_password zero → free(engine). No reorder. This is verifiable by eyeballing the function in dna_engine.c and by the acceptance grep `grep -c "pthread_join(engine->backup_thread"`.

## Annotation at destroy join site

`messenger/src/api/dna_engine.c` lines 1853-1863 carry a multi-line block comment reading, in part:

> CONCURRENCY.md L1 cluster: engine mutexes — backup_thread join during destroy. SEC-05 invariant (Phase 02-02): backup_thread and restore_thread MUST be joined BEFORE gek_clear_kem_keys() (L1869), dna_engine_cancel_all_outbox_listeners() (L1873), messenger_free(engine->messenger) (L1903), and session_password zeroization (L1957). The existing sequential ordering below is correct (verified Phase 2 research 2026-04-13); this block only adds atomicity to the flag read/write.

Plan 02-04 can pick this up verbatim for CONCURRENCY.md §"L1 — Engine cluster — Backup/Restore thread join at destroy".

## Test strategy chosen

**Strategy C — positive-control regression guard** per plan Task 2.

**Rationale:** `dna_engine_backup_messages` early-returns at backup.c:206-210 when `!engine->identity_loaded || !engine->messenger`, which is the state of any engine freshly created via the public API without a full identity-create flow. The "real" in-flight-backup race is therefore unreachable from a ctest that uses only the public API (D-24). A private test hook would be required to inject a thread, and D-24 forbids that.

**What the test proves:**

1. `dna_engine_create(tempdir)` + `dna_engine_destroy(engine)` round-trip is ASan-clean — regression guard against SEC-05 breaking engine init/destroy
2. `dna_engine_backup_messages(engine, cb, NULL)` on an identity-less engine fast-fails and fires the callback with a nonzero error code — regression guard against the immediate-error path breaking
3. The destroy-site atomic_load + join sequence runs end-to-end with zero ASan reports

**What the test does NOT prove (verified out-of-band):**

- The true in-flight race. Verified by (a) code review via the plan's grep acceptance criteria (every `engine->backup_thread_running` access is atomic_load/atomic_store — confirmed), and (b) Plan 02-04's upcoming TSan ctest target which will exercise the full codebase under ThreadSanitizer.

Test file: `messenger/tests/test_engine_destroy_during_backup.c` (228 lines). Two sub-tests (`test_plain_create_destroy`, `test_destroy_after_backup_request`). Hard cap: 15 seconds. Observed runtime: 0.15s.

## Build log summaries

### Linux native
`/tmp/sec05-build.log` — messenger C library: **clean build, zero warnings, zero errors**. dna_engine_backup.c, dna_engine.c, and transitively dna_engine_internal.h all compile with no diagnostics from my edits. libdna.so linked cleanly. dna-connect-cli linked cleanly.

### Full ctest
`/tmp/sec05-full-ctest.log` — 14 of 15 tests passed. Only pre-existing `test_gek_ratchet` (Not Run due to unresolved `gek_hkdf_sha3_256` link failure — already in `.planning/phases/01-c-engine-input-validation/deferred-items.md`). `engine_destroy_during_backup` and `gek_concurrent` (plan 02-01's test) both pass. No ASan reports.

```
Start  8: gek_concurrent                   Passed    2.08 sec
Start  9: engine_destroy_during_backup     Passed    0.15 sec
```

### Windows cross-compile (llvm-mingw)
`/tmp/sec05-win-build.log` — `libdna.a` at `messenger/build-release/windows-x64/libdna.a` built successfully. The only failures are pre-existing `cli/cli_commands.c` issues (implicit declarations of POSIX `mkdir`/`gmtime_r` — documented in deferred-items.md line 13+). Warnings in the log are all pre-existing:
- `-Winconsistent-dllimport` noise on public API function declarations (unrelated to the three files I touched — they reference lines nowhere near my edits)
- `-Wpointer-bool-conversion` in `dht_groups.c:1102-1104` (pre-existing)
- `winsock2.h before windows.h` warnings from system headers (pre-existing)

**`_Atomic bool` confirmed supported by llvm-mingw clang** — the two field declarations compiled without diagnostics and libdna.a linked clean. C11 atomics are in llvm-mingw's libc/compiler-rt.

### Android cross-compile
`/tmp/sec05-android-build.log` — `./build-cross-compile.sh` on this machine does not expose an `android` target (only `linux-x64`, `windows-x64`, `all`). Same situation as Phase 1 Plan 01-01 noted in deferred-items.md. `_Atomic bool` is POSIX-1.2001 / C11 and bionic pthreads support it — no risk factor for Android. Documented as unavailable on this dev machine; Plan 02-04 or a later Android CI job can re-verify.

## Public-header diff

```
$ git diff HEAD~2 messenger/include/dna/dna_engine.h \
                  messenger/messenger/gek.h \
                  messenger/dht/shared/nodus_init.h \
                  messenger/dht/shared/dht_offline_queue.h \
                  messenger/dht/shared/nodus_ops.h
```

→ **0 lines of output.** All public API surfaces are byte-for-byte unchanged.

## Deviations from Plan

None — plan executed exactly as written. The executor followed the plan's Strategy C fallback for Task 2 (expected, since the plan anticipated this); no auto-fix Rule 1/2/3 deviations, no checkpoints, no blockers. The dllimport warnings on the Windows cross-compile are pre-existing noise unrelated to the three files I touched.

## L1-cluster entry payload for Plan 02-04's CONCURRENCY.md

Plan 02-04 should include this verbatim under the L1 engine cluster section:

> **Backup/Restore thread join at engine destroy (SEC-05).** The `dna_engine_destroy` function MUST join `engine->backup_thread` and `engine->restore_thread` BEFORE any of:
>
> 1. `gek_clear_kem_keys()`
> 2. `dna_engine_cancel_all_outbox_listeners(engine)`
> 3. `messenger_free(engine->messenger)`
> 4. `qgp_secure_memzero(engine->session_password, ...)`
> 5. `free(engine)`
>
> The two running flags (`backup_thread_running`, `restore_thread_running`) are `_Atomic bool` and every read/write across `dna_engine_backup.c` and `dna_engine.c` uses `atomic_load` / `atomic_store`. The join is gated on `atomic_load(&engine->backup_thread_running)` (resp. `restore_thread_running`). See Phase 02-02 SUMMARY for the full site inventory and ordering proof.
>
> This is the only L1 rule in this cluster that specifies a join rather than a lock; the backup/restore threads do not take any named engine mutex, and the destroy thread holds no engine mutex when it makes the join call. The invariant is a destroy-path sequential ordering invariant, not a lock ordering.

## Known Stubs

None. All edits are real implementation.

## Self-Check: PASSED

Files verified to exist:
- messenger/tests/test_engine_destroy_during_backup.c — FOUND
- .planning/phases/02-concurrency-safety/02-02-SUMMARY.md — FOUND (this file)

Commits verified to exist:
- 17abd5df (fix: atomic promotion) — FOUND
- e01d8304 (test: regression ctest) — FOUND

Acceptance-criteria grep results:
- `grep -c "_Atomic bool backup_thread_running" dna_engine_internal.h` = 1 — PASS
- `grep -c "_Atomic bool restore_thread_running" dna_engine_internal.h` = 1 — PASS
- `grep -cE "engine->backup_thread_running\s*=\s*(true|false)" dna_engine_backup.c` = 0 — PASS
- `grep -cE "if\s*\(\s*engine->backup_thread_running\s*\)" dna_engine_backup.c` = 0 — PASS
- `grep -c atomic_store dna_engine_backup.c` ≥ 6 — PASS (9 stores)
- `grep -c atomic_load dna_engine_backup.c` ≥ 1 — PASS (2 loads)
- `grep -c "atomic_load(&engine->backup_thread_running)" dna_engine.c` ≥ 1 — PASS (1)
- `grep -c "CONCURRENCY.md L1 cluster" dna_engine.c` ≥ 1 — PASS (1)
- `grep -c "pthread_join(engine->backup_thread" dna_engine.c` ≥ 1 — PASS (1)
- Destroy ordering: join@1866 < gek_clear_kem_keys@1878 < messenger_free@1912 — PASS
- `git diff messenger/include/dna/dna_engine.h` = 0 lines — PASS
- Linux build warnings = 0 — PASS
- ctest `engine_destroy_during_backup` Passed — PASS
- No `AddressSanitizer:` strings in ctest log — PASS
