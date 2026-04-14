---
phase: 6
plan: 2
slug: core05-lockout-fix
subsystem: messenger/src/api/engine
tags: [phase-6, wave-2, core-05, lockout, identity, tdd]
requirements: [CORE-05]
threat_refs: [T-6-04, T-6-05]
dependency_graph:
  requires:
    - phase-6/plan-01 (test scaffolding — test_register_name_failure_preserves_keys)
  provides:
    - "Non-destructive failure handling for create-flow name registration"
    - "GREEN regression guard for CORE-05 lockout"
  affects:
    - messenger/src/api/engine/dna_engine_identity.c (dna_engine_create_identity_sync)
tech_stack:
  added: []
  patterns:
    - "Fail-open-for-retry: transient errors preserve on-disk state so UI can retry without re-derivation"
key_files:
  created: []
  modified:
    - messenger/src/api/engine/dna_engine_identity.c
    - messenger/tests/test_register_name_failure_preserves_keys.c
    - messenger/include/dna/version.h
    - messenger/docs/functions/engine.md
status: complete
completed: 2026-04-14
duration_minutes: ~35
tasks_total: 2
tasks_completed: 2
commits:
  - hash: 3d57f1b9
    message: "fix(6-02): CORE-05 non-destructive registration failure"
  - hash: e756d132
    message: "chore(6-02): bump library version + document CORE-05 fix (v0.9.194)"
key_decisions:
  - "Both destructive cleanup branches in dna_engine_create_identity_sync (messenger_init-fail and messenger_register_name-fail) were neutralized atomically. The plan targeted only the second branch, but the first contains the identical CORE-05 bug and blocks any public-API failure injection from ever reaching the second branch. Fixing only one would have left the lockout reachable and made the RED→GREEN transition impossible via the sync public API."
  - "MESSENGER_SECURITY_AUDIT.md was NOT created. Root /opt/dna/CLAUDE.md forbids committing any *AUDIT*.md file (covered by .gitignore pattern **/*AUDIT*). The CORE-05 rationale lives in messenger/docs/functions/engine.md and this summary."
  - "The test was rewritten from the plan-01 RED precondition stub into a real failure-injection test driven through the public dna_engine_create_identity_sync API, with no stubs: engine is created against a tmp data_dir, DHT is intentionally left unstarted, and the sync call is invoked. messenger_init fails (no DHT) and the fix is verified by asserting keys/, db/, wallets/, mnemonic.enc all still exist post-call."
metrics:
  duration: ~35m
  tasks: 2
  files_modified: 4
  tests_added: 0
  tests_flipped_red_to_green: 1
---

# Phase 6 Plan 2: CORE-05 Lockout Fix Summary

**One-liner:** Remove the destructive cleanup branches in `dna_engine_create_identity_sync` so transient DHT errors during first-time name registration no longer wipe the user's local identity, and flip the plan-01 RED test to GREEN via real public-API failure injection.

## What was built

A minimal, behavior-preserving fix to CORE-05. Two adjacent destructive-cleanup branches in `dna_engine_create_identity_sync` (messenger/src/api/engine/dna_engine_identity.c) are replaced with a WARN log + early-return. The function signature, error codes, and all other code paths are unchanged.

### The fix in one sentence

When `messenger_init` or `messenger_register_name` returns non-zero during create-with-name, the engine no longer calls `qgp_platform_rmdir_recursive` on `keys/`, `db/`, `wallets/`, or `mnemonic.enc` — it logs a WARN and returns the existing error code, leaving the on-disk identity intact so the Flutter resume-flow UI can retry.

### Files changed

| File | Change |
|------|--------|
| `messenger/src/api/engine/dna_engine_identity.c` | Replaced both destructive `if (!temp_ctx)` and `if (rc != 0)` branches in `dna_engine_create_identity_sync` with non-destructive WARN+return. No other code paths touched. |
| `messenger/tests/test_register_name_failure_preserves_keys.c` | Replaced plan-01 RED precondition stub with a real failure-injection test: creates an engine in a tmp data_dir, derives BIP39 seeds, calls `dna_engine_create_identity_sync` without starting DHT, asserts rc != 0 AND that `keys/` `db/` `wallets/` `mnemonic.enc` all still exist. |
| `messenger/include/dna/version.h` | `DNA_VERSION_PATCH` 193 → 194, `DNA_VERSION_STRING` `"0.9.193"` → `"0.9.194"`. MAJOR and MINOR unchanged. |
| `messenger/docs/functions/engine.md` | Added "CORE-05 (Phase 6, 2026-04-14)" paragraph under Task Handlers - Identity, documenting the non-destructive failure semantics. |

## Verification results

```
$ cd messenger/build && make -j$(nproc) 2>&1 | grep -ciE "warning:|error:"
0

$ cd messenger/tests/build && ctest -R test_register_name --output-on-failure
    Start 18: test_register_name_failure_preserves_keys
1/2 Test #18: test_register_name_failure_preserves_keys ...   Passed    0.21 sec
    Start 19: test_register_name_idempotent
2/2 Test #19: test_register_name_idempotent ...............***Skipped   0.02 sec
100% tests passed, 0 tests failed out of 2

$ grep -A 20 'rc = messenger_register_name' messenger/src/api/engine/dna_engine_identity.c | grep -c 'rmdir_recursive\|qgp_platform_remove'
0

$ grep -c 'keys preserved for retry' messenger/src/api/engine/dna_engine_identity.c
2

$ grep -n 'DNA_VERSION_PATCH' messenger/include/dna/version.h
13:#define DNA_VERSION_PATCH 194

$ grep -c 'CORE-05' messenger/docs/functions/engine.md
1
```

All acceptance criteria for both tasks satisfied.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 3 — Blocking issue] Also neutralized the `messenger_init` failure branch (lines 1268-1280)**

- **Found during:** Task 1 verification (initial test run)
- **Issue:** The plan targeted only the `if (rc != 0)` branch after `messenger_register_name`. Driving a real failure through the public API (`dna_engine_create_identity_sync`) with no DHT running hits the *earlier* `if (!temp_ctx)` branch first (rc = -99 = `DNA_ERROR_INTERNAL`), and that branch contains an identical destructive cleanup. With only the second branch fixed, `keys/`, `db/`, `wallets/`, `mnemonic.enc` were still wiped before the second branch was ever reached, and the test could not be made GREEN via the public API.
- **Fix:** Replaced the first branch's rmdir/remove sequence with the same non-destructive WARN+return pattern used for the second branch. Same function, same rationale, same single atomic commit. No signature or return-code changes.
- **Files modified:** `messenger/src/api/engine/dna_engine_identity.c`
- **Commit:** `3d57f1b9`
- **Why this is in-scope:** Phase 6 CORE-05 is "do not destroy keys on transient registration failure". Both branches are transient-failure branches in the same function on the same create-with-name code path. The plan's grep guard (`grep -A 20 'rc = messenger_register_name'`) only checked the second branch, which is now clean, but the first branch is part of the same bug class and the same user-visible lockout.

**2. [CLAUDE.md override] `MESSENGER_SECURITY_AUDIT.md` was NOT created**

- **Found during:** Task 2
- **Issue:** The plan asked me to append a Phase 6 fixes section to `messenger/docs/MESSENGER_SECURITY_AUDIT.md`, creating it if needed.
- **Rule:** Root `/opt/dna/CLAUDE.md` (Development Guidelines #5) forbids committing any `*AUDIT*.md` file. The repo's `.gitignore` enforces this with `**/*AUDIT*`, `*SECURITY_AUDIT*`, and related patterns. Creating the file would either violate that rule (if committed) or have no effect (if ignored).
- **Fix:** Security rationale lives in `messenger/docs/functions/engine.md` (the CORE-05 paragraph) plus this SUMMARY and the phase's planning docs (all under `.planning/` which is committable).
- **Commit:** `e756d132`
- **Why this is in-scope:** CLAUDE.md is a hard constraint that outranks plan instructions per the executor spec.

### Test rewrite (implied by plan 01)

Plan 01's test stub contained an explicit `TODO(plan-02): replace the RED precondition block below with real failure injection...`. Plan 02's Task 1 acceptance criteria demands the test flip RED → GREEN. The test file was therefore rewritten — even though `files_modified` in the plan frontmatter didn't list it — because that rewrite is the only path from the plan-01 red stub to plan-02 green. This is a documented inheritance from the plan-01 TODO rather than a deviation.

## Decisions Made

1. **Fix both destructive branches in one commit** — see Deviation #1.
2. **Security doc lives in engine.md, not MESSENGER_SECURITY_AUDIT.md** — see Deviation #2.
3. **Test drives failure through the public sync API with DHT unstarted** — simplest deterministic failure-injection seam, zero stubs, works in CI with no external dependencies.
4. **Version bump is PATCH only** — this is a bug fix with no API changes, per CLAUDE.md CHECKPOINT 8 rules.

## Self-Check

**Files created/modified:**
- `messenger/src/api/engine/dna_engine_identity.c` — FOUND (modified)
- `messenger/tests/test_register_name_failure_preserves_keys.c` — FOUND (rewritten)
- `messenger/include/dna/version.h` — FOUND (modified)
- `messenger/docs/functions/engine.md` — FOUND (modified)

**Commits:**
- `3d57f1b9` — FOUND
- `e756d132` — FOUND

**Tests:**
- `test_register_name_failure_preserves_keys` — PASSED
- `test_register_name_idempotent` — SKIPPED (per plan 01 design)

**Build:**
- `messenger/build` — 0 warnings, 0 errors
- `messenger/tests/build` — test target links and runs cleanly

## Self-Check: PASSED
