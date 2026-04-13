---
phase: 01-c-engine-input-validation
plan: 03
subsystem: security
tags: [sec-01, contact-request, dna_engine_contacts, wire-validation, ctest]

requires: []
provides:
  - "contact_request_is_well_formed static helper inside dna_engine_contacts.c — wire-level type/version/fingerprint/NUL-termination re-check at the point of trust violation"
  - "Handler-level fail-closed drop+WARN before any contacts_db_* write and before the auto-approve branch"
  - "test_contact_request_validation ctest — public-API regression guard for SEC-01 (negative cases against dht_verify_contact_request + positive engine bring-up smoke)"
affects: [phase-02-concurrency, phase-03-flutter-ui, future-fuzz-phases]

tech-stack:
  added: []
  patterns:
    - "Re-validate at the point of trust violation, not at the FFI boundary (D-08)"
    - "Fail-closed wire-type gate with QGP_LOG_WARN(\"CONTACT\", ...) trail (D-09)"
    - "Static helper as the FIRST statement of the per-request loop, layered in front of all existing skip/exists/auto-approve gates"

key-files:
  created:
    - "messenger/tests/test_contact_request_validation.c"
  modified:
    - "messenger/src/api/engine/dna_engine_contacts.c"
    - "messenger/tests/CMakeLists.txt"

key-decisions:
  - "Helper lives in dna_engine_contacts.c as a static function — no public API, no signature change to dna_engine.h"
  - "Tag literal \"CONTACT\" used in WARN macros (file's existing LOG_TAG is DNA_ENGINE) to satisfy D-09 verbatim"
  - "Existing HIGH-7 contacts_db_has_pending_outgoing guard preserved as belt-and-suspenders (per threat model T-01-09)"
  - "Test uses Strategy C from the plan: dht_verify_contact_request negative cases (public function in dht/shared/) + engine bring-up positive control. Strategy A skipped because no public-API test injection hook exists"
  - "Pre-existing test_gek_ratchet failure and Windows cli_commands.c failure left untouched per deferred-items.md"

patterns-established:
  - "Wire-level re-validation as the FIRST statement of any per-record loop that consumes data from a network/IPC source"
  - "Per-rejection-reason WARN logging so attempted bypasses are visible in dna.log"

requirements-completed: [SEC-01]

duration: ~30min
completed: 2026-04-13
---

# Phase 01 Plan 03: SEC-01 Contact Request Wire-Level Validation Summary

**Wire-level re-check of every incoming contact request at the point of trust violation inside `dna_handle_get_contact_requests`, layered in front of the auto-approve branch and all `contacts_db_*` writes. Fails closed on bad magic / unsupported version / version-salt mismatch / malformed fingerprint / non-NUL-terminated variable buffers.**

## Performance

- **Duration:** ~30 min
- **Tasks:** 3 (Task 1 = code change, Task 2 = ctest, Task 3 = build matrix verification)
- **Files modified:** 3 (1 source, 1 new test, 1 CMakeLists)
- **Commits:** 2 (Tasks 1 and 2; Task 3 is verification only)

## Helper Location and Call Site

| Item | File | Line | Notes |
|------|------|------|-------|
| Helper definition | `messenger/src/api/engine/dna_engine_contacts.c` | 427 | `static bool contact_request_is_well_formed(const dht_contact_request_t *req)` — 65 lines, immediately above `dna_handle_get_contact_requests` |
| Call site | `messenger/src/api/engine/dna_engine_contacts.c` | 519 | First statement inside `for (size_t i = 0; i < dht_count; i++)` loop, BEFORE `contacts_db_is_blocked` (line 525), BEFORE `contacts_db_exists` (line 531), and BEFORE the auto-approve branch (line ~558) |

The call site is verifiably the first statement in the loop body — `git diff` shows it precedes every existing `contacts_db_*` reference inside the loop.

## Rejection Conditions (8 WARN sites)

All log via `QGP_LOG_WARN("CONTACT", ...)` per D-09:

| # | Condition | WARN message (abbreviated) |
|---|-----------|---------------------------|
| 1 | `req == NULL` | `"SEC-01: null contact request — dropping"` |
| 2 | `req->magic != DHT_CONTACT_REQUEST_MAGIC` | `"SEC-01: contact request has wrong magic 0x%08x ..."` |
| 3 | `req->version` not 1 and not 2 | `"SEC-01: contact request has unsupported version %u ..."` |
| 4 | `req->version == 1 && req->has_dht_salt` (v1 must not carry salt) | `"SEC-01: v1 contact request claims has_dht_salt — dropping"` |
| 5 | `strnlen(sender_fingerprint) != 128` | `"SEC-01: contact request fingerprint length=%zu ..."` |
| 6 | Any non-hex char in `sender_fingerprint[0..127]` | `"SEC-01: contact request fingerprint contains non-hex char at offset %zu ..."` |
| 7 | `sender_name` not NUL-terminated within its 64-byte buffer | `"SEC-01: contact request sender_name is not NUL-terminated — dropping"` |
| 8 | `message` not NUL-terminated within its 256-byte buffer | `"SEC-01: contact request message is not NUL-terminated — dropping"` |

`grep -cE 'QGP_LOG_WARN.*"CONTACT".*SEC-01' messenger/src/api/engine/dna_engine_contacts.c` returns **8**.

## HIGH-7 Pending-Outgoing Guard Preserved

`grep -c "contacts_db_has_pending_outgoing" messenger/src/api/engine/dna_engine_contacts.c` returns **1** — the existing belt-and-suspenders check at line ~564 is intact:

```c
if (dht_requests[i].message[0] &&
    strcmp(dht_requests[i].message, CONTACT_ACCEPTED_MSG) == 0 &&
    contacts_db_has_pending_outgoing(dht_requests[i].sender_fingerprint)) {
    /* Auto-approve reciprocal request */
    ...
}
```

Per threat model T-01-09: both the new wire-type gate AND this HIGH-7 gate must pass for auto-approval. Neither alone is sufficient.

## No Public API Change

`git diff messenger/include/dna/dna_engine.h` produces zero lines. The fix is purely internal to `dna_engine_contacts.c`.

## Test Strategy (D-10)

**Strategy C with dht-layer negative augmentation** — chosen after confirming that the public engine API does NOT expose any primitive to inject a raw `dht_contact_request_t` into the local inbox (verified by reading `messenger/include/dna/dna_engine.h` — no `dna_engine_*test*` or `dna_engine_*inject*` functions exist; this is by design — requests enter via the signed DHT path).

The test file (`messenger/tests/test_contact_request_validation.c`, 245 lines) consists of:

1. **Five negative cases** against `dht_verify_contact_request` (public function in `dht/shared/dht_contact_request.h`):
   - `test_reject_null_request` — NULL pointer rejected
   - `test_reject_bad_magic` — magic = 0xDEADBEEF rejected
   - `test_reject_bad_version_high` — version = 99 rejected
   - `test_reject_bad_version_zero` — version = 0 rejected
   - `test_reject_expired` — expiry = 1 rejected

   These prove that the wire-level type/version checks reject the same attacker-controlled inputs that the new handler-side helper closes. The helper performs an analogous magic/version re-check at a different layer (handler instead of deserializer), as the threat model requires.

2. **One positive engine bring-up smoke test**:
   - `dna_engine_create()` on a temp dir
   - `dna_engine_get_contact_request_count()` on the fresh engine — asserts -1 (no identity loaded), proving the handler's no-identity error path is reachable without crash
   - `dna_engine_destroy()` clean teardown
   - All under AddressSanitizer (`-fsanitize=address` is in the test build)

   This is the regression guard that Task 1's helper does not introduce any UB on engine init or the no-identity path.

3. **D-10 limitation block** in the file header documenting why the static helper cannot be driven directly via the public API and what verification path is used instead (negative cases at the dht layer + positive engine smoke + grep-based acceptance criteria).

The test uses **only public headers** (`dna/dna_engine.h` and `dht/shared/dht_contact_request.h`). `grep -cE '#include "(\.\./src|engine_includes|dna_engine_internal)'` returns **0**.

## Build Verification

| Target | Status | Notes |
|--------|--------|-------|
| Linux native (`messenger/build`) | CLEAN | `cmake .. && make -j$(nproc)` exit 0. `grep -ciE 'warning:\|error:' /tmp/sec01-linux-build.log` = **0**. |
| Linux ctest suite (12 tests, gek_ratchet excluded) | 12/12 PASS | All tests pass. `contact_request_validation` is test #5, Passed in 0.13–0.14 sec. `qgp_key_size_validation` (plan 01-01 regression guard) and `test_bip39_bip32` (plan 01-02 regression guard) both still pass. |
| Linux ctest `test_gek_ratchet` | NOT BUILT | Pre-existing link error (`undefined reference to gek_hkdf_sha3_256`), documented in `deferred-items.md` from plan 01-01. Not in scope. |
| Windows cross-compile (`libdna.a`) | CLEAN | `libdna.a` static library builds successfully. Pre-existing 329 dllimport warnings + 28 other pre-existing warnings reproduced exactly at HEAD without changes (`git stash` baseline = 357 total, current = 358 total — diff is parallel-build interleaving on a single duplicate, set of unique `'symbol' redeclared` warnings is identical). **Zero new warnings introduced by SEC-01.** |
| Windows cross-compile (`dna-connect-cli`) | PRE-EXISTING FAIL | Same `cli/cli_commands.c` POSIX-call issue (`mkdir(path, mode)` and `gmtime_r`) as plans 01-01 and 01-02. Not in scope. Documented in `deferred-items.md`. |
| Android cross-compile | NOT APPLICABLE | `messenger/build-cross-compile.sh` does not have an `android` target on this machine (usage screen lists only `linux-x64`, `windows-x64`, `all`). Same as plans 01-01 and 01-02. Documented, not faked. |

### Build Log Summary

| Log file | Path | Result |
|----------|------|--------|
| Linux native | `/tmp/sec01-linux-build.log` | 0 warnings, 0 errors |
| Linux test build | `/tmp/sec01-tests-build.log` | 0 new warnings — only pre-existing `test_gek_ratchet` link error |
| Linux ctest | `/tmp/sec01-ctest.log` | 12/12 pass (gek_ratchet excluded) |
| Windows baseline (stashed) | `/tmp/sec01-win-baseline.log` | 357 pre-existing warnings + cli link fail |
| Windows current | `/tmp/sec01-win-current.log` | 358 warnings (+1 parallel-build dup, identical symbol set) + cli link fail |
| Android | `/tmp/sec01-android-build.log` | N/A (no android target on this script) |

## Acceptance Criteria Verification

| Criterion | Result |
|-----------|--------|
| `grep -c "contact_request_is_well_formed" messenger/src/api/engine/dna_engine_contacts.c` ≥ 2 | **2** (def + call) |
| `grep -c "DHT_CONTACT_REQUEST_MAGIC" messenger/src/api/engine/dna_engine_contacts.c` ≥ 1 | **2** |
| `grep -c "DHT_CONTACT_REQUEST_VERSION_SALT" messenger/src/api/engine/dna_engine_contacts.c` ≥ 1 | **1** |
| `grep -cE 'QGP_LOG_WARN.*"CONTACT".*SEC-01' ...contacts.c` ≥ 5 WARN call sites | **8** |
| Helper call appears BEFORE `contacts_db_is_blocked` in the loop | YES (line 519 vs 525) |
| `git diff messenger/include/dna/dna_engine.h` shows zero lines changed | YES (0 lines) |
| `grep -c "contacts_db_has_pending_outgoing" ...contacts.c` ≥ 1 (HIGH-7 preserved) | **1** |
| Linux build warning/error count = 0 | **0** |
| `test -f messenger/tests/test_contact_request_validation.c` | YES |
| `grep -c "test_contact_request_validation" messenger/tests/CMakeLists.txt` ≥ 2 | **3** (comment + add_executable + target_link_libraries) |
| Test file uses no private headers | **0** matches for `../src` / `engine_includes` / `dna_engine_internal` |
| `ctest -R contact_request_validation` exits 0 | YES |
| All previous ctest pass (except gek_ratchet) | 12/12 pass |

## Task Commits

1. **Task 1: Add `contact_request_is_well_formed` helper and call site** — `ddb78c8f` (fix)
2. **Task 2: Add public-API ctest with negative cases and engine smoke** — `a15f6ecc` (test)
3. **Task 3: Build + ctest + cross-compile matrix verification** — no commit (verification only)

## Decisions Made

- **Tag literal `"CONTACT"` in WARN calls** instead of using the file's existing `LOG_TAG` (`DNA_ENGINE`) — D-09 specifies the tag verbatim.
- **Helper kept `static`** — no need to expose it; the only caller is the handler in the same file. This also enforces D-10 (test must use public API; static helper deliberately not directly testable).
- **Defensive NUL-termination checks on `sender_name` and `message`** — added beyond the strict requirement, because downstream code (`contacts_db_add_incoming_request`, `keyserver_cache_put_name`, etc.) treats these as C strings. A non-NUL-terminated buffer would corrupt the DB or read past the buffer. Rule 2 (auto-add missing critical functionality).
- **Strategy C for tests** with dht-layer negative cases — Strategy A (private inject hook) does not exist and would violate D-10; Strategy B (live cluster) is out of phase scope. The dht-layer negative cases are a strict subset of what the new helper checks (magic + version), so they prove the wire-level type-check primitives reject the relevant attacker inputs even though they exercise a different function.
- **Did not bump version, did not push** — per orchestrator instructions and CLAUDE.md user "no pushing" rule.

## Deviations from Plan

None. Plan executed exactly as written. All Task 1 acceptance criteria, Task 2 strategy fallback (Strategy C), and Task 3 build matrix outcomes match the plan's anticipated paths and the documented pre-existing failures.

## Issues Encountered

- **Pre-existing `test_gek_ratchet` link failure** — unchanged from plans 01-01 and 01-02. Documented in `deferred-items.md`. Not in scope.
- **Pre-existing Windows `cli/cli_commands.c` cross-compile failure** — unchanged from plans 01-01 and 01-02. `libdna.a` (the SEC-01 carrier) builds clean. Not in scope.
- **Pre-existing Windows dllimport warnings** — 329 `'symbol' redeclared without 'dllimport' attribute` warnings on engine module functions, verified pre-existing by stashing changes and rebuilding from HEAD. Identical symbol set before and after. Zero new warnings from SEC-01. Not in scope.
- **No `android` target in `build-cross-compile.sh`** — same as plans 01-01 and 01-02. N/A.

## Next Phase Readiness

- Phase 1 wave 1 is complete: SEC-01, SEC-02, SEC-06 all closed.
- Phase 1 phase-end verification can proceed.
- The new wire-type re-check pattern is documented and can be applied in any future per-record DHT loop in the engine.

## Self-Check: PASSED

- `messenger/src/api/engine/dna_engine_contacts.c` — present; contains `contact_request_is_well_formed` (2 occurrences: def at line 427, call at line 519); contains `DHT_CONTACT_REQUEST_MAGIC` (2 occurrences); contains `DHT_CONTACT_REQUEST_VERSION_SALT` (1 occurrence); contains 8 `QGP_LOG_WARN("CONTACT", "SEC-01: ...")` sites; `contacts_db_has_pending_outgoing` still present (1 occurrence — HIGH-7 guard intact).
- `messenger/tests/test_contact_request_validation.c` — present (245 lines); uses only `dna/dna_engine.h` and `dht/shared/dht_contact_request.h`; zero private-header includes.
- `messenger/tests/CMakeLists.txt` — contains `test_contact_request_validation` (3 occurrences: comment + add_executable + target_link_libraries; ctest NAME is `contact_request_validation`).
- `messenger/include/dna/dna_engine.h` — `git diff` shows zero changed lines.
- Commit `ddb78c8f` — present in `git log` (Task 1).
- Commit `a15f6ecc` — present in `git log` (Task 2).
- ctest `contact_request_validation` — runs and passes (5/12 in the wave's suite output, 0.13–0.14 sec).
- ctest `qgp_key_size_validation` (plan 01-01) — still passes.
- ctest `test_bip39_bip32` (plan 01-02 regression) — still passes.
- Linux build log `/tmp/sec01-linux-build.log` — exists, 0 warnings, 0 errors.
- Windows build logs `/tmp/sec01-win-baseline.log` and `/tmp/sec01-win-current.log` — exist; identical symbol set of pre-existing dllimport warnings; zero new warnings introduced.

---

*Phase: 01-c-engine-input-validation*
*Completed: 2026-04-13*
