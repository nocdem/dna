# Roadmap: DNA Connect Stabilization

## Overview

This roadmap delivers a stabilized DNA Connect messenger by systematically fixing bugs bottom-up through the stack: C engine security and concurrency first (eliminating root causes), then Flutter app hardening and UI fixes (eliminating symptoms). Every phase delivers verifiable correctness improvements. The ordering follows the dependency graph -- C engine bugs manifest as phantom Flutter issues, so fixing the foundation first prevents wasted effort in higher layers.

## Phases

**Phase Numbering:**
- Integer phases (1, 2, 3): Planned milestone work
- Decimal phases (2.1, 2.2): Urgent insertions (marked with INSERTED)

Decimal phases appear between their surrounding integers in numeric order.

- [ ] **Phase 1: C Engine Input Validation** - Fix contact request bypass, key file size validation, and mnemonic memory exposure
- [ ] **Phase 2: Concurrency Safety** - Fix all thread safety and race condition bugs as one coordinated batch with global lock ordering
- [ ] **Phase 3: Unsafe C Pattern Remediation** - Replace all strcpy/sprintf with safe alternatives across the codebase
- [ ] **Phase 4: App Authentication and Data Security** - Fix QR auth injection, app lock bypass, and auth data leaks in release builds
- [ ] **Phase 5: Seed Phrase Protection** - Fix clipboard seed exposure and add screen capture protection on seed export
- [ ] **Phase 6: C Engine Core Flow Fixes** - Fix name registration failure and complete DHT metadata privacy salt migration
- [ ] **Phase 7: Flutter UI and Permission Fixes** - Fix feed category display, background notification toggle, and camera permission after reinstall
- [ ] **Phase 8: Cross-Layer Verification** - Verify all fixes work together across the full stack on all platforms

## Phase Details

### Phase 1: C Engine Input Validation
**Goal**: The C engine rejects malicious or malformed input at trust boundaries and does not leak sensitive data in freed memory
**Depends on**: Nothing (first phase)
**Requirements**: SEC-01, SEC-02, SEC-06
**Success Criteria** (what must be TRUE):
  1. A crafted contact request message cannot bypass user approval -- the engine validates message type before processing
  2. Loading a key file with an attacker-controlled size field does not cause unbounded malloc -- the engine enforces maximum size limits
  3. After a mnemonic seed phrase is used and freed, the memory region contains only zeros -- no seed material persists on the heap
**Plans**: 3 plans
- [x] 01-01-PLAN.md — SEC-02 key file size validation in qgp_key_load_encrypted (covers qgp_key_load via delegation) + ctest
- [x] 01-02-PLAN.md — SEC-06 full seed-material zeroization audit across bip39.c, bip39_pbkdf2.c, seed_derivation.c, and engine identity caller
- [x] 01-03-PLAN.md — SEC-01 contact-request wire-type validation inside dna_handle_get_contact_requests + ctest

### Phase 2: Concurrency Safety
**Goal**: All concurrent access to shared state in the C engine is protected by mutexes with a documented global lock ordering that prevents deadlocks
**Depends on**: Phase 1
**Requirements**: SEC-04, SEC-05, THR-01, THR-02, THR-03
**Success Criteria** (what must be TRUE):
  1. The GEK (Group Encryption Key) KEM key pointers are protected by a read-write lock -- concurrent message decryption does not corrupt key state
  2. Engine destroy waits for all backup threads to complete before freeing resources -- no use-after-free when shutting down during a backup operation
  3. The outbox cache can be accessed from multiple threads without corruption -- offline queue operations are serialized by a mutex
  4. Nodus initialization static globals are protected -- concurrent init calls do not produce torn reads or double initialization
  5. The task queue documents and enforces its concurrency contract -- either true MPSC with CAS or documented single-producer constraint
**Plans**: 4 plans
- [x] 02-01-PLAN.md — SEC-04 GEK rwlock in gek.c + copy-to-stack reader pattern + test_gek_concurrent ctest under ASan
- [x] 02-02-PLAN.md — SEC-05 backup_thread_running/restore_thread_running atomic promotion + destroy-ordering preservation + test_engine_destroy_during_backup
- [x] 02-03-PLAN.md — THR-02 g_nodus_init_mutex + pthread_once first-time bootstrap + test_nodus_init_concurrent
- [x] 02-04-PLAN.md — THR-01 dead outbox_cache_* deletion + THR-03 task queue MPSC-via-task_mutex contract docs + messenger/docs/CONCURRENCY.md (L1..L5) + ENABLE_TSAN ctest target with empty tsan.supp

### Phase 3: Unsafe C Pattern Remediation
**Goal**: All unsafe string operations in the codebase are replaced with bounded alternatives, eliminating buffer overflow risk from string handling
**Depends on**: Phase 2
**Requirements**: SAFE-01
**Success Criteria** (what must be TRUE):
  1. Zero instances of strcpy remain in the messenger codebase -- all replaced with strncpy or equivalent bounded copy
  2. Zero instances of sprintf with fixed-size stack buffers remain -- all replaced with snprintf with explicit size limits
  3. The codebase compiles cleanly with no new warnings after all replacements
**Plans**: 5 plans
- [x] 03-01-PLAN.md — Create shared/crypto/utils/qgp_safe_string.h poison header + deploy to dnac/src (Wave 1)
- [x] 03-02-PLAN.md — shared/crypto/ sweep: 4 strcpy sites + poison include across ~29 first-party files (Wave 2)
- [x] 03-03-PLAN.md — nodus/ sweep: 26 sprintf hex-loop sites + poison include across ~41 files (Wave 2)
- [x] 03-04-PLAN.md — messenger blockchain/config/cli sweep: dna_config + eth/bsc/tron/cellframe + cli_commands (Wave 2)
- [x] 03-05-PLAN.md — messenger engine/dht/messaging sweep: engine_includes.h centralization + 17 wallet sites + 7 dht/messaging files (Wave 2)

### Phase 4: App Authentication and Data Security
**Goal**: The app's authentication flow cannot be exploited through injection or bypass, and sensitive auth data is not exposed in release builds
**Depends on**: Phase 1
**Requirements**: SEC-03, SEC-07, SEC-08
**Success Criteria** (what must be TRUE):
  1. QR code authentication constructs JSON using a proper serialization library -- string interpolation is not used for JSON construction, preventing injection
  2. Session IDs, tokens, and other auth data do not appear in Android logcat output in release builds -- all debugPrint calls with auth data are removed or gated
  3. App lock cannot be bypassed by clearing SharedPreferences -- lockout counters and attempt tracking use encrypted storage
**Plans**: 5 plans
- [x] 04-01-PLAN.md — custom_lint plugin scaffold (rule DISABLED) + pubspec + analysis_options wiring (Wave 1)
- [x] 04-02-PLAN.md — Pre-flight test import fix + SEC-03 jsonEncode byte-identical + parse-side validator + 5 debugPrint sites in qr_auth_service.dart (Wave 2)
- [x] 04-03-PLAN.md — SEC-07 remainder sweep (9 sites in screens + ffi) + delete _debugLog helper + flip custom_lint rule to ENABLED (Wave 2)
- [x] 04-04-PLAN.md — SEC-08 migration of 4 fields (enabled/biometrics/failed/lockout) to FlutterSecureStorage + one-shot migration + unit tests (Wave 2)
- [x] 04-05-PLAN.md — Phase gate: flutter analyze + custom_lint + test + build linux + build apk + messenger ctest + nodus + dnac + API diff (Wave 3)
**UI hint**: yes

### Phase 5: Seed Phrase Protection
**Goal**: The seed phrase export flow protects against clipboard exfiltration and screen capture, closing the two remaining exposure windows
**Depends on**: Phase 4
**Requirements**: SEC-09, SEC-10
**Success Criteria** (what must be TRUE):
  1. Copying a seed phrase to clipboard triggers automatic cleanup after a short timeout, and cleanup occurs even if the app is killed before the timer fires
  2. The seed phrase export screen sets FLAG_SECURE (Android) and equivalent protections -- screenshots and screen recordings of the seed phrase screen produce blank output
**Plans**: 3 plans
- [x] 05-01-PLAN.md — SEC-09 clipboard hardening (10s timeout + lifecycle clear + confirmation dialog + toast + en/tr l10n + unit tests) — Wave 1
- [x] 05-02-PLAN.md — SEC-10 SecureDisplayScope widget + wrap both seed display sites + widget test — Wave 2 (depends on 05-01)
- [x] 05-03-PLAN.md — Phase gate: full build/lint/test matrix + no-C-touched diff + public API diff — Wave 3
**UI hint**: yes

### Phase 6: C Engine Core Flow Fixes
**Goal**: Name registration works reliably and DHT metadata privacy migration is complete, with no communication pattern leakage through deterministic outbox keys
**Depends on**: Phase 2
**Requirements**: CORE-04, CORE-05
**Success Criteria** (what must be TRUE):
  1. A user can register a name successfully AND is not locked out on transient failure -- the local identity is preserved and the resume-flow UI handles retry. (Name-change capability is explicitly DEFERRED to a future phase per post-research D-04 RESOLVED.)
  2. DHT outbox keys use privacy salts -- deterministic keys that leak communication patterns are no longer generated. Group outbox uses per-group salts; DM outbox NULL-salt fallback is closed.
  3. Hard cutover migration for group outbox: salted-only writes and reads from day one. Pre-existing unsalted in-flight entries within their 7-day TTL window may become unreadable -- accepted tradeoff per post-research D-07/D-08/D-11 RESOLVED.
**Plans**: 7 plans
- [x] 6-01-wave0-test-scaffolding-PLAN.md — Wave 0 RED test stubs + audit script + CMake registration
- [x] 6-02-core05-lockout-fix-PLAN.md — CORE-05 non-destructive registration failure handling
- [x] 6-03-groups-db-v3-migration-PLAN.md — groups.db v2->v3 schema adding dht_salt + has_dht_salt
- [ ] 6-04-group-outbox-salt-hard-cutover-PLAN.md — CORE-04 group outbox salted hard cutover + GEK-channel salt distribution
- [ ] 6-05-dm-outbox-null-salt-closure-PLAN.md — CORE-04 close NULL-salt branch in dht_dm_outbox + salt-agreement gate
- [ ] 6-06-offline-queue-dead-code-removal-PLAN.md — CORE-04 remove dead unsalted-key functions from dht_offline_queue.c
- [ ] 6-07-dht-producer-audit-signoff-PLAN.md — Producer audit appendix + full build matrix + manual register-name gate

### Phase 7: Flutter UI and Permission Fixes
**Goal**: Feed categories display correctly and permission requests work on first attempt after install or reinstall
**Depends on**: Phase 6
**Requirements**: CORE-01, CORE-02, CORE-03
**Success Criteria** (what must be TRUE):
  1. Feed categories show human-readable names, not SHA256 hash strings -- no 64-character hex values visible in the feed UI
  2. Toggling the background notification permission switch ON triggers the system permission request dialog -- the toggle is not cosmetic-only
  3. Opening the QR scanner after a fresh install or reinstall prompts for camera permission -- the app does not silently fail to request the permission
**Plans**: TBD
**UI hint**: yes

### Phase 8: Cross-Layer Verification
**Goal**: All fixes from phases 1-7 work together without regressions across the full stack and all target platforms
**Depends on**: Phase 1, Phase 2, Phase 3, Phase 4, Phase 5, Phase 6, Phase 7
**Requirements**: (verification phase -- validates all prior requirements)
**Success Criteria** (what must be TRUE):
  1. The messenger C library builds cleanly with zero warnings on Linux, Android (cross-compile), and Windows (cross-compile)
  2. All existing ctest tests pass after the full set of stabilization changes
  3. The contact request, messaging, and token sending happy paths work end-to-end without errors in a Linux build
**Plans**: TBD

## Progress

**Execution Order:**
Phases execute in numeric order: 1 → 2 → 3 → 4 → 5 → 6 → 7 → 8

| Phase | Plans Complete | Status | Completed |
|-------|----------------|--------|-----------|
| 1. C Engine Input Validation | 0/0 | Not started | - |
| 2. Concurrency Safety | 0/0 | Not started | - |
| 3. Unsafe C Pattern Remediation | 0/0 | Not started | - |
| 4. App Authentication and Data Security | 0/0 | Not started | - |
| 5. Seed Phrase Protection | 0/0 | Not started | - |
| 6. C Engine Core Flow Fixes | 3/7 | In Progress|  |
| 7. Flutter UI and Permission Fixes | 0/0 | Not started | - |
| 8. Cross-Layer Verification | 0/0 | Not started | - |
