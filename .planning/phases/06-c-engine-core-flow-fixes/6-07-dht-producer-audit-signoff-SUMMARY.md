---
phase: 6
plan: 7
subsystem: dht-producer-audit
tags: [core-04, core-05, audit, sign-off, phase-final]
requires: [6-02, 6-03, 6-04, 6-05, 6-06]
provides: ["DHT Producer Audit appendix in DHT_SYSTEM.md", "Phase 6 final version bump", "full build-matrix verification"]
affects: [messenger/docs/DHT_SYSTEM.md, messenger/include/dna/version.h]
tech-stack:
  added: []
  patterns:
    - "Static CI-guardable producer-audit script (audit_dht_keys.sh)"
    - "Classification appendix co-located with DHT architecture docs"
key-files:
  created: []
  modified:
    - messenger/docs/DHT_SYSTEM.md
    - messenger/include/dna/version.h
key-decisions:
  - "Appendix placed in DHT_SYSTEM.md (not MESSENGER_SECURITY_AUDIT.md) per CLAUDE.md *SECURITY_AUDIT* gitignore rule"
  - "test_gek_ratchet pre-existing link failure excluded from ctest run (unrelated to Phase 6)"
  - "Task 3 (manual register-name happy path on cpunk cluster) left as manual checkpoint for operator"
requirements-completed: [CORE-04, CORE-05]
duration: "6 min"
completed: 2026-04-14
---

# Phase 6 Plan 7: DHT Producer Audit & Phase Sign-off Summary

**One-liner:** Closed Phase 6 with a full static classification of every `nodus_ops_put` producer, appended the audit table to `DHT_SYSTEM.md`, bumped the C library to v0.9.199, and verified the full build matrix (C clean, ctest 21/21 green, Flutter Linux + APK debug built).

- **Start:** 2026-04-14T10:14:41Z
- **End:**   2026-04-14T10:20:19Z
- **Duration:** 6 min
- **Tasks completed (autonomous):** 2 of 2 (Task 3 is a blocking manual checkpoint — not executed)
- **Files touched:** 2 (DHT_SYSTEM.md, version.h)
- **Commits:** 2 task commits

## What Was Built

### Task 1 — DHT Producer Audit Appendix (commit `5010773f`)

Walked every file in `messenger/dht/` and `messenger/transport/` that calls
`nodus_ops_put*`. Classified each as:

- **Salted** (5 files): `dht_dm_outbox.c/h`, `dht_contact_request.c`,
  `dht_offline_queue.c`, `dht_contactlist.c`
- **Salted (fixed by Phase 6)** (1 file): `dna_group_outbox.c` — was unsalted
  pre-Phase-6, hard cutover via Plans 6-03 + 6-04.
- **Whitelisted public** (11 files): `dht_profile.c`, keyserver family,
  `dht_followlist.c`, wall family, `dht_bootstrap_registry.c`
- **Whitelisted encrypted** (4 files): `dht_gek_storage.c`, `dht_groups.c`,
  `dht_addressbook.c`, `dht_geks.c`, `dht_message_backup.c`
- **Whitelisted bootstrap** (1 file): `dht_salt_agreement.c` — deterministic
  by protocol necessity; dual-encrypted content
- **Whitelisted residual** (1 file): `dht_grouplist.c` — unsalted,
  content-encrypted, cohort-UUID-only exposure accepted
- **Whitelisted (disabled)** (3 files): `dna_channels.c/h`,
  `dht_channel_subscriptions.c` — re-audit gate on `DNA_CHANNELS_ENABLED`
- **Whitelisted infrastructure** (2 files): `nodus_ops.c/h` wrapper itself

**Total:** 27 classified entries. `messenger/transport/` produces **zero**
`nodus_ops_put` calls — all DHT writes flow through `messenger/dht/`.

The appendix includes residual-risk notes for the 4 accepted-non-salted
surfaces and a verification pointer at `audit_dht_keys.sh`.

### Task 2 — Version Bump + Build Matrix (commit `e368b0be`)

| Check | Result |
|-------|--------|
| `cmake .. -DBUILD_TESTING=ON` | OK |
| `make -j$(nproc)` for libdna | **0 warnings, 0 errors** |
| `ctest --output-on-failure -E test_gek_ratchet` (in `tests/build/`) | **21/21 passed** (1 clean skip: `test_register_name_idempotent`; `test_gek_ratchet` excluded — see Deferred Issues) |
| `flutter build linux` | OK (built `dna_connect` bundle) |
| `flutter build apk --debug` | OK after Rule 3 env fix (`ANDROID_HOME=/opt/android-sdk`) |
| `audit_dht_keys.sh` | **exit 0** |
| `git diff --stat main..HEAD -- messenger/include/dna/` | **Only `version.h` changed** (D-10 binary-stability confirmed) |
| `DNA_VERSION_PATCH` | 198 → **199** (0.9.199) |

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 3 - Blocking] Appendix placement — cannot land in MESSENGER_SECURITY_AUDIT.md**

- **Found during:** Task 1 (before first edit)
- **Issue:** The plan instructs the appendix to be appended to
  `messenger/docs/MESSENGER_SECURITY_AUDIT.md`. However, root `CLAUDE.md`
  §"No Audit Files in Git" + `.gitignore:9` (`*SECURITY_AUDIT*`) forbid any
  such file from being committed, and the file does not exist on disk.
- **Fix:** Per the execution-prompt hard_constraints that anticipated this
  exact collision, placed the appendix in `messenger/docs/DHT_SYSTEM.md` as
  a new "DHT Producer Audit (Phase 6)" section at the end of the document.
  This is within the allowed set in the prompt.
- **Files modified:** `messenger/docs/DHT_SYSTEM.md`
- **Verification:** `grep -c 'DHT Producer Audit' messenger/docs/DHT_SYSTEM.md` → 1; audit script still exit 0.
- **Commit:** `5010773f`

**2. [Rule 3 - Blocking] `flutter build apk --debug` — wrong Android SDK path in local.properties**

- **Found during:** Task 2, Flutter APK build step
- **Issue:** The untracked dev-local file
  `messenger/dna_messenger_flutter/android/local.properties` points
  `sdk.dir` at `/usr/lib/android-sdk`, which on this workstation contains
  only `platform-tools/` — no `cmdline-tools/`, no NDK, no licences. Gradle
  fails with `LicenceNotAcceptedException: ndk;28.2.13676358`. The real
  Android SDK is at `/opt/android-sdk`.
- **Fix:** (a) Accepted SDK licences at `/opt/android-sdk` with
  `yes | sdkmanager --licenses` (idempotent env fix). (b) Flutter
  regenerates `local.properties` each build, so the `sed` fix was
  overwritten. The working solution is to invoke the build with
  `ANDROID_HOME=/opt/android-sdk ANDROID_SDK_ROOT=/opt/android-sdk
  flutter build apk --debug`, which succeeds.
- **Files modified:** none committed. `local.properties` is untracked
  dev-machine config.
- **Verification:** APK built successfully
  (`build/app/outputs/flutter-apk/app-debug.apk`).
- **Commit:** n/a (environment fix, not source change)

**Total deviations:** 2 auto-fixed (both Rule 3 - Blocking).
**Impact:** Neither affects Phase 6 deliverables. The appendix placement
deviation was pre-authorised by the execution prompt; the Android SDK
deviation is a pure dev-environment config. Worth flagging to other
developers building APKs on this or a similarly-configured machine: either
export `ANDROID_HOME=/opt/android-sdk` in your shell profile, or fix the
template that generates `local.properties`.

## Deferred Issues

### `test_gek_ratchet` — pre-existing link failure

`messenger/tests/test_gek_ratchet.c` fails to link because it references
`gek_hkdf_sha3_256`, which is no longer exported from `libdna.so`:

```
test_gek_ratchet.c:127: undefined reference to `gek_hkdf_sha3_256'
test_gek_ratchet.c:128: more undefined references to `gek_hkdf_sha3_256' follow
```

This is **not caused by Phase 6** — the missing symbol pre-dates plan 6-01.
The execution-prompt hard_constraints explicitly authorised excluding it
("document any pre-existing unrelated failures like `test_gek_ratchet`").
Action: `-E test_gek_ratchet` added to the ctest invocation for this plan's
verification run. A separate plan should repair the test (either restore
the symbol export or rewrite the test against the current public GEK API).
Filed for follow-up phase.

## Verification

All acceptance criteria from the plan verified:

**Task 1 acceptance:**
- [x] `audit_dht_keys.sh` exits 0
- [x] Audit appendix present in `DHT_SYSTEM.md` (grep count: 1 matching header)
- [x] ≥15 classification rows (actual: 27 numbered rows)
- [x] Every file from `grep -rln nodus_ops_put messenger/dht/ messenger/transport/` appears in the table (27 files, every one classified)
- [x] `messenger/transport/` → zero producers (documented explicitly in the appendix)

**Task 2 acceptance:**
- [x] C build: 0 warnings, 0 errors
- [x] ctest: 21/21 pass (with 1 clean skip; `test_gek_ratchet` pre-existing unrelated failure excluded)
- [x] `flutter build linux` success
- [x] `flutter build apk --debug` success (after env fix)
- [x] `audit_dht_keys.sh` exit 0
- [x] `git diff --stat main..HEAD -- messenger/include/dna/` shows only `version.h`
- [x] `DNA_VERSION_PATCH` bumped to phase-final value (199)

## Manual Verification Pending (Task 3 — Checkpoint)

Task 3 is a `checkpoint:human-verify` gate that cannot be executed
autonomously. It is the phase's end-to-end success gate per CORE-05 and
must be run by a human operator against the live cpunk cluster using a
fresh Linux build of `dna-connect` or `dna-connect-cli`.

### Manual Verification Steps

Perform **all four** scenarios. Any failure of scenario 3c (keys/db
destroyed on transient registration failure) means Plan 6-02's CORE-05 fix
regressed and must be revisited before merging.

**Preparation:**
1. Build the latest Linux bundle:
   ```
   cd /home/mika/dev/dna/messenger/dna_messenger_flutter
   flutter build linux
   ```
   The app lives at `build/linux/x64/release/bundle/dna_connect`.
2. (Alternative) Use the CLI: `/opt/dna/messenger/build/cli/dna-connect-cli`.
3. Ensure the live cpunk Nodus cluster is reachable from this machine
   (normal outbound DHT/UDP+TCP working).

**Scenario A — Fresh-install happy path (CORE-05 happy path):**
1. Back up or delete any existing identity dir:
   `mv ~/.dna ~/.dna.bak.manual-verify-6-07` (or use a fresh
   `--data-dir /tmp/dna-verify-6-07`).
2. Launch `dna_connect` (or `dna-connect-cli create-identity`).
3. Generate a new identity and choose a unique name.
4. Confirm registration succeeds and HomeScreen loads with the chosen
   name visible. For CLI: `dna-connect-cli whoami` → shows the name.

**Scenario B — Transient-failure resume flow (CORE-05 fix gate):**
1. Start fresh again (new data_dir or wipe).
2. Generate identity up to "Register". Have the `sudo nmcli networking
   off` command ready in a second terminal.
3. Click "Register", **immediately** run `sudo nmcli networking off`.
4. Confirm the app surfaces a network-error message.
5. In the data_dir, confirm the following still exist (this is the
   CORE-05 fix invariant):
   ```
   ls -la ~/.dna.verify-6-07/
   # Expect: keys/, db/, wallets/, mnemonic.enc present
   ```
6. Run `sudo nmcli networking on`.
7. Re-launch the app. Confirm `IdentitySelectionScreen` shows a
   resume-flow entry for the unregistered fingerprint (not the "Create
   New" only screen).
8. Complete registration from the resume flow. Confirm HomeScreen loads
   with the chosen name.

**Scenario C — Group messaging smoke test (CORE-04 salt cutover gate):**

The Flutter `GroupsScreen` is currently orphaned (not reachable from the
router — see §"Groups-UI Hidden Discovery" in `6-CONTEXT.md`). Verify via
CLI or a direct FFI test harness. If no CLI group commands exist, run the
in-tree `test_group_database_migration_v3` + `test_group_outbox_make_key_salted`
executables as an integration proxy (both already pass under ctest):

```
cd /home/mika/dev/dna/messenger/tests/build
./test_group_database_migration_v3
./test_group_outbox_make_key_salted
```

For a real cross-identity smoke test (requires a second identity on a
second device or a second Linux user account):

1. On Identity A: create a group `verify-6-07` and note the UUID.
2. On Identity B (different machine/user): accept the group invite.
3. Identity A sends a message in the group.
4. Confirm Identity B receives it within ~15s.
5. (Optional, passive DHT inspector) Confirm the published outbox key
   has a hex-salt suffix (`dna:group:<uuid>:out:<day>:<64-hex-chars>`).

**Scenario D — Log capture:**
1. From the Flutter Settings → Debug Log, or by copying
   `~/.dna/dna.log`, save the log for all four scenarios.
2. Attach the log to the manual-verification entry on STATE.md.

### Expected Outcome

All four scenarios pass. If (3c) fails — i.e. the transient network
failure destroys keys/db/wallets — then the CORE-05 fix in Plan 6-02 is
broken and this plan's sign-off must be rolled back.

## Commits

| # | Task | Hash | Message |
|---|------|------|---------|
| 1 | Task 1 — producer audit appendix | `5010773f` | `docs(6-07): add DHT Producer Audit appendix to DHT_SYSTEM.md` |
| 2 | Task 2 — version bump + build matrix | `e368b0be` | `chore(6-07): bump DNA_VERSION_PATCH to 199 (Phase 6 final)` |

## Phase 6 Status

With this plan's autonomous tasks complete, Phase 6 requires **only the
manual end-to-end verification** (Task 3) to close. Once the operator
records an "approved" outcome for the four scenarios above, Phase 6 is
fully closed:

- CORE-04 closed — every DHT producer salted/whitelisted and documented.
- CORE-05 closed — name-registration failure no longer destroys keys.
- D-10 preserved — public API binary-compatible (only `version.h` diff on `include/dna/`).
- RC constraint preserved — no breaking changes; migration was a single
  self-contained release (D-11).

**Next step after manual verification:** Phase complete, ready to plan
Phase 7 (or whatever the roadmap's next phase is).

## Self-Check: PASSED

- [x] `messenger/docs/DHT_SYSTEM.md` contains "DHT Producer Audit" header
- [x] `messenger/include/dna/version.h` shows `DNA_VERSION_PATCH 199`
- [x] Commit `5010773f` exists (`git log` shows it on `dev`)
- [x] Commit `e368b0be` exists (`git log` shows it on `dev`)
- [x] `audit_dht_keys.sh` exit 0 at sign-off time
