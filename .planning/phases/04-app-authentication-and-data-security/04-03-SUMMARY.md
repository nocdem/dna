---
phase: 04-app-authentication-and-data-security
plan: 03
subsystem: flutter-app-security
tags: [sec-07, debugprint-sweep, custom-lint, anti-regression]
dependency_graph:
  requires:
    - 04-01 (custom_lint scaffold, rule DISABLED)
    - 04-02 (SEC-03 + qr_auth_service.dart debugPrint sweep)
  provides:
    - "lib/ is free of debugPrint / print / developer.log calls"
    - "dart run custom_lint is a hard gate (exits non-zero on any future forbidden primitive)"
  affects:
    - messenger/dna_messenger_flutter/lib/screens/qr/
    - messenger/dna_messenger_flutter/lib/ffi/dna_engine.dart
    - messenger/dna_messenger_flutter/tools/dna_lints/lib/dna_lints.dart
tech_stack:
  added: []
  patterns:
    - "custom_lint AST visitor targeting addMethodInvocation + addFunctionExpressionInvocation"
    - "Path-based file filter for lib/ vs lib/l10n/ vs generated .g.dart/.freezed.dart"
key_files:
  created: []
  modified:
    - messenger/dna_messenger_flutter/lib/screens/qr/qr_scanner_screen.dart
    - messenger/dna_messenger_flutter/lib/screens/qr/qr_auth_screen.dart
    - messenger/dna_messenger_flutter/lib/screens/qr/qr_result_screen.dart
    - messenger/dna_messenger_flutter/lib/ffi/dna_engine.dart
    - messenger/dna_messenger_flutter/tools/dna_lints/lib/dna_lints.dart
decisions:
  - "ffi/dna_engine.dart cannot route via DnaLogger because logger.dart imports dna_engine.dart (circular). Every former _debugLog call was DELETED per D-09 conservative default."
  - "debugPrint is a top-level FIELD of type DebugPrintCallback (not a plain function), so addMethodInvocation does NOT see debugPrint calls. A second visitor (addFunctionExpressionInvocation) is required. This was discovered during the proof-test — the first draft of the rule silently missed every debugPrint."
  - "Aliased `import 'dart:developer' as dev; dev.log(...)` is not matched. Documented as T-04-10 accepted limitation; no occurrences in lib/ today."
requirements: [SEC-07]
metrics:
  duration: ~30 min
  completed: 2026-04-13
---

# Phase 4 Plan 3: SEC-07 Final Sweep + Anti-Regression Gate Summary

Completed the SEC-07 (debugPrint leaking auth data) cleanup in the 4 remaining files after plan 04-02, deleted the pre-DnaLogger `_debugLog` helper and all its call sites in `ffi/dna_engine.dart`, then flipped the custom_lint `avoid_dna_log_primitives` rule from its Plan 04-01 scaffold state to fully enabled with a working AST visitor. From this commit onward, `dart run custom_lint` is a hard gate against any future `debugPrint` / `print` / `developer.log` call in `lib/`.

## Tasks Executed

### Task 1 — 9-site sweep + `_debugLog` helper removal

Commit: `9b08f454`

Classification applied per CONTEXT.md D-08 / D-09 and the pre-work in `04-RESEARCH.md §SEC-07`:

| File | Line | Content (before) | Disposition |
|------|------|------------------|-------------|
| `lib/screens/qr/qr_scanner_screen.dart` | 226 | `'QR_SCANNER: auth payload, navigating directly to QrAuthScreen'` | **ROUTE** to `dna_logger.log('QR_SCANNER', …)` — pure flow trace, no payload material |
| `lib/screens/qr/qr_scanner_screen.dart` | 233 | `'QR_SCANNER: ${payload.type} payload, navigating to QrResultScreen'` | **ROUTE** — `payload.type` is a public enum (`auth` / `contact` / `plainText`), no auth bytes |
| `lib/screens/qr/qr_auth_screen.dart` | 53 | `'QR_AUTH _close: rootCanPop=$rootCanPop, localCanPop=$localCanPop'` | **ROUTE** — navigator pop-state booleans only |
| `lib/screens/qr/qr_auth_screen.dart` | 68 | `'QR_AUTH _close: FALLBACK - forcing HomeScreen'` | **ROUTE** — static diagnostic string |
| `lib/screens/qr/qr_auth_screen.dart` | 629 | `'QR_AUTH: Unexpected error during approve: $e'` | **DELETE** (D-09 conservative) — exception text from the approve path may embed `DnaEngineException` messages referencing key / signature material. The error still surfaces to the user via `_errorMessage` state field |
| `lib/screens/qr/qr_result_screen.dart` | 331 | `'_AuthResult didChangeDependencies: _navigated=$_navigated, valid=${_isValidAuthPayload()}'` | **ROUTE** — booleans only |
| `lib/screens/qr/qr_result_screen.dart` | 338 | `'_AuthResult: PUSHING QrAuthScreen (this should not happen anymore)'` | **ROUTE** — static diagnostic |
| `lib/screens/qr/qr_result_screen.dart` | 346 | `'_AuthResult: didChangeDependencies called but _navigated=true, NOT re-pushing'` | **ROUTE** — static diagnostic |
| `lib/ffi/dna_engine.dart` | 16-21 | `void _debugLog(String message) { if (kDebugMode) { print(message); } }` | **DELETED** (helper removed entirely per research finding "pre-DnaLogger era leftover") |

**`_debugLog` call sites inside `ffi/dna_engine.dart`** (18 occurrences, all DELETED):

- 1 auth-sensitive: the `[DART-EVENT] MESSAGE_SENT: … recipient=${recipientFp.substring(0, 16)}…` line. Fingerprints are listed as auth material per D-08 ("fingerprints, private keys, seed phrases"). Deleted.
- 17 flow traces: `[DART-EVENT] Callback invoked after dispose`, `[DART-EVENT] _onEventReceived called`, `[DART-EVENT] Adding to stream`, and 14 `[DART-DISPOSE]` progress lines. These contain no auth material and would normally be candidates for routing, BUT `ffi/dna_engine.dart` is imported by `lib/utils/logger.dart` — routing through `DnaLogger` from inside `dna_engine.dart` would create a circular import. Applying D-09 "when in doubt, delete": all deleted. Higher-level callers in providers / screens observe the same state via `DnaEngine`'s public event stream, so observability is not lost in practice.

The head comment block in `ffi/dna_engine.dart` now documents the SEC-07 rationale so future maintainers understand why no logging primitive is allowed in this file.

**Verification:**

```
$ grep -rn "debugPrint(" lib/screens/qr/ lib/ffi/dna_engine.dart
(no output)

$ grep -c "_debugLog" lib/ffi/dna_engine.dart
0

$ flutter analyze lib/screens/qr/ lib/ffi/dna_engine.dart
6 issues found  (all pre-existing curly_braces_in_flow_control_structures
                 infos on unrelated dna_engine.dart lines — 0 errors,
                 0 warnings in the touched code)
```

### Task 2 — Flip custom_lint rule and implement AST visitor

Commit: `6df7f629`

Edited `tools/dna_lints/lib/dna_lints.dart`:

1. **Flipped `_enabled`** from `false` to `true`.
2. **Added file filter** `_shouldCheck(String filePath)`:
   - Only Dart files under a `lib/` directory.
   - Excludes `lib/l10n/**` (generated localization per D-11).
   - Excludes `*.g.dart` and `*.freezed.dart` (generated / build artifacts).
   - Paths are normalized to forward-slash before matching so the exclusion list works on every host.
3. **Registered two AST visitors** on the `context.registry`:

   - **`addMethodInvocation`** matches `print(...)` (with `node.target == null`) and `developer.log(...)` (with `target.toSource() == 'developer'`).
   - **`addFunctionExpressionInvocation`** matches `debugPrint(...)`. This visitor is **load-bearing**: `debugPrint` is declared in `package:flutter/foundation.dart` as
     ```dart
     DebugPrintCallback debugPrint = debugPrintThrottled;
     ```
     — i.e. a top-level **field** of function type, not a plain function. The analyzer parses `debugPrint('x')` as a `FunctionExpressionInvocation`, not a `MethodInvocation`, so a MethodInvocation-only visitor silently misses every `debugPrint` call site. This was discovered during the proof-test when the first draft of the rule reported `print` and `developer.log` but not `debugPrint`. Second visitor added.

4. **Documented T-04-10 accepted limitation** in the rule source: aliased `import 'dart:developer' as dev; dev.log(...)` calls are not matched because the visitor inspects `target.toSource()`, not the import prefix element. No occurrences in `lib/` today; aliased-prefix resolution via the element model is deferred.

**Proof-test (T-04-09 mitigation verified):**

```
Step 1 — Create sandbox violation file:
  lib/tmp_proof_test.dart containing debugPrint(), print(), developer.log()
  (with // ignore_for_file: unused_element, avoid_print)

Step 2 — Run dart run custom_lint:
  lib/tmp_proof_test.dart:7:3 • Use DnaLogger … • avoid_dna_log_primitives • ERROR
  lib/tmp_proof_test.dart:8:3 • Use DnaLogger … • avoid_dna_log_primitives • ERROR
  lib/tmp_proof_test.dart:9:3 • Use DnaLogger … • avoid_dna_log_primitives • ERROR
  3 issues found.
  === EXIT=1 ===

Step 3 — rm lib/tmp_proof_test.dart

Step 4 — Re-run dart run custom_lint on real codebase:
  Analyzing...
  No issues found!
  === EXIT=0 ===
```

The rule fires on ALL THREE primitives (debugPrint, print, developer.log), the plugin returns a non-zero exit code, and the real codebase is clean.

**Verification:**

```
$ grep -c "_enabled = true" tools/dna_lints/lib/dna_lints.dart
1

$ grep -c "_enabled = false" tools/dna_lints/lib/dna_lints.dart
0

$ grep -c "addMethodInvocation" tools/dna_lints/lib/dna_lints.dart
1

$ grep -c "addFunctionExpressionInvocation" tools/dna_lints/lib/dna_lints.dart
1

$ cd messenger/dna_messenger_flutter && dart run custom_lint
No issues found! (exit 0)

$ cd messenger/dna_messenger_flutter && flutter analyze
31 issues found.  (pre-existing infos/warnings on unrelated files — matches
                   the baseline carried from before plan 04-03)

$ cd messenger/dna_messenger_flutter && flutter test
All tests passed!  (89 tests, 0 regressions)

$ ls messenger/dna_messenger_flutter/lib/tmp_proof_test.dart
ls: cannot access … : No such file or directory  (proof scaffolding removed)
```

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] First draft of the AST visitor silently missed every `debugPrint` call**

- **Found during:** Task 2 proof-test.
- **Issue:** The first draft used only `addMethodInvocation` and a `methodName == 'debugPrint'` branch. During the proof test, `print` and `developer.log` violations were reported but `debugPrint` was not. Root cause: `debugPrint` is a top-level field of type `DebugPrintCallback` (not a plain function), so `debugPrint('x')` parses as a `FunctionExpressionInvocation`, not a `MethodInvocation`.
- **Fix:** Added a second visitor via `context.registry.addFunctionExpressionInvocation` that matches `node.function is SimpleIdentifier && function.name == 'debugPrint'`. Without this, the anti-regression gate would have shipped with a blind spot covering the single most common forbidden primitive in the codebase.
- **Files modified:** `messenger/dna_messenger_flutter/tools/dna_lints/lib/dna_lints.dart`
- **Commit:** `6df7f629`

**2. [Rule 2 - Missing critical functionality] Path filter added to the rule**

- **Found during:** Task 2 implementation.
- **Issue:** The scaffolded rule body had a TODO comment about file filtering but no actual filter. Running the rule without exclusions would fire on generated localization and build-artifact files, breaking `dart run custom_lint` on clean codebases that use `flutter gen-l10n` or `build_runner`.
- **Fix:** Implemented `_shouldCheck(filePath)` with explicit exclusions for `lib/l10n/**`, `*.g.dart`, `*.freezed.dart`, and anything outside a `lib/` directory. Per CONTEXT.md D-11.
- **Files modified:** `messenger/dna_messenger_flutter/tools/dna_lints/lib/dna_lints.dart`
- **Commit:** `6df7f629`

No other deviations — plan 04-03 was otherwise executed exactly as written.

## Acceptance Criteria

- [x] 9 remaining SEC-07 sites resolved (2 scanner + 3 auth + 3 result + 1 ffi)
- [x] `_debugLog` helper at `ffi/dna_engine.dart:16-21` deleted along with all 18 call sites
- [x] `grep -rn "debugPrint(" lib/screens/qr/ lib/ffi/dna_engine.dart` → 0 lines
- [x] `grep -c "_debugLog" lib/ffi/dna_engine.dart` → 0
- [x] `_enabled = true` in `tools/dna_lints/lib/dna_lints.dart`
- [x] Real AST visitor implemented (two registry handlers — MethodInvocation + FunctionExpressionInvocation)
- [x] Path-based exclusions (l10n / .g.dart / .freezed.dart / outside lib) implemented
- [x] Proof-test confirms the rule fires on sandbox violations (exit 1, 3 diagnostics)
- [x] Proof-test scaffolding removed (`lib/tmp_proof_test.dart` gone)
- [x] `dart run custom_lint` exits 0 on real codebase (confirms sweep completeness)
- [x] `flutter analyze` — 0 errors (31 unrelated pre-existing infos/warnings, matches baseline)
- [x] `flutter test` — 89/89 passing, 0 regressions
- [x] No public Dart API changes
- [x] Orphan diffs (`.gitignore`, `messenger/dht/shared/nodus_init.c`) untouched
- [x] No version bumps
- [x] Each task committed atomically

## Commits

| Task | Hash | Message |
|------|------|---------|
| 1 | `9b08f454` | `fix(04-03): SEC-07 sweep — 9 debugPrint sites + _debugLog helper removed` |
| 2 | `6df7f629` | `feat(04-03): enable avoid_dna_log_primitives custom_lint with AST visitor` |

## Known Stubs

None. The anti-regression gate is live and enforcing on the real codebase. Aliased `import 'dart:developer' as dev;` is a documented accepted limitation (T-04-10), not a stub — there are no such imports in `lib/` today and the rule's behavior on the canonical form is verified by the proof-test.

## Self-Check: PASSED

- FOUND: `messenger/dna_messenger_flutter/lib/screens/qr/qr_scanner_screen.dart` (modified, 0 debugPrint)
- FOUND: `messenger/dna_messenger_flutter/lib/screens/qr/qr_auth_screen.dart` (modified, 0 debugPrint)
- FOUND: `messenger/dna_messenger_flutter/lib/screens/qr/qr_result_screen.dart` (modified, 0 debugPrint)
- FOUND: `messenger/dna_messenger_flutter/lib/ffi/dna_engine.dart` (modified, 0 debugPrint, 0 `_debugLog`)
- FOUND: `messenger/dna_messenger_flutter/tools/dna_lints/lib/dna_lints.dart` (enabled, dual AST visitor)
- FOUND commit: `9b08f454` (Task 1)
- FOUND commit: `6df7f629` (Task 2)
- MISSING: `messenger/dna_messenger_flutter/lib/tmp_proof_test.dart` — expected, proof scaffolding was removed before commit

All claims in this SUMMARY are backed by commits on the dev branch and verification runs captured above.
