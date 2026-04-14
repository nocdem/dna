---
phase: 04-app-authentication-and-data-security
plan: 02
subsystem: flutter-qr-auth
tags: [sec-03, sec-07, flutter, qr-auth, json-injection, i18n]
requirements_closed: [SEC-03]
requirements_partial: [SEC-07]
dependency_graph:
  requires: [04-01]
  provides:
    - jsonEncode byte-identical canonical signing inputs for v3/v4 QR auth
    - parse-side strict validator for decoded v3 auth payloads
    - invalidQrCode i18n key (English + Turkish)
    - 5/14 SEC-07 sites handled in qr_auth_service.dart
  affects:
    - Plan 04-03 (remaining 9 SEC-07 sites + enabling dna_lints rule)
tech-stack:
  added: []
  patterns:
    - jsonEncode(Map literal) with alphabetical insertion order for byte-identical canonical strings
    - @visibleForTesting static wrapper for private builders (test-only, not public API)
    - Stable i18n errorKey pattern (validator returns 'invalidQrCode'; UI maps to AppLocalizations)
    - Top-level DnaLogger (log(), logError()) routed via 'as dna_logger' alias
key-files:
  created:
    - messenger/dna_messenger_flutter/test/services/qr_auth_service_test.dart
    - messenger/dna_messenger_flutter/test/utils/qr_payload_parser_validation_test.dart
  modified:
    - messenger/dna_messenger_flutter/test/qr_payload_parser_test.dart
    - messenger/dna_messenger_flutter/lib/services/qr_auth_service.dart
    - messenger/dna_messenger_flutter/lib/utils/qr_payload_parser.dart
    - messenger/dna_messenger_flutter/lib/l10n/app_en.arb
    - messenger/dna_messenger_flutter/lib/l10n/app_tr.arb
    - messenger/dna_messenger_flutter/lib/l10n/app_localizations*.dart (12 generated locales)
    - messenger/.gitignore
decisions:
  - "Byte-identical jsonEncode: Map literal keys inserted in alphabetical order (the same order the legacy interpolated template used); Dart jsonEncode emits Map entries in insertion order, so v3/v4 signed payloads are byte-equivalent on clean inputs. Guarded by string-equality tests against hand-computed legacy vectors."
  - "Private _buildCanonicalSignedPayload / _buildCanonicalV4Payload made static; two @visibleForTesting static wrappers (debugBuildCanonicalSignedPayload, debugBuildCanonicalV4Payload) expose them to tests without touching public API."
  - "Validator returns QrPayloadValidationResult with stable errorKey='invalidQrCode' instead of throwing or returning a localized string, so UI layer controls the user-visible wording via AppLocalizations."
  - "Nonce and session_id charset fixed at ^[A-Za-z0-9_-]+$ (URL-safe base64 alphabet) — this is strict enough to reject JSON metacharacters at the parse boundary AND matches the url-safe-base64 encoding the server side uses."
  - "Origin must be http or https scheme with non-empty host — rejects ftp://, javascript:, data:, etc."
  - "SEC-07 line 392 (st payload decode error) routed with exception body stripped to e.runtimeType only, not sanitized via log_sanitizer — the exception bodies from jsonDecode/base64Decode can contain raw payload fragments and runtime type gives operators the failure class without leaking material."
  - "messenger/.gitignore '*_test.*' rule negated for dna_messenger_flutter/test/**/*_test.dart so Flutter test files (which are first-class source) can be added without git add -f."
metrics:
  duration_minutes: ~25
  tasks_completed: 4
  commits: 4
  tests_added: 30
  tests_in_full_suite: 89
  completed_date: 2026-04-13
---

# Phase 4 Plan 2: QR Auth Hardening (SEC-03 full + SEC-07 partial) Summary

Closed SEC-03 end-to-end by replacing string-interpolated JSON construction in the QR auth signing path with byte-identical `jsonEncode(Map literal)` calls, added a strict parse-side validator with localized rejection, and handled the 5 SEC-07 debugPrint sites co-located in the same file. Landed the C-05 pre-flight test import fix first so the Flutter analyzer baseline is honest for subsequent Phase 4 work.

## Tasks Completed

| # | Task | Commit | Files |
|---|------|--------|-------|
| 1 | Pre-flight: fix stale `package:dna_messenger` import in `qr_payload_parser_test.dart` (clears 58 pre-existing analyze errors) | `2c02a9b8` | test/qr_payload_parser_test.dart |
| 2 | SEC-03: jsonEncode byte-identical replacement at 4 sites + 9-test file (3 byte-identical v3, 1 v3 normalization, 3 v3 injection round-trips, 1 v4 byte-identical, 1 v4 injection round-trip) | `590115cb` | lib/services/qr_auth_service.dart, test/services/qr_auth_service_test.dart, messenger/.gitignore |
| 3 | SEC-03 defense-in-depth: parse-side validator (`validateAuthPayload`, `QrPayloadValidationResult`) + 21-test negative suite + `invalidQrCode` i18n key in EN/TR + regenerated all 12 locale bindings | `614d942a` | lib/utils/qr_payload_parser.dart, test/utils/qr_payload_parser_validation_test.dart, lib/l10n/*.arb, lib/l10n/app_localizations*.dart |
| 4 | SEC-07 partial: 5 debugPrint sites in `qr_auth_service.dart` resolved per D-08 (3 DELETE, 2 ROUTE to DnaLogger) | `ab3cda38` | lib/services/qr_auth_service.dart |

## SEC-03: jsonEncode Replacement Sites

All 4 canonical signing-input builders now use `jsonEncode(<String, dynamic>{...})` with alphabetical key insertion order:

| Site | Before (file:line) | Branch | Fields |
|------|--------------------|--------|--------|
| 1 | qr_auth_service.dart:173 | v3 with rp_id + rp_id_hash | expires_at, issued_at, nonce, origin, rp_id, rp_id_hash, session_id |
| 2 | qr_auth_service.dart:179 | v3 with rp_id only | expires_at, issued_at, nonce, origin, rp_id, session_id |
| 3 | qr_auth_service.dart:182 | v3 bare | expires_at, issued_at, nonce, origin, session_id |
| 4 | qr_auth_service.dart:432 | v4 canonical | expires_at, issued_at, nonce, origin, rp_id_hash, session_id, sid, st_hash |

**Byte-identical guarantee:** The 4 byte-identical tests hand-construct the exact legacy template string and assert `expect(jsonEncodeOutput, equals(expected))`. On clean inputs (no JSON metacharacters), the output is identical to the legacy interpolated form — v3/v4 signatures produced by the new code verify correctly on the receive side without any wire protocol change.

**Injection hardening:** Three additional tests inject `"`, `\`, newline, `}`, null byte, and Unicode into nonce / origin / session_id and assert the output is valid JSON that round-trips cleanly through `jsonDecode`, and that no smuggled keys appear in the decoded map.

## SEC-03 Parse-side Validator

`validateAuthPayload(Map<String, dynamic> raw) -> QrPayloadValidationResult` in `qr_payload_parser.dart`:

- **Allowed keys:** `{expires_at, issued_at, nonce, origin, rp_id, rp_id_hash, session_id}` — any other key rejects.
- **Required keys:** expires_at, issued_at, nonce, origin, session_id (rp_id and rp_id_hash optional).
- **Type checks:** expires_at/issued_at are `int`, string fields are `String`.
- **Length bounds:** nonce 1..128, origin 1..2048, rp_id 1..253 (DNS label max), rp_id_hash 1..256, session_id 1..128.
- **Charset:** nonce and session_id must match `^[A-Za-z0-9_-]+$`. Origin must parse via `Uri.tryParse`, scheme must be http or https, host non-empty.
- **Failure:** returns `QrPayloadValidationResult.failure('invalidQrCode')`. UI layer maps the stable `errorKey` to `AppLocalizations.of(context).invalidQrCode`.

21 negative tests cover: missing required fields (5 cases), unexpected field, type mismatches (3), length bounds (5), charset/URI (4), errorKey stability (1), two positive cases.

## i18n (CLAUDE.md mandate)

- `lib/l10n/app_en.arb`: `"invalidQrCode": "Invalid QR code"` + `@invalidQrCode` description.
- `lib/l10n/app_tr.arb`: `"invalidQrCode": "Geçersiz QR kodu"`.
- `flutter gen-l10n` regenerated `app_localizations.dart` plus all 12 locale shims (`_ar`, `_de`, `_en`, `_es`, `_it`, `_ja`, `_nl`, `_pt`, `_ru`, `_tr`, `_zh`). Non-EN/TR locales fall through to English automatically per existing project behavior — no new translations added here.

## SEC-07: 5 debugPrint Sites in qr_auth_service.dart

Classification per D-08 "auth-sensitive → delete, flow trace → route":

| Line (before) | Content | Classification | Action |
|---------------|---------|----------------|--------|
| 115 | `debugPrint('QR_AUTH: payload_v=… payload_len=… payload_sha256=…')` | Hash is a linkable identifier derived from session_id+nonce+origin | DELETE |
| 254 | `debugPrint('QR_AUTH: Auth request denied by user: ${payload.origin}')` | origin is a public URI, flow trace | ROUTE via `dna_logger.log('QR_AUTH', …)` |
| 330 | `debugPrint('QR_AUTH_V4: sid=$sid payload_sha256=$payloadHash')` | sid is the v4 session identifier, hash is linkable | DELETE |
| 368 | `debugPrint('QR_AUTH_V4: verifyUrl=$verifyUrl')` | URL embeds origin and possibly session id in query/path | DELETE |
| 392 | `debugPrint('QR_AUTH_V4: Failed to decode st payload: $e')` | Error path; `$e` may contain raw st payload bytes | ROUTE via `dna_logger.logError('QR_AUTH_V4', 'Failed to decode st payload: ${e.runtimeType}')` — exception body stripped |

Post-edit counts in `lib/services/qr_auth_service.dart`:
- `debugPrint(` → 0
- `print(` (anchored) → 0
- `developer.log(` → 0

## Public API Invariant

`git diff 787500ff HEAD -- lib/services/qr_auth_service.dart` shows:
- `_buildCanonicalSignedPayload` (private) → now `static`, same signature, body changed.
- `_buildCanonicalV4Payload` (private) → now `static`, same signature, body changed.
- Two ADDED `@visibleForTesting` static methods `debugBuildCanonicalSignedPayload`, `debugBuildCanonicalV4Payload` — test-only per `package:meta` annotation, not part of the public screen-facing API.
- Public methods `approve()`, `deny()` — signatures unchanged.

Per D-06 and the plan's acceptance criteria, test-only `@visibleForTesting` additions are explicitly allowed and do not constitute a public API change.

## Verification

| Gate | Result |
|------|--------|
| `flutter analyze` on qr_auth_service.dart | 0 issues |
| `flutter analyze` on qr_payload_parser.dart | 0 issues |
| `flutter analyze` (whole package) errors | 0 (31 pre-existing warnings/info in unrelated files: wallet_screen, wall_post_tile, create_post_screen — out of scope per Rule "SCOPE BOUNDARY") |
| `flutter test test/services/qr_auth_service_test.dart` | 9/9 pass |
| `flutter test test/utils/qr_payload_parser_validation_test.dart` | 21/21 pass |
| `flutter test test/qr_payload_parser_test.dart` | 31/31 pass (post-import-fix) |
| `flutter test` (full Flutter suite) | 89/89 pass, All tests passed |
| `dart run custom_lint` | No issues found (rule still disabled by 04-01 — 04-03 enables it) |
| `grep -c "package:dna_messenger" test/qr_payload_parser_test.dart` | 0 |
| `grep -c "jsonEncode(" lib/services/qr_auth_service.dart` | 8 (4 canonical builders + 4 pre-existing) |
| `grep -c "debugPrint(" lib/services/qr_auth_service.dart` | 0 |
| `grep -c "invalidQrCode" lib/l10n/app_en.arb` | 2 (key + @-metadata) |
| `grep -c "invalidQrCode" lib/l10n/app_tr.arb` | 1 |
| Messenger C ctest | Not re-run (no C code touched; baseline 16/17 from Phase 2/3 remains) |

## Deviations from Plan

### Auto-fixed issues

**1. [Rule 3 - Blocking] Flutter test files gitignored by `*_test.*` rule**

- **Found during:** Task 2 (attempting to commit the new test file)
- **Issue:** `messenger/.gitignore:147` has a global `*_test.*` rule that matches Dart test files. The three pre-existing Flutter test files (`qr_payload_parser_test.dart`, `registered_name_validator_test.dart`, `log_sanitizer_test.dart`) are already tracked and so are grandfathered, but any new test file fails `git add` without `-f`.
- **Fix:** Added a negation rule `!dna_messenger_flutter/test/**/*_test.dart` immediately after line 147. Verified with `git check-ignore -v` and `git add` on the new test file.
- **Files modified:** `messenger/.gitignore`
- **Commit:** `590115cb` (bundled with Task 2 so the new test file could be committed atomically).
- **Justification:** Flutter test sources are first-class source code per CLAUDE.md and the rule should not block them. This is a minimal, scoped negation — other project areas still use `*_test.*` to ignore test artifacts.

### Plan-specified items executed without change

- Task 1 pre-flight: exactly as written, 1-line import fix.
- Tasks 2-4 followed the plan's acceptance criteria directly. No architectural decisions required.

### Public API

- No public API signature changes. `@visibleForTesting` static test wrappers were added as explicitly permitted by the plan's acceptance criteria for Task 2.

## Files Outside Plan Scope (Not Touched)

- `lib/screens/qr/qr_scanner_screen.dart`, `qr_auth_screen.dart`, `qr_result_screen.dart`, `lib/ffi/dna_engine.dart` — remaining 9 SEC-07 sites are Plan 04-03's scope per the wave-2 file-overlap plan.
- `lib/providers/app_lock_provider.dart` — SEC-08, Plan 04-04.
- `tools/dna_lints/lib/dna_lints.dart` — the rule stays disabled until Plan 04-03 enables it.
- Orphan working-tree diffs in `.gitignore` (root) and `messenger/dht/shared/nodus_init.c` — untouched per the sequential-execution instruction.

## Self-Check: PASSED

Verified:
- `test/qr_payload_parser_test.dart` exists, imports `package:dna_connect` — FOUND
- `test/services/qr_auth_service_test.dart` exists and runs — FOUND
- `test/utils/qr_payload_parser_validation_test.dart` exists and runs — FOUND
- `lib/l10n/app_en.arb` contains `invalidQrCode` — FOUND
- `lib/l10n/app_tr.arb` contains `invalidQrCode` — FOUND
- `lib/l10n/app_localizations_en.dart` generated `String get invalidQrCode => 'Invalid QR code';` — FOUND
- `lib/l10n/app_localizations_tr.dart` generated `String get invalidQrCode => 'Geçersiz QR kodu';` — FOUND
- Commits `2c02a9b8`, `590115cb`, `614d942a`, `ab3cda38` all present in `git log` — FOUND
- `debugPrint(` count in qr_auth_service.dart → 0 — VERIFIED
- `jsonEncode(` count in qr_auth_service.dart → 8 — VERIFIED
- Full `flutter test` suite → 89/89 passing — VERIFIED
- `dart run custom_lint` → 0 issues — VERIFIED
