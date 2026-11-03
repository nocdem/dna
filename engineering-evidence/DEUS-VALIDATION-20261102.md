# Deus local integration validation — 2026-11-02

This supersedes the handoff's "not applied / no browser QA" status for this isolated checkout only. It does not claim deployment, remote merge, funded acceptance, or working live provider access.

- Baseline/main verified at transfer: `5eb8dc724679b84fb31d22116e381df71b747a3b`.
- Local integration branch: `codex/pq-integration-20261102`.
- Original ZIP copied from the authorized 199 transfer directory by existing SCP; 899554 bytes; SHA256 `85db60005dd1fc577272338ed4ec259f8326da98518fc180e26cb6d79b165777`.
- User's dirty 199 worktree was not edited. Remote push, merge and deployment were not performed.

## Corrections discovered on Deus

Windows Vite module IDs use forward slashes, whereas resolve() returns backslashes. The extension WASM URL transform therefore missed the actual modules; production restore failed despite passing static asset checks. Normalize both sides, and include the missing XION public-key/recovery and disabled TDC recovery/sign loader mappings. A regression checks ten loaders with native/normalized/query IDs. Real packaged extension restore now succeeds.

Windows builds use pinned sharp for the same SVG icon rasterization when no RSVG_CONVERT override is supplied. Archive creation uses a Windows handle opened without following reparse points and rejects reparse sources; existing Linux no-follow behavior remains. No security permission changes were made. Test paths use explicit Python/Chromium, and source LF checkout policy is local. Upstream license and fixture bytes remain unchanged, including original whitespace.

Browser fixtures were updated for current Send/Receive pages and grouped network controls. These updates do not change production UI behavior.

## Completed checks

| Check | Pass | Fail | Skip |
|---|---:|---:|---:|
| Explicit handoff web list (1031 tests) | 931 | 0 | 100 |
| Explicit nonbrowser extension list | 383 | 0 | 0 |
| Extension WASM URL regression | 1 | 0 | 0 |
| Latest static package checks | 3 | 0 | 0 |
| Latest package browser/archive checks | 2 | 0 | 1 |
| Eight-network send/review/cancel Chromium fixture | 1 | 0 | 0 |

Web, Connect and extension production builds passed. The real production browser script passed web and extension restore/key generation, 13 address/network variants per surface, send gates and QR rendering; extension additionally passed encrypted lock/unlock recovery. This script blocks external network access and uses a public test phrase. The eight-network send UI test mocks background preparation; it does not prove live transaction admission. Real funds were not sent.

Web count reconciliation: the original frozen log had 1030 tests (932 passed, 98 skipped). The delivered source additionally contains the passing `browser WASM hedged source-floor admission fixture is reproducible`. Two original passes skip on Windows: the optional native Tidecoin oracle (`TIDECOIN_SCRIPT_ORACLE` absent), and the Debian license-byte comparison (`/usr/share/common-licenses/Apache-2.0` absent). Thus 932 + 1 - 2 = 931; skips 98 + 2 = 100. This is not a claimed full native-oracle rerun.

Package symlink rejection test skips because this Windows account cannot create the test symlink (EPERM); no new privilege was requested. Other unsafe archive/source cases pass.

## Actual baseline comparisons and remaining blockers

- Three site-sdk native parity cases fail ENOENT on both clean baseline and candidate. They need `NODUS_SEND_VECTOR_BIN` (default `/tmp/nodus-send-native-vector`): native C signature mutation verification, native address vectors, and browser/native signature/address parity. No substitute oracle was used.
- `ui-layout.test.js` fails on the same obsolete navigation expectation on baseline and candidate: expected `#assets-panel` and `Send / Receive`, actual `#`, `Send`, `Receive`.
- The unavailable-address portfolio diagnostic is identical on clean baseline and candidate: label `Updating portfolio`, refresh enabled, IXIOS reading false, but ALGO/CKB/SOQ/QTC/XION/SPLD/ASE reading true. The fixture lacks their addresses. The updated `ui-flows` test still fails its settled-label assertion; this latent baseline issue is unresolved, not silently classified as passing.
- The original web smoke fails its null POST-body route handler on baseline too. With the same external-route guard applied to both, baseline and candidate fail the identical obsolete `Send / Receive · Nodus` heading expectation; actual `Send · Nodus`.
- TDC sending remains disabled until a usable hosted provider is established. ASE sending remains testnet only. Live IXIOS access and previously denied upstream probes were not retried. General PQ dApp signing is not implemented by this candidate.

## Package and evidence

Built package: `web-wallet/dist-extension/nodus-wallet-0.1.155.zip` (gitignored build output), SHA256 `b2f5964631fc0f72542e41e1458d7d5c6b139fa87876a4f035de7320b0e9bc76`.

Detailed local logs are in the sibling `../handoff/` directory, particularly `web-tests-deus-final.log`, `extension-tests-deus-final.log`, `browser-production-pq-deus-final.log`, `package-browser-latest.log`, `package-static-latest.log`, `wasm-path-regression.log`, `baseline-browser-comparison.log`, `baseline-unavailable.log`, `candidate-unavailable.log`, `baseline-web-smoke-guarded.log`, and `browser-aggregate-final.log`. Original handoff logs remain under `../handoff/extracted/validation-logs/`.

Final serial aggregate of all eight formerly excluded extension browser files plus the new PQ-send browser file: **62 total, 56 passed, 5 failed, 1 skipped**. Failures are the three missing native SDK-runner cases and the baseline-reproduced ui-flows/ui-layout issues described above. Package checks and the new send UI check are included in this aggregate; do not add their rows again to produce a global total. The separate production web/extension restore script passed after the WASM fix. All test commands have completed.

Local commit attempt did not execute: Git reports `Author identity unknown` / unable to auto-detect email. No author identity was invented and no global Git settings were changed. All 399 changed/new paths remain staged on the isolated branch; HEAD remains the baseline. A complete binary-capable patch is saved at `../handoff/deus-integrated-candidate.patch` for review/application.
