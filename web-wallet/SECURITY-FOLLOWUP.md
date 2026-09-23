# Web wallet security follow-up — 2026-09-19

Reviewed baseline: `f48968bd3b669edea302a5d1bbf0c25fcd2add30` on `feat/nodus-web-wallet`.
Scope: browser wallet only. Existing native applications and consensus are unchanged.

## Public portfolio reads (0.1.12)

Opening a wallet now automatically reads all four external networks and requests
fixed asset prices directly from DefiLlama. The portfolio controller receives
only public addresses and endpoints; it never receives the wallet or signing
keys. Price requests include no wallet addresses. All reads use the existing
bounded transport, and network identity checks precede balance reads. Lock
aborts pending requests and a session guard rejects late responses. No new
persistence, backend, API key or script origin is introduced.

Values are keyed by chain and configured contract, validated and aggregated with
integers. Missing, stale, malformed and failed reads cannot become a complete
zero total. Partial totals are labeled incomplete; token amounts remain visible
when only prices fail. Quotes do not influence transfer amounts, fees or signing.
Recovery, vault formats and transfer preparation/signing are unchanged.

Six model/transport regressions and an intercepted production-browser portfolio
suite cover these behaviors. Existing wallet, secret-lifecycle and signing
regressions remain part of verification. This is implementation testing, not an
independent audit or a guarantee of provider accuracy/availability.

## Explicit device-storage consent (0.1.10)

New saves and password changes now require an explicit, initially unchecked
acknowledgement of encrypted browser-storage risks. The existing minimum of
16 characters and weak-password rejection still apply. The save path checks
consent again inside the storage lock before writing; withdrawing it during
encryption prevents the write. Lock and successful saving clear the checkbox.
Creating/restoring remains temporary by default, and existing encrypted copies
are not deleted or migrated by this change.

The open-wallet layout now separates identity, assets/receive, send, activity
and device settings. Send/Receive shortcuts only focus their respective
sections. Network names follow the selector in both flows; the storage label
distinguishes a temporary session from an authenticated saved copy.

All 41 Node tests, the production build, browser smoke, browser security and
Nodus browser checks passed. Added browser coverage verifies absent/withdrawn
consent, short passwords, consent reset, blocked password change without consent,
network labels and dashboard navigation. Responsive checks cover 320–1440px.
All test blockchain traffic was intercepted. This is regression verification,
not a new independent security audit.

## Numbered recovery fields and branding (0.1.5)

Creation, restore and backup verification now use 24 separate numbered inputs.
Full-phrase paste fills all positions even when initiated in a middle field;
shorter pastes preserve neighboring positions, overflow is rejected, and an
empty field cannot be collapsed into a different phrase. Generated fields are
read-only. Every input and suggestion is cleared on cancel, idle expiry and
successful open. The existing derivation, vault and signing implementations
are unchanged. Main-site fonts and logo are self-hosted without CSP changes.

One independent read-only agent reviewed the input/paste and cleanup code and
reported no blocking finding; this is a scoped static review, not a new audit
of the wallet. Chromium verification covers full, partial and excess paste,
real clipboard paste, read-only generation, empty middle fields, checksum
rejection, suggestions, 320px layout and the existing secret-lifecycle flows.
All 41 Node tests and the browser smoke, security and Nodus suites passed.
Browser blockchain traffic remained intercepted; no real transfer was sent.

## Additional review and remediation (0.1.4)

Eight independent read-only agent reviews examined deployed baseline
`c3656eedeccfc2ba4adc277204950df3d6f09a49` on 2026-09-20. The resulting
patches are verified by the implementing session; this is not an external
security certification or a fresh audit of the cryptographic primitives.

| Finding | Change | Regression coverage |
|---|---|---|
| One tab can overwrite another tab's authenticated transaction history | Web Locks serialize storage mutations across tabs; writes authenticate and merge current history | Concurrent writes from two unlocked browser tabs preserve both signed records before broadcast; a later stale-tab write preserves both |
| Password change after phrase-only restore can replace unread history | Password change requires an authenticated saved-wallet session | Browser rejects the change and preserves both encrypted records |
| Hidden unlock password and review metadata survive flow changes/lock | Clear the password when leaving unlock; clear review DOM, explorer URL and in-memory history on lock | Browser checks hidden input, dialog contents and explorer link |
| CPUNK module loading can continue derivation after lock | Abort on lock, bound module fetch to 15 seconds, derive mutable secrets only after loading and cancellation checks | Browser lock aborts the fetch; unit tests cover cancellation during fetch/instantiation and whole-instance memory erasure |
| Normalized TRON URL prevents tracking and applying the default RPC | Compare normalized URLs and construct paths without duplicate slashes | Tracking accepts the same endpoint produced by transfer preparation |
| TRON identity was checked only during tracking | Check mainnet genesis before balance reads, preparation and signing | Wrong genesis prevents preparation and signing/broadcast |
| EVM finality lookup can follow an obsolete canonical check | Observe finality before the final canonical lookup; check same-height finalized hash | A simulated reorganization never becomes confirmed |
| Solana absence after blockhash expiry prematurely stops tracking | Keep the outcome unknown and continue polling | Later finalized inclusion is still observed |
| RPC-selected SPL source can refer to an unrelated delegated account | Sign only the locally derived associated token account; validate returned account metadata | Serialized transfer uses that exact account; substituted/mismatched/insufficient source rejected |
| Clearing browser storage does not lock other tabs | Handle the storage-clear event as a wallet change | Browser clears storage in one tab and verifies the other locks |

The Solana change intentionally removes spending across arbitrary source token
accounts. Balance reads can include those accounts, and the send screen explains
that only the primary associated account is spendable here. This does not turn
RPC replies into cryptographic proofs of account state. Saved-wallet operations
require Web Locks; there is no unsafe per-tab fallback. Existing vault/activity
encryption formats and all recovery/address derivation paths remain unchanged.

Verification commands below run against the production bundle, with external
blockchain traffic intercepted in browser suites. No real-funded transfer is
part of remediation testing. Publication is a separate operation; these source
changes do not establish that the production domain has been updated.

Local results for 0.1.4 on 2026-09-20: `npm ci` succeeded with zero reported
dependency advisories; 41/41 Node tests, production build, browser smoke,
browser security and Nodus browser checks passed with Node 22.22.1, npm 10.9.4
and Chromium 146. Five activity regressions fail against the deployed baseline
and pass with the changes. The existing Vite bundle-size and dependency
`punycode` deprecation warnings remain. Tests used public fixtures and made no
real-chain broadcasts. No production publication is claimed by these results.

## Original September 19 findings

| Finding | Change | Regression evidence |
|---|---|---|
| RT-01: phrase screens never time out | Idle lock covers create, backup verification, restore, password entry and in-flight vault operations; focus/visibility enforce the absolute deadline | Production-browser create/verify/restore expiry and simulated suspended timer |
| RT-02: Solana cleanup wipes a getter copy | The long-lived signer owns its mutable secret buffer; lock overwrites that same buffer | A retained signer reference has zeroed bytes after disposal; signing vectors remain unchanged |
| RT-03: trivial local passwords accepted | New saves/changes require 16 characters and reject obvious common/repeated/sequential passwords; feedback is local | Weak examples fail; an actual old 12-character-password v1 vault still unlocks |
| RT-04: editable history can claim a false payment | Activity v2 uses AES-GCM with a wallet-bound HKDF key, authenticated headers and fresh IVs; unauthenticated legacy/corrupt records cannot enter the tracker | Ciphertext/header tampering, different-wallet key, fake v1 records rejected; browser preserves unreadable data until explicit discard |
| RT-05: unbounded RPC responses | Shared bounded transport covers the direct helper and Ethers, Solana and TRON providers, with body timeout/stream cancellation and JSON/numeric limits | Chunked and oversized bodies, deep/large JSON, large numerics, stalled reads and real SDK paths |

Persisting activity is now asynchronous. For saved wallets, the locally computed signed transaction ID must be durably encrypted before broadcast. Queue writes are serialized and discarded when the wallet or vault changes. All three signing adapters recheck lock state after awaiting persistence. Browser tests pause encryption, lock/delete, then release it and verify that neither a broadcast nor a stale disk write occurs. Mocked native and token transfers still follow the original chain-specific signing rules.

The mnemonic vault format remains version 1. In 0.1.2 the operator restricted the Nodus UI to 24-word base phrases: older saved vaults with shorter phrases are left untouched but are not opened by this UI. The envelope decoder remains backward-compatible; no phrase is converted or silently replaced. Password policy is applied only to new passwords. The activity envelope is version 2 under the existing `nodus.activity.v1` storage slot. Old plaintext activity is deliberately not trusted; the UI offers explicit discard after checking the account explorer. It does not silently migrate possibly forged payment details.

The activity key uses HKDF-SHA256 over the recovery phrase, a 16-byte vault ID as salt, and the distinct `nodus.wallet.activity.v2` info string. AES-GCM uses fresh 12-byte IVs and authenticates the version/ID/cipher/IV header. The key is non-extractable and only retained in the active session. Keys are not persisted separately. This separates activity encryption from the password-derived mnemonic-encryption key.

## Verification

Local results on 2026-09-19: **28/28 Node tests passed**, production build passed,
and both intercepted Chromium suites (`test:browser`, `test:security`) passed.
The existing large-bundle warning remains. These results apply to the follow-up
source tree, not to a deployed domain.

Run from `web-wallet` with the committed lockfile and Node 22.12+:

```sh
npm ci
npm test
npm run build
npm run test:browser
npm run test:security
```

Browser scripts intercept every external request and use public test mnemonics; their accounts must never be assumed unfunded. Set `CHROMIUM_PATH` if Chromium is already installed elsewhere. No real-chain transfer is needed for these checks.

## Deployment boundary

These changes address the local review findings, not a compromised deployment. Malicious same-origin JavaScript or a privileged browser extension can still capture an entered/unlocked phrase or password. Browser memory erasure remains best effort. A password change does not rotate blockchain keys or revoke a stolen older vault copy. Authenticated history can still be rolled back to an older authentic copy, and it is not complete account history. The application trusts its selected RPC for network state.

Use the wallet's dedicated origin and bundled scripts. Build with `npm run build` and publish only `dist` over HTTPS. The supplied static-only `deploy/Caddyfile` provides HTTPS and the HTTP `frame-ancestors 'none'` header; the HTML provides the remaining CSP. All RPC requests, including CPUNK reads, go directly from the browser to HTTPS endpoints. No separate application service is required, and no backend handles seeds or private keys.

After deploying the tested branch, verify the actual HTTPS response headers and browser RPC/CPUNK behavior from `https://wallet.nodusnetwork.io`. The current remote work environment could not verify that host: its DNS lookup failed and HTTPS received a proxy 502. No SSH session, server credentials or deployment workflow was available here. This observation does not establish that public DNS is absent or that the operator's server is down. A live deployment and funded mainnet transfer are not claimed by the local tests.

## Nodus address and recovery follow-up (0.1.2)

The primary wallet identity is now the locally derived Nodus address. Create and
restore require 24 English BIP39 words with a valid checksum. Other-chain keys
continue to derive from that same base phrase. Native balance/send are absent.
CF-20 remains a separate temporary read-only component.

The new WASM bridge reuses unchanged native ML-DSA-87 code. Native C vectors
match the browser result; unit tests verify whole-instance wiping on success and
cancellation. Browser regressions cover stale derivation after lock/reopen, module
loading failure, address copy and encrypted reopen. Local word suggestions read
only the bundled BIP39 dictionary and are cleared on lock/cancel. There is no
server-side seed processing. This extends the original review scope with two
independent read-only bridge reviews; it is not a new audit of the primitives.

## Public RPC and UI follow-up (0.1.3)

The Solana default changes to keyless Solana Vibe Station. Reads are paced to
avoid the observed burst limit; the existing timeout includes queueing. A
regression checks cancellation before fetch, spacing, unchanged other endpoints
and exactly one broadcast attempt even on HTTP 429. No retry, key or relay is
added. CPUNK controls now live inside the open wallet; lock aborts reads and
clears the public address/result. Landing-page and lock behavior are checked
in the intercepted browser smoke suite.

## Web portfolio placement (0.1.13)

CPUNK moved from a separate collapsed panel with a manual derive button and a
manual address/endpoint form into one row of the wallet's own asset list,
alongside ETH/BNB/SOL/TRX, with only a Receive action. Its address now derives
automatically as soon as the wallet opens (create, restore or saved-wallet
unlock), the same trigger point and the same AbortController/`current()`
late-result-guard pattern as the existing Nodus address, instead of waiting for
a button click. Its balance read is likewise automatic, started only once that
address is known, through the same portfolio refresh cycle used for the other
four networks; a CPUNK read failure shows "Balance unavailable" on its own row
and never an inferred zero, and never affects the other networks' reads. What
did **not** change: `src/adapters/cpunk.js`'s request shape, its 64 KiB/15 s
bounds, and `src/cpunk-protocol.js`'s response parsing; `src/cpunk/derive.js`'s
WASM bridge, its per-derivation fresh instance and memory wipe; `src/vault.js`
and the encrypted-activity code path; and transfer preparation/signing for the
four permanent chains. Sending on Cellframe remains impossible: `src/wallet.js`
still has no `cellframe` adapter entry, so `prepareTransfer()` rejects it
before reaching a chain implementation, independent of the UI now also hiding
and disabling the send form for a receive-only network. `VITE_ENABLE_CPUNK=false`
continues to exclude the adapter, the derivation module and its WASM from the
bundle; the Cellframe network option, its automatic derivation call and its
CPUNK asset row are gated by the same flag, checked once at bundle build time.

## Red-team fixes (0.1.15)

Findings from the 2026-09-22 red-team review (`docs/plans/2026-09-22-web-wallet-redteam.md`),
resolved per the writer spec `docs/plans/2026-09-23-wallet-0.1.15-spec.md` and,
where an operator decision was needed, `docs/plans/decisions/2026-09-23-web-wallet-double-send-and-password.md`.
All eight are **fixed in 0.1.15**:

- **E-2 (review dialog focus/timing)** — fixed. `index.html`'s `#review-dialog`
  `.actions` now lists `#cancel-send` before `#confirm-send`, so `showModal()`'s
  default-focus algorithm lands on Cancel. `src/app.js`'s send-review handler
  disables Confirm immediately before `showModal()` and re-enables it after
  600 ms (timer cleared in `closeReview()`); a `keydown` listener on the dialog
  suppresses Enter while Confirm is disabled. A successful broadcast clears the
  recipient and amount fields.
- **B-1 (EVM double-send, uncertain outcome)** — fixed via operator decision 1a
  (automatic resolution, not button-only). `src/adapters/evm.js`'s `prepare()`
  now returns the signed `nonce` and passes it to `onBroadcast`; `src/wallet.js`
  and `src/activity.js`'s `recordActivity` carry it into the saved record.
  `src/app.js`'s send-form handler blocks opening a new review for the same
  EVM chain/address while a non-terminal record exists, and offers a two-click
  "Mark as abandoned" / "Confirm abandon" control per Activity row. Resolution
  is automatic: `src/activity.js`'s `checkActivity`, when a receipt is absent
  and the record carries a saved nonce, reads `eth_getTransactionCount` and
  marks the record `replaced` (terminal) once the account's count has passed
  that nonce; a record without a `nonce` (saved by 0.1.14 or earlier) makes no
  extra read and keeps today's behavior. `replaced` and `abandoned` were added
  to `terminal()` and to `src/activity-storage.js`'s validated status set;
  `abandoned` survives a reload, every other status still resets to `pending`.
- **B-2 (TRON expiration unbounded)** — fixed. `src/adapters/tron.js`'s
  `validateTransaction` rejects a transaction whose `raw_data.expiration` is
  not a safe integer or is more than 10 minutes in the future, before the
  encoding-consistency check.
- **A-1 (password shape filter bypass)** — fixed via operator decision 2b (no
  added dependency). `src/vault.js`'s `validateNewPassword` replaced the
  anchored `^(word)[0-9]*$` regex — defeated by a single trailing non-digit
  character — with: removal of every occurrence of an expanded common-word list
  from the folded password wherever it appears (rejecting if fewer than 8
  characters remain); a repeated-pattern/sequential-run scan over every 8+
  character window of the folded password, not only the password as a whole;
  and, for passwords under 24 characters, a requirement of at least two
  character classes (letter/digit/other). Existing 12-character v1 vaults
  still unlock unchanged.
- **E-3 (lower-case address, no checksum feedback)** — fixed. `src/app.js`'s
  review-details now show `getAddress(to)` (checksummed) on the `To` line for
  Ethereum/BSC, and add a highlighted "Address check" line when the typed
  recipient was all-lower-case hex. Sending is not blocked.
- **E-4 (paste during backup verification)** — fixed. `src/phrase-fields.js`'s
  `createPhraseFields(...).set()` takes an `{ allowPaste }` option; `src/app.js`
  disables it only for the "re-enter your saved phrase" verification step,
  with a visible note. Restore and normal entry are unaffected.
- **E-1 (uncertain-outcome wording without a signed transaction)** — fixed.
  `src/app.js`'s send-failure handler now shows only `error.message` when no
  transaction was ever signed and recorded; the "broadcast failure can have an
  uncertain outcome" sentence is shown only when a record exists.
- **D-2 (no explicit RNG/KDF backend lock)** — fixed. `src/main.js` imports
  `randomBytes`/`pbkdf2` from `ethers` and calls `.lock()` on both before the
  wallet module loads, so no later code can register a replacement
  implementation. The saved-wallet KDF uses WebCrypto directly (`src/vault.js`)
  and does not depend on ethers' `pbkdf2`; this changes no existing behavior.

## Known issue — cross-tab record loss (found 2026-09-23, pre-existing, NOT fixed in 0.1.15)

> **FIXED in 0.1.20 (2026-09-23)** by the single-tab rule (operator decision
> `docs/plans/decisions/2026-09-23-web-wallet-single-tab.md`): a wallet opens only
> in the tab holding the exclusive `nodus.wallet.session` Web Lock, so two tabs can
> no longer send concurrently. A second tab is refused ("Wallet is open in another
> tab.") and derives nothing; "Use it here instead" takes the lock over and the
> first tab locks itself. `test/browser-security.js`'s concurrent-send scenario was
> replaced by the refuse / take-over / reopen scenario; the security suite passed
> 3 of 3 rounds afterwards. The description below is kept as history.

Two tabs of the same saved wallet sending within milliseconds of each other can
lose one tab's activity record even though its broadcast still goes out. The
Web Lock that serializes `nodus.activity.v1` writes only serializes execution:
the main tab holds the lock, reads and merges the saved history, writes its own
row and releases; if the peer tab acquires the lock a couple of milliseconds
later, its `localStorage.getItem` read inside the lock does not yet see the
main tab's write (Chromium's per-renderer `localStorage` caching is not
immediately consistent across tabs, an observed, not source-read, behavior),
so it merges only its own row and overwrites the key. The consequence is that
the first tab's send is missing from saved history after a reload, and since
0.1.15's same-network double-send lock (B-1) reads that same saved history, a
reloaded wallet has no record of the lost send and will not block a second one
on that network. This predates 0.1.15: the same race reproduces on the 0.1.14
tree, so it is not a regression introduced by the fixes above. A fix is planned
separately — a cross-tab-consistent activity store (for example IndexedDB
transactions) or a single-tab-at-a-time rule — and is an open operator
decision, not part of this release. `test/browser-security.js`'s "Concurrent
signed records serialized across tabs" scenario can fail intermittently for
this exact reason; that failure must be root-caused again if seen, never
silenced by loosening its assertion.
