# Web wallet security follow-up — 2026-09-19

Reviewed baseline: `f48968bd3b669edea302a5d1bbf0c25fcd2add30` on `feat/nodus-web-wallet`.
Scope: browser wallet only. Existing native applications and consensus are unchanged.

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
