# Tidecoin candidate — post-handoff, isolated, not enabled

This document describes work **after** the frozen seven-network handoff. It is
not included in, and does not modify, the delivered 09:43 candidate ZIP or its
09:46 source/patch artifacts. Tidecoin sending remains **off** in both wallet
surfaces. No production Tidecoin provider, trusted RPC route, UI handler,
permission change, live signed simulation, or broadcast was added. The existing
explorer returned HTTP 403 in prior checks; it was not retried or bypassed.

## Implemented candidate

- `src/pq/tidecoin-preflight.js` accepts only mainnet Falcon-512 P2PKH, with
  1–15 distinct selected inputs and non-witness funding transactions. It hashes
  each full raw funding transaction to the supplied txid and derives the
  referenced output's exact value and script from those bytes. It does not
  trust a provider-supplied amount. It checks sender ownership, confirmed height,
  a coherent reported tip, coinbase maturity of 100 blocks, and bounded input
  value. Other funding formats, including witness, are rejected rather than
  approximated.
- The fee is explicitly chosen by the caller in atoms/kB, capped by the caller,
  and calculated using a conservative maximum of `1700 * inputs + 78` bytes
  for a two-P2PKH-output Falcon transaction. Exact fee and change are fixed in
  the review; no post-review fee mutation is allowed. Both output values must
  meet the upstream default P2PKH dust threshold of 21,906 atoms (for the
  upstream 3,000 atoms/kB dust relay setting). A node may apply stricter policy.
- `src/pq/tidecoin-transfer.js` requires injected trusted transport,
  cross-session reservation, submission, and a durable-pending callback. It
  rechecks the reviewed identity, outpoints, funding and tip before deriving
  the seed, checks the signed size against the reviewed bound, and persists
  before the sole injected submission. Once pending exposure begins, the
  reservation remains held on failures; an invoked submit's errors are always
  ambiguous, regardless of forged error properties. There is no automatic retry.
- `src/pq/tidecoin-recovery.js` binds retained raw transaction hash, recipient,
  change, exact fee, input outpoints, funding raw bytes, sender key hash and
  signatures. `verifyTidecoinSignedPayload` verifies signatures with the native
  WASM verifier without deriving a seed. Raw funding evidence is bounded to
  80,000 hex characters and signed bytes to 51,000; the existing encrypted
  Activity envelope limit is unchanged. Unsupported or malformed records fail
  closed.
- `extension/src/background/tidecoin.js` is an **isolated, unregistered** trusted
  holder. Its Activity record holds raw funding evidence and signed bytes only
  in the existing authenticated encrypted Activity bucket. A random per-attempt
  ID scopes a presealed ciphertext-only known-zero-POST proof across lock;
  replay requires explicit confirmation, re-verification, reconciliation, a
  fresh durable attempt ID, and the exact same signed bytes. A replay failure
  never certifies that an earlier attempt was not submitted. A process-wide
  per-bucket write queue and all-write attempt checks preserve holds across
  stale sessions. Positive confirmation requires a trusted provider's exact
  hash and block metadata and is labeled a report, not an inclusion proof;
  unknown/missing observations never release a hold.

## Required external integration before any gate can be considered

1. An authorized, usable mainnet provider with a verified read-only/broadcast
   contract and an independently checked identity. No provider URL is supplied
   by this candidate. `transport.assertIdentity({signal})` must return
   `{genesisHash:'480ecc7602d8989f32483377ed66381c391dda6215aeef9e80486a7fd3018075'}`;
   the expected value is from pinned upstream `src/kernel/chainparams.cpp`.
2. `transport.getConfirmedUnspent({txid,vout,signal})` must verify, under the
   selected trusted-node policy, that the outpoint is confirmed in the active
   chain and unspent at a coherent tip, and return lower-case full `rawTx`,
   `blockHeight`, `blockHash`, `tipHeight`, `tipHash`, and `unspent:true`.
   Hashing the raw transaction authenticates its outputs against the txid; it
   does **not** itself prove canonical inclusion, confirmation or unspentness.
3. `transport.observe({hash,signal})` must bind every result to that hash and
   return `pending`, `unknown`, or a positively validated `confirmed` result
   with `blockHeight` and `blockHash`. Absence/404 is **not** proof of failure.
4. `reserve` must atomically reserve outpoints across sessions before any seed
   access; `assertReservation` must check that hold for explicit recovery. The
   host must reconcile its reservation database with authenticated Activity and
   cancellation proofs after unlock. It must not release on lock, transport
   failure, or an ambiguous submission.
5. The host's durable callback must save the complete pending row before POST;
   the injected `submit({raw,hash,signal})` must use only the reviewed bytes,
   report the matching txid on acknowledged admission, and never retry on its
   own. A provider error after invocation is uncertain. Explicit replay must
   rotate the durable attempt identity before submitting the same bytes.
6. An independently reviewed provider policy, extension asset/bundler wiring,
   recovery UX, lock/restart/cross-session tests, and browser/device QA are still
   required. No site-provider signing or permission expansion is authorized by
   this candidate. A release decision must not infer availability from these
   offline tests.

## Evidence and limitations

The upstream Tidecoin `7d653be5d24e73b49d101578afb33d8d7a889c1d` C++
`CheckTransaction`, `IsStandardTx`, and `VerifyScript` accepted the synthetic
wallet-generated transaction under the tested legacy, strict, and standard
script flag combinations; mutations were rejected. Reproducible isolated
build and fixture provenance are in `test/tidecoin-reference/README.md`.
Independent bounded review covered the candidate preflight, encrypted holder,
proof/recovery and cross-session lifecycle; the final targeted merged-row test
also passed. The local tests use public synthetic data and injected mocks.
They do not establish real UTXO existence, deployed activation, actual fee
market, provider availability, mempool admission, finality or a successful live
send. The immutable seven-network package remains the separate reviewed
handoff and does not contain this post-handoff host work.
