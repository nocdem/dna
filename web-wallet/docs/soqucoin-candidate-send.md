# SOQ native send: unreleased local candidate

This work is **not a published release or deployment**. The trusted extension
wallet has a mainnet-only native SOQ send candidate. The Web wallet has a separately tested candidate UI path; the shared Connect
send capability is not enabled by these extension overrides. This adds no dApp
provider signing methods or permissions; it is not a claim that PQSwap's site
provider integration is complete.

## Pinned source contracts

- [SoquShield cb3e842 balance service](https://github.com/soqucoin/soqushield/blob/cb3e842af29e4c087a5eb9974f6f76c415862b7a/lib/services/balance_service.dart):
  `/api/v2/utxos/{address}`, `/api/v2/history/{address}` and raw-transaction API.
- [SoquShield cb3e842 RPC service](https://github.com/soqucoin/soqushield/blob/cb3e842af29e4c087a5eb9974f6f76c415862b7a/lib/services/rpc_service.dart):
  public mainnet HTTPS JSON-RPC, including `gettxout`, `getblockhash`, `getblock`
  and `sendrawtransaction`.
- [Core 28222c38 chain parameters](https://github.com/soqucoin/soqucoin/blob/28222c3810701c05eb27e8feb09f032bb75fc097/src/chainparams.cpp):
  mainnet genesis `0d828600816cbd7c23789660b53f90cb6ec7ff85540698e13845eb2d2f0486a8`
  and 288-block coinbase maturity.
- [Core transaction RPC](https://github.com/soqucoin/soqucoin/blob/28222c3810701c05eb27e8feb09f032bb75fc097/src/rpc/rawtransaction.cpp):
  an already-in-mempool transaction returns its txid; an already-mined transaction
  may raise `RPC_TRANSACTION_ALREADY_IN_CHAIN`. Recovery treats that response as
  success only after fresh positive chain confirmation, not as a universal
  idempotence promise.
- [SDK 468ca3ee node oracle](https://github.com/soqucoin-labs/soqucoin-sdk/blob/468ca3eed97b050d8add5715ca109fcaac839a60/tx/testdata/sighash_node_vector.json):
  independent signed transaction, BIP143 digests and txid fixture.

## Implemented candidate

- Fixed official HTTPS providers; genesis, synchronized/stale-node and exact
  amount checks. Indexer candidates are independently checked with `gettxout`:
  native witness-v1 ownership, exact value, maturity and mempool-spent state.
- Native v2/SIGHASH_ALL ML-DSA-44 signing through the existing guarded recovery
  derivation. Recipient and change are reviewed before confirmation; inputs are
  checked again before and after signing. No automatic POST retry.
- Conservative 1,000 shors/vByte policy, 2 SOQ maximum fee, 279,500-shor output
  floor. At most **15 inputs** are selected so encrypted recovery material fits
  the existing 150 KB Activity limit; this is a wallet limit, not consensus.
- Durable authenticated outpoint reservations and signed payload before POST.
  A known-zero-POST cancellation can commit a presealed, attempt-bound ciphertext
  proof after lock without reading keys. Unlock authenticates the proof before
  resolving the hold; old proofs cannot release a later attempt of the same txid.
- Worker/crash ambiguity retains the reservation. The user may explicitly review
  and confirm **the exact same signed transaction** after status reconciliation.
  Recovery does not derive keys, edit bytes, increase the fee or automatically
  retry; a fresh attempt ID prevents delayed old cancellation proofs from
  clearing a replay. A failed replay remains uncertain about earlier attempts.
- Positive historical recovery does not require `txindex`: indexer history may
  supply a candidate height, but canonical-node block lookup must prove the exact
  txid's inclusion. Empty/missing/orphaned/lagging results never release inputs.
- Local submission rows, notification names, saved-recipient checksum validation
  and trusted UI review/confirm/cancel routes are wired. Full indexed account
  history is **not** implemented; the Activity screen explicitly labels local
  submissions. Only one unresolved submission is allowed per account.

## Evidence and remaining limits

Synthetic tests cover real ML-DSA-44 signing, the official node byte fixture,
exact decimal parsing, wrong chain/owner/asset, immature/spent inputs, encrypted
restart, actual lock-after-durable-save before POST, stale proof attempts,
quarantine retention, explicit same-byte replay and duplicate replies.
All financial submission endpoints are mocked in tests.

Read-only live genesis, UTXO and node-preflight observations succeeded on
2026-11-02, including a preflight at height 30,879. They do not prove a successful
live spend, current provider availability, final browser rendering, or a deployed
extension. A later live-history request was denied by the execution environment's
data-disclosure review and was not retried; history recovery is source- and
synthetic-tested, not claimed live-verified. Browser/device QA and release/build
verification remain separate integration work. No real transaction was sent.

## Partial native account history (2026-11-02 local implementation)

The earlier local-submissions-only limitation is superseded in source by
`src/pq/soqu-history.js`, wired through shared `history.js` and the trusted
extension holder. This does **not** establish live history availability: no new
history endpoint probe was made, and the earlier denied probe remains unresolved.

The exact official
[wallet index contract](https://github.com/soqucoin/soqushield/blob/cb3e842af29e4c087a5eb9974f6f76c415862b7a/lib/services/balance_service.dart)
provides only `transactions[{txid,height,confirmed}]`, not amounts or timestamps.
The reader reconstructs native net flow from the pinned node's
[verbose transaction fields](https://github.com/soqucoin/soqucoin/blob/28222c3810701c05eb27e8feb09f032bb75fc097/src/rpc/rawtransaction.cpp):
resolve every input's previous output, compare exact local scripts, subtract
owned input totals from owned output/change totals. Outgoing displayed amounts
are **net debits including fees**, not recipient-only amounts. Self-spends show
the net fee debit. Coinbase receipts are included but may not yet be spendable.

Bounds: at most20 confirmed indexed candidates,100 detailed node reads,32 inputs
per candidate; repeated prevout/block reads (including failures) are cached.
Genesis and synchronized mainnet tip are checked before/after; canonical block
membership supplies confirmed status/time. Changed tips discard the snapshot.
This trusts the configured official node/indexer, not an independent light client.
Mixed-asset, confidential, unconfirmed, malformed, missing/pruned-prevout and
budget-exceeding entries are omitted, explicitly labelled **partial**. The API
list itself has no proven completeness guarantee. Native output asset/visibility
metadata are omitted for defaults in the pinned source; non-default metadata or
confidential/USDSOQ witness scripts are excluded rather than counted as SOQ.

The extension keeps the account page in session memory, guards lock/network
changes, exposes omission counts, retains local pending records on read failures,
and suppresses duplicate account rows while a same-hash local submission is
unresolved. It never turns account history into a cancellation/reservation
release proof. Web SOQ history replaces each snapshot rather than retaining
stale merged rows. PQ account history is not persisted in the legacy history
schema. Focused source/synthetic integration passed25/25 before an added read-
budget case; no browser or live-history acceptance is claimed.
