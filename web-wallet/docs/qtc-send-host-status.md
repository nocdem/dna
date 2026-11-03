# QTC trusted-wallet host status

2026-11-02 local candidate work. **Mainnet trusted-extension send/recovery/confirmation candidate is enabled
after independent integrated review. Testnet and unsupported networks remain OFF.** Trusted extension routing and
local submission history are implemented; no site-provider signing permission
was added. No signed public request or deployment was performed.

## Explicit official structured-UTXO gateway architecture

The current candidate is `qtc-gateway-controller.js` with holder
`transportKind: 'gateway'`, using the fixed official mainnet/testnet explorer
hosts. Enablement policy is mainnet only. This is a separately named
contract, not a hidden weakening of `qtc-review-controller.js`, whose independent
mempool-aware node verification and simulation requirements remain unchanged.

The official [browser backend contract](https://github.com/qtcchain/qtc-explorer/blob/73a6076a5592805de0c5df63f2343fc8d71053df/docs/browser-wallet-backend.md)
requires browser validation of explorer-provided outpoint amount/script and a
constrained final gateway. It does not require exposing authenticated node RPC
or separately obtaining raw previous transactions.

The structured candidate checks exact native input integers, locally derived
owner script, duplicate outpoints, index/node height and genesis, coinbase
maturity, matched transaction/output metadata, changed candidates and exact
bounded fee/change before and after signing. It does **not** claim that an
index proves unspentness or canonical inclusion independently.

Fixed P2MR SIGHASH_DEFAULT commits all input outpoints, amounts, scripts,
sequences and all outputs. The node computes those commitments from its actual
AccessCoin prevouts, not the explorer's claims. False input amounts/scripts
therefore invalidate a signature rather than authorize a redirected output or
increased actual fee. Stale/spent/immature candidates can cause admission
failure or uncertainty. Sources:
[interpreter](https://github.com/qtcchain/qtc/blob/5adbc7d5c2ac252804fd3c61fce3b9bbc3ad9c24/src/script/interpreter.cpp),
[validation](https://github.com/qtcchain/qtc/blob/5adbc7d5c2ac252804fd3c61fce3b9bbc3ad9c24/src/validation.cpp).

Two independent source reviews accepted this distinction. The architecture was
explicitly selected after review; it is **not a fallback following a denied raw
request**. The default controller and observer never request `/hex`. Optional
`qtc-prevout.js`/`readQtcPrevious` helpers remain unused by this send path. No
alternate raw-data route, host, credentials or access workaround was added.

## Durable lifecycle and final gateway contract

- Real guarded derivation/signing, one-use review and atomic background
  reservation; restored authenticated unresolved rows block new signing.
- Exact signed bytes are stored only in existing encrypted Activity before the
  final POST. Public RPC previews/history never expose the payload.
- A presealed attempt-bound no-exposure proof may be committed after lock
  without keys only before final POST (or, in strict-node mode, before simulator
  invocation). Once disclosed, every uncertain result retains the hold.
- Explicit exact-byte recovery reconciles twice, rotates the persisted attempt
  ID, uses no signing key and never retries automatically. A failed replay
  cannot prove the earlier attempt was not submitted.
- `qtc-signed-payload.js` checks canonical native wire shape, witness tree,
  stripped txid, inputs and reviewed recipient/change. This is authenticated
  recovery validation, not a second cryptographic signature verifier.
- Wallet gateway limit: eight inputs AND actual JSON body <=65,536 bytes. The
  strict-node/storage-only path has a separate15-input/60,000-byte raw limit.

The official [gateway source](https://github.com/qtcchain/qtc-explorer/blob/73a6076a5592805de0c5df63f2343fc8d71053df/internal/gateway/broadcast.go)
accepts `POST /api/v1/tx/broadcast` with `{"hex":"..."}`, sequentially invokes
`testmempoolaccept` then `sendrawtransaction`, and returns HTTP200
`{"txid":"..."}`. The response must equal the local txid and is bounded to16KiB
before parsing. This is **final submission**, never a harmless simulator.

The gateway records a full-byte dedupe key before semaphore acquisition or node
validation. HTTP409 within ten minutes does not prove broadcast. HTTP422,502,
503,429, origin failures and timeouts never release exposed holds. Validation
and submission are sequential, not atomic; the node revalidates intervening
conflicts. Local fee bounds remain necessary despite node fee policy.

The pinned [node broadcast implementation](https://github.com/qtcchain/qtc/blob/5adbc7d5c2ac252804fd3c61fce3b9bbc3ad9c24/src/node/transaction.cpp)
may reannounce mempool duplicates but rejects already-in-chain UTXO cases. The
initial gateway acceptance test can instead reject an already-mempool tx. No
universal idempotence or duplicate-error-as-success shortcut is assumed. The
[RPC source](https://github.com/qtcchain/qtc/blob/5adbc7d5c2ac252804fd3c61fce3b9bbc3ad9c24/src/rpc/mempool.cpp)
warns that manual rebroadcast can disclose transaction origin.

## Status trust and public availability observations

The observer uses the configured official HTTPS provider: selected genesis,
fresh synchronized tip, positive tx status, canonical-height block membership,
non-orphan status, confirmations and stable tip. It does not fetch raw bytes;
the target hash is already bound to the authenticated local signed payload.
This is trusted-provider ledger evidence, not a proof-of-work light client.
Absence, incomplete results or changed tips remain pending. Local history is
labelled separately and is not a full indexed account scan.

At08:59UTC, non-wallet GET `/api/v1/chain` returned200 with main/node height5158,
lag0; GET `/api/v1/block/0` returned200 with pinned mainnet genesis;
OPTIONS `/api/v1/tx/broadcast` returned204. No financial POST or signed data
was sent. These observations establish route availability, not live acceptance.

A GET for public genesis txid
`68668615ec36015c9eacfa8a3c3c95b1cb5f78454e8d1aa58e3e94cbad3ade23/hex`
returned403. Only the error string was captured; response headers/body were not
retained. Source `apiTxHex` maps lookup errors to404, so the403 cause remains
unknown. No retry, workaround or alternate data-retrieval path was attempted.
That raw-dependent architecture was not enabled; the independently reviewed
structured design above does not depend on or retrieve those denied bytes.

## Verification and limits

`test/qtc-reference/run-regtest.mjs` runs the hash-pinned official v0.2.5 release
with P2P/discovery/wallet disabled and synthetic blocks. On2026-11-02:

- valid wallet-produced tx accepted by `testmempoolaccept` (3873vB);
- changed signature/output rejected as Invalid ML-DSA signature;
- false structured input amount rejected as Invalid ML-DSA signature;
- false structured owner tree/script rejected as Witness program hash mismatch.

No transaction was broadcast, even on regtest. The source-port pin is newer
than v0.2.5; release oracle provenance/limits are in `test/qtc-reference/README.md`.

Mocked tests cover exact body limits, zero raw-route requests, all gateway
uncertainties, canonical status, encrypted-before-POST, no-key replay and lock
proofs. `extension/test/qtc-trusted-port.test.js` exercises the real production trusted
port/capability/guarded keys/WASM/encrypted storage with mocked public transport.
Independent pre-gate review passed 19 gateway/holder tests plus the actual
trusted-port case; the full QTC focused aggregate passed 51 tests before gate.
These are not browser, live admission or deployed release guarantees.
