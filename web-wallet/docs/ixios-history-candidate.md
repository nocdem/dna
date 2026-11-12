# Ixios recent native history — trusted extension candidate

`src/pq/ixios/history.js` is a read-only helper now wired through the trusted
extension holder (`extension/src/background/ixios.js` `getHistory`), which reads
the history of the selected Ixios network (`networkId` and `endpoint` of the
selected entry of `IXIOS_NETWORKS`); Web Wallet does not use it. The separately
reviewed trusted-extension send code candidate is enabled, but live provider
availability and admission are not established.

Per network (`src/pq/ixios/network.js`): the Aegis start height is 32,400,000
on the main network and 300 on the test network (300 is the reference's value
for chain id 3; the height the running test node uses is not established). The
helper fails with "Ixios post-Aegis history is unavailable." when the head is
below that height. The account-code check around each candidate differs: the
main network uses `eth_getCode` at height−1 and at height; the test network,
which has no `getCode`, uses `ixios_getProof` at height−1 and at height and
treats the account as empty when the answer's `codeHash` is the zero hash or
the hash of empty code. A `getProof` answer is the provider's; its
`accountProof` is not checked against a state root. Provider history errors are
surfaced as unavailable while authenticated local submissions remain visible.
`readIxiosRecentNativeHistory`
accepts a 48-byte address, optional existing HTTPS endpoint, optional explicit
start/end block heights or a recent-window limit, an abort signal, and an
injectable RPC caller for offline tests. It scans at most 50 post-Aegis blocks,
500 transactions per block and 25 matching candidates. An exceeded bound or
malformed response is an error, never a silently complete result.

The helper checks Ixios genesis via block 1's parent, reads an initial head,
checks consecutive parent hashes and transaction positions, validates receipt
hash/block/index/sender/recipient/status, and re-reads both the scanned end
and original head. It uses exact integer arithmetic with 18 decimal places and
interprets block timestamps as milliseconds. Success is labeled `included`, not
final. Failed direct transactions report zero transferred and retain a separate
`attemptedAmount`. It performs no live address probing in its tests.

Only positive-value, empty-calldata direct transactions are candidates. The
helper checks recipient code immediately before and after the block to omit
ordinary calls to persistent contracts; it does not parse token logs or trace
internal transfers. **Limitation:** two state snapshots cannot exclude a
contract created and destroyed within a single block, so the result must not
be presented as a complete or categorical contract-free history. It is a
bounded provider report, not a light-client proof, and may be stale or omit
transactions outside the scanned range. The unchanged RPC transport still
applies its HTTPS, timeout and response-size limits. A failed or rate-limited
provider must be surfaced as unavailable.

Source: ixiosSpark v1.1.1 (`ccd1345eed8873a6d0174b3e9a076da67ceb7750`) [`params/config.go`](https://github.com/ixios-io/ixiosSpark/blob/v1.1.1/params/config.go)
sets the Aegis height, [`internal/ethapi/api.go`](https://github.com/ixios-io/ixiosSpark/blob/v1.1.1/internal/ethapi/api.go)
defines full-block and receipt fields, and
[`consensus/fastClique/fastClique.go`](https://github.com/ixios-io/ixiosSpark/blob/v1.1.1/consensus/fastClique/fastClique.go)
uses millisecond clock values. `node --test test/ixios-history.test.js` exercises
synthetic provider responses, exact values, failure status, contract filtering,
identity/range/continuity/reorg checks, bounds and cancellation. No signed
transaction, wallet credential or live wallet address was used.

## Provider access chronology

The integration team observed an HTTP 403 for a batch request to the configured
Ixios RPC at 10:07 UTC on 2026-11-02. A separate single gas-quote request
succeeded at 10:12 UTC, before the stop instruction reached that worker; it
does not explain or reverse the batch denial, or establish access to this
history scan. No further Ixios RPC retries or alternate-route probes were made
by this helper. Availability must be established only through an authorized
provider or a future explicit change in access; do not treat the synthetic tests
as evidence that the live endpoint permits these calls.
