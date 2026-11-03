# XION account admission: source evidence and unresolved gates

This is source analysis, **not** an on-chain admission result. The candidate
XION send and exact-byte recovery are enabled only in the trusted extension mainnet candidate; testnet and Web remain disabled.
No signed transaction was sent to a public endpoint for this analysis.

## Source pins

* XION v32.0.0: `burnt-labs/xion` commit
  `9b0acaffc126cf10e270bb12a7123a4168882870`.
* Captured configured mainnet node info on 2026-11-02 reports v32.0.0,
  commit `9b0acaffc126cf10e270bb12a7123a4168882870`, Cosmos SDK v0.55.0
  and Go 1.26.10. Captured public testnet node info reports `v32.1.0-rc2`, commit
  `ac20074b40ecdf0d79320396fe1882d4c8f3d457`, Cosmos SDK v0.55.0. The
  XION `app/ante.go`, `x/abstractaccount/ante.go`,
  `x/globalfee/ante/fee.go`, and `go.mod` are identical between those commits.
* Cosmos SDK v0.55.0: `cosmos/cosmos-sdk` commit
  `64fd208a11fb54f7ffdca1a1290c2cfbbc254e49`.

## Findings

* XION installs `NewSetPubKeyDecorator`, `NewSigGasConsumeDecorator`, and its
  `BeforeTxDecorator`. Non-abstract accounts delegate to the SDK
  `SigVerificationDecorator`. Its normal signature path checks account number,
  sequence and chain ID, and verifies via the concrete public key.
* The SDK registers `mldsa65.PubKey`, provides an ML-DSA-65 gas-consumption
  branch, and its implementation hashes the public key to a 20-byte address.
  The pinned generic SDK proto warns about validator-only usage and ADR-28.
  The [XION v32.0.0 release](https://github.com/burnt-labs/xion/releases/tag/v32.0.0),
  matching the captured mainnet commit, explicitly announces ML-DSA-65 for
  native account keys. The chain-specific release and synthetic CheckTx
  provide more specific support evidence; neither proves live inclusion.
* XION's global-fee decorator explicitly skips minimum gas-price and global-fee
  checks during simulation. SDK signature verification also skips cryptographic
  signature verification in simulation. Therefore even a successful
  simulation is neither a fee-policy proof nor an account-signature admission
  proof. Config/global-fee endpoints returned HTTP 403 on both configured
  networks; no alternate endpoint or bypass was attempted.
* A pinned-source in-memory app test on a unique synthetic chain accepted the
  candidate BaseAccount TxRaw via CheckTx and rejected bad signature, chain,
  account number, sequence, and insufficient fee. It also empirically
  accepted bad signature and insufficient fee in simulation. Cached-context
  ante checks also accepted timeout=2 at height 2, rejected at height 3, and
  rejected an unsigned timeout modification. See
  `test/xion-reference/README.md` for exact pins, harness and limitations.
* The 2026-11-02 captured testnet simulation used a synthetic nonexistent
  account and returned unknown account. It establishes endpoint reachability
  only, not authentication, fee adequacy, gas estimation, or inclusion.

## Required before enabling

Have the synthetic CheckTx oracle and lifecycle independently reviewed; verify current deployed
fee and network policy and complete independent security review. Pinned SDK v0.55.0 ML-DSA-65 key-package Go tests passed locally. The isolated application/ante CheckTx oracle passed with a synthetic chain and
local-only genesis; this is not live-network acceptance. No public signed simulation, funded transaction, or broadcast was made.

## CheckTx rejection is not non-exposure

The pinned SDK `client/broadcast.go` and CometBFT v0.40.0
`rpc/core/mempool.go` show that synchronous broadcast returns the contacted
node's CheckTx result and transaction hash. In the default CList mempool,
`mempool/clist_mempool.go` adds a transaction only when CheckTx succeeds; a
nonzero result is not normally inserted or gossiped by that node. This is
source-level evidence of that node's reported rejection, not proof of
network-wide absence: the signed bytes were disclosed, a proxy or peer could
have seen them, a previous attempt may be uncertain, and fee policy may later
change. The candidate keeps this attempt unresolved on code 13 and never labels it
`notSubmitted`; exact-byte recovery is explicit and does not authorize a new
fee-adjusted signature. HTTP failure, timeout, malformed response, mismatched
hash, and other ambiguity remain unknown.

## Bounded height expiry research

SDK v0.55 TxBody field 3 is a uint64 `timeout_height`; it is part of the
SIGN_MODE_DIRECT-signed body. XION's ante installs the height timeout check.
Nonzero timeout `T` remains valid at height `T` and is rejected only when the
executing block height is greater than `T`. The 2026-11-02 public read-only
`/cosmos/base/tendermint/v1beta1/blocks/latest` responses for both configured
networks provide `sdk_block.header.chain_id`, `height`, `time` and a
`block_id.hash`; snapshots are in `test/fixtures/pq-public-read-20261102`.
These are reports from nodes, not authenticated finality proofs. Under the
wallet's configured-node trust model, a committed reported height greater
than T establishes the window is closed, not that the transaction was never
included. The candidate chooses T as the checked head plus 100 blocks and
checks a five-block safety margin before POST. Account and spendable-balance
reads are pinned to one reported height with the SDK request/response height
header; missing, mismatched, or unavailable state fails closed. A final head
check bounds advancement during the last state reads to five blocks. The
extension durably records a separate authenticated execution-window-closed
marker, retains unknown historical outcome, and prohibits exact replay. A
separate ordinary user-initiated payment may use fresh state; no replacement,
fee bump, or automatic signing is performed. Legacy unbounded attempts cannot
be closed by this mechanism. Browser header availability and actual deployed fee policy are unverified;
fee and gas are user-selected, not network quotes.
