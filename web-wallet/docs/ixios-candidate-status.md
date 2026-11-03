# IXIOS post-handoff candidate

This is new work after the immutable 2026-11-02 09:43 extension / 09:46 source handoff. IXIOS is not XION. Do not describe the delivered seven-network package as containing IXIOS sends.

## Current scope

Native mainnet ML-DSA-87 transfers between empty-code accounts, with an explicit gas-price cap, fixed native 1,000 gas and local signing. Trusted extension only; no website-provider permissions. The trusted extension mainnet code-candidate gate is enabled after bounded independent review and native admission evidence, including externally supplied browser-WASM signed bytes executed by the pinned node without re-signing (10/10 native cases). Testnet/unsupported networks and website-provider sends remain disabled. Runtime must fail closed if fresh network/fee/account checks fail; this is not a claim of verified usable live access. No live signed transaction or financial broadcast has been performed.

The account has a 48-byte address. Chain ID 1 alone is insufficient network identification because it collides with Ethereum. The fixed endpoint is `https://ixios-rpc.innova.limited`; block 1 parent hash must equal `0xa19acef59b3b84f192a69407981c50695fd105988d9311dd2e1c60332b629f2f`. Aegis activates at height 32,400,000. Native block timestamps are milliseconds, not Ethereum-style seconds.

Source: [ixiosSpark v1.1.1](https://github.com/ixios-io/ixiosSpark/tree/v1.1.1), commit `ccd1345eed8873a6d0174b3e9a076da67ceb7750`. Relevant files: `params/config.go`, `core/address_format.go`, `core/types/mldsa87.go`, `core/types/transaction_signing.go`, `common/types.go`, `consensus/fastClique/fastClique.go`, `zeta/zeta.go`, `core/txpool/legacypool` and `core/state_processor.go`.

The pinned Go/CIRCL codec/sender oracle matches two synthetic full/compact-recipient vectors byte for byte. This alone is not transaction admission evidence: the initial serialization vectors use a deliberately small gas price, below the post-Aegis ZETA floor. Gas pricing must use source-defined ZETA policy and a fresh unsigned quote, not Ethereum defaults. Independent source arithmetic confirms `params/denomination.go` uses 10^18 atomic units per IXIOS; at height 32,400,000 the ZETA minimum is 93,000,000,000,000,000 atomic units/gas, and native `params.TxGas=1000` gives a source-derived simple-transfer fee of 93 IXIOS. The initially assumed Ethereum-style 21,000 gas limit was incorrect: the pinned native state-transition oracle consumed 1,000 and refunded the remaining gas. Its 1,953 IXIOS upfront cap must NOT be described as the actual fee. This is source-derived, not a live quote or fiat value. A fresh unsigned JSON-RPC batch (`eth_gasPrice`, latest header, `eth_chainId`) returned HTTP403 around10:07UTC; no result was obtained. A different implementation worker independently issued one single-method gas-price query at10:12:30 before the denial constraint was relayed directly to that worker, and reported the source-floor value. This does not resolve the denied batch path or broaden access. All active workers were explicitly stopped from further live RPC probes. Exact chronology is preserved in `test/fixtures/ixios-public-read-20261102/rpc-probe-chronology.json`; live availability remains qualified. Source-derived prices, actual quoted fees and fiat values must remain distinct.

## History

Existing balance reads authenticate the mainnet genesis. Local authenticated submissions are not complete account history. The official site links [Ixoflow](https://ixoflow.io/), which was under AegisPQ maintenance during inspection. A bounded direct-RPC recent-history reader is integrated alongside local submissions; it must not imply complete account/internal-call/token coverage or light-client inclusion proof.

## Price: unavailable, not zero

[The official IXIOS site](https://ixios.io/) links the exact [Coinstore IXIOSUSDT pair](https://www.coinstore.com/spot/IXIOSUSDT). The [official public API documentation](https://coinstore-openapi.github.io/en/index.html) specifies latest trades at `GET /api/v1/market/trade/IXIOSUSDT?size=1`, including trade timestamps and price in **USDT**, not USD. The ticker's fetch time is not a documented last-trade timestamp.

One public, address-free read of that documented trade endpoint returned HTTP 403 on 2026-11-02 around 10:04 UTC. No retry or alternate-route retrieval followed. There is no verified live quote or CORS result. Existing `IXIOS_ASSET` remains without a USD price identity and excluded from USD valuation; do not map it to Ixian/IXI, invent a CoinGecko ID, peg USDT to USD, or substitute zero for missing market data.

## Validation boundaries

Synthetic/offline native oracles and mocked transport tests do not establish funded live acceptance. Device/browser extension installation QA remains unrun under the previously reported environment restrictions. No deployment, push, profile deletion, or modification of the delivered immutable archives is authorized or performed.
