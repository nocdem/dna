# Nodus Web Wallet — first-stage browser implementation

A standalone, accountless browser client alongside the existing DNA applications. No Connect installation, extension, identity registration, email, phone, or account backend is required. This is a development preview, not a deployed or audited custody product.

## Run

Requires Node.js 22.12+ and a modern browser with Web Crypto and BigInt.

```sh
cd web-wallet
npm ci
npm run dev
```

Open the localhost URL printed by Vite. For a production bundle, run `npm run build`; `npm run preview` serves `dist` locally. Production hosting must use HTTPS and a restrictive `frame-ancestors 'none'` response header (it cannot be enforced by a CSP meta tag). Dependencies are bundled locally; no third-party script CDN is used.

## Implemented

- Create a 24-word BIP39 recovery phrase, verify the entire backup, or restore a valid English BIP39 phrase. Recovery phrases and keys are held only in this tab, never persisted or sent to RPCs. Lock, page exit and ten minutes of inactivity discard the wallet. There is no password/account service or automatic recovery. JavaScript cannot guarantee erasure of immutable strings or garbage-collected copies.
- First-account addresses and local signing matching Connect: ETH/BSC `m/44'/60'/0'/0/0`, Solana SLIP-10 `m/44'/501'/0'/0'`, TRON `m/44'/195'/0'/0/0`. Empty BIP39 passphrase matches Connect. Other account indices, hardware wallets and BIP39 passphrases are not included.
- Receive/copy address, explicit balance refresh, native and preset token transfers on Ethereum, BSC, Solana and TRON mainnets. Preset token contracts/decimals are copied from the C headers: ETH USDT/USDC/DAI; BSC USDT/USDC; SOL USDT/USDC; TRON USDT/USDC/USDD. Token listing is not an endorsement or statement of current issuer support.
- Exact integer amount handling, address validation by chain libraries, EVM chain-ID and Solana genesis checks, explicit review of network/sender/recipient/asset/amount/fee before local signing and broadcast, expiring single-use reviews, and transaction explorer links. Broadcast submission is shown as pending, never as confirmed. Ambiguous failures are not automatically retried.
- EVM gas estimation with a 20% gas-limit margin and legacy gas-price transactions; Solana fee/rent estimation and idempotent recipient token account creation, including spending across multiple source token accounts; TRON native/TRC-20 transaction intent and protobuf consistency validation. TRON token energy has a 100 TRX limit; bandwidth/activation charges are network dependent and not falsely presented as an exact fee estimate. TRON sending uses only the configured default mainnet provider; there is no testnet fallback.
- Temporary **CPUNK-only, read-only** Cellframe/Backbone query using a public address. No seed import, wallet creation, signing, sending, trading or claim execution in the Cellframe module. Its balance is not proof of ownership, a snapshot, or airdrop eligibility.

## CPUNK availability is an unresolved live integration dependency

The repository uses `http://rpc.cellframe.net/connect`, which is unsuitable for a production HTTPS browser app because of mixed-content restrictions. This implementation deliberately does not silently invent a working HTTPS replacement or proxy. The CPUNK form requires a trusted HTTPS endpoint implementing the same RPC and allowing the app origin through CORS. It has no default endpoint until an operator verifies one.

The source contract is `messenger/blockchain/cellframe/cellframe_rpc.c` (`wallet`, `info`, `{net:'Backbone', addr, token:'CPUNK'}`) and `cell_chain.c` (`result[0][0].balance`, an already formatted decimal string). Responses are parsed strictly; missing/malformed data and connectivity failures are errors, never inferred zero balances. Address validation is structural Base58/length checking only, not checksum or ownership verification.

On 2026-09-19, this environment's `curl -IL --max-time 15 https://rpc.cellframe.net/connect` timed out with no upstream response. This does **not** establish a Cellframe-wide outage. Real CPUNK access and browser CORS compatibility remain unverified. No claim system, snapshot rule or ownership proof has been supplied or implemented.

## Permanent chain RPC limitations

RPC defaults are taken from the repository's providers. Actual production availability, quotas and CORS access must be verified from the deployment origin. Ethereum/BSC and Solana endpoints may be changed for this tab; network identities are checked before reads and sends. A user-selected RPC sees public addresses and signed transactions. No seed or private key is transmitted. There is no backend relay or API-key service, and no silent endpoint fallback.

Chain SDKs, not the existing native C binaries, implement browser signing; existing Connect/Nodus code is unchanged. Real mainnet transfers have not been executed during development. This slice does not include transaction history indexing, confirmation tracking beyond the explorer, custom-token discovery, Nodus Network integration, ZK, claims, DEX/swap or tokenomics changes.

## Remove temporary Cellframe support

```sh
VITE_ENABLE_CPUNK=false npm run build
```

The CPUNK panel is removed and the lazy-loaded adapter is excluded from the bundle. The reusable `src/wallet.js`, permanent adapters and key derivation do not import CPUNK. For final source removal, delete `src/adapters/cpunk.js`, its isolated UI block/form and corresponding tests. No permanent-chain changes are needed.

## Verification

```sh
npm test
npm run build
npx playwright install chromium
npm run test:browser
```

The browser test starts its own preview server and intercepts **all external HTTPS requests**, so it never broadcasts to a real chain. Set `CHROMIUM_PATH` to use an existing Chromium binary or `WALLET_URL` to test an already running preview. Offline tests cover deterministic recovery addresses, exact amounts, malformed responses, CPUNK public-only requests, review lifecycle, ETH/SOL signatures and TRON transaction tampering. Browser smoke covers create/backup/restore, chain selection, mocked ETH/native and ERC-20 send review/confirmation, network mismatch, CPUNK error/success, lock, no storage and mobile overflow.

`npm audit` after compatible updates still reports 9 findings (6 moderate, 3 high) through the legacy Solana SDK tree. The high root advisory is `bigint-buffer`'s native binding; this browser bundle uses its pure-JavaScript browser entry. Remaining moderate roots are `stream-json` and `uuid` through `jayson`. Advisory roots: [GHSA-3gc7-fjrx-p6mg](https://github.com/advisories/GHSA-3gc7-fjrx-p6mg) (high, native `bigint-buffer` overflow; browser entry does not load native bindings); [GHSA-528h-pc64-c93x](https://github.com/advisories/GHSA-528h-pc64-c93x) (moderate, `stream-json` filter DoS; the inspected `jayson` browser client does not import stream filters); [GHSA-w5hq-g745-h8pq](https://github.com/advisories/GHSA-w5hq-g745-h8pq) (moderate, `uuid` v3/v5/v6 caller-buffer bounds; the inspected browser client uses v4 without a caller buffer). This is source-level reachability triage, not proof that every transitive path is safe. These dependencies are not claimed clean or audited; replacing the legacy SDK is separate work. Do not use `npm audit fix --force`, which proposes incompatible ancient SDK versions. The build also warns about the large bundled chain-library chunk (~1.34 MB before gzip).

## Source layout

- `src/config.js`: permanent mainnet/token registry sourced from C headers.
- `src/keys.js`: local recovery/generation and compatible derivation.
- `src/core.js`: exact units and bounded public RPC helper.
- `src/wallet.js`: common adapter routing and single-use transfer review.
- `src/adapters/{evm,solana,tron}.js`: permanent balance and send adapters.
- `src/adapters/cpunk.js`: isolated temporary public balance adapter.
- `src/app.js`, `index.html`, `src/style.css`: accountless responsive UI.
- `test/`: offline and fully intercepted browser verification.
