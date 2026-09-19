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

## CPUNK connection

The default is `https://rpc.cellframe.net/connect`. On 2026-09-19 a read-only POST using the repository's public DNA registration address returned HTTP 200, `Access-Control-Allow-Origin: *`, POST/OPTIONS allowed, and the full CellframeNode 5.7-44 JSON response. CPUNK was `0.00000000000000001` coins / `10` datoshi; the response also contained CELL. This is an observation, not a current balance guarantee. An earlier 12-second HTTPS probe received headers but timed out before the body; HTTP also timed out. These observations do not establish a network outage. Browser preflight and live access from the final deployment origin still require verification.

The native query contract is `messenger/blockchain/cellframe/cellframe_rpc.c`: `wallet`, `info`, `{net:'Backbone', addr, token:'CPUNK'}`. The live response uses `result[0][0].tokens[]`, `token.ticker`, `coins` and `datoshi`. The parser selects exactly one CPUNK entry, checks Backbone and matching returned address, and verifies coins against integer datoshi with 18 decimal places. The older native `result[0][0].balance` format is also supported. Missing tokens, malformed data, mismatched amounts and connectivity failures are errors, never inferred zero balances. Address validation remains structural Base58/length checking, not checksum or ownership verification. UI status reports the last read outcome and resets when input changes.

A custom trusted HTTPS endpoint may be entered for this tab. An optional same-origin gateway is available for deployments needing an operator connection:

```sh
# Terminal 1: Node 22.12+, binds loopback only
npm run cpunk:gateway
# Terminal 2: Vite forwards /api/cpunk/ to that service
VITE_CPUNK_ENDPOINT=/api/cpunk/balance npm run dev
# Read-only verification: public address from cellframe_rpc.h
npm run cpunk:verify
# Verify the default remote HTTPS endpoint directly instead
npm run cpunk:verify -- --direct
```

For production, run the gateway under your service manager, build with `VITE_CPUNK_ENDPOINT=/api/cpunk/balance npm run build`, and use `deploy/Caddyfile` with `WALLET_HOST` set to your domain and `WALLET_DIST` set to the absolute `dist` directory. Caddy terminates HTTPS and forwards only `/api/cpunk/*` to the loopback gateway. Keep port 8787 private; if changing `CPUNK_PORT`, update the proxy target too. For direct-only static hosting, use ordinary `npm run build` without the gateway environment setting. No service is deployed by these files.

After deployment run `npm run cpunk:verify -- https://YOUR_DOMAIN` for gateway deployments, then use the page's public-address read to verify browser access. The command fails on missing setup, upstream errors or malformed responses. It does not test browser CORS. Gateway requests accept **only** `{address}` at `/api/cpunk/balance`; the server constructs the fixed CPUNK query to the fixed HTTPS upstream. Arbitrary RPC methods, upstream URLs, signing, credentials and secrets are not supported. Request bodies are capped at 512 bytes, upstream responses at 64 KiB, upstream operations at 10 seconds and browser operations at 15 seconds; redirects are refused and balances are not cached. Apply ordinary edge rate limits appropriate to your public deployment. No claim system, snapshot rule or ownership proof is implemented.

## Permanent chain RPC limitations

RPC defaults are taken from the repository's providers. Actual production availability, quotas and CORS access must be verified from the deployment origin. Ethereum/BSC and Solana endpoints may be changed for this tab; network identities are checked before reads and sends. A user-selected RPC sees public addresses and signed transactions. No seed or private key is transmitted. There is no backend relay or API-key service, and no silent endpoint fallback.

Chain SDKs, not the existing native C binaries, implement browser signing; existing Connect/Nodus code is unchanged. Real mainnet transfers have not been executed during development. This slice does not include transaction history indexing, confirmation tracking beyond the explorer, custom-token discovery, Nodus Network integration, ZK, claims, DEX/swap or tokenomics changes.

## Remove temporary Cellframe support

```sh
VITE_ENABLE_CPUNK=false npm run build
```

The CPUNK panel is removed and the lazy-loaded adapter is excluded from the bundle. The reusable `src/wallet.js`, permanent adapters and key derivation do not import CPUNK. For final source removal, delete `src/adapters/cpunk.js`, `src/cpunk-protocol.js`, `server/cpunk-gateway.js`, `scripts/verify-cpunk.js`, the optional proxy configuration, its isolated UI block/form and corresponding tests. No permanent-chain changes are needed.

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
