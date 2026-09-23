# Nodus Web Wallet — first-stage browser implementation

A standalone, accountless browser client alongside the existing DNA applications. No Connect installation, extension, identity registration, email, phone, or account backend is required. This is a development preview; it is not an audited custody product.

The product is Nodus Wallet. CPUNK is the temporary CF-20 integration until the airdrop; it is not a permanent chain module or the wallet identity. Airdrop eligibility and claims are outside this release.

## Run

Requires Node.js 22.12+ and a modern browser with Web Crypto and BigInt. Saved-wallet operations also require the Web Locks API to serialize storage changes across tabs.

The lockfile includes Jayson's optional `ws` peer `utf-8-validate` 5.0.10 separately
from `rpc-websockets`' 6.x dependency. Both records are needed for a clean
`npm ci` with npm 10.9.4 (verified with Node.js 22.22.1); do not remove the 5.x
record just because a 6.x copy is also present.

```sh
cd web-wallet
npm ci
npm run dev
```

Open the localhost URL printed by Vite. For a production bundle, run `npm run build`; `npm run preview` serves `dist` locally. Production hosting must use HTTPS and a restrictive `frame-ancestors 'none'` response header (it cannot be enforced by a CSP meta tag). Dependencies are bundled locally; no third-party script CDN is used.

## Publish

Run `npm ci`, `npm test` and `npm run build`, then serve only `web-wallet/dist` from `https://wallet.nodusnetwork.io` using the existing HTTPS web server. Node.js is needed for building and local verification, not as a production application service. All blockchain requests go directly from the browser to their HTTPS RPC endpoints.

For Caddy, `deploy/Caddyfile` serves the static files and supplies the response headers: set `WALLET_HOST` to your domain and `WALLET_DIST` to the absolute `dist` directory. Use equivalent settings with an existing web server. Do not serve production through Vite preview. After publication, verify HTTPS, response headers and direct RPC access in a browser on the actual wallet domain. No service is deployed by these files.

## Implemented

- Create a 24-word BIP39 recovery phrase, verify the entire backup, or restore a valid 24-word English BIP39 Nodus phrase. Recovery phrases and keys stay local and are never sent to RPCs. Optional device persistence stores only an authenticated encrypted phrase; temporary wallets do not persist secrets. Lock, page exit and ten minutes of inactivity discard the wallet; the same timeout clears phrase creation, backup verification, restore and password entry screens. Focus/visibility checks also enforce the deadline after tab suspension. There is no account service or automatic recovery; an optional local password unlocks the encrypted device copy. JavaScript cannot guarantee erasure of immutable strings or garbage-collected copies.
- First-account addresses and local signing matching Connect: ETH/BSC `m/44'/60'/0'/0/0`, Solana SLIP-10 `m/44'/501'/0'/0'`, TRON `m/44'/195'/0'/0/0`. Empty BIP39 passphrase matches Connect. Other account indices, hardware wallets and BIP39 passphrases are not included.
- Receive/copy address, automatic balance reads on opening the wallet, manual refresh, native and preset token transfers on Ethereum, BSC, Solana and TRON mainnets. Preset token contracts/decimals are based on the C headers, with DAI corrected against the issuer's documentation: ETH USDT/USDC/DAI; BSC USDT/USDC; SOL USDT/USDC; TRON USDT/USDC/USDD. Token listing is not an endorsement or statement of current issuer support.
- Exact integer amount handling, address validation by chain libraries, EVM chain-ID and Solana genesis checks, explicit review of network/sender/recipient/asset/amount/fee before local signing and broadcast, expiring single-use reviews, and transaction explorer links. Broadcast submission is shown as pending, never as confirmed. Ambiguous failures are not automatically retried.
- EVM gas estimation with a 20% gas-limit margin and legacy gas-price transactions; Solana fee/rent estimation and idempotent recipient token account creation, spending only from the sender’s locally derived associated token account; TRON native/TRC-20 transaction intent and protobuf consistency validation. TRON token energy has a 100 TRX limit; bandwidth/activation charges are network dependent and not falsely presented as an exact fee estimate. Solana balances can include other token accounts, but those accounts cannot be spent here. TRON reads and sends require the configured default mainnet provider and matching genesis; there is no testnet fallback.
- Temporary **CPUNK-only, read-only** Cellframe/Backbone integration (0.1.13): CPUNK sits inside the wallet's own asset list like any other network, no separate panel. Its address is derived automatically as soon as the wallet opens, from the same recovery phrase, the same way as the Nodus address; there is no manual derive step. Cellframe signing, sending, trading and claiming are unavailable, and the send form is disabled with a plain-language note when Cellframe is selected. Its balance is not proof of ownership, a snapshot, or airdrop eligibility. Since 0.1.14, CPUNK (asset row) and the Cellframe network (badge and holding row) each carry their own icon (`cpunk.png`, `cellframe.svg`) instead of sharing one, since both previously keyed off the same `CPUNK` symbol.

## Multichain portfolio (0.1.12)

Create, restore and saved-wallet unlock automatically read balances across all
four supported external networks. Like Connect, the dashboard shows an estimated
USD total and groups preset assets such as USDT across networks. Expand a token
to see its network amounts and choose Send or Receive on that exact network.
Network filters affect the asset list; the hero total always spans all four
networks. Hide balances masks the portfolio amounts until shown again or locked.

The keyless [DefiLlama prices API](https://github.com/DefiLlama/api-docs/blob/main/llms.txt)
provides indicative USD prices, requested directly by the browser for fixed
native-coin IDs and exact chain/token contracts. Metadata, timestamps and
confidence are validated. Stablecoins use their returned price, not an assumed
$1 peg. There is no Bitcointry dependency, API key, gateway, analytics or remote
script. The price request contains asset identifiers but no wallet address;
RPC balance requests contain public addresses. Both providers see connection
information such as the browser's IP. No seed, private key or password is sent.

The estimate's USD total covers only the 14 configured native/token balances.
**NODUS and CPUNK are excluded from the total**: Nodus remains address-only
(no balance at all), and CPUNK's balance is shown alongside the other assets
but has no price display or USD value, so it never affects the total or the
"all balances included" completeness message. Custom tokens, other accounts
and unsupported networks are not discovered.
Amounts and aggregation use integers; display rounds only the USD value. This
is not an executable sale quote or proof that a provider reported honest data.

Failed, missing or wrong-network balance reads are unavailable, never zero.
Missing/invalid prices leave token quantities visible but omit their USD value.
Partial totals are explicitly marked incomplete; no known positive value means
an unavailable total rather than a misleading $0. A verified all-zero portfolio
can display $0 without prices. Balances expire after five minutes and quotes
after fifteen; a 30-second display check removes stale values. Refresh all
requests new data; there are no background polling requests or automatic retries.
Lock cancels in-flight reads, clears the portfolio and rejects late replies.
Endpoint changes invalidate the old snapshot and require Refresh all. Nothing
from the portfolio is written to browser storage; saving remains explicit opt-in.

`npm run test:portfolio` exercises the production bundle with all external
traffic intercepted: automatic reads, grouped holdings and totals, filters,
network-specific actions, hiding, partial errors, wrong networks, missing/stale
prices, balance expiry, locking/reopening and 320–1440px layouts. Set
`SCREENSHOT_DIR` to capture public-fixture screenshots. These are regression
tests, not a new independent security audit; no real transfers are made.

## Planned Earn and Trade areas

Earn is specifically for delegating native NODUS to witnesses and managing those
delegations, using DNA Connect's witness selection/delegation flow as a reference.
Trade is the separate future DEX/swap area. Neither integration is enabled in
this release. The web wallet currently derives and displays the native Nodus
address; native balance reads and transactions require a separate integration.

## Wallet loading (0.1.11)

Create, Restore and Unlock stay disabled until the application module has
initialized. A loading message is shown while waiting; a module load failure
shows a reload instruction and leaves the controls disabled. Browser checks
hold or fail the module request to verify both outcomes without blockchain
requests or recovery words.

## Open-wallet sections and storage consent (0.1.10)

The open wallet separates native Nodus identity, external-network assets/receive,
sending, activity and device settings. Send and Receive shortcuts bring the
relevant section into view without submitting a transfer. The selected external
network appears beside both flows; unrequested or failed balance reads are not
presented as zero. The layout keeps the Nodus website's fonts and colors and uses
the DNA Connect wallet's identity/actions/assets hierarchy as a reference.

Creation and restore still default to temporary memory-only use. Saving a new
encrypted copy or changing its password requires an unchecked-by-default risk
acknowledgement alongside the storage warnings and a valid password of at least
16 characters. The label explains the offline-guessing reason for the minimum;
length alone is not a strength guarantee. Consent is rechecked before writing
and cleared after saving or locking. Existing saved wallets can still unlock
without a new save acknowledgement. No consent record or new secret is stored.

## Recovery phrase warning (0.1.8)

The page precautions and the top of the create/restore word form explicitly state
that nobody from Nodus will ask for recovery words. They explain that verification,
activation, syncing and repair do not require sharing a phrase: this wallet restores
locally in the browser. Before any word entry, users are directed to check the exact
`https://wallet.nodusnetwork.io` address themselves and never send words to anyone,
including a person claiming to represent Nodus. The warning is visible above the
fields; it does not introduce a new acceptance checkbox or send any data. In
0.1.9, opening create/restore focuses and scrolls to the warning first. Focusing
the first word had scrolled its heading off screen at 320px; browser regression
checks cover initial warning visibility at 320px, 390px and desktop widths.

## Recovery storage explanations (0.1.7)

The landing page and optional save controls explain temporary memory use versus
an encrypted copy in this origin’s browser-profile `localStorage`. No automatic
save, app-provided cloud sync or password reset is implied. The encryption facts
are read from `src/vault.js` and the save/lock paths in `src/app.js`: AES-256-GCM,
PBKDF2-HMAC-SHA-256 with 600,000 iterations, a fresh random salt and nonce per save,
and no password persistence by the app. Existing encrypted activity storage is
also described next to the save control.

The copy states the limits: offline password guessing against stolen ciphertext,
exposure during use to malicious code/extensions/device compromise, best-effort
memory cleanup, loss of browser data, and old encrypted copies remaining usable
with their original passwords. Users are directed to keep a private offline
24-word backup and choose a unique long password. These explanations do not
change encryption, storage formats, idle locking or signing behavior, and do not
claim security certification.

Browser-storage facts were checked against [MDN localStorage](https://developer.mozilla.org/en-US/docs/Web/API/Window/localStorage)
and the [OWASP storage guidance](https://cheatsheetseries.owasp.org/cheatsheets/HTML5_Security_Cheat_Sheet.html#storage-apis).
These references explain browser boundaries; they are not an endorsement or audit
of this wallet.

## Native Nodus address (0.1.2)

New wallets create **24 BIP39 words** and automatically show the **Nodus address**
as the primary address. Restore and encrypted unlock reproduce it from the same
phrase. The native coin is **NODUS**. The separate external-network selector does
not change the native address. Copy is available only after derivation succeeds;
lock clears the address and cancels pending work. This release displays the
address only: no native balance, sending, registration or claim is implied.

Creation and restore accept only the 24-word Nodus base phrase. Other mnemonic
lengths and BIP39 passphrases are unsupported. This is the project’s existing
BIP39/SHAKE256 derivation, not a new phrase encoding. CF-20 is not involved.
The application cannot infer which product originally generated a valid BIP39
phrase; it validates 24 words and checksum, then derives the Nodus identity.

Create, restore and backup verification use 24 individually numbered word boxes.
Generated words are read-only until backup verification. Pasting a full 24-word
phrase into any box fills the entire grid in order; shorter pastes fill from the
selected box, and excess words are rejected without truncation. Empty boxes and
invalid checksums cannot open a wallet. Local BIP39 suggestions complete only the
selected word and move focus to the next box. Lock, cancel, idle expiry and a
successful open clear every input and suggestion. No recovery text is persisted
by the input component or sent over the network.

The wallet uses the main site's Nodus SVG mark, self-hosted Inter variable fonts,
and shared colors/typography. Assets were byte-matched to nodusnetwork.io on
2026-09-20; the font license is included under `public/assets/fonts/OFL.txt`.
No external font/CDN requests or additional CSP permissions are needed. The
wallet layout includes a privacy summary and precautions: verify the exact wallet
domain in the browser address bar, keep recovery words private/offline, and use a
trusted device. It distinguishes local secret processing from the public address
and connection information visible to network and hosting providers. These are
user instructions, not an origin-verification badge or anonymity guarantee.

### Determinism and native references

The implementation uses the unchanged repository C key generator, compiled as a
small standalone WASM with Emscripten 4.0.16. The native sources below are pinned
at `b9a1a813a46223cf5ff0226d461721f35bbfae17` and are also unchanged in this release:

1. `shared/crypto/key/bip39/{bip39_pbkdf2,seed_derivation}.c`: BIP39 PBKDF2-HMAC-SHA512
   (2048 iterations, empty passphrase) gives 64 bytes; SHAKE256 of that seed followed
   by the exact UTF-8 bytes `qgp-signing-v1` gives the 32-byte signing seed.
2. `shared/crypto/sign/qgp_dilithium.c::qgp_dsa87_keypair_derand`: native ML-DSA-87
   public key, 2592 bytes. Primitive reference: [NIST FIPS 204](https://csrc.nist.gov/pubs/fips/204/final).
3. `messenger/messenger/keygen.c` and `messenger/dht/keyserver/keyserver_helpers.c`:
   SHA3-512 of that public key, rendered as 128 lowercase hexadecimal characters.
   `dnac/src/wallet/wallet.c::dnac_init` uses this fingerprint as ledger owner.

The compatibility domain `qgp-signing-v1` is unchanged by the Nodus product name.
No random key generation, signing, Cellframe encoding, prefix or checksum is
invented for the native address.

### Threat model and security boundaries

Only a same-origin static WASM file is fetched; phrase, seeds and keys never enter
an HTTP request. Each derivation owns a fresh WASM instance with no imports. The
bridge exposes only input/public-key pointers and derivation; the private key is
wiped internally. The JS caller wipes its mutable seed buffers and the entire
WASM memory in `finally`, including cancellation. Lock and wallet replacement
reject late results. Public address display does not prove network connectivity
or airdrop eligibility. Immutable JS strings and library internals still have the
existing best-effort erasure limitation; hostile same-origin code/extensions are
outside this protection.

### Verification and independent review

`test/fixtures/nodus-addresses.json` contains only public test phrases. Its four 24-word
addresses were generated by native C BIP39/SHAKE256/key-generation functions and
OpenSSL SHA3-512, then compared with the browser derivation. Tests cover 24-word
native vectors, rejection of other lengths, normalization, invalid phrases, zeroed WASM memory, cancellation,
create/restore/copy/lock/unlock/reload, stale results after reopening a different
wallet, external-network switching, and explicit module-loading errors. External
blockchain calls stay intercepted in automated browser suites.

Two independent read-only reviews checked native compatibility and UI/secret
lifecycle. They found no blocking bridge defect; their CF-20 removal-documentation
finding is corrected here. This is a scoped compatibility/security review, not
a new audit of the underlying primitives.

```sh
EMCC_BIN=/path/to/emcc bash scripts/build-nodus-wasm.sh
bash scripts/build-nodus-native-vector.sh
# Public test mnemonic on stdin only; never use personal recovery phrases:
# /tmp/nodus-wallet-native-vector < public-test-phrase.txt
npm test
npm run build
npm run test:browser
npm run test:security
npm run test:portfolio
```

## CPUNK connection

The default is `https://rpc.cellframe.net/connect`. On 2026-09-19 a read-only POST using the repository's public DNA registration address returned HTTP 200, `Access-Control-Allow-Origin: *`, POST/OPTIONS allowed, and the full CellframeNode 5.7-44 JSON response. CPUNK was `0.00000000000000001` coins / `10` datoshi; the response also contained CELL. This is an observation, not a current balance guarantee. An earlier 12-second HTTPS probe received headers but timed out before the body; HTTP also timed out. These observations do not establish a network outage. Browser preflight and live access from the final deployment origin still require verification.

The native query contract is `messenger/blockchain/cellframe/cellframe_rpc.c`: `wallet`, `info`, `{net:'Backbone', addr, token:'CPUNK'}`. The live response uses `result[0][0].tokens[]`, `token.ticker`, `coins` and `datoshi`. The parser selects exactly one CPUNK entry, checks Backbone and matching returned address, and verifies coins against integer datoshi with 18 decimal places. The older native `result[0][0].balance` format is also supported. Missing tokens, malformed data, mismatched amounts and connectivity failures are errors, never inferred zero balances. The address is always the one derived locally from the open wallet's phrase (0.1.13: there is no manual address-entry field); derivation itself verifies the Backbone network, signature type and SHA3 checksum before the address is ever queried. Neither establishes ownership to a server. The Cellframe row shows the last read outcome for its balance and updates automatically on refresh, like every other network.

A custom trusted HTTPS endpoint for Cellframe may be chosen through the same per-network provider select used for the other chains (select Cellframe, expand Device & settings, pick "Custom HTTPS endpoint…"; 0.1.16), not a dedicated CPUNK field. The default and custom endpoints are contacted directly by the browser and must allow browser access (CORS). Read-only command-line verification uses the public address from `cellframe_rpc.h`:

```sh
npm run cpunk:verify
# Optional direct HTTPS RPC endpoint
npm run cpunk:verify -- https://rpc.cellframe.net/connect
```

The command fails on connection errors or malformed responses; it does not test browser CORS. After deployment, use the page's public-address read to verify access from the actual wallet origin. Only the public address and fixed CPUNK query fields are sent to the RPC. Responses are capped at 64 KiB and browser operations at 15 seconds; redirects are refused and balances are not cached. No claim system, snapshot rule or ownership proof is implemented.

## Permanent chain RPC limitations

Ethereum uses keyless PublicNode and Solana uses the keyless Solana Vibe Station public HTTPS endpoint; BSC and TRON retain the native repository providers. Actual production availability, quotas and CORS access must be verified from the deployment origin. Ethereum/BSC and Solana endpoints may be changed for this tab; network identities are checked before reads and sends. A user-selected RPC sees public addresses and signed transactions. No seed or private key is transmitted. There is no backend relay or API-key service, and no silent endpoint fallback.

Chain SDKs, not the existing native C binaries, implement browser signing; existing Connect/Nodus code is unchanged. Real mainnet transfers have not been executed during development. This slice derives and displays the native Nodus address locally; it does not query a Nodus balance or send native transactions. Global transaction history indexing, custom-token discovery, ZK, claims, DEX/swap and tokenomics changes are outside this release.

## Remove temporary Cellframe support

```sh
VITE_ENABLE_CPUNK=false npm run build
```

The Cellframe network option, its automatic address derivation and its CPUNK asset row disappear from the network list, the network selector and the portfolio; the lazy-loaded adapter and derivation module (and their WASM) are excluded from the bundle, verified by inspecting `dist/assets` after a disabled build. The reusable `src/wallet.js`, permanent adapters and key derivation do not import CPUNK. `src/config.js`'s `CELLFRAME` export and `src/portfolio.js`'s `CPUNK_ASSET` export remain defined either way (plain data, no import of the adapter/derivation/WASM), but nothing renders or uses them when the flag is off.

For final source removal, delete `src/adapters/cpunk.js`, `src/cpunk-protocol.js`, `scripts/verify-cpunk.js`, `src/cpunk/` (including WASM), `crypto/cpunk-wasm.c`, `crypto/native-vector.c`, `scripts/build-cpunk-wasm.sh`, `scripts/build-native-vector.sh`, and the corresponding CPUNK-specific tests. Also remove: `CELLFRAME` from `src/config.js`; `CPUNK_ASSET` from `src/portfolio.js`; the `cellframe`-specific branches in `src/portfolio-view.js` (the `cellframe` constructor option, `networks`/`assets` merge, `setAddress`, the receive-only Send-button omission); and, in `src/app.js`, `showCellframeAddress`/`doShowCellframeAddress`, `cellframeDerivation`/`cellframeReader`, the top-level `if (import.meta.env.VITE_ENABLE_CPUNK...)` block, the `cellframe` branches in `selectChain()`/`readBalances`/`lock()`/the send-form guard, and the `#cellframe-address-status`/`#send-fields`/`#send-disabled-note` wiring (the `#send-fields` wrapper and its compensating `#send-fields > button` CSS rule may stay or be flattened back, since no other network currently needs the split). Keep `src/nodus/`, `crypto/nodus-*.c` and `scripts/build-nodus-*.sh`: native Nodus address derivation is permanent and independent of CF-20. No permanent-chain changes are needed.

## Verification

```sh
npm test
npm run build
npx playwright install chromium
npm run test:browser
npm run test:security
npm run test:portfolio
```

The browser test starts its own preview server and intercepts **all external HTTPS requests**, so it never broadcasts to a real chain. Set `CHROMIUM_PATH` to use an existing Chromium binary or `WALLET_URL` to test an already running preview. Offline tests cover deterministic recovery addresses, exact amounts, malformed responses, CPUNK public-only requests, review lifecycle, ETH/SOL signatures and TRON transaction tampering. Browser smoke covers create/backup/restore, chain selection (including Cellframe), mocked ETH/ERC-20 send review/finality/scoped activity, network mismatch, automatic Cellframe address derivation and CPUNK balance display/error, send disabled on Cellframe, lock, temporary no-storage mode, encrypted save/unlock/password change/delete, reload/history recovery, KDF-lock cancellation and mobile overflow. Browser portfolio checks additionally cover the CPUNK row's grouping, its exclusion from the USD total and completeness, and its receive-only actions.

`npm audit --json` on 2026-09-19 reports **0 vulnerabilities** across all severities; the recorded result is `test/fixtures/dependency-audit.json`. `@solana/web3.js` is pinned to 1.99.0. Legacy `@solana/spl-token` and its vulnerable `bigint-buffer` tree were removed in favor of the maintained generated `@solana-program/token` 0.16.1 instruction client. A small adapter converts standard instruction account roles to the existing web3.js signer; golden prior-SPL instruction bytes/account roles, ATA derivation, rejection of substituted source accounts and signed native/SPL RPC flows are regression-tested.

A scoped `@solana/web3.js` dependency override uses Jayson 5.0.0, removing vulnerable `stream-json` and old `uuid` dependencies. Its browser request/callback API was inspected and exercised through the SDK’s real RPC transport in deterministic tests. This is a deliberate tested major dependency override; reassess it on future SDK upgrades. No advisory is suppressed and `npm audit fix --force` was not used. A zero-advisory result is not a security audit or assurance against unknown vulnerabilities. The existing large chain-library bundle warning remains (~1.37 MB before gzip).

## Source layout

- `src/config.js`: permanent mainnet/token registry, browser RPC defaults, full Solana genesis hash, and the temporary read-only `CELLFRAME` network definition (name/symbol/decimals/endpoint, `icon`, `receiveOnly: true`; kept out of the sendable `CHAINS` registry). Every `CHAINS` entry and `CELLFRAME` carry an explicit `icon` file name (0.1.14) so `src/portfolio-view.js` never guesses one from the symbol.
- `src/keys.js`: local 24-word generation, recovery and external-chain derivation.
- `src/nodus/`, `crypto/nodus-*.c`, `scripts/build-nodus-*.sh`: permanent native Nodus address derivation and native compatibility verifier.
- `src/core.js`, `src/rpc-transport.js`: exact units, bounded JSON/stream parsing and shared timeout-limited transport for direct RPC plus Ethers, Solana and TRON SDK calls.
- `src/wallet.js`: common adapter routing and single-use transfer review.
- `src/adapters/{evm,solana,tron}.js`: permanent balance and send adapters.
- `src/adapters/cpunk.js`, `src/cpunk-protocol.js`: isolated temporary public balance adapter and bounded protocol parser, called from `src/app.js`'s portfolio wiring like the permanent chain adapters (0.1.13: no longer a separate manual-entry panel).
- `src/cpunk/`, `crypto/cpunk-wasm.c`, `crypto/native-vector.c`, `scripts/build-native-vector.sh`, `scripts/build-cpunk-wasm.sh`: temporary legacy Cellframe address derivation, native reference bridge and reproducible build.
- `src/activity.js`, `src/activity-storage.js`: public confirmation tracking and bounded, authenticated encrypted activity storage.
- `src/vault.js`: optional authenticated local encryption.
- `src/app.js`, `index.html`, `src/style.css`: accountless responsive UI.
- `test/`: offline and fully intercepted browser verification.

## Connect-compatible Cellframe address derivation

Open or restore your Nodus wallet: the Cellframe (CPUNK) address derives automatically in the browser, right alongside the Nodus address, with no separate panel or button (0.1.13). Select **Cellframe** from the network list to see it in the receive panel; reading the derived public balance for the portfolio's CPUNK row is a separate, automatic step that starts once the address is ready. This mode accepts the same normalized, checksum-valid English BIP39 phrase as the multichain wallet. Arbitrary non-BIP39 Cellframe strings are not supported; there is no field to paste one. No recovery phrase is sent to the RPC.

The temporary `src/cpunk/` module compiles the repository's unchanged legacy Cellframe Dilithium MODE_1 C, not modern ML-DSA. It matches native `EVP_sha3_256(mnemonic)` (not Keccak), the key generator’s subsequent SHA3, 1196-byte serialized public key and 77-byte Backbone address/checksum. A fresh WASM instance is used per derivation and its memory is overwritten afterward; JavaScript string erasure cannot be guaranteed. The open wallet retains its phrase in RAM until lock to support derivation.

Rebuild with Zig 0.13.0: `ZIG_BIN=/path/to/zig bash scripts/build-cpunk-wasm.sh`. Native reference verification (GCC/OpenSSL development headers): `bash scripts/build-native-vector.sh`, then `CPUNK_NATIVE_CHECK=/tmp/nodus-cpunk-native-vector npm test`. Three public BIP39 vectors crosscheck the actual native wallet/address functions against the browser module. The committed WASM allows normal builds without installing a compiler. `VITE_ENABLE_CPUNK=false` excludes this module and WASM from the production bundle.

## Live read verification

Run `CHROMIUM_PATH=/path/to/chromium npm run verify:networks` to open a minimal localhost page and execute standard public network-identity/native-balance reads against every provider in each network's `rpcOptions` list (0.1.16; EVM entries also read the `finalized` block and gas price). The script does not create keys, sign or broadcast; all addresses are public repository test vectors. It exits unsuccessfully when any connection is blocked. `python3 scripts/verify-rpc-transport.py` separately probes permanent-chain identity and public native balances using curl; it is not a browser CORS test.

The final recorded 2026-09-19 browser results are in `test/fixtures/network-verification.json`: with the configured environment proxy, all five providers were blocked by Chromium’s `net::ERR_CERT_AUTHORITY_INVALID` before CORS could be established. The local probe page loaded successfully. TLS validation was kept enabled; no certificate checks were bypassed. This is an environment observation, not evidence that the providers are offline. `test/fixtures/rpc-transport-verification.json` records independent curl results. CPUNK HTTPS curl previously returned a valid live balance as detailed above. Ethereum/BSC adapters compare chain IDs and Solana compares its mainnet genesis; TRON uses the pinned mainnet provider, and the verification report records an observed genesis when available without claiming an independent genesis match. Final deployment-origin CORS and actual funded mainnet transfers remain unverified. Offline signing/serialization and intercepted browser sends do not substitute for real-transfer validation.

Curl results in that run: BSC returned chain ID `0x38` and native balance `0x0`; TRON returned genesis `00000000000000001ebf88508a03865c71d452e25f4d51194196a1d22b6653dc` and an account response without a native balance field. Ethereum requests timed out at 25 seconds; Solana returned HTTP/RPC 403 `Access forbidden`. No automatic provider substitution was made.

## Confirmation and activity

Sends initiated here appear under **Activity recorded in this tab**, scoped to the current chain and sender. This is not a full incoming/outgoing account history. Use the account explorer for global history. By default records stay in tab memory and are cleared on lock. Opting into a saved wallet also saves up to 100 activity records encrypted for reload recovery; keys are not kept by history.

The app computes the transaction ID locally before broadcast and records it even if the response is ambiguous. It never retries a broadcast automatically. Polling checks only public status and stops on lock or chain changes. Ethereum/BSC require a canonical receipt and the provider’s finalized block before reporting confirmed/failed. Solana requires finalized signature status; missing history after the finalized validity window remains unknown, with continued polling and an explorer verification reminder. TRON uses the solidified transaction execution result and checks the observed mainnet genesis; absence is pending, not an invented failure. Providers lacking finality/status APIs may leave activity unresolved with a read error. Transient read failures do not overwrite prior status. Pending and included are never labeled confirmed. Tracking starts with the endpoint that prepared the send. Changing RPC settings cancels current reads and updates visible records to the selected provider; reloaded records use chain defaults until changed.

## Optional encrypted device wallet

**Save wallet on this device** encrypts the open wallet’s full recovery phrase using browser Web Crypto: AES-256-GCM, a new random 128-bit salt and 96-bit IV, and PBKDF2-HMAC-SHA256 with 600,000 iterations. New passwords must be 16–1024 characters; obvious repetitions, sequences and common-password patterns are rejected locally. These checks do not guarantee entropy: use a unique password generated by a password manager. Existing version-1 vaults using the previous 12-character minimum still unlock so they can be migrated without losing access. The strict versioned format authenticates its header (including KDF parameters and wallet ID) and rejects malformed/oversized records. Passwords are never persisted or transmitted. Wrong passwords and altered ciphertext fail authentication. This is not a security audit or protection against malicious scripts/extensions executing in an unlocked browser.

Lock/reload requires either the saved local password or the recovery phrase. The recovery phrase remains the backup if storage is cleared or the password is forgotten. Save/unlock/password-change operations are invalidated by lock or wallet replacement; changes in another tab lock this tab. Change password requires the current password and matching open saved wallet. Explicitly deleting the device copy also deletes its saved activity, without moving funds. Temporary wallets remain available. JavaScript strings and garbage-collected copies cannot be reliably erased.

Saving also stores **authenticated encrypted activity** (chain, sender/recipient, amount, symbol, transaction ID and timestamps), capped at 100 rows. The version-2 activity envelope uses AES-256-GCM with fresh 96-bit IVs; a non-extractable key is derived from the high-entropy recovery phrase using HKDF-SHA256, the vault ID as salt and the separate `nodus.wallet.activity.v2` context. The envelope header is authenticated as AAD. It contains no recovery phrase, private key, password or custom provider URL/API credentials. Password changes preserve the vault ID and activity access. Activity is bound to the wallet but is not a proof that an RPC provider is honest.

Writes are serialized across tabs using Web Locks and scoped to the active wallet/vault. Each write authenticates and merges the latest stored history before encryption. Vault changes, deletion and explicit history discard use the same lock. A phrase-only restore must lock and unlock the saved wallet before changing its password; it cannot overwrite unread or damaged history. A saved wallet's signed transaction ID is encrypted and stored before the first broadcast; storage failure or a lock/vault change during this operation stops submission. The adapters recheck the lock after this asynchronous step. Old unauthenticated version-1 history and damaged activity are not imported or automatically overwritten: the wallet can still unlock, but sending remains blocked until the user checks the explorer and explicitly discards the unreadable local history. This does not delete the saved wallet or move funds. Previously completed statuses are rechecked after unlock; custom RPC settings remain in memory and restored activity uses chain defaults.

Solana uses an application-owned mutable `Signer.secretKey` buffer, which is overwritten on lock. The SDK `Keypair.secretKey` getter returns copies and is not used for long-lived secret storage. JavaScript, cryptographic-library temporaries and immutable strings still cannot provide guaranteed physical-memory erasure.

## Security regression checks

`npm test` includes the original vectors and protocol checks plus red-team regressions for real Solana buffer erasure, weak-password rejection with legacy unlock, activity tampering/cross-wallet replay/forged plaintext history, stream/JSON/numeric bounds, stalled-body cancellation and the real SDK transport paths. It exercises mocked TRX and TRC-20 signatures and verifies that Solana/TRON do not broadcast if locked while awaiting activity persistence.

`npm run test:security` exercises the production bundle in Chromium with all external requests intercepted: timeouts during create/verify/restore, suspended-tab expiry, weak password feedback, encrypted history, hash persistence before broadcast, tampered/legacy history handling, and lock/delete during pending encryption. Use `CHROMIUM_PATH` as with the browser smoke test. No real blockchain transaction is submitted.

Permanent-chain transport limits are 256 KiB per response by default, 2 MiB for EVM block reads and 4 MiB for Solana token-account lists, with 4,096 entries per object/array, 65,536 characters per string and depth/node limits. Numeric balances are bounded before BigInt conversion. Streams are counted independently of Content-Length, redirects are refused and the 15-second timeout covers body reads. Very large legitimate account lists can therefore produce an explicit error instead of a partial balance.

The five findings from the 2026-09-19 local review are covered by these regressions. Of the eight 2026-09-22 red-team findings fixed in 0.1.15, six are covered by these regressions: review-dialog focus/timing (E-2), the same-network EVM double-send lock and its abandon escape hatch (B-1), the TRON expiration bound (B-2), the local password rules (A-1), the lower-case-address review warning (E-3) and paste-disabled backup verification (E-4). The remaining two, the broadcast-uncertain message wording (E-1) and the ethers RNG/KDF lock (D-2), are verified by code review only, not by an automated test. This is not an independent security certification. See [security follow-up](SECURITY-FOLLOWUP.md) for scope and remaining deployment checks.

## Deployment corrections (0.1.1, 2026-09-20)

The initial production-origin read checks found browser access failures at
`eth.llamarpc.com` (CORS) and `api.mainnet-beta.solana.com` (HTTP 403).
Version 0.1.1 selected the endpoints published by [PublicNode Ethereum](https://ethereum.publicnode.com/)
and [PublicNode Solana](https://solana.publicnode.com/), with no API key or gateway.
These defaults remain user-changeable and no silent fallback is introduced.

Solana's `getGenesisHash` returns the full genesis hash
`5eykt4UsFv8P8NJdTREpY1vzqKqZKvdpKuc147dw2N9d`, not the truncated
[CAIP-2 reference](https://namespaces.chainagnostic.org/solana/caip2).
Balance, send and activity paths use the same full expected hash; regression
tests accept the full mainnet value and reject its truncated prefix and other networks.

The malformed DAI preset is corrected to
`0x6B175474E89094C44Da98b954EedeAC495271d0F` with 18 decimals, as documented in
the [issuer's Dai guide](https://github.com/sky-ecosystem/developerguides/blob/master/dai/dai-token/dai-token.md).
The native C header is unchanged. The historical September 19 probe fixtures above
remain evidence of that earlier environment, not results for this release.

## Public Solana RPC and wallet layout (0.1.3, 2026-09-20)

PublicNode accepted SOL reads but refused indexed USDT/USDC queries with HTTP
403 requiring a personal token. Solana now defaults to the provider-published
[Solana Vibe Station public endpoint](https://solanavibestation.com/)
`https://public.rpc.solanavibestation.com`. Production-origin Chromium reads
verified the full mainnet genesis, SOL, USDT and USDC without an API key.
A burst hit HTTP 429; reads to this exact default URL are spaced by 1.2 seconds
per tab, including SDK and activity reads. Waiting is included in the existing
15-second timeout, cancellation prevents a queued fetch, and failed reads remain
errors. Other RPC URLs and broadcasts are not queued; nothing is automatically
retried. Shared public capacity and access policies can still change.

The landing page is solely the Nodus wallet. The separate CPUNK card and its
Cellframe/airdrop promotion are removed. Existing CPUNK read-only support
(0.1.13) is one row in the wallet's own asset list, next to ETH/BNB/SOL/TRX,
not a separate collapsed panel. Lock aborts its pending address derivation and
balance read and clears its displayed address. No CELL balance or transfer
support is claimed. The CF-20 code remains isolated and removable with the
existing flag.

## Red-team fixes (0.1.15)

Eight findings from the 2026-09-22 red-team review (`docs/plans/2026-09-22-web-wallet-redteam.md`,
resolved per the writer spec `docs/plans/2026-09-23-wallet-0.1.15-spec.md`):

- **Review dialog focus and timing (E-2).** The transfer review dialog now places
  Cancel first in the DOM so `showModal()` focuses it by default, and Confirm
  starts disabled for 600 ms after the dialog opens. A keydown handler on the
  dialog suppresses Enter while Confirm is disabled, so a key held down while
  filling the send form cannot reach a signing action before the reviewer has
  had a moment to read the details. The recipient and amount fields clear after
  a successful broadcast.
- **Same-network EVM double-send lock (B-1, operator decision
  `docs/plans/decisions/2026-09-23-web-wallet-double-send-and-password.md`,
  option 1a).** Ethereum/BSC transfers now carry their signed nonce into the
  review and into the saved activity record. While a previous send on the same
  network has no final result yet, opening a new review is blocked with a
  plain-language message naming the pending transaction. Resolution is
  automatic: the existing 12-second activity tracker also reads the account's
  current transaction count when a receipt is absent, and marks the record
  `replaced` (terminal) once that count has passed the saved nonce. A record can
  also be marked `abandoned` (permanent, requires two clicks) from the Activity
  panel; records saved before this release (no `nonce` field) keep today's
  behavior unchanged, with no extra network read.
- **TRON expiration bound (B-2).** `validateTransaction` now rejects a TRON
  transaction whose `raw_data.expiration` is not a safe integer or is more than
  10 minutes in the future, before it reaches the encoding-consistency check.
- **Local password rules (A-1, operator decision option 2b, no added
  dependency).** `validateNewPassword` closes the previous anchored-regex bypass
  (a single trailing non-digit character defeated `^(word)[0-9]*$`) by removing
  every occurrence of an expanded common-word list from the folded password
  wherever it appears; what remains must still carry at least 8 characters.
  Repeated-pattern and sequential-run checks now scan every 8+ character window
  of the folded password, not only the password as a whole. A password under 24
  characters must also mix at least two character classes (letter/digit/other).
  Existing 12-character v1 vaults still unlock unchanged.
- **Lower-case EVM address warning (E-3).** The review's `To` line always shows
  the checksummed address; if the recipient was typed as an all-lower-case hex
  address, an additional highlighted "Address check" line asks the sender to
  compare it character by character. Sending is not blocked.
- **Backup verification blocks paste (E-4).** During the "re-enter your saved
  phrase" verification step only, pasting into a recovery word box is rejected
  with a visible note; restoring an existing wallet is unaffected.
- **Broadcast-uncertain wording (E-1).** When a send fails before a signed
  transaction exists, the status message is just the error; the "broadcast
  failure can have an uncertain outcome" sentence now only appears when a
  transaction was actually signed and recorded.
- **RNG/KDF hardening (D-2).** `main.js` locks ethers' `randomBytes` and
  `pbkdf2` backends (`.lock()`) before the wallet module loads, so nothing later
  in the page can register a replacement implementation. The saved-wallet KDF
  uses WebCrypto directly (`src/vault.js`) and does not depend on ethers'
  `pbkdf2`, so this changes no existing behavior.

## RPC provider list, Ixios address and ML-DSA-87 signing module (0.1.16)

Spec `docs/plans/2026-09-23-wallet-0.1.16-ixios-spec.md`; decisions
`docs/plans/decisions/2026-09-23-ixios-separate-mldsa-key.md`,
`2026-09-23-web-wallet-mldsa-hedged-signing.md`, `2026-09-23-ixios-send-mainnet-first.md`.

- **RPC provider list.** Every network in `src/config.js` carries
  `rpcOptions: [{ url, label, note? }]`; `rpcOptions[0]` is the unchanged default
  `endpoint`. **Device & settings → Network connection settings** is now a
  provider select plus a "Custom HTTPS endpoint…" choice (not offered for TRON,
  which keeps its single pinned provider; Apply still re-checks it). Listed on
  2026-09-23 after identity, CORS, balance, `finalized` block and gas-price reads:
  Ethereum — PublicNode, dRPC, Blast API, MEV Blocker (shown with a
  private-submission note); BSC — Binance dataseed and dataseed1–4, Defibit,
  Ninicoin, PublicNode; Solana, TRON, Cellframe — the existing single provider.
  Not listed, with the observed reason: cloudflare-eth (`finalized` and
  `eth_gasPrice` rejected, activity tracking would break), 1rpc.io (finalized
  block behind), Ankr (API key), LlamaRPC (525), BlockPI (521), BSC dRPC (rate
  limit), Solana mainnet-beta (403), Solana PublicNode (token reads need a key),
  Solana dRPC (paid), Flashbots Protect (`eth_getBalance` HTTP 504 after 10.5 s,
  3/3; browser "Failed to fetch"). A listed provider is not more trustworthy than
  a custom one: an RPC can still misreport balances and nonces.
  `npm run verify:networks` probes every listed URL from Chromium; the 2026-09-23
  run returned READ_OK for all 15.
- **Ixios address, build flag `VITE_ENABLE_IXIOS=true` (default off in the
  source; the published 0.1.16 build turns it on — operator decision
  2026-09-23: show it, remove later if needed; the panel was replaced in 0.1.17,
  see below).** When enabled, a panel shows the
  wallet's Ixios Q-address: seed `SHAKE256(BIP39 master seed ‖ "ixios-mldsa87-v1", 32)`,
  key generation through the existing keygen-only `src/nodus/mldsa87.wasm`,
  address `SHA3-512(pk)[16..63]` shown with Ixios' Keccak-512 mixed-case
  checksum. It is a separate key from the Nodus identity. Ixios is not in the
  network selector, portfolio or send form. **Not usable yet:** on 2026-09-23 the
  Ixios mainnet validators ran ixiosSpark 1.0.3 and the public RPC 1.0.5; those
  versions use 32-byte addresses and have no ML-DSA support (Q-addresses arrive
  with v1.1.0, which the network had not adopted). A Q-address cannot receive
  on that network, so the panel is labelled "not active yet" and tells users
  not to send IXIOS to it. A disabled build contains no Ixios JavaScript (the
  panel's hidden markup and CSS remain).
- **ML-DSA-87 signing module (in the tree, not in any build).**
  `src/pq/mldsa87-sign.wasm` (`crypto/mldsa87-sign-wasm.c`,
  `scripts/build-mldsa87-sign-wasm.sh`, Emscripten 4.0.16, zero imports): one
  call takes seed, 32-byte hash and 32-byte `rnd`, runs pq-crystals
  `qgp_dsa87_keypair_derand` + `crypto_sign_signature_internal` with the
  empty-context prefix, and returns only the public key and signature; the
  secret key never leaves WASM and `src/pq/sign.js` zeroes the whole instance
  after every call. Production signing is hedged (`rnd` from
  `crypto.getRandomValues`). Nothing imports it yet; it is for Ixios (and later
  Nodus) sending.
- **Cross-implementation evidence.** `bash scripts/build-ixios-native-vector.sh`
  builds a native generator; its output for the public phrases is committed as
  `test/fixtures/ixios-vectors.json` and must reproduce byte for byte. The same
  keys, signatures and addresses were checked against Cloudflare circl v1.6.3
  (independent ML-DSA-87: identical public keys from the same seed, signatures
  verify, tampered ones fail) and ixiosSpark v1.1.0 (`874f6d6c`) address and
  checksum code; `test/fixtures/ixios-checksum.json` is ixiosSpark
  `common.Address.Hex()` output. The Go oracles live outside this tree
  (`~/releases/nodus-web-wallet/ixios-interop/`) because ixiosSpark is LGPL;
  no Ixios code is copied here.
- **Tests.** `test/mldsa87-sign.test.js` and `test/ixios-address.test.js` run in
  `npm test`; `npm run test:ixios` builds flag-on and flag-off bundles and checks
  the panel, the lock behaviour and that no build ships the signing module.
  **How these can lie:** C ↔ WASM equality proves the two builds of the same
  pq-crystals code agree, not that the code is correct — the circl comparison
  is the independent check, and it is run by hand, not in CI. No Ixios
  transaction has been sent on any network.

## Ixios listed like the other coins (0.1.17)

The 0.1.16 top-of-page Ixios panel is gone (operator, 2026-09-23: Ixios belongs
where the other coins are). With `VITE_ENABLE_IXIOS=true` (the published build):

- Ixios is a receive-only network in the same places as Cellframe/CPUNK: the
  network selector, the portfolio filters and health badges, and the asset list
  (an IXIOS row with its own icon `public/assets/coins/ixios.png`, the Ixios
  mark, and only a Receive action). Selecting it shows the checksummed Q-address
  in the receive panel, hides the send fields and shows an Ixios-specific note:
  "Do not send IXIOS to this address yet…". Cellframe keeps its own note.
- The network is marked `notActive`: its balance is **never read** (no request
  to any Ixios host), because the public RPC (v1.0.5) answers 0 for any 48-byte
  address. The row and badge say "Not active yet" and the amount is "—", never
  a false zero. IXIOS is unpriced and outside the USD total.
- The definition lives in `src/ixios/network.js`, pulled in only by the flag-on
  build; `createPortfolio` takes an ordered `extraNetworks` list
  (Cellframe, then Ixios) instead of the single `cellframe` option.
- `npm run test:ixios` checks the placement, the zero Ixios requests, the lock
  behaviour and the flag-off build (no Ixios option, row, badge, markup or JS).

## Ixios handled exactly like Cellframe (0.1.18)

Operator, 2026-09-23: no special treatment for Ixios. The 0.1.17 `notActive`
behaviour is removed:

- The IXIOS balance is read like CPUNK's, from the selected Ixios RPC
  (`src/ixios/balance.js`): network identity first — block 0 hash must equal
  Ixios mainnet genesis `0xa19acef5…2f2f` (ixiosSpark `params/config.go:27`;
  never `eth_chainId`, which is 1 on both Ixios and Ethereum) — then
  `eth_getBalance`. A wrong network or a failed read shows the shared
  "Balance unavailable" state. IXIOS stays unpriced and outside the USD total.
- The send note matches Cellframe's style: "Sending IXIOS is not available in
  this release. The Ixios network does not accept this address type yet."
- Note: on 2026-09-23 the Ixios mainnet (validators on ixiosSpark 1.0.3, RPC
  1.0.5) has no Q-address support, so the balance shown is 0.
- Tests mock the Ixios RPC (`test/portfolio-routes.js` `ixiosRead`,
  `test/ixios-balance.test.js`); `browser-nodus.js` now routes Ixios reads to
  that mock instead of counting them as unexpected requests.
