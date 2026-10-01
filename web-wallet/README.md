# Nodus Web Wallet — first-stage browser implementation

A standalone, accountless browser client alongside the existing DNA applications. No Connect installation, extension, identity registration, email, phone, or account backend is required. This is a development preview; it is not an audited custody product.

The product is Nodus Wallet. CPUNK is the temporary CF-20 integration until the airdrop; it is not a permanent chain module or the wallet identity. Airdrop eligibility and claims are outside this release.

## Run

Requires Node.js 22.12+ and a modern browser with Web Crypto and BigInt. Saved-wallet operations also require the Web Locks API to serialize storage changes across tabs.

Since 0.1.23 the lockfile holds a single `utf-8-validate` record (6.0.6, the
optional `ws` peer of `ethers` and `@solana/kit`; `ws` is not in the browser
bundle). The separate 5.0.10 record that Jayson needed left with
`@solana/web3.js`; `npm ci` from the 0.1.23 lockfile was verified clean with
npm 10.9.9 on Node.js 22.23.3.

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

- **Claim a genesis allocation on the Nodus testnet (0.1.26).** When the open wallet's Nodus address holds an allocation in the chain's genesis distribution, a "Claim your allocation (… NODUS)" action appears under the NODUS asset; it opens a review (amount, paid to your own address, chain id, "can be claimed only once"), then submits and tracks the claim in Activity. The C side is nodus-cli `v2-claim` (`nodus/tools/nodus-cli.c` `cmd_v2_claim`) compiled into `send.wasm` (`crypto/nodus-send-wasm.c` "GENESIS CLAIM", over the shared codec `shared/dnac/manifest_wire.c`, now in both build scripts together with `ledger_roots_v2.c`).
  - **Data:** no node RPC serves a manifest, a leaf list or a proof, so `src/nodus/send-module.js` `NODUS_CLAIM_DATA` embeds the testnet's genesis manifest (431 bytes, as stored in `v2_manifests`), its hash (`1807f972…31b4b8`) and its single allocation leaf (the Founder, 50,000,000 NODUS), next to the pinned chain id. `validateNodusClaimData` checks the shape; the module refuses to claim unless the manifest decodes strictly and re-hashes to the embedded hash, targets the native coin, and the leaves rebuild the manifest's committed allocation root and total (`nsw_claim_set_manifest` / `nsw_claim_seal`). A key bound by more than one leaf is refused (the CLI claims every match; the wallet claims one).
  - **Module API** (`send-module.js`, passed through the `client.js` queue; optional — a module without them still connects and every claim call answers "not available"): `claimStatus()` → `{ found: false }` or `{ found, amount, tip, startHeight, endHeight, window: 'open'|'not-open'|'closed', claimed: 'yes'|'no-evidence'|'unknown', outputId }`; `claimBuild()` → `{ bytes, claimId, decoded: { recipient, amount, chainId, nullifier, outputId, leafIndex } }` read back from the signed bytes (decode, proof and signature re-verified in C); `claimSubmit({ bytes })` → `{ accepted, message? }`, only the bytes of the last build. Adapter: `src/adapters/nodus.js` `claimStatus`, `prepareClaim`, `isClaimRow`.
  - **"Already claimed"** is an inference, not a lookup: `dnac_supply`'s `unclaimed` bucket below this allocation's amount proves it was claimed (only this key can claim it); otherwise "no evidence" and the node's admission decides. The `dnac_nullifier` RPC is not used — it reads the legacy `nullifiers` table, not the claim spent-set. The claim window is checked against the node's tip + 1, as admission does.
  - **Tracking:** the Activity record's id is the coin the claim creates (`dna_claim_utxo_id` of its nullifier — the same for every signature variant); the block scan matches an applied claim that created that coin. The record lists that id as its single "input", which marks it as a claim after a reload and locks no coin. A claim has no expiry: past the 90-block scan window the claim state decides (claimed → confirmed; otherwise the record closes with a note that the allocation can be claimed again, never paid twice).
  - **Also in 0.1.26:** the portfolio note says the NODUS balance is shown (testnet, not counted in the total) once the send module is connected, and still "not shown yet" before that; the network label reads "Testnet" for Nodus instead of "Mainnet" (transfer panel, send block, review dialog).
  - **Not verified in this build:** a claim against the live testnet (the operator runs it); the Asyncify stack bound was not re-measured for the claim exports (`scripts/build-nodus-send-wasm.sh` comment).
- **Earn (0.1.31).** The staking panel below is reached from an "Earn" button beside Send / Receive, an "Earn" link in the wallet navigation and an "Earn" button on the NODUS portfolio row (`src/app.js` `setEarnAvailable`, `src/portfolio-view.js` `setEarn`); all three appear only while staking is available. The right-hand column shows either the Send / Receive panel or the Earn panel, never both (0.1.32, `showEarn`): Earn swaps Send / Receive out; Send, Receive, the "Send / Receive" link or selecting an asset row swaps it back. Its heading reads "Earn · Delegate NODUS · Testnet". Earn selects NODUS as the network so Activity shows where a delegation is tracked. Not covered by the browser suites (they do not bring up a staking-capable module).
- **Activity and Earn styling.** Activity rows, the validator list and "Your delegations" use the portfolio's row style (one bordered group, amount/identity on the left, a status pill on the right, the row's link or buttons right-aligned below; Activity rows also show the network and the send's local time); the Earn panel's blocks are separated like the Send block (`src/style.css` `.activity-row`, `.stake-row`, `.status-badge`, `.stake-block`).
- **Delegate, undelegate and become a validator on the Nodus testnet (0.1.29).** A "Delegate NODUS · Testnet" panel appears while the NODUS send module is connected: the validator list (shortened key, status, own stake, delegated, commission), a delegation form (a new delegation is at least 100 NODUS; adding to an existing one can be any amount), "Your delegations" with an undelegate amount per row, and "Become a validator" (exactly 10,000,000 NODUS bond, commission 0–50%, bond returns to the wallet's own address) behind an extra "I understand" checkbox. Every action opens the usual review dialog; its values are read back by the module from the signed envelope and compared with the request before anything is shown, and the transaction is tracked in Activity like a send (its coins held until it is included or expires).
  - **Same C code as nodus-cli.** The envelopes are built by the shared builder `nodus/src/client/nodus_v2_stake.c` (nodus-cli `v2-envelope stake | delegate | undelegate` uses it too; `undelegate` is new in both), compiled into `send.wasm` (`crypto/nodus-send-wasm.c` "STAKING": `nsw_validators`, `nsw_delegations`, `nsw_stake_build`, `nsw_stake_offline_build`, the `nsw_const_*` chain constants). The SYSTEM ruleset identity the record leg is signed against now comes from the generated `nodus/include/nodus/nodus_ruleset_pins.h` (the "Yol 2" mechanism, extended; `test_ruleset_pins` byte-compares it with the node's table).
  - **What the wallet checks before building** (the builder cannot see chain state): the target is listed and Active or Waiting for a seat; the 100-NODUS minimum for a new delegation; an undelegation is not above the delegation and leaves 0 or at least 100 NODUS; a wallet already listed as a validator (any status but Stopped) cannot bond again. The module itself resolves a validator's public key from its own last listing (it derives each fingerprint from the key) and refuses a target not in it.
  - **Undelegating** returns the NODUS as a separate coin locked for 12 epochs (12 × 720 = 8,640 blocks) after the validator set next changes; it keeps earning until then. The network fee is paid from spendable NODUS. There is no unstake action for a validator in this wallet.
  - **Known limits:** Activity shows "Delegation / Undelegation / Validator bond" only in the tab that made it — the saved activity format (`src/activity-storage.js`) has no field for the action, so after a reload such a row reads as a NODUS transfer to the validator's address. The validator list shows at most 256 validators. A delegation whose validator is not in the list cannot be undelegated from here.
  - **Clearer submit refusal wording.** A node answers a CheckTx refusal with error code 7, and the client also returns code 7 when a reply cannot be read or carries no status (`nodus/src/client/nodus_client.c` `nodus_client_dnac_spend`), so the module cannot tell the two apart. A code-7 claim now reads "refused this claim, or its answer could not be read (code 7) … check the balance before trying again" (previously "refused … may already have been claimed"); another error code reads "could not accept this claim (code N)"; a readable non-approved status reads "refused this claim". A code-7 transfer reads "refused this transfer, or its answer could not be read" instead of "did not answer". Outcomes are unchanged.
  - **Not verified in this build:** nothing was run against the testnet (the operator runs it); the Asyncify stack bound was not re-measured for the staking exports (`scripts/build-nodus-send-wasm.sh` comment).
- **Readable balances (0.1.28).** Balances show thousands separators and at most 6 fractional digits, truncated (never rounded up), trailing zeros removed, on one line; a positive amount under 0.000001 reads `<0.000001`; the exact value is in the tooltip. Display only — sending and review use the exact amounts. 18-decimal balances (CPUNK, ETH) used to wrap mid-number and look like a separate label. A failed "is an allocation waiting?" check now shows a retry action with the reason instead of hiding the claim offer silently.
- **Six NODUS endpoints (0.1.27).** The module now tries EU-5, US-1, EU-1, EU-2, EU-3 and EU-4 in that order (each Caddy TLS on 443 → the node's WebSocket entry, installed 2026-09-30); if one is down the next is used. EU-6 has no entry: its 443 serves the websites and this wallet. The wallet server's CSP header lists exactly those six `wss://` addresses.
- **NODUS balance and send on the Nodus testnet (0.1.25).** `src/nodus/send-module.js` `NODUS_SEND_NETWORK` now holds the testnet: chain id `a48d1a78…6114` (read from the live genesis document), scheme `wss`, one endpoint (EU-5, `164.68.116.180:443`, Caddy TLS → the node's WebSocket entry), and all seven validator keys pinned (each node's `identity/nodus.fp`, re-derived as SHA3-512 of its public key). Opening the wallet connects the NODUS send module (`send.wasm`, package (c3)) to that node; the module refuses a server whose key is not pinned and a node that reports another chain id. Only EU-5 serves the browser today — if it is down, NODUS shows as unavailable (no fallback yet). The wallet server's `Content-Security-Policy` header must allow `wss://164.68.116.180` (the page's own meta CSP already allows `wss:`). `dist/THIRD-PARTY-LICENSES.txt` now also carries OpenSSL 3.0.15 (Apache-2.0), musl (MIT) and Emscripten 6.0.10 (MIT OR NCSA), compiled into `send.wasm` (provenance in `licenses/SOURCES.txt`). Claim, delegate and stake are not in this release.
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
to see its network amounts and choose Send or Receive on that exact network
(since 0.1.22, clicking the network row itself also selects that network in the
Send / Receive panel).
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

The open wallet separates the portfolio, the asset list (02), one Send / Receive
panel (03), activity (04) and device settings (05). (Until 0.1.21 the native Nodus
address also had its own panel beside the portfolio; since 0.1.21 NODUS is the
first entry of the asset list and network selector instead — see "NODUS in the
asset list (0.1.21)". Until 0.1.22 the receive address sat at the bottom of the
asset list and sending had its own panel; since 0.1.22 both are one panel — see
"Send and receive in one panel, QR codes, third-party licenses (0.1.22)".) The
Send and Receive shortcuts bring the send or receive block of that panel into
view without submitting a transfer. The selected network appears beside both flows; unrequested or failed balance reads are not
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
phrase. The native coin is **NODUS**. Switching to another network never changes
the native address. Copy is available only after derivation succeeds;
lock clears the address and cancels pending work. This release displays the
address only: no native balance, sending, registration or claim is implied.
Since 0.1.21 the address is shown in the receive block (since 0.1.22 part of the
Send / Receive panel, with a QR code) when Nodus (the first, default-selected
network) is selected, and copied with the shared Copy button, instead of in a
separate panel.

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

`npm audit --json` on 2026-09-19 reports **0 vulnerabilities** across all severities; the recorded result is `test/fixtures/dependency-audit.json`. Since 0.1.23 the Solana path runs on `@solana/kit` 8.3.0 with the generated `@solana-program/system` 0.14.1 and `@solana-program/token` 0.16.1 instruction clients (all exact pins); `@solana/web3.js` and its scoped Jayson 5.0.0 override are gone — see "Solana on @solana/kit, no LGPL dependency (0.1.23)". Legacy `@solana/spl-token` and its vulnerable `bigint-buffer` tree were removed earlier in favor of `@solana-program/token`; golden prior-SPL instruction bytes/account roles, ATA derivation, rejection of substituted source accounts and signed native/SPL RPC flows are regression-tested. `npm audit` on the 0.1.23 lockfile (2026-09-25) reports 0 vulnerabilities; the recorded 2026-09-19 fixture above predates it. No advisory is suppressed and `npm audit fix --force` was not used. A zero-advisory result is not a security audit or assurance against unknown vulnerabilities. The large chain-library bundle warning remains (app chunk ~1.26 MB before gzip in 0.1.23, ~1.42 MB in 0.1.22).

## Source layout

- `src/config.js`: permanent mainnet/token registry, browser RPC defaults, full Solana genesis hash, and the temporary read-only `CELLFRAME` network definition (name/symbol/decimals/endpoint, `icon`, `receiveOnly: true`; kept out of the sendable `CHAINS` registry). Every `CHAINS` entry and `CELLFRAME` carry an explicit `icon` file name (0.1.14) so `src/portfolio-view.js` never guesses one from the symbol.
- `src/keys.js`: local 24-word generation, recovery and external-chain derivation.
- `src/nodus/`, `crypto/nodus-*.c`, `scripts/build-nodus-*.sh`: permanent native Nodus address derivation and native compatibility verifier; `src/nodus/network.js` (0.1.21) is the receive-only Nodus network entry listed first in the wallet (no endpoint, `balanceUnavailable`).
- `src/core.js`, `src/rpc-transport.js`: exact units, bounded JSON/stream parsing and shared timeout-limited transport for direct RPC plus Ethers, Solana and TRON SDK calls.
- `src/wallet.js`: common adapter routing and single-use transfer review.
- `src/adapters/{evm,solana,tron}.js`: permanent balance and send adapters.
- `src/adapters/cpunk.js`, `src/cpunk-protocol.js`: isolated temporary public balance adapter and bounded protocol parser, called from `src/app.js`'s portfolio wiring like the permanent chain adapters (0.1.13: no longer a separate manual-entry panel).
- `src/cpunk/`, `crypto/cpunk-wasm.c`, `crypto/native-vector.c`, `scripts/build-native-vector.sh`, `scripts/build-cpunk-wasm.sh`: temporary legacy Cellframe address derivation, native reference bridge and reproducible build.
- `src/activity.js`, `src/activity-storage.js`: public confirmation tracking and bounded, authenticated encrypted activity storage.
- `src/vault.js`: optional authenticated local encryption.
- `src/app.js`, `index.html`, `src/style.css`: accountless responsive UI.
- `src/wallet-extensions.js`, `src/site-lock.js`, `src/connect-main.js`, `connect-site/index.html`, `vite.connect.config.js`, `src/connect/ui/`: the Nodus Connect site build and the cross-site rule (section "Nodus Connect site" below).
- `src/qr.js` (0.1.22): draws the receive-address QR code as SVG DOM nodes with `qrcode-generator`; `src/app.js` `setReceiveAddress()` is the only writer of the address text and its QR.
- `scripts/third-party-licenses.mjs`, `vite.config.js` (0.1.22): collect the license notice of every npm package rendered into the bundle and write `dist/THIRD-PARTY-LICENSES.txt`; the build fails for a bundled package with no license field and no license file.
- `test/`: offline and fully intercepted browser verification.

## Connect-compatible Cellframe address derivation

Open or restore your Nodus wallet: the Cellframe (CPUNK) address derives automatically in the browser, right alongside the Nodus address, with no separate panel or button (0.1.13). Select **Cellframe** from the network list (or click its row in the asset list) to see it, with its QR code, in the receive block of the Send / Receive panel; reading the derived public balance for the portfolio's CPUNK row is a separate, automatic step that starts once the address is ready. This mode accepts the same normalized, checksum-valid English BIP39 phrase as the multichain wallet. Arbitrary non-BIP39 Cellframe strings are not supported; there is no field to paste one. No recovery phrase is sent to the RPC.

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

Solana uses an application-owned mutable 64-byte `secretKey` buffer (seed ‖ public key, `src/keys.js`), which is overwritten on lock. Signing reads its first 32 bytes in place with `@noble/curves` Ed25519 (`src/adapters/solana.js`); the SDK's own WebCrypto key-pair signers, whose keys cannot be overwritten, are not used. JavaScript, cryptographic-library temporaries and immutable strings still cannot provide guaranteed physical-memory erasure.

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
  (`src/ixios/balance.js`): network identity first — block 1's `parentHash`
  must equal Ixios mainnet genesis `0xa19acef5…2f2f` (ixiosSpark
  `params/config.go:27`; never `eth_chainId`, which is 1 on both Ixios and
  Ethereum) — then `eth_getBalance`. **0.1.19 fix:** 0.1.18 read block 0, whose
  ~215 KB `extraData` string exceeds the transport's 65 536-character cap, so
  every live read failed ("Balance unavailable"); block 1 is ~1.6 KB. Verified
  2026-09-23 against the live Ixios RPC (balance read) and an Ethereum RPC
  (rejected as the wrong network). A wrong network or a failed read shows the shared
  "Balance unavailable" state. IXIOS stays unpriced and outside the USD total.
- The send note matches Cellframe's style: "Sending IXIOS is not available in
  this release. The Ixios network does not accept this address type yet."
- Note: on 2026-09-23 the Ixios mainnet (validators on ixiosSpark 1.0.3, RPC
  1.0.5) has no Q-address support, so the balance shown is 0.
- Tests mock the Ixios RPC (`test/portfolio-routes.js` `ixiosRead`,
  `test/ixios-balance.test.js`); `browser-nodus.js` now routes Ixios reads to
  that mock instead of counting them as unexpected requests.
- Live note (2026-09-23): browsers cannot read `ixios-rpc.innova.limited` yet —
  its POST responses carry `Access-Control-Allow-Origin: *` twice, which Chromium
  rejects ("multiple values '*, *'"); the row shows "Balance unavailable" until
  Ixios fixes the header. No client-side workaround (a relay would break the
  no-backend design).

## One open wallet per browser (0.1.20)

Operator decision `docs/plans/decisions/2026-09-23-web-wallet-single-tab.md`
closes the cross-tab record-loss issue (`SECURITY-FOLLOWUP.md`). Opening a wallet
(restore, create after verification, unlock) first takes the exclusive Web Lock
`nodus.wallet.session` (`ifAvailable`); no key is derived and no password KDF runs
before the lock is granted. The tab holds it until Lock, idle timeout or page
exit; the browser releases it if the tab closes or crashes (no timers or storage
flags). A second tab is refused with "Wallet is open in another tab." and
"Use it here instead", which takes the lock with `steal`; the first tab locks
itself and says "Wallet was opened in another tab. This tab was locked." The
activity write lock `nodus.wallet.storage` is unchanged. Covered by
`test/browser-security.js` (refuse / take over / reopen after close) and
`test/browser-smoke.js` (hold, release, failed unlock gives the lock back).

## NODUS in the asset list (0.1.21)

The separate Nodus address panel above the assets is gone (operator,
2026-09-25: NODUS belongs where the other coins are, first in every list; the
deferred first request in `docs/plans/decisions/2026-09-25-web-wallet-nodus-send-transport.md`).
The portfolio card now stands on its own.

- NODUS is a receive-only network (`src/nodus/network.js`), listed **first** in
  the network selector, the portfolio health badges and filters, and the asset
  list (a NODUS row with the Nodus mark, `public/assets/coins/nodus.svg`, and
  only a Receive action). Because it is the first option, **Nodus is the network
  selected when the page loads**. Selecting it shows the locally derived Nodus
  address in the receive panel with its own status line ("Calculating your Nodus
  address locally…" / "Derived locally from this wallet’s recovery phrase." /
  "Nodus address unavailable. Lock and reopen your wallet to retry."), hides the
  send fields with the note "Sending NODUS is not available in this release.",
  and hides the account-explorer link and the network connection settings (Nodus
  has no RPC to choose). Nodus activity is empty. The shared Copy button says
  "Address not available yet." until derivation succeeds; lock clears the
  address and its status and cancels the derivation.
- **The NODUS balance is not shown yet.** No balance is read for it (no request
  to any host), and none is implied: the row says "Balance not shown yet", the
  badge "Nodus · Balance not shown yet", the amount "—" — never a read state, an
  error or a zero. NODUS is unpriced, outside the USD total and outside the
  "X of N" and "all balances included" counts; its row does not change the
  portfolio's idle/updating/complete state or the Refresh buttons.
- **No sending.** Nothing in this release sends NODUS, registers or claims
  anything. Balance and sending need the separate browser↔chain path described
  in the decision above; none of it is built here.
- `CHAINS` and the 14 priced `ASSETS` are unchanged. `createPortfolio` takes a
  `leadingNetworks` list (placed before `CHAINS`) next to `extraNetworks`; a
  network with `balanceUnavailable` is never read and its rows are reported
  `'unsupported'` by `portfolioSnapshot`.
- Tests: `test/portfolio.test.js` (an unsupported row keeps the state idle and
  stays out of totals and completeness; NODUS sorts first);
  `test/browser-smoke.js`, `test/browser-nodus.js`, `test/browser-ixios.js`,
  `test/browser-security.js` read the address through the receive panel with
  Nodus selected. **How these can lie:** the checks run against intercepted
  traffic and a fixture phrase; they prove no NODUS balance request is made by
  the portfolio code paths exercised, not that a future balance source is correct.

## Send and receive in one panel, QR codes, third-party licenses (0.1.22)

Operator, 2026-09-25: send and receive belong in one place, and the bundle must
carry the license notices of the packages it contains.

- **One Send / Receive panel.** The former "03 / Send assets" panel is now
  "03 / Send / Receive · <network>" (the heading follows the selected network
  through the existing `.selected-network-name` labels). The network selector
  `#chain` stays at the top for keyboard use. Below it, the **receive block**
  (moved out of the asset list, element ids unchanged: `#receive-panel`,
  `#receive-title`, `#receive-address`, `#copy-address`, the per-network status
  lines) now shows a QR code above the address; below that, the **send block**
  (`#send-block`, "Send on <network> · Mainnet") holds the send fields, or the
  receive-only note for Nodus, Cellframe and Ixios exactly as before. The Copy
  button stays `type="button"`, so it never submits the send form. The
  navigation link reads "Send / Receive"; the Send and Receive shortcuts focus
  the send or receive block of that panel.
- **Clicking a network row selects it.** In the expanded asset list, clicking a
  network row (outside its Send/Receive buttons) switches the panel to that
  network without moving focus; the network name is a button, so Enter/Space do
  the same from the keyboard. The selected network's rows are marked
  (`aria-current="true"`, class `selected`) and stay marked across the periodic
  re-render. On screens up to 900px wide, where the panel sits below the asset
  list, selecting a row scrolls the panel into view. The per-row Send/Receive
  buttons still select the network and focus the matching block.
- **QR = exactly the displayed address.** `src/qr.js` encodes the text of
  `#receive-address` itself — no URI scheme, no amount, no prefix — with
  qrcode-generator (error correction M, smallest version that fits) and draws it
  as SVG DOM nodes: a white background and one `<path>` of dark modules, 4-module
  quiet zone, `shape-rendering="crispEdges"`, `role="img"`,
  `aria-label="QR code for the receive address"`, 168px wide. No markup string,
  data URL, `innerHTML` or inline style is produced (the page CSP is
  `style-src 'self'`). `setReceiveAddress()` in `src/app.js` is the only writer
  of the address text, so the QR changes with it everywhere: network selection,
  the late Nodus / Cellframe / Ixios derivations, and lock (empty address ⇒ empty
  QR). Text that is not printable ASCII draws no QR, because the library's
  default byte encoder keeps only the low 8 bits of each character; every
  address this wallet shows is ASCII.
- **How QR correctness is tested.** `test/browser-smoke.js` serializes the drawn
  `<svg>`, renders it through an image onto a white canvas at 4 px per module,
  and decodes the pixels with jsQR (a dev dependency, run in Node because the
  page CSP blocks an injected inline script). The decoded text must equal the
  `#receive-address` text for Nodus, Ethereum, BNB Smart Chain, Solana and TRON;
  `test/browser-ixios.js` does the same for the checksummed Ixios address. The
  smoke test also checks that the QR is empty after lock and that the dashboard
  has no horizontal overflow at 320px and 390px with the QR visible. **How these
  can lie:** jsQR is a second implementation of the QR standard, not a phone
  camera; a code that jsQR reads could still be hard to scan on a low-quality
  screen, and the checks run only in headless Chromium.
- **Third-party licenses.** The 0.1.21 bundle carried no license notices although
  it bundles MIT, ISC, BSD and Apache-2.0 packages. A small build plugin in
  `vite.config.js` now passes every module rendered into the output (`modules` of
  each output chunk with `renderedLength > 0`) to
  `scripts/third-party-licenses.mjs`, which finds each module's owning npm
  package (nearest `package.json` with a name and version, nested `node_modules`
  and scoped packages included), deduplicates by name and version, and writes
  `dist/THIRD-PARTY-LICENSES.txt`: a header, the pointer to the font license
  `assets/fonts/OFL.txt`, then per package "name@version — license" and the full
  text of its LICENSE / LICENCE / COPYING files, sorted by name. The footer links
  it as "Licenses". **The build fails, naming the package, if a bundled package
  has neither a license field nor a license file.** A package with a license field
  but no license file is listed with "(no license file in package; license field
  only)"; in 0.1.22 that applies to `@solana-program/token`, `bs58` and
  `qrcode-generator`. Only npm packages are covered: Vite's own small runtime
  helpers (virtual modules `\0vite/preload-helper.js`,
  `\0vite/modulepreload-polyfill.js`), the @rollup/plugin-commonjs helpers
  (`\0commonjsHelpers.js`, applied through Vite's bundled copy) and the WASM modules built from this repository's C
  code are not listed. `test/licenses.test.js` runs the resolver on real
  `node_modules` files and on synthetic packages (nested copy; no license at all
  ⇒ error). Reviewing the licenses in the list is a separate step.
- **Full license texts (appendix).** Some packages only refer to a license text
  they do not ship. When a bundled package's license expression contains
  `LGPL-3.0`, the file ends with an "Appendix: full license texts" section holding
  the full LGPL-3.0 text and the GPL-3.0 text (LGPL-3.0 incorporates GPL-3.0 by
  reference); when it contains `Apache-2.0` and none of the package's own license
  files contains the Apache terms, the Apache-2.0 text is appended too. Each text
  appears once however many packages need it, and every entry that relies on one
  ends with "full text: see Appendix — <license>". In 0.1.22: `rpc-websockets`
  (LGPL-3.0-only; its own LICENSE, a copyright line and a pointer to gnu.org, is
  kept above the reference) and `@solana-program/token` (Apache-2.0, no license
  file). The texts live in `licenses/` (`LGPL-3.0.txt`, `GPL-3.0.txt`,
  `Apache-2.0.txt`): byte-for-byte copies of this machine's Debian
  `/usr/share/common-licenses/{LGPL-3,GPL-3,Apache-2.0}` (package `base-files`
  12.4+deb12u15); `licenses/SOURCES.txt` records each source path, the owning
  Debian package and version, and the SHA-256. `test/licenses.test.js` checks the
  copies against the Debian originals when those files exist and says so when it
  skips.
- **Copyright lines for packages without a license file.** For a package with a
  license field but no license file, the generator takes the Copyright line(s)
  of the first comment block containing "Copyright", searching the package's
  `module` and `main` entry files first and then every other file in the package
  (sorted, binary files skipped), and prints each line verbatim followed by
  "(copyright line from <file>:<line>)". For such an MIT package it then adds the
  MIT permission paragraphs verbatim from the LICENSE file of the bundled
  top-level `@noble/hashes` (Debian ships no MIT text); the build fails if that
  package is not in the bundle. If no copyright line is found, the entry says
  "(no copyright line found in package files)" and the build prints a warning
  naming the package (not an error). In 0.1.22: `qrcode-generator` →
  `// Copyright (c) 2009 Kazuhiko Arase` (`dist/qrcode.mjs:5`); `bs58` 4.0.1 and
  `@solana-program/token` 0.16.1 have no copyright line in any of their files,
  so both are warned about.
- **Dependency pins.** `qrcode-generator` 2.0.4 (runtime, MIT;
  `sha512-mZSiP6RnbHl4xL2Ap5HfkjLnmxfKcPWpWe/c+5XxCuetEenqmNFf1FH/ftXPCtFG5/TDobjsjz6sSNL0Sr8Z9g==`)
  and `jsqr` 1.4.0 (dev only, Apache-2.0;
  `sha512-dxLob7q65Xg2DvstYkRpkYtmKm2sPJ9oFhrhmudT1dZvNFFTlroai3AWSpLey/w5vMcLBXRgOJsbXpdN9HzU/A==`),
  both exact versions. No other dependency changed.

## Solana on @solana/kit, no LGPL dependency (0.1.23)

Decision: `docs/plans/decisions/2026-09-25-web-wallet-solana-kit.md` (operator,
2026-09-25).

- **Why.** The 0.1.22 license list showed one LGPL package in the bundle:
  `rpc-websockets` 9.3.9 (LGPL-3.0-only), pulled in by `@solana/web3.js` 1.99.0
  (a static import; the wallet never opened a socket). LGPL-3.0 §4d (the user
  can relink a modified library) is not met by a single minified bundle. The
  Solana path now uses `@solana/kit` 8.3.0 (MIT), `@solana-program/system`
  0.14.1 and `@solana-program/token` 0.16.1 (Apache-2.0), all exact pins, plus
  `@solana/rpc-spec-types` 8.3.0 (MIT, already in kit's tree) pinned directly for
  its bigint-preserving JSON helpers. `@solana/web3.js` and its Jayson 5.0.0
  override are removed.
- **What changed.** `src/keys.js:37` stores the Solana address as a base58 string
  (kit `Address`) instead of a web3.js `PublicKey`; the 64-byte `secretKey`
  buffer and its wipe on lock (`src/keys.js:35-38, 47`) are unchanged.
  `src/adapters/solana.js` builds a legacy (non-versioned) transaction message
  with kit (`createTransactionMessage({ version: 'legacy' })`, fee payer, blockhash
  lifetime, instructions), compiles it once, sends those message bytes to
  `getFeeForMessage`, and signs the same bytes at send time. The native transfer
  comes from `@solana-program/system` `getTransferSolInstruction`; the token
  instructions from `@solana-program/token` as before, now used directly without
  a conversion to web3.js objects (`src/adapters/solana-token.js`). Every guard
  of the send path stays: address check (`Invalid Solana address.` — web3.js
  said `Invalid public key input`), genesis check, u64 amount bound, only the
  wallet's own associated token account as source, token account owner / mint /
  state / decimals checks, balance ≥ amount + fee + rent, expiry against block
  height, lock checks before signing and after the activity write, one broadcast
  with `maxRetries: 0` and preflight on, returned-ID match. kit returns RPC
  integers as `bigint`; the adapter rejects any fee, balance, rent, block height
  or `lastValidBlockHeight` that is not a non-negative bigint, and the blockhash
  must have a 32-byte base58 shape (`src/adapters/solana.js:66-68`). The
  recipient token account lookup (`getAccountInfo`) counts as "absent" only for a
  well-formed `{ value: null }` and as "present" only for a well-formed account
  object; any other reply stops the send with `RPC returned an invalid recipient
  token account.` (`src/adapters/solana.js:57-64, 120-122`) — web3.js's
  response validation rejected such replies too.
  `lastValidBlockHeight` is handed to activity tracking as a Number, as before.
  kit's production error texts ("Solana error #…; Decode this error by running
  npx …") never reach the UI: RPC errors become `RPC rejected …` text
  (`src/adapters/solana.js:32-38`), and errors from building, compiling, signing
  or encoding the transaction become `Invalid Solana transaction …` text
  (`src/adapters/solana.js:42-54`); a recipient that is a program address (for
  example SOL sent to the System Program address) reads `Invalid Solana
  transaction: the recipient is a program address and cannot receive this
  transfer.`
- **Behaviour changes beyond the SDK swap.**
  - The signature check and the 1232-byte size check (web3.js did both inside
    `serialize()`, i.e. just before broadcast, after the activity record was
    written) now run at signing time, before `onBroadcast` writes the activity
    record (`src/adapters/solana.js:147-149`). A transaction that fails either
    check is therefore never recorded.
  - New guard `Unexpected Solana transaction signers.`: the compiled transaction
    must require exactly one signature, the wallet's (`src/adapters/solana.js:74`).
  - web3.js checked the JSON-RPC reply shape: `jsonrpc` must be `'2.0'` and `id`
    must be a string, with `result` or `error` (`createRpcResult`,
    `@solana/web3.js/lib/index.browser.esm.js:3967-3977` in 1.99.0). kit reads
    `error`/`result` and checks neither `jsonrpc` nor `id`. Jayson never matched
    the reply id to the request either. The adapter's transport only rejects a reply that is
    not a JSON object (`src/adapters/solana.js:26`).
  - If `getMinimumBalanceForRentExemption` returns an RPC error, the send stops;
    web3.js returned 0 rent and continued.
- **Signing stays noble over the raw buffer.** kit's key-pair signers hold the
  Ed25519 key as a non-extractable WebCrypto key that lock cannot overwrite, so
  they are not used. `src/adapters/solana.js:72-85` signs the compiled message
  with `ed25519.sign(message, secretKey.subarray(0, 32))` — the call web3.js
  1.99.0 made (`ed25519.sign(message, secretKey.slice(0, 32))`). The wallet no
  longer makes web3.js's `.slice(0, 32)` copy of the seed; `@noble/curves` still
  copies the key internally while signing (`Uint8Array.from` in its
  `ensureBytes`, `node_modules/@noble/curves/esm/utils.js:86`), and those
  temporaries are not wiped. It then, like web3.js `serialize()`, verifies the
  signature against the fee payer's key and refuses a transaction over the
  1232-byte limit. The recipient on-curve check keeps web3.js's exact test,
  `ed25519.ExtendedPoint.fromHex` on the 32 address bytes
  (`src/adapters/solana-token.js:8`).
- **Transport keeps the rpc-transport.js protections.** kit's default HTTP
  transport calls the global `fetch` and accepts no custom one. The adapter
  builds kit's RPC from its own transport (`createSolanaRpcFromTransport`,
  `src/adapters/solana.js:21-29`) that posts through `rpcFetch`, so the response
  size limit, stream bound, JSON shape check, 15 s timeout, no-redirect /
  no-credentials request and the public endpoint's read pacing all still apply;
  bodies are serialized and parsed with kit's bigint-preserving JSON helpers.
  kit adds `commitment: 'confirmed'` (`preflightCommitment` for
  `sendTransaction`) by default, which is what web3.js sent.
- **Parity proof.** Before any source change, `scripts/make-solana-parity-fixture.mjs`
  ran once against the 0.1.22 web3.js code with every RPC response stubbed to a
  fixed value (no network) and wrote `test/fixtures/solana-kit-parity.json` for
  three sends by the public test phrase: a SOL transfer, a USDC transfer to an
  existing associated account, and a USDC transfer that creates it. For each it
  recorded the JSON-RPC method and params of every request in order, the fee
  estimate message, the broadcast wire bytes, the message bytes, the signature,
  the fee text and the broadcast details. `test/solana-kit-parity.test.js`
  replays the same responses into the kit code and requires identical request
  sequences and params, byte-identical wire transactions, messages and
  signatures (Ed25519 is deterministic), the same fee text and the same
  broadcast details; it also checks the fixture on its own (fee message = sent
  message, signature verifies under the wallet key). **Provenance:** the
  fixture's `source` field is a constant the generator always writes, so it
  proves nothing about which code produced the file. Provenance was proven
  separately (orchestrator, 2026-09-25): the generator was re-run on the
  pre-migration tree (`git archive 84f331f3` with `@solana/web3.js` 1.99.0 in
  `node_modules`) and its output compared byte-for-byte (`cmp`) with the
  committed fixture — identical. **How it can lie:** re-running the generator on
  the kit code rewrites the reference from the code under test, and the test
  then compares the code with itself. Both paths run in Node with stubbed
  replies; a real RPC's reply shapes and a funded mainnet transfer are not
  covered.
- **Removed from the bundle** (`dist/THIRD-PARTY-LICENSES.txt`, 0.1.22 → 0.1.23):
  `rpc-websockets` 9.3.9 (LGPL-3.0-only), `@solana/web3.js` 1.99.0,
  `@solana/buffer-layout` 4.0.1, `@solana/codecs-core` / `codecs-numbers` /
  `errors` 5.5.1 (web3.js's older copies), `base-x` 3.0.11, `bn.js` 5.2.5,
  `borsh` 0.7.0, `bs58` 4.0.1, `eventemitter3` 5.0.4, `jayson` 5.0.0,
  `safe-buffer` 5.2.1, `superstruct` 2.0.2, `text-encoding-utf-8` 1.0.2.
  **Added:** `@solana-program/system` 0.14.1 (Apache-2.0) and the kit 8.3.0
  packages `@solana/functional`, `promises`, `rpc`, `rpc-api`, `rpc-spec`,
  `rpc-spec-types`, `rpc-transformers`, `rpc-types`, `subscribable`,
  `transaction-messages`, `transactions` (MIT). No package in the list declares
  an LGPL or GPL license, so the file carries no LGPL/GPL text (the appendix
  keeps Apache-2.0 for the two `@solana-program` packages, which ship no license
  file and no copyright line; the build warns about both). `npm ls` finds no
  `rpc-websockets`, `@solana/web3.js` or `jayson`.
- **Size.** 0.1.22 release build vs the 0.1.23 `VITE_ENABLE_IXIOS=true` build
  (the variant with the same chunk set): app chunk 1,417,995 → 1,256,428 bytes,
  all JavaScript chunks 1,477,466 → 1,315,743 bytes. The default build's app
  chunk is 1,254,356 bytes.

## NODUS send skeleton — wallet side only, inert until the module exists (unreleased)

Design: `docs/plans/2026-09-25-web-wallet-nodus-send-design.md` (package (d),
§1.4, §1.5); decisions `2026-09-25-web-wallet-nodus-send-transport.md`,
`2026-09-23-web-wallet-mldsa-hedged-signing.md` (its İSTİSNA 1/2),
`2026-09-23-web-wallet-single-tab.md`; binding note
`docs/plans/2026-09-26-note-to-web-wallet-session-expiry.md`. This is
everything on the wallet side that can be built and tested before the browser
module (package (c3): nodus tier-2 client + SPEND builder compiled C→WASM)
exists. **Nothing about NODUS changes on the live site with this code**: the
module's registration point `src/nodus/send-module.js` exports `null`, and with
`null` no client is created, NODUS stays receive-only with "Balance not shown
yet", and the "Sending NODUS is not available in this release." note stays
(everything in "NODUS in the asset list (0.1.21)" above still holds).

What is in place:

- **CSP** (`index.html`): `connect-src 'self' https: wss:` — `https:` does not
  cover `wss:`, so without this the page could never open the module's
  WebSocket. The generic `wss:` scheme (any host) is the design's open
  question §5 item 15 (narrow it to the build's validator IPs or not); today it
  permits a connection nothing in the page makes.
- **Module loader** (`src/nodus/client.js`). The JS contract (c3)'s glue must
  implement is written at the top of that file: asynchronous `unlock`,
  `balance`, `list`, `buildAndSign`, `submit`, `scanConfirm`, `tick`;
  synchronous `cancel`, `lock`, `release`; `memory`. Amounts and heights cross
  the boundary as decimal integer strings of raw units (1 NODUS = 10^8) and are
  `BigInt` in JS. Rules it enforces:
  - **One operation queue.** Asyncify has a single global `currData`, so a
    second export entered while the first is suspended would corrupt it. Every
    call waits until the previous module call has actually returned; a caller
    that aborts before its call started leaves the queue; keepalives never pile
    up (at most one queued).
  - **Lock order:** stop the queue (queued and in-flight callers get "Wallet is
    locked.") → `cancel()` (C cancel flag) → `lock()` (WebSocket closed) → the
    whole linear memory zeroed (`derive.js` pattern) → `release()` (must make any
    pending Asyncify wake-up a no-op). Each step runs even if an earlier one
    throws. Locking while the module is still loading wipes and drops it.
  - **Identity check:** `unlock` gets the signing seed (`nodusSigningSeed` in
    `src/nodus/derive.js`, now shared with the address derivation, unchanged
    bytes); the JS copy is zeroed afterwards. The fingerprint the module reports
    must equal the address this wallet derived, and the chain id must be 32
    bytes of hex, or the module is wiped and never becomes ready.
  - **Keepalive:** a `tick()` through the queue every 60 s (the server closes
    an idle tier-2 session at 180 s); a failed tick takes the client out of
    `ready`.
- **NODUS adapter** (`src/adapters/nodus.js`, `adapters.nodus` in
  `src/wallet.js`):
  - Recipient: a 128-hex fingerprint (upper case accepted, shown lower case).
    There is no checksum, so the review shows all 128 characters with a
    compare-every-character note. Amount: 8 decimals, `BigInt`, at most
    2^64 − 1 raw units.
  - Balance: the **spendable** native balance from `balance()` (the contract
    also carries `total`; `spendable > total` is rejected). Any failure is
    "Balance unavailable", never 0. Unpriced, outside the USD total.
  - Building: `balance()` then `list()`. Tip 0 or missing → **no send** ("The
    current Nodus block height is unknown"); otherwise `expiry_height = tip + 90`
    (`nodus-cli.c` `CLI_ENV_EXPIRY_AHEAD` = 100 − 10). An empty coin list with a
    positive spendable balance is reported as "coin list could not be read",
    never "insufficient". Coins held by pending sends are removed from the
    candidate list given to the builder.
  - **Review = the signed envelope (G1).** Recipient, amount, fee, change,
    expiry block and chain id on the review screen come from the module's
    decoding of the envelope it signed; if recipient, amount, expiry or chain id
    differ from the request, or an input is not a candidate coin, nothing is
    shown or sent. The review also says the fee may be charged even if the
    transfer fails.
  - **Pending send:** the activity record (encrypted activity, like the other
    networks) stores the intent_id (as the record's transaction ID), the
    expiry block, the first block to scan, and the input nullifiers; it is
    written before the envelope leaves the browser. Status comes from
    `scanConfirm` (blocks first-to-expiry for the intent_id): included →
    `confirmed`; chain past the expiry block and not found → `expired`;
    otherwise `pending`. The answer comes from one node (design §5 item 16).
    NODUS rows have no explorer link and no "Mark as abandoned" button.
  - **Resend rule** (note item 3): a send's coins stay locked in every status
    except `expired` (which only a scan sets); a resend before that must use the
    same coins (`resendInputs`), so at most one of the two can ever be applied.
- **Portfolio**: `createPortfolio` gained `setNetwork(chain, network)` so NODUS
  can switch between the receive-only and sendable definitions
  (`nodusNetworkFor` in `src/nodus/network.js`) without a reload.

Tests: `test/nodus-send.test.js` against the TEST-ONLY mock module
`test/nodus-mock-module.js` — no-module gating, unlock identity check and seed
wipe, 60 s tick, queue serialization (the mock flags any overlapping call),
exact lock order with the memory zero at `release()`, expiry and tip-0 refusal,
input rules, review-from-envelope with seven tamper cases, the pending record
written before submit and surviving the encrypted activity round trip, the
resend/lock rule, the scan mapping and the balance rules. **How these can lie:**
the mock returns canned data and echoes the request as its "decoded" envelope;
they prove the wallet-side discipline only — not the (c3) module, its envelope
decoding, the chain, or the browser wiring in `src/app.js` (no browser test
covers a ready module, because none exists).

Still missing before anyone can send NODUS from the web wallet:

- The network settings of the module (next section): chain id, validator key
  pins, WebSocket endpoints.
- Package (f) — WebSocket entry (Caddy + IP certificate) on the nodes; server
  discovery from the roster and the pinned validator key list.
- `test/browser-nodus.js` for the sendable mode, and a localhost end-to-end
  send (design §0a.3 step 6).
- Pending sends of a **temporary** (unsaved) wallet live only in the tab: after
  lock, their coins are no longer known to be held, so a different-coin send
  before the first one's expiry block can pay twice. Saved wallets keep them in
  the encrypted activity.
- A resend button (the rule and `resendInputs` exist; no UI calls them), the
  portfolio scope text for a readable NODUS balance, and the version bump.

## NODUS send module — C→WASM, built, not enabled (unreleased)

Design: `docs/plans/2026-09-25-web-wallet-nodus-send-design.md` package (c3)
(§0a.3, §1.3–§1.5, §2 test plan item 2). Decisions:
`2026-09-25-web-wallet-nodus-send-transport.md` (same C builder as nodus-cli,
session open until lock, one thread, generated ruleset pins "Yol 2", pinned
client ML-KEM-1024 only), `2026-09-23-web-wallet-mldsa-hedged-signing.md`
İSTİSNA 1/2, `2026-09-25-mempool-policy.md`, `2026-09-25-gas-price.md`.

Files: `crypto/nodus-send-wasm.c` (entry points), `scripts/build-nodus-send-wasm.sh`
→ `src/nodus/send.wasm` + `src/nodus/send.js` (Emscripten glue, generated),
`src/nodus/send-module.js` (the `src/nodus/client.js` contract on top of the
glue), `crypto/nodus-send-native-vector.c` + `scripts/build-nodus-send-native-vector.sh`
(parity vector), `test/nodus-send-wasm.test.js`.

**Not enabled:** `NODUS_SEND_NETWORK` in `src/nodus/send-module.js` is `null`,
so `nodusSendModuleFactory` is `null` and nothing on the live site changes. It
takes the testnet chain id (64 hex), the accepted validators' key fingerprints
(128 hex each, SHA3-512 of the ML-DSA-87 public key) and their WebSocket
endpoints (IPv4 + port; `wss`, or `ws` only for `127.0.0.1`). None of these is
in this tree; they come from the operator once the nodes' WebSocket entries
are open (package (f)).

What the module does (every chain rule is the shared C code, not this wallet):

- **unlock** — ML-DSA-87 identity from the 32-byte signing seed
  (`nodus_identity_from_seed`; the module's copy of the seed is wiped), the
  generated ruleset pins rebuilt and checked against their digest, a tier-2
  session to the first endpoint that passes the server-key pin (fail-closed,
  ML-KEM-1024 only — `nodus_client_config_t.pinned_server_fps`), and the
  node's chain id (`dnac_supply` `chain_id32`) compared with the configured
  one. Another chain = no session.
- **balance** — `dnac_balance` for the wallet's own fingerprint, native token
  row only; a read error is an error, never 0.
- **list** — `dnac_utxo`: native, non-zero, `unlock_block <= tip` coins (the
  nodus-cli filter); the tip is passed through (the wallet refuses 0); a row of
  another owner or a repeated coin rejects the whole answer.
- **buildAndSign** — only coins of the last listing; `expiryHeight` must be
  exactly listing tip + 90; the chain id is re-read on the session;
  `gas_price` from `dnac_fee_info` (a failed read refuses); then nodus-cli's
  request for one native spend (fee floor `max(DNAC_MIN_FEE_RAW,
  NODUS_W_BASE_TX_FEE)`, largest-first, no shard) through
  `nodus_v2_spend_plan` / `nodus_v2_spend_build`. The review fields come from
  the builder's read-back of the envelope bytes and are checked again here:
  output 0 = recipient/amount/native, every other output = the sender (their
  sum = change), inputs from the candidates, inputs = amount + fee + change.
  The chain id is not a field of the envelope; it is the one the preflight bound
  into the envelope's ids (self-consistent, design §1.4).
- **submit** — only the envelope built last, byte for byte; `dnac_spend` with
  `wire_id` signed as nodus-cli does (`t6_submit_on`). The answer is mempool
  CheckTx only.
- **scanConfirm** — `dnac_v3_block` pages from `fromHeight` to min(tip,
  `toHeight`) (span ≤ 100) for an applied envelope with the intent_id; any
  unread height is an error, not "not found". Heights already read fully are
  remembered per intent for the session (committed blocks are final).
- **tick** — `nodus_client_tick` (60 s keepalive and the pinned reconnect);
  operations refuse while reconnecting and re-check the chain id after a
  reconnect to another server.
- **cancel / lock** — synchronous: a terminal flag; the socket is closed
  (`nodus_client_force_disconnect` if an operation is suspended, else
  `nodus_client_close`); identity, seed, built envelope and listing wiped.
  **release** aborts the instance (Emscripten `ABORT`) so no suspended wait
  resumes.

Randomness: one function, `qgp_platform_random` in `crypto/nodus-send-wasm.c`,
serves every draw (`nodus_random`, `qgp_randombytes` → hedged ML-DSA `rnd`,
ML-KEM coins, output seeds). In the shipped build it is `getentropy()`, which
Emscripten 6.0.10 routes to `crypto.getRandomValues` (musl
`src/misc/getentropy.c` → `__wasi_random_get` → `libwasi.js` `random_get`).
`-DNODUS_SEND_TEST_FIXED_RANDOM` replaces it with caller-loaded bytes; it
exists only in the native vector and the `parity` wasm builds, and cannot be
compiled together with `-DNODUS_SEND_RELEASE` (`#error`).

Build (Emscripten **6.0.10** exactly — the version the linked OpenSSL
3.0.15 `libcrypto.a` is built with; the script refuses any other):

```bash
scripts/build-openssl-wasm.sh              # once: ~/wasm-deps/openssl-3.0.15-wasm
scripts/build-nodus-send-wasm.sh           # -> src/nodus/send.wasm + send.js
scripts/build-nodus-send-native-vector.sh  # -> /tmp/nodus-send-native-vector
NODUS_SEND_PARITY_OUT=/tmp/nodus-send-parity scripts/build-nodus-send-wasm.sh parity
NODUS_SEND_PARITY_OUT=/tmp/nodus-send-parity NODUS_SEND_VECTOR_BIN=/tmp/nodus-send-native-vector \
  node --test test/nodus-send-wasm.test.js
```

`ASYNCIFY_STACK_SIZE` is 16384: a static bound (not a run-time measurement)
from the disassembly of the same link with names kept — the heaviest chain
from an export to `emscripten_sleep` is 380 bytes counting every local; the
derivation is in the build script.

Tests (`test/nodus-send-wasm.test.js`): always — the shipped `send.wasm` has
every entry point and no test-only one, draws randomness through WASI
`random_get`, the factory stays `null` without network settings, and the
settings validator's accept/refuse matrix. With the parity builds — the TEST
wasm and the native vector produce the same envelope byte for byte, and the
shipped-flags wasm (hedged signature) the same intent_id with a different
wire_id. **How these can lie:** the parity inputs are synthetic (made-up coins
and chain id), so they prove the builds agree with each other, not that a node
accepts the envelope; the hedged-signature test loads the shipped `send.wasm`
bytes (checked equal to the parity build's `send-node.wasm`) through node glue,
not the shipped web glue; without the two environment variables the parity
tests are skipped, and a skip is not a pass. Nothing here opens a session: unlock / balance / list / submit / scan /
tick are exercised only by a localhost harness run (design §0a.3 step 6).

Known gaps: the third-party notice (`dist/THIRD-PARTY-LICENSES.txt`) lists npm
packages only; `send.wasm` carries OpenSSL 3.0.15 (Apache-2.0) and the
Emscripten runtime/libc, which need their own entry before the module is
released. The Asyncify single-thread spike (design §1.3) ran on Emscripten
4.0.16; this module is built with 6.0.10 and has not been run in a browser.

## Nodus Connect thin core — NC-2 (unreleased, no UI, not wired)

Messaging core for the web (design `docs/plans/2026-09-24-web-connect-design.md`
rev 5, package NC-2; decision `2026-09-30-nodus-connect-thin-core.md`). Nothing
here is loaded by the wallet; the Messages UI and the shared module are NC-4.

- `connect/` — C library (`nc_core.h` documents every rule): the three-outcome
  read (found / empty / unreadable; "unreadable" never leads to a write), own
  profile read + update (EXCLUSIVE, "address taken" on `KEY_OWNED`; a record is
  created only for words generated in this session), contact requests (send,
  the app's ACCEPT round trip, cancel, fetch), per-contact salt read + the
  native reconcile choice + the gated publish (NC-1b: packet v1, the app's own
  builder), the own contact list (NC-1b, R4: read, and merge-only add — never
  fewer entries; the first list only for words generated in this session),
  the 1:1 daily outbox (send whole-day blob, fetch one day with the
  authorship gate) and delivery ACKs, and the embedded server list
  (`nodus-connect-servers` v1, entries carry a `kind`). Wire bytes come from
  `messenger/codec/`, `messenger/dna_api.c` and
  `messenger/dht/client/dna_profile.c`, compiled verbatim — no byte layout is
  reproduced in the core (NC-1b moved the last four inline sequences — ACK
  value, contact-request signing preimage, salt packet build, contact-list
  `CLST` blob — into `messenger/codec/`, and the app calls the same
  functions).
- `connect/nc_wasm.c` — the JSON exports. Since NC-4b (below) they are
  linked into `send.wasm`; the standalone test build of NC-2 is retired.
- `src/connect/core.js` — JS glue: `(generation, requestId)` on every
  result; since NC-4b it runs in the wallet's queue (below). API listed at
  the top of the file.
- `connect/tests/` — native tests (CMake, same compile set): classifier
  matrix, wire bytes vs the codecs' own verify (requests signed over the
  codec's preimage, salt packet v1, contact-list blob read the way the app's
  fetch does), R0 fault matrix against a fake node (timeout, empty, bad
  signature, wrong owner, undecodable → no PUT) including the contact-list
  and salt write gates.

RT1 fixes (unreleased). Profiles (own and a contact's) are read with get-all
filtered to the profile's owner, not with a single GET: a node's single GET
returns the newest row of ANY writer unless an EXCLUSIVE row exists, so a
stranger's newer row at `<fp>:profile` used to hide the real profile and the
web waited forever. The owner's row is chosen (EXCLUSIVE first, then newest);
rows of other writers are never used and are counted (`foreign` in
`nc_profile_get` / `nc_profile_update`) so the page can say someone is
interfering; a stranger's row alone is still "unreadable" (no write), and an
item that does not decode next to the owner's row makes the read
"unreadable" too. Salt packets are bound to the pair: a packet is used only
if its two entries are exactly this identity and the contact
(`nc_salt_packet_check`); a packet this identity signed for someone else and
replayed at this pair's key is dropped and counted (`wrong_pair`).

Paged owner-filtered reads (unreleased; needs nodus 0.23.6 — DHT Package A).
Every get-all of the core is now paged (`nodus_client_get_all_page_strict`):
the profile, the contact list, the outbox day bucket and the ACK are read
with the node's owner filter (`own` = the record's owner), the salt with one
paging loop per party, the request inbox with one loop over every writer.
A stranger's large rows at someone's key therefore no longer make the
node's whole-key answer too big to send (`nodus/BUGS.md` "DHT get_all"
F1). The read rule is unchanged: rows of another owner or key, bad
signatures and items that do not decode are still counted and still make
the read "unreadable" where they did before (the client does not trust the
node to have filtered). New: a loop reads at most `NC_READ_MAX_PAGES` (8)
pages of ≤ 2 MiB; an owner-filtered read with pages left is "unreadable"
with why `too_large` (no write); the request inbox keeps what it read and
reports `truncated` (`nc_requests_get`); a node that predates paging and
answers empty is "unreadable" (`node_error`), never "empty"; a node that
could not look (error 21) is `node_error`.

Not in NC-2/NC-1b: removing a contact from the list (add is merge-only);
at-rest storage (Q4, NC-4). The json-c version of the frozen app build is not
established (host 0.16, wasm 0.17); the profile signature is over json-c's
output, so this is checked before release (NC-3).

## Nodus Connect Messages preview — NC-4c (unreleased, separate build)

The Messages page under `/preview/` (design `docs/plans/2026-09-24-web-connect-design.md`
rev 5 §1.7-§1.10, package NC-4; decisions `2026-09-30-nodus-connect-thin-core.md`
incl. Ek / Ek 2 and `2026-09-30-connect-history-at-rest.md` rev 2). First stage
only: contact list, send / accept / decline / withdraw contact requests, 1:1
text messages, editing the own profile (about, location, https website; no
name, no avatar). No groups, media or calls. The live `/` build is unchanged.

- Build: `npm run build:preview` (`vite.preview.config.js`, root `preview/`,
  base `/preview/`, output `dist-preview/`, its own `THIRD-PARTY-LICENSES.txt`);
  `npm run preview:preview` serves it locally. `publicDir` is off and the page
  uses the system font stack and a `data:` icon, so it requests nothing outside
  `/preview/` except the node WebSockets. Response headers (CSP header,
  `frame-ancestors 'none'`) are the deploy package's job.
- `preview/index.html` + `src/connect/ui/` — `main.js` (entry; freezes ethers'
  RNG/KDF as `src/main.js` does), `standalone.js` (this page's unlock screens
  and lifecycle) and `messages.js` (Messages: views, sync; host-driven since
  the Nodus Connect site, see "Nodus Connect site" below), `messenger.css`,
  `dom.js` (every text through `textContent`; someone else's text in a `<bdi>`
  with an "unusual characters" marker), `text.js` (pure helpers), `style.css`.
- Opening: unlock the saved wallet (same vault, same password), type the 24
  words, or create a new account (words shown, typed back). Only the new-account
  words count as "fresh" (decision Q1): a restored identity never creates a
  record, and if its own profile cannot be read Messages stays closed with a
  retry. The page takes the wallet's single-tab lock `nodus.wallet.session`;
  it locks after 10 minutes without input, on Lock, on `pagehide`, and when the
  saved wallet changes in another tab.
- `src/connect/store.js` — history in IndexedDB, database named by the vault id
  (32 lowercase hex), stores `messages` / `state` / `meta`; every record is
  `{ id, nonce, ct, tag }` (bytes kept separately, sealed by the core's
  `historyEncrypt`), one decimal-string counter record per vault, refused at
  2^32. Record ids are opaque (`m` + local sequence, `state`), so contacts and
  salts are only inside the ciphertext. All bytes are ready before a
  transaction opens; the transaction only puts; `oncomplete` resolves and
  `onerror` / `onabort` are shown. A typed-words or new account keeps nothing
  (memory only) and never sends delivery confirmations — a confirmation is sent
  only after the messages are stored (G11). "Delete message history on this
  device" takes the `nodus.wallet.storage` lock.
- Messages: sent as the whole pending set (undelivered, last 7 days); received
  for yesterday / today / tomorrow, de-duplicated, ordered by the local receive
  sequence, the sender's time labelled "sender's clock". Requests are labelled
  "Not a contact"; claimed names are shown only as "says their name is …".
- Tests: `test/connect-ui.test.js` (record / counter encoding, UI helpers,
  the saved-wallet history delete against a stub of `deleteDatabase`). The
  IndexedDB read / write transactions have NO automated test
  (`fake-indexeddb` is not a dependency and no browser test opens this page).

One page = one module = one session (NC-4b): the page derives the Nodus
address locally (`src/nodus/derive.js`), creates and unlocks the wallet's own
NODUS client (`src/nodus/client.js` with `nodusSendModuleFactory`, the same
`send.wasm` that carries the Messages exports), and builds the Messages core
on it (`createNodusConnectCore({ nodus })`). Lock: Messages core, then the
client, then the store, then the single-tab lock. History records are sealed
as UTF-8 JSON of at most 65536 bytes (`nc_wasm.c` `NC_HIST_PT_MAX`).

**NC-RT2 fixes (preview, unreleased).**
- Delivery confirmation (ACK). The wire value is unchanged (8 bytes BE unix
  seconds, `dht_ack_value_encode`), but the web no longer writes its clock
  there: the value is the NEWEST sender timestamp of that contact's messages
  it has durably stored (`text.js` `ackToSend` → `core.ackPublish(fp, salt,
  ackTs)` → `nc_ack_send` → `nc_ack_publish`). No ACK when a message of that
  check failed verification, and none unless something newer was stored than
  the value last published (`state.ackSent`, kept across sessions). As
  sender, an own message counts as delivered only if it was in a blob that
  was successfully published BEFORE the ACK read was issued and its time is
  <= the ACK value (`published` / `delivered` flags in the message record,
  `markPublished` / `markDelivered`); a never-published message stays
  pending whatever the ACK says. Shown as "waiting to send" / "sent" /
  "delivered".
- Non-text payloads: the core classifies each authentic plaintext as the app
  does (`nc_plaintext_is_chat`: reaction, `call_signal`, `group_invite`,
  `delete`, and the chat screen's `token_transfer` / `media_ref` /
  `image_attachment` cards) and returns only chat text; the rest is counted
  as `other` and the conversation says such items were not shown.
- Opening: the form is hidden while Messages opens; a superseded open locks
  the core and client it built (core, then client).
- Closing Messages (`nc_lock`) points the core's cancel flag at an
  always-set flag, so a suspended read-then-write stops before its PUT.
- Counter: kept also in localStorage (`nodus.connect.counter.v1.<database>`),
  the larger value is used on open, written before every database write; a
  history delete keeps it (the key K does not change), deleting the saved
  wallet removes it.
- Deleting the saved wallet (main page) also deletes its Messages database
  in the same storage-lock section, and says so — or says that it is still
  open in another tab, or could not be found / deleted.
- Names: more invisible characters are removed and marked (tag characters,
  variation selectors, U+206A-206F, U+034F, U+2028/2029); a claimed name with
  no Latin letter, or with fullwidth Latin, is marked "check carefully".

### NC-RT3 — red-team round 2 fixes (LOW)

- Invisible characters are now Unicode's whole `Default_Ignorable_Code_Point`
  set plus U+2028/2029 (the hand list missed U+E0100-E01EF, U+180B-180F,
  U+FFF0-FFF8, U+1D173-1D17A, …). Direction controls and every range are
  written as escapes in `text.js`, no literal invisible character remains.
- A NAME that holds Latin letters and any letter of another script (Armenian,
  Cherokee, Han, …) is marked unusual; message text keeps the Latin /
  Cyrillic / Greek rule so mixed-language chat is not marked.
- "sender's clock": a peer-signed value past the Date range (8.64e15 ms)
  shows "unknown" instead of throwing and breaking the conversation view.
- `nc_plaintext_is_chat` returns 1 / 0 / -1; -1 (no memory) counts as
  dropped, never as `other`, so an unclassified message can no longer be
  covered by the next ACK without being shown.
- The history store closes for good on `versionchange` (another tab deleting
  the saved wallet), and a save that finishes sealing after that writes
  nothing — not even the localStorage counter copy.
- OPEN (operator decision): the delivery watermark (`markDelivered`,
  `ts <= ack`, seconds) can mark a published-but-not-fetched message
  delivered and drop it from the next blob (same second, a clock step back,
  an app receiver whose ACK is its own clock).

## Nodus Connect in the wallet's one module — NC-4b (unreleased, no UI)

Design rev 5 §1.1: one WebAssembly module, one tier-2 session per unlocked
wallet. A second module would open a second session of the same identity,
and a node closes the other one (`nodus_auth.c:95-116`), so Messages and
NODUS send would knock each other off.

- `scripts/build-nodus-send-wasm.sh` links the thin core (`connect/nc_*.c`
  incl. `nc_history.c` and `nc_contactlist.c`, the `messenger/codec/` units,
  `messenger/dna_api.c`, `messenger/dht/client/dna_profile.c`, BIP39,
  `qgp_aes`) and json-c 0.17 (wasm) into `src/nodus/send.wasm`, in the
  release AND parity builds (the parity test compares their bytes).
  `scripts/build-connect-wasm.sh` / `npm run build:connect-core` now run
  that script (and so write `src/nodus/send.*`).
- Session and bracket: `crypto/nodus-send-wasm.c` "Messages host" hands the
  Messages exports its client, its op bracket (one export of the module at a
  time), its identity and its cancel flag (`nc_core.h` "Host"). No Messages
  export creates a client or opens a connection.
- Keys: `nc_unlock` (after the wallet's `nsw_unlock`) takes the words once,
  derives the Messages KEM keys (`nc_keys_from_words`: Kyber round-3 from the
  encryption seed, ML-KEM-1024 from the master seed — the signing seed the
  send module holds cannot give them) and refuses unless the derived ML-DSA
  public key is the session's. `nc_keys_t` keeps its own copy of the ML-DSA
  key (the library signs with it). The wallet's lock (`nsw_lock`) wipes every
  Messages secret (`nc_session_wipe`); `nc_lock` closes Messages alone.
- History key (decision `2026-09-30-connect-history-at-rest.md` rev 2):
  `nc_hist_key` derives K from the session's ML-DSA secret key and the
  vault id; K never leaves module memory. `nc_hist_encrypt` /
  `nc_hist_decrypt` return / take nonce, ciphertext and tag separately and
  the invocation counter as a decimal string (refused at 2^32). A record's
  plaintext is capped at 64 KiB (its hex crosses `ccall` on the 1 MiB C
  stack).
- JS: `src/nodus/send-module.js` offers `connect(run)` (queued) and
  `connectSync(run)` (never suspends), limited to `nc_*` names;
  `src/nodus/client.js` runs `connect` in its ONE queue (optional ops, like
  claim and staking). `src/connect/core.js` takes the wallet's unlocked
  client (`createNodusConnectCore({ nodus })`) and never loads or
  instantiates a module; API at the top of that file.
- Asyncify: there is no explicit function list; `ASYNCIFY=1` instruments
  every function that can reach `emscripten_sleep`. The waiting `nc_*`
  exports are called with `ccall { async: true }`. The 16 KiB unwind bound
  is measured for the send chains only; for the Messages chains it is
  expected to hold, not measured.

Not verified: nothing here has been run in a browser or against a node.

## Nodus Connect site (connect.nodusnetwork.io) — unreleased

Decision `docs/plans/decisions/2026-10-01-connect-own-origin.md` (operator,
2026-10-01): `wallet.nodusnetwork.io` stays the wallet only;
`connect.nodusnetwork.io` is ONE app holding the wallet AND Messages, built
from this same directory; the two sites must not be open (unlocked) at the
same time in one browser.

**Two builds from one tree.**

| | Wallet site | Nodus Connect site |
|---|---|---|
| Command | `npm run build` (`vite.config.js`) | `npm run build:connect` (`vite.connect.config.js`) |
| Entry | `index.html` → `src/main.js` | `connect-site/index.html` → `src/connect-main.js` |
| Output | `dist/` | `dist-connect/` (own `THIRD-PARTY-LICENSES.txt`) |
| Contains | the wallet (portfolio, send / receive, earn, activity, device & settings) | the same wallet page, branded "Nodus Connect", plus a **Messages** section in the wallet navigation |

`connect-site/index.html` is the wallet's `index.html` with: the title,
header product name, hero text and footer saying Nodus Connect; the
address-bar checks naming `connect.nodusnetwork.io`; a "Messages" link in the
open-wallet navigation (with an unread count); the Messages panel
(`#messages-panel`, section 04; Activity and Device & settings become 05 and
06) holding an empty `#nc-root` that `src/connect/ui/messages.js` fills. Keep
the two files in step when the wallet markup changes: every id `src/app.js`
reads must exist in both. `npm run preview:connect` serves `dist-connect/`
locally. The wallet build carries no Messages code: only
`src/connect-main.js` imports `src/connect/ui/`; `test/connect-smoke.js`
checks `dist/` for the Messages navigation, panel and UI strings. (The
string "Message history" in the wallet's `app.js` chunk is the saved-wallet
delete text of 0.1.37, not Messages UI.) Ixios is a build flag in both:
`VITE_ENABLE_IXIOS=true npm run build:connect` for the same set as the wallet
site.

**One unlock, one session, one lock.** `src/wallet-extensions.js` is the only
seam: `src/app.js` raises `attach`, `nodusReady`, `nodusClosing`,
`nodusUnavailable`, `vaultDeleting` and `locked`; the wallet page registers
nothing (no-ops). `src/connect-main.js` names the site (`configureSite
('connect')`), mounts Messages and registers `walletExtension` BEFORE it
imports `src/app.js`.
- Open: when the wallet's NODUS client is ready (`startNodusSend`), Messages
  is opened on THAT client (`openMessages({ client, phrase, vaultId, fresh })`):
  same words, same send.wasm module, same tier-2 session — no second unlock
  screen and no second session. `vaultId` is the saved wallet's id when the
  wallet was opened by unlocking its saved copy (or saved here before
  Messages opened): message history is then kept in IndexedDB (S8);
  otherwise memory only and no delivery confirmations (saving the wallet
  later takes effect at the next unlock). `fresh` is true only for words created and
  verified in this tab (decision thin-core Q1).
- Close: `stopNodusSend` raises `nodusClosing` BEFORE `client.lock()`, so the
  order of design §1.8 holds (Messages core, then the client). Lock, idle lock
  (10 min; typing in Messages counts as activity), `pagehide`, the single-tab
  takeover, a saved-wallet change in another tab and the cross-site rule all
  go through the wallet's `lock()`. The Messages panel's Lock button is the
  wallet's Lock. A lost connection closes Messages with a reason; it reopens
  after the wallet is locked and opened again (`core.lock()` is terminal for
  the module instance). Deleting the saved wallet closes its open history
  first, so the delete is not blocked by this tab.
- Messages itself (`src/connect/ui/messages.js`) has no unlock, no Web Lock and
  no idle timer of its own; the sync, delivery, ACK, outbox and history rules
  are unchanged (`text.js`, `store.js`, `core.js`, the `nc_*` C code are not
  touched).

**Messages layout.** Inside a dashboard panel: left, the contacts column
("Add contact", "Your ID & profile", a "Contact requests" entry with its
count, then the conversations — an ID mark (two hex digits of the ID, never a
claimed name), the short ID, a claimed name only as "claims the name …", the
last message, its time and an unread count; unread counts are kept in memory
for this session only); right, one view at a time: the conversation (own
messages right in lime, received left; time under each bubble; own status
"waiting to send" / "sent" / "delivered"; the "sender's clock" kept, small),
the add-contact form, the requests (incoming: Accept / Decline; sent: Withdraw),
or your ID (Copy) and profile. The composer sits at the bottom of the
conversation: grows to 5 lines, Enter sends, Shift+Enter is a new line (not
while an input method composes), 4000 characters. Empty, loading and closed
states are shown in the right side. At 700 px and below the contact list
comes first and any view opens alone with a "← Contacts" button. All text goes
through `textContent` (`dom.js`), other people's text in `<bdi>` with the
unusual-character marker, websites only as checked https links; no innerHTML,
no inline styles (CSP `style-src 'self'`). Styles: `src/connect/ui/messenger.css`
on the wallet's tokens.

**Cross-site rule — `src/site-lock.js` (both builds).** Web Locks and storage
are per origin, so the single-tab lock cannot see the other site; a cookie
can. While a wallet is unlocked its page writes, at once and every 5 s,
`nodus_open=<site>.<ms>; Path=/; Max-Age=15; Secure; SameSite=Strict`, with
`Domain=nodusnetwork.io` only when the host name ends in `.nodusnetwork.io`
(none on localhost / in tests). `<site>` is `wallet` or `connect`; the cookie
holds no identity data. Before any open (restore, create, unlock, "Use it here
instead") a fresh (< 15 s) mark of the OTHER site refuses with "Your wallet is
open on wallet.nodusnetwork.io. Lock it there first." (or the Nodus Connect
equivalent) — before any key derivation or password check. While open, the
other site's fresh mark locks this page with a plain message. On lock and
`pagehide` the cookie is cleared if the mark is ours. Limits: per browser
profile only (two browsers or two devices can both be open; then only the
node's same-node session eviction applies); a background tab whose timers the
browser throttles below one tick per 15 s lets its mark expire, so the other
site may open — the throttled tab then locks itself at its next tick; a
browser that refuses the cookie is not blocked (fails open). Tests:
`test/site-lock.test.js` (`npm test`).

**/preview/ (until it is removed from the wallet site).** `preview/index.html`
keeps its own unlock screens, now in `src/connect/ui/standalone.js` (single-tab
Web Lock, 10-minute idle lock, client creation, lock order: Messages, client,
Web Lock); the Messages part is the same `messages.js` mounted into `#nc-root`
(`npm run build:preview` still builds it). The old "Messages could not open"
screen and the Contacts / My profile tabs are replaced by the layout above.

**Tests.** `npm run test:connect` (`test/connect-smoke.js`, after `npm run
build` and `npm run build:connect`): the wallet `dist/` has no Messages
entry or UI strings; one unlock opens the wallet dashboard and the Messages
panel (no second unlock screen); a fresh `wallet` mark refuses the unlock;
no horizontal scroll at 390 and 320 px; the panel's Lock locks the wallet.
NOT covered: every node WebSocket is closed by the test, so Messages never
opens — the contact list with real contacts and the conversation composer
(shown only for a contact) are not reached; sending, receiving, requests and
profile editing need a live node. Not verified: nothing in this section has
been run in a browser yet.
