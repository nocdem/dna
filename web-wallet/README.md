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

- **Messages check progress in the status line and the session log (0.1.71, 2026-10-07).** Operator: on a phone Nodus Connect connected, but the Chats status line said "Updating…" for many minutes and a message never appeared, with nothing to show which step was running. The status line now names the step of the first check round before the contacts are checked ("Updating: your account…", "Updating: contact list…", "Updating: contact requests…", "Updating: names…"), and counts the contacts in every round ("Checking messages: 5 of 31 contacts…"); a later round leaves "Last checked HH:MM…" in place until its contacts are checked, then shows the count, then its usual end text. The session log (category Messages; memory only, scrubbed, never sent) gets: each first-round step when it starts and its duration ("check round 1 stage names started", "check round 1 stage account: 812 ms" — account, contact list, requests, publish contacts, names); the round ("check round 3 started (regular): 31 contacts, 3 days", logged once the day count is known, so after the first round's step lines; "check round 3 done in 12 s: 2 new messages, 0 failed"); each contact when its check starts, before each of its network steps ("contact ID 1a2b3c4d…9f0e: outbox day 20368" — profile, salt, ack, outbox publish, outbox day N, ack publish) and when it ends ("contact ID 1a2b3c4d…9f0e checked in 1834 ms: 2 new, profile ok, salt ok (earlier), 2/3", flagged as an error with ", check failed" when the check failed). A check that never ends therefore leaves its last step as the last line of the log. Short IDs only, no message text. Nothing else changed: the same calls in the same order, no timeouts, nothing new stored. Text builders: `src/connect/ui/text.js` (`updatingStageText`, `checkingContactsText`, `roundStartLine`, `stageStartLine`, `stageLine`, `contactStartLine`, `contactStepLine`, `contactLine`, `roundDoneLine`); tests: `test/connect-ui.test.js`.
- **Connection watchdog and session Logs (0.1.70, 2026-10-07).** Operator: "sometimes when I open Connect it stays in 'connecting'". A connection attempt was retried only once it failed; a step that never answered left it in 'connecting' with nothing to retry it. Now each attempt of the NODUS client — identify / unlock (module load + identity) and connectNetwork (session + rule-set check) — must settle within 30 s (`src/nodus/client.js` `NODUS_CONNECT_BOUND_MS`, the operator's choice; the module's own steps have a 5 s connect timeout). Past it the client locks itself (the only way to abandon a call the module's one queue is holding), the attempt fails as `timedOut`, and the wallet makes a NEW client after its usual reconnect wait (`src/app.js` `connectNodus`; the bar stays amber); a late answer of the abandoned call is discarded. On `/preview/` a timeout ends the page as a lost connection does (it keeps no words to make a new client). New general session log (`src/session-log.js`): memory only, the last 500 lines, cleared on lock and gone with the page, never sent anywhere — every connection step with its duration and outcome ("attempt 2 · connect 5 012 ms failed (…)", "running 34 s — stuck"), the retries and their wait, network-status changes, every status text the wallet shows, Messages' failures, the vault and smart-contract panels' outcomes, uncaught page errors (message only). Every line is scrubbed (no hex run of 16+, no base58 address, no quoted name, no amount; short ID prefixes only). Shown under Device & settings → Logs on both sites (filter All / Network / Messages / Wallet / Errors; Copy logs; Download logs as `nodus-<connect|wallet>-log-YYYYMMDD-HHMM.txt` with a header: version, page, browser, session start), and in Nodus Connect's More menu as "Logs". Tests: `test/nodus-send.test.js` (watchdog), `test/session-log.test.js`.
- **"Witness", not "validator", on screen (0.1.69, 2026-10-07).** Operator: the Nodus chain's block producers are called witnesses, everywhere. Every text the wallet and Nodus Connect show for the Earn panel now says witness: the panel intro, the "Witnesses" heading and its hint, "Your delegations to witnesses not listed above" (`index.html`, `connect-site/index.html`); the status lines, row labels, hints and the "No witnesses listed." line (`src/app.js` `refreshStaking` / `renderStaking`); the Activity descriptions "→ witness …", "back from witness …" and "Witness bond", and the "Review witness bond" title; the review rows "Witness" / "Witness commission" and the notes about the witness set (`src/adapters/nodus.js` `prepareStake`); and the adapter's refusals ("Choose a witness.", "This witness is not in the current witness list.", "This wallet is already a witness.", "The Nodus module returned an invalid witness list / witness stake.", and the rest). Only text changed: element ids (`validator-list`, `validators-title`), `data-validator`, the module's `validator` fields and `nsw_validators` calls keep their names, and nothing stored changes (saved activity records carry no staking label — `src/activity-storage.js`). The send module's C error texts (`crypto/nodus-send-wasm.c`, e.g. "The validator list could not be read") still say validator; they are compiled into `send.wasm` and were not part of this change. `test/nodus-send.test.js` asserts the new texts.
- **Nodus network status in the open-wallet bar (0.1.68, 2026-10-07).** Next to "Wallet open in this browser" the wallet page now shows its connection to the Nodus network as a dot and one line (`#net-status` in `index.html`, styles `.session-network` in `src/style.css`): green "Connected to the Nodus network" while the wallet's NODUS client is `ready`; amber "Connecting to the Nodus network…" while it identifies or connects and while a failed or lost connection waits to be tried again by itself (the existing RECONNECT retry in `src/app.js`); red "Not connected to the Nodus network. Lock and reopen your wallet to retry." only where the wallet does not retry by itself (the node serves another chain, or the Nodus address could not be derived) — the same way back the receive panel already names. A build without the NODUS module shows no line. The mapping is pure (`src/net-status.js` `netLevelFor` client state → level, `netStatusView` level → text; unknown states show red, never green) and `src/app.js` `setNetStatus` is its only writer: driven by the client's `onState` (identifying / identified / connecting / ready) and by the retry / final decisions in `startNodusSend` / `connectNodus`; lock resets it. The text is in a polite live region and stays the same across retries (no countdown read out); the dot is hidden from screen readers. Below 760 px the line takes its own row. The node the wallet is connected to is not shown — the client does not expose it. Nodus Connect loads the same `src/app.js` but its page has no such line (the writer skips a missing element), so Connect is unchanged. `test/net-status.test.js` covers the mapping.
- **Add a contact by chain name in Nodus Connect (0.1.67, 2026-10-07).** The Messages "Add a contact" box now takes an ID (128 hex, unchanged) or a chain name, read with the wallet's own name rule (`src/nodus/names.js` `chainName`: 3 to 36 letters a–z and digits, typed capitals lowered, ID-like all-hex names of 8+ refused; `src/connect/ui/text.js` `parseContactInput`). A name is resolved to its owner's Nodus ID by the same lookup the NODUS send uses (`src/adapters/nodus.js` `resolveChainName` on the wallet's client — one node's committed state, decision `2026-10-02-onchain-names.md` item 9; `src/connect/ui/chain-names.js` `resolveContactName`). The first press of "Send request" only looks the name up and shows "<name> belongs to ID 1a2b…9f0e", the full ID and the wallet's look-alike caution (`NAME_CHECK_ROW`); the button then reads "Send request to <name>" and only the next press sends. Editing the box drops the shown result. An owner that is this wallet, already a contact or already requested gets the same refusal as a typed ID (`requestRefusal`). Plain errors: "No one has registered that name.", the network not ready, or the lookup failed — never a fallback. The empty-contacts hints mention chain names. The found name is not stored in `state.chainNames` by this step; names shown for contacts still come only from the usual reverse lookup. `test/connect-ui.test.js` covers the parsing, the lookup (a stub client) and the refusals; the dialog itself has not been looked at in a browser.
- **Offline smart-contract build in the shipped module (0.1.65, 2026-10-07).** `send.wasm` now exports `nsw_evm_offline_build`: one EVM envelope (CALL, CREATE, DEPOSIT, WITHDRAW, REDEEM) built and signed with NO node — the shape of `nsw_stake_offline_build` / `nsw_name_offline_build`: the identity from `nsw_seed_buf` (wiped on every path), the coins from `nsw_req_*`, the call data / access list / effect ceilings / estimate from the existing `nsw_evm_*` request buffers, and every network fact given (rule-set generation ≥ the EVM generation, chain id, tip, gas price, the EVM leg's ruleset version + hash — which must equal the compiled EVM generation's, the same check as `nsw_evm_net_set`; expiry exactly tip + 90). It calls `nsw_evm_core` — the shared builder `nodus/src/client/nodus_v2_evm.c` the networked builds and nodus-cli `evm` use; no new encoder, no envelope change, the networked builds unchanged. Each op takes only its own fields; a field it does not carry must be absent (`""` / `"0"`) or the build refuses. `send-module.js` exposes it as `evmBuildOffline({ seed, generation, chainId, tip, gasPrice, ...the evmBuild fields })` (same result shape as `evmBuild`; removed with `evmBuild` when the smart-contract settings are refused); `client.js` does not pass it through — no wallet screen calls it (the staking / name offline builders are not exposed in `send-module.js` at all; this one is, because the SDK's `NodusEvm.buildOffline` needs it). The EVM build part of `crypto/nodus-send-wasm.c` (request, `nsw_evm_core`, read-back, offline build) is now compiled into the native vector too (`scripts/build-nodus-send-native-vector.sh` links `nodus_v2_evm.c`, `evm_call_wire.c`, `keccak256.c`; new `evm` mode in `crypto/nodus-send-native-vector.c`). Tests: `test/evm-call-wire-wasm.test.js` (see "Smart contracts" below); `nsw_test_evm_build` (generation 2 + test op weights, synthetic EVM identity) is unchanged.
- **Smart contracts in Nodus Connect too (0.1.63, 2026-10-06).** Nodus Connect's Wallet tab now has the same "Smart contracts · NODUS · Testnet" panel as the wallet page, mounted and registered as a wallet extension the way the shared vaults are (`src/connect-main.js`, before `src/app.js` loads; markup `#evm-panel`, `#evm-root` and the "Smart contracts" link `#nav-evm` in `connect-site/index.html`). Nothing about when it shows changed: it stays hidden exactly as on the wallet page until the connected node reports the EVM generation (`src/evm/ui.js` `showPanel`: `client.evmBuildable` / `evmReadable`, NODUS selected) — HF-5, `EVM_ACTIVE` voted to switch on at block 79,757 (decision `2026-10-06-hf5-evm-activation.md`). No new network request, polling or `src/evm/` change; both pages already had the same Content-Security-Policy. `test/connect-evm.test.js` checks the wiring and markup statically (source text, not a running page); the panel's placement in the Connect Wallet tab has not been looked at in a browser.
- **Chain-name discovery and password controls (0.1.57, 2026-10-05).** Connect Home now puts **Register a chain name** directly below the identity, with an explanation of what the name is for. It stays visible but disabled until the wallet's existing name registration entry is ready, showing the name lookup's status or an availability note. Once ready, it opens Wallet and forwards to the existing registration shortcut, which selects NODUS and focuses the form. The entry disappears when the existing own-name display knows a name, and resets on lock/reopen. No new registration transaction path, name cache or polling was added.
  - Both sites show **Save current wallet** only without a saved copy. After saving or unlocking that copy, the section reads **Change saved password**, with current-password and new-password fields. A phrase-only session with a saved copy instead explains how to lock and unlock it; neither action nor password fields are offered. The result remains visible below the controls.
  - Saving and changing a password both require entering the new password twice. Missing or different confirmation shows an error and focuses confirmation before encryption or storage work, preserving the entries for correction. Confirmation clears with the other password inputs on an operation or lock and participates in the existing inactivity guard. The current-password, authenticated-session, consent and saved-history protections remain in place; encryption and storage formats are unchanged.
  - Existing browser regressions now cover these state transitions, missing/mismatched confirmation, phrase-only restore with a saved copy, and the offline Home entry. Wallet smoke/security suites also intercept IXIOS reads and close node WebSockets so release builds cannot reach a chain. These suites do not register a real name or verify registration with a live node; the Connect smoke covers the disabled entry and reset, not the connected navigation path.
- **Operator feedback round (2026-10-03, wallet and Nodus Connect).**
  - **Earn: delegation inside each validator row.** The separate delegation form with a validator drop-down is gone. Each validator row shows its figures, its delegator places as "N/2048" ("?" when the node's answer carries no count — an older node; never 0) and, when you have one, "Your delegation: X NODUS". The row header is one button (`aria-expanded`); clicking it opens the row's own controls (`src/app.js` `renderStaking`, `expandedValidator`): with a delegation — "Add more" (any amount) and "Withdraw" (pre-filled with the full amount, with the lock note); without — an amount and "Review delegation" (with the 100-NODUS minimum note); a validator that takes no delegations or whose places are all taken says so. Every action goes through the same `prepareStake` checks and review dialog as before. A delegation whose validator is not in the list (it cannot be withdrawn here: the module needs the validator's key from the list) is listed under "Your delegations to validators not listed above", shown only when there is one.
  - **Delegator places through the module.** `crypto/nodus-send-wasm.c` keeps the validator list reply's optional `dlg` per row (`nsw_val_delegators`, -1 = unknown) and exposes the chain cap `NODUS_MAX_DELEGATORS_PER_VALIDATOR` (`nsw_const_max_delegators`, defined in `nodus/include/nodus/nodus_types.h` since this round); `send-module.js` passes them as `validators()[i].delegators` and `stakingRules.maxDelegators`; `src/adapters/nodus.js` `parseValidators` turns -1 / absent into `null`. `prepareStake` refuses, before building, a NEW delegation to a validator whose reported count is at the cap — the chain's own condition (`nodus_witness_rt_native.c` `rtn_delegate_exec`: a top-up is exempt; an unknown count is left to the chain).
  - **"Preparing…" on action buttons.** Send's "Review transfer", "Review registration", the Earn row actions and the "Claim your allocation" action show "Preparing…" and stay disabled from the press until the review or the result is shown or the preparation fails (`src/app.js` `showPreparing`; the portfolio row action hands its button to `run(button)`). Saving shows "Saving…". The shared-vault panel already disabled every button while busy; the pressed one now also reads "Preparing…" (`src/vaults/ui.js` `pressed`), and a vault card's "Add this vault" shows "Adding the vault…". Each action's `busy` flag stays the real guard against a second press.
  - **Earn refreshes after a delegation.** Before, after confirming a delegate / add more / withdraw the row stayed open with its amount and the list was read once at submission, before the chain had included anything. Now a submitted action (or one whose broadcast outcome is uncertain) closes its row at once and drops the amount typed there (`src/app.js` `closeStakeRow`), and the list is read again then and once more when the transaction's Activity record becomes final (included or expired — `checkNodusActivity` answers `confirmed` / `expired` — through the existing tracker, `checkRow`; no new polling), so "Your delegation", the totals and "N/2048" follow without a reload. If nothing was broadcast (the review expired, signing failed) the row and its amount stay for another try. A background re-read no longer wipes a row you are typing in for another validator: the amounts you edited, the keyboard focus and the cursor position survive the redraw (`renderStaking` `drafts`; the withdraw box's untouched pre-filled amount follows the new figures). The final re-read waits while another network is selected: Activity checks only the selected network's records. Not covered by the browser suites (no staking-capable module there).
  - **Saving the wallet says what it does and whether it worked.** "Save wallet on this device" opens with a plain explanation (kept in this browser on this device, unlocked with your password; without saving you type your 24 words each time; the three steps). The result — saved, password changed, not saved and why — is written right under the buttons (`#vault-save-status`, `saveResult`) as well as in `#vault-status`; before, it went only to `#vault-status`, far above the button on the wallet page and, in Nodus Connect, on the start screen that is hidden while the wallet is open. The unsaved storage line points to the save section.
  - **NODUS connection is tried again by itself.** Before, NODUS left receive-only mode only if the first connection succeeded; a failed first connection (no pinned node answered in time, the module file did not load, the chain check failed) or a later lost one stayed down until lock / reopen or a reload — no balance, no Earn, and the send note. Now `startNodusSend` schedules a new client after 5, 10, 20, 40, then every 60 seconds (fixed, no randomness) while the same wallet is open (`src/app.js` RECONNECT, `scheduleNodusRetry`); success restores the sendable network, balance, Earn, the name and the extensions. With a send module in the build the not-yet-connected note reads "Connecting to the Nodus network… Sending NODUS becomes available as soon as the connection is ready." (`src/nodus/network.js` `nodusNetworkFor(ready, { module })`).
  - **Nodus Connect header shows your chain name.** Home's identity title shows the wallet's own chain name as the reverse lookup (`ownChainName`, `dnac_name_of` for this address) answered it on open, else "Your ID" (`src/app.js` `refreshName` raises the new `ownName` extension event; `src/connect-main.js` `nameExtension`). The wallet page has no "Your ID" label, so nothing changed there.
  - **Nodus Connect shows names from this device's saved copy, without the 7-day limit.** A chain name is permanent (decision `2026-10-02-onchain-names.md` item 4), so a name found for this wallet or a contact and kept in the saved wallet's encrypted Messages history (`state.chainNames`, `src/connect/store.js`) no longer expires after 7 days (`src/connect/ui/chain-names.js` `keptChainName`). A contact's kept name is shown as soon as Messages opens and is not asked again; an ID without a kept name is asked once per session. This wallet's own kept name is shown at once on Home (title and identity line), in More (the entry reads "<name> — ID & profile", `#more-name`; "Your ID & profile" when no name is known) and on "Your ID & profile" (marked "saved on this device" until confirmed), and is asked again once per session: a confirmed other name replaces it, a confirmed "no name" removes it. The wallet's own lookup now says when it answered (`ownName({ name, confirmed: true })`, `src/app.js` `refreshName`); once it has answered, Home and More show its answer (`chain-names.js` `shownOwnName`). The name lookups now run before the message check of each round instead of after it, so names appear on the first check. An unsaved wallet keeps the names in memory only, as before. **Limit:** the saved copy can be read only after the Nodus connection is made — its key comes from the Messages core, which runs on the wallet's Nodus client, and that client connects as part of its unlock (`crypto/nodus-send-wasm.c` `nsw_unlock`); before the connection, Home shows "Your ID" as before. (Lifted by the local-first open, 2026-10-04: the key needs only the identity — `nsw_identify` — so the saved copy is read before the connection; "Nodus Connect site" below.)
  - **Nodus Connect asks a contact's chain name again when you open the conversation.** Before, an ID was looked up at most once per session and a failed lookup counted as asked, so a contact who registered a name after the session began — or whose first lookup failed — stayed an ID until the next session. Now opening a conversation with a contact that has no known chain name looks the name up again right then (`src/connect/ui/messages.js` `recheckChainNameOnOpen`, from `selectContact`); a found name is shown in the conversation header and the lists at once and kept through the usual save (a saved wallet's encrypted Messages history, as before). A failed lookup no longer counts as asked: the next sync round tries again. No ID is looked up twice within 60 seconds, whichever path asks (`chain-names.js` `CHAIN_LOOKUP_SPACING_MS`, `chainLookupSpaced`; the times are held in memory only, never saved). Unchanged: a contact's kept name is not asked again, the own name is asked once per session (after a successful answer), a confirmed "no name" still counts as asked for the sync round, and names come only from the confirmed reverse lookup.
  - **One contact's failed check no longer stops the others; a conversation shows its last check under "Details".** Before, the message check walked the contact list with no per-contact error handling (`src/connect/ui/messages.js` `sync`): an exception from any step of one contact's check (profile read, salt step, delivery read, publish, a day read, saving) jumped to the round's single catch, which showed only "The network could not be reached…" — and every contact after it in the list was never checked, round after round, with no note in their conversations. Now each contact's check is caught on its own: the next contact is still checked, the status line adds "N contact(s) could not be checked (see Details in the conversation)", and the error is kept with that contact. Each conversation has a collapsed "Details" line (`src/connect/ui/diag.js` `diagText`) with the last check of that contact: its time, whether the profile was read, the salt step's status (and whether the salt changed — never the salt), and for each day read its outcome, how many messages it returned, how many could not be checked and how many were other items (empty days are folded into one count); a failed check adds "Last check failed: <message>" (bounded, any long hex run cut out). The diagnostics live in memory only, are never written to the encrypted history store (`src/connect/store.js`, decision `2026-09-30-connect-history-at-rest.md`), and are dropped with the rest of the session on lock (`messages.js` `wipe`).
- **Claim a genesis allocation on the Nodus testnet (0.1.26).** When the open wallet's Nodus address holds an allocation in the chain's genesis distribution, a "Claim your allocation (… NODUS)" action appears under the NODUS asset; it opens a review (amount, paid to your own address, chain id, "can be claimed only once"), then submits and tracks the claim in Activity. The C side is nodus-cli `v2-claim` (`nodus/tools/nodus-cli.c` `cmd_v2_claim`) compiled into `send.wasm` (`crypto/nodus-send-wasm.c` "GENESIS CLAIM", over the shared codec `shared/dnac/manifest_wire.c`, now in both build scripts together with `ledger_roots_v2.c`).
  - **Data:** no node RPC serves a manifest, a leaf list or a proof, so `src/nodus/send-module.js` `NODUS_CLAIM_DATA` embeds the testnet's genesis manifest (431 bytes, as stored in `v2_manifests`), its hash (`1807f972…31b4b8`) and its single allocation leaf (the Founder, 50,000,000 NODUS), next to the pinned chain id. `validateNodusClaimData` checks the shape; the module refuses to claim unless the manifest decodes strictly and re-hashes to the embedded hash, targets the native coin, and the leaves rebuild the manifest's committed allocation root and total (`nsw_claim_set_manifest` / `nsw_claim_seal`). A key bound by more than one leaf is refused (the CLI claims every match; the wallet claims one).
  - **Module API** (`send-module.js`, passed through the `client.js` queue; optional — a module without them still connects and every claim call answers "not available"): `claimStatus()` → `{ found: false }` or `{ found, amount, tip, startHeight, endHeight, window: 'open'|'not-open'|'closed', claimed: 'yes'|'no-evidence'|'unknown', outputId }`; `claimBuild()` → `{ bytes, claimId, decoded: { recipient, amount, chainId, nullifier, outputId, leafIndex } }` read back from the signed bytes (decode, proof and signature re-verified in C); `claimSubmit({ bytes })` → `{ accepted, message? }`, only the bytes of the last build. Adapter: `src/adapters/nodus.js` `claimStatus`, `prepareClaim`, `isClaimRow`.
  - **"Already claimed"** is an inference, not a lookup: `dnac_supply`'s `unclaimed` bucket below this allocation's amount proves it was claimed (only this key can claim it); otherwise "no evidence" and the node's admission decides. The `dnac_nullifier` RPC is not used — it reads the legacy `nullifiers` table, not the claim spent-set. The claim window is checked against the node's tip + 1, as admission does.
  - **Tracking:** the Activity record's id is the coin the claim creates (`dna_claim_utxo_id` of its nullifier — the same for every signature variant); the block scan matches an applied claim that created that coin. The record lists that id as its single "input", which marks it as a claim after a reload and locks no coin. A claim has no expiry: past the 90-block scan window the claim state decides (claimed → confirmed; otherwise the record closes with a note that the allocation can be claimed again, never paid twice).
  - **Also in 0.1.26:** the portfolio note says the NODUS balance is shown (testnet, not counted in the total) once the send module is connected, and still "not shown yet" before that; the network label reads "Testnet" for Nodus instead of "Mainnet" (transfer panel, send block, review dialog).
  - **Not verified in this build:** a claim against the live testnet (the operator runs it); the Asyncify stack bound was not re-measured for the claim exports (`scripts/build-nodus-send-wasm.sh` comment).
- **Earn (0.1.31).** The staking panel below is reached from an "Earn" button beside Send / Receive, an "Earn" link in the wallet navigation and an "Earn" button on the NODUS portfolio row (`src/app.js` `setEarnAvailable`, `src/portfolio-view.js` `setEarn`); all three appear only while staking is available. The right-hand column shows either the Send / Receive panel or the Earn panel, never both (0.1.32, `showEarn`): Earn swaps Send / Receive out; Send, Receive, the "Send / Receive" link or selecting an asset row swaps it back. Its heading reads "Earn · Delegate NODUS · Testnet". Earn selects NODUS as the network so Activity shows where a delegation is tracked. Not covered by the browser suites (they do not bring up a staking-capable module).
- **Activity and Earn styling.** Activity rows, the validator list and "Your delegations" use the portfolio's row style (one bordered group, amount/identity on the left, a status pill on the right, the row's link or buttons right-aligned below; Activity rows also show the network and the send's local time); the Earn panel's blocks are separated like the Send block (`src/style.css` `.activity-row`, `.stake-row`, `.status-badge`, `.stake-block`).
- **Delegate, undelegate and become a validator on the Nodus testnet (0.1.29).** A "Delegate NODUS · Testnet" panel appears while the NODUS send module is connected: the validator list (shortened key, status, own stake, delegated, commission), a delegation form (a new delegation is at least 100 NODUS; adding to an existing one can be any amount), "Your delegations" with an undelegate amount per row (both moved into the validator rows on 2026-10-03, see "Operator feedback round" above), and "Become a validator" (removed from the page on 2026-10-03) (exactly 10,000,000 NODUS bond, commission 0–50%, bond returns to the wallet's own address) behind an extra "I understand" checkbox. Every action opens the usual review dialog; its values are read back by the module from the signed envelope and compared with the request before anything is shown, and the transaction is tracked in Activity like a send (its coins held until it is included or expires).
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
can display $0 without prices. A balance counts as current for five minutes and
a quote for fifteen; a 30-second display check moves older values out of the
total. Refresh all requests new data; there are no background polling requests
or automatic retries.
Lock cancels in-flight reads, clears the portfolio and rejects late replies.
Endpoint changes invalidate the old snapshot and require Refresh all.

**Last balances (0.1.41).** Like the app's wallet cache
(`messenger/database/wallet_cache.h`, stale-while-revalidate), the last
balance read per asset stays on screen when it is no longer current (older
than five minutes, being read again, or the new read failed): the amount
with "Last read HH:MM" (or "Read failed · last read HH:MM"), the network
badge "Last read HH:MM". Such a value is never priced, never part of the
total and still counts as a missing balance. Only a value read for the
address shown now is used. Where it is kept follows the operator rule of
2026-10-02 (decision `2026-10-02-device-cache-only-when-saved.md`): an
unsaved wallet keeps it in memory only, gone on lock; a SAVED wallet also
writes it to `localStorage['nodus.balances.v1']`, encrypted like the saved
activity (AES-256-GCM, random 12-byte IV, header as additional data) under
its own key — HKDF-SHA-256 of the phrase with the vault id as salt and info
`nodus.wallet.balances.v1` instead of the activity's `nodus.wallet.activity.v2`
(`src/activity-storage.js` balancesKeyFor / serializeBalances /
parseBalances). It is shown at once on unlock until fresh reads replace it;
one that does not authenticate is not shown. Deleting the saved wallet
deletes it.

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
16 characters, entered twice with an exact match (0.1.57).
Length alone is not a strength guarantee. Consent is rechecked before writing
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

**Content type (0.1.40).** The request is sent as `Content-Type: text/plain;charset=UTF-8`, which keeps it a CORS "simple" request with no preflight. On 2026-10-01 `rpc.cellframe.net` answered the `OPTIONS` preflight that `application/json` needs with HTTP 405 and no CORS headers, so browsers dropped every balance read (the Cellframe badge showed "Incomplete" and no CPUNK balance); the same POST with `text/plain` gets HTTP 200, `Access-Control-Allow-Origin: *` and the same JSON (checked with curl and in Chromium from `wallet.nodusnetwork.io`). The body is unchanged JSON.

The command fails on connection errors or malformed responses; it does not test browser CORS. After deployment, use the page's public-address read to verify access from the actual wallet origin. Only the public address and fixed CPUNK query fields are sent to the RPC. Responses are capped at 64 KiB and browser operations at 15 seconds; redirects are refused. The last balance read is kept like every other network's ("Last balances" under Multichain portfolio: in memory, and encrypted only with a saved wallet). No claim system, snapshot rule or ownership proof is implemented.

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
- `src/evm/` (unreleased): smart contracts on the Nodus EVM domain — `address.js`, `abi.js`, `units.js`, `rpc.js`, `contract.js`, `ui.js`; the C side is `crypto/nodus-send-wasm.c` "SMART CONTRACTS" over `../shared/dnac/evm_call_wire.c` (section "Smart contracts" at the end). The panel (`ui.js`) is registered as a wallet extension by `src/main.js` and, since 0.1.63, `src/connect-main.js`.
- `../sdk/js/` (not part of this package): the Nodus EVM SDK for Node.js scripts — imports `src/evm/`, `src/nodus/` and a node-environment build of the same send module (`scripts/build-nodus-send-wasm.sh parity`); see `sdk/js/README.md`.
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

Sends initiated here appear under **Sent from here** (scoped to the current chain and sender) and are tracked until final. Since 0.1.42 the incoming and outgoing transfers of the account are listed below them under **Account history** (next section).

## Account history (0.1.42)

Like the DNA Connect app (`messenger/src/api/engine/dna_engine_wallet.c dna_handle_get_transactions`), the Activity panel lists the newest 50 transfers of the selected network's address, in and out, read from the same kind of public source (`src/history.js`):

| Network | Source | Requests per read |
|---|---|---|
| Ethereum | Blockscout `eth.blockscout.com/api` `txlist` + `tokentx` per listed token (the app: `eth_rpc.c:363-395`, `:650-660`) | 4 |
| TRON | TronGrid `/v1/accounts/<a>/transactions` + `/transactions/trc20` (the app: `trx_rpc.c:351`) | 2 |
| Solana | the selected Solana RPC: `getSignaturesForAddress` (newest 20) + `getTransaction` for each signature not read before (the app skips known ones too, `dna_engine_wallet.c:942-963`) | 1 + new ones, paced 1.2 s |
| Cellframe | `tx_history` on the CPUNK RPC, CPUNK rows only (the app: `cellframe_rpc.c:371-387`), text/plain like the balance read | 1 |
| BNB Smart Chain | none — the app has it switched off too (`dna_engine_wallet.c:887`) | 0 |
| NODUS, Ixios | not yet | 0 |

**Untrusted data.** Every field from a provider is checked: hash format per network, integer amounts, addresses of the network's form, only transfers that involve this address; the symbol and decimals always come from the wallet's own asset list (`src/config.js`), never from the provider (an unlisted token is dropped). Rows are drawn with `textContent`; the explorer link is built from the checked hash. The status line names the provider ("as reported by Blockscout"): the list is what that provider reported, not a proof. An unfiltered `tokentx` of a busy Ethereum address passed the 256 KiB response bound (measured 2026-10-02), so tokens are asked per contract, as the app does.

**Request limits.** Public providers limit requests (operator 2026-10-02; measured that day: Blockscout without a key answered `x-ratelimit-limit: 10` with a reset of about 20 minutes). So history is read only for the network shown in Send / Receive, when it is selected, at most once per 30 minutes for Ethereum and once per 5 minutes for the others; "Refresh history" reads again at most once per 30 seconds. Selecting another network cancels the read in flight. A refused request (HTTP 429 included) is reported ("The history provider is limiting requests right now…") and never retried automatically.

**Kept.** In memory for the session; with a SAVED wallet also encrypted in `localStorage['nodus.history.v1']` (decision `2026-10-02-device-cache-only-when-saved.md`): the same envelope as the saved balances under its own key (HKDF info `nodus.wallet.history.v1`, `src/activity-storage.js` serializeHistory / parseHistory). Saved rows are checked again when loaded (`checkHistoryRows`) and merged with each fresh read (one row per transfer, fresh wins, newest 50 kept — the app's cache merge, `dna_engine_wallet.c:1282-1300`). Deleting the saved wallet deletes it.

Use the account explorer for anything older than the newest 50.

**Version on the page (0.1.42).** Both builds show the release from `package.json` ("Version x.y.z"): the wallet in its footer, Nodus Connect on the start screen and in More. `vite.config.js` and `vite.connect.config.js` define `__APP_VERSION__`; `src/main.js` / `src/connect-main.js` write it into every `.app-version` element.

**Browser tests start and stop their own server (0.1.42).** `test/preview-server.js` startPreview: a port that already answers is refused before anything starts (a `vite preview` left over from an earlier run was answering and the tests checked that old build — two such servers, from 2026-09-30 and 2026-10-01, made test:browser / test:security check an old dist), the server must accept a TCP connection while still running (not fetch(): Node refuses port 4190, a Fetch "bad port"), and it is stopped with SIGKILL in `finally` and on process exit (servers with ppid 1 were left after normal runs).

### Sends made here

By default records stay in tab memory and are cleared on lock. Opting into a saved wallet also saves up to 100 activity records encrypted for reload recovery; keys are not kept by history.

The app computes the transaction ID locally before broadcast and records it even if the response is ambiguous. It never retries a broadcast automatically. Polling checks only public status and stops on lock or chain changes. Ethereum/BSC require a canonical receipt and the provider’s finalized block before reporting confirmed/failed. Solana requires finalized signature status; missing history after the finalized validity window remains unknown, with continued polling and an explorer verification reminder. TRON uses the solidified transaction execution result and checks the observed mainnet genesis; absence is pending, not an invented failure. Providers lacking finality/status APIs may leave activity unresolved with a read error. Transient read failures do not overwrite prior status. Pending and included are never labeled confirmed. Tracking starts with the endpoint that prepared the send. Changing RPC settings cancels current reads and updates visible records to the selected provider; reloaded records use chain defaults until changed.

## Optional encrypted device wallet

**Save wallet on this device** encrypts the open wallet’s full recovery phrase using browser Web Crypto: AES-256-GCM, a new random 128-bit salt and 96-bit IV, and PBKDF2-HMAC-SHA256 with 600,000 iterations. New passwords must be 16–1024 characters; obvious repetitions, sequences and common-password patterns are rejected locally. These checks do not guarantee entropy: use a unique password generated by a password manager. Existing version-1 vaults using the previous 12-character minimum still unlock so they can be migrated without losing access. The strict versioned format authenticates its header (including KDF parameters and wallet ID) and rejects malformed/oversized records. Passwords are never persisted or transmitted. Wrong passwords and altered ciphertext fail authentication. This is not a security audit or protection against malicious scripts/extensions executing in an unlocked browser.

Lock/reload requires either the saved local password or the recovery phrase. The recovery phrase remains the backup if storage is cleared or the password is forgotten. Save/unlock/password-change operations are invalidated by lock or wallet replacement; changes in another tab lock this tab. Change password requires the current password and matching open saved wallet. Explicitly deleting the device copy also deletes its saved activity, without moving funds. Temporary wallets remain available. JavaScript strings and garbage-collected copies cannot be reliably erased.

Saving also stores **authenticated encrypted activity** (chain, sender/recipient, amount, symbol, transaction ID and timestamps), capped at 100 rows. The version-2 activity envelope uses AES-256-GCM with fresh 96-bit IVs; a non-extractable key is derived from the high-entropy recovery phrase using HKDF-SHA256, the vault ID as salt and the separate `nodus.wallet.activity.v2` context. The envelope header is authenticated as AAD. It contains no recovery phrase, private key, password or custom provider URL/API credentials. Password changes preserve the vault ID and activity access. Activity is bound to the wallet but is not a proof that an RPC provider is honest.

Since 0.1.41 saving also stores the **last balances** (per asset: amount in base units, read time, the address read) in `nodus.balances.v1`: the same envelope shape (version 1) under a separate non-extractable key from the same HKDF with the `nodus.wallet.balances.v1` context, so neither key opens the other record. They are written only while a saved wallet is open; an unsaved wallet writes nothing (operator rule 2026-10-02). See "Last balances" under Multichain portfolio.

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

## Status line follows the submission (unreleased)

Operator 2026-10-03: after a send, delegation, undelegation, claim or chain
name registration the status line said "confirmation is pending" and never
changed, even once the transaction was in a block. It now follows the
Activity record that the existing tracker already polls (`src/activity.js`
`watchActivity`, 12 s; no second poller): `src/app.js` `followSubmission`
rewrites the line with `submissionStatus()` each time the tracker stores a
new answer on the record —

- NODUS: "… confirmed at block N (reported by one Nodus node)" once the
  block scan found the transaction (`src/adapters/nodus.js`
  `checkNodusActivity` now also returns the height as `block`; the saved
  activity format does not keep it), or "… expired. Not included before
  block X …" once the tip passes its expiry block (a claim: the claim state
  decides, as before).
- Other networks: "seen on the network, not final yet", then "confirmed" /
  "failed" / "was replaced" from the same checks Activity shows; the
  explorer link stays.

While the record is unresolved the submission text stays; "confirmed" is
written only after a check reported the transaction included. The line stops
following once the answer is final, or as soon as any other message replaces
it (another action, lock); the record itself is still tracked in Activity.
The tracker checks only the selected network's records, so while another
network is selected the line does not change. It is rewritten only when its text changes, so the
Nodus Connect toast (`src/connect-main.js`) re-appears once with the final
answer rather than on every check. Tests: `test/activity.test.js`
(submission status line), `test/nodus-send.test.js` (pending → confirmed at
block N / expired through `watchActivity` and the mock module).

## "Become a validator" removed from the page (unreleased)

Operator 2026-10-03: the "Become a validator" block of the Earn panel
(0.1.29) is gone from the wallet and Nodus Connect pages (`index.html`,
`connect-site/index.html`, its handlers in `src/app.js`). Delegate and
undelegate stay. The STAKE builder behind it is kept unchanged
(`src/adapters/nodus.js` `prepareStake` kind `'stake'`, the module's
`stakeBuild` op `'stake'`, `crypto/nodus-send-wasm.c` STAKING, and its test
in `test/nodus-send.test.js`); nothing on the page calls it now.

## Shared vaults — general multisig (unreleased)

Decision `docs/plans/decisions/2026-09-29-general-multisig.md` (M-of-N
address, at most 7 keys per address, auth_kind 3, a payment valid until
tip + 90 blocks; the Foundation 2-of-3) with design
`docs/plans/2026-09-29-general-multisig-design.md` §7 rev 2, decision
`2026-09-25-web-wallet-nodus-send-transport.md` (the wallet builds with the
same C code as nodus-cli), and the operator's product note of 2026-10-03
(create a vault in Connect by member names, the address computed by
Connect, members told by message and adding it with one tap, the
Foundation vault ready-made, anyone may open their own; a vault is listed
only for its members — watching any other vault is the user's own choice).

- **Where.** A "Shared vaults · NODUS" panel in the NODUS account area of
  both pages (`index.html`, `connect-site/index.html`; shown while NODUS is
  the selected network and the module is ready; nav link "Shared vaults").
  Code: `src/vaults/ui.js` (panel + Messages cards, registered as a wallet
  extension by `src/main.js` and `src/connect-main.js`), `src/vaults/core.js`
  (message kinds, kept record, states — no DOM, no module),
  `src/vaults/foundation.js` (the preset).
- **Create.** Members by chain name, by ID (128 hex) or — in Connect — from
  the contacts; this wallet is always a member; 2..7 members; approvals
  needed 1..N. "Check members" reads each member's SIGNED profile in the
  module (`nsw_msig_member_add` → `connect/nc_profile.c` `nc_profile_read`:
  signature and SHA3-512(key) == ID checked) and computes the vault code
  and address (`nodus_v2_msig_desc_from_keys`); the page shows the members
  and the address before "Create vault". A member's key never passes
  through JS.
- **Members told by message (Connect).** "Share with members" sends each
  member who is a contact an encrypted 1:1 Messages item (JSON, `"type":
  "nodus_vault"`, kind `share`: the vault code, a name, the block its
  history starts at). The receiver's chat shows a card; "Add vault" makes
  the module derive the address and the member IDs FROM THE CODE (nothing
  in the message names them), shows them with M of N, and a second tap
  adds it — only if this wallet is a member. The DNA Connect app (frozen)
  shows such items as raw text.
- **The Foundation vault** (`src/vaults/foundation.js`): the 7794-byte
  descriptor of `docs/plans/genesis-testnet/foundation_2of3.desc` (a local
  file) as hex, beside the decision's address `9885…30c6`; the module
  re-derives the address and the preset is listed only when it matches AND
  this wallet's key is one of the three. Members are shown by the chain
  name / short ID resolved for each key, never by a name written in this
  file (operator note 2026-10-03: one key is not the person its directory
  name suggests).
- **Balance and history.** Balance = `dnac_balance` of the vault address
  (public). Coins: no node lists an address's coins without its key
  (`dnac_utxo` is gated to the session's own ID, C11 — nodus-cli's `--msig`
  takes them by hand for the same reason), so the module FINDS them by
  reading committed blocks (`dnac_v3_block`, public) from the vault's first
  block: coins created for the vault, minus coins a later item consumed;
  200 blocks per step, up to 10 000 per "Refresh", resumable from the kept
  cursor. **Cost:** the first reading of a vault reads every block since it
  was created. **Genesis coins:** genesis outputs are in no block, so the
  Foundation vault's 5 starting coins are carried as DATA in
  `src/vaults/foundation.js` (`genesisCoins`: id = nullifier, amount; read
  by the ORCHESTRATOR from the live `utxo_set` on EU-1 and US-1, identical,
  2026-10-03). The vault's record starts from them (`genesis: true`) and
  block reading from height 1 drops one when a block consumes it, exactly
  like a found coin (`nsw_ms_apply_item`). They are NOT re-derived here:
  the id is SHA3-512("NDS.GENOUT.v1" ‖ source_commit ‖ index) and no RPC or
  build data carries `source_commit`; the chain checks each coin when it is
  spent. The `dnac_utxo` owner gate (C11) is unchanged.
- **Propose (Connect).** Pay to (address or chain name) + amount → the
  module builds nodus-cli's UNSIGNED vault spend (`nodus_v2_msig_build`:
  found coins largest first, the fewest that cover amount + fee; change to
  the vault; K = M; expiry tip + 90 via `nsw_expiry_for`; the generation the
  node runs) and reads it back. "Approve and send to members" signs and
  sends two items to every member contact: kind `request` (nodus-cli's
  export minus the unsigned auth blob — K zero slots + the descriptor,
  which the receiver rebuilds from its OWN copy of the vault code, so a
  7-key request fits one stored Messages record; the export bytes are
  nodus-cli's again on arrival) and kind `approval` (nodus-cli's signature
  text).
- **Approve.** A member opens the request: the module's read-back of the
  bytes at the node's current tip (`nodus_v2_msig_review`: shape,
  membership, the digest re-derived and EQUAL, call lengths, expiry not 0
  and not past the export's tip + 90; then **every coin it spends must be
  one of this vault's own coins** — the record's found + genesis coins,
  handed to the module before every review, approve and send; otherwise it
  is REFUSED, "this request spends coins this vault does not hold" (F1:
  the descriptor a request carries is rebuilt from the receiver's own
  vault code, so the coins are what binds it to the vault) —, every output
  native NODUS, expiry not past the node's tip + 90, expired = tip + 1 >
  last valid block) — recipient, amount, change back to the vault, network
  fee, last valid block. The message carries no description of the
  payment to show. "Approve" signs only if the request is still the digest
  that was shown, re-checking the coins on the bytes it signs. Reviews are
  kept per (vault, digest). nodus-cli `msig sign` also prints the last
  valid block and refuses an expiry of 0 or past the export's tip + 90.
- **Approvals count only when verified (F2).** Each approval is checked in
  the module against the reviewed request (digest, member,
  ML-DSA-87 signature) and only if the Messages item came from its own
  signer (sender ID == SHA3-512 of its key); only verified approvals are
  kept, one per key (a forged one cannot shadow a valid one), and the page
  shows and acts on that verified count. Items (requests, approvals,
  shares) from someone who is not a member of the named vault are ignored.
  At most 8 approval texts per member (newest first) are checked per
  review. Names beside IDs appear only when the chain's reverse lookup
  confirms them (F5); vault names refuse direction / invisible characters
  and mixed alphabets, and "Foundation vault" is reserved for the preset
  (F4).
- **Send.** With M verified approvals: "Send payment" — the first K
  verified combined
  (`nodus_v2_msig_combine`, ascending keys, pass-2 self-check) and sent with
  `dnac_spend`. The chain's own auth hook is witness code the browser
  cannot link (nodus-cli runs it locally); the node judges the
  authorization on arrival. **Expired:** after the last valid block the
  request shows "Expired — propose again"; nothing can sign or send it.
- **Kept.** In Connect with a saved wallet, one encrypted record per vault
  in the Messages history (`src/connect/store.js` `state.vaults` →
  record id `v` + 20 digits); otherwise for the session only. The wallet
  page has no Messages: vaults there live for the session and proposing /
  approving says to use Nodus Connect.
- **Same C code as nodus-cli.** `nodus/src/client/nodus_v2_msig.{c,h}` is
  the body of `msig address`, `v2-envelope spend --msig`, `msig sign` and
  `msig combine`, moved out (nodus-cli calls it); `send.wasm` links it with
  `shared/dnac/msig_wire.c` (`crypto/nodus-send-wasm.c` "VAULTS", the
  `nsw_msig_*` exports; TEST-only `nsw_test_msig_*`). Module contract: the
  optional `vault*` group (`src/nodus/client.js` `vaultable`).

Tests (written, not run by the change author): nodus ctest
`test_v2_msig` (the library vs the pre-move nodus-cli code byte for byte,
refusals, the read-back refusing changed fields, the combine through the
chain's auth hook) and `test/vaults.test.js` (message kinds and refusals,
the Foundation bytes against the documented address, kept record, states,
expiry, exports; with `NODUS_SEND_PARITY_OUT`: address / member parity with
the C and the read-back refusals — else SKIP). **How they can lie:** the
inputs are synthetic; no test talks to a node, reads blocks, or drives the
browser UI (`src/vaults/ui.js` wiring is untested); nothing proves a node
accepts a combined vault payment except `test_v2_msig`'s auth-hook check.

## Register a chain name (unreleased)

Decision `docs/plans/decisions/2026-10-02-onchain-names.md` (items 2–6, 10,
11, 16: first come wins, one name per ID, permanent; 3–36 of a–z0–9, an
all-hex name of 8+ characters refused; the price by length is the chain's,
votable) and design `docs/plans/2026-10-02-onchain-names-design.md` rev 4 §2.
The wallet and Nodus Connect (the same `src/app.js` and markup in
`connect-site/index.html`) can now register this wallet's chain name.

- **Where.** No panel of its own: a "Register a name" button beside Send /
  Receive / Earn, and a "Chain name" block in the NODUS receive part of the
  Send / Receive panel (shown while NODUS is the selected network). It
  shows this wallet's chain name if it has one (`dnac_name_of`); otherwise
  the prices by length and a name field.
- **Steps.** Type a name → "Check name": taken / this wallet already has a
  name / available with the price for its length (`nameQuote`,
  `src/adapters/nodus.js`; uppercase is lower-cased ASCII-only) → "Review
  registration": the module builds and signs, the usual review dialog shows
  the name, the owner (this wallet's Nodus ID), the price, the network fee,
  the total, the change, the rules (first come; a refused registration never
  pays the price — design §2; one name per ID; no expiry), a "Price change"
  row when a scheduled price change takes effect before the registration's
  last valid block, and the expiry → "Confirm & register" → the
  registration is tracked in Activity ("Chain name registration") like a
  send, its coins held until it is included or expires. When it is
  included the block re-reads and shows the new name.
- **Prices come from the node, never from this code.** The module reads
  `dnac_fee_info`'s name prices on the build call itself
  (`nodus_client_dnac_name_prices`; no answer → nothing is built) and the
  wallet never hands it a price; the price on the review is the one decoded
  from the signed envelope, and if it differs from the price shown at
  "Check name" nothing is shown ("the price of this name changed").
- **Same C code as nodus-cli.** The envelope is built by the shared builder
  `nodus/src/client/nodus_v2_name.c` (nodus-cli `name register` now calls it
  too), compiled into `send.wasm` (`crypto/nodus-send-wasm.c` "CHAIN NAME
  REGISTRATION": `nsw_name_prices`, `nsw_name_build`,
  `nsw_name_offline_build`, the `nsw_np_*` and `nsw_built_name` /
  `nsw_built_price` getters). Before building, the module repeats the CLI's
  checks on the same session: rule-set generation 2 or later (generation 1
  → "Chain names open at block H"), the name is free, this ID holds no
  name. The chain judges all of them again. Module contract: the optional
  pair `namePrices()` / `nameBuild()` (`src/nodus/client.js` `registrable`;
  a module without them still resolves names).
- **Not in the native vector.** The name section is compiled into the two
  emcc modules only (`scripts/build-nodus-send-native-vector.sh` does not
  link `nodus_v2_name.c`); its parity is TEST wasm vs the shipped wasm plus
  the call layout pinned against the nodus ctest `test_v2_name_build`
  fixture.

Tests (written, not run by the change author): `test/name-register.test.js`
(client gating, price list and tier, the quote, every refusal before a
build, every read-back field, a price change between quote and build, the
scheduled-change row, record-before-submit), the mock module's
`namePrices` / `nameBuild` (`test/nodus-mock-module.js`), and in
`test/nodus-send-wasm.test.js` the export list plus "name parity" (needs
`NODUS_SEND_PARITY_OUT`, else SKIP). **How they can lie:** the mock models
the module's rules with canned data; the parity tests use synthetic coins
and a made-up chain id and never talk to a node; nothing drives the browser
UI (`src/app.js` wiring is untested).

## Release build always includes Ixios (0.1.44)

The 0.1.43 release was built without `VITE_ENABLE_IXIOS=true`, so neither the
wallet nor Connect shipped any Ixios code (the flag is read only at
`src/app.js` — `import.meta.env.VITE_ENABLE_IXIOS === 'true'` — and nothing in
the tree set it; it depended on the builder's shell). Decision
`2026-09-23-ixios-send-mainnet-first.md` keeps Ixios visible in the live build.
0.1.44 pins the flag in `package.json`: `npm run build` and
`npm run build:connect` now always build with `VITE_ENABLE_IXIOS=true`.
No code change. The Ixios row still shows "Balance unavailable" until the
Ixios RPC stops sending `Access-Control-Allow-Origin` twice (their server).

## HF-4 client: rule-set generation, expiry cap, chain names (0.1.43)

Design `docs/plans/2026-10-02-onchain-names-design.md` rev 4 §1.6, §2
"Queries"/"Clients", §4 (R2, R3, R6, R12); decisions
`2026-10-02-onchain-names.md` (item 9: one node's answer is trusted —
accepted risk) and `2026-10-02-device-cache-only-when-saved.md`. Must ship
before the RULESET_GEN2 vote (design §1.5).

- **Which rules the node runs.** Before any NODUS envelope is built (send,
  stake, delegate, undelegate) the module asks the node `dnac_ruleset_info`
  and builds for the pinned generation (`nodus/include/nodus/nodus_ruleset_pins.h`,
  every generation) whose SYSTEM and CORE (version, hash) EQUAL the answer —
  never chosen by height; nodus-cli `cli_select_runtimes` is the reference
  (`crypto/nodus-send-wasm.c` `nsw_select_generation` / `nsw_gen_match`).
  An older node ("unknown DNAC method") or an unreadable answer: nothing is
  built. No matching generation: "This page is out of date … Reload the
  page." Each build asks again on its own call; `rulesetInfo()` (new,
  required in the module contract, `src/nodus/client.js`) only feeds the
  expiry the wallet requests. `unlock` checks every pinned generation's
  policy digest.
- **Expiry cap.** `tip + 90`, and for a generation-1 envelope while a switch
  height H is committed never past H−1, judged against the larger of the
  listing tip and the ruleset answer's tip; with H−1 not above it nothing is
  built ("try again after block H"). Same rule in JS (`src/adapters/nodus.js`
  `expiryHeightFor`) and C (`nsw_expiry_for`, which refuses any other value);
  nodus-cli `cli_env_expiry` is the reference. A capped expiry adds a
  "Rule change" row to the review, and a "Timing" row when at most 15 blocks
  remain (60 s review / 4 s minimum block gap, `nodus_witness_cmt_node.c`
  `timeout_commit`): it may expire before the user confirms; then nothing is
  spent and its coins are free after that block. The genesis claim is not an
  envelope and is unchanged.
- **Send to a chain name.** The recipient field takes an address or a chain
  name (`src/nodus/names.js`: 3–36 of a–z0–9, an all-hex name of 8+ refused —
  the JS mirror of `dnac_name_bytes_ok`; A–Z is lower-cased with an
  ASCII-only table; shared vectors `test/chain-name-vectors.js`, also run
  against the module's `nsw_name_ok`). An address of the selected network
  always wins, and address-SHAPED text is never a name: TRON text of 34
  characters starting with T/t or `41` + 40 hex, and EVM text starting with
  `0x`/`0X`, is refused as "Invalid … address" when it is not a valid
  address — never looked up (`looksLikeAddress` in `src/adapters/tron.js` /
  `evm.js`, used by `src/wallet.js`; a case-mangled TRON address lower-cases
  to a legal name). NODUS: `dnac_name_lookup` → the owner's fingerprint → the
  normal send. Ethereum / BNB Smart Chain / Solana / TRON: the owner's
  `eth` / `bsc` / `sol` / `trx` address from the owner's profile, read and
  signature-checked by the module with the Messages profile reader
  (`nsw_profile_address` → `connect/nc_profile.c` `nc_profile_read`); no
  field is used for another network. The review shows the name, the source
  ("looked up on one Nodus node", the block of that state), the owner's
  Nodus ID (other coins), the address, and a look-alike note in place of the
  address-check note. An unregistered name, an unreadable or unsigned
  profile, or a missing field is an error — never a fallback.
- **History.** The wallet reads no NODUS account history (table above:
  "NODUS — not yet"); its only `dnac_v3_block` reader is the module's
  confirmation scan, whose decoder (`nodus_client.c`) accepts the new
  `"nm"`/`"pr"` keys. A name registration therefore has no wallet row to
  render yet; Nodus Scan shows it.
- **Nodus Connect.** Contacts, requests, the conversation head, the home
  identity and "Your ID & profile" show the CHAIN name (`dnac_name_of`, at
  most one read per ID per session; a found name of this wallet or an own
  contact kept in the saved wallet's encrypted state `chainNames` — since
  2026-10-03 without expiry, a name being permanent; nothing kept for an
  unsaved wallet) as the title, with a check mark, a "chain
  name" label and the short ID beside it. The profile (network directory)
  name is shown only as "profile name …"; it is no longer the title. An
  older node or a failed read: no chain name, nothing kept.

Tests (written, not run by the change author): `test/hf4-client.test.js`,
`test/chain-name-vectors.js`, the mock module's new operations
(`test/nodus-mock-module.js`), the export list in
`test/nodus-send-wasm.test.js`. **How they can lie:** the mock echoes canned
answers; the C generation choice and name rule are checked only with the
parity build (`NODUS_SEND_PARITY_OUT`, else SKIP); nothing here talks to a
node or drives the browser UI.

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
  - Recipient: a 128-hex fingerprint (upper case accepted, shown lower case),
    or — HF-4 — a chain name resolved to its owner (section above).
    There is no checksum, so the review shows all 128 characters with a
    compare-every-character note. Amount: 8 decimals, `BigInt`, at most
    2^64 − 1 raw units.
  - Balance: the **spendable** native balance from `balance()` (the contract
    also carries `total`; `spendable > total` is rejected). Any failure is
    "Balance unavailable", never 0. Unpriced, outside the USD total.
  - Building: `balance()` then `list()`. Tip 0 or missing → **no send** ("The
    current Nodus block height is unknown"); otherwise `expiry_height = tip + 90`
    (`nodus-cli.c` `CLI_ENV_EXPIRY_AHEAD` = 100 − 10), capped at H−1 before a
    committed rule-set switch (HF-4, section above). An empty coin list with a
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
- **buildAndSign** — only coins of the last listing; the rule-set generation
  is chosen from the node's `dnac_ruleset_info` answer on this call, and
  `expiryHeight` must be exactly the expiry rule's value (listing tip + 90,
  capped at H−1 for generation 1 — see "HF-4 client" above); the chain id is
  re-read on the session;
  `gas_price` from `dnac_fee_info` (a failed read refuses); then nodus-cli's
  request for one native spend (fee floor `max(DNAC_MIN_FEE_RAW,
  NODUS_W_BASE_TX_FEE)`, largest-first, no shard) through
  `nodus_v2_spend_plan` / `nodus_v2_spend_build`. The review fields come from
  the builder's read-back of the envelope bytes and are checked again here:
  output 0 = recipient/amount/native, every other output = the sender (their
  sum = change), inputs from the candidates, inputs = amount + fee + change.
  The chain id is not a field of the envelope; it is the one the preflight bound
  into the envelope's ids (self-consistent, design §1.4).
- **evmBuildOffline** (0.1.65) — one EVM envelope with no session: the
  identity from the `seed` handed in (the module's copy wiped), every
  network fact given (generation, chain id, tip, gas price), the EVM leg's
  ruleset identity = the module's accepted smart-contract setting (checked
  in C against the compiled one); `nsw_evm_offline_build` → `nsw_evm_core`
  (see "Smart contracts" below). Not passed through `client.js`.
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

## Nodus Connect groups codec — G1 + G2 exports (unreleased, no UI)

Byte layer of Connect groups (design `docs/plans/2026-10-04-connect-groups-design.md`
rev 1; bytes `docs/plans/2026-10-05-connect-groups-bytes.md` items 1-7 + REV 2,
approved 2026-10-05; decisions `2026-10-04-connect-groups.md` items 1-11).
Pure C, no network, no clock, no storage; no page calls it yet.

- `connect/nc_group.h` / `nc_group.c` — tags, `salt_v`, DHT addresses
  (`"ncg:"` + hex, purposes HEAD / KEY PACKET / RECORD / OUTBOX), the key
  packet (fresh ML-KEM-1024 encapsulation per member after `ek_check`, KEK by
  HKDF-SHA3-256, RFC 3394 wrap, entries by `kem_ct`, owner ML-DSA-87
  signature; reader: structure, signature FIRST, group / version / owner,
  `prev_digest` conflict / unavailable, trial unwrap), the encrypted member
  record, HEAD, the signed group message and its accept rule, the per-sender
  day bucket (≤ 100 items, ≤ 1 MiB, text ≤ 4,000 B) and the invite / accept /
  welcome JSON (exact field set, `invite_id`). Every parser checks lengths
  before allocating, consumes exactly and refuses duplicates; secrets are
  wiped. `nc_group.h` documents every layout and rule.
- `connect/tests/test_nc_group.c` — every preimage, digest, address, KEK,
  wrapped key, record and bucket of the independent oracle's
  `test/fixtures/groups_kat.json` byte-compared; signatures verified (never
  byte-compared, ML-DSA signing is randomized); the oracle's `kem_ct` are
  not ML-KEM ciphertexts, so the packet vectors inject its shared secrets and
  the real ML-KEM path is a round trip; every reject case refused.
- `connect/nc_wasm.c` "groups codec" (G2) — the module's exports, linked into
  the wallet's one module by `scripts/build-nodus-send-wasm.sh` (source
  `connect/nc_group.c`): `nc_group_addr_str`, `nc_group_salt`,
  `nc_group_kp_new` / `_kp_read`, `nc_group_record_new` / `_record_read`,
  `nc_group_head_new` / `_head_read`, `nc_group_msg_new`,
  `nc_group_bucket_read`, `nc_group_invite`, `nc_group_accept`,
  `nc_group_welcome`, `nc_group_json_read`. All synchronous and pure (no
  network); results are one JSON object (`nc_result()`), bytes as lowercase
  hex, numbers as decimal strings; readers answer a `status`. Signing,
  decapsulation and the own fingerprint use the session's Messages keys;
  every other member's / owner's / sender's key comes from the verified
  profile cache (`nc_profile_get` / `nc_profile_load`), never from the page.
  The committed `src/nodus/send.wasm` is not rebuilt with them yet.

Group message text is at least 1 byte (decision 11, operator 2026-10-05):
seal, parse, bucket encode / decode and open all refuse an empty text. The
oracle's vectors predate the decision (reading 13 calls an empty text
valid); the test asserts that item, and the 2-item bucket that carries it,
as refused, and compares only their layout.

Not in G2: a bucket encoder export (sending a day bucket), group key /
group id / `addr_secret` generation, and the membership accept rule as an
export (the page applies it). `nc_group_bucket_read` reads buckets up to
256 KiB (the hex argument is copied onto the 1 MiB C stack); a full 1 MiB
bucket needs a heap input buffer export. (G3 below adds it, the
bucket send with its read, the secret generator and the network reads /
writes.)

## Nodus Connect groups — G3 page side (unreleased)

Groups in the Connect site: create a group, invite contacts, accept, send and
read group messages, members (the owner adds / removes), leave. Design
`docs/plans/2026-10-04-connect-groups-design.md` rev 1; bytes
`docs/plans/2026-10-05-connect-groups-bytes.md` items 1-7 + REV 2; decisions
`2026-10-04-connect-groups.md` items 1-18 (17 + 18: chain names, below),
`2026-10-02-onchain-names.md` item 4, `2026-09-30-nodus-connect-thin-core.md`
(S3: a read that could not be made never leads to a write; Q3 one device =
warning only; Q4 history at rest), `2026-10-04-connect-local-first.md`.
The committed `src/nodus/send.wasm` is NOT rebuilt here: the release build
regenerates it with the new exports.

**Module (C).** `connect/nc_group.c` / `.h`: `nc_group_kp_open_pinned` — the
welcomed member opens packet N against the welcome's `kp_digest` (it holds no
packet N-1; a different digest is a conflict), a reader rule, no new bytes;
the leave of decision 13 (`{"type":"nodus_group_leave","v":1,"group_id":…}`,
`nc_group_leave_encode`, parsed by `nc_group_json_parse`). `connect/nc_wasm.c`
"groups (package G3)":

| export | network | what |
|---|---|---|
| `nc_group_in_alloc(len)` | no | heap input buffer (≤ 1 MiB), filled by the page and consumed by the next export in the same queue slot |
| `nc_group_random()` | no | `{ group_id, group_key, addr_secret }` from the module's one random source |
| `nc_group_leave(gid)` | no | the leave JSON |
| `nc_group_get(purpose, gid, secret, x, owner)` | one read | HEAD / packet / record read with the pinned owner (owner-filtered paged read) |
| `nc_group_put(purpose, gid, secret, x)` | read + ≤ 1 write | the owner's HEAD (EXCLUSIVE) / packet / record (PERMANENT); the own row is read first in the same call: `wait` (unreadable), `unchanged`, `stale` (a newer HEAD), `conflict` (other bytes for that version), `taken`, `published`, `failed` |
| `nc_group_bucket_send(gid, salt, v, day)` | read + ≤ 1 write | the sender's day bucket: own row read in the same call, merged with EVERY own item the page keeps for it (heap buffer), EPHEMERAL 7 days; `wait` / `refused` (own row not a bucket) / `full` (> 100 items or 1 MiB) |
| `nc_group_bucket_fetch(gid, salt, v, day, key)` | one read | every sender's row (owner-less read), the row's owner must be its sender, every item verified and opened |

`nc_group_kp_read` gains `pinned_digest_hex`; `nc_group_bucket_read` reads a
bucket from the heap buffer when its hex argument is empty (full 1 MiB). A
read that returned only OTHER owners' rows counts as "no own row" for the
two writes (a removed member still knows the packet addresses, bytes §1, and
could otherwise stop the owner from publishing); every other unreadable read
is `wait`.

**Page.** `src/connect/core.js` exposes every group export (`group*`).
`src/connect/groups/model.js` holds the pure rules (accept rule of decision 6,
next member list, 30-day rotation / "key is old", bucket versions, order,
caps, stored-record checks); `groups/engine.js` the state machine:

- member: `invited` → (Join) `accepting` → welcome from the pinned owner →
  `joining` → packet N + record N read → `active`; a HEAD-announced packet
  without our entry → `removed`; Leave → `left` (hidden, the owner told);
  Ignore forgets the invitation (decline = no reply).
- owner: `active` from creation; joins (accepts), leave requests, removals and
  the key reaching 30 days stage the next version (record + key packet +
  HEAD, kept on the device first — the packet in pieces), published record →
  packet → HEAD LAST; only then is the version applied (members added or
  removed in the view) and the welcomes sent. A joiner whose profile has no
  ML-KEM-1024 key is refused by name; an existing member's key that cannot be
  read makes the change wait.
- each check (the 30-second Messages check, after the contacts): owner
  change; member catch-up (HEAD → walk v+1 … HEAD.v, each packet bound to the
  held digest); own unsent messages; today's and yesterday's buckets of the
  newest version and the one before it (never below the version that added
  this device — no pre-join history), the membership rule applied, messages
  deduplicated by (group, sender, message id).
- send: one at a time (the 0.1.55 rule); kept on the device first, then
  published; the composer empties once it is kept.

Invites, accepts, welcomes and leaves travel as 1:1 messages:
`nc_plaintext_is_chat` returns `nodus_group_*` texts as chat (it drops only
the old app's `group_invite`), so `ui/messages.js` takes every text that
claims one of the four types off the chat, hands it to the engine with the
authenticated 1:1 sender, and keeps it as a 1:1 record flagged `control`
(published, acknowledged and deduplicated like any message, never shown).
Invites only from a contact naming itself the owner; welcomes only from the
pinned owner for the invite accepted; accepts only for a pending invite of
that contact (consumed once); leaves only from a current member.

**Only people with a chain name (0.1.61; decisions items 17 + 18).** Group
membership is kept by the clients (not on the chain), so the clients enforce
it; no byte or wire format changed. The engine reads a name state per ID
through two page functions (`ui/messages.js` `groupNameStatus` /
`groupNameLookup`, over the same lookup as the rest of Messages,
`ensureChainName` → `nameOf` → `parseNameOf`): `found` = a chain name is
known (kept in `state.chainNames` or found this session — a name is
permanent, so one confirmed name is enough and is never asked again);
`none` = a lookup ANSWERED "no name" (never final: asked again on the next
check); `unknown` = no answer yet (never asked, or the lookup failed — a
failed lookup changes nothing). A name found by a group lookup is kept in
`state.chainNames` whoever it belongs to (a group member need not be a
contact), so a group's history shows at the next local open.
- create: refused without this ID's own confirmed name (`New group` says
  why; the dialog does not open); invite and join need it too.
- invite: only contacts whose name is confirmed; the New group list and the
  owner's Invite list show the others greyed out with the reason.
- join: an invitation whose owner has no confirmed name is not accepted (no
  accept is sent); the invitation says so when the answer was "no name".
- each check (`engine.js` `syncAll` → `checkNames`): every member, joiner,
  invitee and inviting owner without a confirmed name is looked up — at most
  once per ID per check, whatever the number of groups; the page also spaces
  lookups of one ID by `CHAIN_LOOKUP_SPACING_MS` (60 s). Opening a group or
  New group does one such round for the people shown.
- owner: a MEMBER answered "no name" is removed automatically, with no
  prompt, through `removeMember` — the same call as the owner's Remove — so
  the next version (record, packet, HEAD last) leaves it out. Done once: it
  is skipped while it is in `removals` or left out of a staged change, and
  once the version is out it is no longer a member. A joiner answered "no
  name" is not added (it stays listed as a joiner; the owner may withdraw
  it); one not answered yet waits.
- every member: messages of a sender without a confirmed name are kept on the
  device but not shown and not counted as new — hidden when the answer was
  "no name", waiting when there is no answer yet (shown once confirmed); the
  member list marks such a person ("no chain name" / "checking chain name");
  the group keeps working until the owner's change removes them.

**Storage.** `state.groups` (gid → its `g` record); key versions in `k`
records (all kept, decision 14), a staged packet in `x` pieces; group
messages in the `messages` store with a `group` field, loaded apart from the
1:1 list. Everything is sealed per record like the rest of the history;
memory only for an unsaved wallet. Records left behind by a finished stage
stay in the database (opened, not used).

**Screens** (`src/connect/groups/ui.js`): the Groups part of Chats
(invitations with Join / Ignore, group rows with unread counts, New group);
the group conversation (sender names, a banner for "the owner has not been
online for over 30 days", changes waiting, or "you are no longer in this
group"); Members (owner: Invite a contact, Remove with a confirmation; a
member: Leave). The Chats chip shows one-to-one conversations without groups.

**Tests (written, not run in this package):** `test/connect-groups.test.js`
(the state machine against a mocked core — what it proves and how it can lie
are in its header), `test/connect-groups-names.test.js` (the chain-name rule
of decisions 17 + 18 against a mocked lookup: create / invite / join refused
without a name, one lookup per ID per check, a failed lookup changes nothing,
the owner's removal happens once through `removeMember`, hidden and waiting
messages), `connect/tests/test_nc_group.c` (pinned open, leave
JSON), `test/connect-smoke.js` (the offline Groups part of Chats only).

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
  the conversation "Details" text of `src/connect/ui/diag.js`,
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
- Keys: `nc_unlock` (after the wallet's `nsw_identify` or `nsw_unlock` — it
  needs the identity only, not the connection) takes the words once,
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
  claim and staking). `src/connect/core.js` takes the wallet's client
  (`createNodusConnectCore({ nodus })`) and never loads or instantiates a
  module; API at the top of that file. Since the local-first open
  (2026-10-04) the client may be only IDENTIFIED: `connectLocal(run)` (same
  queue) runs the identity-only exports (`nc_unlock`, `nc_profile_load`,
  `nc_hist_*`), `connect(run)` the rest once 'ready'; on the C side every
  sending export binds the client per call and runs the wallet's own
  session check (`nc_host_session_ok` = `nsw_session_ok`, which also checks
  the chain id again after a reconnect to another pinned server).
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
| Contains | the wallet (portfolio, send / receive, earn, activity, device & settings) | an app in the shape of the DNA Connect app: Home, Chats (Messages), Wallet (the same wallet sections), More |

`connect-site/index.html` holds the wallet's markup (every id `src/app.js`
reads) inside an app shell; see "App layout" below. Keep the two files in
step when the wallet markup changes: every id `src/app.js` reads must exist
in both, and so must the two selectors it uses, `.wallet-card` and
`.wallet-navigation a[href="#send-form"]`. `npm run preview:connect` serves
`dist-connect/` locally. The wallet build carries no Messages or shell code:
only `src/connect-main.js` imports `src/connect/ui/`, and the shell's styles
live in `src/connect/ui/messenger.css`; `test/connect-smoke.js` checks
`dist/` for the shell, the Messages navigation and UI strings. (The
string "Message history" in the wallet's `app.js` chunk is the saved-wallet
delete text of 0.1.37, not Messages UI.) Ixios is a build flag in both:
`VITE_ENABLE_IXIOS=true npm run build:connect` for the same set as the wallet
site.

**Wallet extensions in Connect.** `src/connect-main.js` registers, before
`src/app.js` loads: Messages, the own-name display, the shared vaults
(`#vault-panel`) and — since 0.1.63 — the smart contracts (`src/evm/ui.js`,
`#evm-panel` / `#evm-root`, nav link `#nav-evm`), mounted the same way as on
the wallet page. The smart-contracts panel and its link stay hidden until
the connected node reports the EVM generation (HF-5, switching on at block
79,757), as on the wallet page.

**One unlock, one session, one lock.** `src/wallet-extensions.js` is the only
seam: `src/app.js` raises `attach`, `nodusReady`, `nodusConnectFailed`,
`nodusClosing`, `nodusUnavailable`, `ownName` (2026-10-03: the own chain
name from the reverse lookup, '' for none; `confirmed: true` only when the
lookup answered), `vaultDeleting` and `locked`, and asks (gather)
`nodusIdentified` (answered with promises it waits for) and `recipients`;
the wallet page
registers only the shared vaults. `src/connect-main.js` names the site (`configureSite
('connect')`), mounts Messages and registers `walletExtension` BEFORE it
imports `src/app.js`.
- Open, LOCAL FIRST (operator 2026-10-04: "everything once cached must show
  first, the network work runs in the background"): `startNodusSend` first
  IDENTIFIES the wallet's NODUS client (`client.identify` →
  `nsw_identify`: the identity from the seed, no session, nothing sent),
  then asks the extensions `gather('nodusIdentified', …)`; Messages answers
  with the promise of its local open on THAT client (`openMessages({ client,
  phrase, vaultId, fresh })` → `openLocal`: history store, contacts,
  conversations, kept profiles and pictures — the own one included — kept
  chain names, own ID; shown at once). Only after that settles does the
  wallet connect (`connectNodus` → `client.connectNetwork` → `nsw_connect`:
  pinned session + chain check): the client runs one operation at a time, so
  a connection queued first would hold the local steps. Then `nodusReady`
  starts Messages' network phase in the background (`goOnline` → `sync`:
  own profile read, or a fresh account's publish; the contact-list merge;
  the usual check) with a status line ("Connecting…", "Updating…", or the
  failure); nothing is sent before the own account was checked (`online`:
  composer Send, add contact, accept / withdraw, profile and picture save,
  vault items). A failed connection attempt keeps the client and the view
  (`nodusConnectFailed`) and is tried again on the SAME client after the
  RECONNECT wait; a node of another chain is final (the client locks itself,
  `nodusClosing` with a reason). Same words, same send.wasm module, same
  tier-2 session — no second unlock screen and no second session. `vaultId` is the saved wallet's id when the
  wallet was opened by unlocking its saved copy (or saved here before
  Messages opened): message history is then kept in IndexedDB (S8);
  otherwise memory only and no delivery confirmations (saving the wallet
  later takes effect at the next unlock). `fresh` is true only for words created and
  verified in this tab (decision thin-core Q1).
- Close: `stopNodusSend` raises `nodusClosing` BEFORE `client.lock()`, so the
  order of design §1.8 holds (Messages core, then the client). Lock, idle lock
  (10 min; typing in Messages counts as activity), `pagehide`, the single-tab
  takeover, a saved-wallet change in another tab and the cross-site rule all
  go through the wallet's `lock()`. The Lock entry in More IS the wallet's
  `#lock` button. A lost connection closes Messages with a reason; it reopens
  after the wallet is locked and opened again (`core.lock()` is terminal for
  the module instance). Deleting the saved wallet closes its open history
  first, so the delete is not blocked by this tab.
- Messages itself (`src/connect/ui/messages.js`) has no unlock, no Web Lock and
  no idle timer of its own; the sync, delivery, ACK, outbox and history rules
  are unchanged (`text.js`, `store.js`, `core.js`, the `nc_*` C code are not
  touched).

**Caches like the app's (0.1.41).** Operator rule 2026-10-02 (decision
`2026-10-02-device-cache-only-when-saved.md`): something is kept on the
device only for a SAVED wallet; an unsaved one keeps nothing after lock.
- Profiles (the app's profile cache, `profile_cache.h:40`, and
  `profile_manager.c:58-130`): a contact's profile row as read
  (`core.profileGet` now returns it as `record`) is kept in the encrypted
  history — one record per contact in the `state` store, id `p` + 20
  digits, indexed by `state.profileCache` (fp -> id, read time, verified
  name). For 7 days it is used instead of a network read: the core checks
  it again before its keys are used (`nc_profile_load` ->
  `nc_profile_check`: decode, ML-DSA-87 signature, SHA3-512(key) == fp; no
  network) and keeps the verified name only if it is still the row's
  registered name. Older: read again and replaced; if the network gives
  nothing, the older row is used (the app's stale fallback); if the
  network row fails its checks (`bad_record` / `bad_signature`) the kept
  row is dropped. Kept rows are loaded before the first screen, so names
  and pictures show at once. Strangers' requests are not kept.
- Smart sync (the app's, `transport_offline.c:37`, `:228-260`): the
  per-contact time of the last complete check is in `state.dmSync`; when
  any contact was never checked or the oldest check is over 3 days old the
  check reads 8 day buckets (today-6 .. today+1, `dht_dm_outbox_sync_full`),
  else 3. This closes a gap: messages sent 4-7 days before were never read.
  Stricter than the app: a contact counts as checked only when none of its
  buckets was unreadable. The time is saved when it moved by an hour or
  more. An unsaved wallet starts every session with the 8-bucket check.
- Day buckets (the app's blob cache, `dht_dm_outbox.c:30-80`; this session
  only, both kinds of wallet): `core.outboxFetchDay` returns the bucket's
  SHA3-256 (`blob`); passed back once that bucket's messages are stored, an
  equal bucket is not decoded (`unchanged`; `nc_outbox_fetch_day`
  `skip_blob`). A bucket with a message that did not verify is never
  skipped.
- Measured live 2026-10-02 (test identity B, saved wallet, one contact with
  a picture): first open 23 node requests, picture after 22.6 s; reopen 16
  requests, picture after 4.8 s.

**App layout.** The SHAPE follows the DNA Connect app
(`messenger/dna_messenger_flutter/lib`); the COLOURS are only the wallet's
(`src/style.css` tokens and the tints already used by the wallet and
`messenger.css`: lime accent, dark surfaces; no colour of the Flutter app).
One breakpoint, 900 px (the wallet's `SINGLE_COLUMN_DASHBOARD`).
- Before unlock: a start screen (`#start-screen`, centred): the mark,
  "nodus Connect", the address-bar check, then the wallet's own welcome /
  restore / create / unlock / session-conflict flows (same ids, same logic),
  "Delete saved wallet from this device", and links to Privacy & safety and
  the licences.
- After unlock (`#wallet-open`, shown and hidden by `src/app.js` as before)
  the app (`screens/home_screen.dart`): four entries Home, Chats (unread
  count), Wallet, More (count of contact requests waiting). Below 900 px one
  screen at a time with a 64 px bottom bar (`dna_bottom_bar.dart`: icon over
  label, active line, badge at the icon); from 900 px a centred app window
  (max 1200 px) with the same four entries as a left rail. Each screen has a
  sticky top bar (`dna_app_bar.dart`).
- Home: your ID (your profile picture or initials, verified name, short ID,
  Copy — available once Messages is open), "Wallet open in this browser", the wallet's estimated value and
  NODUS balance shown again read-only from the Wallet screen, an "Open
  wallet" button, and New chat / Send / Receive (Send and Receive open the
  Wallet screen and press the wallet's own `#quick-send` / `#quick-receive`).
- Chats: Messages (below). A screen opened from it (a conversation,
  Contacts, Your ID & profile) covers the bottom bar below 900 px, as a
  pushed screen does in the app.
- Wallet: the wallet's sections unchanged in ids, forms and behaviour
  (section links as chips, portfolio, network actions, assets | send /
  receive or earn, activity, device & settings); only the outer frame
  differs. While the wallet is open, "Delete saved wallet from this device"
  is moved into Device & settings (the same element, moved back on lock).
- More (`screens/more/more_screen.dart`): Your ID & profile, Contacts,
  Contact requests (count), Address book (opens the Wallet screen at the
  wallet's `#address-book-panel`), Device & settings, Privacy & safety,
  Licenses, and Lock (the wallet's `#lock`).
- Privacy & safety (`#about-screen`): the wallet page's privacy, storage
  and care texts as one screen with Back, reachable before and after unlock;
  in-page links to them (`#privacy`, `#storage-guide`) open it.
- The wallet's status line (`#wallet-status`) is a bar above the bottom bar
  while it has text, with a Dismiss button (shown again on the next message).
- `src/connect-main.js` drives the shell: it watches `#wallet-open`'s
  `hidden` to switch to Home on unlock, shows the screen holding the target
  of an in-page link before the link's own handlers run, mirrors the two
  wallet numbers on Home, and hosts Messages' navigation callbacks. It never
  writes into the wallet's state.

**Messages layout** (`src/connect/ui/messages.js`, also used by `/preview/`).
- Chats (`screens/messages/messages_screen.dart`): a top bar "Chats" with
  Contact requests (count) and Your ID & profile; filter chips All / Unread
  (count) / Chats (count) — Chats shows the same list as All, as in the app
  without groups; an entry "N contact requests are waiting for you" while
  some are; the conversations, most recent first — the avatar (40 px, see
  "Profile pictures" below; never from a claimed name), the verified name or
  else the short ID in bold, a claimed name only as "claims the name …", the last message, on the right
  its time and an unread count, a chevron (unread counts are kept in memory
  for this session only); an add-contact button at the bottom right. While
  Messages is not open, Chats shows its status (waiting / opening / closed,
  with Try again where it applies) instead of the chips and list.
- Conversation (`screens/chat/chat_screen.dart`): its own screen with Back,
  the 32 px avatar, the verified name or short ID and a claimed name; bubbles with 16 px corners, the
  sender's bottom corner 4 px, 12 x 8 padding, 48 px kept free on the other
  side; own messages right on the lime accent, received left on a neutral
  surface; time and status (own: "waiting to send" / "sent" / "delivered";
  received: the "sender's clock") small at the bubble's foot; day separators.
  The composer is pinned at the bottom: a rounded field (grows to 5 lines,
  Enter sends, Shift+Enter is a new line, not while an input method composes,
  4000 characters) and a round send button. From 900 px Chats stays on the
  left and the conversation opens on the right (no Back there).
- Contacts (`screens/contacts/contacts_hub_screen.dart`): Back, Add contact,
  tabs Contacts / Requests (count); each contact has "Remove contact" (asks
  to confirm; see "Remove a contact and the address book" below); Requests
  lists incoming (Accept / Decline) and sent (Withdraw) requests.
- Your ID & profile: your ID (Copy), your picture (Change picture / Remove
  picture), the profile form, the not-saved note and "Delete message history
  on this device".
- Profile pictures (0.1.40). The avatar everywhere (Chats, Contacts,
  requests, the conversation bar, Home, More, Your ID & profile) is the
  profile's `avatar_base64` — the field the app writes (128x128 JPEG,
  quality 80, plain base64; `profile_editor_screen.dart:507-516`,
  `dna_engine.h:377`) in the signature-checked profile — else two letters of
  the verified name, else of the ID. `text.js avatarSource` shows it only when
  it is canonical base64 of at most 20480 characters whose bytes start like a
  JPEG or a PNG; the `data:` type comes from those bytes (CSP `img-src` allows
  `data:`), and the image is set as a property (`dom.js fillAvatar`), with the
  initials back if the browser cannot decode it. Change picture takes a JPEG,
  PNG or WebP (at most 20 MB), crops its centre square, scales it to 128x128 on
  a canvas (transparent parts white) and encodes JPEG at quality 0.8, stepping
  down to 0.4 until the base64 fits the app's own 18000-character limit
  (`profile_editor_screen.dart:516`); it is saved as a patch of
  `avatar_base64` alone (`core.profileUpdate`: the core applies it to a fresh
  read of the profile, `nc_profile.c nc_profile_publish`), Remove picture
  writes `''`. Everyone can read it, as in the app.
- Add contact (`screens/contacts/add_contact_dialog.dart`): a modal dialog
  (their ID, an optional note, Send request / Close).
- Host callbacks (`mountMessages(root, host)`): `onUnread`, `onRequests`,
  `onIdentity`, `onScreen`, `onBack`, all optional; `messagesNavigate()`
  opens Chats, Contacts, Requests, Your ID & profile or the dialog.
All text goes through `textContent` (`dom.js`), other people's text in
`<bdi>` with the unusual-character marker, websites only as checked https
links, icons built with `createElementNS`; no innerHTML, no inline styles
(CSP `style-src 'self'`). Styles: `src/connect/ui/messenger.css`.

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
screen and the Contacts / My profile tabs are replaced by the Messages layout
above; with no host callbacks, the Chats bar's Contact requests and Your ID &
profile buttons are the way to those screens there. The app shell's rules in
`messenger.css` are scoped to `body.connect-app` and do not apply to it.

**Tests.** `npm run test:connect` (`test/connect-smoke.js`, after `npm run
build` and `npm run build:connect`): the wallet `dist/` has no app shell,
Messages navigation or UI strings; one unlock opens the app on Home (no
second unlock screen) with Home / Chats / Wallet / More as a left rail at
1280 px and a bottom bar at 390 and 320 px; the Wallet screen shows the
wallet's sections and holds "Delete saved wallet" while open (back on the
start screen after lock); Chats is Messages opened LOCALLY with no node
(2026-10-04, local first: the own ID, the empty list and the add button at
once; the status line "Connecting…" or the failed-attempt text; sending a
contact request and saving the profile are refused offline); a fresh
`wallet` mark refuses the unlock; no horizontal scroll at 390 and 320 px on
any screen; the Lock in More locks the wallet and Messages. The Home name entry
stays visible and disabled offline, resets on lock/reopen, and the real save /
delete flows show only their appropriate password controls with confirmation.
NOT covered: every node WebSocket is closed by the test, so Messages opens
only locally, initially for an unsaved wallet with no history (the save/delete
checks follow) — no contact, no conversation, no request: the composer's and the requests' offline
refusals, kept history and Contacts are not reached; whether the failed
attempt was already reported is not asserted; sending, receiving, requests
and profile editing need a live node.
Not verified: nothing in this section has been run in a browser yet.

## Remove a contact and the address book (unreleased)

Operator 2026-10-03: contacts can be added and removed in Contacts; when
sending, an address book like the DNA Connect app's — for every network the
wallet sends on, not only NODUS.

**Remove a contact (Nodus Connect, Contacts tab).** Each contact has "Remove
contact"; the first press asks ("Remove this contact from this device? …"),
"Confirm: remove this contact" removes it, "Keep" cancels. What happens
(`src/connect/ui/messages.js` removeContactAction, `text.js` removeContact):
- The contact leaves the list on THIS device; its conversation is no longer
  shown and its messages are no longer checked.
- **Messages are kept** on this device (hidden), and so are the ACK values
  (no second delivery confirmation for messages already confirmed). If the
  person becomes a contact again (a request accepted either way) the history
  is there again. The kept profile row index, the chain name and the
  message-check time of that contact are dropped (the app drops its key cache
  on removal too, `dna_engine_contacts.c:253`).
- **The own contact list on the network is NOT changed.** The core only adds
  to it — `nc_contactlist_add` is merge-only by design (`connect/nc_core.h`,
  "MERGE ONLY, never fewer entries") and there is no export that writes a
  shorter list. So other devices and the DNA Connect app keep listing the
  person, and this device must not take them back from that list: the removed
  IDs are kept in the history state (`state.removed`, `src/connect/store.js`;
  saved wallet only — an unsaved wallet forgets the removal on lock, and the
  network list brings the contact back at the next open). Publishing a
  removal needs a C change in `web-wallet/connect/` (an export that reads the
  list in the same call, drops exactly the named IDs and writes it with
  `nc_contactlist_build`, like the app's `messenger_sync_contacts_to_dht`) —
  not made here.
- The removed person can send a new request; it shows under Requests.
Adding a contact is unchanged: Add contact in the Contacts bar (and on Chats).

**Address book (wallet page and Nodus Connect, Wallet screen).** A panel
"Address book" (section link and, in Nodus Connect, More → Address book)
lists saved recipients `{ label, network, address }` — one entry per network
and address (the same address on two networks is two entries) — with Edit and
Delete (asks to confirm), and a form Name / Network / Address. Rules
(`src/address-book.js`, pure; `test/address-book.test.js`):
- Name: required, trimmed, at most 48 characters, no line breaks, no
  invisible or direction-changing characters, no mixed alphabets — the vault
  name rule (`src/vaults/core.js vaultLabel`, `connect/ui/text.js
  inspectUntrusted`). It is the user's own text, shown through `textContent`.
- Address: checked by that network's own check, the ones the send path uses
  (`src/app.js` ADDRESS_CHECKS): Ethereum and BNB Smart Chain
  `isRecipientAddress` + `getAddress` (a wrong mixed-case checksum is refused;
  the checksummed form is saved), Solana and TRON `isRecipientAddress`, NODUS
  `nodusRecipient` (128 hex, saved lower-case), Cellframe
  `validateCellframeAddress` (structural only — Base58, 100–110 characters; no
  checksum check exists in this tree). Cellframe entries can be saved, but
  Cellframe sending is not available, so they are never offered. Ixios is not
  in the list.
- At most 200 entries; shown by name (letter case ignored), then network,
  then address.
- **Send form:** under the recipient field, "Or choose a saved recipient"
  lists the entries of the selected network only (on Nodus Connect, also the
  contacts for NODUS: a contact's ID is its NODUS address — `core.js` refuses
  an identity whose fingerprint differs from the NODUS client's — labelled by
  chain name or short ID, never a profile name). A choice only fills the
  recipient field; the send is checked and reviewed exactly as if the address
  had been typed. The wallet's own address is not offered.
- **After a plain send** (not staking, a name registration or a claim), if
  the recipient is not saved: "… is not in your address book" with "Save this
  address", which fills the form (network and address fixed by the send; a
  chain name the send went to is the suggested name).
- **Storage** (decision `2026-10-02-device-cache-only-when-saved.md`): with
  a SAVED wallet, encrypted in `localStorage['nodus.addressbook.v1']` — the
  same envelope as the saved balances (AES-256-GCM, random 12-byte IV, header
  as additional data) under its own key (HKDF info
  `nodus.wallet.addressbook.v1`, `src/activity-storage.js`
  serializeAddressBook / parseAddressBook); read back and checked again at
  unlock. An unsaved wallet keeps it in memory until lock (the panel says so);
  saving the wallet saves it. A saved book that does not authenticate is not
  shown ("could not be read; saving an address replaces it") and is left as it
  is until an address is saved. A failed write is reported, not hidden.
  Deleting the saved wallet deletes it. Per origin: the wallet site and the
  Nodus Connect site have separate address books (decision
  `2026-10-01-connect-own-origin.md`). Not synced to other devices, and not
  shared with the DNA Connect app's address book.
- Extension question `recipients({ network })` (`src/wallet-extensions.js`
  `gather`): how Messages offers contacts; every address is checked by the
  wallet again before it is shown.

Tests: `test/address-book.test.js` (`npm test`) — names, per-network
address checks, add / edit / delete / duplicates / limit / order, the stored
list re-check, the encrypted record (own key, vault id bound, tamper
refused), and contact removal (not merged back from the network list, cleared
when added again, the saved state's `removed` field). Not verified: nothing
in this section has been run in a browser yet; `test/connect-smoke.js` does
not reach Contacts (Messages opens there only locally, with no contact).

## Validator delegator count (node side only, unreleased)

The node's validator list reply now carries each validator's delegator count
(`dlg`, of the chain's 2048-per-validator cap) and the shared client decodes
it (`nodus_dnac_validator_list_entry_t.has_delegator_count` /
`delegator_count`); the wallet does NOT show it yet — `send.wasm` has no
getter for it, and the export list and `src/nodus/send-module.js` are not
changed.

## Smart contracts — the Nodus EVM domain (unreleased, wired, not run in a browser)

Design: `docs/plans/2026-10-04-nodus-evm-chain-integration-design.md` rev 3 §2
(envelope = `[CORE EVMFUND leg, op 9]` + `[EVM leg, domain 2, ops 1 CALL /
2 CREATE / 3 DEPOSIT / 4 WITHDRAW / 5 REDEEM]`; the EVM sender is
SHA3-512(ML-DSA-87 public key)[0..32]; the fee is a CORE-funded DECLARED
ceiling), §5 (1 raw unit = 10^10 wei; withdrawal tickets), §7 (receipt
encoding), §16 (wallet), §18 (the read RPC). Decisions
`2026-10-04-nodus-evm-kurultay-k1.md` (operator 1, 3, 4) and
`2026-10-04-nodus-evm-kurultay-k2-summary.md` (operator 2: one pending EVM
transaction per sender — the SDK waits for inclusion before it builds the
next).

**The panel is wired:** `NODUS_EVM_NETWORK` in `src/nodus/send-module.js`
carries the EVM ruleset identity, the module exports `evmBuild` and
`evmQuery`, and the nodus client has the §18 requests
(`nodus/src/client/nodus_client.c` `nodus_client_evm_*`). The panel is shown
when the connected node's `dnac_ruleset_info` names the EVM generation (the
`EVM_ACTIVE` vote) — on a chain without it, it stays hidden. **It has not
been run in a browser** — every statement below is from the code and the
Node tests, not from a page.

What exists:

- **Call bytes** — `../shared/dnac/evm_call_wire.{h,c}`: encode + strict
  decode of the five EVM ops (big-endian, exact length, trailing bytes
  refused, CREATE initcode ≤ 49 152) — the same byte strings the node's
  `nodus_witness_rt_evm.c rtevm_decode` accepts — and of the CORE EVMFUND
  call `ver ‖ role ‖ in_count ‖ nullifiers ascending ‖ out_count ‖ 232-byte
  change`. The node decodes CORE op 9 with this same codec
  (`nodus/src/witness/nodus_witness_rt_native.c` `rtn_evmfund_parse` →
  `dna_evmfund_decode`); roles FEE 1, DEPOSIT 2, RELEASE 3.
- **Build + sign** — `crypto/nodus-send-wasm.c` "SMART CONTRACTS":
  `nsw_evm_call / _create / _deposit / _withdraw / _redeem` on the staking
  builder's path (listed coins, ascending by nullifier until lock + fee,
  deterministic change seed, one key signs both legs with
  `nodus_v2_env_sign_one_key`, read-back of both legs before anything is
  kept) — since Nodus EVM Faz 4 through the shared builder
  `nodus/src/client/nodus_v2_evm.c` (nodus-cli `evm` uses the same).
  Units (`nodus_v2_evm.h` "UNITS"): the static units of both legs
  (`dna_meter_plan_build_ex`, the EVM leg streamed) + the funding leg's
  reads (in_count + 1 for FEE, + 2 for DEPOSIT / RELEASE) + for CALL/CREATE
  `gas_limit × w_gas + FAIL_RESERVE`, for a bridge op its two reads; `0` =
  that minimum plus, for CALL/CREATE, the read units the node's
  `evm_estimate` implies (`ue − ref`, checked below); an explicit ceiling
  below the minimum is refused. Fee = max(floor, units × gas price). The
  leg declarations: the funding leg EXACT from its shape
  (`nodus_v2_evm_fund_decl`), a CALL/CREATE leg 256 / 65 536 by default,
  a bridge leg EXACT (`nodus_v2_evm_bridge_decl`: 2 effects, 468 or 352
  bytes).
  The node's `evm_estimate` answer (one node's) is REFUSED, never clamped,
  when malformed (red-team 1 F9): `ue` below the reference shape's units,
  or read units `ue − ref` above `(EVM_READS_BASE + 2 × access-list keys) ×
  w_read` (`nsw_evm_core`); `gu > ge` or `ge` above the 30 000 000 cap
  (`src/evm/contract.js`). A built fee above the local bound
  `EVM_MAX_FEE_RAW` (50 NODUS — a placeholder; ≈ 36 NODUS is a full-cap call
  at the genesis price of 121 raw / unit) is refused before review, because
  both the units and the gas price come from the node.
  **Offline** (0.1.65): `nsw_evm_offline_build(gen, op, chain, tip,
  gas_price, evm_ver, evm_hash, to, value, gas, nonce, amount, dest, ticket,
  units, expiry)` — no node; the identity from `nsw_seed_buf`, every network
  fact given, `gen` ≥ `NODUS_RT_GEN_EVM` (its pinned policy weighs CORE op
  9; no test op weight in the shipped module), the EVM identity equal to the
  compiled one or refused, expiry exactly tip + 90; the same `nsw_evm_core`
  and read-back. Fields per op: CALL to / value / gas / nonce; CREATE value
  / gas / nonce; DEPOSIT amount / nonce; WITHDRAW amount / nonce / dest;
  REDEEM ticket / amount / dest — every other field absent (`""` / `"0"`).
  JS: `send-module.js` `evmBuildOffline`.
  A deployment's address is computed from the SIGNED envelope's sender and
  nonce (`nsw_evm_built_created`, the shared rule
  `nodus/src/client/nodus_v2_evm.c nodus_v2_evm_create_address` = the
  engine's `evm_compute_contract_address` in 32-byte mode) and compared
  with the receipt's `cr`.
- **SDK** — `src/evm/`: `address.js` (32-byte addresses, the 64-digit
  EIP-55 checksum of the Nodus solc, 20-byte addresses refused, the ticket
  system address), `abi.js` (Solidity ABI with `address` = the full word,
  strict decoding, selectors, event topics, revert reasons), `units.js`
  (raw ↔ wei, 18 decimals), `rpc.js` (the §18 reply checks and the §7
  receipt digest re-computed from the fields), `contract.js` (`EvmAccount`:
  nonce from `evm_account`, one pending transaction at a time, receipt
  polling 2 s ×1.5 up to 15 s until the receipt or the expiry block;
  `Contract`: read, estimate, write, deploy, log decoding).
- **Client** — `src/nodus/client.js`: `evmBuild` (group EVM_BUILD_OPS) and
  one method per §18 query over the module's `evmQuery({ method, args })`
  (group EVM_QUERY_OPS) — arguments checked and tagged, replies checked.
- **Panel** — `src/evm/ui.js` (wallet extension, `src/main.js`): the
  smart-contract address and balance, move NODUS in / back (the recipient
  defaults to this wallet's own address), withdrawal tickets + collect,
  open a contract (address + ABI: read and write functions) or deploy one
  (bytecode + ABI), a review dialog filled from the module's read-back
  (destination, value, fee ceiling, resource ceiling, chain id), and each
  transaction's outcome: done / ran but failed (fee charged) / not included
  (nothing charged), the inclusion block (a receipt's `h`, design §18
  rev 5), gas used, events, new contract address — every receipt line is
  labelled as reported by the connected node (its digest matches its
  fields; binding it to the chain's `LastResultsHash` is not implemented).
  The extension receives with `nodusReady` (`src/app.js`):
  `lockedInputs()` (coins of pending NODUS sends are never offered),
  `evmRecord(details, { title, amount })` and `evmPending()`.
- **Activity + the one-pending reservation (red-team 1 F8).** Confirming
  writes the transaction's Activity row — the same NODUS row a send writes
  (intent id, expiry block, first scanned block, input coins), so
  `lockedInputs` holds its coins against every other send — and saves it
  BEFORE the envelope leaves the browser; if it cannot be saved nothing is
  sent. The row is the account's reservation: the next smart-contract
  transaction is refused while an unresolved row may be this account's
  (`evmPending`: marked `evm` in this tab; after a reload — the saved
  Activity does not keep the mark — any unresolved row to this wallet's
  own address, which over-matches self-transfers and name registrations).
  A submission whose outcome is uncertain, and a receipt-polling error, do
  NOT release it: only a receipt, the chain passing the expiry block, or
  the Activity tracker resolving the row does. Restored with the saved
  Activity on unlock, before the panel opens.

Missing before anyone can use it:

- A browser run: nothing here has been run in a browser.

(`src/nodus/send-module.js` reads `nsw_evm_built_created` into
`decoded.created` since `b50b9c9a` — `send-module.js` `evmBuild`, exported by
`scripts/build-nodus-send-wasm.sh`; a deployment's receipt address is then
checked against it (`createdCheck`). "as reported by the node; not checked"
remains only for a receipt `cr` with no locally computed address,
`src/evm/ui.js:390-391`.)

Tests (written; how they can lie is in each file's header):
`test/evm-units.test.js`, `test/evm-address.test.js` (checksums against the
Nodus solc's own diagnostics), `test/evm-abi.test.js` (selectors / topics
against `solc --hashes` of `test/fixtures/evm-sample.sol`, encodings against
ethers 6 with `address` as `uint256`), `test/evm-client.test.js` (§18
argument tagging, reply checks, §7 digest assembled independently, the
one-pending queue — on the TEST-ONLY mock module),
`test/evm-call-wire-wasm.test.js` (the C codec and an offline DEPOSIT build
through the parity wasm — skipped without `NODUS_SEND_PARITY_OUT`; a skip is
not a pass). Red-team 1 (F8–F11) added: the ABI decode budgets with
aliased-offset bombs and the parse-time type bounds (`evm-abi.test.js`);
the record-before-submit order, the row shape `lockedInputs` holds, the
reservation kept on a refused submission / a polling error / a restored
row, the malformed-estimate and fee-limit refusals, `createdCheck`
(`evm-client.test.js`); the CREATE-address rule against the engine's oracle
vectors read from `shared/evm/tests/addr32_vectors.h`, an offline CREATE's
`nsw_evm_built_created`, and the offline CALL estimate bounds
(`evm-call-wire-wasm.test.js`, parity — skipped without
`NODUS_SEND_PARITY_OUT`). The shipped offline build (0.1.65,
`evm-call-wire-wasm.test.js`, skipped without `NODUS_SEND_PARITY_OUT` and
`NODUS_SEND_VECTOR_BIN`): at the real EVM generation and the compiled EVM
identity, for DEPOSIT, WITHDRAW, CALL (data + an access-list entry), CREATE
and REDEEM the TEST wasm and the native vector build the same envelope and
read-back byte for byte, the shipped wasm the same intent_id with a
different wire_id; `evmBuildOffline` on the shipped build gives the native
intent_id and fields; the refusals (generation, EVM identity, expiry, a
foreign field, unknown op, data on a transfer) build nothing and the seed
buffer is wiped. Inputs synthetic: the builds agree with each other; no
node accepts anything here. Vectors: `test/fixtures/evm-solc-vectors.json` (generator line
inside).
