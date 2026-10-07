# @nodus/evm-sdk — the Nodus EVM for Node.js scripts

A small Node.js (ESM) library for scripts that use the **Nodus EVM** (smart
contracts on the Nodus chain): derive an identity from a 24-word recovery
phrase, connect to a Nodus node, read EVM state, and deposit, withdraw,
deploy and call contracts — each write only after the caller confirms the
reviewed fee.

**In-repo only.** This package is `private` and is **not published to npm**
(decision `docs/plans/decisions/2026-10-06-evm-dev-tooling.md` item 3; a
publication is a later, separate decision). Use it from a checkout of this
repository.

It is the web wallet's code, not a re-implementation: identity derivation,
addresses, the ABI codec, units, the read-reply checks, the review /
one-pending queue (`web-wallet/src/evm/*`, `web-wallet/src/nodus/*`) are
**imported** from `web-wallet/src`, and signing is done by a
node-environment build of the **same send module** the wallet ships
(`web-wallet/crypto/nodus-send-wasm.c` + the nodus client + the shared
envelope builders, the same sources and C flags; `send-node.wasm` is
byte-identical to the wallet's `src/nodus/send.wasm`, checked by
`test/module.test.js`).

> **The EVM is not active until block 79,757 on the testnet.** HF-5 (the
> `EVM_ACTIVE` vote, decision `2026-10-06-hf5-evm-activation.md`; height as in
> `web-wallet/README.md` "Smart contracts in Nodus Connect too") switches it
> on. Before that, a connected node does not run the EVM rule-set generation:
> `evm.evmActive` is `false` and every EVM read or write says "Smart
> contracts are not active on the connected node". That is expected, not a
> bug.

## Requirements

- **Node.js ≥ 22.12.0** (the wallet's `engines`).
- **`npm ci` in `web-wallet/`** — the imported wallet files resolve `ethers`
  and `@noble/hashes` from `web-wallet/node_modules` (Node resolves a bare
  import from the importing file's own package). `npm ci --omit=dev` is
  enough.
- **`npm ci` in `sdk/js/`** — installs `ws`, which the node-environment
  Emscripten glue loads for its WebSocket (`require('ws')` under
  `ENVIRONMENT_IS_NODE`, emsdk `src/lib/libsockfs.js`).
- **The send module, built:** `bash scripts/build-wasm.sh` (or `npm run
  build:wasm`). It runs `web-wallet/scripts/build-nodus-send-wasm.sh parity`
  with its output in `sdk/js/wasm/` (gitignored) — nothing is forked; every
  source list, flag and toolchain check is the wallet script's. That script
  needs:
  - **Emscripten 6.0.10 exactly** (`EMSDK`, default `~/emsdk`; it refuses
    any other version),
  - OpenSSL 3.0.15 for wasm (`OPENSSL_WASM_PREFIX`, default
    `~/wasm-deps/openssl-3.0.15-wasm`; `web-wallet/scripts/build-openssl-wasm.sh`),
  - json-c 0.17 for wasm (`JSONC_WASM_PREFIX`, default
    `~/wasm-deps/json-c-0.17-wasm`; `web-wallet/scripts/build-jsonc-wasm.sh`),
  - a `sqlite3.h` (`SQLITE3_H`, default `/usr/include/sqlite3.h`; declarations
    only).

  The parity mode writes two builds; the SDK loads **only `send-node.mjs`**
  (release flags, `-DNODUS_SEND_RELEASE`, hedged signatures). The other,
  `send-test-node.mjs` (fixed randomness, test-only exports), is never loaded.

```
cd web-wallet && npm ci --omit=dev && cd ..
cd sdk/js && npm ci && bash scripts/build-wasm.sh
npm test                     # offline unit tests
```

## API

```js
import { NodusEvm, Interface, parseRaw, parseWei } from './sdk/js/src/index.js';

const evm = await NodusEvm.connect({ phrase: process.env.NODUS_PHRASE });
```

Amounts are `BigInt`: **raw NODUS units** (1 NODUS = 100 000 000 raw) for
NODUS-side amounts and fees; **wei** inside the EVM (1 raw = 10¹⁰ wei, so
1 NODUS = 10¹⁸ wei = "1 ether" in Solidity). Addresses are **32 bytes**:
`"0x"` + 64 hex (any of: lower case, upper case, or the correct checksum);
results come back as 64 lowercase hex (`evm.address`, receipts, logs) or
checksummed text (ABI-decoded values).

### Opening and closing

| Call | What |
|---|---|
| `NodusEvm.open(options)` | Derives the identity from the phrase and loads the send module — **no network**. State `'identified'`. |
| `evm.connect()` | Opens the pinned session (ML-KEM-1024, the server's ML-DSA-87 key must be pinned) and checks the chain id; then asks the node whether it runs the EVM generation. State `'ready'`. |
| `NodusEvm.connect(options)` | `open` + `connect`; locks the module if connecting fails. |
| `evm.close()` | Locks: session closed, the module's whole linear memory zeroed, the instance released. The Emscripten glue prints `Aborted(Nodus send module released)` to stderr at this point — that is the release, not an error. |

`options`:

| Option | Default | |
|---|---|---|
| `phrase` | required | the 24-word recovery phrase |
| `network` | the wallet's testnet (`DEFAULT_NETWORK` = `NODUS_SEND_NETWORK`) | `{ chainId, scheme, endpoints: [{ host, port }], pins }`, checked by the wallet's `validateNodusSendNetwork`: endpoints are **IPv4 only** (no host names), 1–8, tried in order; `scheme: 'ws'` only when every endpoint is `127.0.0.1`; 1–64 pins (SHA3-512 of each accepted server's ML-DSA-87 public key) |
| `endpoint` | — | `'wss://<IPv4>:<port>'` or `'ws://127.0.0.1:<port>'`: replaces the network's endpoint list with this one (chain id and pins kept) |
| `evm` | the wallet's `NODUS_EVM_NETWORK` | the EVM ruleset identity; the module refuses any value but the one it was compiled with (smart contracts then stay off); `null` = off |
| `wasmDir` | `sdk/js/wasm/` | where `send-node.mjs` is |
| `pending` | `[]` | records from an earlier run (see "One pending transaction") |
| `moduleFactory` | — | tests only: replaces the send module |

Properties: `evm.fingerprint` (the Nodus address, 128 hex), `evm.address`
(the EVM address = the fingerprint's first 32 bytes, 64 hex),
`evm.displayAddress` (checksummed), `evm.state`, `evm.chainId`,
`evm.evmActive`, `evm.pending()`.

`deriveIdentity(phrase)` → `{ fingerprint, evmAddress, displayAddress }`
does the same derivation without loading the module.

### Reads (one node's committed tip state)

| Call | Returns |
|---|---|
| `evm.tip()` | the node's tip height |
| `evm.nodusBalance()` | `{ total, spendable }` raw NODUS of this identity |
| `evm.account(address = own)` | `{ nonce, balanceWei, codeHash, codeSize, height }` |
| `evm.code(address)` | `{ code (hex), height }` |
| `evm.storage(address, key)` | `{ value (64 hex), height }`; `key` = 64 hex or a `BigInt` slot |
| `evm.call({ to, abi, fn, args, valueWei?, gas? })` | simulation, nothing written or signed; sender = this identity. `{ values, names, gasUsed, height }`, or a throw carrying the decoded revert reason (`Error(string)`, `Panic(uint256)`, a custom error of the ABI). With `data` (hex / `Uint8Array`) instead of `abi`/`fn`: the raw `{ success, output, gasUsed, height }` |
| `evm.receipt(intentId)` | the receipt or `null`: `{ height, index, success, status, op, gasUsed, created, output, logs, weiDestroyed, tickets, digest }` |
| `evm.logs({ fromHeight, toHeight, address?, topics?, limit?, cursor? })` | one page `{ logs: [{ height, index, logIndex, address, topics, data, intentId }], more, cursor }`. At most 10 000 blocks per range, `limit` ≤ 1000; `topics[0]` = the event signature hash, `null` = any. When `more`, send `cursor` back with the **same** range / address / topics; a page may be empty and still have `more` |
| `evm.contract(address, abi)` | the wallet's `Contract`: `read(fn, args)`, `estimate(fn, args)`, `decodeReceiptLogs(receipt)`, `iface` |
| `decodeLog(abi, log)` | `{ name, signature, args: [{ name, value }] }` or `null` |

### Writes

| Call | What |
|---|---|
| `evm.deposit(amountRaw, options)` | NODUS → this identity's EVM balance |
| `evm.withdraw(amountRaw, { dest?, ...options })` | EVM balance → NODUS at `dest` (128-hex Nodus address; default this identity). Whole raw units only; a remainder below 10¹⁰ wei stays in the EVM |
| `evm.deploy({ bytecode, abi?, args?, valueWei?, gasLimit? }, options)` | `bytecode` = the creation hex (Nodus solc `--bin`), constructor arguments ABI-encoded from `abi`. The result's `address` is the new contract when the receipt's `created` equals the address computed from the signed transaction (`createdCheck: 'match'`), else `null` |
| `evm.send({ to, abi, fn, args?, valueWei?, gasLimit? }, options)` | a state-changing call (`fn` = name, or the full signature for an overloaded name) |

Every write:

1. **refuses without `options.confirm`** — before anything is built or
   signed;
2. asks the node for an estimate (CALL / CREATE without `gasLimit`; a call
   the node expects to revert is refused with the reason, nothing built),
   builds and signs the envelope in the module, and reads every reviewed
   value back **from the signed bytes**; a fee above the wallet's own bound
   (`EVM_MAX_FEE_RAW`, 50 NODUS) is refused;
3. refuses a fee above **`options.maxFee`** (`BigInt` raw units) — `confirm`
   is not asked;
4. calls **`options.confirm(review)`**, which must return exactly `true`
   (anything else — `false`, `"yes"`, a throw — closes the review, nothing
   is sent). `review = { op, intentId, fee, feeText, rows, decoded,
   expiresAt }`; `rows` are the wallet's review lines. The review expires
   **60 s** after it was built (`NODUS_REVIEW_MS`): a later `true` gets
   "Review expired", nothing is sent;
5. calls `options.onRecord(row)` if given (`{ hash, expiryHeight,
   fromHeight, inputs }`) and waits for it **before** the envelope leaves the
   process — persist it there; a throw sends nothing;
6. submits, then polls the receipt until it arrives or the chain passes the
   transaction's expiry block.

It resolves `{ intentId, status, receipt?, createdCheck, createdExpected }`:
`'applied-success'`, `'applied-failed'` (the contract ran and rejected it —
**the whole declared fee is still charged and the nonce consumed**; unused
gas is not refunded), or `'refused'` (never included — nothing charged). A
submission the node refused, or a polling failure, rejects with
`error.sent = { intentId, receipt }`: the outcome is uncertain and the
receipt promise keeps polling.

`reviewAndSend(prepare, { confirm, maxFee, onBroadcast })` is the gate
itself, for a caller that drives `evm.contract(...)` directly.

### Offline build (no network)

`NodusEvm.buildOffline(options)` builds and signs **one** EVM envelope with
no connection and **sends nothing**: the release module's
`nsw_evm_offline_build` (web wallet 0.1.64, through `send-module.js`
`evmBuildOffline`) — the same shared C builder as the writes above, so the
result's `decoded` is read back from the signed bytes the same way. The
module is loaded for this one build and locked, zeroed and released before
the promise settles. You supply what a node would have told you; carrying
the envelope to a node is yours (there is no review, `confirm` or one-pending
record on this path — it only signs).

| Option | |
|---|---|
| `phrase` | required |
| `tip`, `gasPrice` | required: the chain tip and the gas price a node reported (`BigInt` / decimal) |
| `expiryHeight` | default `tip + 90n` — the only value the module accepts |
| `generation` | default: the EVM generation the module was built with; a lower one refuses |
| `chainId` | default: the network's |
| `op` | `'deposit'` \| `'withdraw'` \| `'call'` \| `'create'` \| `'redeem'` |
| `amount` | `BigInt` raw units (deposit / withdraw / redeem) |
| `nonce` | this identity's EVM nonce (every op but redeem; default `0n`) |
| `to`, `data`, `valueWei`, `gasLimit`, `accessList` | call (`to` = the contract) / create (`data` = initcode) |
| `dest` | withdraw / redeem: 128-hex Nodus address (default this identity) |
| `ticketId` | redeem: 128 hex |
| `units` | the declared resource ceiling (default `0n` = the minimum of this shape; give the node's estimate yourself for a call that reads storage) |
| `coins` | required: this identity's spendable NODUS coins `[{ nullifier, amount }]` — the funding inputs (ascending by nullifier until lock + fee) |
| `network`, `evm`, `wasmDir`, `moduleFactory` | as for `open()`; `evm: null` refuses |

Resolves `{ envelope: Uint8Array, intentId, decoded: { op, to, valueWei,
gasLimit, nonce, units, amount, dest, ticketId, dataLength, created,
recipient, fee, change, expiryHeight, chainId, inputs } }`. The signature is
hedged: two builds of one request share `intentId`, not the bytes. The EVM
leg's ruleset identity is the `evm` setting, which the module refuses unless
it is the one it was compiled with.

### One pending transaction

The node accepts only the account's current nonce, so the SDK sends one EVM
transaction per identity at a time (decision
`2026-10-04-nodus-evm-kurultay-k2-summary.md` #2, the wallet's
`EvmAccount` queue). A sent transaction's record stays in `evm.pending()`
until its receipt, or the chain past its expiry block, is seen; while a
record is undecided the next write is refused, and its coins are not
offered to the builder. Records live **in this process only**: to survive a
crash, persist what `onRecord` gives you and pass it back as
`open({ pending })` — each write first re-checks the records it holds
(`evm.checkPending()`).

### Re-exported from the wallet

`Interface`, `decodeRevert`, `selectorOf`, `topicOf`, `parseAddress`,
`isAddress`, `toChecksumAddress`, `evmAddressFromFingerprint`,
`evmAddressFromPublicKey`, `EVM_WITHDRAW_ADDRESS`, the units
(`WEI_PER_RAW`, `rawToWei`, `weiToRaw`, `formatUnits`, `parseUnits`,
`formatWei`, `parseWei`, `formatRaw`, `parseRaw`), `EMPTY_CODE_HASH`,
`EVM_LOGS_MAX`, `EVM_LOGS_SPAN`, `EVM_MAX_FEE_RAW`, `EVM_TX_GAS_CAP`,
`NODUS_REVIEW_MS`, `revertText`. The ABI supports what the wallet's codec
supports: `address` (32 bytes), `bool`, `uint<M>` / `int<M>`, `bytes<M>`,
`bytes`, `string`, fixed and dynamic arrays, tuples; function-typed values
are refused.

## Examples

Settings come from the **environment only** — never from argv or a file
in the repository:

| Variable | |
|---|---|
| `NODUS_PHRASE` | the recovery phrase (required) |
| `NODUS_ENDPOINT` | optional, e.g. `wss://164.68.116.180:443`; default: the wallet's endpoint list |
| `NODUS_MAX_FEE` | optional maxFee, raw units |
| `NODUS_TOKEN`, `NODUS_TO`, `NODUS_AMOUNT`, `NODUS_FROM_HEIGHT` | per example |

| Script | What |
|---|---|
| `examples/deploy-token.mjs` | deploys `nodus/tools/evm/examples/out/default/NodusToken.creation.hex` (no constructor arguments; the supply goes to the deployer) and prints its address |
| `examples/transfer.mjs` | `transfer(NODUS_TO, NODUS_AMOUNT)` on `NODUS_TOKEN` (amount in tokens, 18 decimals) |
| `examples/read-balance.mjs` | NODUS balance, EVM balance + nonce, and `NODUS_TOKEN`'s `balanceOf` |
| `examples/watch-transfers.mjs` | follows `NODUS_TOKEN`'s `Transfer` events from `NODUS_FROM_HEIGHT` (default: the tip), paging by cursor, polling every 10 s |

The writing examples ask on the terminal: they print the review lines and
send only when you type `yes`; without a terminal nothing is sent.

## What differs from Ethereum

- **No ethers / viem / MetaMask / `eth_*` JSON-RPC.** Those expect 20-byte
  addresses; Nodus EVM addresses are 32 bytes. There is no HTTP JSON-RPC
  (decision `2026-10-06-evm-dev-tooling.md` item 2); reads go over the
  node's tier-2 session (WebSocket), as in the wallet.
- **Addresses are 32 bytes** (decision `2026-10-04-nodus-evm-domain.md`
  item 3): an account's address is `SHA3-512(ML-DSA-87 public key)[0..32]`.
  A 20-byte address is refused, never zero-padded — a padded one would be a
  different account. Contracts must be compiled with the Nodus solc
  (`nodus/tools/evm/solc`, `nodus/tools/evm/examples/README.md`).
- **Signatures are ML-DSA-87** (post-quantum); there is no secp256k1 key and
  `ecrecover` is not account authorization.
- **The fee is a declared ceiling paid in NODUS** from your coins, charged
  in full once the transaction runs, even if the contract reverts.
- **The EVM balance is separate from the NODUS balance**: `deposit` /
  `withdraw` move value between them.

## Security notes

- **The phrase stays in this process.** It is used to derive the signing
  seed and the identity; the seed is copied into the module's memory and
  wiped there and on the JS side by the wallet's client; `close()` zeroes
  the module's whole memory. JavaScript strings cannot be wiped: the phrase
  string (and `process.env.NODUS_PHRASE`) stays in the heap until the
  process ends — run scripts in short-lived processes and keep the phrase
  out of shell history and committed files.
- **Nothing is signed and sent without your `confirm` function** returning
  `true`, and only within `maxFee` / the 50 NODUS bound. A `confirm` that
  always returns `true` is your decision to auto-sign; the SDK does not
  provide one.
- **Server pinning:** the module accepts only a server whose ML-DSA-87 key
  is in `pins`, over ML-KEM-1024, and only a node reporting the expected
  chain id.
- **Trust:** every read is **one node's** committed state; a receipt's digest
  is re-checked against its own fields, not against the chain (no light
  client).

## How it can lie

- **The unit tests are offline.** `test/review.test.js` drives the SDK with
  the wallet's test-only mock module (canned answers, no envelope, no
  signature); `test/abi.test.js` checks the codec against itself plus two
  pinned upstream constants; `test/module.test.js` loads the real release
  module but never connects. None of them shows that a node accepts
  anything.
- **The offline build test uses synthetic coins, tip and gas price.**
  `test/module.test.js` builds an offline DEPOSIT and CALL through the
  release module and checks the fields read back from the signed bytes and
  the signer (the CALL's key is found by scanning the envelope for a
  2592-byte window whose SHA3-512 is the identity's address — it does not
  parse the authorization section). Byte-for-byte parity of this build
  with the native C vector is the web wallet's test
  (`web-wallet/test/evm-call-wire-wasm.test.js`), not this one.
- **The module tests skip** when `wasm/send-node.mjs` is not built.
- **The live path** — WebSocket over TLS to an IP address, the pinned
  handshake, estimate, build, submit, receipt, logs — is exercised **only**
  by running the examples against a node, which the tests do not do.
- `send-node.wasm` is byte-identical to the wallet's `send.wasm` only when
  both are built from the same tree; `test/module.test.js` fails otherwise.
