# Nodus developer starter

A Node.js project for deploying and using two Nodus contract templates:
**MultisigVault** and **MilestoneEscrow**, from contract library **0.2.0**.
The archive includes the existing Nodus SDK and wallet modules, release WASM,
32-byte-address Solidity compiler, source, ABI and bytecode. No local C build
or Emscripten installation is needed to use an archive.

This release is for **Linux x86-64** and dedicated **testnet identities**.
It is private and is not published to npm. Nodus Observatory is trader76's
independent application; this starter does not modify or integrate it.

## Install an archive

Use **Node.js 22.23.4 or newer in 22.x**, or **24.22.1 or newer in 24.x**,
with npm. The compiler also needs the system libraries listed in its
`compiler/README.md` (including glibc 2.34+ and suitable libstdc++).

```bash
sha256sum -c nodus-developer-starter-0.1.0-linux-x86_64.tar.gz.sha256
tar -xzf nodus-developer-starter-0.1.0-linux-x86_64.tar.gz
cd nodus-developer-starter-0.1.0-linux-x86_64
npm ci --ignore-scripts
npm run doctor
cp starter.config.example.json starter.config.json
```

Obtain the archive and expected checksum from a trusted release source.
A checksum shipped beside an archive detects accidental changes; it does
not authenticate a publisher who controls both files. This repository work
prepares an archive; it does not itself publish a download or npm package.

`doctor` is offline: it checks the file allowlist and hashes, release WASM
exports, compiler version, SDK imports and both template ABIs. It fails on
missing or changed artifacts and unexpected files in protected directories.
It does not connect to a node or show that a transaction will be accepted.
Keep packaged `runtime/`, `templates/`, `compiler/`, `src/`, `bin/`, `scripts/`,
`test/` and `licenses/` unchanged. Put your own application in a new `app/`
directory and your own contracts outside `templates/`.

The Node floor follows the [21 October 2026 security release](https://nodejs.org/en/blog/vulnerability/october-2026-security-releases),
checked on 24 October 2026. It is a point-in-time minimum, not a promise that
these versions stay free of vulnerabilities. Check newer security releases
and update the runtime. `engines`, `.npmrc` and the CLI enforce the floor;
the CLI checks it before loading the SDK, reading a phrase or opening sockets.
Dependencies are exact-pinned with a lockfile. `.npmrc` disables lifecycle
scripts; keep using `npm ci --ignore-scripts`, not an unreviewed installer.

## Identity, configuration and amounts

Use a separate testnet recovery phrase for each actor. The starter does not
generate, store or fund identities. Enter a phrase without putting it in
shell history, a command-line argument, config, `.env` or source:

```bash
read -rsp 'Testnet recovery phrase: ' NODUS_PHRASE
export NODUS_PHRASE
printf '\n'
node bin/nodus-starter.mjs identity
```

`identity` is offline and prints the native Nodus fingerprint and EVM address.
Record the public addresses. Repeat for the other actors, then select the
actor required for each step by entering that actor's phrase again. Run
`unset NODUS_PHRASE` when finished. The CLI does not print phrases and removes
the phrase from its own environment before opening the SDK. JavaScript strings
are not guaranteed to be erased from process memory; use a trusted local machine.

Edit `starter.config.json`. Only public configuration belongs there:

- `maxFeeRaw` is a positive decimal **string**. The example allows at most
  `"100000000"` raw = 1 NODUS per transaction; choose your own ceiling. The
  SDK's independent 50 NODUS ceiling still applies.
- Fill `vault.owners` and `vault.threshold` for vault deployment. Fill its
  `address` only after a successful deployment with a checked address.
- Fill `escrow.payer`, `payee`, `arbiter`, `amountsWei` and `deadline` for
  escrow deployment. The three parties must be distinct and nonzero; each
  amount must be positive and a multiple of 10¹⁰ wei. The deadline is a Unix
  timestamp in **seconds**, encoded as a decimal string, after the chain's
  current block timestamp. The compiler/node simulation checks it. For a
  convenient local estimate of tomorrow, Linux has `date -d '+1 day' +%s`.
- The unused template's placeholders do not block the chosen flow.
  `identity` needs no config; `balance`, `deposit` and `pending` need only
  the base settings. Unknown config fields are refused, including key fields.

By default the SDK uses its existing testnet endpoints, pinned server keys,
chain ID and EVM ruleset. Optional `endpoint` is `wss://<IPv4>:<port>`;
it changes the endpoint, retaining pins and chain ID. Custom `network` and
`evm` objects use the existing SDK formats documented in `sdk/js/README.md`
in the source repository. Plain `ws` is allowed only for localhost. For a
local harness you must supply its real chain ID, server pins and compatible
EVM settings; an arbitrary endpoint does not disable pin checks.

Set `NODUS_CONFIG` to select a different config file. Addresses are **32 bytes**:
`0x` plus 64 hex characters. A 20-byte Ethereum address is refused, never padded.
Use decimal integer strings for all config amounts and CLI amounts:

| Unit | Value |
|---|---|
| 1 NODUS | 100000000 raw native units |
| 1 NODUS in the EVM | 1000000000000000000 wei |
| 1 raw native unit | 10000000000 wei |

Every signer needs native testnet NODUS for fees, including an owner who only
approves and a payee who withdraws. Fund those dedicated identities using
your existing testnet wallet/funding route. A `deposit` moves native NODUS
into **that actor's** EVM balance; it does not fund a contract yet.

```bash
node bin/nodus-starter.mjs balance
node bin/nodus-starter.mjs deposit 100000000
```

Every write requires an interactive terminal and shows the existing SDK review.
The SDK builds and signs **locally for review**; only typing `yes` permits
broadcast, after the journal has been persisted. A rejected confirmation or
fee over the ceiling sends nothing. The review expires after 60 seconds.
There is no `--yes` option; piping a write refuses before a key is opened.
A failed EVM execution may still charge the entire shown fee. Check `status`,
not merely that an intent ID was printed. No command automatically retries a write.

## Example: two-of-three vault

Set three distinct owner addresses and `"threshold": "2"` in config.
Use owner A's phrase, with enough native coins for fees. Deploy, then copy
the returned `address` into `vault.address` **only** when `status` is
`applied-success` and the address is non-null (the SDK checked it against the
signed deployment). No address is silently written into your config.

```bash
node bin/nodus-starter.mjs vault deploy
node bin/nodus-starter.mjs vault state
```

Deposit 1 NODUS into A's EVM balance if needed, then fund the vault with
1 NODUS. This calls the vault's payable `receive()` with empty calldata:

```bash
node bin/nodus-starter.mjs deposit 100000000
node bin/nodus-starter.mjs vault fund 1000000000000000000
```

Set the public environment variable `RECIPIENT_EVM` to the chosen receiver's
full EVM address. Propose a 0.25 NODUS payment:

```bash
node bin/nodus-starter.mjs vault submit "$RECIPIENT_EVM" 250000000000000000
node bin/nodus-starter.mjs vault state 0
node bin/nodus-starter.mjs vault simulate-execute 0
```

The first proposal ID is 0; later runs must use the actual ID from the
Submitted event/state. `submit` includes A's approval. Before a second
owner approves, `simulate-execute` must refuse with `VaultBelowThreshold`.
This is a read-only simulation: no transaction, signature or fee.
Do not treat an unrelated connection/error message as proof of that check.

Switch to owner B's phrase and inspect the proposal before approving it.
An owner can then execute it:

```bash
node bin/nodus-starter.mjs vault state 0
node bin/nodus-starter.mjs vault approve 0
node bin/nodus-starter.mjs vault execute 0
node bin/nodus-starter.mjs vault state 0
node bin/nodus-starter.mjs balance "$RECIPIENT_EVM"
```

The payment arrives in the receiver's **EVM balance**. A vault is not the
native Nodus multisig account type: it collects approvals on-chain in a
contract and complements native multisig. Owner/threshold changes in the
library invalidate all older pending proposals; this introductory payment
CLI does not expose configuration-changing proposals.

## Example: milestone escrow

Use three distinct identities as payer, payee and arbiter. The example
config specifies two milestones, 1 and 2 NODUS, and needs a fresh future
deadline. Select the payer, deploy, and copy the checked deployment address
into `escrow.address`:

```bash
node bin/nodus-starter.mjs escrow deploy
node bin/nodus-starter.mjs escrow state
node bin/nodus-starter.mjs deposit 300000000
node bin/nodus-starter.mjs escrow fund
node bin/nodus-starter.mjs escrow release 0
```

Deposit only what the payer still needs; every step also needs native fee
coins. `fund` reads the deployed contract's `total()` and sends exactly that
amount, once, as payer, strictly before the deadline. `release 0` credits
the payee but does not transfer the credit until withdrawal.

Switch to the payee. First try the negative authorization example, then
withdraw the released credit:

```bash
node bin/nodus-starter.mjs escrow simulate-release 1
node bin/nodus-starter.mjs escrow state
node bin/nodus-starter.mjs escrow withdraw
```

The simulation must refuse with `EscrowUnauthorized` and sends nothing.
`withdraw` pays the caller's credit into its EVM balance. It is not a bridge
withdrawal to native NODUS; that separate operation is `evm.withdraw()` in
the SDK or your existing wallet.

For the second milestone, switch to the arbiter and choose the recipient:

```bash
node bin/nodus-starter.mjs escrow resolve 1 payee
```

Switch back to the payee and run `escrow withdraw` again. Choosing `payer`
instead credits the payer, who must withdraw with the payer's phrase.
Each milestone settles once. After the deadline the payer may use
`escrow refund <index>` on an unsettled milestone. The deadline grants
refund eligibility, **not priority**: a release or resolution included
first still settles it. Plain transfers to escrow are not a funding path;
it has no `receive()` and its accounting accepts only `fund()`.

## Events, compilation and application imports

Both templates support an events command. Supply actual block heights around
your receipts, at most 10000 blocks per request range:

```bash
node bin/nodus-starter.mjs vault events "$FROM_HEIGHT" "$TO_HEIGHT"
node bin/nodus-starter.mjs escrow events "$FROM_HEIGHT" "$TO_HEIGHT"
node bin/nodus-starter.mjs compile vault
node bin/nodus-starter.mjs compile escrow
```

Event pages are streamed and decoded with the template ABI. An empty page
with `more` is followed using its cursor; a cursor that fails to advance is
refused. Compile writes `build/vault/` or `build/escrow/`, first checking
that the rebuilt ABI, creation code and runtime code exactly match the
packaged artifacts. It preserves Solidity source unit names and uses
`--evm-version prague --bin --bin-runtime --abi`, no optimizer. The compiler
is local; it is never installed system-wide. For your own contracts, copy
a source into your application and invoke `compiler/solc-nodus` explicitly
with the same EVM version. Do not use stock Ethereum solc for Nodus addresses.

Your application can import the bundled SDK, for example from `app/main.mjs`:

```js
import { NodusEvm, parseAddress } from '../runtime/sdk/js/src/index.js';
```

The CLI remains the runnable reference for confirmation, fee limits and
durable `onRecord` persistence (`src/session.mjs`). A custom app must carry
those requirements forward. Direct SDK use is not automatically covered by
the CLI's process lock or journal. Do not use the same identity concurrently
from a separate wallet or app that does not share this reservation state.

## Pending transactions and local state

The default journal root is `$XDG_STATE_HOME/nodus-starter`, falling back to
`~/.local/state/nodus-starter`. It is shared across extracted copies. Under
it, chain ID and full native fingerprint identify a private directory:
`<chain>/<fingerprint>/pending.json`. It contains intent ID, expiry/from
heights and input nullifiers, never a phrase or signing seed.

An exclusive `operation.lock` allows one CLI process for an identity at a
time. `pending.json` is written to a private temporary file, fsynced,
renamed and the directory fsynced **before** SDK submission. After a restart,
the SDK restores that reservation and checks for a receipt or passed expiry.
An unresolved record blocks another write. An uncertain submission or
persistence error preserves the journal rather than replacing the transaction.
On every acquisition, the directory hierarchy is fsynced through the filesystem
root before any reservation can be recorded. This includes existing directories:
another process may have just created them without completing its parent fsync.
The tests check both paths and an injected fsync failure; they do not simulate a
physical power loss or guarantee a filesystem's hardware durability.

```bash
node bin/nodus-starter.mjs pending
```

You may set `NODUS_STATE_DIR` to relocate state, but every copy/app using
the same identity must use the same directory. Changing this directory or
deleting state to bypass a pending result defeats the safety check.
The filesystem must support exclusive file creation, atomic rename and fsync;
use local storage, not a shared/cloud-synced directory.

After a killed process, the lock deliberately remains. Stop any process
using that identity, inspect its PID and preserve the journal before removing
only a confirmed stale `operation.lock`. PID existence alone is not enough
because PIDs can be reused. Preserve and inspect a leftover `pending.next`
as well; a malformed journal, wrong identity, symlink or non-private directory
is a hard stop. Do not delete or edit pending records to resend. Normal
exceptions close the SDK and release the lock without clearing uncertain state.

## Trust and scope

- Runtime modules are copied unchanged from one checkout, retaining their
  import layout. There is no new signature implementation, ABI codec or
  browser wallet provider. npm supplies only `ethers`, `@noble/hashes`,
  `ws` and their locked dependencies.
- Every read, estimate, runtime-code check and receipt is **one pinned
  node's** reported state. The SDK checks receipt fields/digest consistency;
  it does not verify inclusion with a light client.
- Before using an existing template address, the CLI compares its reported
  runtime code with the packaged default-build runtime. An address from an
  optimized/different build is refused. This is a typo/configuration check
  within the same one-node read trust model, not a chain proof.
- The security contract library is **not externally audited**. Read its
  included README and sources. Internal review/tests do not replace an audit.
- `artifact-manifest.json` records HEAD, whether any tracked worktree file
  (including native WASM inputs) or included untracked source differs, file
  hashes and WASM parity-reference hash. If the tree is
  dirty, HEAD alone does not identify the shipped bytes. Hash checks detect
  changed bytes, not source equivalence or a malicious release whose code
  and manifest were replaced.
- The release excludes contract mocks, test-only signing WASM, private
  state, `.env`, node_modules and recovery phrases. Unit-test fake accounts
  never produce signatures and are not loaded by the CLI.

## Maintainer build and verification

Run from a source checkout. The archive build needs GNU tar, the supported
Node runtime, already-built SDK release WASM and the pinned compiler archive.
WASM builds additionally need Emscripten **6.0.10**, OpenSSL **3.0.15** for
WASM, json-c **0.17** for WASM and the prerequisites in `sdk/js/README.md`.

```bash
cd sdk/starter
npm ci --ignore-scripts
node scripts/build.mjs --compiler /absolute/path/to/nodus-solc-0.8.30-nodus.addr256-linux-x86_64.tar.gz
```

The compiler archive SHA256 is pinned to
`a09d6486c944a795009f08dbc8210ce2eee2785248f9f5f7edc2aaa9c6934649`.
It comes from the Nodus compiler distribution described in
`nodus/tools/evm/solc/README.md` and the developer wiki. The build checks this
hash before reading individual allowlisted tar members, checks the exact
compiler version, and invokes the existing library `verify.sh` to recompile
and compare committed artifacts. No compiler is downloaded or installed by
the build. GPL compiler licenses, source offer, upstream pin, patch and build
recipe accompany its binary. WASM notices cover OpenSSL, Emscripten, musl,
json-c and the upstream pq-crystals code; npm packages carry their own notices.
The recorded commit identifies the base checkout in the Nodus source repository.
Maintainers must retain any dirty native sources or their diff and the build
logs separately: the manifest hashes shipped files and does not capture those
native source changes.

WASM parity is checked **against a wallet build from the same source tree**.
The committed `web-wallet/src/nodus/send.wasm` can lag C source changes; a
fresh SDK build then correctly fails the parity check. Build both using the
wallet's pinned script, preserving any existing working-tree changes, and
pass the rebuilt wallet artifact explicitly:

```bash
node scripts/build.mjs --compiler /absolute/path/to/compiler.tar.gz --wallet-wasm /absolute/path/to/rebuilt/send.wasm
```

Do not substitute the SDK WASM itself as the reference and claim an
independent rebuild. The manifest labels an explicit maintainer reference;
the hash records byte equality, while the build logs establish its source.
Keep the original SDK `module.test.js` parity expectation honest when running
that suite: a stale committed wallet artifact is a baseline drift, not a
passing parity result. Run against the rebuilt same-source wallet artifact
and separately report the stale committed artifact if present.

The archive goes to `dist/` (or `--out-dir`), along with a `.sha256` file.
The builder replaces only its named archive/checksum, creates its own temporary
staging directory and removes only that directory. It uses a fixed file
allowlist, normalized modes/owner/order/mtime and gzip without timestamps.
With identical inputs and the same packaging toolchain, bytes are repeatable,
including across caller umasks. No publishing or push is performed.

Read this section and each test header before running tests:

| Command | What it establishes | Requirements and leftovers | Limits |
|---|---|---|---|
| `npm test` | Node floor, exact integer/config boundaries, journal persistence/lock/refusal, exception-safe reservations, artifact tampering/exclusion, template command dispatch and event cursor behavior | Supported Node; no compile flags, keys, network or env; temporary directories removed | Fake SDK/account responses, no signatures or node acceptance |
| `npm run test:package` inside an extracted archive | Relocatable SDK imports, real 32-byte codec/constructor ABIs, CLI doctor and source/artifact compiler parity for both templates | `npm ci --ignore-scripts`, Linux x86-64, compiler system libraries; no phrase/network; temporary compile output removed | No connection, real transaction or proof of consensus execution |
| `STARTER_PACKAGE_DIR=/absolute/extracted/root npm run test:package` from source | Same package smoke against that extracted copy | Same prerequisites; source test files stay outside the artifact | Must use a clean copy outside the repo to establish relocation |
| `npm test` in `sdk/js/` | Existing real release identity/offline signing/ABI tests plus transfer fee/confirmation/pending regressions | SDK and wallet npm dependencies, rebuilt release WASM and same-source wallet parity reference; see the SDK README | Module tests skip if WASM is absent: report those as absent, never passes; synthetic coins and mock review tests do not prove node acceptance |
| `npm audit --omit=dev` inside extracted archive | Known advisories in the actual shipped npm dependency graph at query time | Registry access; report audit timestamp/results | No guarantee about unknown advisories or native/WASM code |

No live-chain writes are part of these checks. To establish end-to-end
behavior, run the documented actor flows against a correctly configured
local harness, or an explicitly authorized testnet run with dedicated funded
identities. Record chain, block range, transaction IDs, expected negative
reasons and resulting state; offline smoke alone is not that evidence.
