# Nodus developer starter and plain EVM transfer

Source: `sdk/starter/` and the additional `NodusEvm.transfer` method in
`sdk/js/src/sdk.js`. No native ABI, consensus, cryptography or wire format
changes. The SDK continues importing the wallet's implementations; an archive
copies their reviewed file closure unchanged under `runtime/`.

## SDK addition

`NodusEvm.transfer({ to, valueWei, gasLimit? }, options) -> Promise<WriteResult>`

- `to` is parsed by the existing 32-byte `parseAddress` codec; 20-byte
  addresses and incorrect mixed-case checksums refuse.
- `valueWei` must be a positive BigInt below 2²⁵⁶. It is EVM value, not a
  native-NODUS transfer amount. `gasLimit`, when supplied, follows the
  existing account validation; omitted gas uses the node's estimate.
- Calls existing private `#write` with `EvmAccount.prepare({ op: 'call',
  to, valueWei, gasLimit, data: new Uint8Array(0), title })`.
- Existing confirmation, fee, signed-field readback, durable `onRecord`,
  pending reservation and receipt semantics are unchanged. It does not
  expose a raw-signing path or automatically confirm. `receive()` funding
  of the MultisigVault template is its starter consumer.

`sdk/js/test/review.test.js` adds mock-module transfer regressions for valid
empty-calldata value, all address bytes, validation, confirmation/fee gates,
failed persistence, ordering and restored pending reservations. The SDK's
release-WASM suite is separate; see its README for prerequisites and skips.

## Runtime policy and configuration

| Function | Behavior |
|---|---|
| `assertNode(version = process.versions.node)` (`src/version.mjs`) | Accepts stable 22.x ≥22.23.4 and 24.x ≥24.22.1; refuses all other majors, older patches and prereleases. CLI invokes before SDK/key/network access. `NODE_POLICY` records check date and floors. |
| `integer(value, label, { positive = false, bits = 256 } = {})` (`src/config.mjs`) | Decimal-string-only conversion to BigInt with unsigned bit-width and positivity checks; never rounds through Number. |
| `fields(object, allowed, label)` (internal) | Refuses nonobjects and unknown configuration fields without printing values. |
| `readConfig(path)` | Reads JSON, refuses over 65536 bytes or malformed JSON, returns parsed config; never includes raw contents in parse errors. |
| `configBase(config, sdk)` | Validates schema/version/field allowlists and fee; delegates network/EVM validation to existing SDK. Returns `{network, evm, maxFee}`. |
| `nonzero(value, sdk)` (internal) | Existing SDK parser plus nonzero check; returns `0x`-prefixed lowercase 32-byte address. |
| `contractAddress(config, kind, sdk)` | Validates the configured deployed vault/escrow address. |
| `vaultArgs(config, sdk)` | Constructor args `[owners, threshold]`; 1–32 distinct nonzero owners and valid positive threshold. |
| `escrowArgs(config, sdk)` | Constructor args `[payer,payee,arbiter,amounts,deadline]`; distinct nonzero parties, 1–32 positive q-multiple amounts, bounded uint256 sum and positive timestamp. Chain simulation, not local wall time, validates future deadline. |

## Durable journal and session

`acquireJournal({ stateDir, chainId, fingerprint })` (`src/journal.mjs`)
creates/opens `<stateDir>/<chainId>/<fingerprint>/`. It validates the scope,
requires private owned nonsymlink leaf directories, durably creates newly
needed ancestors, and exclusively creates `operation.lock`. A lock already
present refuses; it is never reclaimed automatically based on PID age.

It returns:

| Member | Behavior |
|---|---|
| `path` | Absolute or caller-root-relative path of `pending.json`. |
| `pending()` | Defensive copy of the validated pending rows, at most one. |
| `replace(rows)` | Validates before writing; private `pending.next`, file fsync, atomic rename, directory fsync; only then updates in-memory rows. A leftover temporary file refuses rather than silently overwriting crash evidence. |
| `record(row)` | Refuses an existing pending reservation; durably stores this row before SDK submission. |
| `close()` | Idempotently closes/removes the owned lock and fsyncs its directory; does not clear pending records. |

Internal helpers:

- `keysAre(object, keys)`, `height(value)` and `rowsChecked(rows)` validate
  strict schema, canonical uint64 height strings, 128-hex identifiers,
  distinct inputs (1–15), and return copies. Malformed state fails closed.
- `privateDirectory(path)` creates/validates the private leaf and fsyncs its
  directory hierarchy through the filesystem root on every acquisition,
  including pre-existing entries that another process may just have created.
- `syncDirectory(path)` opens a directory without following a final symlink,
  fsyncs, then closes it. Filesystem errors are not ignored.

`withAccount({ sdk, phrase, config, stateDir, write, confirm, run })`
(`src/session.mjs`) derives the identity, acquires the journal, opens the
existing SDK with restored rows, verifies identity/chain, connects, and
resolves pending records. It persists the SDK map only after successful
`checkPending`, and after a definitive write result. Remaining pending state
blocks a write. It calls `run(evm, {maxFee, confirm, onRecord})`; `onRecord`
awaits `journal.record`. On any write exception it does **not** copy the SDK
map back: a journal rename may have succeeded before fsync/onRecord failed,
with the SDK map still empty. Finally it locks/releases the SDK and journal.
Dependencies are explicit for fake-account tests; the CLI passes the real SDK.

## Commands, templates and compiler

| Function | Behavior |
|---|---|
| `prepareCommand(argv, config, sdk)` (`src/commands.mjs`) | Validates command/arity/addresses/integers before keys/network; returns a plain command descriptor and whether it writes. |
| `arity(args,min,max=min)` (internal) | Bounded positional-argument count; does not echo supplied values. |
| `executeCommand(command,{evm,options,templates,sdk,emit})` | Balance/deposit/pending and vault/escrow actor flows. Existing template addresses require exact packaged runtime bytes from `evm.code`. Vault fund calls `transfer`; escrow fund reads `total` then `send('fund')`. Simulations call read-only `evm.call`; writes retain options from `withAccount`. |
| `events(evm,command,template,sdk,emit)` (internal) | Streams decoded events across pages, including empty pages with `more`; rejects a nonadvancing/out-of-range cursor. |
| `loadSdk(root=PACKAGE_ROOT)` (`src/sdk.mjs`) | Imports only `runtime/sdk/js/src/index.js` from the selected archive root; no repo fallback. |
| `loadTemplates(root=PACKAGE_ROOT)` | Reads manifest entries, parses ABI and loads/trim creation/runtime hex from their allowlisted paths. |
| `compileTemplate(id,root=PACKAGE_ROOT,output=resolve('build'))` (`src/compile.mjs`) | Runs pinned compiler over production sources with original unit names/default Prague flags. Diagnostics or any difference in selected ABI/creation/runtime outputs refuse. Copies selected results to `build/<id>/`; removes only its own temp directory. CLI calls doctor first. |

`bin/nodus-starter.mjs` is the gated CLI entry. Help/doctor/compile/identity
are offline. It loads phrase only from environment, checks terminal presence
before opening a write identity, confirms only typed `yes`, emits BigInts as
decimal strings, redacts phrase values from errors and returns nonzero for
failed/refused or address-mismatched deployments. Default state is shared
per user through XDG state, not tied to one extracted project.

## Artifact integrity and assembly

| Function/constant | Behavior |
|---|---|
| `COPY_FILES`, `DISTRIBUTION_FILES`, `STARTER_FILES`, `CONTRACT_SOURCES`, `COMPILER_FILES` (`src/distribution.mjs`) | Explicit source→archive closure and exact permitted file set; no recursive repository copy. Compiler archive hash/version and protected directories are also constants here. |
| `assertDistributionPaths(paths)` | Requires exact equality with the release file set, preventing omitted and additional signing/template artifacts. |
| `sha256(bytes)` (`src/artifacts.mjs`) | Built-in Node SHA256 of packaged bytes; integrity/provenance, not an authentication root. |
| `childEnvironment()` | Copies process environment with `NODUS_PHRASE` removed for compiler/git/tar subprocesses. |
| `packagePath(root,path)` | Rejects absolute, dot/parent, empty-segment and malformed manifest paths. |
| `regularFile(root,path)` (internal) | Checks each path segment for symlinks/type before reading. |
| `listFiles(root,relative)` (internal) | Sorted recursive regular-file list; refuses symlink/special entries. |
| `verifyFiles(root,files,directories=PROTECTED_DIRECTORIES)` | Checks size/hash of every manifest entry and absence of extra files in protected directories. |
| `releaseWasm(bytes)` | Compiles a WebAssembly module for inspection only; refuses any `nsw_test_*` export and requires the six release EVM exports. |
| `doctor(root=PACKAGE_ROOT,{compiler=true}={})` | Runtime floor, manifest/provenance, exact file set, integrity, release exports, WASM-reference hash and compiler pin/platform checks. Returns manifest. Never opens a node. |

`scripts/build.mjs` is maintainer-only. It accepts `--compiler`, optional
`--wallet-wasm`, optional `--out-dir`; checks pinned tar SHA256 before reading
allowlisted members; copies sources unchanged, runs existing library
`verify.sh`, generates provenance, normalizes tar metadata/modes and creates
a gzip archive plus checksum. Its temporary staging directory alone is
removed. `worktreeDirty` covers all tracked changes (including native WASM
inputs) and included untracked sources. Source HEAD or file hashes alone do
not prove generated binary/source equivalence; maintainer build logs matter.

The starter README documents every test suite's requirements, leftovers and
limits. Unit tests use fake accounts and filesystem instrumentation; package
smoke uses the real extracted SDK codec/compiler; SDK release signing and any
real-chain run are separate evidence. None of these checks is an external
security audit.
