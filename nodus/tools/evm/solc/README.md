# Nodus EVM solc — 32-byte addresses

A patch against upstream Solidity **v0.8.30** (commit
`73712a01b2de56d9ad91e3b6936f85c90cb7de36`) that makes the Solidity `address` type
256 bits wide, for the Nodus EVM domain.

Governing records:
- `docs/plans/decisions/2026-10-04-nodus-evm-domain.md`, decision 3 — EVM addresses are 32 bytes.
- `docs/plans/2026-10-04-nodus-evm-engine-design.md` §2 — the engine's 32-byte mode: the whole
  256-bit word is the address everywhere; ADDRESS/CALLER/ORIGIN/COINBASE push 32 bytes;
  CREATE = `keccak256(rlp([sender32, nonce]))` (all 32 bytes);
  CREATE2 = `keccak256(0xff ‖ sender32 ‖ salt ‖ keccak256(initcode))` (all 32 bytes).

Why: stock solc treats an address as 160 bits and masks every address it reads
(`PUSH20 0xff…ff AND`). On a chain whose addresses are 32 bytes that mask silently turns
one account into another. This variant removes every 160-bit assumption it can find and
turns the ones it cannot support into compile errors.

## Files

| File | What |
|---|---|
| `0001-nodus-address-256.patch` | the change, `git format-patch` against v0.8.30 |
| `build.sh` | clone v0.8.30, verify the commit hash, apply the patch, build `solc`, print `solc --version` |
| `tests/*.sol`, `tests/check.sh` | output checks (bytecode, IR, storage layout, ABI, diagnostics) — no execution |

## Build

```
JOBS=4 ./build.sh /path/to/work          # BOOST_ROOT=<prefix> if the system Boost lacks static libs
SOLC=/path/to/work/solidity/build/solc/solc ./tests/check.sh
```

Requirements (upstream, v0.8.30): CMake, g++ ≥ 11, Boost ≥ 1.67 with `filesystem`,
`program_options`, `system`, `unit_test_framework` (`cmake/EthDependencies.cmake:32,46-53`),
linked statically by default (`:27`); network access at configure time (the `fmtlib`,
`nlohmann-json`, `range-v3` submodules are fetched by CMake). v0.8.30 has **no**
`USE_Z3` / `USE_CVC4` options: Z3 is looked up only for emscripten builds
(`CMakeLists.txt:99-123`); a native solc calls SMT solvers as external processes.
`build.sh` passes `-DTESTS=OFF -DTOOLS=OFF -DSTRICT_Z3_VERSION=OFF` and builds only the
`solc` target.

GCC 12 prints `-Wrestrict` warnings in upstream string code (GCC bug 105651); upstream
already downgrades them from errors for GCC 12 (`cmake/EthCompilerSettings.cmake:97-101`).

## Version string

`0.8.30+nodus.addr256.commit.73712a01.<platform>` (e.g. `…Linux.g++`).

Mechanism: the `+` build-metadata part. `cmake/scripts/buildinfo.cmake:63,65` is patched so
both `SOL_VERSION_COMMIT` and `SOL_VERSION_BUILDINFO` start with `nodus.addr256.`; therefore
`solc --version` (`VersionString`) and the metadata JSON `compiler.version`
(`VersionStringStrict`, `libsolidity/interface/CompilerStack.cpp:1726`) both carry the tag.
`build.sh` writes an empty `prerelease.txt` (release build — no `develop.<date>` suffix, so
the string does not depend on the build day) and `commit_hash.txt` = the upstream commit (no
`.mod` suffix for the patched tree).
Limitation: for a release build the CBOR metadata appended to the bytecode stores only the
three version bytes `0.8.30` (`libsolidity/interface/CompilerStack.cpp:1943-1952`,
`CompilerStack.h:429`: the full string is embedded only for pre-releases),
so the **bytecode CBOR alone does not distinguish** this compiler from stock 0.8.30; the
metadata JSON (`compiler.version`) does.

Default EVM version: **prague** — unchanged from v0.8.30 (`liblangutil/EVMVersion.h:170`,
`Version m_version = Version::Prague;`), which matches the engine's target fork (design §1).

## Semantic rules

1. **Width.** `address` and `address payable` are 256-bit values. ABI-encoded size is 32
   bytes padded and unpadded (so `abi.encodePacked(address)` emits **32 bytes**), storage size
   is 32 bytes — an address always takes a whole slot and is never packed with neighbours.
   Contract-typed values follow (`ContractType::storageBytes` = 32).
2. **Cleanup is the identity.** No `and(x, 2**160-1)` is emitted anywhere: legacy
   (`CompilerUtils`, `ExpressionCompiler`) and Yul IR (`YulUtilFunctions` cleanup /
   conversion / left-align). The ABI decoder validator for `address` is
   `eq(value, cleanup(value))` with the identity cleanup — exactly like `uint256`, i.e. no
   value is rejected (every 256-bit word is a valid address); the optimizer folds it away.
3. **Conversions.** Explicit `address(uint256)`, `uint256(address)`, `address(bytes32)`,
   `bytes32(address)` are allowed and are the identity. Any explicit conversion between
   `address` and an integer or fixed-bytes type of another width (`uint160`, `bytes20`, …) is a
   **compile error**:
   `Nodus EVM addresses are 32 bytes (256 bits): "address" converts explicitly only to and from "uint256" and "bytes32"; a conversion involving "<type>" would silently truncate the address.`
   Contract ↔ address conversions are unchanged. A number literal converts explicitly to
   `address` if it fits in 256 bits (was: 160). There is no implicit conversion between
   `address` and any integer/bytes type (unchanged).
4. **Address literals.** A hex literal of exactly **64 hex digits containing both lower- and
   upper-case letters** is an `address` literal and must carry a valid checksum: the EIP-55
   rule applied to the 64 digits — keccak256 of the 64 lowercase ASCII hex characters; the
   i-th letter is upper case iff the i-th hex nibble of the hash is ≥ 8
   (`util::passesAddress32Checksum` / `util::getChecksummedAddress32`, next to the untouched
   40-digit `passesAddressChecksum`). A bad checksum is an error that prints the correct form.
   A 64-digit literal that is all lowercase or all uppercase stays an ordinary number literal
   (as in upstream). A 39–41-digit literal that upstream would treat as an address (valid
   checksum or not) is now an error telling the user to write the 64-digit form
   (`… prepend '00'` if it is not meant as an address).
   Example (checksummed): `0x8076F99ED6A2095ddE395300cF2E056F44e3F5CFA66b300c7b84E3972f379E50`.
   Corner case: if the correct checksum of a value happens to put all its letters in one case,
   the checksummed text is not recognised as an address literal; write `address(0x…)`.
5. **Optimizer.** The libevmasm rule `AND(ADDRESS|CALLER|ORIGIN|COINBASE, 2**160-1) → <opcode>`
   is removed: with 32-byte addresses the masked value is not the opcode value. The libyul
   expression simplifier consumes the same rule list (`libevmasm/RuleList.h`), so one removal
   covers both pipelines.
6. **External function types.** An external function value is a 32-byte address plus a
   4-byte selector — 36 bytes, which no longer fits the single word that ABI encoding, storage,
   memory and calldata use for it (upstream packs `address ‖ selector` into 24 bytes). It is a
   **compile error** to use a type that contains an external function type for: state variables
   (incl. constants/immutables), struct members, array/mapping element types, memory/storage/
   calldata variables, parameters and returns of public/external functions and of external
   function types, event and error parameters, try/catch return variables, `abi.encode*`
   arguments, `abi.decode` target types, inline arrays and `new T[](n)`:
   `Nodus EVM addresses are 32 bytes: an external function value (32-byte address + 4-byte selector) does not fit the single 32-byte word used to ABI-encode it or to keep it in storage, memory or calldata. …`
   Still allowed (stack only): local variables of external function type, parameters/returns
   of internal/private functions and of internal function types, calling them, `.address`,
   `.selector`, `==`/`!=` between them (compared without a mask). Internal function types are
   unaffected. Safety net: the four pack/unpack helpers (legacy
   `CompilerUtils::split/combineExternalFunctionType`, Yul
   `split/combineExternalFunctionIdFunction`) raise an `UnimplementedFeatureError` with the same
   reason, so a path the TypeChecker missed fails to compile instead of producing a wrong
   address.
   Alternative not implemented: a two-word (64-byte) ABI/storage encoding for external function
   values (address word + selector word). It is correct but changes the ABI of `function`
   types for every tool, so the error was chosen.
7. **Libraries.** Calling an external/public library function needs a linked library address,
   and the whole linker (`__$…$__` placeholders of 40 hex characters, 20-byte link references,
   `--libraries`, standard-JSON `libraries` with `h160`) is 20-byte. A library link reference
   that reaches the final bytecode — external library call or `address(L)` in legacy codegen,
   Yul `linkersymbol` (via-IR and raw Yul), imported EVM assembly — is refused when the
   bytecode is assembled, with `UnimplementedFeatureError: Nodus EVM addresses are 32 bytes:
   linking library "<name>" is not supported. …`. References the optimizer removes as unused
   (the via-IR generator emits an unused `linkersymbol` for `L.internalFn(...)`, which the
   always-run `UnusedPruner` step removes) never reach that point. Corner case: via-IR without
   `--optimize` skips that pruning when the code uses `msize()` (`libyul/YulStack.cpp:97-101`),
   so `L.internalFn(...)` there is refused too — use `using L for T` or `--optimize`.
   Internal library functions (the common case) are inlined and work. Compiling a library itself works: its deploy-time
   "called via DELEGATECALL" self-address slot is now `PUSH32 00…00` and the library
   constructor writes the full 32-byte `address()` into it (legacy codegen; the via-IR
   pipeline already used a 32-byte immutable).
8. **SMTChecker.** Addresses are modelled as `uint256` (was `uint160`).
9. **`ecrecover`** stays typed `address`. Its value is the 20-byte Ethereum address recovered
   by the precompile, left-padded with zeros to 32 bytes: 12 zero bytes ‖ 20 bytes. The
   disjointness from Nodus 32-byte account addresses (ML-DSA-derived, `SHA3-512(pk)[0..32]`)
   is **probabilistic, not structural** — nothing in the 32-byte mode excludes an address
   whose top 12 bytes are zero, so a Nodus account equals an `ecrecover` result only by a
   ~2^-96 accident or a ~2^96 search (Kurultay #9, 2026-10-06). **Never use `ecrecover` for
   Nodus account authorization.**
10. **ABI JSON** still names the type `"address"`, and function selectors / event topics are
    computed from the same signatures as upstream (`f(address)`), but an address value now
    occupies the full 32-byte word — a 20-byte, zero-left-padded value is a *different*
    account.

## Upstream sites changed (v0.8.30 line numbers)

| File:line (upstream) | Change |
|---|---|
| `libsolidity/ast/Types.h:458-459` | `AddressType::calldataEncodedSize` → 32 padded and unpadded; `storageBytes` → 32 |
| `libsolidity/ast/Types.h:978` | `ContractType::storageBytes` 20 → 32 |
| `libsolidity/ast/Types.cpp:64` | new `nodusAddressWidthError()` message helper |
| `libsolidity/ast/Types.cpp:503-506` | address → integer/bytes: only `uint256` / `bytes32`, others error with the Nodus message |
| `libsolidity/ast/Types.cpp:634-637` | integer → address: only `uint256` |
| `libsolidity/ast/Types.cpp:1056` | number literal → address: fits in 256 bits (was 160) |
| `libsolidity/ast/Types.cpp:1366-1369` | bytes → address: only `bytes32` |
| `libsolidity/analysis/TypeChecker.cpp:51,58` | `containsExternalFunctionType()` + message |
| `libsolidity/analysis/TypeChecker.cpp:162` | `abi.decode` target containing an external function type → error 7215 |
| `libsolidity/analysis/TypeChecker.cpp:483` | variable declarations holding an external function value off the stack → error 6259 |
| `libsolidity/analysis/TypeChecker.cpp:1591` | inline array of external functions → error 2318 |
| `libsolidity/analysis/TypeChecker.cpp:2160` | `abi.encode*` argument containing an external function type → error 4831 |
| `libsolidity/analysis/TypeChecker.cpp:3028` | `new` array of external functions → error 5562 |
| `libsolidity/analysis/TypeChecker.cpp:3739-3761` | 40-digit address literal → error 7631; 64-digit mixed-case literal → `address`, bad checksum → error 9429 |
| `libsolidity/ast/AST.h:2496`, `AST.cpp:1065` | `Literal::looksLikeAddress32 / passesAddress32Checksum / getChecksummedAddress32` |
| `libsolutil/CommonData.h:603`, `CommonData.cpp:163` | `passesAddress32Checksum`, `getChecksummedAddress32` (64-digit EIP-55 rule) |
| `libsolidity/codegen/CompilerUtils.cpp:710-741` | external function pack/unpack → `UnimplementedFeatureError` (safety net) |
| `libsolidity/codegen/CompilerUtils.cpp:832-833` | bytes → address: `bytes32` only, no shift |
| `libsolidity/codegen/CompilerUtils.cpp:888` | address → bytes: `bytes32` only |
| `libsolidity/codegen/CompilerUtils.cpp:926` | address/contract cleanup width 160 → 256 (identity) |
| `libsolidity/codegen/ExpressionCompiler.cpp:2446-2448` | external function `==`: address compared without 160-bit mask |
| `libsolidity/codegen/YulUtilFunctions.cpp:69-100` | Yul external function pack/unpack → `UnimplementedFeatureError` (safety net) |
| `libsolidity/codegen/YulUtilFunctions.cpp:383` | left-align of address: full word |
| `libsolidity/codegen/YulUtilFunctions.cpp:3503,3517,3612` | address/contract ↔ integer/bytes conversions through `uint256` (was `uint160`) |
| `libsolidity/codegen/YulUtilFunctions.cpp:3945` | `cleanup_t_address` = `cleanup_t_uint256` (identity) |
| `libsolidity/codegen/ContractCompiler.cpp:240-252,318` | library deploy: patch a 32-byte self address after `PUSH32` at offset 0 (was `PUSH20` at 11) |
| `libevmasm/Assembly.cpp:1166` | `assemblePushLibraryAddress` → `UnimplementedFeatureError` (no 20-byte library link reference reaches bytecode) |
| `libevmasm/Assembly.cpp:1181-1184` | deploy-time address = `PUSH32` + 32 zero bytes |
| `libevmasm/AssemblyItem.cpp:164` | size of library/deploy-time address push 1+20 → 1+32 |
| `libevmasm/RuleList.h:369-386` | removed `AND(ADDRESS|CALLER|ORIGIN|COINBASE, 2**160-1)` rule |
| `libsolidity/formal/SymbolicTypes.cpp:479`, `SymbolicVariables.cpp:132` | SMT address model `uint160` → `uint256` |
| `cmake/scripts/buildinfo.cmake:63,65` | `nodus.addr256.` build tag |

Not changed on purpose: `libsolidity/codegen/ExpressionCompiler.cpp:2928-2929` (that
`IntegerType(160)` / `bytes20` is the `ripemd160` return value, not an address);
`libsolidity/formal/SymbolicState.h:257` (same, `ripemd160`); `libevmasm/LinkerObject.cpp`,
`solc/CommandLineParser.cpp:438`, `solc/CommandLineInterface.cpp:1193-1197`,
`libsolidity/interface/StandardCompiler.cpp:370,952` (20-byte linker; left unchanged — they
operate on 20-byte placeholders this compiler never emits).

## Known incompatibilities for existing Solidity code

- `address(uint160(x))`, `uint160(a)`, `address(bytes20(x))`, `bytes20(a)` — error. Typical
  sources: OpenZeppelin `Create2`, `Clones`, `ECDSA`, `Address`, hand-written CREATE2
  prediction. Port to `address(uint256(...))` / `uint256(a)` **and** check the logic: the
  CREATE/CREATE2 address on Nodus is the full 32-byte hash (engine design §2), not its low 20 bytes.
- 40-digit address literals — error; rewrite as 64-digit checksummed literals (the value of a
  Nodus account is not the zero-padded Ethereum address).
- 64-digit **mixed-case** hex numbers used as `bytes32`/`uint256` constants are now address
  literals (error on bad checksum, or a type error when assigned to `bytes32`) — write them in
  one case.
- External function types in storage, events, ABI (params/returns of public/external
  functions), `abi.encode`, memory arrays — error. Pass `(address, bytes4)` instead.
- Calls to external/public library functions (linked libraries) — error. Make them `internal`
  or deploy the library as a contract and call it through an interface.
- Storage layout changes: an address no longer packs with smaller neighbours; contracts that
  rely on upstream slot/offset layout (proxies, upgradeable storage gaps, inline-assembly slot
  arithmetic) must be re-checked with `--storage-layout`.
- `abi.encodePacked(address)` is 32 bytes (was 20): any hash or signature over packed
  addresses changes.
- Inline assembly that masks addresses itself (`and(a, 0xff…ff)` with 40 f) truncates; remove
  such masks.
- Off-chain tooling (ethers/viem/web3, hardhat/foundry) assumes 20-byte addresses in ABI
  coding, checksums and linking; it needs the Nodus SDK/ABI adaptation (separate work).
- `ecrecover` must never be used to authorize Nodus accounts (rule 9: its disjointness from
  them is probabilistic, not structural).
