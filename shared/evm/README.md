# Nodus EVM engine (`shared/evm/`)

An EVM execution engine written for this project, in C11, for **Nodus EVM** —
smart contracts on Nodus Chain as its third domain (HF-5, nodus 0.24.0). It is
not a wrapper around an existing EVM implementation: the execution
specification and the official tests are used as the reference and the test
oracle only.

- **Reference (pinned):** `ethereum/execution-specs @a87891f7`
  (`a87891f7e69eab1f903233c61c5514d8c94bd5d1`), fork **Prague**
  (`src/ethereum/forks/prague/`) — `evm.h:6-8`, `tests/statetest.c:14-15`;
  every gas constant in `evm_gas.h` is copied from it with its source line.
- **Status:** in the tree and wired into the node (`nodus/src/witness/nodus_witness_rt_evm.c`,
  built when `NODUS_EVM_ENABLED`); no chain has activated the EVM domain. Chain
  integration, activation and the node-side rules: `nodus/docs/ARCHITECTURE.md`
  "Nodus EVM (HF-5, v0.24.0)". Function reference:
  `messenger/docs/functions/evm.md`.

## Shape

- **Pull backend, journaled overlay** (`evm.h:10-19`): committed state is read
  through read-only backend callbacks; every write goes into an engine-owned
  journaled overlay; the caller reads one canonical, totally ordered change set.
- **Return convention** (`evm.h:21-30`): 0 success / outcome, -1 deterministic
  refusal, -2 node FAULT (never converted into an outcome), -3 `EVM_BUDGET`
  (the backend's deterministic host-work verdict; inside execution it ends the
  whole transaction as an applied failure).
- **Address width** is configuration: 20 bytes (Ethereum — the conformance
  mode) or 32 bytes (Nodus: address-taking opcodes use the whole stack word;
  CREATE / CREATE2 keep all 32 hash bytes).
- **Nodus profile** (`nodus_profile == 1`): two documented deviations from
  Prague, both for the ticket system address — a CALL into it runs the ticket
  hook, and a valued CALL into it is not charged the `NEW_ACCOUNT` surcharge
  (`evm.h:110-121`).
- **Code integrity is the backend's contract:** `get_code` must return bytes
  whose keccak256 equals the account's `code_hash`, or -2; the engine does not
  re-hash code (`evm.h:144-153`).
- Iterative interpreter (an explicit frame stack — call depth 1 024 cannot
  overflow the C stack), 256-bit arithmetic in `evm_u256.{h,c}` with a portable
  path (`-DEVM_U256_PORTABLE`, no `__int128`).

| File | Contents |
|---|---|
| `evm.h` | public API: configuration, backend, block environment, transaction, result, change set |
| `evm_u256.{h,c}` | 256-bit integers |
| `evm_state.c` | the journaled overlay (accounts, storage, transient storage, access sets, logs, tickets) |
| `evm_interp.c` | the interpreter |
| `evm_tx.c` | the transaction state transition, `evm_tx_prevalidate` |
| `evm_precompile.{h,c}` | precompiles 0x01-0x11 and the start-up self-test |
| `evm_gas.h` | Prague gas constants |
| `trie/` | the Nodus state commitment: SHA3-512 Merkle Patricia Trie (consensus code — `trie/evm_trie.h` header for the root definition and its substitutions) |
| `tests/` | u256 / addr32 / Nodus-profile / precompile tests, the official state-test runner (json-c), test-only RLP + MPT, an in-memory backend |
| `bench/` | the measurement-gate bench (worst-case workloads, shared with `nodus/tests/bench/bench_evm_apply.c`) |

## Build and test

From `shared/evm/` (targets from `Makefile`'s header):

```bash
make lib            # build/libevm.a
make deps           # build/libevm_deps.a (blst, c-kzg-4844, mcl, secp256k1 + the
                    # embedded KZG trusted setup) and build/gmp/install/lib/libgmp.a
make test           # addr32-vectors-check, then run test_u256, test_u256_portable,
                    # test_addr32, test_nodus_profile, test_trie
make statetest      # link the state-test runner, test_rlp_mpt, test_precompile
make conformance FIXTURES=<extracted fixtures/state_tests dir>
                    # test_rlp_mpt + statetest --fork Prague over the fixtures
make bench          # build/evm_bench (built, never run by `make test`)
make trie-vectors-check FIXTURES=<dir>   # the committed trie vectors vs their oracle
make clean
```

A consumer links, in this order: `libevm.a libevm_deps.a libgmp.a -lcrypto
-lstdc++ -lpthread` (`Makefile`, "vendored precompile libraries"). Build host
needs: a C11 compiler and a C++ compiler (mcl), `xxd` (the KZG trusted setup
is embedded), `sha256sum`, `xz` and `m4` (the GMP tarball is checked,
extracted and configured), python3 (the u256 / addr32 oracles), OpenSSL ≥
3.0.7 development headers (checked by `#error`, `evm_precompile.c:202-203`),
json-c (the state-test runner only). Inside nodus the same sources are built by
`nodus/CMakeLists.txt` with the Makefile's flags (`:783-969`).

## Conformance

execution-spec-tests **v5.4.0** `fixtures_stable`, Prague state tests, 20-byte
mode: **PASS 17 265, FAIL 0, FAULT 0, ERROR 0, PENDING 0, DEVIATION 9,
EXCLUDED 1 595** (985 type-3 blob + 610 type-4 set-code), identical under
ASan + UBSan + LSan — measured at commit `165c2f73` (its commit message).

- **DEVIATION 9:** Prague modexp cases whose expected result differs only by
  the EIP-7823 input bound (lengths ≤ 1 024), which this engine adopts to
  bound modexp work; each is matched by exact name and never counted as a pass
  (`tests/statetest.c:180-206`; `evm_precompile.c:323`, `:362`).
- **EXCLUDED:** type-3 blob (EIP-4844) and type-4 set-code (EIP-7702)
  transactions — Nodus has no counterpart (`tests/statetest.c:131`,
  `:1265-1276`). An excluded case is never counted as a pass.

## Precompiles and pinned libraries

All of 0x01-0x11 (Prague). Every library is vendored and version-pinned; its
`PINNED.md` records the upstream, tag / commit, license, how it was fetched and
what was verified.

| Precompile | Library | Pin | Record |
|---|---|---|---|
| 0x01 ecrecover | libsecp256k1 (recovery module) | `v0.8.0`, commit `6e2c8bc4ecdc6e71dbe7a368f360d8d453ce435d`; tag signature verified 2026-10-05 | `third_party/secp256k1/PINNED.md` |
| 0x02 sha256, 0x03 ripemd160 | OpenSSL (system library) | minimum **3.0.7** — not pinned | `evm_precompile.c:202-203`, `:224` |
| 0x05 modexp | GMP | `6.3.0` signed release tarball, sha256 `a3c2b80201b89e68616f4ad30bc66aee4927c3ce50e33929ca819d5c43538898` | `third_party/gmp/PINNED.md` |
| 0x06-0x08 bn254 | mcl (C++, behind its C API) | `v4.20`, commit `828c95660fdc9bffd351f069b2c4c20beebe2060`; one local patch (no `MCL_CPU` environment override) | `third_party/mcl/PINNED.md` |
| 0x0a point evaluation | c-kzg-4844 | `v2.1.8`, commit `e125905e5e01186e6ccb7a0ced4845bf7eddbcfe` (built against blst v0.3.17, not its own submodule pin) | `third_party/c-kzg-4844/PINNED.md` |
| 0x0b-0x11 BLS12-381 | blst | `v0.3.17`, commit `54e6e55674722fc2797ebb4bbb71b26d881eb4b8` | `third_party/blst/PINNED.md` |

0x04 identity and 0x09 blake2f are the engine's own code. Keccak-256
(`shared/crypto/hash/keccak256.c`) uses XKCP's Keccak-f[1600] (commit
`4affab454735d54e78156880b3b44e38dcbf765c`,
`shared/crypto/hash/third_party/xkcp/PINNED.md`).

**Host requirement:** on x86-64, mcl refuses to initialise without AVX + BMI2 +
ADX (`third_party/mcl/PINNED.md`, local patch 2).

**Start-up self-test** — `evm_precompile_selftest_report(&failed)`
(`evm_precompile.h:35-49`, `evm_precompile.c:1672-1720`): OpenSSL ≥ 3.0.7
loaded, SHA-256 and RIPEMD-160 from its default provider, mcl's bn254
initialisation, the KZG trusted setup, then known-answer vectors for 0x01,
0x02, 0x03, 0x05, 0x06, 0x08, 0x09, 0x0a, 0x0b, 0x0f and 0x11 (`PC_KATS`,
`evm_precompile.c:1491-1626` — 11 of the 17; at least one per library family).
On failure it names the missing capability. The node runs it on every start and
refuses to start on a failure (`nodus/src/witness/nodus_witness.c:2616-2639`).

## What this directory does not settle

- The gas limits the chain uses (per-transaction cap, block gas limit, read
  caps) are node constants in `nodus/src/witness/nodus_witness_runtime.h` and
  chain-config parameter 15 — placeholders until the measurement gate (`bench/`).
- OpenSSL is a minimum version, not a pinned implementation (open operator
  question).
