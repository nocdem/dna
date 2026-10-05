# XKCP (eXtended Keccak Code Package) — vendored macros (Keccak-f[1600] for crypto/hash/keccak256.c)

| Field | Value |
|---|---|
| Upstream | https://github.com/XKCP/XKCP (the Keccak team's reference package) |
| Commit | `4affab454735d54e78156880b3b44e38dcbf765c` (2026-09-25, "Fix makefiles"; `master` HEAD when fetched — XKCP publishes no release tags) |
| Last change to the copied files | `b3bcadea239e016b80c0a1aff2d0c8ce9daced0f` (2026-06-12, "Fix unaligned and aliasing-violating lane accesses in portable code") — `git log -1` over the three files below; `KeccakP-1600-opt64.c` last changed in `78477d2e0b980737deaa07b928b29302257055ca` (2026-06-12) |
| License | the two `.macros` files: CC0 (public-domain dedication in each file's header); `LICENSE` (XKCP's, copied) lists the per-file terms |
| Fetched | `git clone https://github.com/XKCP/XKCP`, `git rev-parse HEAD` = the commit above, 2026-10-05 |

## Why

The Nodus EVM red-team 1 bench (i5-7400T, 30M gas) measured `keccak-4k` at 3.7 s
with `crypto/hash/keccak256.c` at about 43 MB/s: its Keccak-f[1600] was a
loop with `% 5` indexing and table-driven rho/pi. The permutation is replaced
by XKCP's generic 64-bit implementation; the sponge, padding (0x01 … 0x80,
rate 136) and the public API of keccak256.h are unchanged.

## Files copied (byte-identical to the commit above; verified with `cmp`)

- `KeccakP-1600-64.macros` — from `lib/low/KeccakP-1600/common/`
- `KeccakP-1600-unrolling.macros` — from `lib/low/KeccakP-1600/common/`
- `LICENSE` — from the repository root

## How keccak256.c uses them (not a copy of a .c file)

`keccak256.c` reproduces `KeccakP1600_plain64_Permute_24rounds` from
`lib/low/KeccakP-1600/plain-64bits/KeccakP-1600-opt64.c:332-343` and its
round-constant table `KeccakF1600RoundConstants` (`:58-82`; the 24 values are
identical to the table keccak256.c already had), with the `ROL64` definition of
`:46` (portable shift/xor form) — on the existing `uint64_t[25]` state:

    declareABCDE
    copyFromState(A, state)
    rounds24
    copyToState(state, A)

Configuration = the file's default (`KeccakP-1600-plain64.h`:
`KeccakP1600_plain64_fullUnrolling`, lane complementing OFF — so the plain
lane array needs no complement transform around the call): `FullUnrolling`
selects the 24-round unrolled body in `KeccakP-1600-unrolling.macros`.

The macros are included from `keccak256.c` itself (path
`crypto/hash/third_party/xkcp/…` through `-I shared`), so every build that
compiles keccak256.c (messenger `libdna`, nodus `nodus_evm_keccak`,
shared/evm Makefiles) needs no build-file change.

Not used: everything else in `KeccakP-1600-64.macros` (`addInput`,
`loadInputLane` — its `PLATFORM_BYTE_ORDER` test is never expanded here;
the sponge in keccak256.c loads lanes with its own `load64_le`).

## Verification

- `shared/evm/tests/test_rlp_mpt.c` `test_keccak`: keccak256("") and ("abc")
  (execution-spec-tests vectors) plus 135 / 136 / 137 / 272 / 1000-byte inputs
  (rate boundary, multi-block) against the independent FIPS 202 oracle
  `shared/evm/tests/addr32_oracle.py`.
- `shared/evm/tests/test_addr32.c` (oracle-derived CREATE/CREATE2 addresses).
- The full Prague state-test conformance (`make conformance`), run by the
  ORCHESTRATOR.

## Local patches

None.
