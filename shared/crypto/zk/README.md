# shared/crypto/zk — STARK range proof module (DNAC v3)

**Status:** Faz 1 scaffolding (2026-05-21). No implementation yet.

**Design doc:** `dnac/docs/plans/2026-05-21-stark-range-proof-keccak-design.md` (local-only, gitignored — read before touching anything here).

**Plonky3 reference version pinned:** `82cfad73cd734d37a0d51953094f970c531817ec` (2026-05-20).

## What this module is

A clean-room C implementation of a STARK-based zero-knowledge range proof system for DNAC v3 transactions. Hides output amounts behind cryptographic commitments + STARK proofs of well-formedness.

**NOT a port** of any existing library. Plonky3 is used as a *reference / spec / test-vector oracle only* — its Rust source is never copy-pasted into this tree (per `feedback_cellframe_license_risk.md` anti-pattern lesson).

## What this module is NOT

- A general STARK framework. The AIR here proves exactly one statement family: amount range + sum balance + commitment binding. No Cairo, no general computation.
- A recursive STARK system. Cross-TX aggregation is post-v3 work.
- A SNARK / Bulletproof / KZG system. STARK only; hash-based PQ security only.
- A Plonky3 Rust binding. We use Rust ONLY in `tools/plonky3_oracle/` to generate test vectors — production C library does not link Rust at runtime.

## Directory layout (planned, not yet implemented)

```
shared/crypto/zk/
├── README.md                  (this file)
├── CMakeLists.txt             (TBD — build integration after primitives stable)
│
├── field_goldilocks.h         API: modular arithmetic, extension field
├── field_goldilocks.c         impl (Faz 1)
│
├── merkle_smt.h               API: binary Merkle tree, SHA3-512 internal nodes
├── merkle_smt.c               impl (Faz 1)
│
├── transcript.h               API: Fiat-Shamir transcript with strict ordering
├── transcript.c               impl (Faz 1)
│
│   Note: per Option B revision (2026-05-21), there is NO separate in-AIR
│   hash helper. All hashing uses SHA3-512 (FIPS-202) via the project-wide
│   `crypto/hash/qgp_sha3.h`. In-AIR commitment hashing is encoded as
│   constraints inside range_air.c (Faz 3 scope) — no custom padding.
│
├── fri_prover.h               API: FRI commit + query phase
├── fri_prover.c               impl (Faz 2)
├── fri_verifier.h
├── fri_verifier.c             impl (Faz 2)
│
├── range_air.h                API: AIR specification (constraint system)
├── range_air.c                impl (Faz 3)
├── range_prover.h
├── range_prover.c             impl (Faz 3)
├── range_verifier.h
├── range_verifier.c           impl (Faz 3)
│
├── proof_serialize.h          API: proof wire format codec
├── proof_serialize.c          impl (Faz 3)
│
├── tests/                     ctest unit tests, per primitive
│   ├── test_field_goldilocks.c
│   ├── test_merkle_smt.c
│   ├── test_transcript.c
│   ├── test_sha3_air.c       (Faz 3 — AIR-encoded SHA3-512 vs reference)
│   ├── test_fri.c
│   └── test_range_proof_e2e.c
│
└── tools/
    ├── plonky3_oracle/        Rust binary that dumps test vectors
    │   ├── Cargo.toml         pinned to Plonky3 commit 82cfad73
    │   ├── Cargo.lock         (committed for reproducibility)
    │   └── src/main.rs        per-primitive test vector dump
    └── vectors/               JSON test vectors generated from Plonky3 oracle
        ├── field_ops.json
        ├── merkle.json
        ├── transcript.json
        └── ...
```

## Implementation order (Faz 1 scope)

Per design doc § 8 Faz 1:

1. **field_goldilocks** — modular arithmetic + Goldilocks² extension. Plonky3 oracle: test vectors for add, sub, mul, inv, exp; extension multiplication & inversion. Target: ~500-800 LoC C + 100+ ctests. ✅ Sprint 1.2 + 1.3 GREEN — 13,389 cross-validated cases.
2. **merkle_smt** — binary tree, SHA3-512 (FIPS-202) internal nodes, fixed-depth + indexed leaves + typed null-padding (D4, D4.1 from design doc). Uses `crypto/hash/qgp_sha3.h` from the project root. Target: ~300-400 LoC + 50+ ctests.
3. **transcript** — Fiat-Shamir per design doc § 4.3 (with F4 fix: chain_id + block_height + tx_index in T₀). SHA3-512 hash chain. Target: ~200-300 LoC + 30+ ctests.
4. ~~**keccak_air_helpers**~~ — RETIRED per Option B revision 2026-05-21. All hashing is uniform SHA3-512; no separate in-AIR hash module. In-AIR SHA3-512 encoding lives in `range_air.c` (Faz 3 scope).
5. **plonky3_oracle** — Rust binary cross-validates every C output against Plonky3. Target: ~500 LoC Rust + integration with C tests via JSON vectors. ✅ Sprint 1.1 GREEN — field_ops + field_ext dumps.

**Cross-validation gate:** Every C public function MUST byte-match Plonky3 oracle output for at least 1000 randomized test cases before merging. CI failure if any drift.

## NOT in Faz 1 scope

- FRI prover / verifier (Faz 2).
- AIR / range proof (Faz 3).
- DNAC wire integration (Faz 4).
- CMake build integration with libdna (later — once primitives stable).

## Coding rules specific to this module

- **Determinism is law.** Per design doc § 4 invariants D1-D7, every operation byte-identical across implementations. No `time()`, no `rand()` outside seeded PRNG, no SIMD that changes reduction order.
- **No copy-paste from Plonky3.** Read for understanding, write from scratch. Faz 1 close: grep this tree for distinctive Plonky3 phrasing; reject any match.
- **Scalar arithmetic only.** No SIMD in verifier (per F10). Prover may use SIMD later if proven equivalent, but Faz 1 is scalar.
- **Constant-time where it matters.** Field inversion and SHA3-512 / Keccak-f[1600] permutation should be constant-time (constant-time SHA3 is the existing `crypto/hash/qgp_sha3.c` already); trace generation NEED NOT be constant-time (amounts are private to wallet anyway).
- **C99 with GNU extensions for `__uint128_t`.** No C++. No Rust at runtime.
- **Logging via QGP_LOG_*** per project convention. No printf.
- **Memory: caller-allocated buffers preferred.** No malloc in hot paths if possible.

## Plonky3 oracle build (Faz 1 first action)

```bash
cd /opt/dna/shared/crypto/zk/tools/plonky3_oracle
cargo build --release --frozen
./target/release/plonky3_oracle dump-all --out ../vectors/
```

Cargo.lock pinning ensures bit-reproducible oracle builds. Drift = CI fail.

## Faz 1 — full test pipeline (Sprint 1.6 closure)

```bash
# Quickest: just run all 4 cross-validation suites using cached vectors.
cd /opt/dna/shared/crypto/zk
./run_tests.sh

# Full pipeline: regen vectors from Plonky3 oracle, verify hashes, run tests.
# Use this on first checkout or after touching tools/plonky3_oracle/.
./run_tests.sh --regen
```

What `run_tests.sh --regen` does:

1. Builds the Rust Plonky3 oracle with `--frozen` (Cargo.lock consistency).
2. Regenerates all 4 vector JSON files (`tools/vectors/*.json`).
3. Verifies each JSON's sha256 matches `tools/vectors/.expected_hashes`.
   - **Drift fails fast** with a clear diff — means Plonky3 upstream or oracle
     generation changed. Required action: re-pin Plonky3 commit in Cargo.toml
     and design doc § 0, then update `.expected_hashes` with new hashes.
4. Builds the 4 C test binaries via `make all`.
5. Runs `make test` — executes all 4 cross-validation suites and prints
   `FAZ 1 GATE: ALL GREEN` on success.

## Direct Makefile targets

```bash
make all       # build all 4 test binaries → build/test_*
make test      # build + run all suites
make clean     # remove build/
```

## Current Faz 1 status

| Sprint | Primitive | Test cases | Status |
|--------|-----------|-----------|--------|
| 1.2 | field_goldilocks base    | 7,204 | ✅ |
| 1.3 | field_goldilocks ext     | 6,185 | ✅ |
| 1.4 | merkle_smt               |   809 | ✅ |
| 1.5 | transcript               |    71 | ✅ |
| 1.6 | CI gate                  |    —  | ✅ (this script) |
| **Cumulative** | | **14,269** | **0 fail** |

## Build integration (deferred)

Faz 1 primitives ship as standalone C files with their own ctests. No integration into `messenger/build` yet. Once primitives are stable (~Faz 1 end), we add to `messenger/CMakeLists.txt` and link into libdna.
