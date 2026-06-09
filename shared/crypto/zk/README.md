# shared/crypto/zk — STARK range proof module (DNAC v3)

**Status (2026-06-09):** v3 ships **transparent**. This ZK stack is the **ADDITIVE, P7-audited, verify-only foundation**, parked in-tree. **Confidential (hidden) amounts are DEFERRED to v4** — decisions + rationale below. Per-module working log: `RESUME.md`. v4 plan: `docs/plans/2026-06-09-v4-confidential-northstar-design.md`.

---

## PROJECT STATUS, DECISIONS & WHAT'S MISSING

### Where we are (one glance)
- **Built + grounded + P7-audited:** a complete STARK *verifier* stack + range/balance AIR, every public function oracle byte-matched against Plonky3 (pin `82cfad7`). `make clean && make test` GREEN, ~35 binaries, 0 warnings.
- **Mode = ADDITIVE only:** amounts are **cleartext**; the proof is *redundant* with the witness's native balance check (`nodus/src/witness/nodus_witness_verify.c:672-783` Check 4, native u64, overflow guard `:719`). **No privacy yet.**
- **Not linked into consensus:** `shared/crypto/zk` is a standalone Makefile — zero references in `nodus/src` / `dnac/src` (grep-confirmed). Nothing here runs in production.
- **Confidential (hidden amounts) = DEFERRED to v4.**

### Decisions & WHY (the load-bearing part)

**D1 — v3 ships transparent; confidential deferred to v4.**
*Why:* (a) confidential is months away regardless of crypto choice — there is **no prover** (this stack is verify-only) and **no consensus integration**; (b) the old v3 draft was *half-shield* (inputs cleartext) → privacy breaks at first spend, i.e. it would take the **full** soundness risk for only **partial** privacy; (c) the irreducible invisible-inflation risk (D5) is in tension with DNAC's verifiability premise (7/7 `state_root`); (d) no time pressure — v3 works transparent today.

**D2 — Binding a hidden amount (B1) is unavoidably an in-AIR hash, and in-AIR SHA3 has NO grounded reference.**
*Why:* hash commitments are **not homomorphic** → balance cannot be checked on commitments (unlike EC Pedersen); the amount must be hashed *inside* the proof to bind it to its published commitment. A 2026-06-08 deep-research pass (103 agents, primary-source, adversarially verified) found: **no citable/audited in-AIR FIPS-202 SHA3 *sponge* exists** to port. Plonky3 `keccak-air` is permutation-only (`lib.rs:1`); `symmetric/sponge.rs:19` is out-of-circuit overwrite-mode; the only full in-circuit Keccak sponge (PSE/Scroll) is Halo2/BN254, not AIR/Goldilocks. **No confidential design binds value with in-circuit SHA3** — all use algebraic hashes; SHA2/3 have "prohibitively large STARK complexity" (eprint 2020/948, EF/StarkWare). Full source list: v4 north-star Appendix A.

**D3 — Lock amendment: Poseidon2 for the in-AIR value commitment ONLY.**
`project_v3_zk_bitcoin_style`'s *"uniform SHA3-512 incl. in-AIR"* → **SHA3 stays for chain / transcript / Merkle / proof-internal**; **Poseidon2** is the in-AIR commitment hash. *Why Poseidon2:* it is the only in-AIR algebraic hash that is both Plonky3-shipped AND the most cryptanalyzed (over Monolith; Rescue has no `rescue-air`). Grounded params: `goldilocks/src/poseidon2.rs` — α=7 (`:70`), RF=8 (`:20-22`), R_P=22 (`:32`), WIDTH∈{8,12,16}; spec **eprint 2023/323**. With `SBOX_REGISTERS=1` constraint degree stays **3** → `num_qc=2` (`poseidon2-air/src/air.rs:305-309`). Cost ≈ 1 row, ~180 cells vs SHA3's 24 rows × 2633 (`keccak_p3_cols.h:22`) — ~350× cheaper.

**D4 — v4 confidential will be FULL-shield (inputs + outputs hidden), not half.**
*Why:* half-shield = weak privacy for full risk. Confidential is worth doing only fully.

**D5 — Crypto-agility + fallback baked in from day one.**
*Why:* in confidential mode a soundness break (hash / AIR / proof) → **invisible, unprovable inflation** (hidden amounts can't be summed; no homomorphic supply audit; cf. Monero's inflation-bug class). Mitigation: `hash_id` versioning + a **cleartext fallback switch** (via `DNAC_TX_CHAIN_CONFIG`) that degrades to ADDITIVE so the native Check 4 resumes enforcing visible balance. Base chain (Dilithium5 sigs, SHA3 nullifiers/state_root) is unaffected. Honest limit: fallback stops *future* inflation, not past silent inflation. Detail: v4 north-star §3.

### What we DID (done, grounded)
- **STARK verifier stack (C, pure, no Rust at runtime):** `field_goldilocks`, `zk_field_helpers`, `ntt_goldilocks`, `keccak_ref`, `keccak_p3_{cols,trace,air}`, `sponge_sha3_512`, `transcript`, `merkle_smt`, `fri_fold`, `fri_verifier` (incl. the FRI terminal-index **P0 fix** + its regression guard), `fri_proof_codec`, `stark_priming`, `stark_proof_codec`, `stark_constraints`.
- **Range/balance AIR (ADDITIVE):** `range_air` (B/S), `sum_balance` (I/U/F), combined `range_proof_air` air_eval (66-col, 68 constraints) — P7-audited (12 independent auditors, 2026-06-01), end-to-end C↔Plonky3 byte-matched.
- **B6 (field-wrap) solution designed:** B-bit range, `B+M≤63`, B≈57 — pure arithmetic, ready.
- **B7 (padding/output-count) solution designed:** `is_real` + `(1−is_real)·amount=0` + `count_acc` — existing idioms, ready.
- **Research verdict** (in-AIR SHA3 sponge does not exist) + **v4 north-star design doc** (3 mandatory sections + crypto-agility + red-team plan).

### What's MISSING (v4 work items)
- **Prover** — FFT/LDE (reuse `ntt_goldilocks`), FRI commit loop (reuse `fri_fold`), quotient computation, trace Merkle (reuse `merkle_smt`), query opening. Orchestration unwritten. **[MISSING]**
- **2-chunk quotient recompose** (`uni-stark/verifier.rs:59-96`) — shipped API is 1-chunk only (`stark_constraints.h:88-100`). Poseidon2 degree-3 needs it. **[MISSING]**
- **B1 commitment preimage layout** (fields, rate/capacity, domain-sep, output truncation, `hash_id`) — the old §6.2 draft is INVALIDATED; ground to eprint 2023/323. **[OPEN]**
- **Full-shield input hiding** (note-commitment tree + nullifier relation). **[OPEN]**
- **ZK/hiding layer** for real privacy — current STARK is non-ZK (`is_zk=0`), so binding ≠ hiding. **[OPEN]**
- **Consensus integration** + CMake/libdna link + Genesis 7/7 determinism gate. **[MISSING]**

### Durability
The current stack (the whole verifier + the FRI P0 fix) was **git-untracked** (P7 finding) — it would vanish on a fresh checkout / `git clean`. Committing the stack locks the fix and its guards in. (This README + the source are part of that commit.)

---

**Design docs (all local-only, gitignored — read before touching anything here):**
- `docs/plans/2026-06-09-v4-confidential-northstar-design.md` — **v4 confidential north-star (current direction; read FIRST)**
- `docs/plans/2026-05-30-dnac-range-proof-air-regrounding.md` — ratified ADDITIVE range_proof_air (66-col), B1/B6/B7 framing
- `dnac/docs/plans/2026-05-21-stark-range-proof-keccak-design.md` — original STARK design (§4.5/§6.2 INVALIDATED — see re-grounding)
- `dnac/docs/plans/2026-05-26-merkle-mmcs-design.md` — Merkle/MMCS module spec
- `docs/plans/2026-05-26-transcript-design.md` — Fiat-Shamir transcript spec
- `docs/plans/2026-05-27-fri-verifier-design.md` — FRI verifier spec (SHIPPED)
- `docs/plans/2026-05-29-fri-proof-wire-codec-design.md` — proof wire codec (SHIPPED)
- `docs/plans/2026-05-30-pcs-transcript-priming-design.md` — PCS/STARK priming (SHIPPED)
- `docs/plans/2026-05-30-stark-constraint-check-implementation-design.md` — generic verify_constraints (SHIPPED)

**Plonky3 reference version pinned:** `82cfad73cd734d37a0d51953094f970c531817ec` (2026-05-20).

## What this module is

A clean-room C implementation of a STARK-based zero-knowledge range proof system for DNAC v3 transactions. Hides output amounts behind cryptographic commitments + STARK proofs of well-formedness.

**NOT a port** of any existing library. Plonky3 is used as a *reference / spec / test-vector oracle only* — its Rust source is never copy-pasted into this tree (per `feedback_cellframe_license_risk.md` anti-pattern lesson).

## What this module is NOT

- A general STARK framework. The AIR here proves exactly one statement family: amount range + sum balance + commitment binding. No Cairo, no general computation.
- A recursive STARK system. Cross-TX aggregation is post-v3 work.
- A SNARK / Bulletproof / KZG system. STARK only; hash-based PQ security only.
- A Plonky3 Rust binding. We use Rust ONLY in `tools/plonky3_oracle/` to generate test vectors — production C library does not link Rust at runtime.

## Directory layout (current — see RESUME.md for grounding evidence per file)

```
shared/crypto/zk/
├── README.md                  (this file)
├── RESUME.md                  per-module status, audit history, rework-owed
├── Makefile                   build + `make test` harness (~35 binaries)
├── SUBAGENT_AUDIT_2026_05_23.md  evening-of-nuke independent audit record
│
├── field_goldilocks.{c,h}     Plonky3-grounded Goldilocks base + ext (fp2)
├── zk_field_helpers.{c,h}     bit utils + reverse_slice_index_bits + extended_pow
├── keccak_ref.{c,h}           reference Keccak-f[1600] (OpenSSL + NIST KAT)
├── keccak_p3_{cols,trace,air}.{c,h}  direct port of Plonky3 keccak-air
├── ntt_goldilocks.{c,h}       Plonky3 Radix2Dit port (base + ext)
├── sponge_sha3_512.{c,h}      FIPS-202 SHA3-512 sponge over keccak_p3 backend
├── transcript.{c,h}           port of Plonky3 SerializingChallenger64 + HashChallenger
├── merkle_smt.{c,h}           port of Plonky3 MerkleTreeMmcs (single-matrix + Phase 2A batch)
├── fri_fold.{c,h}             port of Plonky3 TwoAdicFriFolding (fold_row + fold_matrix all branches)
├── range_air.{c,h}            port of Plonky3 u64_to_bits_le + keccak-air column pattern
├── sum_balance.{c,h}          port of Plonky3 fib_air accumulator pattern (I constraint DNAC-original)
│
├── tests/                     ~35 C ctest-style binaries, all wired into `make test`
│
└── tools/
    ├── plonky3_oracle/        Rust binary that dumps test vectors
    │   ├── Cargo.toml         pinned to Plonky3 commit 82cfad73
    │   ├── Cargo.lock         (committed for reproducibility)
    │   └── src/main.rs        14 dump-* subcommands, one per vector
    ├── vectors/               JSON test vectors (14 files, all SHA-pinned in .expected_hashes)
    └── (refs/ holds NIST.FIPS.202.pdf — local-only, SHA-pinned)
```

### Roadmap notes (PARTIALLY SUPERSEDED — see the top STATUS section + RESUME.md for ground truth)

> Several items below have since SHIPPED (fri_verifier, fri_proof_codec, stark_priming, stark_proof_codec, stark_constraints, keccak_p3_*, sponge, ntt, range_proof_air air_eval). The authoritative current state is the **PROJECT STATUS** section at the top of this file. Kept for historical context.

#### (historical) Not yet on disk (next milestones, in design or queued)

- `fri_verifier.{c,h}` — FRI query / verifier port; design at `docs/plans/2026-05-27-fri-verifier-design.md`. Replaces the deleted `fri_commit` + `fri_query` modules (see RESUME.md "Second nuke" section).
- `range_proof_air.{c,h}` (or equivalent) — Faz 3 close; range proof end-to-end (3.4 rewrite). Blocked on FRI verifier + design doc § 4.5 rewrite.
- `range_prover` / `range_verifier` / `proof_serialize` (names tentative) — Faz 3 close.
- DNAC TX wire integration — Faz 4.

The historical "Faz 1 scaffolding" file plan referenced `fri_prover.h`, `fri_verifier.h`, `range_prover.h`, `range_verifier.h`, `proof_serialize.h`, `test_sha3_air.c`, `test_fri.c`, `test_range_proof_e2e.c`; those names are not authoritative — the actual layout will follow the FRI verifier design doc and the Faz 3 rewrite plan.

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

## Current status (per `make test` GREEN, see RESUME.md for per-module evidence)

| Module | Vector(s) | Oracle subcommand | C replay test | Grounding |
|---|---|---|---|---|
| field_goldilocks (base + ext) | field_ops, field_ext, two_adic_gens | `dump-field-ops`, `dump-field-ext`, `dump-two-adic-gens` | test_field_goldilocks*, test_two_adic_gens | Plonky3 direct call |
| zk_field_helpers | (none — unit tests) | n/a | test_zk_field_helpers (89/89) | Plonky3 source line-cited per fn |
| primitive_ops | primitive_ops.json | `dump-primitive-ops` | test_primitive_oracle (31/31) | Plonky3 reverse_slice_index_bits + extended_pow |
| keccak_ref (SHA3-512 backend) | (NIST KAT inline) | n/a | test_keccak_ref | OpenSSL + NIST KAT |
| sponge_sha3_512 | sha3_512_sponge.json | `dump-sha3-512-sponge` | test_sponge_sha3_512 (74×3 triple) | Plonky3 sha3 crate + keccak_ref + incremental |
| keccak_p3 (cols/trace/air) | (trace vs keccak_ref) | n/a | test_keccak_p3 | Direct port of Plonky3 keccak-air |
| ntt_goldilocks | ntt_goldilocks.json | `dump-ntt-goldilocks` | test_ntt_goldilocks + oracle (64/64) | Plonky3 Radix2Dit::dft + brute-force DFT |
| range_air | range_air.json | `dump-range-air` | test_range_air + column_layout | Plonky3 u64_to_bits_le + keccak-air |
| sum_balance | sum_balance.json | `dump-sum-balance` | test_sum_balance + column_layout | Plonky3 fib_air (I constraint DNAC-original) |
| transcript | transcript.json | `dump-transcript` | test_transcript_oracle (14 cases / 48 ops) | Plonky3 SerializingChallenger64 + HashChallenger |
| fri_fold (D.1 + D.2 + D.3 + D.4) | fri_fold_row, fri_fold_matrix_loga1, fri_fold_matrix | `dump-fri-fold-row`, `dump-fri-fold-matrix-loga1`, `dump-fri-fold-matrix` | test_fri_fold + 3 oracle tests (3125 + 330 + 1080) | Plonky3 TwoAdicFriFolding |
| merkle_smt (single-matrix) | merkle_mmcs.json | `dump-merkle-mmcs` | test_merkle_mmcs (501/501) | Plonky3 MerkleTreeMmcs (Strategy C) |
| merkle_smt (Phase 2A batch) | merkle_mmcs_batch_same_height.json | `dump-merkle-mmcs-batch-same-height` | test_merkle_mmcs_batch (511/511 incl. nm1=1 regression 204/204) | Plonky3 commit_batch / open_batch / verify_batch |

`make test` runs ~35 binaries; ~14,000+ byte-match cases GREEN. Vector SHAs pinned in `tools/vectors/.expected_hashes`. (The module table above is partial — see RESUME.md for the full, current per-module list incl. fri_verifier / stark_* / codecs.)

## Build integration (deferred)

Primitives still ship as standalone C files with their own ctests. No integration into `messenger/build` yet. Once the FRI verifier + Faz 3 close are in, we add to `messenger/CMakeLists.txt` and link into libdna.
