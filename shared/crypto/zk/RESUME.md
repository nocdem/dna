# RESUME — DNAC v3 ZK module implementation state

**Last work:** 2026-05-21 (single session, 20 sub-sprints, 16,013 cross-validated tests).
**Status:** Faz 0 + Faz 1 + Faz 2 + Faz 3 partial (3.1, 3.2, 3.3a, 3.3b.1-7) complete.

---

## Quickest sanity check (next session, first thing)

```bash
cd /opt/dna/shared/crypto/zk
./run_tests.sh
```

Expected: **ALL GREEN** for every sub-sprint, totaling ~16k tests. If anything fails, the upstream Plonky3 oracle drifted (recheck Cargo.lock against pin) or a primitive regressed.

To regenerate vectors from scratch (requires rustup):

```bash
./run_tests.sh --regen
```

---

## Where to read first (re-context)

1. **Memory:**
   - `project_v3_zk_bitcoin_style.md` — architectural identity (Bitcoin-style v3.0, Cosmos migration later)
   - `project_v3_zk_implementation_progress.md` — what was built in this session
   - `project_master_roadmap.md` — updated 2026-05-21 with the new direction
2. **Design doc:**
   - `dnac/docs/plans/2026-05-21-stark-range-proof-keccak-design.md` (local-only, gitignored — read for protocol intent, threat model, red-team self-audit)
3. **Module readme:**
   - `shared/crypto/zk/README.md` — directory layout, build/test commands, sprint status
4. **Tool:**
   - `shared/crypto/zk/tools/plonky3_oracle/README.md` — Plonky3 oracle build (Rust)

---

## What's built (file inventory in shared/crypto/zk/)

### C implementation (Faz 1 + 2 + 3.1-3.3)

| File | Purpose |
|---|---|
| `field_goldilocks.{c,h}` | Goldilocks base + Goldilocks² extension arithmetic |
| `merkle_smt.{c,h}` | SHA3-512 binary Merkle tree (DNAC domain separators) |
| `transcript.{c,h}` | Fiat-Shamir SHA3-512 chain (F4 fix: chain_id+block_height+tx_index in T₀) |
| `fri_fold.{c,h}` | Arity-2 FRI fold primitive |
| `fri_commit.{c,h}` | Multi-layer FRI commit phase (Merkle commits + transcript-derived betas) |
| `fri_query.{c,h}` | FRI query phase prover + verifier |
| `range_air.{c,h}` | 64-bit range decomposition AIR |
| `sum_balance.{c,h}` | Multi-output composition + TX conservation AIR |
| `keccak_ref.{c,h}` | Standalone FIPS-202 SHA3-512 + step-by-step API |
| `keccak_air_bits.{c,h}` | Bit decomposition + XOR-in-field primitives |
| `keccak_air_theta.{c,h}` | θ step AIR encoding |
| `keccak_air_rho_pi.{c,h}` | ρ + π step AIR encoding |
| `keccak_air_chi.{c,h}` | χ step AIR encoding (non-linear) |
| `keccak_air_iota.{c,h}` | ι step AIR encoding (round constant XOR) |
| `keccak_air_f1600.{c,h}` | 24-round Keccak-f[1600] assembly |
| `keccak_air_sha3_512.{c,h}` | Single-block SHA3-512 AIR e2e (padding + state binding + squeeze) |

### Rust reference oracle (build-time only)

- `tools/plonky3_oracle/Cargo.toml` — Plonky3 pinned to `82cfad73`
- `tools/plonky3_oracle/Cargo.lock` — full dep graph pinned
- `tools/plonky3_oracle/src/main.rs` — CLI binary, 8 `dump-*` subcommands
- `tools/vectors/*.json` (6 files) — committed test vectors
- `tools/vectors/.expected_hashes` — sha256 pin per vector

### Build / test runner

- `Makefile` — standalone, builds 13 test binaries
- `run_tests.sh` — full pipeline (optional `--regen` flag rebuilds oracle)
- `README.md` — module documentation
- `tests/test_*.c` (13 files) — per-sub-sprint cross-validation

---

## What's NOT built yet (next sub-sprints in order)

### Sub-sprint 3.3b.8: Multi-block SHA3-512 (input > 70 bytes)

The current `keccak_air_sha3_512.c` only handles `input_len ≤ 70`. DNAC range proof commitment input is ~188 bytes (`"DNAC_RP_COMMIT\0"` + amount(8) + blinding(32) + recipient_fp(129) + output_index(4) = 188), requiring 3 blocks.

**Work:** Chain multiple Keccak-f[1600] invocations through state-mutating absorption. Each block XORs into rate portion, runs f1600, becomes input to next block's absorb. Witness extends to N × f1600 witnesses + N block-padding witnesses + inter-block state-chaining constraints.

**Estimate:** 1 session.

### Sub-sprint 3.4: Full range proof statement integration

Compose into one combined witness:
- Per output: range AIR (`range_air.c`) + commitment SHA3-512 AIR (`keccak_air_sha3_512.c`)
- Across outputs: sum-balance AIR (`sum_balance.c`)
- Public inputs: output commitments[], claimed_input_sum, fee, chain_id, block_height, tx_index

Verify that:
- Each output's range AIR `acc[63]` value equals the amount fed into the commitment hash
- All commitments byte-match the published `c_i` in the public input
- Σ output amounts + fee = claimed_input_sum

**Estimate:** 1-2 sessions.

### Sub-sprint 3.5: Full STARK prover

AIR → trace → FRI commit (using `fri_commit.c`) → query openings (`fri_query.c`) → serialized proof bytes. This is the proof bytes that go into `DNAC_TX_V3.range_proof` field.

**Estimate:** 1-2 sessions.

### Sub-sprint 3.6: Full STARK verifier + tamper resistance

Verifier reconstructs transcript, verifies FRI proof, checks AIR constraints at sampled points. Plus end-to-end attack-resistance test suite (forge amount, swap commitments, etc.).

**Estimate:** 1-2 sessions.

### Faz 4+: DNAC wire integration

After Faz 3 complete:
- `DNAC_TX_V3` wire format (`dnac/include/dnac/transaction.h`)
- `verify.c::Check N` for range proof
- `nodus_witness_bft.c` PROPOSE invocation
- Flutter FFI for wallet
- Chain wipe deploy (per `feedback_consensus_deploy_stop_all.md`)
- Genesis Protocol harness 7/7 (per `feedback_genesis_protocol.md`)

**Estimate:** 3-4 sessions.

---

## Open spec questions (Faz 0 § 10 carryover)

| # | Question | Status |
|---|---|---|
| Q4 | Input cleartext `amount` field — keep in V3 or drop in V4? | Open; keep for now |
| Q6 | `DNAC_CFG_MAX_TXS_PER_BLOCK = 5` at v3.0 genesis | Open; recommend yes |
| Q7 | v3.0 release notes formally promise "migration is future deliberate decision" | Open; recommend yes |

---

## Open ship-blockers (parallel work, not blocking ZK development)

| # | Issue | Reference |
|---|---|---|
| SB1 | debug.keystore leaked (pw=android, signs release APKs) | `project_debug_keystore_leak.md` |
| SB2 | Cellframe Dilithium GPL3 contamination in shared/crypto/sign/cellframe_dilithium/ | `feedback_cellframe_license_risk.md` |
| External RT | Multi-agent red-team audit of design doc + impl (per `feedback_red_team_every_design.md`) | not yet performed |
| GitLab CI | Add zk-test job to .gitlab-ci.yml (run_tests.sh) | not yet wired |

---

## Critical conventions (do not deviate without design-doc revision)

1. **SHA3-512 (FIPS-202) for ALL hashing** — chain-level, proof-internal, AND in-AIR. No Poseidon, no Pedersen, no custom-padded Keccak.
2. **Goldilocks² over `x² − 7`** — irreducible verified against Plonky3 pinned commit.
3. **Plonky3 commit pin `82cfad73`** — bump requires design-doc revision + full vector re-validation + `.expected_hashes` update.
4. **No Rust at runtime** — Plonky3 oracle is build-time only. Production binaries are pure C.
5. **Test vectors are gospel** — `.expected_hashes` is the gate. Drift = fail = chain split risk.
6. **Bitcoin-style identity** — v3.0 is 1 TPS sustainable, full-history, no pruning. Migration to snapshot model is post-2027 deliberate decision (per `project_v3_zk_bitcoin_style.md`).

---

## How to run a quick smoke test of any single sub-sprint

```bash
cd /opt/dna/shared/crypto/zk
make build/test_<name>      # e.g., test_keccak_air_sha3_512
./build/test_<name>
```

Test names: `test_field_goldilocks`, `test_field_goldilocks_ext`, `test_merkle_smt`, `test_transcript`, `test_two_adic_gens`, `test_fri_fold`, `test_fri_commit`, `test_fri_e2e`, `test_range_air`, `test_sum_balance`, `test_keccak_ref`, `test_keccak_air_bits`, `test_keccak_air_theta`, `test_keccak_air_rho_pi`, `test_keccak_air_chi`, `test_keccak_air_iota`, `test_keccak_air_f1600`, `test_keccak_air_sha3_512`.

---

## Critical pitfalls to remember next session

1. **Goldilocks field bound:** `p = 2⁶⁴ − 2³² + 1 < 2⁶⁴`. Amounts ≥ p reduce mod p — DNAC supply ~2⁵⁷ is fine but never test with UINT64_MAX.
2. **F4 fix:** transcript T₀ MUST bind chain_id + block_height + tx_index, otherwise intra-block proof replay possible.
3. **F8 fix:** range proof statement MUST include `claimed_input_sum` as public input, NOT trust cleartext input fields. Witness cross-checks.
4. **Padded Keccak vs SHA3:** Option B revision (2026-05-21) — there is ONLY SHA3-512 (FIPS-202). No custom-padded Keccak variant. Cross-protocol separation via domain separator prefixes, not padding differences.
5. **AIR witness memory:** each Keccak-f[1600] witness is ~5.7 MB. SHA3-512 single-block witness is ~6 MB. Multi-block SHA3 (3 blocks) ≈ 18 MB per hash. 4 hashes per range proof → ~72 MB witness. Heap-allocate; don't stack.
6. **Constraint count realism:** ~582k constraints per single-block SHA3-512. 4 hashes per range proof + range_air (~128 per output × 2 outputs = 256) + sum-balance (~1) + commitment chain = **roughly 2.3M constraints total per range proof**. Prove time will be substantial — mobile bench in Faz 5 is the real gate.
7. **Test counters are cumulative** — when adding new sub-sprints, the suite total grows. Don't regress an earlier suite while adding new tests.

---

## Snapshot of all primitives' validation status

| Primitive | Last validated | Validation method |
|---|---|---|
| Goldilocks base ops | 2026-05-21 | 7,204 cases vs Plonky3 |
| Goldilocks² ext ops | 2026-05-21 | 6,185 cases vs Plonky3 |
| Two-adic generators (33) | 2026-05-21 | exact table match |
| SHA3-512 Merkle (DNAC seps) | 2026-05-21 | 809 cases vs reference |
| Fiat-Shamir transcript | 2026-05-21 | 71 multi-step scenarios |
| FRI arity-2 fold | 2026-05-21 | 1,374 cases vs Plonky3 |
| FRI commit phase | 2026-05-21 | 123 inter-state checks |
| FRI query+verify | 2026-05-21 | self + 5 tamper attack |
| Range AIR (64-bit) | 2026-05-21 | self + 3 tamper types |
| Sum-balance AIR | 2026-05-21 | self + 5 tamper types |
| Standalone SHA3-512 | 2026-05-21 | NIST KAT + OpenSSL |
| Keccak-AIR bit primitives | 2026-05-21 | XOR-2, XOR-5 with aux |
| Keccak θ step AIR | 2026-05-21 | self + 5 tamper types |
| Keccak ρ+π step AIR | 2026-05-21 | self + 4 tamper types |
| Keccak χ step AIR | 2026-05-21 | self + 3 tamper types |
| Keccak ι step AIR (24 RCs) | 2026-05-21 | self + wrong-RC tamper |
| 24-round Keccak-f[1600] AIR | 2026-05-21 | 4 valid + 2 inter-round tamper |
| Single-block SHA3-512 AIR | 2026-05-21 | 5 valid + 2 tamper (output, padded) |

---

**To pick up next session:** start with `cd /opt/dna/shared/crypto/zk && ./run_tests.sh` to verify nothing regressed, then read the "What's NOT built yet" section above and pick the next sub-sprint.
