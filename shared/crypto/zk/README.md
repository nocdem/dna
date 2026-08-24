# DNAC STARK / zero-knowledge implementation

This directory contains the C prover, verifier, AIR, transcript, MMCS and FRI
components used by DNAC's shielded-transaction work.

## Current status

The cryptographic stack is implemented and has a standalone test harness.
The shielded verifier entry is compiled into Nodus, but shielded transactions
are **not accepted by the current consensus path**.

| Layer | Source status | Runtime / consensus status |
|-------|---------------|----------------------------|
| Goldilocks field and fp2 | Implemented | Standalone/library component |
| Poseidon2 transcript and MMCS | Implemented | Used by the current STARK stack |
| FRI and batched STARK verifier | Implemented | Linked into Nodus |
| Batched STARK prover | Implemented | Not a live consensus admission path |
| Shielded wire decode + statement verification | Implemented | Linked, but not called on an accepting path |
| Type-11 shielded transaction | Serialized and parsed | Rejected unconditionally by the witness until C3 |
| Shielded state transition | Incomplete | No live nullifier-set / anchor-root / state-root-v4 apply path |
| Ledger V2 | Separate work in progress | Not activated by this tree |

The decisive consensus boundary is
`nodus/src/witness/nodus_witness_verify.c::verify_shielded_tx`: after
fail-closed format checks it returns a rejection explaining that admission is
disabled until C3. “Verifier linked” therefore does not mean “shielded pool
live.”

## Test and vector inventory

The current Makefile registers **87** `test_*` binaries. The vector directory
contains **60** JSON vector files. These are source-tree counts, not a claim
that tests were executed for this README edit.

```bash
make -C shared/crypto/zk test
```

The Makefile compiles with warnings treated as errors and executes each
registered binary. Vector hashes are pinned in
`tools/vectors/.expected_hashes`.

## Reference oracle

`tools/plonky3_oracle/` is a build-time Rust program that generates reference
vectors. It is not linked into production C binaries.

Plonky3 dependencies are pinned in `Cargo.toml` to:

```text
11cc5849a1b57a2f520d6edc608b9e516517d841
```

This is the current v0.6.2-line pin. The older `82cfad73` pin is historical
and must not be presented as the active dependency.

```bash
cargo build --release --frozen \
  --manifest-path shared/crypto/zk/tools/plonky3_oracle/Cargo.toml
```

See [the oracle README](tools/plonky3_oracle/README.md) for vector-generation
commands and determinism boundaries.

## Current source layout

```text
shared/crypto/zk/
├── field_goldilocks.*          Goldilocks base-field arithmetic
├── field_goldilocks_ext.*      quadratic extension arithmetic
├── poseidon2_goldilocks.*      Poseidon2 permutation
├── duplex_challenger.*         Fiat-Shamir challenger
├── poseidon2_mmcs.*            plain and hiding MMCS paths
├── ntt_goldilocks.*            NTT / inverse NTT
├── fri_fold.*                  FRI folding
├── fri_verifier.*              FRI verification
├── batch_priming.*             batched transcript priming
├── batch_verify.*              batched STARK verification
├── batch_prover.*              batched STARK proving
├── shielded_verify.*           shielded statement verification entry
├── shielded_tree.*             depth-24 note tree component
├── conf_*                      confidential-action AIR components
├── range_air.*                 amount range constraints
├── sum_balance.*               balance constraints
├── tests/                      C test binaries
└── tools/
    ├── plonky3_oracle/         pinned Rust reference generator
    └── vectors/                committed JSON vectors and hashes
```

The retired `merkle_smt`, `sponge_sha3_512`, `stark_priming`,
`stark_proof_codec` and single-instance v3 prover files are not part of the
current source layout. Historical notes about them belong in archive/history,
not in the current inventory.

## Implementation boundaries

### Implemented

- Goldilocks and fp2 arithmetic;
- NTT/LDE building blocks;
- Poseidon2 permutation, challenger and transcript logic;
- plain, mixed-height and hiding MMCS paths;
- FRI folding, query verification and terminal checks;
- range, balance and confidential-action AIR components;
- batched proof encode/decode, prove and verify paths;
- shielded statement verification;
- a depth-24 note-tree component and cross-component KATs.

### Not established by this module

- an accepting consensus path for type 11;
- atomic insertion into a live nullifier set;
- accepted-anchor management in witness state;
- shielded state-root mutation and block application;
- shield/unshield boundary transaction semantics;
- production deployment, independent audit or certification;
- recursive proof aggregation.

## Security and evidence scope

- Plonky3 is used as a pinned reference and vector oracle; the production path
  remains C.
- Deterministic KATs establish agreement with the pinned reference for the
  covered inputs. They do not establish universal correctness or an external
  security audit.
- Fixed test seeds make committed vectors reproducible. Production prover
  entropy must not reuse deterministic KAT randomness.
- Hash-based/post-quantum design goals do not by themselves establish overall
  system privacy. Consensus state transitions, key management, metadata and
  boundary transactions remain part of the security model.

## Status records

`RESUME.md` contains a detailed engineering chronology and hand-off notes. It
is useful for historical reasoning but may include dates, counts and local plan
references from intermediate states. For current implementation claims, prefer
the tracked source, Makefile, tests and pinned dependency files.

## License

This directory is covered by the repository's [Apache License 2.0](../../../LICENSE).
