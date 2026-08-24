# plonky3_oracle — DNAC reference-vector generator

`plonky3_oracle` is a build-time Rust program that generates deterministic
JSON vectors for the C implementation in `shared/crypto/zk/`. It is never
linked into the production C runtime.

## Dependency pin

The active Plonky3 pin is defined in `Cargo.toml`:

```text
11cc5849a1b57a2f520d6edc608b9e516517d841
```

This corresponds to the v0.6.2 line used by the current batch-STARK stack. The
older `82cfad73` value is a previous pin and is not the active reference.
`Cargo.lock` is committed and should remain synchronized with
`Cargo.toml`.

## Build

From the repository root:

```bash
cargo build --release --frozen \
  --manifest-path shared/crypto/zk/tools/plonky3_oracle/Cargo.toml
```

The first uncached build needs network access to fetch the pinned Git
dependencies. `--frozen` prevents dependency-resolution drift; it does not
make an uncached network dependency available offline.

## Commands

The oracle now covers field, transcript, Poseidon2/MMCS, FRI, AIR, prover and
batched-proof scenarios. It is not a field-operations-only Sprint 1 stub.

Use the binary's help as the authoritative command list:

```bash
cargo run --release --frozen \
  --manifest-path shared/crypto/zk/tools/plonky3_oracle/Cargo.toml -- --help
```

Examples:

```bash
# One vector family
cargo run --release --frozen \
  --manifest-path shared/crypto/zk/tools/plonky3_oracle/Cargo.toml -- \
  dump-field-ops --out shared/crypto/zk/tools/vectors/field_ops.json

# Regenerate the families included by dump-all
cargo run --release --frozen \
  --manifest-path shared/crypto/zk/tools/plonky3_oracle/Cargo.toml -- \
  dump-all --out-dir shared/crypto/zk/tools/vectors
```

Some historical subcommands remain as explicit retirement messages so old
automation fails visibly instead of silently producing obsolete proof-path
vectors. `dump-all` intentionally omits retired families.

## Determinism

- Arithmetic and structural cases use deterministic inputs.
- Prover/hiding KATs use fixed seeded streams where byte-stable randomness is
  required.
- The active Plonky3 commit and dependency graph are pinned.
- Generated vector hashes are recorded by the parent ZK harness.

Fixed seeds are for test-vector reproducibility only. They are not a production
entropy source.

## Regeneration policy

Regenerate and review vectors when:

- the Plonky3 pin changes;
- the oracle output format changes;
- a covered C primitive or proof shape changes;
- a new cross-language KAT is added.

After regeneration, run:

```bash
make -C shared/crypto/zk test
```

Any vector or expected-hash drift must be reviewed together with the code or
parameter change that caused it.

## Scope

The oracle establishes byte-level agreement for covered cases against a pinned
reference implementation. It does not establish production readiness, live
consensus integration, an independent audit, or universal cryptographic
correctness.
