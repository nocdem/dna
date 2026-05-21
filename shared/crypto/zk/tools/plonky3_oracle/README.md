# plonky3_oracle — DNAC-ZK reference test vector generator

A standalone Rust binary that links Plonky3 (pinned to commit `82cfad73cd734d37a0d51953094f970c531817ec`) and emits JSON test vectors. The C side of `shared/crypto/zk/` consumes these vectors in `ctest` and asserts byte-identical output.

**Why this exists:** clean-room C implementations of cryptographic primitives have a high bug rate at the bit level. The Plonky3 oracle is the ground-truth reference — if our C output diverges from the oracle by a single byte, that's a determinism violation and a chain-split bug waiting to happen.

This oracle is **build-time only**. It is NEVER linked into the runtime DNAC binary. Production C code does not depend on Rust.

## Prerequisites

- **Rust toolchain (rustup recommended)**. Tested with Rust 1.85+ (edition 2024 required by `Cargo.toml`).
- **Network access** during first build (cargo fetches Plonky3 from GitHub).
- **~2 GB free disk** for build artifacts + Plonky3 source.

Install rustup (one-time, user-local, no root):

```sh
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
. "$HOME/.cargo/env"
rustup install stable
```

## Build

```sh
cd /opt/dna/shared/crypto/zk/tools/plonky3_oracle
cargo build --release
```

First build downloads Plonky3 (~10 MB) plus crate dependencies (~100 MB). Subsequent builds are incremental.

**Important:** After first successful build, **commit `Cargo.lock`** to lock down the full dependency graph. Run `cargo build --release --frozen` thereafter to enforce frozen dependency resolution (CI fails if `Cargo.lock` doesn't match upstream).

## Run

```sh
# Emit base-field test vectors (Sprint 1.1 scope).
cargo run --release -- dump-field-ops --out ../vectors/field_ops.json

# Emit all available vectors (skipping not-yet-implemented dumps).
cargo run --release -- dump-all --out-dir ../vectors/
```

Each subcommand writes a single JSON file. Output is pretty-printed for review; C-side tests parse with a streaming JSON parser.

## Sprint status

| Subcommand            | Sprint | Status |
|-----------------------|--------|--------|
| `dump-field-ops`      | 1.1    | ✅ implemented (this sprint) |
| `dump-field-ext`      | 1.3    | stub — exits cleanly with message |
| `dump-merkle`         | 1.4    | stub |
| `dump-transcript`     | 1.5    | stub |
| `dump-keccak-air`     | 1.6    | stub |

## Determinism

Inputs are derived via a deterministic SplitMix64-style mix of (operation_id, case_index). No `rand`. No `time`. Same binary → same JSON output, byte-for-byte, on any machine, any architecture, any day.

Build determinism relies on:

1. **Pinned Plonky3 commit** (`Cargo.toml` `[dependencies]` rev = `82cfad73...`).
2. **Committed `Cargo.lock`** (after first build).
3. **`cargo build --release --frozen`** to refuse upstream drift.
4. **`profile.release` with `codegen-units = 1` + `lto = "fat"`** (already set in `Cargo.toml`).

If you suspect oracle non-determinism, hash the JSON output and compare with a teammate's hash. They must match.

## When to regenerate vectors

- After bumping Plonky3 commit pin (rare — requires design-doc revision).
- After changing `CASES_PER_OP` (currently 1024 per operation).
- After adding new test scenarios to subcommands.

Regenerated vectors must be committed to `shared/crypto/zk/tools/vectors/` and any drift triggers C-side ctest review.

## Why edition 2024

Plonky3 at the pinned commit uses Rust 2024 edition idioms. Matching here avoids workspace-vs-package edition mismatches.
