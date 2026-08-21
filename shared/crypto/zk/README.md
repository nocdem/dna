# shared/crypto/zk — STARK proof stack (DNA Chain shielded lane)

A clean-room C implementation of a batched STARK prover + verifier for
the DNA Chain's shielded transaction lane (Goldilocks field, Poseidon2
MMCS/transcript, FRI, LogUp lookups, range/balance AIRs, aggregate
shielded statement verification).

> **AUTHORITATIVE STATUS LIVES IN [`RESUME.md`](RESUME.md).** Read its
> top block FIRST before touching anything here — per-module state,
> grounding evidence, audit history and next steps are maintained there,
> not in this file.

## What this module is

- A **verify + prove** stack in pure C — no Rust at runtime. The wallet
  side proves; the witness side verifies.
- **Plonky3 is the reference oracle, not a dependency**: every public
  function is byte-matched against test vectors emitted by
  [`tools/plonky3_oracle/`](tools/plonky3_oracle/README.md), a
  standalone Rust binary pinned to Plonky3 **tag v0.6.2**
  (commit `11cc5849`; previous pin `82cfad73` — see the pin-history
  note in `tools/plonky3_oracle/Cargo.toml`). Plonky3 source is never
  copy-pasted into this tree.
- **Consensus-linked but consensus-inert today:** the shielded verify
  stack (entry `dnac_shielded_verify_statement`, plus the native V3
  verifier `dnac_v3_native_verify_stateless`) compiles into `libnodus`
  (`nodus/CMakeLists.txt`), but the witness still rejects shielded
  transaction types (11/12/13) unconditionally. The accept-flip is a
  separate, gated activation step.

## What this module is NOT

- A general STARK framework — the AIRs prove exactly the DNA Chain
  statement family (range + balance + commitment binding).
- A SNARK / Bulletproof / KZG system — hash-based PQ security only.
- A Plonky3 binding — Rust is used only at vector-generation time.

## Build & test

```bash
cd /opt/dna/shared/crypto/zk
make test        # builds + runs all test binaries (89 currently)
make clean
```

Regenerating oracle vectors (only needed after touching the oracle or
re-pinning Plonky3):

```bash
./run_tests.sh --regen   # rebuilds the Rust oracle, regenerates + hash-verifies vectors
```

Vector JSON hashes are pinned in `tools/vectors/.expected_hashes`;
drift fails fast and means the pin or the oracle changed.

## Rules specific to this module

- **Every cryptographic construct MUST cite a pinned reference**
  (Plonky3 commit `file:line`, FIPS-202 page, NIST KAT). No invented
  parameters, domain separators or constructions — see root `CLAUDE.md`
  (`ANA HEDEF: KAFADAN KRİPTO YASAK`).
- **Determinism is law.** Byte-identical output across platforms; no
  `time()`, no unseeded randomness, scalar arithmetic in the verifier.
- **No copy-paste from Plonky3.** Read for understanding, write from
  scratch (license hygiene — see `feedback_cellframe_license_risk`).
- **C99 + `__uint128_t`**, QGP_LOG_* logging, caller-allocated buffers
  preferred.
- Cross-validation gate: public functions byte-match the oracle before
  merging.

## Design docs

Design docs live under `docs/plans/` and `dnac/docs/plans/`
(**local-only, gitignored** — never `git add`). The historical design
narrative (which modules shipped, were retired, or superseded) is
tracked in `RESUME.md`.
