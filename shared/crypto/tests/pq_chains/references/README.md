# Test reference dependencies

These files pin independent **test oracle** dependencies. They are not production
dependencies. Native/WASM conformance tests require neither Go nor npm: they use
the committed, hashed binary fixtures. Fixture refresh is a maintenance action.

* CIRCL 1.6.3: CometBFT v0.40.0 / Cosmos SDK v0.55.0 / XION v32.0.0 dependency.
* CIRCL 1.6.5: Splendor `38ac3ded57d6fa931dba3036d490c5d66b0fbcbc` dependency.
* Noble 0.2.1: exact version selected from Asentum SDK 0.2.0's `~0.2.1` range.
  Its transitive `@noble/hashes` is exactly 1.6.0. The lock pins npm integrity.

`prepare_chain_vectors.py --only circl --upstream-root PATH` uses these Go
module/sum files and `-mod=readonly`, under exact toolchain Go 1.26.10. Module
downloads use Go's checksum verification. The SHA3-256 anchors checked by the
ML-DSA oracle are committed in Splendor's `core/crypto/mldsa_kat_test.go`.

For Noble, copy `noble-package.json` and `noble-package-lock.json` to
`PATH/noble-oracle/package.json` and `PATH/noble-oracle/package-lock.json`, then
run `npm ci --ignore-scripts --no-audit --no-fund` there. Run
`prepare_chain_vectors.py --only noble --upstream-root PATH` afterwards. The
oracle exercises the same `ml_dsa65.keygen(seed)` and `sign(sk,msg)` calls as the
published SDK; it does not exercise network calls or transaction serialization.

The C oracles use the exact repositories and source files listed in the scripts
and [chain contract document](../../../sign/PQ_PORTS.md). Generated answers are
checked against the port only after the independent reference accepts them.
The explicit negative controls retain the reference's rejection result.
