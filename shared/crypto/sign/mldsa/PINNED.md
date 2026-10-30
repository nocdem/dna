# Shared ML-DSA-44 and ML-DSA-65 adapters

This target reuses existing DNA `shared/crypto/sign/dsa` sources at local base
`7822a02d9cde6347fe47005bf880d695de92b58c`, without copying or modifying them.
`PROVENANCE.sha256` records the source/header paths and local hashes. Parent
research pins their reference to https://github.com/pq-crystals/dilithium at
`444cdcc84eb36b66fe27b3a2529ee48f6d8150c2`. This is source provenance, not an
independent claim of conformance; parent NIST tests and review remain required.

`EXISTING_SOURCE_DIFFS.txt` preserves the parent's complete local-versus-pinned
source comparison, including both hashes for each compared file. Existing
differences are seed-keypair declarations/implementation, mode-5 config,
parameter macro cleanup, secure clearing in SHAKE/polynomial/signing code,
the QGP entropy adapter and propagated entropy errors, and an accumulated-byte
signature challenge comparison. `secure_clear.h` is local-only. None of those
existing differences is introduced or edited by this target.

New build adaptations:

- Compile existing mode-dependent sources twice, selecting mode 2 (44) and mode
  3 (65) through a private forced include. Its CONFIG_H guard suppresses the
  local config's mode-5 selection. Private namespaces are
  `qgp_mldsa44_private_*` and `qgp_mldsa65_private_*`; randomized-signing config
  remains enabled.
- Keep the existing SHAKE namespace unchanged. Reuse an existing CMake `dsa`
  target when present; otherwise compile its `fips202.c` once into this archive.
- Alias the raw source entropy call to a private provider that fails every
  nonempty request. Existing raw failure handling remains intact. The public
  facade calls only seed-based key generation and explicit-randomness internal
  signing; it never substitutes zero randomness after a failure.
- Validate parameter identifiers, pointers, exact sizes, capacities and context
  limits; normalize empty NULL messages/contexts; stage outputs and clear
  temporary key/signature buffers using existing `secure_clear.h`.
- Public pure signing/verification builds the existing source's
  `00 || ctxlen || ctx` prefix. Internal interfaces pass prefix length zero.
  No HashML-DSA or chain-specific preprocessing is implemented.

Parameter sizes are obtained from the reused mode-specific `params.h` through
`mode_adapter.c`: 44 uses 1312/2560/2420 bytes and 65 uses 1952/4032/3309 bytes
for public key/secret key/signature. Seed and signing randomness are 32 bytes.
Facade staging arrays use the larger supported sizes.

Build from this directory inside DNA:

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --target qgp_mldsa
emcmake cmake -S . -B build-wasm -DCMAKE_BUILD_TYPE=Release
cmake --build build-wasm --target qgp_mldsa
```

No downloads or executable tests occur during configuration/build.
