# Algorand deterministic Falcon det1024

Source: https://github.com/algorand/falcon, commit
`19f185792c39326bebc173b2a100c2c247423be3` (v0.2.0).
`PROVENANCE.sha256` records every copied file and its repository-relative
basename. All files under `upstream/` are unchanged, including embedded
license notices. No separate upstream LICENSE file exists in this snapshot.

The CMake target compiles the ten core sources listed by upstream's Makefile
plus the committed `deterministic1024.c`; no generation, downloads, det512
implementation, tests, or chain integration are included. The unchanged
`deterministic.h` also contains upstream det512 declarations.
The unchanged config selects FPEMU=1, FPNATIVE=0, AVX2=0 and FMA=0.
The target defines `FALCON_UNALIGNED=0` for all builds, overriding the upstream
platform default through its supported configuration mechanism. Parent sanitizer
testing found a misaligned `uint64_t` dereference in `inner.h`'s `prng_get_u64`
fast path. This definition selects the existing upstream bytewise portable path;
vendored sources and sanitizer checks remain unchanged.

The new adapter validates pointers and lengths before fixed-size upstream calls,
normalizes empty NULL inputs, stages output before publication, and clears its
temporary buffers through the existing DSA secure-clear helper. Upstream internal
stack buffers and cleanup behavior are unchanged. Signature salt handling,
compressed/CT encodings and cryptographic operations are unchanged. Key generation
feeds explicit seed bytes to `shake256_init_prng_from_seed` followed by
`falcon_det1024_keygen`. The wrapper never calls a system randomness API; upstream
system-randomness entry points remain in the unchanged source.

From this directory, within the DNA source tree:

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --target qgp_algorand_falcon
emcmake cmake -S . -B build-wasm -DCMAKE_BUILD_TYPE=Release
cmake --build build-wasm --target qgp_algorand_falcon
```

Emscripten requires an installed SDK. The target uses the existing
`shared/crypto/sign/dsa/secure_clear.h`; it does not download dependencies.
These commands describe builds; they do not claim execution or test results.
