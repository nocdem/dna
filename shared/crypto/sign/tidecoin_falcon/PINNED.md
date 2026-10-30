# Tidecoin legacy Falcon-512 port

Primary source: Tidecoin commit `7d653be5d24e73b49d101578afb33d8d7a889c1d`.
See MANIFEST.md for every copied file and upstream/local SHA256. Licenses are
upstream/COPYING and upstream/pq/falcon-512/LICENSE. No configure downloads.

The facade calls deterministic keypair from falcon-512/pqclean.c (48-byte seed),
tidecoin_falcon512_sign_legacy, and tidecoin_falcon512_verify with legacy_mode=1.
It preserves hash_to_point_ct, legacy 7085 norm fallback, header 0x39, and the
10000-attempt legacy signing loop. Public key/secret key sizes are from api.h;
688-byte signature capacity is falcon512.c's 1+40+(690-40-3). Legacy verification
has no added signature-size or salt restrictions.

Adaptations:
- private_namespace.h mechanically aliases pinned FIPS202 functions/context types,
  PQClean identifiers and raw Tidecoin functions. It is force-included privately by
  CMake. Upstream arithmetic and SHAKE permutation/absorb/finalize/squeeze
  operations remain unchanged.
- The wrapper supplies the only randombytes implementation, backed by an explicit
  caller callback in a C11 thread-local, per-call frame. Nested calls restore the
  previous frame. There is no OS/default entropy source; missing/failed entropy
  returns failure and clears the requested buffer. Raw symbols are namespaced and
  hidden; only the three facade functions have default visibility.
- patches/falcon512.patch checks both entropy calls, returns an internal -2 sentinel
  to stop outer retries on entropy failure, releases SHAKE on encoding failure,
  and wipes decoded private keys, seed and scratch on every legacy signer exit.
- patches/pqclean.patch checks its three raw entropy calls and releases SHAKE on
  encoding failure, so unused raw random APIs cannot silently use failed entropy.
- patches/fips202-c.patch and patches/fips202-h.patch change only the private
  SHAKE256 incremental context ABI/storage from a heap pointer to an inline array
  of PQC_SHAKEINCCTX_BYTES / sizeof(uint64_t) words. Init and clone retain their
  original Keccak initialization and memcpy; release wipes the inline array.
  Falcon's inner_shake256_* mappings use this context, so the facade crypto path
  does not allocate heap storage or exit on SHAKE allocation failure. Other unused
  SHAKE/SHA3 variants retain their upstream allocation behavior. This private ABI
  must not be mixed with the upstream pointer-owning context layout.
- The facade validates pointers/exact key and seed lengths/capacity, normalizes
  NULL empty messages, stages output, resets signature length on failure, and wipes
  staging and RNG frames. Inputs/outputs must be disjoint as documented in header.

Success calculations and entropy request order are unchanged by the patches;
byte equivalence is for the parent to verify independently. Builders run no tests.

Standalone build:
```sh
cmake -S . -B .build-native -DCMAKE_BUILD_TYPE=Release
cmake --build .build-native --target qgp_tidecoin_falcon
emcmake cmake -S . -B .build-wasm -DCMAKE_BUILD_TYPE=Release
cmake --build .build-wasm --target qgp_tidecoin_falcon
```
C11 is required. Emscripten uses the same sources and TLS adapter. Integration
must preserve private forced-include aliases and target visibility. No transaction,
address, wallet, Cellframe or chain behavior is included.
