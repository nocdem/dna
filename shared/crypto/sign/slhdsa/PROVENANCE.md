# Pinned source and adaptation record

SPHINCS+ source: sphincs/sphincsplus commit
129b72c80e122a22a61f71b5d2b042770890ccee, pinned by
nervosnetwork/quantum-resistant-lock-script commit
082c0a19ce4e0b2c0b00f7b46f423f59a30afc71.

Every file under upstream/ is copied unchanged: upstream/X corresponds to ref/X,
except upstream/LICENSE corresponds to repository LICENSE. Only the twelve
SHA2/SHAKE 128/192/256 f/s parameter headers are shipped. Only simple thash
implementations are built, matching the pinned CKB build.

Exact upstream source patch: empty. namespace.h is a compiler forced include:
it loads the unchanged parameter header, then replaces SPX_NAMESPACE(s) with
qgp_spx_<hash>_<level>_s via token concatenation. It additionally aliases the
unprefixed crypto_sign, randombytes, SHA2, and FIPS202 exported names. Each
variant uses separate object files; upstream math and hashing stay unchanged.
CMake supplies PARAMS and QGP_VARIANT and explicitly chooses simple thash.
No existing DSA hash implementation is reused.

variant.c replaces linking randombytes.c with a private thread-local scoped
provider. Detached signing requires exactly one request of N bytes; missing,
wrong-sized, repeated, or nested consumption fails and signature output is not
published. No RNG fallback is present. qgp_slhdsa.c stages signature/key outputs,
clears adapter allocations, validates lengths, and implements pure context
framing from the parent-provided pinned CKB message.rs:48-74 evidence.
The unchanged upstream implementation retains its own original stack cleanup
behavior; adapter cleanup does not claim to erase upstream stack frames.

The public API requires nonoverlapping buffers. Internal messages are already
framed. External sign/verify use 00 || context length byte || context || message;
context length is at most255. Explicit optrand must be N bytes. Deterministic
callers supply PK.seed; randomized callers supply CSPRNG output.

Standalone native build:
cmake -S shared/crypto/sign/slhdsa -B <build-dir>
cmake --build <build-dir> --target qgp_slhdsa
Emscripten uses the same targets via emcmake cmake. No downloads occur.
Compatibility tests and source review belong to the parent, not this builder.

SHA256SUMS lists shipped upstream source hashes with repository-relative paths.
