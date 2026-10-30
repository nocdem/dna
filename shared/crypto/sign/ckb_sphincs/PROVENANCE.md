# Pinned CKB adapter provenance

Wire IDs48..59 and personalized message hash come from the parent-verified
nervosnetwork/quantum-resistant-lock-script
082c0a19ce4e0b2c0b00f7b46f423f59a30afc71:
crates/ckb-fips205-utils/src/lib.rs:33-58.
The order is SHA2 128f,s,192f,s,256f,s, then SHAKE in the same order.
Only these exact IDs are accepted; wire flag packing is out of scope.

The caller supplies serialized transaction preimage bytes. Message hashing is
Blake2b output32 with all16 personal bytes "ckb-sphincs+-msg", without a NUL.
It is performed only by message_hash. sign_digest and verify_digest accept
digest32 and call pure SLH-DSA with empty context, producing internal message
00 00 || digest32, matching parent evidence root-lock.c:94-106,280-310,411-423.
No preimage serialization or additional digest hash is performed here.

upstream/blake2b.h and LICENSE are unchanged copies of the corresponding files
from pinned nervosnetwork/ckb-c-stdlib
7245b6268ef623f204501dc2beb6b3ae7d7b3cf4. Exact source patch: empty.
The adapter defines preprocessor aliases for its externally linked Blake2b
functions and DEFAULT_PERSONAL to qgp_ckb_private_* before including the standalone implementation.
It initializes blake2b_param directly, rather than calling the CKB default
personalization helper. SHA256SUMS contains shipped source hashes.

Build standalone with:
cmake -S shared/crypto/sign/ckb_sphincs -B <build-dir>
cmake --build <build-dir> --target qgp_ckb_sphincs
The target adds slhdsa only if qgp_slhdsa does not already exist.
Emscripten uses the same configuration through emcmake cmake.
