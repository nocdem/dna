# PQ primitive ports and chain contracts

These are standalone cryptographic libraries under `shared/crypto/sign`.
They do not register chains, construct transactions, implement wallet key
derivation, or alter the wallet UI. Standard packed formats share algorithm
directories; chain-specific formats have separate adapters. Existing `dsa`
(ML-DSA-87) and `cellframe_dilithium` source files are unchanged.

| Directory / CMake target | Contract | Public / secret / signature bytes |
| --- | --- | --- |
| `algorand_falcon` / `qgp_algorand_falcon` | Algorand deterministic Falcon-1024, det1024 v0 | 1793 / 2305 / compressed ≤1423, CT 1538 |
| `tidecoin_falcon` / `qgp_tidecoin_falcon` | Tidecoin legacy Falcon-512 | 897 / 1281 / signer ≤688; verifier retains upstream legacy acceptance |
| `mldsa` / `qgp_mldsa` | FIPS-204 ML-DSA-44 and ML-DSA-65 | 1312 / 2560 / 2420; 1952 / 4032 / 3309 |
| `slhdsa` / `qgp_slhdsa` | FIPS-205 simple SHA2/SHAKE, 128/192/256, f/s | Query `qgp_slhdsa_get_params`; 12 sets |
| `ckb_sphincs` / `qgp_ckb_sphincs` | CKB IDs and personalized message hash over the shared SLH core | 32-byte message digest; key/signature sizes follow the selected set |

`mldsa` compiles the existing pinned DSA core under two private mode namespaces.
It does not copy another lattice implementation or modify mode 5. Its provenance
record includes the existing local differences from pq-crystals. `slhdsa` uses
CKB's pinned SPHINCS+ source, whose FORS bit order already matches finalized
FIPS-205; its published positive and negative NIST fixtures test that claim.

All facade signing/key-generation APIs take explicit seed/randomness inputs.
Tidecoin takes an explicit entropy callback and fails closed on callback errors.
Callers must provide cryptographically suitable entropy for real keys and
randomized signing. Deterministic ML-DSA uses 32 zero randomness bytes;
deterministic SLH-DSA uses the public seed, as in FIPS-205 and CIRCL. These choices
do not specify a mnemonic, HD path, chain KDF, or transaction signing policy.
Seed sizes are 32 for ML-DSA, 48 for Tidecoin, and 3N for SLH-DSA. Algorand's
upstream key generator accepts an explicit byte string as its SHAKE seed.

The public standard APIs implement pure signing with contexts of at most 255
bytes. `_internal` APIs expect an already prepared message. A caller must not
silently substitute internal signing for external pure signing: external input
is `00 || context_length || context || message`. There is no public HashML-DSA,
HashSLH-DSA, external-mu, ASN.1, PEM, or key-import validation API in this change.
Use exact-sized valid packed keys, disjoint buffers, and the return value;
length checks alone do not establish that an arbitrary secret key is valid.

## Chain evidence and limits

The following sources were checked at explicit revisions. These contracts are
source compatibility, not claims about the height, binary, or activation state
of a live network. Chain envelopes, transaction preimages and activation routing
remain work for a later integration.

**Algorand.** [go-algorand's pinned dependency](https://github.com/algorand/go-algorand/blob/853f03d6e85a1af1b0d93113df2a94371fb56213/go.mod)
uses falcon v0.2.0, commit
[`19f185792c39326bebc173b2a100c2c247423be3`](https://github.com/algorand/falcon/tree/19f185792c39326bebc173b2a100c2c247423be3).
`deterministic.h` and `deterministic1024.c` define compressed header `0xBA`,
CT header `0xDA`, and salt version 0. This is not the ordinary nonce-bearing
Falcon or FN-DSA format. The upstream integer floating-point emulation config is
preserved; native floating-point/AVX2 substitutions are not enabled. The
build also sets `FALCON_UNALIGNED=0` to select the upstream portable byte-read
path on every target; native UBSan found the auto-detected x86 pointer cast
misaligned. This is an existing upstream configuration choice, not a source
patch or a sanitizer suppression. The
go-algorand `crypto/falconWrapper.go` hashable-object path adds its own message
domain handling before calling Falcon; this library signs the supplied bytes.

**Tidecoin.** Commit
[`7d653be5d24e73b49d101578afb33d8d7a889c1d`](https://github.com/tidecoin/tidecoin/tree/7d653be5d24e73b49d101578afb33d8d7a889c1d),
`src/pq/falcon512.c` and `src/pq/falcon-512/pqclean.c`, supplies the legacy signer,
legacy verifier and deterministic seeded key generator. The legacy verifier
uses constant-time hash-to-point and the historical norm fallback; a dedicated
test distinguishes that acceptance from the standard verifier. Signing retains
the `0x39` header and 40-byte nonce. The 688-byte bound is a signer capacity,
not a new verifier restriction. Historical verification fixtures separately use
[`tidecoin-old/tidecoin@cfcb4d8a21f5a944c29d5c215c38ef7b66323f7b`](https://github.com/tidecoin-old/tidecoin/tree/cfcb4d8a21f5a944c29d5c215c38ef7b66323f7b).
The historical key generator is not claimed equivalent to the current seeded
one. `src/pq/pq_api.h` also has strict/legacy dispatch; this adapter intentionally
implements the requested legacy primitive, not every Tidecoin witness rule.

**CKB.** The [lock-script revision](https://github.com/nervosnetwork/quantum-resistant-lock-script/tree/082c0a19ce4e0b2c0b00f7b46f423f59a30afc71)
is `082c0a19ce4e0b2c0b00f7b46f423f59a30afc71`; its SPHINCS+ submodule is
`129b72c80e122a22a61f71b5d2b042770890ccee`, and ckb-c-stdlib is
`7245b6268ef623f204501dc2beb6b3ae7d7b3cf4`. Source contracts are
`crates/ckb-fips205-utils/src/lib.rs` and
`contracts/c-sphincs-all-in-one-lock/ckb-sphincsplus-root-lock.c`.

| CKB ID | Set | CKB ID | Set |
| --- | --- | --- | --- |
| 48 | SHA2-128f | 54 | SHAKE-128f |
| 49 | SHA2-128s | 55 | SHAKE-128s |
| 50 | SHA2-192f | 56 | SHAKE-192f |
| 51 | SHA2-192s | 57 | SHAKE-192s |
| 52 | SHA2-256f | 58 | SHAKE-256f |
| 53 | SHA2-256s | 59 | SHAKE-256s |

Message hashing is BLAKE2b-256, fanout 1, depth 1, with exactly the **16 bytes**
`ckb-sphincs+-msg` as personalization, without a NUL byte. The helper accepts the
already serialized preimage; it does not build `CKB_TX_MESSAGE_ALL`. The lock
verifies raw SPHINCS+ over `00 00 || digest32`, which the adapter obtains by
external pure signing of the digest with an empty context. Public keys are
`PK.seed || PK.root`, following the executable source and NIST fixtures, despite
the reverse-order comment in the upstream `api.h`.

**Soqucoin.** At
[`28222c3810701c05eb27e8feb09f032bb75fc097`](https://github.com/soqucoin/soqucoin/tree/28222c3810701c05eb27e8feb09f032bb75fc097),
`src/pubkey.cpp` uses `pqcrystals_dilithium2_ref_verify` with a 1312-byte key,
2420-byte signature, empty context, and 32-byte transaction hash. The active
`src/crypto/dilithium` implementation produces FIPS-204 ML-DSA-44 bytes in the
independent reference tests. The shared `mldsa` directory is therefore used.

**QTC.** At
[`5adbc7d5c2ac252804fd3c61fce3b9bbc3ad9c24`](https://github.com/qtcchain/qtc/tree/5adbc7d5c2ac252804fd3c61fce3b9bbc3ad9c24),
`src/libbitcoinpqc/CMakeLists.txt` selects ML-DSA-44 and simple SHAKE-128s.
`src/pqkey.cpp` and `src/libbitcoinpqc/sphincsplus/ref/fors.c` distinguish legacy
SPHINCS+ from finalized FIPS-205: both framing and FORS bit order change. The
shared SLH-DSA API matches **FIPS-205 mode only**; it must not verify old-mode
signatures by fallback. Tests preserve four old-order rejection controls and
QTC's committed NIST case 530. At this pin, `CMainParams` explicitly sets
`nShieldedC002ActivationHeight=0`; other network configurations and historical
revisions must be examined before integration. No QTC legacy-format adapter or
activation-height selector is included. ML-DSA uses the shared standard API.

**Verona/XION.** The [official organization](https://github.com/burnt-labs)
identifies `xion` as the Verona chain daemon. The inspected XION tag v32.0.0 is
[`9b0acaffc126cf10e270bb12a7123a4168882870`](https://github.com/burnt-labs/xion/tree/9b0acaffc126cf10e270bb12a7123a4168882870).
Its dependencies lead to cosmos-sdk v0.55.0
(`64fd208a11fb54f7ffdca1a1290c2cfbbc254e49`, `crypto/keys/mldsa65/key.go`), then
CometBFT v0.40.0
[`0880b4d378f347ab16e54ec677ff50d803f37d62`](https://github.com/cometbft/cometbft/blob/0880b4d378f347ab16e54ec677ff50d803f37d62/crypto/mldsa65/key.go).
That implementation uses CIRCL v1.6.3 ML-DSA-65, packed keys, deterministic
signing and an empty context. The protobuf/account envelope is separate from
these standard primitive bytes. This evidence establishes an available key
type, not that every XION/Verona account already uses it.

**Splendor.** At
[`38ac3ded57d6fa931dba3036d490c5d66b0fbcbc`](https://github.com/Splendor-Protocol/splendor-quantum-blockchain/tree/38ac3ded57d6fa931dba3036d490c5d66b0fbcbc),
`core/crypto/mldsa.go` and `slhdsa.go` use CIRCL v1.6.5, standard ML-DSA-65 and
SLH-DSA-SHA2-128s packed formats. Its wrappers require nonempty contexts such as
`SPLENDOR-QC-TX-v1` and `SPLENDOR-QC-BLOCK-v1`. The primitive APIs accept these
contexts; callers must retain the chain's exact context policy. Reference tests
check the committed `mldsa_kat_test.go` SHA3-256 anchors and full signature bytes,
plus CIRCL SLH-DSA signatures. The chain's self-pinned hashes supplement NIST
conformance; they are not independent proof of the standard.

**Asentum testnet.** [Official documentation](https://www.asentum.com/docs)
specifies ML-DSA-65. The inspected published package is `@asentum/sdk@0.2.0`,
whose `dist/index.js` calls `ml_dsa65.keygen(seed32)` and
`ml_dsa65.sign(secretKey,message)` from `@noble/post-quantum ~0.2.1`.
The test oracle pins Noble **0.2.1** (and its exact `@noble/hashes` 1.6.0
dependency); it does not silently follow that semver range. These are standard
ML-DSA-65 bytes with empty context and the library's deterministic default.
The SDK tarball's npm integrity is
`sha512-Axwe/di3BRgxp8oj+EqelcZ3xqQWzV00yHi4F/cPjWmL7W4970qFO+o7ODf+S/u5Fk4ZhwcuBvBHWs4ynKgMvA==`.
Its public package was available; a public core-node implementation was not
established in this investigation. Accordingly, compatibility evidence is SDK
and primitive evidence, not independently reproduced node consensus behavior.

**Cellframe, research only.** The inspected dap-sdk pin is
[`b9b57340f5936b1639499e6b66379efd918271cf`](https://github.com/demlabs-cellframe/dap-sdk/tree/b9b57340f5936b1639499e6b66379efd918271cf).
`crypto/src/dap_enc_dilithium.c` selects `DILITHIUM_MAX_SPEED` by default; the
existing DNA `cellframe_dilithium` API uses that MODE_1, K=4/L=3, 1184-byte public
key, 2800-byte secret key and 2044-byte detached signature. SDK MODE_3 is also
an older parameter/encoding family, not current ML-DSA-65. Cellframe additionally
serializes kind/length fields and attached-message signatures. The existing
packing/parameter/math sources were compared, and platform/cleanup differences
were identified. No new full SDK interoperability certification is claimed, and
none of its source, serialization, or integration code is modified here.

## Provenance and verification

Each implementation directory carries its source pin, copied-file hashes and
adaptation record. The modified vendored files are the documented Tidecoin
entropy-error/cleanup patches and private SHAKE256 incremental context storage
adaptation. That context retains its exact 26-word sponge state inline instead
of allocating it and terminating the process on allocation failure. Permutation,
absorb, finalize and squeeze calculations are unchanged; reference outputs
are compared byte for byte. Wrappers clear their staging buffers. Unchanged
upstream stack-clearing behavior is retained and is not represented as complete
secret erasure or a side-channel certification.

See [the test instructions](../tests/pq_chains/README.md), fixture manifest and
reference-generation programs for reproducible native/WASM checks. The test
corpus and programs are public test data, not production keys. Builds never
fetch the latest upstream or regenerate expected answers from the port.
Consumers should link the CMake targets; copying source lists without their
private namespace/configuration flags does not preserve the tested build.
