# Pinned PQ primitive conformance tests

This standalone test target links all new primitive adapters together. It does
not build a wallet, select chain activation rules, or construct transactions.
The parent author maintains these tests separately from the production builders.

Expected answers come from committed upstream KATs, NIST ACVP fixtures, or
programs compiled against pristine pinned upstream checkouts. None are generated
by the implementation under test. `prepare_vectors.py` is an explicit maintenance
command; normal builds use the committed compressed fixtures without networking.
All keys, seeds and randomness here are public test data.

Corpus:

* Algorand: 512 committed det1024 signature KATs, including 32 committed CT
  signatures; the remaining CT encodings and seeded keys come from the pinned
  reference. Exact bytes, headers, truncated and modified encodings are checked.
* Tidecoin: 16 deterministic reference signing cases, 16 historical verification
  cases and a synthetic norm boundary accepted by legacy verification and rejected
  by standard verification. The boundary is explicitly not a generated keypair.
  RNG failure must return an error without publishing output or retrying entropy.
* SLH-DSA: all 504 positive/negative CKB-hosted NIST sigVer cases across 12 sets;
  one positive internal case per set also checks seeded keys and exact signatures.
* CKB: 12 reference signatures over `00 00 || digest`, with independently computed
  Python BLAKE2b digests and exact parameter-ID mapping checks.
* ML-DSA: NIST keyGen, sigGen and sigVer for 44 and 65. External-mu cases are
  excluded because the public adapter does not expose that interface. Pure
  context framing is tested through both the public and internal APIs. Prehash
  fixtures exercise the internal primitive with externally prepared messages;
  they do not claim a public HashML-DSA or HashSLH-DSA implementation.
* Existing ML-DSA-87: a NIST subset is executed in the same binary as the new
  modes, checking that the existing namespace and shared SHAKE still work.
* Chain libraries: separate pristine Soqucoin/QTC ML-DSA-44 reference programs;
  QTC FIPS-205 SHAKE-128s and four incompatible legacy FORS-order controls;
  QTC's committed NIST case 530; CIRCL 1.6.3 and 1.6.5 ML-DSA-65, including
  Splendor's committed hash anchors; CIRCL 1.6.5 SHA2-128s; Noble 0.2.1 ML-DSA-65
  as used by Asentum SDK 0.2.0. CIRCL cases include 255-byte contexts. These
  fixtures come from chain primitives/dependencies, not a full running node.
* Red-team differential corpus: 96 deterministic mutations per reference input,
  covering Algorand compressed and CT, Tidecoin legacy, all 12 SLH parameter sets,
  and ML-DSA-44/65 (1,632 reference decisions). Signatures, keys and messages are
  truncated, extended, bit-flipped and filled with boundary values. Acceptance
  is recorded by pristine upstream executables; the port must match every answer.
* CKB hash boundaries: independently computed hashlib answers for 14 input sizes,
  including empty input, BLAKE2 block boundaries and 1 MiB.
* Argument boundaries: NULL/length mismatches, size overflow in pure framing,
  contexts over 255 bytes, unknown selectors, output capacity and unchanged
  output on rejected calls. This does not validate arbitrary inaccessible C
  pointers or unsupported overlapping buffers.
* Tidecoin entropy: nested callbacks with successful and failed inner operations;
  native builds additionally use two pthreads with distinct entropy tapes.
  WASM/Node exercises reentrancy, not WebWorker/pthread concurrency.
* Linux allocation injection: `--wrap=malloc` denies allocations during valid
  Tidecoin keygen/sign/verify. Exact reference bytes must still match and no heap
  allocation may be attempted on that facade path. This caught upstream's
  process-terminating `exit(111)` behavior before the private context adaptation.
  A second Linux injection test fails each SLH/CKB allocation site in turn and
  checks error propagation, unchanged output and subsequent verification recovery.

`CHECK` remains active under `NDEBUG`. Missing, empty, truncated and trailing
fixture data fail the run. Rejections must match the upstream expected result;
negative cases do not count as skips. Exact signature comparisons require the
same explicit randomness as the reference, not merely successful round trips.
`fixtures/manifest.json` pins compressed and uncompressed SHA-256, byte lengths,
record counts and per-parameter counts. The build verifies these before unpacking.
`check_provenance.py` checks copied and reused source hashes and completeness.
For a WASM build that one provenance test runs on the host; the cryptographic
fixture tests themselves run in WASM/Node.

```sh
cmake -S shared/crypto/tests/pq_chains -B /tmp/pq-native -DCMAKE_BUILD_TYPE=Release
cmake --build /tmp/pq-native -j2
ctest --test-dir /tmp/pq-native --output-on-failure
emcmake cmake -S shared/crypto/tests/pq_chains -B /tmp/pq-wasm -DCMAKE_BUILD_TYPE=Release
cmake --build /tmp/pq-wasm -j2
ctest --test-dir /tmp/pq-wasm --output-on-failure
```

The WASM tests execute the same corpus in Node; compiling an archive alone is
not counted as WASM validation. `-DPQ_SANITIZE=ON` enables native ASan/UBSan.
These are functional and memory-safety checks, not a formal cryptographic proof,
side-channel certification, or evidence of live-chain activation.

The 2026-10-30 parent-run validation used GCC 12.2.0, CMake 3.25.1,
Emscripten 4.0.16 and Node 22.23.4 on Linux x86-64. Native Release passed
23/23 groups, then the newly added SLH/CKB allocation-failure target passed
1/1. Native RelWithDebInfo with `PQ_SANITIZE=ON` passed the same 23/23 plus
1/1, with `ASAN_OPTIONS=detect_leaks=1` and
`UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=1`. WASM Release executed
22/22 groups successfully in Node; the two Linux linker-injection tests do
not run in WASM. The final corpus contains 1,462 binary records, including
17 differential records encoding 1,632 reference acceptance decisions.
No failed or skipped group is counted as passing. Windows, physical ARM,
CKB-VM execution and full-chain integration were not exercised.

Reference preparation is deliberately separate from normal test execution.
`prepare_vectors.py` requires exact clean checkouts named by its `PINS` map under
`--upstream-root`; ML-DSA ACVP inputs go under `acvp/`. The script verifies their
hardcoded SHA-256 values. ML-DSA inputs are NIST ACVP-Server commit
`975de31eb83d87039ec88934fdc47d8c312b892d`, paths
`gen-val/json-files/ML-DSA-{keyGen,sigGen,sigVer}-FIPS204/internalProjection.json`.
The SLH-DSA file is byte-identical (SHA-256 checked) to NIST commit
`85f8742965b2691862079172982683757d8d91db`, path
`gen-val/json-files/SLH-DSA-sigVer-FIPS205/internalProjection.json`, also committed
by the pinned CKB repository. No external-mu cases are silently counted as tested.

`prepare_chain_vectors.py` documents and checks its chain pins. Its CIRCL oracles
use Go 1.26.10 with exact module versions, and its Noble oracle requires the
exact npm versions/integrity values in `references/`. These maintenance commands
leave oracle binaries and expanded files in `UPSTREAM_ROOT/vector-build`; normal
CMake leaves expanded fixtures and test artifacts only in the selected build
directory. Neither workflow modifies the upstream checkouts. Updating a fixture
requires explicit review of its source and the committed integrity manifest.
`refresh_fixture_manifest.py` adds reviewed new fixtures and refuses any change
to existing fixture bytes. It is never invoked by the build or tests.
