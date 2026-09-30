# Fuzz Testing for DNA Connect

This document describes the libFuzzer-based fuzz testing infrastructure for finding memory safety bugs in DNA Connect's parsing and deserialization code.

## Overview

Fuzz testing (fuzzing) automatically generates random/malformed inputs to find crashes, memory leaks, and security vulnerabilities. DNA Connect uses [libFuzzer](https://llvm.org/docs/LibFuzzer.html), LLVM's coverage-guided fuzzer, combined with AddressSanitizer (ASAN) for memory error detection.

## Prerequisites

- **Clang compiler** (libFuzzer is LLVM-specific, GCC not supported)
- Main project must be built first (`messenger/build/libdna.so`)
- wasm32 build only: Emscripten 6.0.10 (`~/emsdk`), the OpenSSL wasm archive, node
- Standard build dependencies (cmake, make)

## Building Fuzz Targets

There are two builds. Use the first one.

### 1. `tests/fuzz/CMakeLists.txt` — instrumented parsers (recommended)

```bash
# Main library first (the fuzz build links the rest of libdna.so)
cd /opt/dna/messenger/build
cmake .. && make -j$(nproc)

# Fuzz targets
cd /opt/dna/messenger/tests/fuzz
mkdir -p build && cd build
CC=clang cmake ..
make -j$(nproc)
```

Every target here compiles the **parser's own source file** into the fuzz
executable with `-fsanitize=fuzzer,address`, so libFuzzer's coverage feedback
comes from inside the parser. Everything else (shared crypto, `gek.c`, json-c,
OpenSSL) comes from `libdna.so` and the system, uninstrumented. The
executable's own definitions take precedence over `libdna.so`'s — that is how
`fuzz_dht_stub.c` replaces the DHT I/O for parsers that live inside DHT I/O
files. This build contains all targets below, including the five original
ones.

### 2. `tests/CMakeLists.txt -DENABLE_FUZZING=ON` — original five, uninstrumented parsers

```bash
cd /opt/dna/messenger/tests
mkdir build-fuzz && cd build-fuzz
CC=clang CXX=clang++ cmake -DENABLE_FUZZING=ON -DCMAKE_BUILD_TYPE=Debug ..
make -j$(nproc)
```

This older block links the five original harnesses against the gcc-built
`libdna.so`. The parser code inside `libdna.so` carries **no coverage
instrumentation**, so libFuzzer only sees the harness itself and mutates
blind. Crashes it hits are still real, but ASan only sees what its
interceptors (`memcpy`, `malloc`, ...) see inside `libdna.so` — a plain
out-of-bounds load in uninstrumented code goes unreported. Coverage-guided
search with full ASan on the parser is build 1.

## Available Fuzz Targets

### Web Connect targets (NC-5)

Added by web Connect package NC-5 (`docs/plans/2026-09-24-web-connect-design.md`
rev 5, §5 A2 "fuzz coverage still insufficient and wasm32 has a 32-bit
`size_t`", §8 NC-5): the parsers the web Connect thin core will run on
untrusted network input. The tier-2 reply decode and CBOR decoder are
nodus-side — see `nodus/tests/fuzz/README.md`.

| Target | Entry point (file:line) | Compiled in (instrumented) |
|--------|-------------------------|----------------------------|
| `fuzz_anchor_json` | `dna_identity_from_json` (`dht/client/dna_profile.c:254`), then `dna_identity_to_json_unsigned` / `_to_json` / `dna_identity_free` | `dht/client/dna_profile.c` |
| `fuzz_seal_decode` | `dna_decrypt_message_raw_alg` (`dna_api.c:468`), `dna_verify_seal_authorship` (`dna_api.c:725`) | `dna_api.c` |
| `fuzz_contactlist` | `dht_contactlist_fetch` (`dht/client/dht_contactlist.c:447`) → blob parse (`:481-640`) → Seal decode → `deserialize_from_json` (static, `:147`) | `dht/client/dht_contactlist.c`, `dna_api.c` |
| `fuzz_salt_packet` | `salt_agreement_fetch_v2` (`dht/shared/dht_salt_agreement.c:547`) → `packet_verify_signature` / `packet_decrypt_salt` (static, `:67-184`) → dedup / tiebreak | `dht/shared/dht_salt_agreement.c` |

What each covers, its input format, and how it can lie:

- **`fuzz_anchor_json`** — the Anchor (profile / identity) record. Anyone can
  publish one and every client that looks it up parses it. Input: JSON text
  (a NUL is appended). A parsed record is re-serialised exactly as the
  signature check does (`keyserver_lookup.c` verifies over
  `dna_identity_to_json_unsigned`), so the encoder also runs on every field
  combination the parser accepts, including the `mlkem_pubkey` intake
  `ek_check`. *Cannot find:* bugs inside json-c (not instrumented); anything
  about signature verification (not called). This is **not** `fuzz_profile_json`,
  which tests a copy of the legacy `dht_profile.c` string scanner.
- **`fuzz_seal_decode`** — the 1:1 message envelope, including the code
  **behind** a successful key decapsulation. At start-up the harness seals a
  real message to its own ML-KEM-1024 key (`dna_encrypt_message_raw_alg`, keys
  from `fuzz_keys.c`). Input byte 0, low bit: `0` = bytes 1.. are the whole
  Seal (decrypted with the local round-3 and ML-KEM keys); `1` = bytes 1..10
  overwrite header bytes 10..19 of the real Seal (`recipient_count`,
  `message_type`, `encrypted_size`, `signature_size`, layout `dna_api.c:62-74`)
  and bytes 11.. replace everything after the first recipient entry (with none,
  the real tail is kept). Any sender can reach the post-decapsulation code
  (the recipient's public key is public); `fuzz_message_decrypt` cannot, its
  fake key never decapsulates. *Cannot find:* AES-GCM or KEM internals
  (uninstrumented, libdna.so); the random DEK / nonce change every process
  start (structure and lengths do not), so a finding that depends on the exact
  ciphertext bytes would not replay — none of the parse checks does.
- **`fuzz_contactlist`** — the contact-list record. The parser is static
  inside a DHT I/O file (and NC-1 extracts it in parallel), so the target
  calls the exported fetch with `nodus_ops_get_str` replaced by
  `fuzz_dht_stub.c`. Input byte 0, low bit: `0` = raw, bytes 1.. are the DHT
  value (header, both length fields, Seal decode); `1` = sealed, bytes 1.. are
  the JSON plaintext, sealed by the harness exactly as `dht_contactlist_publish`
  does and wrapped in the header of a blob the real publisher produced at
  start-up — this reaches `deserialize_from_json`. *Cannot find:* in raw mode
  nothing behind the authorship check (a random blob cannot pass it); sealed
  mode models only the list owner (in reality nobody else can author the
  JSON), it exists for memory-safety coverage of the JSON parser. Sealed mode
  signs and encapsulates per input and runs much slower than raw mode.
- **`fuzz_salt_packet`** — the per-contact salt-agreement packet (v1 8013 B,
  v2 8015 B). Called through the exported fetch with `nodus_ops_get_all_str`
  replaced. Input byte 0: bit0 `0` = raw, bytes 1.. are the values for the
  key, each prefixed by a 2-byte big-endian length (harness framing only);
  bit0 `1` = signed, bytes 1.. are the data portion of one packet, sized for
  its declared version, signed by the **contact's** key and appended — the
  packet a malicious contact can legitimately publish; bit1 writes the local
  fingerprint into entry 1; bit2 returns the packet twice (dedup path).
  *Cannot find:* in raw mode nothing behind the signature check except via the
  real-signature seeds; `gek_decrypt_alg` (`messenger/gek.c`) is in libdna.so,
  uninstrumented.

Supporting files: `fuzz_keys.c/.h` (deterministic REAL keypairs —
ML-DSA-87 / Kyber round-3 / ML-KEM-1024 derand, fingerprint = SHA3-512 of the
signing key; `FUZZ_ID_SELF`, `FUZZ_ID_CONTACT`), `fuzz_dht_stub.c/.h` (test
doubles for `nodus_ops_get_str`, `_get_all_str`, `_put_str`,
`_put_str_exclusive`, `_value_id`; writes are captured).

### Original targets

| Target | Function | Description |
|--------|----------|-------------|
| `fuzz_offline_queue` | `dht_deserialize_messages()` (`dht/shared/dht_offline_queue.c:229`) | DHT offline message queue binary format (also a web Connect NC-5 parser) |
| `fuzz_contact_request` | `dht_deserialize_contact_request()` | DHT contact request binary format |
| `fuzz_message_decrypt` | `dna_decrypt_message_raw()` | v0.08 encrypted message parsing, fake key — header parsing only |
| `fuzz_profile_json` | copy of `dht_profile.c` `json_get_string` | Legacy profile JSON field extraction (tests a copy, not the source) |
| `fuzz_base58` | `base58_decode()` | Base58 string decoding |

**Note:** A `fuzz_gsk_packet` target was previously documented but does not exist. The GEK (formerly GSK) packet extraction is not currently fuzz-tested. `generate_corpus.sh` still writes into `corpus/gsk_packet/`, a directory that does not exist.

## wasm32 build (32-bit `size_t`)

The browser runs the web Connect core as wasm32, where `size_t` and pointers
are 32 bits: a length check such as `offset + len > buf_len` with a 32-bit
`len` read from the input can wrap there and not on x86-64.

```bash
bash messenger/tests/fuzz/build_wasm32.sh         # -> messenger/tests/fuzz/build-wasm32/
node messenger/tests/fuzz/build-wasm32/fuzz_seal_decode.js messenger/tests/fuzz/corpus/seal_decode/
node messenger/tests/fuzz/build-wasm32/fuzz_contactlist.js -mutate=20000 -seed=1 messenger/tests/fuzz/corpus/contactlist/
node messenger/tests/fuzz/build-wasm32/fuzz_seal_decode.js crash-<hash>   # native finding at 32 bits
```

Emscripten 6.0.10 (pinned; the OpenSSL wasm archive
`~/wasm-deps/openssl-3.0.15-wasm` from `web-wallet/scripts/build-openssl-wasm.sh`
is built with it), `-fsanitize=address`, node with `NODERAWFS`. Emscripten
has no libFuzzer, so each harness is linked with
`nodus/tests/fuzz/fuzz_driver.c`: it replays every file (directories sorted by
name) and, with `-mutate=N -seed=S`, runs N deterministic mutations per input
(bit flips, byte sets, 32-bit edge lengths such as `0xFFFFFFFF` in both byte
orders, truncation). **This is replay + seeded mutation, not coverage-guided
fuzzing**; its job is to run the native corpus and crash files with 32-bit
arithmetic.

| wasm32 target | Built | Note |
|---|---|---|
| `fuzz_seal_decode` | yes | both modes |
| `fuzz_message_decrypt` | yes | |
| `fuzz_offline_queue` | yes | |
| `fuzz_contact_request` | yes | |
| `fuzz_contactlist` | yes, **raw mode only** (`-DFUZZ_CONTACTLIST_RAW_ONLY`) | no wasm32 json-c here; the JSON parser is not exercised |
| `fuzz_anchor_json` | **no** | needs json-c for wasm32 (design §1.2: must be the frozen app's json-c version — not pinned yet) |
| `fuzz_salt_packet` | **no** | `gek.c` pulls the group database; possible once NC-1 extracts the KEM-wrap codec |

Link-only pieces (test code): `nodus/tests/fuzz/fuzz_wasm_platform.c`
(deterministic `qgp_platform_random`, `qgp_secure_memzero`,
`qgp_platform_home_dir`), `nodus/tests/fuzz/fuzz_wasm_log.c` (QGP log back
end), `tests/fuzz/fuzz_wasm_abort_stubs.c` (keyring, DHT I/O and json-c
symbols the parsers never call, each defined as `abort()` with its real
prototype — reaching one is a harness bug, never a silent fake result).

A native `-m32` build is not provided: this machine has no `libc6-dev-i386`,
i386 OpenSSL or i386 json-c. With them, `fuzz_driver.c` (or clang's i386
libFuzzer runtime) plus the source lists in `build_wasm32.sh` is the build.

## Running Fuzzers

### Basic Usage

```bash
# Run with corpus directory (recommended)
./fuzz_offline_queue ../fuzz/corpus/offline_queue/

# Run for 60 seconds
./fuzz_offline_queue ../fuzz/corpus/offline_queue/ -max_total_time=60

# Run N iterations
./fuzz_base58 ../fuzz/corpus/base58/ -runs=10000
```

### Parallel Fuzzing

```bash
# Run with 4 parallel workers
./fuzz_contact_request ../fuzz/corpus/contact_request/ -jobs=4 -workers=4
```

### Useful Options

| Option | Description |
|--------|-------------|
| `-max_total_time=N` | Stop after N seconds |
| `-runs=N` | Stop after N test cases |
| `-max_len=N` | Maximum input size in bytes |
| `-jobs=N` | Number of parallel fuzzing jobs |
| `-workers=N` | Number of worker processes |
| `-print_final_stats=1` | Print statistics at exit |
| `-print_pcs=1` | Print new coverage PCs |

### Finding and Reproducing Crashes

When a crash is found, libFuzzer saves the crashing input:

```bash
# Crash files are saved as crash-<hash> or oom-<hash>
ls crash-* oom-* leak-*

# Reproduce a crash
./fuzz_offline_queue crash-abc123def456
```

## Seed Corpus

Seed files help the fuzzer explore code faster by providing valid starting points.

```bash
# Hand-written seeds for the original targets
./fuzz/generate_corpus.sh

# Seeds for the NC-5 targets, produced by the REAL encoders (build 1 above)
cd /opt/dna/messenger/tests/fuzz/build
./fuzz_seed_gen ../corpus          # exit 0 = every seed written

# Corpus structure
tests/fuzz/corpus/
    offline_queue/      # DHT message format seeds (+ two_real_seals.bin from fuzz_seed_gen)
    contact_request/    # Contact request seeds
    message_decrypt/    # Encrypted message seeds
    profile_json/       # JSON profile seeds
    base58/             # Base58 string seeds
    anchor_json/        # fuzz_seed_gen: dna_identity_to_json output (legacy / ML-KEM + name)
    seal_decode/        # fuzz_seed_gen: real Seals (ML-KEM, round-3) + overlay header seed
    contactlist/        # fuzz_seed_gen: real published blob (mode 0) + its JSON (mode 1)
    salt_packet/        # fuzz_seed_gen: real v1 / v2 packets (mode 0) + data portions (mode 1)
```

`fuzz_seed_gen` writes nothing by hand: `dna_identity_to_json`,
`dna_encrypt_message_raw_alg`, `dht_serialize_messages`,
`dht_contactlist_publish` and `salt_agreement_publish` / `_publish_v2`
(captured through `fuzz_dht_stub.c`) produce every byte, with the
`fuzz_keys.c` identities the harnesses use — so the Seal, contact-list and
salt seeds decrypt and verify inside the targets. Signing is randomized
(`shared/crypto/sign/dsa/config.h:6`) and KEM / AES draw fresh randomness, so
a re-run writes different bytes of the same shape. The new corpus
directories are committed empty (`.gitkeep`); run the generator before the
first fuzzing session.

## Architecture

### Harness Structure

Each fuzz harness implements `LLVMFuzzerTestOneInput()`:

```c
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // 1. Skip invalid sizes
    if (size < MIN_SIZE) return 0;

    // 2. Call target function with fuzzed input
    target_function(data, size, ...);

    // 3. Free any allocated memory
    // 4. Return 0 (non-zero aborts fuzzing)
    return 0;
}
```

### Shared Utilities

`fuzz/fuzz_common.h` provides deterministic fake key generation for testing:

- `fuzz_generate_fake_kyber_privkey()` - Fake Kyber1024 private key
- `fuzz_generate_fake_dilithium_privkey()` - Fake Dilithium5 private key
- `fuzz_generate_fake_fingerprint()` - Fake binary fingerprint
- `fuzz_generate_fake_fingerprint_hex()` - Fake hex fingerprint

These are NOT cryptographically valid - they're deterministic byte sequences for coverage testing.

## What the Fuzzers Test

### Message Format Parsing

- Magic byte validation
- Version field handling
- Size field bounds checking
- Variable-length field parsing
- Buffer overflow detection

### Cryptographic Operations

- Invalid ciphertext handling
- Malformed key material
- Signature verification with corrupt data
- Key decapsulation edge cases

### Common Vulnerabilities Found

- Buffer overflows in fixed-size fields
- Integer overflows in size calculations
- Missing bounds checks on array indexing
- Heap corruption from invalid lengths
- Use-after-free in error paths

## Continuous Fuzzing

For extended fuzzing sessions, consider:

```bash
# Run overnight with crash reporting
./fuzz_offline_queue corpus/ -max_total_time=28800 \
    -print_final_stats=1 \
    -artifact_prefix=crashes/
```

## Troubleshooting

### Build Errors

**"libFuzzer requires Clang compiler"**
```bash
CC=clang CXX=clang++ cmake -DENABLE_FUZZING=ON ..
```

**"Main project not built"**
```bash
cd ../build && cmake .. && make -j$(nproc)
```

### Runtime Issues

**Low coverage**: Improve seed corpus with more valid inputs

**OOM crashes**: Use `-rss_limit_mb=2048` to set memory limit

**Slow fuzzing**: Use parallel workers with `-jobs=N -workers=N`

## Adding New Fuzz Targets

1. Create `fuzz/fuzz_<target>.c` with `LLVMFuzzerTestOneInput()`
2. Add to `tests/fuzz/CMakeLists.txt`, listing the parser's own source so it
   is instrumented:
   ```cmake
   add_fuzz_target(fuzz_<target> ${FUZZ_DIR}/fuzz_<target>.c ${DNA_ROOT}/<path/to/parser>.c)
   ```
   (The older `tests/CMakeLists.txt` `add_fuzz_target(... fuzz/fuzz_<target>.c)`
   still works but gives the fuzzer no coverage inside the parser.)
3. Create seed corpus in `fuzz/corpus/<target>/` — from the real encoder
   (extend `fuzz_seed_gen.c`), not hand-written bytes, where one exists
4. If the web Connect core runs the parser, add it to `build_wasm32.sh`
5. Update this documentation

## Related Files

- `tests/fuzz/` - Fuzz harness source files
- `tests/fuzz/CMakeLists.txt` - Instrumented-parser build (all targets)
- `tests/CMakeLists.txt` - Older build (ENABLE_FUZZING option, original five targets)
- `tests/fuzz/build_wasm32.sh` - wasm32 (32-bit `size_t`) build
- `tests/fuzz/fuzz_seed_gen.c` - Seed generator for the NC-5 targets
- `tests/fuzz/corpus/` - Seed corpus directories
- `tests/fuzz/generate_corpus.sh` - Hand-written seeds for the original targets
- `nodus/tests/fuzz/` - Tier-2 / CBOR / signed-value targets, the wasm32 driver (`README.md` there)
