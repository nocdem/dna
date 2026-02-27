# Fuzz Testing for DNA Messenger

This document describes the libFuzzer-based fuzz testing infrastructure for finding memory safety bugs in DNA Messenger's parsing and deserialization code.

## Overview

Fuzz testing (fuzzing) automatically generates random/malformed inputs to find crashes, memory leaks, and security vulnerabilities. DNA Messenger uses [libFuzzer](https://llvm.org/docs/LibFuzzer.html), LLVM's coverage-guided fuzzer, combined with AddressSanitizer (ASAN) for memory error detection.

## Prerequisites

- **Clang compiler** (libFuzzer is LLVM-specific, GCC not supported)
- Main project must be built first (`../build/libdna_lib.a`)
- Standard build dependencies (cmake, make)

## Building Fuzz Targets

```bash
# Ensure main project is built first
cd /path/to/dna-messenger/build
cmake .. && make -j$(nproc)

# Build fuzz targets
cd /path/to/dna-messenger/tests
mkdir build-fuzz && cd build-fuzz
CC=clang CXX=clang++ cmake -DENABLE_FUZZING=ON -DCMAKE_BUILD_TYPE=Debug ..
make -j$(nproc)
```

## Available Fuzz Targets

| Target | Function | Description |
|--------|----------|-------------|
| `fuzz_offline_queue` | `dht_deserialize_messages()` | DHT offline message queue binary format |
| `fuzz_contact_request` | `dht_deserialize_contact_request()` | DHT contact request binary format |
| `fuzz_message_decrypt` | `dna_decrypt_message_raw()` | v0.08 encrypted message parsing |
| `fuzz_profile_json` | JSON parsing functions | Profile JSON field extraction |
| `fuzz_base58` | `base58_decode()` | Base58 string decoding |

**Note:** A `fuzz_gsk_packet` target was previously documented but does not exist. The GEK (formerly GSK) packet extraction is not currently fuzz-tested.

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
# Generate seed corpus
./fuzz/generate_corpus.sh

# Corpus structure
tests/fuzz/corpus/
    offline_queue/      # DHT message format seeds
    contact_request/    # Contact request seeds
    message_decrypt/    # Encrypted message seeds
    profile_json/       # JSON profile seeds
    base58/             # Base58 string seeds
```

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
2. Add to `tests/CMakeLists.txt`:
   ```cmake
   add_fuzz_target(fuzz_<target> fuzz/fuzz_<target>.c)
   ```
3. Create seed corpus in `fuzz/corpus/<target>/`
4. Update this documentation

## Related Files

- `tests/fuzz/` - Fuzz harness source files
- `tests/CMakeLists.txt` - Build configuration (ENABLE_FUZZING option)
- `tests/fuzz/corpus/` - Seed corpus directories
- `tests/fuzz/generate_corpus.sh` - Corpus generation script
