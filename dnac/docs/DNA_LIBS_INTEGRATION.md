# DNA Modular Libraries Integration Guide

**Version:** 1.0.0
**Date:** 2026-01-26
**Status:** Ready for Implementation

This guide explains how to integrate the modular DNA libraries from `dna-messenger` into the `dnac` project for cleaner dependencies and smaller binary size.

---

## Table of Contents

1. [Overview](#1-overview)
2. [Benefits](#2-benefits)
3. [Library Structure](#3-library-structure)
4. [Prerequisites](#4-prerequisites)
5. [Setup Instructions](#5-setup-instructions)
6. [CMakeLists.txt Migration](#6-cmakeliststxt-migration)
7. [Building](#7-building)
8. [Verification](#8-verification)
9. [Troubleshooting](#9-troubleshooting)
10. [Appendix: Library API Reference](#10-appendix-library-api-reference)

---

## 1. Overview

The DNA Messenger project has been refactored into 6 independent static libraries that can be selectively linked. This allows `dnac` to use only the components it needs (crypto + DHT) instead of linking against the entire `libdna_lib` which includes messaging, blockchain wallets, and other unneeded features.

### Current Architecture (Before)

```
┌─────────────────────────────────────────┐
│              dnac                       │
│                                         │
│  Links: libdna_lib.a (~95K lines)      │
│         - Crypto ✓ (needed)             │
│         - DHT ✓ (needed)                │
│         - Transport (partially needed)  │
│         - Messenger ✗ (not needed)      │
│         - Blockchain ✗ (not needed)     │
│         - Database (partially needed)   │
└─────────────────────────────────────────┘
```

### New Architecture (After)

```
┌─────────────────────────────────────────┐
│              dnac                       │
│                                         │
│  Links: libdna-crypto.a (~22K lines)   │
│         libdna-dht.a (~27K lines)      │
│         ─────────────────────────       │
│         Total: ~49K lines (-48%)        │
└─────────────────────────────────────────┘
```

---

## 2. Benefits

| Metric | Before (libdna_lib) | After (Modular) | Improvement |
|--------|---------------------|-----------------|-------------|
| **Code linked** | ~95,000 lines | ~49,000 lines | **-48%** |
| **Binary size** | ~4.5 MB | ~2.3 MB | **-49%** |
| **Build time** | Full rebuild | Incremental | **Faster** |
| **Dependencies** | All DNA deps | Crypto + DHT only | **Cleaner** |
| **Attack surface** | Large | Minimal | **More secure** |

### Specific Benefits for dnac:

1. **No Messenger Code**: dnac doesn't need messaging features - they won't be linked
2. **No Blockchain Wallets**: ETH, SOL, TRON wallet code won't be included
3. **Clearer Dependencies**: Explicit about what crypto/DHT functions are used
4. **Independent Updates**: Can update dnac without full dna-messenger rebuilds
5. **Easier Auditing**: Smaller codebase to review for security

---

## 3. Library Structure

The modular libraries are located in `/opt/dna-messenger/libs/`:

```
/opt/dna-messenger/libs/
├── CMakeLists.txt              # Main orchestration
├── dna-crypto/                 # Foundation (22K lines)
│   └── CMakeLists.txt          # Kyber, Dilithium, AES, SHA3, BIP32/39
├── dna-dht/                    # DHT Layer (27K lines)
│   └── CMakeLists.txt          # Context, keyserver, offline queue
├── dna-transport/              # P2P Layer (925 lines)
│   └── CMakeLists.txt          # Discovery, offline messaging
├── dna-database/               # Caching (6.4K lines)
│   └── CMakeLists.txt          # Contacts, profiles, presence
├── dna-blockchain/             # Wallet (18.6K lines)
│   └── CMakeLists.txt          # Cellframe, ETH, SOL, TRON
└── dna-messenger-core/         # Messaging (8.5K lines)
    └── CMakeLists.txt          # Identity, messages, GEK, groups
```

### Dependency Graph

```
                        ┌─────────────────┐
                        │      dnac       │
                        └────────┬────────┘
                                 │
                    ┌────────────┴────────────┐
                    │                         │
                    ▼                         │
             ┌───────────┐                    │
             │  dna-dht  │                    │
             └─────┬─────┘                    │
                   │                          │
                   ▼                          │
             ┌───────────┐                    │
             │dna-crypto │◀───────────────────┘
             └───────────┘
              (foundation)
```

**For dnac, you only need:**
- `dna-crypto` - Kyber1024, Dilithium5, SHA3-512, platform utils
- `dna-dht` - DHT context, keyserver, value storage

---

## 4. Prerequisites

Before integration, ensure:

### 4.1 dna-messenger Build with Modular Libraries

```bash
cd /opt/dna-messenger/build
cmake -DBUILD_DNA_LIBS=ON ..
make -j$(nproc)
```

Verify libraries exist:
```bash
ls -la /opt/dna-messenger/build/libs/*/lib*.a
```

Expected output:
```
libs/dna-crypto/libdna-crypto.a
libs/dna-crypto/libdna_kem.a
libs/dna-crypto/libdna_dsa.a
libs/dna-crypto/libdna_cellframe_dilithium.a
libs/dna-dht/libdna-dht.a
libs/dna-transport/libdna-transport.a
libs/dna-database/libdna-database.a
libs/dna-blockchain/libdna-blockchain.a
libs/dna-messenger-core/libdna-messenger-core.a
```

### 4.2 OpenDHT-PQ

The DHT library requires OpenDHT-PQ (built with dna-messenger):
```bash
ls /opt/dna-messenger/build/vendor/opendht-pq/libopendht.a
```

---

## 5. Setup Instructions

### Option A: Symlink Approach (Recommended for Development)

Create a symlink from dnac to the dna-messenger libs directory:

```bash
cd /opt/dnac
ln -sf /opt/dna-messenger/libs libs
```

This allows dnac to reference the libraries as if they were local:
```cmake
add_subdirectory(libs/dna-crypto)
add_subdirectory(libs/dna-dht)
```

### Option B: Direct Reference (No Symlink)

Reference the libraries directly from dna-messenger:
```cmake
set(DNA_LIBS_DIR "/opt/dna-messenger/libs")
add_subdirectory(${DNA_LIBS_DIR}/dna-crypto ${CMAKE_BINARY_DIR}/dna-crypto)
add_subdirectory(${DNA_LIBS_DIR}/dna-dht ${CMAKE_BINARY_DIR}/dna-dht)
```

### Option C: Pre-built Libraries (Production)

Link against pre-built static libraries:
```cmake
set(DNA_BUILD_DIR "/opt/dna-messenger/build")
target_link_libraries(dnac
    ${DNA_BUILD_DIR}/libs/dna-dht/libdna-dht.a
    ${DNA_BUILD_DIR}/libs/dna-crypto/libdna-crypto.a
    ${DNA_BUILD_DIR}/libs/dna-crypto/libdna_dsa.a
    ${DNA_BUILD_DIR}/libs/dna-crypto/libdna_kem.a
    ${DNA_BUILD_DIR}/libs/dna-crypto/libdna_cellframe_dilithium.a
)
```

---

## 6. CMakeLists.txt Migration

### 6.1 Current CMakeLists.txt Structure

The current `CMakeLists.txt` links against the full `libdna_lib`:

```cmake
# Current approach - links everything
if(EXISTS "${DNA_BUILD_DIR}/libdna_lib.so")
    target_link_libraries(dnac ${DNA_BUILD_DIR}/libdna_lib.so)
else()
    target_link_libraries(dnac ${DNA_BUILD_DIR}/libdna_lib.a)
endif()
```

### 6.2 Migrated CMakeLists.txt

Replace with modular library linking. Here's the complete migration:

```cmake
# ============================================================================
# DNAC - CMakeLists.txt with Modular DNA Libraries
# ============================================================================

cmake_minimum_required(VERSION 3.16)
project(dnac VERSION 0.7.0 LANGUAGES C CXX)  # C++ needed for OpenDHT

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_CXX_STANDARD 17)  # OpenDHT requires C++17
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

# ============================================================================
# Options
# ============================================================================

option(DNAC_USE_MODULAR_LIBS "Use modular DNA libraries instead of libdna_lib" ON)
option(DNAC_BUILD_TESTS "Build DNAC tests" ON)
option(DNAC_BUILD_CLI "Build dnac-cli executable" ON)
option(DNAC_BUILD_WITNESS "Build dnac-witness server" ON)
option(ENABLE_ASAN "Enable AddressSanitizer in Debug builds" ON)

# ============================================================================
# DNA Messenger Paths
# ============================================================================

set(DNA_MESSENGER_DIR "/opt/dna-messenger" CACHE PATH "Path to DNA Messenger source")
set(DNA_BUILD_DIR "${DNA_MESSENGER_DIR}/build" CACHE PATH "Path to DNA Messenger build")

# ============================================================================
# Dependencies
# ============================================================================

find_package(PkgConfig REQUIRED)
find_package(OpenSSL REQUIRED)
pkg_check_modules(SQLITE3 REQUIRED sqlite3)

# GnuTLS (required by OpenDHT)
pkg_check_modules(GNUTLS REQUIRED gnutls)

# ============================================================================
# Modular DNA Libraries (New Approach)
# ============================================================================

if(DNAC_USE_MODULAR_LIBS)
    message(STATUS "Using modular DNA libraries")

    # Verify modular libraries exist
    if(NOT EXISTS "${DNA_BUILD_DIR}/libs/dna-crypto/libdna-crypto.a")
        message(FATAL_ERROR
            "Modular DNA libraries not found. Build dna-messenger with -DBUILD_DNA_LIBS=ON:\n"
            "  cd ${DNA_BUILD_DIR} && cmake -DBUILD_DNA_LIBS=ON .. && make -j$(nproc)")
    endif()

    # Include directories from DNA Messenger
    set(DNA_INCLUDE_DIRS
        ${DNA_MESSENGER_DIR}
        ${DNA_MESSENGER_DIR}/include
        ${DNA_MESSENGER_DIR}/include/dna
        ${DNA_MESSENGER_DIR}/crypto
        ${DNA_MESSENGER_DIR}/crypto/utils
        ${DNA_MESSENGER_DIR}/crypto/kem
        ${DNA_MESSENGER_DIR}/crypto/dsa
        ${DNA_MESSENGER_DIR}/crypto/bip32
        ${DNA_MESSENGER_DIR}/crypto/bip39
        ${DNA_MESSENGER_DIR}/dht
        ${DNA_MESSENGER_DIR}/dht/core
        ${DNA_MESSENGER_DIR}/dht/client
        ${DNA_MESSENGER_DIR}/dht/shared
        ${DNA_MESSENGER_DIR}/dht/keyserver
        ${DNA_MESSENGER_DIR}/vendor/opendht-pq/include
    )

    # Library paths
    set(DNA_CRYPTO_LIBS
        ${DNA_BUILD_DIR}/libs/dna-crypto/libdna-crypto.a
        ${DNA_BUILD_DIR}/libs/dna-crypto/libdna_kem.a
        ${DNA_BUILD_DIR}/libs/dna-crypto/libdna_dsa.a
        ${DNA_BUILD_DIR}/libs/dna-crypto/libdna_cellframe_dilithium.a
    )

    set(DNA_DHT_LIBS
        ${DNA_BUILD_DIR}/libs/dna-dht/libdna-dht.a
        ${DNA_BUILD_DIR}/dht/libdht_lib.a           # Still needed for C++ DHT wrapper
        ${DNA_BUILD_DIR}/vendor/opendht-pq/libopendht.a
    )

    # Combined DNA libraries for dnac
    set(DNA_LIBRARIES
        ${DNA_DHT_LIBS}
        ${DNA_CRYPTO_LIBS}
    )

else()
    # Fallback to full libdna_lib (legacy approach)
    message(STATUS "Using full libdna_lib (legacy)")

    if(NOT EXISTS "${DNA_BUILD_DIR}/libdna_lib.a" AND NOT EXISTS "${DNA_BUILD_DIR}/libdna_lib.so")
        message(FATAL_ERROR "libdna not found at ${DNA_BUILD_DIR}. Build DNA Messenger first.")
    endif()

    set(DNA_INCLUDE_DIRS
        ${DNA_MESSENGER_DIR}
        ${DNA_MESSENGER_DIR}/include
        ${DNA_MESSENGER_DIR}/crypto
        ${DNA_MESSENGER_DIR}/crypto/utils
    )

    if(EXISTS "${DNA_BUILD_DIR}/libdna_lib.so")
        set(DNA_LIBRARIES ${DNA_BUILD_DIR}/libdna_lib.so)
    else()
        set(DNA_LIBRARIES ${DNA_BUILD_DIR}/libdna_lib.a)
    endif()
endif()

# ============================================================================
# Include Directories
# ============================================================================

include_directories(
    ${CMAKE_SOURCE_DIR}/include
    ${DNA_INCLUDE_DIRS}
    ${OPENSSL_INCLUDE_DIR}
    ${SQLITE3_INCLUDE_DIRS}
    ${GNUTLS_INCLUDE_DIRS}
)

# ============================================================================
# Source Files
# ============================================================================

set(DNAC_SOURCES
    src/version.c
    src/wallet/wallet.c
    src/wallet/utxo.c
    src/wallet/balance.c
    src/wallet/selection.c
    src/transaction/transaction.c
    src/transaction/builder.c
    src/transaction/serialize.c
    src/transaction/verify.c
    src/transaction/genesis.c
    src/nodus/client.c
    src/nodus/attestation.c
    src/nodus/discovery.c
    src/nodus/tcp_client.c
    src/db/db.c
    src/bft/serialize.c
    src/bft/tcp.c
    src/bft/peer.c
    src/bft/consensus.c
    src/bft/roster.c
)

# ============================================================================
# Library Target
# ============================================================================

add_library(dnac STATIC ${DNAC_SOURCES})

target_include_directories(dnac PUBLIC
    ${CMAKE_SOURCE_DIR}/include
)

target_link_libraries(dnac
    ${DNA_LIBRARIES}
    OpenSSL::SSL
    OpenSSL::Crypto
    ${SQLITE3_LIBRARIES}
    ${GNUTLS_LIBRARIES}
    pthread
    m
)

# C++ standard library for OpenDHT
if(DNAC_USE_MODULAR_LIBS)
    target_link_libraries(dnac stdc++)
endif()

# ============================================================================
# CLI Executable
# ============================================================================

if(DNAC_BUILD_CLI)
    add_executable(dnac-cli
        src/cli/main.c
        src/cli/commands.c
    )

    target_link_libraries(dnac-cli
        dnac
        ${DNA_LIBRARIES}
        OpenSSL::SSL
        OpenSSL::Crypto
        ${SQLITE3_LIBRARIES}
        ${GNUTLS_LIBRARIES}
        pthread
        m
    )

    if(DNAC_USE_MODULAR_LIBS)
        target_link_libraries(dnac-cli stdc++)
    endif()

    install(TARGETS dnac-cli RUNTIME DESTINATION bin)
endif()

# ============================================================================
# Witness Server
# ============================================================================

if(DNAC_BUILD_WITNESS)
    add_executable(dnac-witness
        src/witness/main.c
        src/witness/nullifier.c
        src/witness/ledger.c
        src/witness/utxo_tree.c
        src/witness/bft_main.c
        src/witness/forward.c
    )

    target_include_directories(dnac-witness PRIVATE
        ${CMAKE_SOURCE_DIR}/src/witness
    )

    target_link_libraries(dnac-witness
        dnac
        ${DNA_LIBRARIES}
        OpenSSL::SSL
        OpenSSL::Crypto
        ${SQLITE3_LIBRARIES}
        ${GNUTLS_LIBRARIES}
        pthread
        m
    )

    if(DNAC_USE_MODULAR_LIBS)
        target_link_libraries(dnac-witness stdc++)
    endif()

    install(TARGETS dnac-witness RUNTIME DESTINATION bin)
endif()

# ============================================================================
# Tests
# ============================================================================

if(DNAC_BUILD_TESTS)
    enable_testing()

    foreach(TEST_NAME real remote gaps)
        add_executable(test_${TEST_NAME} tests/test_${TEST_NAME}.c)

        target_link_libraries(test_${TEST_NAME}
            dnac
            ${DNA_LIBRARIES}
            OpenSSL::SSL
            OpenSSL::Crypto
            ${SQLITE3_LIBRARIES}
            ${GNUTLS_LIBRARIES}
            pthread
            m
        )

        if(DNAC_USE_MODULAR_LIBS)
            target_link_libraries(test_${TEST_NAME} stdc++)
        endif()

        add_test(NAME ${TEST_NAME} COMMAND test_${TEST_NAME})
    endforeach()
endif()

# ============================================================================
# Summary
# ============================================================================

message(STATUS "")
message(STATUS "DNAC Configuration Summary:")
message(STATUS "  Version:           ${PROJECT_VERSION}")
message(STATUS "  Build type:        ${CMAKE_BUILD_TYPE}")
message(STATUS "  Modular libs:      ${DNAC_USE_MODULAR_LIBS}")
message(STATUS "  DNA Messenger:     ${DNA_MESSENGER_DIR}")
message(STATUS "  DNA Build:         ${DNA_BUILD_DIR}")
message(STATUS "  CLI:               ${DNAC_BUILD_CLI}")
message(STATUS "  Witness:           ${DNAC_BUILD_WITNESS}")
message(STATUS "  Tests:             ${DNAC_BUILD_TESTS}")
message(STATUS "")
```

---

## 7. Building

### 7.1 Build DNA Messenger with Modular Libraries

```bash
cd /opt/dna-messenger/build
cmake -DBUILD_DNA_LIBS=ON ..
make -j$(nproc)
```

### 7.2 Build dnac with Modular Libraries

**Option A: With modular libraries (recommended)**
```bash
cd /opt/dnac/build
cmake -DDNAC_USE_MODULAR_LIBS=ON ..
make -j$(nproc)
```

**Option B: Legacy mode (full libdna_lib)**
```bash
cd /opt/dnac/build
cmake -DDNAC_USE_MODULAR_LIBS=OFF ..
make -j$(nproc)
```

---

## 8. Verification

### 8.1 Verify Library Linking

Check which libraries are linked:
```bash
ldd ./dnac-cli 2>/dev/null || otool -L ./dnac-cli
```

### 8.2 Verify Binary Size

Compare binary sizes before and after:
```bash
# Before (with libdna_lib)
ls -lh /opt/dnac/build-legacy/dnac-cli

# After (with modular libs)
ls -lh /opt/dnac/build/dnac-cli
```

Expected: ~40-50% size reduction

### 8.3 Run Tests

```bash
cd /opt/dnac/build
ctest --output-on-failure
```

### 8.4 Verify Crypto Functions

```bash
./dnac-cli --test-crypto
```

Expected output:
```
Kyber1024 KEM: OK
Dilithium5 DSA: OK
SHA3-512: OK
AES-256-GCM: OK
```

---

## 9. Troubleshooting

### 9.1 "Modular DNA libraries not found"

**Problem:** CMake error about missing modular libraries

**Solution:** Build dna-messenger with the modular libraries flag:
```bash
cd /opt/dna-messenger/build
cmake -DBUILD_DNA_LIBS=ON ..
make -j$(nproc)
```

### 9.2 "undefined reference to `dht_*`"

**Problem:** Linker errors for DHT functions

**Solution:** Ensure `libdht_lib.a` and `libopendht.a` are linked. The modular `libdna-dht.a` contains C wrappers but still needs the C++ DHT implementation:
```cmake
set(DNA_DHT_LIBS
    ${DNA_BUILD_DIR}/libs/dna-dht/libdna-dht.a
    ${DNA_BUILD_DIR}/dht/libdht_lib.a           # C++ wrappers
    ${DNA_BUILD_DIR}/vendor/opendht-pq/libopendht.a
)
```

### 9.3 "undefined reference to `std::*`"

**Problem:** Missing C++ standard library

**Solution:** Link `stdc++` for OpenDHT C++ code:
```cmake
target_link_libraries(dnac stdc++)
```

### 9.4 "undefined reference to `gnutls_*`"

**Problem:** OpenDHT requires GnuTLS

**Solution:** Find and link GnuTLS:
```cmake
pkg_check_modules(GNUTLS REQUIRED gnutls)
target_link_libraries(dnac ${GNUTLS_LIBRARIES})
```

### 9.5 Include Path Issues

**Problem:** "No such file or directory" for DNA headers

**Solution:** Add all necessary include directories:
```cmake
set(DNA_INCLUDE_DIRS
    ${DNA_MESSENGER_DIR}
    ${DNA_MESSENGER_DIR}/include
    ${DNA_MESSENGER_DIR}/crypto
    ${DNA_MESSENGER_DIR}/crypto/utils
    ${DNA_MESSENGER_DIR}/dht
    ${DNA_MESSENGER_DIR}/dht/core
    # ... etc
)
```

---

## 10. Appendix: Library API Reference

### 10.1 dna-crypto API

Key functions available from `libdna-crypto.a`:

```c
// Kyber1024 KEM
int crypto_kem_keypair(uint8_t *pk, uint8_t *sk);
int crypto_kem_enc(uint8_t *ct, uint8_t *ss, const uint8_t *pk);
int crypto_kem_dec(uint8_t *ss, const uint8_t *ct, const uint8_t *sk);

// Dilithium5 DSA
int crypto_sign_keypair(uint8_t *pk, uint8_t *sk);
int crypto_sign_signature(uint8_t *sig, size_t *siglen, const uint8_t *m, size_t mlen,
                          const uint8_t *ctx, size_t ctxlen, const uint8_t *sk);
int crypto_sign_verify(const uint8_t *sig, size_t siglen, const uint8_t *m, size_t mlen,
                       const uint8_t *ctx, size_t ctxlen, const uint8_t *pk);

// SHA3-512
void qgp_sha3_512(const uint8_t *input, size_t input_len, uint8_t output[64]);

// AES-256-GCM
int qgp_aes_encrypt(const uint8_t *key, const uint8_t *nonce, const uint8_t *plaintext,
                    size_t plaintext_len, uint8_t *ciphertext, uint8_t tag[16]);
int qgp_aes_decrypt(const uint8_t *key, const uint8_t *nonce, const uint8_t *ciphertext,
                    size_t ciphertext_len, const uint8_t tag[16], uint8_t *plaintext);

// Platform utilities
const char* qgp_platform_get_data_dir(void);
int qgp_randombytes(uint8_t *buf, size_t len);
```

### 10.2 dna-dht API

Key functions available from `libdna-dht.a`:

```c
// DHT Context
dht_context_t* dht_singleton_get(void);
int dht_singleton_init(const char *data_dir);
void dht_singleton_shutdown(void);

// DHT Operations
int dht_put(dht_context_t *ctx, const uint8_t *key, size_t key_len,
            const uint8_t *value, size_t value_len);
int dht_get(dht_context_t *ctx, const uint8_t *key, size_t key_len,
            uint8_t **value_out, size_t *value_len_out);

// Keyserver
int dht_keyserver_lookup(dht_context_t *ctx, const char *identity,
                         dht_pubkey_entry_t *entry_out);
int dht_keyserver_publish(dht_context_t *ctx, const char *fingerprint,
                          const char *display_name,
                          const uint8_t *dilithium_pubkey,
                          const uint8_t *kyber_pubkey,
                          const uint8_t *dilithium_privkey);

// Value Storage
int dht_put_signed(dht_context_t *ctx, const uint8_t *key, size_t key_len,
                   const uint8_t *value, size_t value_len,
                   uint64_t value_id, uint32_t ttl);
```

---

## Migration Checklist

- [ ] Build dna-messenger with `-DBUILD_DNA_LIBS=ON`
- [ ] Verify all modular libraries exist in `build/libs/`
- [ ] Update dnac CMakeLists.txt with modular library support
- [ ] Add `DNAC_USE_MODULAR_LIBS` option
- [ ] Add GnuTLS dependency for OpenDHT
- [ ] Link C++ standard library for OpenDHT
- [ ] Test build with `cmake -DDNAC_USE_MODULAR_LIBS=ON ..`
- [ ] Verify binary size reduction
- [ ] Run all tests
- [ ] Verify crypto operations work correctly

---

## Version History

| Version | Date | Changes |
|---------|------|---------|
| 1.0.0 | 2026-01-26 | Initial guide |

---

*Document generated as part of DNA Library Refactoring project.*
