# =============================================================================
# DNA Messenger Test Suite
# =============================================================================
# Standalone CMake build for test executables.
#
# Usage:
#   cd tests && mkdir build && cd build
#   cmake ..
#   make
#
# Prerequisites:
#   - Main project must be built first (../build)
#   - Identity must exist for DHT tests
# =============================================================================

cmake_minimum_required(VERSION 3.10)
project(dna_tests C CXX)

# =============================================================================
# Find the main project build
# =============================================================================
set(DNA_ROOT "${CMAKE_SOURCE_DIR}/..")
set(DNA_BUILD "${DNA_ROOT}/build")

# Verify main project is built
if(NOT EXISTS "${DNA_BUILD}/dht/libdht_lib.a")
    message(FATAL_ERROR
        "Main project not built. Run:\n"
        "  cd ${DNA_ROOT}/build && cmake .. && make\n"
        "Then try again."
    )
endif()

message(STATUS "DNA root: ${DNA_ROOT}")
message(STATUS "DNA build: ${DNA_BUILD}")

# =============================================================================
# Include paths from main project
# =============================================================================
include_directories(
    ${DNA_ROOT}
    ${DNA_ROOT}/include
    ${DNA_ROOT}/vendor/opendht-pq/include
    /usr/local/include
)

# =============================================================================
# Find required libraries
# =============================================================================
find_package(PkgConfig REQUIRED)
pkg_check_modules(GNUTLS REQUIRED gnutls)
pkg_check_modules(JSONC REQUIRED json-c)
find_package(SQLite3 REQUIRED)
find_package(OpenSSL REQUIRED)

# =============================================================================
# Link directories
# =============================================================================
link_directories(
    ${DNA_BUILD}/dht
    ${DNA_BUILD}/p2p
    ${DNA_BUILD}/vendor/opendht-pq
    ${DNA_BUILD}/crypto/kem
    ${DNA_BUILD}/crypto/dsa
    /usr/local/lib
)

# =============================================================================
# Common libraries for all tests
# =============================================================================
# Find fmt library
find_package(fmt CONFIG REQUIRED)

# Find jsoncpp library
find_package(PkgConfig REQUIRED)
pkg_check_modules(JSONCPP REQUIRED jsoncpp)

# Link order matters! dht_lib must come after crypto libs that need qgp_randombytes
# dna_lib includes messenger module (gek, messages, groups, etc.)
set(TEST_LIBS
    ${DNA_BUILD}/libdna_lib.a
    ${DNA_BUILD}/p2p/libp2p_transport.a
    ${DNA_BUILD}/dht/libdht_lib.a
    ${DNA_BUILD}/vendor/opendht-pq/libopendht.a
    ${DNA_BUILD}/crypto/kem/libkem.a
    ${DNA_BUILD}/crypto/dsa/libdsa.a
    ${DNA_BUILD}/dht/libdht_lib.a
    ${DNA_BUILD}/vendor/libjuice/install/lib/libjuice.a
    ${GNUTLS_LIBRARIES}
    ${JSONC_LIBRARIES}
    ${SQLite3_LIBRARIES}
    ${OPENSSL_LIBRARIES}
    ${JSONCPP_LIBRARIES}
    fmt::fmt
    nettle
    hogweed
    argon2
    zstd
    z
    msgpackc
    ${DNA_BUILD}/secp256k1/lib/libsecp256k1.a
    pthread
    m
)

# =============================================================================
# Compiler flags
# =============================================================================
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Wextra")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -Wextra")

# Debug build by default for tests
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Debug)
endif()

if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -g -O0 -fsanitize=address -fno-omit-frame-pointer")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -g -O0 -fsanitize=address -fno-omit-frame-pointer")
    set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -fsanitize=address")
endif()

# =============================================================================
# Test: DHT listen() Update Detection
# NOTE: test_listen_updates.c was removed, using test_dht_listen.c instead
# =============================================================================

# =============================================================================
# Test: DHT listen() Basic Functionality
# =============================================================================
add_executable(test_dht_listen
    test_dht_listen.c
)
set_target_properties(test_dht_listen PROPERTIES LINKER_LANGUAGE CXX)
target_link_libraries(test_dht_listen ${TEST_LIBS} stdc++)

# Note: test_signed_put.c and test_pq_put_get.c use different include paths
# They need to be updated to use the same pattern as the other tests

# =============================================================================
# Build info
# =============================================================================
message(STATUS "")
message(STATUS "DNA Messenger Test Suite")
message(STATUS "========================")
message(STATUS "Build type: ${CMAKE_BUILD_TYPE}")
message(STATUS "")
message(STATUS "Test executables:")
message(STATUS "  - test_dht_listen      : DHT listen() basic functionality")
message(STATUS "  - test_aes256_gcm      : AES-256-GCM encryption/decryption")
message(STATUS "  - test_key_encryption  : Key encryption (PBKDF2 + AES-256-GCM)")
message(STATUS "  - test_kyber1024       : Kyber1024 (ML-KEM-1024) post-quantum KEM")
message(STATUS "  - test_bip39_bip32     : BIP39/BIP32 mnemonic and HD key derivation")
message(STATUS "")
message(STATUS "Run tests:")
message(STATUS "  ./test_dht_listen")
message(STATUS "  ./test_aes256_gcm")
message(STATUS "  ./test_key_encryption")
message(STATUS "  ./test_kyber1024")
message(STATUS "  ./test_bip39_bip32")
message(STATUS "")

# =============================================================================
# Test: AES-256-GCM Encryption/Decryption
# =============================================================================
add_executable(test_aes256_gcm
    test_aes256_gcm.c
)
set_target_properties(test_aes256_gcm PROPERTIES LINKER_LANGUAGE CXX)
target_link_libraries(test_aes256_gcm ${TEST_LIBS} stdc++)

# =============================================================================
# Test: Key Encryption (PBKDF2 + AES-256-GCM) - P1-1
# =============================================================================
add_executable(test_key_encryption
    test_key_encryption.c
)
set_target_properties(test_key_encryption PROPERTIES LINKER_LANGUAGE CXX)
target_link_libraries(test_key_encryption ${TEST_LIBS} stdc++)

# =============================================================================
# Test: Kyber1024 (ML-KEM-1024) Post-Quantum KEM - P1-4
# =============================================================================
add_executable(test_kyber1024
    test_kyber1024.c
)
set_target_properties(test_kyber1024 PROPERTIES LINKER_LANGUAGE CXX)
target_link_libraries(test_kyber1024 ${TEST_LIBS} stdc++)

# =============================================================================
# Test: BIP39/BIP32 Mnemonic and HD Key Derivation - P1-2
# =============================================================================
add_executable(test_bip39_bip32
    test_bip39_bip32.c
)
set_target_properties(test_bip39_bip32 PROPERTIES LINKER_LANGUAGE CXX)
target_link_libraries(test_bip39_bip32 ${TEST_LIBS} stdc++)

# =============================================================================
# Fuzzing Configuration (libFuzzer)
# =============================================================================
# Enable with: CC=clang CXX=clang++ cmake -DENABLE_FUZZING=ON ..
#
# libFuzzer is LLVM's coverage-guided fuzzer. It requires:
#   - Clang compiler (GCC not supported)
#   - -fsanitize=fuzzer flag (provides LLVMFuzzerTestOneInput entry point)
#   - ASAN is automatically included for memory error detection
#
# Usage:
#   cd tests && mkdir build-fuzz && cd build-fuzz
#   CC=clang CXX=clang++ cmake -DENABLE_FUZZING=ON -DCMAKE_BUILD_TYPE=Debug ..
#   make -j$(nproc)
#   ./fuzz_offline_queue corpus/offline_queue/ -max_total_time=60
# =============================================================================
option(ENABLE_FUZZING "Enable libFuzzer fuzz testing (requires Clang)" OFF)

if(ENABLE_FUZZING)
    # Verify Clang compiler
    if(NOT CMAKE_C_COMPILER_ID STREQUAL "Clang")
        message(FATAL_ERROR
            "libFuzzer requires Clang compiler.\n"
            "Current C compiler: ${CMAKE_C_COMPILER_ID}\n"
            "Usage: CC=clang CXX=clang++ cmake -DENABLE_FUZZING=ON .."
        )
    endif()

    # Include fuzz directory for fuzz_common.h
    include_directories(${CMAKE_SOURCE_DIR}/fuzz)

    # Common fuzz harness sources
    set(FUZZ_COMMON_SOURCES
        ${CMAKE_SOURCE_DIR}/fuzz/fuzz_common.c
    )

    # Fuzzer-specific compile/link flags (applied per-target, not globally)
    set(FUZZ_COMPILE_FLAGS "-fsanitize=fuzzer,address -fno-omit-frame-pointer -g")
    set(FUZZ_LINK_FLAGS "-fsanitize=fuzzer,address")

    # Macro to add fuzz targets with proper flags
    macro(add_fuzz_target TARGET_NAME SOURCE_FILE)
        add_executable(${TARGET_NAME}
            ${SOURCE_FILE}
            ${FUZZ_COMMON_SOURCES}
        )
        set_target_properties(${TARGET_NAME} PROPERTIES
            LINKER_LANGUAGE CXX
            COMPILE_FLAGS "${FUZZ_COMPILE_FLAGS}"
            LINK_FLAGS "${FUZZ_LINK_FLAGS}"
        )
        target_link_libraries(${TARGET_NAME} ${TEST_LIBS} stdc++)
    endmacro()

    # Fuzz targets
    add_fuzz_target(fuzz_offline_queue fuzz/fuzz_offline_queue.c)
    add_fuzz_target(fuzz_contact_request fuzz/fuzz_contact_request.c)
    add_fuzz_target(fuzz_message_decrypt fuzz/fuzz_message_decrypt.c)
    add_fuzz_target(fuzz_profile_json fuzz/fuzz_profile_json.c)
    add_fuzz_target(fuzz_base58 fuzz/fuzz_base58.c)

    message(STATUS "")
    message(STATUS "Fuzzing targets enabled (libFuzzer):")
    message(STATUS "  - fuzz_offline_queue   : DHT offline message deserialization")
    message(STATUS "  - fuzz_contact_request : DHT contact request deserialization")
    message(STATUS "  - fuzz_message_decrypt : DNA message decryption (v0.08)")
    message(STATUS "  - fuzz_profile_json    : Profile JSON parsing")
    message(STATUS "  - fuzz_base58          : Base58 decoding")
    message(STATUS "")
    message(STATUS "Run fuzzers:")
    message(STATUS "  ./fuzz_offline_queue ../fuzz/corpus/offline_queue/ -max_total_time=60")
    message(STATUS "")
endif()
