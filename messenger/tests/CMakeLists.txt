# =============================================================================
# DNA Connect Test Suite
# =============================================================================
# Standalone CMake build for test executables.
#
# Usage:
#   cd tests && mkdir -p build && cd build
#   cmake ..
#   make -j$(nproc)
#
# Prerequisites:
#   - Main project must be built first (../build)
# =============================================================================

cmake_minimum_required(VERSION 3.10)
project(dna_tests C)

# =============================================================================
# Find the main project build
# =============================================================================
set(DNA_ROOT "${CMAKE_SOURCE_DIR}/..")
set(DNA_BUILD "${DNA_ROOT}/build")
set(SHARED_DIR "${DNA_ROOT}/../shared")

# Verify main project is built (shared lib)
if(NOT EXISTS "${DNA_BUILD}/libdna.so")
    message(FATAL_ERROR
        "Main project not built. Run:\n"
        "  cd ${DNA_ROOT}/build && cmake .. && make -j$(nproc)\n"
        "Then try again."
    )
endif()

message(STATUS "DNA root: ${DNA_ROOT}")
message(STATUS "DNA build: ${DNA_BUILD}")
message(STATUS "Shared dir: ${SHARED_DIR}")

# =============================================================================
# Include paths
# =============================================================================
include_directories(
    ${DNA_ROOT}
    ${DNA_ROOT}/include
    ${SHARED_DIR}          # shared/crypto/utils/*.h, shared/crypto/bip39/*.h
)

# =============================================================================
# Find required system libraries
# =============================================================================
find_package(PkgConfig REQUIRED)
find_package(OpenSSL REQUIRED)
pkg_check_modules(SQLCIPHER REQUIRED sqlcipher)

# =============================================================================
# Link against the shared library (carries all internal deps)
# =============================================================================
set(TEST_LIBS
    ${DNA_BUILD}/libdna.so
    ${SQLCIPHER_LIBRARIES}
    ${OPENSSL_LIBRARIES}
    pthread
    m
)

# SQLCipher include dirs (provides sqlite3.h with encryption support)
include_directories(${SQLCIPHER_INCLUDE_DIRS})

# =============================================================================
# Compiler flags
# =============================================================================
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Wextra -Wno-unused-parameter")

# Debug build by default for tests
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Debug)
endif()

if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -g -O0 -fsanitize=address -fno-omit-frame-pointer")
    set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -fsanitize=address")
endif()

# Set RPATH so test binaries find libdna.so at runtime
set(CMAKE_BUILD_RPATH "${DNA_BUILD}")
set(CMAKE_INSTALL_RPATH "${DNA_BUILD}")

# =============================================================================
# Build info
# =============================================================================
message(STATUS "")
message(STATUS "DNA Connect Test Suite")
message(STATUS "========================")
message(STATUS "Build type: ${CMAKE_BUILD_TYPE}")
message(STATUS "")
message(STATUS "Test executables:")
message(STATUS "  - test_aes256_gcm      : AES-256-GCM encryption/decryption")
message(STATUS "  - test_key_encryption  : Key encryption (PBKDF2 + AES-256-GCM)")
message(STATUS "  - test_kyber1024       : Kyber1024 (ML-KEM-1024) post-quantum KEM")
message(STATUS "  - test_bip39_bip32     : BIP39/BIP32 mnemonic and HD key derivation")
message(STATUS "  - test_db_encryption   : Database encryption (SQLCipher)")
message(STATUS "")

# =============================================================================
# Test: AES-256-GCM Encryption/Decryption
# =============================================================================
add_executable(test_aes256_gcm test_aes256_gcm.c)
target_link_libraries(test_aes256_gcm ${TEST_LIBS})
add_test(NAME test_aes256_gcm COMMAND test_aes256_gcm)

# =============================================================================
# Test: Key Encryption (PBKDF2 + AES-256-GCM)
# =============================================================================
add_executable(test_key_encryption test_key_encryption.c)
target_link_libraries(test_key_encryption ${TEST_LIBS})
add_test(NAME test_key_encryption COMMAND test_key_encryption)

# =============================================================================
# Test: Kyber1024 (ML-KEM-1024) Post-Quantum KEM
# =============================================================================
add_executable(test_kyber1024 test_kyber1024.c)
target_link_libraries(test_kyber1024 ${TEST_LIBS})
add_test(NAME test_kyber1024 COMMAND test_kyber1024)

# =============================================================================
# Test: BIP39/BIP32 Mnemonic and HD Key Derivation
# =============================================================================
add_executable(test_bip39_bip32 test_bip39_bip32.c)
target_link_libraries(test_bip39_bip32 ${TEST_LIBS})
add_test(NAME test_bip39_bip32 COMMAND test_bip39_bip32)

# =============================================================================
# Test: GEK v2 HKDF Ratchet Chain
# =============================================================================
add_executable(test_gek_ratchet test_gek_ratchet.c)
target_link_libraries(test_gek_ratchet ${TEST_LIBS})
add_test(NAME test_gek_ratchet COMMAND test_gek_ratchet)

# =============================================================================
# Test: Salt Agreement Protocol (Kyber dual-encrypted, authenticated)
# =============================================================================
add_executable(test_salt_agreement test_salt_agreement.c)
target_link_libraries(test_salt_agreement ${TEST_LIBS})
add_test(NAME test_salt_agreement COMMAND test_salt_agreement)

# =============================================================================
# Test: Group Channel (Phase 2) — UUID mapping, crypto, connector lifecycle
# =============================================================================
add_executable(test_group_channel test_group_channel.c)
target_link_libraries(test_group_channel ${TEST_LIBS})
add_test(NAME test_group_channel COMMAND test_group_channel)

# =============================================================================
# Test: Database Encryption (SQLCipher key derivation + encrypted open)
# =============================================================================
add_executable(test_db_encryption test_db_encryption.c)
target_link_libraries(test_db_encryption ${TEST_LIBS})
add_test(NAME test_db_encryption COMMAND test_db_encryption)

# =============================================================================
# Test: Debug Log Wire Format (encode/decode)
# =============================================================================
add_executable(test_debug_log_wire
    test_debug_log_wire.c
    ${DNA_ROOT}/src/api/engine/dna_debug_log_wire.c)
target_include_directories(test_debug_log_wire PRIVATE ${DNA_ROOT}/src/api/engine)
target_link_libraries(test_debug_log_wire ${TEST_LIBS})
add_test(NAME test_debug_log_wire COMMAND test_debug_log_wire)

# =============================================================================
# CTest integration
# =============================================================================
enable_testing()

# =============================================================================
# Fuzzing Configuration (libFuzzer)
# =============================================================================
# Enable with: CC=clang CXX=clang++ cmake -DENABLE_FUZZING=ON ..
option(ENABLE_FUZZING "Enable libFuzzer fuzz testing (requires Clang)" OFF)

if(ENABLE_FUZZING)
    if(NOT CMAKE_C_COMPILER_ID STREQUAL "Clang")
        message(FATAL_ERROR
            "libFuzzer requires Clang compiler.\n"
            "Usage: CC=clang CXX=clang++ cmake -DENABLE_FUZZING=ON .."
        )
    endif()

    include_directories(${CMAKE_SOURCE_DIR}/fuzz)

    set(FUZZ_COMMON_SOURCES ${CMAKE_SOURCE_DIR}/fuzz/fuzz_common.c)
    set(FUZZ_COMPILE_FLAGS "-fsanitize=fuzzer,address -fno-omit-frame-pointer -g")
    set(FUZZ_LINK_FLAGS "-fsanitize=fuzzer,address")

    macro(add_fuzz_target TARGET_NAME SOURCE_FILE)
        add_executable(${TARGET_NAME} ${SOURCE_FILE} ${FUZZ_COMMON_SOURCES})
        set_target_properties(${TARGET_NAME} PROPERTIES
            COMPILE_FLAGS "${FUZZ_COMPILE_FLAGS}"
            LINK_FLAGS "${FUZZ_LINK_FLAGS}"
        )
        target_link_libraries(${TARGET_NAME} ${TEST_LIBS})
    endmacro()

    add_fuzz_target(fuzz_offline_queue fuzz/fuzz_offline_queue.c)
    add_fuzz_target(fuzz_contact_request fuzz/fuzz_contact_request.c)
    add_fuzz_target(fuzz_message_decrypt fuzz/fuzz_message_decrypt.c)
    add_fuzz_target(fuzz_profile_json fuzz/fuzz_profile_json.c)
    add_fuzz_target(fuzz_base58 fuzz/fuzz_base58.c)

    message(STATUS "Fuzzing targets enabled (libFuzzer)")
endif()
