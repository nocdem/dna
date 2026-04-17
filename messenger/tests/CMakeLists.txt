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
# DNA_BUILD defaults to ../build but can be overridden from the command line
# via -DDNA_BUILD=... (Phase 02-04: used to point tests at build-tsan/ when
# running the concurrency suite under ThreadSanitizer).
if(NOT DEFINED DNA_BUILD OR DNA_BUILD STREQUAL "")
    set(DNA_BUILD "${DNA_ROOT}/build")
endif()
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
    ${DNA_ROOT}/dht/client  # dna_profile.h (transitively included by dht_keyserver.h)
    ${DNA_ROOT}/../nodus/include  # nodus/nodus_types.h (THR-02 test_nodus_init_concurrent)
    ${DNA_ROOT}/../nodus/src      # nodus/nodus.h transitively needs core/nodus_media_storage.h (Phase 6 wave 0)
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

# Phase 02-04 THR-03/SEC-04/SEC-05/THR-02 concurrency tests: opt-in
# ThreadSanitizer via -DENABLE_TSAN=ON. Mutually exclusive with AddressSanitizer.
# See messenger/docs/CONCURRENCY.md for usage.
option(ENABLE_TSAN "Build with ThreadSanitizer (conflicts with ASan)" OFF)

if(ENABLE_TSAN)
    message(STATUS "ENABLE_TSAN=ON — building tests with -fsanitize=thread (ASan disabled)")
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -g -O1 -fsanitize=thread -fno-omit-frame-pointer")
    set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -fsanitize=thread")
elseif(CMAKE_BUILD_TYPE STREQUAL "Debug")
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
# Test: SEC-02 — qgp_key file size validation (exact-bounds rejection)
# =============================================================================
add_executable(test_qgp_key_size_validation test_qgp_key_size_validation.c)
target_link_libraries(test_qgp_key_size_validation ${TEST_LIBS})
add_test(NAME qgp_key_size_validation COMMAND test_qgp_key_size_validation)

# =============================================================================
# Test: SEC-01 — Contact request wire-level validation regression guard
# =============================================================================
add_executable(test_contact_request_validation test_contact_request_validation.c)
target_link_libraries(test_contact_request_validation ${TEST_LIBS})
add_test(NAME contact_request_validation COMMAND test_contact_request_validation)

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
# Test: SEC-04 — concurrent GEK KEM-key rwlock race regression (Phase 02-01)
# =============================================================================
add_executable(test_gek_concurrent test_gek_concurrent.c)
target_link_libraries(test_gek_concurrent ${TEST_LIBS})
add_test(NAME gek_concurrent COMMAND test_gek_concurrent)

# =============================================================================
# Test: SEC-05 — engine destroy during backup regression (Phase 02-02)
# =============================================================================
add_executable(test_engine_destroy_during_backup test_engine_destroy_during_backup.c)
target_link_libraries(test_engine_destroy_during_backup ${TEST_LIBS})
add_test(NAME engine_destroy_during_backup COMMAND test_engine_destroy_during_backup)

# =============================================================================
# Test: THR-02 — concurrent nodus init mutex + pthread_once regression (Phase 02-03)
# =============================================================================
add_executable(test_nodus_init_concurrent test_nodus_init_concurrent.c)
target_link_libraries(test_nodus_init_concurrent ${TEST_LIBS} pthread)
add_test(NAME nodus_init_concurrent COMMAND test_nodus_init_concurrent)
set_tests_properties(nodus_init_concurrent PROPERTIES TIMEOUT 30)

# =============================================================================
# Test: THR-03 — task queue MPSC-via-task_mutex contract regression (Phase 02-04)
# =============================================================================
# Positive: N threads call public engine API that funnels through the
# THR-03 assert under task_mutex. Negative: fork() child mirrors the
# assert(pthread_equal(...)) pattern with a zero-initialized owner and
# must abort with SIGABRT — proves the mechanism actually trips.
add_executable(test_concurrency_task_queue_contract test_concurrency_task_queue_contract.c)
target_link_libraries(test_concurrency_task_queue_contract ${TEST_LIBS} pthread)
add_test(NAME concurrency_task_queue_contract COMMAND test_concurrency_task_queue_contract)
set_tests_properties(concurrency_task_queue_contract PROPERTIES TIMEOUT 30)

# =============================================================================
# TSan suppression wiring (Phase 02-04 THR-03/SEC-04/SEC-05/THR-02)
# =============================================================================
# When built with -DENABLE_TSAN=ON, run the concurrency tests with
# TSAN_OPTIONS pointing at the (empty, comment-only) tsan.supp scaffold.
if(ENABLE_TSAN)
    set_tests_properties(
        gek_concurrent
        engine_destroy_during_backup
        nodus_init_concurrent
        concurrency_task_queue_contract
        PROPERTIES
        ENVIRONMENT "TSAN_OPTIONS=suppressions=${CMAKE_CURRENT_SOURCE_DIR}/tsan.supp:halt_on_error=1"
    )
endif()

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
# Test: Platform Keystore (TEE noop backend on desktop)
# =============================================================================
add_executable(test_platform_keystore test_platform_keystore.c)
target_link_libraries(test_platform_keystore ${TEST_LIBS})
add_test(NAME test_platform_keystore COMMAND test_platform_keystore)

# =============================================================================
# Test: Registered name validator (regression for reverse_lookup bug)
# =============================================================================
add_executable(test_registered_name_validation test_registered_name_validation.c)
target_link_libraries(test_registered_name_validation ${TEST_LIBS})
add_test(NAME test_registered_name_validation COMMAND test_registered_name_validation)

# =============================================================================
# Phase 6 Wave 0 — RED test scaffolding for CORE-04 / CORE-05
# =============================================================================
# These five tests are intentionally RED until their respective fixing plans
# (02..05) land. They MUST compile, link, and be discoverable via `ctest -N`
# from day one so later plans can drive them GREEN one at a time.
# See: .planning/phases/06-c-engine-core-flow-fixes/6-01-wave0-test-scaffolding-PLAN.md

# CORE-05: register-name failure must not delete on-disk identity material
add_executable(test_register_name_failure_preserves_keys test_register_name_failure_preserves_keys.c)
target_link_libraries(test_register_name_failure_preserves_keys ${TEST_LIBS})
add_test(NAME test_register_name_failure_preserves_keys COMMAND test_register_name_failure_preserves_keys)

# CORE-05: register-name idempotency regression guard (nodus-dependent: SKIP=77)
add_executable(test_register_name_idempotent test_register_name_idempotent.c)
target_link_libraries(test_register_name_idempotent ${TEST_LIBS})
add_test(NAME test_register_name_idempotent COMMAND test_register_name_idempotent)
set_tests_properties(test_register_name_idempotent PROPERTIES SKIP_RETURN_CODE 77)

# CORE-04: group outbox key derivation must accept and embed a per-group salt
add_executable(test_group_outbox_make_key_salted test_group_outbox_make_key_salted.c)
target_link_libraries(test_group_outbox_make_key_salted ${TEST_LIBS})
add_test(NAME test_group_outbox_make_key_salted COMMAND test_group_outbox_make_key_salted)

# CORE-04: DM outbox helper must reject NULL salt (close legacy fallback)
add_executable(test_dm_outbox_requires_salt test_dm_outbox_requires_salt.c)
target_link_libraries(test_dm_outbox_requires_salt ${TEST_LIBS})
add_test(NAME test_dm_outbox_requires_salt COMMAND test_dm_outbox_requires_salt)

# CORE-04: groups.db schema v2 -> v3 migration adds dht_salt + has_dht_salt
add_executable(test_group_database_migration_v3 test_group_database_migration_v3.c)
target_link_libraries(test_group_database_migration_v3 ${TEST_LIBS})
add_test(NAME test_group_database_migration_v3 COMMAND test_group_database_migration_v3)

# =============================================================================
# Test: Reaction JSON build/parse helpers
# =============================================================================
add_executable(test_reactions test_reactions.c)
target_link_libraries(test_reactions ${TEST_LIBS})
add_test(NAME test_reactions COMMAND test_reactions)

# =============================================================================
# Test: Portable u128 round-trip (DNAC reward accumulator)
# =============================================================================
# Phase 2 Task 5 of witness stake v1. Full KAT suite lands in Task 6.
add_executable(test_u128_roundtrip test_u128_roundtrip.c)
target_link_libraries(test_u128_roundtrip ${TEST_LIBS})
add_test(NAME test_u128_roundtrip COMMAND test_u128_roundtrip)

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
