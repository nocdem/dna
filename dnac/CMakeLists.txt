cmake_minimum_required(VERSION 3.16)
project(dnac VERSION 0.6.0 LANGUAGES C)

# ============================================================================
# DNAC - Post-Quantum Digital Cash over DHT
# ============================================================================

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# Build type
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release)
endif()

message(STATUS "DNAC Version: ${PROJECT_VERSION}")
message(STATUS "Build Type: ${CMAKE_BUILD_TYPE}")

# ============================================================================
# Options
# ============================================================================

option(DNAC_BUILD_TESTS "Build DNAC tests" ON)
option(DNAC_BUILD_SHARED "Build shared library" OFF)
option(ENABLE_ASAN "Enable AddressSanitizer in Debug builds" ON)

# ============================================================================
# AddressSanitizer (match dna-messenger pattern)
# ============================================================================

if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    if(ENABLE_ASAN)
        set(CMAKE_C_FLAGS_DEBUG "-g -O0 -DDEBUG -fsanitize=address -fno-omit-frame-pointer")
        set(CMAKE_EXE_LINKER_FLAGS_DEBUG "${CMAKE_EXE_LINKER_FLAGS_DEBUG} -fsanitize=address")
        message(STATUS "Debug build with AddressSanitizer enabled")
    else()
        set(CMAKE_C_FLAGS_DEBUG "-g -O0 -DDEBUG")
        message(STATUS "Debug build (ASAN disabled)")
    endif()
endif()

# ============================================================================
# Dependencies
# ============================================================================

# Monorepo paths
set(SHARED_DIR "${CMAKE_SOURCE_DIR}/../shared")
set(DNA_MESSENGER_DIR "${CMAKE_SOURCE_DIR}/../messenger" CACHE PATH "Path to DNA Connect source")
set(DNA_BUILD_DIR "${DNA_MESSENGER_DIR}/build" CACHE PATH "Path to DNA Connect build")

# Check if libdna exists
if(NOT EXISTS "${DNA_BUILD_DIR}/libdna.a" AND NOT EXISTS "${DNA_BUILD_DIR}/libdna.so")
    message(FATAL_ERROR "libdna not found at ${DNA_BUILD_DIR}. Build DNA Connect first.")
endif()

# Find dependencies
find_package(PkgConfig REQUIRED)
find_package(OpenSSL REQUIRED)
pkg_check_modules(SQLITE3 REQUIRED sqlite3)


# ============================================================================
# Include directories
# ============================================================================

set(NODUS_DIR "${CMAKE_SOURCE_DIR}/../nodus")

include_directories(
    ${CMAKE_SOURCE_DIR}/include
    ${DNA_MESSENGER_DIR}/include
    ${DNA_MESSENGER_DIR}
    ${DNA_MESSENGER_DIR}/dht/shared
    ${NODUS_DIR}/include
    ${NODUS_DIR}/src
    ${SHARED_DIR}
    ${SHARED_DIR}/crypto
    ${SHARED_DIR}/crypto/utils
    ${OPENSSL_INCLUDE_DIR}
    ${SQLITE3_INCLUDE_DIRS}
)

# ============================================================================
# Source files
# ============================================================================

set(DNAC_SOURCES
    # Version
    src/version.c

    # Wallet
    src/wallet/wallet.c
    src/wallet/utxo.c
    src/wallet/balance.c
    src/wallet/selection.c

    # Transaction
    src/transaction/transaction.c
    src/transaction/builder.c
    src/transaction/serialize.c
    src/transaction/verify.c
    src/transaction/genesis.c
    src/transaction/nullifier.c
    src/transaction/token_create.c

    # Nodus
    src/nodus/client.c
    src/nodus/discovery.c
    src/nodus/tcp_client.c

    # Database
    src/db/db.c

    # Utils
    src/utils/crypto_helpers.c
)

# ============================================================================
# Library target
# ============================================================================

if(DNAC_BUILD_SHARED)
    add_library(dnac SHARED ${DNAC_SOURCES})
else()
    add_library(dnac STATIC ${DNAC_SOURCES})
endif()

target_include_directories(dnac PUBLIC
    ${CMAKE_SOURCE_DIR}/include
)

# Link against libdna
if(EXISTS "${DNA_BUILD_DIR}/libdna.so")
    target_link_libraries(dnac
        ${DNA_BUILD_DIR}/libdna.so
    )
else()
    target_link_libraries(dnac
        ${DNA_BUILD_DIR}/libdna.a
    )
endif()

# Link other dependencies
target_link_libraries(dnac
    OpenSSL::SSL
    OpenSSL::Crypto
    ${SQLITE3_LIBRARIES}
    pthread
    m
)


# CLI removed — all DNAC commands are now in dna-connect-cli (messenger/cli/cli_dna_chain.c)

# ============================================================================
# Tests
# ============================================================================

if(DNAC_BUILD_TESTS)
    enable_testing()

    # ── Multi-TX block refactor: register_dnac_test macro ────────────
    # Convenience helper for new tests created by the refactor sprint.
    # Wraps the boilerplate (link dnac, libdna, OpenSSL, sqlite, pthread, m).
    # Existing tests below continue using the explicit pattern.
    function(register_dnac_test name)
        add_executable(${name} tests/${name}.c)
        target_link_libraries(${name} dnac)
        if(EXISTS "${DNA_BUILD_DIR}/libdna.so")
            target_link_libraries(${name} ${DNA_BUILD_DIR}/libdna.so)
        else()
            target_link_libraries(${name} ${DNA_BUILD_DIR}/libdna.a)
        endif()
        target_link_libraries(${name}
            OpenSSL::SSL
            OpenSSL::Crypto
            ${SQLITE3_LIBRARIES}
            pthread
            m
        )
        add_test(NAME ${name} COMMAND ${name})
    endfunction()

    # Real end-to-end test (uses real genesis, real witnesses, real DHT)
    add_executable(test_real tests/test_real.c)

    target_link_libraries(test_real dnac)

    # Link libdna directly for dna_engine functions
    if(EXISTS "${DNA_BUILD_DIR}/libdna.so")
        target_link_libraries(test_real ${DNA_BUILD_DIR}/libdna.so)
    else()
        target_link_libraries(test_real ${DNA_BUILD_DIR}/libdna.a)
    endif()

    target_link_libraries(test_real
        OpenSSL::SSL
        OpenSSL::Crypto
        ${SQLITE3_LIBRARIES}
        pthread
        m
    )

    add_test(NAME real COMMAND test_real)

    # Chain ID derivation and phase 1 genesis tests (offline, no network)
    add_executable(test_chain_id tests/test_chain_id.c)

    target_link_libraries(test_chain_id dnac)

    if(EXISTS "${DNA_BUILD_DIR}/libdna.so")
        target_link_libraries(test_chain_id ${DNA_BUILD_DIR}/libdna.so)
    else()
        target_link_libraries(test_chain_id ${DNA_BUILD_DIR}/libdna.a)
    endif()

    target_link_libraries(test_chain_id
        OpenSSL::SSL
        OpenSSL::Crypto
        ${SQLITE3_LIBRARIES}
        pthread
        m
    )

    add_test(NAME chain_id COMMAND test_chain_id)

    # Remote send test (sends to different machine)
    add_executable(test_remote tests/test_remote.c)

    target_link_libraries(test_remote dnac)

    # Link libdna directly for dna_engine functions
    if(EXISTS "${DNA_BUILD_DIR}/libdna.so")
        target_link_libraries(test_remote ${DNA_BUILD_DIR}/libdna.so)
    else()
        target_link_libraries(test_remote ${DNA_BUILD_DIR}/libdna.a)
    endif()

    target_link_libraries(test_remote
        OpenSSL::SSL
        OpenSSL::Crypto
        ${SQLITE3_LIBRARIES}
        pthread
        m
    )

    # v0.6.0 Gap fixes test
    add_executable(test_gaps tests/test_gaps.c)

    target_link_libraries(test_gaps dnac)

    # Link libdna directly for dna_engine functions
    if(EXISTS "${DNA_BUILD_DIR}/libdna.so")
        target_link_libraries(test_gaps ${DNA_BUILD_DIR}/libdna.so)
    else()
        target_link_libraries(test_gaps ${DNA_BUILD_DIR}/libdna.a)
    endif()

    target_link_libraries(test_gaps
        OpenSSL::SSL
        OpenSSL::Crypto
        ${SQLITE3_LIBRARIES}
        pthread
        m
    )

    add_test(NAME gaps COMMAND test_gaps)

    # Multi-asset TX foundation tests (offline, no network)
    add_executable(test_multi_asset tests/test_multi_asset.c)

    target_link_libraries(test_multi_asset dnac)

    if(EXISTS "${DNA_BUILD_DIR}/libdna.so")
        target_link_libraries(test_multi_asset ${DNA_BUILD_DIR}/libdna.so)
    else()
        target_link_libraries(test_multi_asset ${DNA_BUILD_DIR}/libdna.a)
    endif()

    target_link_libraries(test_multi_asset
        OpenSSL::SSL
        OpenSSL::Crypto
        ${SQLITE3_LIBRARIES}
        pthread
        m
    )

    add_test(NAME multi_asset COMMAND test_multi_asset)

    # Chain-def codec roundtrip + determinism (anchored-merkle-proofs Task 9)
    register_dnac_test(test_chain_def_codec)

    # Fixed-vector test for dnac_merkle_verify_proof (anchored-merkle-proofs Task 17)
    register_dnac_test(test_merkle_verify)
    register_dnac_test(test_anchor_verify)
    register_dnac_test(test_genesis_verify)

    # Phase 9 end-to-end: genesis + anchor + merkle proof composition (Tasks 50-53)
    register_dnac_test(test_anchored_proofs)

    # Stake & delegation v1 — Phase 1 Task 1: TX type enum values
    register_dnac_test(test_tx_types)

    # Stake & delegation v1 — Phase 1 Task 2: stake/committee/timing constants
    register_dnac_test(test_stake_constants)

    # Stake & delegation v1 — Phase 1 Task 3: validator/delegation/reward record structs
    register_dnac_test(test_validator_structs)

    # Stake & delegation v1 — Phase 1 Task 4: version bump marker
    register_dnac_test(test_version_bump)

    # Stake & delegation v1 — Phase 5 Task 14: TX preimage binds chain_id
    register_dnac_test(test_preimage_binding)

    # Stake & delegation v1 — Phase 5 Task 15: signer-count truncation invariance
    register_dnac_test(test_signer_canonical)

    # Stake & delegation v1 — Phase 5 Task 16: STAKE appended-field serialization
    register_dnac_test(test_stake_serialize)

    # Stake & delegation v1 — Phase 5 Task 17: DELEGATE appended-field serialization
    register_dnac_test(test_delegate_serialize)

    # Stake & delegation v1 — Phase 5 Task 18: UNDELEGATE + CLAIM_REWARD appended fields
    register_dnac_test(test_undelegate_serialize)
    register_dnac_test(test_claim_reward_serialize)
endif()

# ============================================================================
# Install
# ============================================================================

install(TARGETS dnac
    LIBRARY DESTINATION lib
    ARCHIVE DESTINATION lib
)

install(DIRECTORY include/dnac
    DESTINATION include
)

# ============================================================================
# Summary
# ============================================================================

message(STATUS "")
message(STATUS "DNAC Configuration Summary:")
message(STATUS "  Version:        ${PROJECT_VERSION}")
message(STATUS "  Build type:     ${CMAKE_BUILD_TYPE}")
message(STATUS "  DNA Connect:  ${DNA_MESSENGER_DIR}")
message(STATUS "  DNA Build:      ${DNA_BUILD_DIR}")
message(STATUS "  CLI:            ${DNAC_BUILD_CLI}")
message(STATUS "  Tests:          ${DNAC_BUILD_TESTS}")
message(STATUS "")
