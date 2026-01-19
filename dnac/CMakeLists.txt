cmake_minimum_required(VERSION 3.16)
project(dnac VERSION 0.1.0 LANGUAGES C)

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

# ============================================================================
# Dependencies
# ============================================================================

# libdna from DNA Messenger
set(DNA_MESSENGER_DIR "/opt/dna-messenger" CACHE PATH "Path to DNA Messenger source")
set(DNA_BUILD_DIR "${DNA_MESSENGER_DIR}/build" CACHE PATH "Path to DNA Messenger build")

# Check if libdna exists
if(NOT EXISTS "${DNA_BUILD_DIR}/libdna_lib.a" AND NOT EXISTS "${DNA_BUILD_DIR}/libdna_lib.so")
    message(FATAL_ERROR "libdna not found at ${DNA_BUILD_DIR}. Build DNA Messenger first.")
endif()

# Find dependencies
find_package(PkgConfig REQUIRED)
find_package(OpenSSL REQUIRED)
pkg_check_modules(SQLITE3 REQUIRED sqlite3)

# Optional: secp256k1-zkp for Bulletproofs (will use vendored if not found)
pkg_check_modules(SECP256K1 libsecp256k1)

# ============================================================================
# Include directories
# ============================================================================

include_directories(
    ${CMAKE_SOURCE_DIR}/include
    ${DNA_MESSENGER_DIR}/include
    ${DNA_MESSENGER_DIR}
    ${DNA_MESSENGER_DIR}/crypto
    ${DNA_MESSENGER_DIR}/crypto/utils
    ${OPENSSL_INCLUDE_DIR}
    ${SQLITE3_INCLUDE_DIRS}
)

# ============================================================================
# Source files
# ============================================================================

set(DNAC_SOURCES
    # Version
    src/version.c

    # Crypto (v2 ZK stubs - not used in v1)
    src/crypto/bulletproofs.c
    src/crypto/balance_proof.c

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

    # Nodus
    src/nodus/client.c
    src/nodus/anchor.c
    src/nodus/discovery.c

    # Database
    src/db/db.c
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
if(EXISTS "${DNA_BUILD_DIR}/libdna_lib.so")
    target_link_libraries(dnac
        ${DNA_BUILD_DIR}/libdna_lib.so
    )
else()
    target_link_libraries(dnac
        ${DNA_BUILD_DIR}/libdna_lib.a
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

# secp256k1 if available
if(SECP256K1_FOUND)
    target_compile_definitions(dnac PRIVATE HAVE_SECP256K1_ZKP=1)
    target_link_libraries(dnac ${SECP256K1_LIBRARIES})
    target_include_directories(dnac PRIVATE ${SECP256K1_INCLUDE_DIRS})
endif()

# ============================================================================
# CLI Executable
# ============================================================================

option(DNAC_BUILD_CLI "Build dnac-cli executable" ON)

if(DNAC_BUILD_CLI)
    set(DNAC_CLI_SOURCES
        src/cli/main.c
        src/cli/commands.c
    )

    add_executable(dnac-cli ${DNAC_CLI_SOURCES})

    target_link_libraries(dnac-cli
        dnac
    )

    # Link libdna directly for dna_engine functions
    if(EXISTS "${DNA_BUILD_DIR}/libdna_lib.so")
        target_link_libraries(dnac-cli ${DNA_BUILD_DIR}/libdna_lib.so)
    else()
        target_link_libraries(dnac-cli ${DNA_BUILD_DIR}/libdna_lib.a)
    endif()

    target_link_libraries(dnac-cli
        OpenSSL::SSL
        OpenSSL::Crypto
        ${SQLITE3_LIBRARIES}
        pthread
        m
    )

    install(TARGETS dnac-cli RUNTIME DESTINATION bin)
endif()

# ============================================================================
# Anchor Server
# ============================================================================

option(DNAC_BUILD_ANCHOR_SERVER "Build dnac-anchor server" OFF)

if(DNAC_BUILD_ANCHOR_SERVER)
    set(DNAC_ANCHOR_SOURCES
        src/anchor-server/main.c
        src/anchor-server/server.c
        src/anchor-server/nullifier.c
        src/anchor-server/replication.c
    )

    add_executable(dnac-anchor ${DNAC_ANCHOR_SOURCES})

    target_include_directories(dnac-anchor PRIVATE
        ${CMAKE_SOURCE_DIR}/src/anchor-server
    )

    target_link_libraries(dnac-anchor
        dnac
    )

    # Link libdna directly for dna_engine functions
    if(EXISTS "${DNA_BUILD_DIR}/libdna_lib.so")
        target_link_libraries(dnac-anchor ${DNA_BUILD_DIR}/libdna_lib.so)
    else()
        target_link_libraries(dnac-anchor ${DNA_BUILD_DIR}/libdna_lib.a)
    endif()

    target_link_libraries(dnac-anchor
        OpenSSL::SSL
        OpenSSL::Crypto
        ${SQLITE3_LIBRARIES}
        pthread
        m
    )

    install(TARGETS dnac-anchor RUNTIME DESTINATION bin)
endif()

# ============================================================================
# Tests
# ============================================================================

if(DNAC_BUILD_TESTS)
    enable_testing()

    # Test executables
    set(DNAC_TESTS
        test_transaction
        test_wallet
    )

    foreach(TEST ${DNAC_TESTS})
        if(EXISTS "${CMAKE_SOURCE_DIR}/tests/${TEST}.c")
            add_executable(${TEST} tests/${TEST}.c)
            target_link_libraries(${TEST} dnac)
            add_test(NAME ${TEST} COMMAND ${TEST})
        endif()
    endforeach()
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
message(STATUS "  DNA Messenger:  ${DNA_MESSENGER_DIR}")
message(STATUS "  DNA Build:      ${DNA_BUILD_DIR}")
message(STATUS "  secp256k1:      ${SECP256K1_FOUND}")
message(STATUS "  CLI:            ${DNAC_BUILD_CLI}")
message(STATUS "  Tests:          ${DNAC_BUILD_TESTS}")
message(STATUS "")
