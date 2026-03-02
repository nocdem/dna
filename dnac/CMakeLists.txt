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
set(DNA_MESSENGER_DIR "${CMAKE_SOURCE_DIR}/../messenger" CACHE PATH "Path to DNA Messenger source")
set(DNA_BUILD_DIR "${DNA_MESSENGER_DIR}/build" CACHE PATH "Path to DNA Messenger build")

# Check if libdna exists
if(NOT EXISTS "${DNA_BUILD_DIR}/libdna_lib.a" AND NOT EXISTS "${DNA_BUILD_DIR}/libdna_lib.so")
    message(FATAL_ERROR "libdna not found at ${DNA_BUILD_DIR}. Build DNA Messenger first.")
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

    # Nodus
    src/nodus/client.c
    src/nodus/attestation.c
    src/nodus/discovery.c
    src/nodus/tcp_client.c

    # Database
    src/db/db.c

    # BFT (serialization, roster, replay detection)
    src/bft/serialize.c
    src/bft/roster.c
    src/bft/replay.c
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
# Tests
# ============================================================================

if(DNAC_BUILD_TESTS)
    enable_testing()

    # Real end-to-end test (uses real genesis, real witnesses, real DHT)
    add_executable(test_real tests/test_real.c)

    target_link_libraries(test_real dnac)

    # Link libdna directly for dna_engine functions
    if(EXISTS "${DNA_BUILD_DIR}/libdna_lib.so")
        target_link_libraries(test_real ${DNA_BUILD_DIR}/libdna_lib.so)
    else()
        target_link_libraries(test_real ${DNA_BUILD_DIR}/libdna_lib.a)
    endif()

    target_link_libraries(test_real
        OpenSSL::SSL
        OpenSSL::Crypto
        ${SQLITE3_LIBRARIES}
        pthread
        m
    )

    add_test(NAME real COMMAND test_real)

    # Remote send test (sends to different machine)
    add_executable(test_remote tests/test_remote.c)

    target_link_libraries(test_remote dnac)

    # Link libdna directly for dna_engine functions
    if(EXISTS "${DNA_BUILD_DIR}/libdna_lib.so")
        target_link_libraries(test_remote ${DNA_BUILD_DIR}/libdna_lib.so)
    else()
        target_link_libraries(test_remote ${DNA_BUILD_DIR}/libdna_lib.a)
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
    if(EXISTS "${DNA_BUILD_DIR}/libdna_lib.so")
        target_link_libraries(test_gaps ${DNA_BUILD_DIR}/libdna_lib.so)
    else()
        target_link_libraries(test_gaps ${DNA_BUILD_DIR}/libdna_lib.a)
    endif()

    target_link_libraries(test_gaps
        OpenSSL::SSL
        OpenSSL::Crypto
        ${SQLITE3_LIBRARIES}
        pthread
        m
    )

    add_test(NAME gaps COMMAND test_gaps)
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
message(STATUS "  CLI:            ${DNAC_BUILD_CLI}")
message(STATUS "  Tests:          ${DNAC_BUILD_TESTS}")
message(STATUS "")
