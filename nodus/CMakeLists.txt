cmake_minimum_required(VERSION 3.16)
project(nodus VERSION 0.5.0 LANGUAGES C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

# ── Paths ────────────────────────────────────────────────────────────
# Nodus lives at /opt/dna/nodus/, shared crypto at /opt/dna/shared/
get_filename_component(NODUS_DIR "${CMAKE_CURRENT_LIST_DIR}" ABSOLUTE)
get_filename_component(MONOREPO_ROOT "${NODUS_DIR}/.." ABSOLUTE)
set(SHARED_DIR "${MONOREPO_ROOT}/shared")

# ── Dependencies ─────────────────────────────────────────────────────
# When built within the messenger tree (NODUS_STANDALONE=OFF), the parent
# CMakeLists.txt already found these packages. Only search when standalone.
if(NODUS_STANDALONE OR NOT DEFINED NODUS_STANDALONE)
    find_package(OpenSSL REQUIRED)
    find_package(SQLite3 REQUIRED)

    # json-c (for server config)
    find_package(PkgConfig QUIET)
    if(PKG_CONFIG_FOUND)
        pkg_check_modules(JSONC json-c)
    endif()
endif()

# ── Crypto sub-libraries (shared/) ───────────────────────────────────
# These are already built by the main messenger CMakeLists.txt.
# When built standalone, we add them ourselves.
if(NOT TARGET dsa)
    add_subdirectory(${SHARED_DIR}/crypto/dsa ${CMAKE_BINARY_DIR}/dsa)
endif()
if(NOT TARGET kem)
    add_subdirectory(${SHARED_DIR}/crypto/kem ${CMAKE_BINARY_DIR}/kem)
endif()

# ── Standalone mode ──────────────────────────────────────────────────
# When built within the messenger tree, shared crypto and the log shim
# are already provided by dht_lib. Set NODUS_STANDALONE=OFF to skip them.
option(NODUS_STANDALONE "Include shared crypto sources and log shim" ON)

# ── Shared crypto utility sources (standalone only) ──────────────────
set(SHARED_CRYPTO_SOURCES "")
if(NODUS_STANDALONE)
    list(APPEND SHARED_CRYPTO_SOURCES
        ${SHARED_DIR}/crypto/utils/qgp_sha3.c
        ${SHARED_DIR}/crypto/utils/qgp_dilithium.c
        ${SHARED_DIR}/crypto/utils/qgp_random.c
        # qgp_log.c depends on dna_config.h — use nodus_log_shim.c instead
    )

    # Platform-specific source
    if(WIN32)
        list(APPEND SHARED_CRYPTO_SOURCES ${SHARED_DIR}/crypto/utils/qgp_platform_windows.c)
    elseif(ANDROID)
        list(APPEND SHARED_CRYPTO_SOURCES ${SHARED_DIR}/crypto/utils/qgp_platform_android.c)
    else()
        list(APPEND SHARED_CRYPTO_SOURCES ${SHARED_DIR}/crypto/utils/qgp_platform_linux.c)
    endif()
endif()

# ── Nodus library sources ───────────────────────────────────────────
set(NODUS_SOURCES
    # Core
    src/core/nodus_value.c
    src/core/nodus_routing.c
    src/core/nodus_storage.c

    # Protocol
    src/protocol/nodus_cbor.c
    src/protocol/nodus_wire.c
    src/protocol/nodus_tier1.c
    src/protocol/nodus_tier2.c
    src/protocol/nodus_tier3.c

    # Transport (Linux: epoll)
    src/transport/nodus_tcp.c
    src/transport/nodus_udp.c

    # Crypto
    src/crypto/nodus_sign.c
    src/crypto/nodus_identity.c

    # Channel
    src/channel/nodus_hashring.c
    src/channel/nodus_channel_store.c
    src/channel/nodus_replication.c

    # Consensus
    src/consensus/nodus_pbft.c

    # Server
    src/server/nodus_server.c
    src/server/nodus_auth.c

    # Witness (DNAC BFT consensus module)
    src/witness/nodus_witness.c
    src/witness/nodus_witness_db.c
    src/witness/nodus_witness_bft.c
    src/witness/nodus_witness_verify.c
    src/witness/nodus_witness_peer.c
    src/witness/nodus_witness_handlers.c

    # Client SDK
    src/client/nodus_client.c
    src/client/nodus_singleton.c
    src/client/nodus_republish.c

    # Shared crypto (standalone only — messenger tree provides these via dht_lib)
    ${SHARED_CRYPTO_SOURCES}
)

# Log shim — only needed standalone (messenger tree has the real qgp_log.c)
if(NODUS_STANDALONE)
    list(APPEND NODUS_SOURCES src/nodus_log_shim.c)
endif()

add_library(nodus_lib STATIC ${NODUS_SOURCES})

target_include_directories(nodus_lib PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${CMAKE_CURRENT_SOURCE_DIR}/src
    ${SHARED_DIR}
    ${SHARED_DIR}/crypto
    ${OPENSSL_INCLUDE_DIR}
    ${SQLite3_INCLUDE_DIRS}
)

target_link_libraries(nodus_lib PUBLIC
    dsa
    OpenSSL::Crypto
    ${SQLite3_LIBRARIES}
)

# Security flags
target_compile_options(nodus_lib PRIVATE
    -Wall -Wextra -Werror
    -Wno-unused-parameter
    -Wno-format-truncation
    -fstack-protector-strong
    -D_FORTIFY_SOURCE=2
)

# ── Tests & Tools (standalone only) ──────────────────────────────────
# When built within the messenger tree, tests/tools use the standalone
# build in /opt/dna/nodus/build instead.
if(NOT NODUS_STANDALONE)
    return()
endif()

enable_testing()

# CBOR test
add_executable(test_cbor tests/test_cbor.c)
target_link_libraries(test_cbor nodus_lib)
add_test(NAME test_cbor COMMAND test_cbor)

# Wire frame test
add_executable(test_wire tests/test_wire.c)
target_link_libraries(test_wire nodus_lib)
add_test(NAME test_wire COMMAND test_wire)

# Value test (needs extra nodus_lib for circular dep: dsa -> qgp_randombytes -> nodus_lib)
add_executable(test_value tests/test_value.c)
target_link_libraries(test_value nodus_lib dsa nodus_lib)
add_test(NAME test_value COMMAND test_value)

# Identity test
add_executable(test_identity tests/test_identity.c)
target_link_libraries(test_identity nodus_lib dsa nodus_lib)
add_test(NAME test_identity COMMAND test_identity)

# Routing table test
add_executable(test_routing tests/test_routing.c)
target_link_libraries(test_routing nodus_lib dsa nodus_lib)
add_test(NAME test_routing COMMAND test_routing)

# Storage test
add_executable(test_storage tests/test_storage.c)
target_link_libraries(test_storage nodus_lib dsa nodus_lib)
add_test(NAME test_storage COMMAND test_storage)

# Hash ring test
add_executable(test_hashring tests/test_hashring.c)
target_link_libraries(test_hashring nodus_lib dsa nodus_lib)
add_test(NAME test_hashring COMMAND test_hashring)

# TCP transport test
add_executable(test_tcp tests/test_tcp.c)
target_link_libraries(test_tcp nodus_lib dsa nodus_lib)
add_test(NAME test_tcp COMMAND test_tcp)

# Tier 1 protocol test
add_executable(test_tier1 tests/test_tier1.c)
target_link_libraries(test_tier1 nodus_lib dsa nodus_lib)
add_test(NAME test_tier1 COMMAND test_tier1)

# Tier 2 protocol test
add_executable(test_tier2 tests/test_tier2.c)
target_link_libraries(test_tier2 nodus_lib dsa nodus_lib)
add_test(NAME test_tier2 COMMAND test_tier2)

# Tier 3 protocol test (BFT CBOR)
add_executable(test_tier3 tests/test_tier3.c)
target_link_libraries(test_tier3 nodus_lib dsa nodus_lib)
add_test(NAME test_tier3 COMMAND test_tier3)

# Channel storage test
add_executable(test_channel_store tests/test_channel_store.c)
target_link_libraries(test_channel_store nodus_lib dsa nodus_lib)
add_test(NAME test_channel_store COMMAND test_channel_store)

# Server integration test
add_executable(test_server tests/test_server.c)
target_link_libraries(test_server nodus_lib dsa nodus_lib pthread)
add_test(NAME test_server COMMAND test_server)

# Client SDK test
add_executable(test_client tests/test_client.c)
target_link_libraries(test_client nodus_lib dsa nodus_lib pthread)
add_test(NAME test_client COMMAND test_client)

# Witness transaction verification test
add_executable(test_witness_verify tests/test_witness_verify.c)
target_link_libraries(test_witness_verify nodus_lib dsa nodus_lib)
add_test(NAME test_witness_verify COMMAND test_witness_verify)

# ── Tools ────────────────────────────────────────────────────────────
add_executable(nodus-cli tools/nodus-cli.c)
target_link_libraries(nodus-cli nodus_lib dsa nodus_lib)
target_compile_options(nodus-cli PRIVATE -Wall -Wextra -Wno-unused-parameter)

add_executable(nodus-server tools/nodus-server.c)
target_link_libraries(nodus-server nodus_lib dsa nodus_lib)
target_compile_options(nodus-server PRIVATE -Wall -Wextra -Wno-unused-parameter)
if(JSONC_FOUND)
    target_compile_definitions(nodus-server PRIVATE NODUS_HAS_JSONC)
    target_include_directories(nodus-server PRIVATE ${JSONC_INCLUDE_DIRS})
    target_link_libraries(nodus-server ${JSONC_LIBRARIES})
endif()
