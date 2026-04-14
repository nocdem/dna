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
    add_subdirectory(${SHARED_DIR}/crypto/sign/dsa ${CMAKE_BINARY_DIR}/dsa)
endif()
if(NOT TARGET kem)
    add_subdirectory(${SHARED_DIR}/crypto/enc/kem ${CMAKE_BINARY_DIR}/kem)
endif()

# ── Standalone mode ──────────────────────────────────────────────────
# When built within the messenger tree, shared crypto and the log shim
# are already provided by dht_lib. Set NODUS_STANDALONE=OFF to skip them.
option(NODUS_STANDALONE "Include shared crypto sources and log shim" ON)

# ── ML-KEM-1024 (Kyber) ────────────────────────────────────────────
if(NOT TARGET kem)
    add_subdirectory(${SHARED_DIR}/crypto/enc/kem ${CMAKE_BINARY_DIR}/crypto/kem)
endif()

# ── Shared crypto utility sources (standalone only) ──────────────────
set(SHARED_CRYPTO_SOURCES "")
if(NODUS_STANDALONE)
    list(APPEND SHARED_CRYPTO_SOURCES
        ${SHARED_DIR}/crypto/hash/qgp_sha3.c
        ${SHARED_DIR}/crypto/hash/hkdf_sha3.c
        ${SHARED_DIR}/crypto/enc/qgp_aes.c
        ${SHARED_DIR}/crypto/enc/qgp_kyber.c
        ${SHARED_DIR}/crypto/enc/kyber_deterministic.c
        ${SHARED_DIR}/crypto/sign/qgp_dilithium.c
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
# Client SDK + protocol + crypto: all platforms (TCP is cross-platform)
set(NODUS_SOURCES
    # Core
    src/core/nodus_value.c
    src/core/nodus_routing.c
    src/core/nodus_storage.c
    src/core/nodus_media_storage.c

    # Circuit (VPN mesh)
    src/circuit/nodus_circuit.c
    src/circuit/nodus_inter_circuit.c

    # Protocol
    src/protocol/nodus_cbor.c
    src/protocol/nodus_wire.c
    src/protocol/nodus_tier1.c
    src/protocol/nodus_tier2.c
    src/protocol/nodus_tier3.c

    # Transport — TCP is cross-platform (epoll on Linux, select on Windows)
    src/transport/nodus_tcp.c

    # Crypto
    src/crypto/nodus_sign.c
    src/crypto/nodus_identity.c
    src/crypto/nodus_channel_crypto.c

    # Client SDK
    src/client/nodus_client.c
    src/client/nodus_singleton.c
    src/client/nodus_republish.c

    # Shared crypto (standalone only — messenger tree provides these via dht_lib)
    ${SHARED_CRYPTO_SOURCES}
)

# Server-only sources: Linux only (UDP uses epoll, server/witness are Linux-only)
if(NOT WIN32)
    list(APPEND NODUS_SOURCES
        src/transport/nodus_udp.c
        src/channel/nodus_hashring.c
        src/channel/nodus_channel_store.c
        src/channel/nodus_channel_server.c
        src/channel/nodus_channel_primary.c
        src/channel/nodus_channel_replication.c
        src/channel/nodus_channel_ring.c
        src/consensus/nodus_cluster.c
        src/server/nodus_server.c
        src/server/nodus_media_handler.c
        src/server/nodus_auth.c
        src/server/nodus_presence.c
        src/witness/nodus_witness.c
        src/witness/nodus_witness_db.c
        src/witness/nodus_witness_bft.c
        src/witness/nodus_witness_merkle.c
        src/witness/nodus_witness_verify.c
        src/witness/nodus_witness_peer.c
        src/witness/nodus_witness_handlers.c
        src/witness/nodus_witness_sync.c
        src/witness/nodus_witness_mempool.c
        src/witness/nodus_witness_cert.c
    )
endif()

# Log shim — only needed standalone (messenger tree has the real qgp_log.c)
if(NODUS_STANDALONE)
    list(APPEND NODUS_SOURCES src/nodus_log_shim.c)
endif()

add_library(nodus STATIC ${NODUS_SOURCES})

# Channel system disabled — heap corruption in ring/replication causes SIGABRT
target_compile_definitions(nodus PUBLIC NODUS_CHANNELS_DISABLED)

target_include_directories(nodus PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${CMAKE_CURRENT_SOURCE_DIR}/src
    ${SHARED_DIR}
    ${SHARED_DIR}/crypto
)
# OpenSSL and SQLite3 include dirs — needed regardless of standalone mode.
# When standalone, find_package above sets these. When within messenger tree,
# the parent CMakeLists.txt already called find_package and vars propagate.
if(OPENSSL_INCLUDE_DIR)
    target_include_directories(nodus PUBLIC ${OPENSSL_INCLUDE_DIR})
endif()
if(SQLite3_INCLUDE_DIRS)
    target_include_directories(nodus PUBLIC ${SQLite3_INCLUDE_DIRS})
endif()

if(NODUS_STANDALONE OR NOT DEFINED NODUS_STANDALONE)
    target_link_libraries(nodus PUBLIC
        dsa
        kem
        OpenSSL::Crypto
        ${SQLite3_LIBRARIES}
    )
else()
    # Within messenger tree — messenger handles linking OpenSSL and SQLite3
    target_link_libraries(nodus PUBLIC dsa)
endif()

# Security flags
if(CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
    target_compile_options(nodus PRIVATE
        -Wall -Wextra -Werror
        -Wno-unused-parameter
        -Wno-unused-but-set-variable
        -fstack-protector-strong
        -D_FORTIFY_SOURCE=2
    )
    # -Wno-format-truncation is GCC-only (Clang doesn't recognize it)
    if(CMAKE_C_COMPILER_ID STREQUAL "GNU")
        target_compile_options(nodus PRIVATE -Wno-format-truncation)
    endif()
endif()

# ── Tests & Tools (standalone only) ──────────────────────────────────
# When built within the messenger tree, tests/tools use the standalone
# build in /opt/dna/nodus/build instead.
if(NOT NODUS_STANDALONE)
    return()
endif()

enable_testing()

# ── Multi-TX block refactor: register_witness_test macro ─────────────
# Convenience helper for tests created by Phases 1-15 that need access
# to internal witness primitives via NODUS_WITNESS_INTERNAL_API. Existing
# tests continue using the explicit add_executable/add_test pattern below.
#
# Usage:
#     register_witness_test(test_apply_tx_to_state)
#
# The macro:
#   - Compiles tests/${name}.c and links against nodus + dsa
#   - Defines NODUS_WITNESS_INTERNAL_API so internal headers are visible
#   - Registers the test with ctest
#
# Guarded against accidental Release builds: NODUS_WITNESS_INTERNAL_API
# would otherwise compile internal headers into the production library
# if a Release CI job ran the test target by mistake. Mirrors the
# NODUS_WITNESS_TEST_HOOKS guard from Task 4.4.
if(CMAKE_BUILD_TYPE STREQUAL "Release" AND NODUS_WITNESS_INTERNAL_API)
    message(FATAL_ERROR
        "NODUS_WITNESS_INTERNAL_API must not be set in Release builds — "
        "internal headers would leak into the production binary")
endif()

# Test hook guard (Phase 4 / Task 4.4): NODUS_WITNESS_TEST_HOOKS lets
# tests bypass production checks (e.g. propose_batch's layer-2 chained
# UTXO defense). The flag must never be set in a Release build because
# the bypass would be compiled into the shipped library.
if(CMAKE_BUILD_TYPE STREQUAL "Release" AND NODUS_WITNESS_TEST_HOOKS)
    message(FATAL_ERROR
        "NODUS_WITNESS_TEST_HOOKS must not be set in Release builds — "
        "production checks would be bypassable in the shipped binary")
endif()

function(register_witness_test name)
    add_executable(${name} tests/${name}.c)
    target_link_libraries(${name} nodus dsa nodus)
    target_compile_definitions(${name} PRIVATE NODUS_WITNESS_INTERNAL_API)
    add_test(NAME ${name} COMMAND ${name})
endfunction()

# CBOR test
add_executable(test_cbor tests/test_cbor.c)
target_link_libraries(test_cbor nodus)
add_test(NAME test_cbor COMMAND test_cbor)

# Wire frame test
add_executable(test_wire tests/test_wire.c)
target_link_libraries(test_wire nodus)
add_test(NAME test_wire COMMAND test_wire)

# Value test (needs extra nodus for circular dep: dsa -> qgp_randombytes -> nodus)
add_executable(test_value tests/test_value.c)
target_link_libraries(test_value nodus dsa nodus)
add_test(NAME test_value COMMAND test_value)

# Identity test
add_executable(test_identity tests/test_identity.c)
target_link_libraries(test_identity nodus dsa nodus)
add_test(NAME test_identity COMMAND test_identity)

# Routing table test
add_executable(test_routing tests/test_routing.c)
target_link_libraries(test_routing nodus dsa nodus)
add_test(NAME test_routing COMMAND test_routing)

# Storage test
add_executable(test_storage tests/test_storage.c)
target_link_libraries(test_storage nodus dsa nodus)
add_test(NAME test_storage COMMAND test_storage)

# Media storage test
add_executable(test_media_storage tests/test_media_storage.c)
target_link_libraries(test_media_storage nodus dsa nodus)
add_test(NAME test_media_storage COMMAND test_media_storage)

# Hash ring test
add_executable(test_hashring tests/test_hashring.c)
target_link_libraries(test_hashring nodus dsa nodus)
add_test(NAME test_hashring COMMAND test_hashring)

# TCP transport test
add_executable(test_tcp tests/test_tcp.c)
target_link_libraries(test_tcp nodus dsa nodus)
add_test(NAME test_tcp COMMAND test_tcp)

# Phase 3: Pending queue / backpressure test
add_executable(test_pending_queue tests/test_pending_queue.c)
target_link_libraries(test_pending_queue nodus dsa nodus)
add_test(NAME test_pending_queue COMMAND test_pending_queue)

# Inter-node auth state machine test
add_executable(test_inter_auth tests/test_inter_auth.c)
target_link_libraries(test_inter_auth nodus dsa nodus)
add_test(NAME test_inter_auth COMMAND test_inter_auth)

# Tier 1 protocol test
add_executable(test_tier1 tests/test_tier1.c)
target_link_libraries(test_tier1 nodus dsa nodus)
add_test(NAME test_tier1 COMMAND test_tier1)

# Tier 2 protocol test
add_executable(test_tier2 tests/test_tier2.c)
target_link_libraries(test_tier2 nodus dsa nodus)
add_test(NAME test_tier2 COMMAND test_tier2)

# Circuit wire protocol test (VPN mesh Faz 1)
add_executable(test_circuit_wire tests/test_circuit_wire.c)
target_link_libraries(test_circuit_wire nodus dsa nodus)
add_test(NAME test_circuit_wire COMMAND test_circuit_wire)

add_executable(test_circuit_ri_wire tests/test_circuit_ri_wire.c)
target_link_libraries(test_circuit_ri_wire nodus dsa nodus)
add_test(NAME test_circuit_ri_wire COMMAND test_circuit_ri_wire)

add_executable(test_circuit_table tests/test_circuit_table.c)
target_link_libraries(test_circuit_table nodus dsa nodus)
add_test(NAME test_circuit_table COMMAND test_circuit_table)

# Circuit live integration test (same-nodus bridge, VPN mesh Faz 1)
add_executable(test_circuit_live tests/test_circuit_live.c)
target_link_libraries(test_circuit_live nodus dsa nodus)
add_test(NAME test_circuit_live COMMAND test_circuit_live)

# Cross-nodus circuit live integration test (VPN mesh Faz 1)
add_executable(test_circuit_cross_live tests/test_circuit_cross_live.c)
target_link_libraries(test_circuit_cross_live nodus dsa nodus pthread)
add_test(NAME test_circuit_cross_live COMMAND test_circuit_cross_live)

# Media Tier 2 protocol test
add_executable(test_media_tier2 tests/test_media_tier2.c)
target_link_libraries(test_media_tier2 nodus dsa nodus)
add_test(NAME test_media_tier2 COMMAND test_media_tier2)

# Batch forward live tests (not in ctest — requires running server)
add_executable(test_batch_forward_live tests/test_batch_forward_live.c)
target_link_libraries(test_batch_forward_live nodus dsa nodus)

add_executable(test_batch_real_data tests/test_batch_real_data.c)
target_link_libraries(test_batch_real_data nodus dsa nodus)

# Tier 3 protocol test (BFT CBOR)
add_executable(test_tier3 tests/test_tier3.c)
target_link_libraries(test_tier3 nodus dsa nodus)
add_test(NAME test_tier3 COMMAND test_tier3)

# Channel storage test
add_executable(test_channel_store tests/test_channel_store.c)
target_link_libraries(test_channel_store nodus dsa nodus)
add_test(NAME test_channel_store COMMAND test_channel_store)

# Server integration test
add_executable(test_server tests/test_server.c)
target_link_libraries(test_server nodus dsa nodus pthread)
add_test(NAME test_server COMMAND test_server)

# Client SDK test
add_executable(test_client tests/test_client.c)
target_link_libraries(test_client nodus dsa nodus pthread)
add_test(NAME test_client COMMAND test_client)

# Presence table + protocol test
add_executable(test_presence tests/test_presence.c)
target_link_libraries(test_presence nodus dsa nodus)
add_test(NAME test_presence COMMAND test_presence)

# Witness transaction verification test
add_executable(test_witness_verify tests/test_witness_verify.c)
target_link_libraries(test_witness_verify nodus dsa nodus)
add_test(NAME test_witness_verify COMMAND test_witness_verify)

# Witness chain DB archive test (Fix 1 — orphan DB prevention)
add_executable(test_witness_chain_archive tests/test_witness_chain_archive.c)
target_link_libraries(test_witness_chain_archive nodus dsa nodus)
add_test(NAME test_witness_chain_archive COMMAND test_witness_chain_archive)

# Witness DB savepoint wrapper test (Phase 0 / Task 0.15)
add_executable(test_db_savepoint tests/test_db_savepoint.c)
target_link_libraries(test_db_savepoint nodus dsa nodus)
add_test(NAME test_db_savepoint COMMAND test_db_savepoint)

# Tier 2 cluster-status wire round-trip test (Phase 0 / Task 0.2)
add_executable(test_t2_status_wire tests/test_t2_status_wire.c)
target_link_libraries(test_t2_status_wire nodus dsa nodus)
add_test(NAME test_t2_status_wire COMMAND test_t2_status_wire)

# Witness DB schema v12 migration test (Phase 1 / Task 1.1)
add_executable(test_schema_migration tests/test_schema_migration.c)
target_link_libraries(test_schema_migration nodus dsa nodus)
add_test(NAME test_schema_migration COMMAND test_schema_migration)

# RFC 6962 Merkle domain tag tests (Phase 2 / Tasks 2.1, 2.2, 2.4)
add_executable(test_merkle_domain_tags tests/test_merkle_domain_tags.c)
target_link_libraries(test_merkle_domain_tags nodus dsa nodus crypto)
add_test(NAME test_merkle_domain_tags COMMAND test_merkle_domain_tags)

# UTXO state_root determinism tests (Phase 2 / Task 2.5)
add_executable(test_merkle_utxo_root tests/test_merkle_utxo_root.c)
target_link_libraries(test_merkle_utxo_root nodus dsa nodus)
add_test(NAME test_merkle_utxo_root COMMAND test_merkle_utxo_root)

# RFC 6962 Merkle proof round-trip tests (Phase 2 / Task 2.6)
add_executable(test_merkle_proof tests/test_merkle_proof.c)
target_link_libraries(test_merkle_proof nodus dsa nodus)
add_test(NAME test_merkle_proof COMMAND test_merkle_proof)

# apply_tx_to_state + finalize_block isolation tests (Phase 3 / Task 3.6)
register_witness_test(test_apply_finalize)

# Intra-batch chained UTXO defense tests (Phase 4 / Task 4.5)
register_witness_test(test_chained_utxo)

# compute_block_hash helper tests (Phase 5 / Task 5.4)
add_executable(test_compute_block_hash tests/test_compute_block_hash.c)
target_link_libraries(test_compute_block_hash nodus dsa nodus crypto)
add_test(NAME test_compute_block_hash COMMAND test_compute_block_hash)

# Phase 6 commit wrapper tests (Phase 6 / Task 6.4)
register_witness_test(test_commit_wrappers)

# Phase 7 / Task 7.1 — bft_start_round_from_entries guard tests
register_witness_test(test_bft_start_round_from_entries)

# Phase 7 / Task 7.2 — bft_start_round_from_mempool guard tests
register_witness_test(test_bft_start_round_from_mempool)

# Phase 7.5 / Task 7.5.1 — witness cert preimage layout tests
add_executable(test_witness_cert_preimage tests/test_witness_cert_preimage.c)
target_link_libraries(test_witness_cert_preimage nodus dsa nodus crypto)
add_test(NAME test_witness_cert_preimage COMMAND test_witness_cert_preimage)

# Phase 7.5 / Task 7.5.5 — sync cert sign/verify tamper tests
add_executable(test_witness_cert_verify tests/test_witness_cert_verify.c)
target_link_libraries(test_witness_cert_verify nodus dsa nodus crypto)
add_test(NAME test_witness_cert_verify COMMAND test_witness_cert_verify)

# Phase 11 / Task 11.6 — multi-tx sync_rsp wire guard tests
add_executable(test_sync_rsp_guards tests/test_sync_rsp_guards.c)
target_link_libraries(test_sync_rsp_guards nodus dsa nodus crypto)
add_test(NAME test_sync_rsp_guards COMMAND test_sync_rsp_guards)

# BFT quorum formula tests (Phase 8)
add_executable(test_bft_quorum_formula tests/test_bft_quorum_formula.c)
target_link_libraries(test_bft_quorum_formula nodus dsa nodus)
add_test(NAME test_bft_quorum_formula COMMAND test_bft_quorum_formula)

# Witness Merkle state_root test
add_executable(test_witness_merkle tests/test_witness_merkle.c)
target_link_libraries(test_witness_merkle nodus dsa nodus)
add_test(NAME test_witness_merkle COMMAND test_witness_merkle)

# Replication phase tests
add_executable(test_put_if_newer tests/test_put_if_newer.c)
target_link_libraries(test_put_if_newer nodus dsa nodus)
add_test(NAME test_put_if_newer COMMAND test_put_if_newer)

add_executable(test_routing_stale tests/test_routing_stale.c)
target_link_libraries(test_routing_stale nodus dsa nodus)
add_test(NAME test_routing_stale COMMAND test_routing_stale)

add_executable(test_bucket_refresh tests/test_bucket_refresh.c)
target_link_libraries(test_bucket_refresh nodus dsa nodus)
add_test(NAME test_bucket_refresh COMMAND test_bucket_refresh)

add_executable(test_hinted_handoff tests/test_hinted_handoff.c)
target_link_libraries(test_hinted_handoff nodus dsa nodus)
add_test(NAME test_hinted_handoff COMMAND test_hinted_handoff)

add_executable(test_fetch_batch tests/test_fetch_batch.c)
target_link_libraries(test_fetch_batch nodus dsa nodus)
add_test(NAME test_fetch_batch COMMAND test_fetch_batch)

# Channel rewrite protocol test
add_executable(test_channel_protocol tests/test_channel_protocol.c)
target_link_libraries(test_channel_protocol nodus dsa nodus)
add_test(NAME test_channel_protocol COMMAND test_channel_protocol)

add_executable(test_storage_cleanup tests/test_storage_cleanup.c)
target_link_libraries(test_storage_cleanup nodus dsa nodus)
add_test(NAME test_storage_cleanup COMMAND test_storage_cleanup)

# Channel server session management test
add_executable(test_channel_server tests/test_channel_server.c)
target_link_libraries(test_channel_server nodus dsa nodus)
add_test(NAME test_channel_server COMMAND test_channel_server)

# Channel primary role test
add_executable(test_channel_primary tests/test_channel_primary.c)
target_link_libraries(test_channel_primary nodus dsa nodus)
add_test(NAME test_channel_primary COMMAND test_channel_primary)

# Channel replication test
add_executable(test_channel_replication tests/test_channel_replication.c)
target_link_libraries(test_channel_replication nodus dsa nodus)
add_test(NAME test_channel_replication COMMAND test_channel_replication)

# Channel ring management test
add_executable(test_channel_ring tests/test_channel_ring.c)
target_link_libraries(test_channel_ring nodus dsa nodus)
add_test(NAME test_channel_ring COMMAND test_channel_ring)

# Encrypted channel test
add_executable(test_channel_encrypted tests/test_channel_encrypted.c)
target_link_libraries(test_channel_encrypted nodus dsa nodus)
add_test(NAME test_channel_encrypted COMMAND test_channel_encrypted)

add_executable(test_channel_crypto tests/test_channel_crypto.c)
target_link_libraries(test_channel_crypto nodus dsa kem nodus)
add_test(NAME test_channel_crypto COMMAND test_channel_crypto)

# ── Tools ────────────────────────────────────────────────────────────
add_executable(nodus-cli tools/nodus-cli.c)
target_link_libraries(nodus-cli nodus dsa nodus)
target_compile_options(nodus-cli PRIVATE -Wall -Wextra -Wno-unused-parameter)

add_executable(nodus-server tools/nodus-server.c)
target_link_libraries(nodus-server nodus dsa nodus)
target_compile_options(nodus-server PRIVATE -Wall -Wextra -Wno-unused-parameter)
if(JSONC_FOUND)
    target_compile_definitions(nodus-server PRIVATE NODUS_HAS_JSONC)
    target_include_directories(nodus-server PRIVATE ${JSONC_INCLUDE_DIRS})
    target_link_libraries(nodus-server ${JSONC_LIBRARIES})
endif()
