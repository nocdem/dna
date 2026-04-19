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
        ${SHARED_DIR}/crypto/utils/qgp_u128.c
        ${SHARED_DIR}/crypto/utils/qgp_fingerprint.c
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
    src/client/nodus_cc_client.c

    # Shared dnac wire format (Hard-Fork v1 — single source of truth for
    # the CHAIN_CONFIG TX extension block encoder/decoder shared with dnac)
    ${SHARED_DIR}/dnac/chain_config_wire.c

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
        src/witness/nodus_witness_spend_preimage.c
        src/witness/nodus_witness_validator.c
        src/witness/nodus_witness_delegation.c
        src/witness/nodus_witness_reward.c
        src/witness/nodus_witness_committee.c
        src/witness/nodus_witness_genesis_seed.c
        src/witness/nodus_witness_chain_config.c
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
    ${MONOREPO_ROOT}/dnac/include
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

# Shared fixture for storage tests (unique mkstemp path + WAL/SHM cleanup).
# Used as a source dep by every storage test below so the .o is rebuilt
# when the helper changes.
set(NODUS_TEST_STORAGE_HELPER tests/test_storage_helper.c)

# Storage test
add_executable(test_storage tests/test_storage.c ${NODUS_TEST_STORAGE_HELPER})
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

# Witness ↔ DNAC tx_hash parity test (F-CRYPTO-10 chain_id binding +
# per-type appended fields). Ensures nodus_witness_recompute_tx_hash
# matches dnac_tx_compute_hash() byte-for-byte for every TX type.
add_executable(test_witness_tx_hash_parity tests/test_witness_tx_hash_parity.c)
target_link_libraries(test_witness_tx_hash_parity nodus dsa nodus crypto)
add_test(NAME test_witness_tx_hash_parity COMMAND test_witness_tx_hash_parity)

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

# Merkle tree-tag domain separator constants (witness stake v1 / Phase 3 Task 8)
add_executable(test_merkle_tree_tags tests/test_merkle_tree_tags.c)
target_link_libraries(test_merkle_tree_tags nodus dsa nodus)
add_test(NAME test_merkle_tree_tags COMMAND test_merkle_tree_tags)

# Merkle leaf key / value hash / empty-root helpers (witness stake v1 / Phase 3 Task 9)
add_executable(test_merkle_leaf_helpers tests/test_merkle_leaf_helpers.c)
target_link_libraries(test_merkle_leaf_helpers nodus dsa nodus)
add_test(NAME test_merkle_leaf_helpers COMMAND test_merkle_leaf_helpers)

# 4-subtree composite state_root KAT (witness stake v1 / Phase 3 Task 10)
add_executable(test_state_root_4subtree tests/test_state_root_4subtree.c)
target_link_libraries(test_state_root_4subtree nodus dsa nodus)
add_test(NAME test_state_root_4subtree COMMAND test_state_root_4subtree)

# Hard-Fork v1 — witness-side chain_config lookup + merkle + 5-input combiner
add_executable(test_chain_config_witness tests/test_chain_config_witness.c)
target_link_libraries(test_chain_config_witness nodus dsa nodus)
add_test(NAME test_chain_config_witness COMMAND test_chain_config_witness)

# Hard-Fork v1 Stage C — vote primitives (digest + sign + verify + derive)
add_executable(test_chain_config_votes tests/test_chain_config_votes.c)
target_link_libraries(test_chain_config_votes nodus dsa nodus)
add_test(NAME test_chain_config_votes COMMAND test_chain_config_votes)

# Hard-Fork v1 Stage E — shared CHAIN_CONFIG TX extension wire format
add_executable(test_cc_wire ${SHARED_DIR}/dnac/tests/test_cc_wire.c)
target_link_libraries(test_cc_wire nodus)
add_test(NAME test_cc_wire COMMAND test_cc_wire)

# Hard-Fork v1 Stage E.2 — tier-3 client helper guard-path tests
add_executable(test_cc_client tests/test_cc_client.c)
target_link_libraries(test_cc_client nodus dsa nodus)
add_test(NAME test_cc_client COMMAND test_cc_client)

# UTXO state_root determinism tests (Phase 2 / Task 2.5)
add_executable(test_merkle_utxo_root tests/test_merkle_utxo_root.c)
target_link_libraries(test_merkle_utxo_root nodus dsa nodus)
add_test(NAME test_merkle_utxo_root COMMAND test_merkle_utxo_root)

# RFC 6962 Merkle proof round-trip tests (Phase 2 / Task 2.6)
add_executable(test_merkle_proof tests/test_merkle_proof.c)
target_link_libraries(test_merkle_proof nodus dsa nodus)
add_test(NAME test_merkle_proof COMMAND test_merkle_proof)

# RFC 6962 tx_root inclusion proof tests (anchored-merkle-proofs / Tasks 32-35)
add_executable(test_merkle_tx_proof tests/test_merkle_tx_proof.c)
target_link_libraries(test_merkle_tx_proof nodus dsa nodus)
add_test(NAME test_merkle_tx_proof COMMAND test_merkle_tx_proof)

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

# Phase 11 follow-up — block_txs_get DB query test
register_witness_test(test_block_txs_get)

# Phase 12 / Task 12.6 — spend_result preimage layout tests
add_executable(test_spend_preimage tests/test_spend_preimage.c)
target_link_libraries(test_spend_preimage nodus dsa nodus crypto)
add_test(NAME test_spend_preimage COMMAND test_spend_preimage)

# Phase 9 / Task 9.6 — strict top-level decoder tests
add_executable(test_strict_decoder tests/test_strict_decoder.c)
target_link_libraries(test_strict_decoder nodus dsa nodus crypto)
add_test(NAME test_strict_decoder COMMAND test_strict_decoder)

# Phase 12 follow-up — spend_result sign/verify roundtrip
add_executable(test_spend_signed_roundtrip tests/test_spend_signed_roundtrip.c)
target_link_libraries(test_spend_signed_roundtrip nodus dsa nodus crypto)
add_test(NAME test_spend_signed_roundtrip COMMAND test_spend_signed_roundtrip)

# BFT quorum formula tests (Phase 8)
add_executable(test_bft_quorum_formula tests/test_bft_quorum_formula.c)
target_link_libraries(test_bft_quorum_formula nodus dsa nodus)
add_test(NAME test_bft_quorum_formula COMMAND test_bft_quorum_formula)

# Witness Merkle state_root test
add_executable(test_witness_merkle tests/test_witness_merkle.c)
target_link_libraries(test_witness_merkle nodus dsa nodus)
add_test(NAME test_witness_merkle COMMAND test_witness_merkle)

# Task 11 — stake/delegation schema migration test
register_witness_test(test_stake_schema)

# Spend replay DB helper test (Fix #4 B)
add_executable(test_spend_replay tests/test_spend_replay.c)
target_link_libraries(test_spend_replay nodus dsa nodus)
add_test(NAME test_spend_replay COMMAND test_spend_replay)

# Replication phase tests
add_executable(test_put_if_newer tests/test_put_if_newer.c ${NODUS_TEST_STORAGE_HELPER})
target_link_libraries(test_put_if_newer nodus dsa nodus)
add_test(NAME test_put_if_newer COMMAND test_put_if_newer)

add_executable(test_routing_stale tests/test_routing_stale.c)
target_link_libraries(test_routing_stale nodus dsa nodus)
add_test(NAME test_routing_stale COMMAND test_routing_stale)

add_executable(test_bucket_refresh tests/test_bucket_refresh.c)
target_link_libraries(test_bucket_refresh nodus dsa nodus)
add_test(NAME test_bucket_refresh COMMAND test_bucket_refresh)

add_executable(test_hinted_handoff tests/test_hinted_handoff.c ${NODUS_TEST_STORAGE_HELPER})
target_link_libraries(test_hinted_handoff nodus dsa nodus)
add_test(NAME test_hinted_handoff COMMAND test_hinted_handoff)

add_executable(test_fetch_batch tests/test_fetch_batch.c ${NODUS_TEST_STORAGE_HELPER})
target_link_libraries(test_fetch_batch nodus dsa nodus)
add_test(NAME test_fetch_batch COMMAND test_fetch_batch)

# Channel rewrite protocol test
add_executable(test_channel_protocol tests/test_channel_protocol.c)
target_link_libraries(test_channel_protocol nodus dsa nodus)
add_test(NAME test_channel_protocol COMMAND test_channel_protocol)

add_executable(test_storage_cleanup tests/test_storage_cleanup.c ${NODUS_TEST_STORAGE_HELPER})
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

# Hard-Fork v1 Stage E.3 — chain-config propose verb depends on libdna for
# TX serialize/compute_hash (pure wire functions). Build messenger tree
# first to produce libdna.so, then this optional link enables the verb.
# When libdna.so is missing (e.g., first-ever clean build, or a nodus-only
# standalone bring-up), the verb is compiled out and nodus-cli stays
# functional for its DHT / witness commands.
#
# Tech debt: this direct link violates nodus's "pure C, no libdna" rule.
# See memory project_nodus_cli_libdna_decouple.md for the proper refactor
# (move serialize.c to shared/dnac/tx_wire.c) that retires the dependency.
find_library(DNA_SO dna PATHS
    ${MONOREPO_ROOT}/messenger/build
    ${MONOREPO_ROOT}/messenger/build-asan
    NO_DEFAULT_PATH)
if(DNA_SO)
    message(STATUS "nodus-cli: libdna.so found at ${DNA_SO} — chain-config propose enabled")
    target_link_libraries(nodus-cli ${DNA_SO})
    target_include_directories(nodus-cli PRIVATE
        ${MONOREPO_ROOT}/dnac/include
        ${MONOREPO_ROOT}/messenger/include)
    target_compile_definitions(nodus-cli PRIVATE NODUS_CLI_HAS_DNAC=1)
    # RPATH so `nodus-cli` finds libdna.so at runtime without LD_LIBRARY_PATH.
    get_filename_component(DNA_SO_DIR "${DNA_SO}" DIRECTORY)
    set_target_properties(nodus-cli PROPERTIES
        BUILD_RPATH   "${DNA_SO_DIR}"
        INSTALL_RPATH "${DNA_SO_DIR}")
else()
    message(STATUS "nodus-cli: libdna.so NOT found — chain-config propose disabled "
                    "(build messenger/build first to enable).")
endif()

add_executable(nodus-server tools/nodus-server.c)
target_link_libraries(nodus-server nodus dsa nodus)
target_compile_options(nodus-server PRIVATE -Wall -Wextra -Wno-unused-parameter)
if(JSONC_FOUND)
    target_compile_definitions(nodus-server PRIVATE NODUS_HAS_JSONC)
    target_include_directories(nodus-server PRIVATE ${JSONC_INCLUDE_DIRS})
    target_link_libraries(nodus-server ${JSONC_LIBRARIES})
endif()

# Task 12 — validator tree DB CRUD (witness stake v1 / Phase 4)
register_witness_test(test_validator_db)

# Task 13 — delegation + reward DB CRUD (witness stake v1 / Phase 4)
register_witness_test(test_delegation_db)
register_witness_test(test_reward_db)

# Task 61 — dnac_pending_rewards_query RPC helper (Phase 14)
register_witness_test(test_pending_rewards_rpc)

# Task 62 — dnac_committee_query RPC shape (Phase 14)
register_witness_test(test_committee_query_rpc)

# Task 63 — dnac_validator_list_query paged helper (Phase 14)
register_witness_test(test_validator_list_query_rpc)

# Task 29 — SPEND rejects locked UTXO inputs (Rule D)
register_witness_test(test_locked_utxo)

# Task 30 — MIN_TENURE (Rule R) committee eligibility boundary
register_witness_test(test_min_tenure_boundary)

# Task 31 — SPEND fees route to block_fee_pool (not burn UTXO)
register_witness_test(test_fee_routing)

# Task 40 — STAKE state mutation (validator insert + active_count bump)
register_witness_test(test_apply_stake)

# Task 41 — DELEGATE state mutation (delegation row + validator totals)
register_witness_test(test_apply_delegate)

# Task 42 — UNSTAKE phase 1 (RETIRING status transition)
register_witness_test(test_apply_unstake)

# Task 43 — UNDELEGATE state mutation (dual-UTXO auto-claim, always-emit)
register_witness_test(test_apply_undelegate)

# Task 44 — CLAIM_REWARD state mutation (validator + delegator paths)
register_witness_test(test_apply_claim_reward)

# Task 45 — VALIDATOR_UPDATE state mutation with pending semantics
register_witness_test(test_apply_validator_update)

# Task 46 — Epoch-boundary state transitions (commission activation +
# RETIRING->UNSTAKED graduation; AUTO_RETIRED + committee TODOs)
register_witness_test(test_apply_epoch_boundary)

# Task 47 — single-SQLite-transaction block commit + rollback on abort
register_witness_test(test_commit_atomicity)

# Task 48 — per-block attendance tracking + liveness-based AUTO_RETIRED
register_witness_test(test_liveness_attendance)

# Task 49 — accumulator update with liveness gate + residual dust
register_witness_test(test_accumulator_math)

# Task 50 — F-CONS-06 mandatory independent state_root recompute on PREVOTE
register_witness_test(test_prevote_state_root_mutation)

# Task 51 — committee election (post-commit lookback + state_seed tiebreak)
register_witness_test(test_committee_election)

# Task 53 — per-epoch committee cache
register_witness_test(test_committee_cache)

# Task 54 — UNDELEGATE auto-claim end-to-end integration
register_witness_test(test_integration_undelegate_claim)

# Task 55 — UNSTAKE two-phase graduation + locked-UTXO unlock
register_witness_test(test_integration_unstake_two_phase)

# Task 57 — Genesis seeds validator_tree + reward_tree from chain_def
register_witness_test(test_genesis_seed_validators)

# Task 59 — BFT roster sourced from committee snapshot (chain-authoritative)
register_witness_test(test_bft_roster_committee)

# Task 60 — RETIRING validator stays in epoch committee until graduation
register_witness_test(test_retiring_committee_membership)

# Task 81 — supply invariance property test (Phase 17).
# Pure-C simulated state machine — does NOT need the witness internal
# API, only DNAC public enum + constants. Linked without NODUS_WITNESS_INTERNAL_API.
add_executable(test_supply_invariant tests/test_supply_invariant.c)
target_link_libraries(test_supply_invariant nodus dsa nodus)
add_test(NAME test_supply_invariant COMMAND test_supply_invariant)
