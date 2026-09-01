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

# ── QGP bench instrumentation (perf harness, 2026-04-24) ───────────
# When ON, hot paths record per-op timing into atomic counters via
# QGP_BENCH_START/END macros. Default OFF: macros expand to ((void)0)
# and no instrumentation runs. See:
#   shared/crypto/utils/qgp_bench.h
#   nodus/docs/plans/2026-04-24-perf-harness-design.md
option(QGP_BENCH "Enable perf bench instrumentation" OFF)

# O15J Faz 3 — the NODUS_V2_ACTIVATION option (which defined the compile
# macro NODUS_V2_ACTIVATION_AUTHORITY, producing a "rehearsal" binary with
# type-15/16 admission, the boundary state machine, terminal refusal,
# state_root v4 and the successor-derivation seam) is REMOVED with the
# activation ceremony itself. There is no second build variant of this
# tree any more: a Ledger V2 chain is born V2, so there is nothing to
# activate and nothing to gate at compile time.
if(QGP_BENCH)
    add_compile_definitions(QGP_BENCH)
endif()

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
        ${SHARED_DIR}/crypto/utils/qgp_bench.c
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

    # Ledger V2 S1 — shared TX codec: ExecutionContext + Wire V3 (inactive
    # until the V2 devnet reset) + the ONE legacy tx-hash implementation
    # (dnac_txw_legacy_tx_hash) both libdna and the witness call.
    ${SHARED_DIR}/dnac/tx_wire.c

    # Ledger V2 K1 — INACTIVE generic transaction ENVELOPE codec + the four
    # commitment helpers (call_commit / auth_context_commit / auth_digest /
    # tx_id). A separate wire family from V3; nothing calls it yet.
    ${SHARED_DIR}/dnac/env_wire.c

    # Ledger V2 — INACTIVE generic TYPED-EFFECT RESULT codec: the canonical,
    # bounded representation of the state mutations one leg proposes
    # (CREATE/SET/DELETE over opaque keys/values namespaced by a compiled
    # adapter op id). Carries no domain id and no commitment; nothing calls
    # it yet.
    ${SHARED_DIR}/dnac/effect_wire.c

    # Ledger V2 — INACTIVE deterministic envelope PREFLIGHT: the frozen
    # order in which the four commitments above are derived, plus the
    # expiry and contextual-ruleset gates. Adds no preimage of its own and
    # holds no state; the DERIVED tx_id is the only transaction identity
    # it knows.
    ${SHARED_DIR}/dnac/env_preflight.c

    # Ledger V2 — INACTIVE deterministic resource METERING + RESERVATION:
    # checked u64 arithmetic, the sealed engine-supplied policy snapshot,
    # the pure reservation-plan calculation, and the per-transaction meter
    # lifecycle over global + per-domain block budgets. Prices come from
    # the policy only — no caller-supplied cost value exists. No live
    # consensus caller.
    ${SHARED_DIR}/dnac/res_meter.c

    # Ledger V2 S2 — INACTIVE tagged root hierarchy + BlockHeader V2 codec
    # (shared canonical hashing) and the witness-side V2 root loaders
    # (tests/harness only; no consensus path calls them).
    ${SHARED_DIR}/dnac/ledger_roots_v2.c
    ${SHARED_DIR}/dnac/block_v2.c
    src/witness/nodus_witness_roots_v2.c

    # Ledger V2 S4 — INACTIVE compiled NATIVE_BUILTIN runtime table
    # (exact-tuple lookup, fail-closed; SYSTEM + DNA_CORE only) + the
    # domain registry (persistence, staged activation scheduler,
    # readiness accounting, registry root).
    src/witness/nodus_witness_runtime.c
    src/witness/nodus_witness_rt_native.c
    src/witness/nodus_witness_domreg.c

    # Ledger V2 S5 — INACTIVE versioned schema/migration + atomic
    # global-block apply engine + V2 supply gate.
    src/witness/nodus_witness_v2_schema.c
    src/witness/nodus_witness_v2_apply.c

    # Ledger V2 O12 S2 — INACTIVE engine-mandatory epoch-boundary
    # transition (pending-commission activation, RETIRING -> UNSTAKED
    # graduation with its canonical per-record release identity, then
    # the S3 boundary flips + next-epoch snapshot). Mirrors the legacy
    # apply_epoch_boundary_transitions; the legacy lane is untouched and
    # remains the only boundary a running chain executes.
    src/witness/nodus_witness_v2_epoch.c

    # Ledger V2 O15J Faz 2 — V1's economics on the V2 lane: the per-block
    # inflation mint (engine phase 6f) and the epoch settlement that
    # drains each epoch's pool into CORE payout UTXOs and burn (boundary
    # step 2b). Without these a pure-V2 chain mints nothing and — both
    # lanes already burning every fee — pays validators exactly zero
    # (the O15J red-team's L2-F5). The spec is the shipped V1
    # implementation, cited line by line in the source.
    src/witness/nodus_witness_v2_econ.c
    src/witness/nodus_witness_v2_qc.c
    src/witness/nodus_witness_v2_preflight.c
    src/witness/nodus_witness_v2_finalize.c
    # Ledger V2 O15B — the ONE production activation gate, the ingress
    # adapter it guards, and bounded sync.
    #
    # O15J Faz 3: these are NO LONGER production-dormant. The gate's
    # authority is now the chain's OWN committed genesis manifest, so on a
    # pure-V2 database a DEFAULT build can and should open it, arm ingress
    # and dispatch V2 frames — that is the whole point of a chain born V2.
    # On any other database the gate reports NO_AUTHORITY and nothing is
    # dispatched. See nodus_witness_v2_gate.h.
    #
    # Still true and still load-bearing: NODUS_V2_TEST_AUTHORITY — the
    # test-only fixture that can grant SYNTHETIC authority — is
    # deliberately NOT defined on this target; see test_v2_gate_linked,
    # which proves with `nm` that the fixture symbols are absent from
    # libnodus and nodus-server.
    src/witness/nodus_witness_v2_gate.c
    src/witness/nodus_witness_v2_ingress.c
    src/witness/nodus_witness_v2_sync2.c

    # Ledger V2 — successor-chain block production, the genesis bundle
    # codec that carries a chain's committed base tables, and the joiner
    # that re-derives a V2 database from that bundle against a local pin.
    #
    # O15J Faz 3 removed the activation ceremony that used to head this
    # block (the shared record/schedule/readiness codec, the witness-side
    # activation record and root, the type-15/16 apply lanes, the boundary
    # state machine, terminal refusal and the successor-derivation seam).
    # These three survive because none of them was ever about the V1→V2
    # transition — they serve any Ledger V2 chain, however it was born.
    src/witness/nodus_witness_v2_produce.c
    src/witness/nodus_witness_v2_bundle.c
    src/witness/nodus_witness_v2_join.c

    # Ledger V2 O15J Faz 1 — the PURE-V2 genesis builder: a complete
    # Ledger V2 chain derived from a local operator config, with no legacy
    # ancestor. Depends on NO activation symbol, which is why it survived
    # the removal of the ceremony — and is now the ONLY way a V2 chain
    # comes into being.
    src/witness/nodus_witness_v2_gen.c

    # Ledger V2 S6 — INACTIVE generic genesis/distribution manifest +
    # claim codec (shared) and the witness-side manifest/claims module
    # (real manifest_root/claims_root legs, distribution accounting,
    # claim pipeline). No consensus caller.
    ${SHARED_DIR}/dnac/manifest_wire.c
    src/witness/nodus_witness_v2_claims.c

    # Ledger V2 — INACTIVE witness-side envelope preflight SEAM: candidate
    # envelope bytes + the DERIVED chain id (never the legacy 16-byte one)
    # + the contextual ruleset table -> derived transaction identities.
    # Read-only; the apply engine still takes caller-supplied tx_ids (the
    # six later switch sites are enumerated in the header).
    src/witness/nodus_witness_v2_env.c

    # Ledger V2 — INACTIVE typed-effect / compiled STORAGE-ADAPTER
    # boundary: op resolution, adapter self-check, the one precondition
    # decision table and the validate/apply walks. No consensus caller;
    # the production runtime table registers no adapter.
    src/witness/nodus_witness_v2_adapter.c

    # Ledger V2 S7 — INACTIVE shielded-pool state: canonical pool
    # commitments (shared codec) and the witness-side pool module
    # (D=24 frontier persistence, finalized-root history + anchors,
    # nullifier set, pool balance, real per-domain pools_root, the
    # CORE runtime's pool policy). No consensus caller; Type 11 stays
    # REJECT. The D=24 tree primitive itself (shielded_tree.c +
    # note_commit.c) joins the zk block below (Poseidon2 dependency).
    ${SHARED_DIR}/dnac/pool_wire.c
    src/witness/nodus_witness_v2_pools.c

    # Ledger V2 S3 — INACTIVE validator-set snapshot codec + QC V2
    # (certificate codec and historical verification). No consensus path
    # calls either; the live 144-byte cert path (nodus_witness_cert.c)
    # is untouched. Same ownership pattern as ledger_roots_v2.c.
    ${SHARED_DIR}/dnac/vset_wire.c
    ${SHARED_DIR}/dnac/qc_v2.c

    # Ledger V2 O15B — canonical BlockMessage v1 wire codec. Structure and
    # bounds ONLY: it computes no consensus value and touches no committed
    # state, so it can never become a second engine. Production-dormant with
    # the rest of the V2 network surface (nodus_witness_v2_gate.c).
    ${SHARED_DIR}/dnac/blockmsg_v2.c

    # Ledger V2 S4 — INACTIVE domain manifest / registry / readiness codec
    # (canonical encodings + tagged hashes). No consensus path calls it;
    # same ownership pattern as ledger_roots_v2.c.
    ${SHARED_DIR}/dnac/domain_wire.c

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
        # O15C-D.1 — env-driven fault-injection predicate installer.
        # Entire TU is #ifdef QGP_FAULT_INJECT; compiles to nothing in
        # every normal build (and CMake rejects that flag for Release).
        src/witness/nodus_witness_fault.c
        src/witness/nodus_witness_o15h_diag.c   # O15H TEMPORARY — see header
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
        src/witness/nodus_witness_epoch.c
        src/witness/nodus_witness_emission.c
        src/witness/nodus_witness_committee.c
        # Ledger V2 S3 — validator-set snapshot persistence + builder
        # (INACTIVE). Placed here, not in the common list, because it
        # calls nodus_committee_compute_for_epoch directly.
        src/witness/nodus_witness_vset.c
        src/witness/nodus_witness_genesis_seed.c
        src/witness/nodus_witness_chain_config.c
        src/witness/nodus_witness_bootstrap.c
    )

    # ── Phase-C C1 (2026-07-21): shielded-pool ZK verify stack ─────────
    # Everything the consensus verify entry links: the DZKF wire codec, the
    # FRI verifier, the Poseidon2 DuplexChallenger transcript + Poseidon2
    # MMCS, and the Goldilocks field. LINKAGE ONLY — no consensus behavior
    # change; the witness starts CALLING it at C3 (S6 roadmap).
    #
    # M5 gate (restated at d4.d, 2026-07-26 — the previous wording described a
    # world that no longer exists): the two unpinned/params-trusting v3 entries
    # dnac_fri_verify_wire and dnac_fri_verify_wire_shielded are no longer
    # "compiled out here" — they are DELETED FROM THE TREE, so no build of any
    # kind can define them. What DNAC_ZK_ENABLE_TEST_WIRE still gates (and this
    # build still does NOT define) are the KAT-only prover exports in
    # stark_prover_agg.c / batch_prover.c, none of which is in NODUS_SOURCES
    # anyway. The ONLY verify entry reachable from libnodus is the pinned
    # dnac_shielded_verify_statement in the C2.1 block below, and the ONLY wire
    # fri_proof_codec.c still speaks is DZKF v4 — the v3 decoder went with the
    # rest of the v3 surface, so no version-3 buffer can be parsed at all.
    #
    # Prover-side sources (stark_prover*.c, zk_entropy.c) are deliberately
    # NOT here — proving is client-side (wallet, S7) and zk_entropy.c is
    # Linux-only; the verify stack below is portable C.
    # P1c (2026-07-22): proof-internal hash cutover SHA3→Poseidon2 — the
    # transcript is the DuplexChallenger (duplex_challenger.c over
    # poseidon2_goldilocks.c, appended in the C2.1 block below) and the MMCS
    # is poseidon2_mmcs.c; merkle_smt/sponge_sha3_512/keccak_p3 are RETIRED
    # from the proof path (keccak_ref stays: conf_txbind consumer).
    list(APPEND NODUS_SOURCES
        ${SHARED_DIR}/crypto/zk/fri_proof_codec.c
        ${SHARED_DIR}/crypto/zk/shielded_fri_params.c
        ${SHARED_DIR}/crypto/zk/fri_verifier.c
        ${SHARED_DIR}/crypto/zk/fri_fold.c
        ${SHARED_DIR}/crypto/zk/poseidon2_mmcs.c
        ${SHARED_DIR}/crypto/zk/duplex_challenger.c
        ${SHARED_DIR}/crypto/zk/zk_field_helpers.c
        ${SHARED_DIR}/crypto/zk/field_goldilocks.c
        ${SHARED_DIR}/crypto/zk/transcript.c
        ${SHARED_DIR}/crypto/zk/keccak_ref.c
    )
    # ── Phase-C C2.1 (2026-07-22): consensus shielded-statement verify ──
    # dnac_shielded_verify_statement (shielded_verify.c) = wire-recomputed
    # publics + fresh-primed transcript (SAMPLED zeta, H2/H3 closed) + pinned
    # FRI verify AND the N-chunk AIR constraint check (CRIT-1 — FRI alone is
    # soundness-vacuous). Pulls: priming, constraint glue, the aggregate fold
    # AIR (constraint-EVAL only, no prover), and the tx_binding map chain.
    # dnac_tx_shielded_sighash stays in dnac/src/transaction/serialize.c —
    # consumers (test_zk_link now, the witness at C2.2) compile it alongside,
    # exactly the nodus-cli DNAC_TX_WIRE_SOURCES precedent (single source,
    # design v2 G-DET-2). Still NOT called by consensus: witness admission
    # REJECTS type-11 unconditionally through all of C2 (accept-flip = C3).
    # d4.c-3 (2026-07-26): shielded_verify.c re-based onto the DZKF v4 BATCHED
    # wire + dnac_batch_verify (verify_batch mirror) — the v3 single-instance
    # uni-stark path retired. dnac_batch_wire_decode lives in fri_proof_codec.c
    # (already in the C1 block); dnac_batch_verify + its batched priming + the
    # LogUp gadget/bus (vacuous here — the agg AIR has no lookups) are pulled in
    # below. Consensus-inert (type-11 still REJECT-unconditional through C2).
    # d4.d (2026-07-26): stark_priming.c DROPPED from this list — the v3
    # uni-stark priming module is deleted; nothing in the nodus source set ever
    # called it (the batched path primes inside batch_priming.c).
    # ── Ledger V2 S9 Gate 2 W3 (2026-08-06): the NATIVE stateless V3
    # verifier. native_verify_v3.c sits ABOVE shielded_verify.c — it decodes a
    # whole Transaction Wire V3 transaction (header ‖ optional transparent leg ‖
    # shielded section), applies the per-type count/boundary rules the
    # policy-neutral shared codec deliberately does not own, recomputes the
    # transparent-leg commitment + sighash_v5 + tx_binding, runs the type-12
    # signature check through a CALLER-SUPPLIED verifier (so this library links
    # no signature source of its own) and exports the deferred S10 state
    # expectations. It needs nothing beyond what shielded_verify.c already
    # pulls: shared/dnac/tx_wire.c is in NODUS_SOURCES above and dnac/include is
    # on the target's include path.
    #
    # CONSENSUS-INERT, and structurally so: NOTHING calls
    # dnac_v3_native_verify_stateless from any admission, mempool, BFT or apply
    # path — the six independent stops that keep types 11/12/13 unadmittable are
    # enumerated with file:line in native_verify_v3.h. Compiling it here is the
    # same linkage-without-consumption seam that already carries
    # dnac_shielded_verify_statement (C2.1 above): a missing source shows up as
    # a LINK error in the gate below, not as a surprise at activation.
    list(APPEND NODUS_SOURCES
        ${SHARED_DIR}/crypto/zk/native_verify_v3.c
        ${SHARED_DIR}/crypto/zk/shielded_verify.c
        ${SHARED_DIR}/crypto/zk/batch_verify.c
        ${SHARED_DIR}/crypto/zk/batch_priming.c
        ${SHARED_DIR}/crypto/zk/logup_bus.c
        ${SHARED_DIR}/crypto/zk/logup.c
        ${SHARED_DIR}/crypto/zk/stark_constraints.c
        ${SHARED_DIR}/crypto/zk/conf_action_agg_fold.c
        ${SHARED_DIR}/crypto/zk/conf_action_fold.c
        ${SHARED_DIR}/crypto/zk/poseidon2_fold.c
        ${SHARED_DIR}/crypto/zk/conf_txbind.c
        ${SHARED_DIR}/crypto/zk/conf_root_air.c
        ${SHARED_DIR}/crypto/zk/conf_commit_air.c
        ${SHARED_DIR}/crypto/zk/conf_balance_air.c
        ${SHARED_DIR}/crypto/zk/poseidon2_air.c
        ${SHARED_DIR}/crypto/zk/poseidon2_air_trace.c
        ${SHARED_DIR}/crypto/zk/poseidon2_air_cols.c
        ${SHARED_DIR}/crypto/zk/poseidon2_goldilocks.c
        # Ledger V2 S7: the consensus-side D=24 note-commitment tree
        # (F1b/F1c) + its Poseidon2 sponge/compress — the authoritative
        # pool tree primitive nodus_witness_v2_pools.c appends through.
        ${SHARED_DIR}/crypto/zk/note_commit.c
        ${SHARED_DIR}/crypto/zk/shielded_tree.c
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
# Phase-C C1: zk headers use flat same-dir includes ("fri_verifier.h") — keep
# the dir PRIVATE so generic names (transcript.h, ...) cannot shadow anything
# for nodus consumers; witness sources include them explicitly at C2.
if(NOT WIN32)
    target_include_directories(nodus PRIVATE ${SHARED_DIR}/crypto/zk)
endif()
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

# Faz 5.4 fault injection (M5). QGP_FAULT_INJECT enables the
# nodus_witness_test_inject_drop predicate hook in dispatch_t3.
# Same Release guard as the other test hooks above — a Release
# binary with this flag would let a runtime caller silently drop
# any T3 message via a stale predicate pointer.
option(QGP_FAULT_INJECT "Enable T3 drop-predicate hook (test builds only)" OFF)
if(CMAKE_BUILD_TYPE STREQUAL "Release" AND QGP_FAULT_INJECT)
    message(FATAL_ERROR
        "QGP_FAULT_INJECT must not be set in Release builds — "
        "the drop predicate hook would be live in the shipped binary")
endif()
if(QGP_FAULT_INJECT)
    add_compile_definitions(QGP_FAULT_INJECT)
endif()

# O15H — TEMPORARY diagnostic instrumentation (nodus_witness_o15h_diag.*).
# Default OFF, so a build without this flag is byte-identical in behaviour
# to a tree with the instrumentation deleted. Same Release guard as the
# hooks above: a Release binary has no business writing a per-node
# diagnostic trace. REVERT: delete this block, the source entry, the two
# o15h_diag files and every O15H_DIAG(...) call site.
option(O15H_DIAG "O15H temporary view-change causal tracing (test only)" OFF)
if(CMAKE_BUILD_TYPE STREQUAL "Release" AND O15H_DIAG)
    message(FATAL_ERROR
        "O15H_DIAG must not be set in Release builds — it is temporary "
        "diagnostic instrumentation, not a product feature")
endif()
if(O15H_DIAG)
    # The gate macro is deliberately NOT named O15H_DIAG: that name is the
    # call macro in nodus_witness_o15h_diag.h, and defining both collides.
    add_compile_definitions(O15H_DIAG_ENABLED)
endif()

function(register_witness_test name)
    add_executable(${name} tests/${name}.c)
    target_link_libraries(${name} nodus dsa nodus)
    target_compile_definitions(${name} PRIVATE NODUS_WITNESS_INTERNAL_API)
    add_test(NAME ${name} COMMAND ${name})
endfunction()

# O15J — engine-level tests that drive SYNTHETIC envelopes creating value
# from nothing (env_core_utxo_create). They cover the apply engine's
# effect plumbing, not economics, and no genesis seeding can balance
# conjured value: that is precisely what the CORE conservation equation
# forbids. Before L2-F1 they passed only because an ABSENT
# supply_tracking row skipped the equation outright — the same hole that
# let a production chain run unchecked for its whole life, now a hard
# refusal.
#
# NODUS_V2_TEST_SUPPLY is defined HERE AND NOWHERE ELSE among the targets
# this project ships. The claims TU is compiled INTO each of these test
# binaries with the macro rather than into libnodus; libnodus is STATIC,
# so the linker resolves those symbols from this object and never
# extracts the archive member — one definition, no duplicates, and the
# bypass exists in no shipped artefact. Same arrangement and same
# reasoning as the NODUS_V2_TEST_AUTHORITY gate fixture below.
#
# The absence is NOT argued from this comment: test_v2_supply_linked
# proves it with `nm` against libnodus and nodus-server, so a future edit
# that leaks the macro onto a library target fails a test.
function(register_witness_test_supply_bypass name)
    add_executable(${name} tests/${name}.c
                   src/witness/nodus_witness_v2_claims.c)
    target_link_libraries(${name} nodus dsa nodus crypto)
    target_compile_definitions(${name} PRIVATE
                               NODUS_WITNESS_INTERNAL_API
                               NODUS_V2_TEST_SUPPLY=1)
    add_test(NAME ${name} COMMAND ${name})
endfunction()

# CBOR test
add_executable(test_cbor tests/test_cbor.c)
target_link_libraries(test_cbor nodus)
add_test(NAME test_cbor COMMAND test_cbor)

# Phase-C C1 — shielded ZK verify stack linkage gate (pulls the whole
# consensus verify chain out of libnodus.a; a missing zk source in
# NODUS_SOURCES is a LINK error here, not a C2/C3 surprise).
# C2.1: the chain is rooted at dnac_shielded_verify_statement + the linked
# libdna sighash (serialize.c compiled alongside, nodus-cli precedent).
# d4.d: the test's three v3 cases were re-anchored onto that same entry when
# dnac_fri_verify_wire_shielded was deleted, so the gate now exercises the
# DZKF v4 decode + dnac_batch_verify chain it is meant to protect.
add_executable(test_zk_link tests/test_zk_link.c
    ${MONOREPO_ROOT}/dnac/src/transaction/serialize.c
    ${MONOREPO_ROOT}/dnac/src/ledger/chain_def_codec.c
    ${MONOREPO_ROOT}/shared/dnac/chain_config_wire.c)
target_link_libraries(test_zk_link nodus dsa nodus)
target_include_directories(test_zk_link PRIVATE ${SHARED_DIR}/crypto/zk)
add_test(NAME test_zk_link COMMAND test_zk_link)

# Ledger V2 S9 W3 — the NATIVE stateless V3 verifier gate.
# The test source lives beside the module it exercises
# (shared/crypto/zk/tests/), the same place the standalone zk suite runs it
# from, so ONE test file serves both builds and the two cannot drift.
# It links only `nodus`: shared/dnac/tx_wire.c (the V3 codec + sighash_v5 + the
# transparent-leg commitment) and native_verify_v3.c are both in NODUS_SOURCES,
# and the type-12 signature verifier is a caller-supplied function pointer the
# test fills with its own deterministic stub — so no dnac source and no
# signature source is compiled alongside. `dsa` is repeated after `nodus` for
# the same circular dependency the neighbouring gates carry.
add_executable(test_native_verify_v3
    ${SHARED_DIR}/crypto/zk/tests/test_native_verify_v3.c)
target_link_libraries(test_native_verify_v3 nodus dsa nodus)
target_include_directories(test_native_verify_v3 PRIVATE ${SHARED_DIR}/crypto/zk)
add_test(NAME test_native_verify_v3 COMMAND test_native_verify_v3)

# C2 domain separation test (needs extra nodus for dsa -> qgp_randombytes -> nodus circular dep)
add_executable(test_sign_domain_separation tests/test_sign_domain_separation.c)
target_link_libraries(test_sign_domain_separation nodus dsa nodus)
add_test(NAME test_sign_domain_separation COMMAND test_sign_domain_separation)

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

# Circuit latency probe — PQ-VoIP Faz 0 netem characterization (manual, NOT a
# ctest: run inside a netns with netem via tests/run_circuit_netem.sh).
add_executable(circuit_latency_probe tests/circuit_latency_probe.c)
target_link_libraries(circuit_latency_probe nodus dsa nodus pthread)

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

# Tier 3 oversize sync_rsp wsig verify regression
# (Regression for the 2026-05-03 production halt: receiver verify cap
#  < sender sync_rsp cap, see nodus_t3_verify in nodus_tier3.c.)
# O15N Faz 2C1 — the VIEW_OK wire (verbs 26/27). Codec level only:
# nothing sends or handles them yet. Pins the round-trip at N=1 and at
# the ceiling, BOTH method tables in BOTH directions, the decoder's hard
# reject of an oversized entry array, and that both sides of the
# bootstrap-domain predicate are live.
add_executable(test_viewok_wire tests/test_viewok_wire.c)
target_link_libraries(test_viewok_wire nodus dsa nodus)
add_test(NAME test_viewok_wire COMMAND test_viewok_wire)

add_executable(test_tier3_oversize tests/test_tier3_oversize.c)
target_link_libraries(test_tier3_oversize nodus dsa nodus)
add_test(NAME test_tier3_oversize COMMAND test_tier3_oversize)

# PR 3 Yol B — witness auto-bootstrap wire format regression.
# Covers w_chain_q / w_chain_r / w_genesis_req / w_genesis_rsp roundtrip,
# nonce echo invariant, and 64 KB chain_def_blob cap. RED until A3 lands.
add_executable(test_t3_bootstrap_wire tests/test_t3_bootstrap_wire.c)
target_link_libraries(test_t3_bootstrap_wire nodus dsa nodus)
add_test(NAME test_t3_bootstrap_wire COMMAND test_t3_bootstrap_wire)

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

# O15C-D — request/result correlation: a response never reaches the
# wrong request, and a reply to an abandoned request is not captured.
# This is what makes the late "unknown txn" warning an attribution gap
# rather than a delivery defect.
add_executable(test_client_request_correlation
    tests/test_client_request_correlation.c)
target_link_libraries(test_client_request_correlation nodus dsa nodus pthread)
add_test(NAME test_client_request_correlation
         COMMAND test_client_request_correlation)

# 2026-07-21 parallel-safety: every server-spawning test now uses a FULLY
# explicit, test-unique port set (test_server 140xx, test_circuit_live
# 150xx, test_client 151xx, test_server_init_fail_closes 152xx,
# test_circuit_cross_live 16xxx/17xxx) — an unset peer/witness port made
# nodus_server_init bind the production defaults 4002/4004, which collided
# under `ctest -j`. No shared ports remain, so no RESOURCE_LOCK is needed.

# Regression: nodus_server_init partial-failure must release everything it
# acquired (fd-leak fix; a leaked LISTEN socket held ports hostage).
add_executable(test_server_init_fail_closes tests/test_server_init_fail_closes.c)
target_link_libraries(test_server_init_fail_closes nodus dsa nodus)
add_test(NAME test_server_init_fail_closes COMMAND test_server_init_fail_closes)

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

# Ledger V2 S1 — legacy tx-hash KAT: links the REAL client implementation
# (dnac transaction.c/serialize.c, nodus-cli precedent) alongside the witness
# recompute and the shared codec; pins fixed hash literals captured from the
# pre-S1 struct-walk algorithm.
# NOTE: sources listed explicitly — the DNAC_TX_WIRE_SOURCES variable is
# set() further down this file (nodus-cli section) and would expand EMPTY
# here (CMake evaluates top-to-bottom).
add_executable(test_tx_hash_kat tests/test_tx_hash_kat.c
    ${MONOREPO_ROOT}/dnac/src/transaction/transaction.c
    ${MONOREPO_ROOT}/dnac/src/transaction/serialize.c
    ${MONOREPO_ROOT}/dnac/src/ledger/chain_def_codec.c)
target_link_libraries(test_tx_hash_kat nodus dsa nodus crypto)
add_test(NAME test_tx_hash_kat COMMAND test_tx_hash_kat)

# Ledger V2 S1 — Wire V3 + ExecutionContext codec tests (byte-literal KATs,
# mutation sweep, truncation/trailing/version negatives).
add_executable(test_tx_wire_v3 tests/test_tx_wire_v3.c)
target_link_libraries(test_tx_wire_v3 nodus dsa nodus)
add_test(NAME test_tx_wire_v3 COMMAND test_tx_wire_v3)

# Ledger V2 S1 — per-chain parameter boundary: chain_def-committed supply
# drives genesis Rule P.2 and the chain identity (genesis block hash).
add_executable(test_chain_params tests/test_chain_params.c
    ${MONOREPO_ROOT}/dnac/src/transaction/block.c
    ${MONOREPO_ROOT}/dnac/src/ledger/chain_def_codec.c)
target_link_libraries(test_chain_params nodus dsa nodus crypto)
add_test(NAME test_chain_params COMMAND test_chain_params)

# Ledger V2 S2 — inactive tagged root hierarchy: oracle-pinned KATs,
# witness loaders over real sqlite state, 7/7 determinism.
add_executable(test_roots_v2 tests/test_roots_v2.c)
target_link_libraries(test_roots_v2 nodus dsa nodus crypto)
add_test(NAME test_roots_v2 COMMAND test_roots_v2)

# Ledger V2 S2 — BlockHeader V2 codec: oracle-pinned KATs, mutation sweep,
# strict negatives, deterministic fuzz.
add_executable(test_block_v2 tests/test_block_v2.c)
target_link_libraries(test_block_v2 nodus dsa nodus crypto)
add_test(NAME test_block_v2 COMMAND test_block_v2)

# Ledger V2 S3 — validator-set snapshot codec: oracle-pinned KATs,
# round-trip byte identity, bounds/duplicate/ruleset/seed negatives.
add_executable(test_vset_wire tests/test_vset_wire.c)
target_link_libraries(test_vset_wire nodus dsa nodus crypto)
add_test(NAME test_vset_wire COMMAND test_vset_wire)

# Ledger V2 S3 — QC V2: preimage KAT, quorum table, and a REAL-KEY
# adversarial suite (non-member, duplicate, unsorted, wrong-context,
# key-rotation) plus an informational N=30 verify benchmark.
add_executable(test_qc_v2 tests/test_qc_v2.c)
target_link_libraries(test_qc_v2 nodus dsa nodus crypto)
add_test(NAME test_qc_v2 COMMAND test_qc_v2)

# Ledger V2 O15A — obligation 1: an allocation failure in or beneath the
# QC path is a NODE FAULT, never a consensus verdict. malloc/calloc are
# interposed at LINK time (--wrap) so the code under test is the
# PRODUCTION code, unmodified: no test-only allocation hook is compiled
# into the shipped library. The interposer is armed around the exact call
# under test and fails the Nth allocation inside that window, and the
# sweep covers every site the path actually reaches. Each fault assertion
# is paired with its converse (malformed bytes must still be a VERDICT) so
# the suite cannot pass by turning everything into a fault.
add_executable(test_v2_qc_alloc_fault tests/test_v2_qc_alloc_fault.c)
target_link_libraries(test_v2_qc_alloc_fault nodus dsa nodus crypto)
target_link_options(test_v2_qc_alloc_fault PRIVATE
                    -Wl,--wrap=malloc -Wl,--wrap=calloc)
add_test(NAME test_v2_qc_alloc_fault COMMAND test_v2_qc_alloc_fault)

# Ledger V2 O15A — obligation 5: the state validated for migration must be
# the state migrated. Uses a SECOND sqlite3 connection to the same file
# (not a second handle) to write at the migration seam, because the v8->v9
# migration DROPs and rebuilds v2_blocks and its safety rests entirely on
# the table being empty. O14 rated this LOW on the grounds that no second
# writer exists today — a deployment property, not a code property — so
# the invariant is tested directly instead of assumed.
add_executable(test_v2_migration_toctou tests/test_v2_migration_toctou.c)
target_link_libraries(test_v2_migration_toctou nodus dsa nodus crypto)
add_test(NAME test_v2_migration_toctou COMMAND test_v2_migration_toctou)

# Ledger V2 O15B — the activation gate, ingress reachability and the
# network result algebra.
#
# NODUS_V2_TEST_AUTHORITY is defined ONLY on test targets that deliberately
# compile the gate TU in — today this one and test_v2_sync_claims (:1237) —
# and on NO library or server target. It compiles in the test-only fixture
# that can grant synthetic activation authority, which is the only way the
# ARMED ingress/sync paths can be exercised without deriving a real chain.
#
# O15J Faz 3 corrected the older wording here, which claimed "HERE AND
# NOWHERE ELSE": test_v2_sync_claims has carried the macro alongside this
# target, so the sentence was false where it mattered most. What is true —
# and what test_v2_gate_linked actually proves — is the absence from every
# SHIPPED artefact, which is the claim the gate exists to defend.
#
# The symbol's ABSENCE from libnodus and nodus-server is not argued from
# this line; test_v2_gate_linked proves it with `nm` against the linked
# binaries, so a future edit that leaks the macro onto a library target
# fails a test rather than passing review.
#
# The gate TU is compiled INTO THIS TEST BINARY, with the macro, rather than
# into libnodus. That is what makes the absence proof airtight instead of
# merely configured: the fixture's DEFINITION exists nowhere else, so no
# combination of link flags can pull it into a shipped artefact. libnodus is
# STATIC, so the linker resolves the gate symbols from this object and never
# extracts the archive member — one definition, no duplicates.
#
# The first attempt defined the macro only for the test's own translation
# unit, which compiled but did not link: the declaration was visible and the
# definition was (correctly) absent from libnodus. That failure is the same
# fact this arrangement now relies on.
add_executable(test_v2_gate
               tests/test_v2_gate.c
               src/witness/nodus_witness_v2_gate.c)
target_compile_definitions(test_v2_gate PRIVATE NODUS_V2_TEST_AUTHORITY=1)
target_link_libraries(test_v2_gate nodus dsa nodus crypto)
add_test(NAME test_v2_gate COMMAND test_v2_gate)

# Ledger V2 O15B — canonical BlockMessage v1 codec: round trips, byte-exact
# offsets, truncation at every boundary, trailing bytes, non-canonical
# forms, over-cap fields and overflowed lengths.
add_executable(test_blockmsg_v2 tests/test_blockmsg_v2.c)
target_link_libraries(test_blockmsg_v2 nodus dsa nodus crypto)
add_test(NAME test_blockmsg_v2 COMMAND test_blockmsg_v2)

# O15B §8 — the transport must never kill its host process on a peer
# disconnect, and must never count a partial write as complete.
#
# This test deliberately leaves SIGPIPE at its DEFAULT disposition: with a
# handler installed it would pass even with the MSG_NOSIGNAL fix reverted,
# which is exactly the wrong test. If the transport ever raises SIGPIPE
# again, this dies by signal rather than printing a failure.
add_executable(test_tcp_sigpipe tests/test_tcp_sigpipe.c)
target_link_libraries(test_tcp_sigpipe nodus dsa nodus crypto)
add_test(NAME test_tcp_sigpipe COMMAND test_tcp_sigpipe)

# Ledger V2 O15B — LINK GATE. A source-level test cannot prove what is in a
# shipped binary: this test binary compiles the fixture in on purpose, so
# its own symbol table says nothing about production. This gate inspects
# the LINKED libnodus and nodus-server with `nm` and asserts the test-only
# authority fixture is absent from both, and that the gate itself IS
# present (so the check cannot pass by looking at the wrong file).
add_test(NAME test_v2_gate_linked
         COMMAND ${CMAKE_COMMAND}
                 -DNODUS_LIB=$<TARGET_FILE:nodus>
                 -DNODUS_SERVER=$<TARGET_FILE:nodus-server>
                 -DGATE_PURE=$<TARGET_FILE:test_v2_gate_pure>
                 -P ${CMAKE_CURRENT_SOURCE_DIR}/tests/v2_gate_linked.cmake)

# Ledger V2 O15J — the same absence proof for the test-only CONSERVATION
# bypass. Red-team L2-F1 (CRITICAL) found that an absent supply_tracking
# row SKIPPED the CORE supply equation for the life of the chain; that is
# now a hard refusal, and the two engine-level tests that relied on it
# use an explicit bypass instead. The whole point is that the replacement
# cannot exist in a shipped artefact where the original could — which
# only `nm` against the LINKED binaries can show, since those two test
# binaries compile the bypass in on purpose.
add_test(NAME test_v2_supply_linked
         COMMAND ${CMAKE_COMMAND}
                 -DNODUS_LIB=$<TARGET_FILE:nodus>
                 -DNODUS_SERVER=$<TARGET_FILE:nodus-server>
                 -P ${CMAKE_CURRENT_SOURCE_DIR}/tests/v2_supply_linked.cmake)

# Ledger V2 O15A — obligation 6: the RESTART path runs the same post-open
# integrity gate as creation. It previously ran neither check, so a
# database that would have been refused at creation was accepted on every
# subsequent boot — and restarts vastly outnumber creations. Also pins the
# two companion defects in the same scanner: the filename chain-id parse
# now fails closed, and selection follows a stable total order over names
# rather than readdir order (first-match-wins once activated the wrong
# chain in production — see witness_archive_stale_chain_dbs).
#
# O15L Faz 5 — NODUS_WITNESS_INTERNAL_API is added so this executable can
# see nodus_witness_bft_internal.h, which now carries the canonical
# prototypes for the two chain-identity gates this test drives
# (verify_chain_id, witness_chain_quorum_observe). NOT migrated to the
# register_witness_test macro: that macro links `nodus dsa nodus` and
# this target additionally needs `crypto`, so the migration would drop a
# library. One define is the whole delta.
add_executable(test_v2_restart_gate tests/test_v2_restart_gate.c)
target_link_libraries(test_v2_restart_gate nodus dsa nodus crypto)
target_compile_definitions(test_v2_restart_gate PRIVATE NODUS_WITNESS_INTERNAL_API)
add_test(NAME test_v2_restart_gate COMMAND test_v2_restart_gate)

# Ledger V2 O15A — obligation 7 (and obligation 8's fail-closed gate): the
# activation-readiness preflight. The properties under test are that it
# does not WRITE (proven by whole-database digest, not by reading the
# code), that it is deterministic across runs, that it reports every issue
# in canonical order instead of stopping at the first, and that it can
# never report ready while Rule N has no attendance source.
add_executable(test_v2_preflight tests/test_v2_preflight.c)
target_link_libraries(test_v2_preflight nodus dsa nodus crypto)
add_test(NAME test_v2_preflight COMMAND test_v2_preflight)

# Ledger V2 S4 — domain manifest/registry/readiness codec: oracle-pinned
# KATs, round-trip byte identity, unknown-enum / ordering / coherence
# negatives, empty-registry root == frozen S2 placeholder.
add_executable(test_domain_wire tests/test_domain_wire.c)
target_link_libraries(test_domain_wire nodus dsa nodus crypto)
add_test(NAME test_domain_wire COMMAND test_domain_wire)

# Ledger V2 S4 — NATIVE_BUILTIN runtime table: self-check (pinned digest ==
# fresh recomputation), per-axis lookup refusal, admission incl. the C3
# type-11 stop, cost declarations, test-only third runtime extensibility.
add_executable(test_domain_runtime tests/test_domain_runtime.c)
target_link_libraries(test_domain_runtime nodus dsa nodus crypto)
add_test(NAME test_domain_runtime COMMAND test_domain_runtime)

# Ledger V2 S4 — domain registry + staged activation scheduler: real
# witness DB, real Dilithium5 readiness signals, every replay axis, N=7/9
# quorum arithmetic, Stage C exclusions + floor guard, Stage D/E boundary
# (postpone / separation / activate), restart identity.
register_witness_test(test_domreg)

# Ledger V2 S5 — versioned schema + atomic migration: fresh/S4/legacy
# paths, per-stage failure rollback, idempotency, restart, UTXO domain
# ownership backfill, unknown-version fail-close, no CPUNK.
register_witness_test(test_v2_schema)

# Ledger V2 S5 — atomic apply engine: genesis-root cycle proof, heads/
# updates, replay matrix, cross-domain atomicity, 15-point fault-injection
# with full-DB digest rollback proof, resource limits, official 1B/70M
# supply conservation. Execution season: blocks carry ENVELOPES through
# the typed runtime path (v2_exec_fixture.h scripted runtimes).
register_witness_test_supply_bypass(test_v2_apply)

# Ledger V2 execution season — the engine-level adversarial matrix of
# the typed execution path: block-count epoch gates, fail-closed local
# index, frozen-snapshot resolution (per-axis mismatch, stale ruleset,
# READ legs, op ownership), metering authority (SYSTEM-committed policy
# only; decoy/mutated policies; inert tx_cost; exact-fit budgets),
# engine-mediated reads (canonical order, same-block observation),
# hostile runtime results (verdict -1 vs node fault -2), determinism
# twins + restart.
register_witness_test_supply_bypass(test_v2_exec)
register_witness_test(test_v2_native)

# Ledger V2 capacity season — legacy 64 KiB vs derived 1 MiB V2 ceiling:
# constant separation, independent worst-case arithmetic, wire-family
# classification in both directions, ceiling-boundary encode/decode.
register_witness_test(test_v2_capacity)

# Ledger V2 S6 — generic manifest/snapshot/claim codec: round-trips,
# per-field root sensitivity, strict-decode negatives, deterministic
# mutant fuzz, snapshot ordering/duplicates, shape-derived inclusion
# proofs, checked conversion arithmetic, frozen empty-root identity.
add_executable(test_manifest_wire tests/test_manifest_wire.c)
target_link_libraries(test_manifest_wire nodus dsa nodus crypto)
add_test(NAME test_manifest_wire COMMAND test_manifest_wire)

# Ledger V2 S6 — witness manifest/claims integration: v6 migration,
# genesis fixtures (absent/present distribution), claim lifecycle +
# adversarial matrix (substitution / replay / early / late / duplicate /
# spent-after-restart), fault-injection digest rollback, one-owner
# supply conservation, insertion-order-independent claims_root.
# O15J review R2-F5 (secondary): test_v2_claims does NOT need the bypass.
# It never calls v2x_genesis_min, so it never arms it, and all nine of its
# supply_check assertions run against the LIVE invariant over genuinely
# seeded rows. What it actually needed was the supply_init seeding at
# test_v2_claims.c:1066+. Enabling a compile-time conservation off-switch
# on a target that does not use it only widens the surface the link gate
# has to defend.
register_witness_test(test_v2_claims)
register_witness_test(test_v2_pools)

# Ledger V2 O12 S2 — the engine-mandatory epoch boundary: the derivation
# matrix (fires exactly at H % E == 0, H > 0), RETIRING graduation
# (actual-bond release UTXO, independently re-derived grad_id, bond
# zeroing, exact active_count decrement, supply invariant), no double
# graduation across replay and later boundaries, multi-graduate
# insertion-order independence, the zero-envelope boundary block,
# pending-commission timing, the flip predicate (no resurrection),
# commit_next rebuild identity + conflict, fault points F39-F45 with
# full-DB-digest rollback and clean-retry twin identity, restart
# persistence, and the malformed-row refusal.
register_witness_test(test_v2_epoch)

# O15J Faz 2 — V1's economics on the V2 lane, driven through the real
# apply engine against a LIVE conservation invariant (no supply bypass:
# every value this test moves is minted or burned by the code under
# test, never conjured). Covers the emission gate and its
# INFLATION_START_BLOCK boundary from both sides, the epoch-start
# committee snapshot, the flat and delegated settlement splits, EACH of
# the three burn legs, the whole-pool leg-completeness identity, the
# supply equation recomputed term by term, and a two-fixture determinism
# twin seeded in opposite validator order.
register_witness_test(test_v2_econ)

# O15J Faz 2 Block 2C — the economic parameters are COMMITTED GENESIS
# STATE. DNAC_BLOCKS_PER_YEAR / DNAC_DECIMAL_UNIT / DNAC_EPOCH_LENGTH are
# -D-overridable and decide how much is minted and where epoch boundaries
# fall; before 2C they appeared in no committed field, so a differently
# built node derived the SAME chain id and then diverged silently. This
# test pins BOTH bindings INDEPENDENTLY — the canonical config encoding
# into source_commit, and the committed chain_config_history rows into
# chain_config_root — because a single mutant of either one survives an
# end-to-end chain-id assertion. It also covers the mirror-image half:
# the inflation start is expressible AT GENESIS instead of only
# repealable by a later governance vote.
register_witness_test(test_v2_econ_params)

# O15J Block 2 — the per-validator delegator CAP, LEGACY lane.
# Drives apply_delegate directly through the NODUS_WITNESS_INTERNAL_API
# surface (the apply_tx_to_state precedent). The Ledger V2 half of the
# same rule is test_delegator_cap() inside test_v2_native, which owns the
# envelope fixture.
#
# RESTORED during integration: Block 2C's worktree was branched BEFORE
# Block 2B landed, so copying C's CMakeLists.txt over the tree silently
# reverted this registration and the suite count stayed flat instead of
# growing. Caught by counting tests rather than by reading the diff.
register_witness_test(test_delegator_cap)

register_witness_test(test_v2_qc_authority)
register_witness_test(test_v2_finalize)
register_witness_test(test_v2_produce)

# O15G — cert verification bound to the committed committee snapshot: the
# roster-free Layer-A resolvers, order-free unique Layer-B, snapshot-integrity
# faults, resolver-only quorum, and roster-immunity determinism twin.
register_witness_test(test_cert_verify_snapshot)

# O15G Round 2 — HIGH-2 genesis bootstrap-anchor binding
# (nodus_witness_sync_genesis_anchor_check + verify_certs_chain_def): forged
# chain_def reject, roster-sybil immunity, chain_id/cert-shortfall/malformed.
register_witness_test(test_sync_genesis_anchor)

# O15G Round 2 — HIGH-1 per-peer invalid-cert cooldown
# (nodus_witness_sync_find_peer / _rotate_peer): byzantine height-inflating peer
# skipped, honest lower-index peer selected, cooldown expiry re-admits.
register_witness_test(test_sync_peer_cooldown)

# Ledger V2 O15F Task 3 — successor CLAIM ingress (transport-local class
# 201): the verify divert (admission incl. canonicality, tx_hash, spent
# and mempool-pending dedup), produce_batch_check duplicate-nullifier
# rejection, and a mixed [envelope, claim, claim] produce_commit with
# leader/follower BlockID identity. Drives the REAL production functions;
# the successor role is set directly on the handle (the flag wiring is
# rehearsal-covered), so it runs in both build variants.
register_witness_test(test_v2_claim_ingress)

# Ledger V2 O15E Faz A — the successor committee seed source (activation
# obligation 2): committed v2_blocks BlockID at the lookback height,
# fail-closed integrity matrix, legacy-table immunity on successors,
# byte-identical legacy behavior.
register_witness_test(test_v2_committee_seed)

# Ledger V2 O15E Faz D — the genesis bundle codec + pinned joiner adopt:
# persist/get/apply round-trip, byte-identical base tables + genesis id
# vs source, wrong-pin/malformed rejection with zero trace.
register_witness_test(test_v2_bundle)

# Ledger V2 O15J Faz 1 — the PURE-V2 genesis builder: the §0 composition
# (1 treasury + 7 × 10M self-stake == 10^17) derived from a config with no
# legacy ancestor, determinism twins (byte-identical chain id / genesis
# BlockID / whole-database digest from independent derivations), config
# sensitivity, and one explicit REJECT per red-team defect (L2-F1 absent
# supply row, L2-F2 total_claimable vs leaves, L2-F3 claim window,
# L2-F4 graduation-malformed validator, L2-F6 rules P.1/P.2/P.3,
# L1-F1 validator_stats carried in the genesis bundle).
register_witness_test(test_v2_gen)

# O15J Faz 3 — test_v2_activation and test_v2_seam are GONE with the
# activation ceremony they covered (the committed activation record and
# its codecs, the type-15/16 apply matrices, the boundary state machine,
# terminal-height refusal, Stage C exclusions, the state_root v4
# combiner, and the successor-derivation seam). Every module under test
# has been deleted, so the tests are not "disabled" — there is nothing
# left for them to assert.
#
# Ledger V2 O15J Faz 3 — THE GATE ON A DEFAULT BUILD.
#
# test_v2_gate (above) compiles the gate TU with NODUS_V2_TEST_AUTHORITY
# so it can exercise the ARMED paths through the synthetic fixture. That
# is exactly why it cannot prove the property this one exists for: that a
# PRODUCTION binary, with no fixture and no build flag, opens the gate on
# a real pure-V2 chain and refuses everything else.
#
# So this target defines NEITHER NODUS_V2_TEST_AUTHORITY NOR any
# activation macro — it is a default build, and the authority it reads is
# the chain's own committed genesis manifest. It mirrors
# register_witness_test (nodus, dsa, nodus + NODUS_WITNESS_INTERNAL_API)
# and adds `crypto`, which the helper does not link and which building a
# real V2 chain needs. Written out rather than changed in the helper:
# editing register_witness_test would silently relink every other witness
# test.
add_executable(test_v2_gate_pure tests/test_v2_gate_pure.c)
target_compile_definitions(test_v2_gate_pure PRIVATE
               NODUS_WITNESS_INTERNAL_API)
target_link_libraries(test_v2_gate_pure nodus dsa nodus crypto)
add_test(NAME test_v2_gate_pure COMMAND test_v2_gate_pure)

# Ledger V2 O15F Task 1 — the successor active-set maximum (30): target
# clamp, insert/resolve reject, live serve, and the seam terminal-set +
# carried-chain_config reconciliation, all fail-closed on a successor and
# byte-identical (128 ceiling) on legacy.
register_witness_test(test_v2_active_max)

# Ledger V2 O15F Task 5 — sync/joiner CLAIM carriage (blkframe v2). Two
# successor twins A (producer) + B (empty at genesis): A commits a claim
# block + a claim-free block with real QCs; serve yields a 0x02 container
# for the claim block and a BARE v1 blockmsg for the claim-free one;
# adversarial containers (claim omitted / extra valid / truncated /
# trailing) reject with the DB digest byte-unchanged; the honest range
# brings B to A's head with byte-identical BlockID/roots and equal
# v2_claim_bytes rows; a reordered-claim container is ACCEPTED on a fresh
# twin B2 with the identical BlockID (claim order is not consensus-bound);
# a pre-S12 height (count row absent) serves rc 1.
#
# Like test_v2_gate, this compiles the gate TU in WITH NODUS_V2_TEST_AUTHORITY
# — the ARMED serve/ingress/sync paths cannot answer at all without a gate
# that opens, and the fixture's synthetic authority exists in this binary
# and NOWHERE else (test_v2_gate_linked proves the absence from libnodus /
# nodus-server).
add_executable(test_v2_sync_claims
               tests/test_v2_sync_claims.c
               src/witness/nodus_witness_v2_gate.c)
target_compile_definitions(test_v2_sync_claims PRIVATE
               NODUS_WITNESS_INTERNAL_API NODUS_V2_TEST_AUTHORITY=1)
target_link_libraries(test_v2_sync_claims nodus dsa nodus crypto)
add_test(NAME test_v2_sync_claims COMMAND test_v2_sync_claims)

# Ledger V2 O14 — LINK GATE for the production V2 acceptance seam.
#
# A source-level test cannot prove this: the test binaries link libnodus
# directly and call the seam themselves, so they stay green even if
# nothing in the SERVER references it and the linker drops the object.
# This asserts the property that actually matters — that
# nodus_witness_v2_finalize_block is present in the linked production
# server AND that its machine code calls nodus_witness_v2_qc_verify.
# Removing the startup selfcheck (or the TU from the link) makes this
# test fail by name rather than silently making the seam dead code.
add_test(NAME test_v2_seam_linked
         COMMAND sh -c
         "objdump -t '$<TARGET_FILE:nodus-server>' | grep -q 'nodus_witness_v2_finalize_block' \
          && objdump -t '$<TARGET_FILE:nodus-server>' | grep -q 'nodus_witness_v2_qc_verify' \
          && objdump -d '$<TARGET_FILE:nodus-server>' | grep -q 'call.*<nodus_witness_v2_qc_verify>'")

# Ledger V2 — generic typed-effect + compiled storage-adapter boundary
# (INACTIVE): adapter registration through the five-axis runtime lookup,
# probe/eval/mutate precondition truth, fault-vs-missing distinction,
# domain authority, and the impossibility of SQL/table selection through
# the public surface.
register_witness_test(test_v2_effects)

# Ledger V2 S3 — snapshot persistence: insert/get round-trip, conflict
# detection, corruption fail-close, oracle-pinned validator_set_root,
# insertion-order independence, reopen, and the committee builder.
add_executable(test_vset_persist tests/test_vset_persist.c)
target_link_libraries(test_vset_persist nodus dsa nodus crypto)
add_test(NAME test_vset_persist COMMAND test_vset_persist)

# Ledger V2 S3 wave 2 — epoch-boundary validator-set lifecycle:
# commit_next (freeze + idempotence + conflict), boundary flips
# (ACTIVE↔ELIGIBLE, bonds/active_count untouched, idempotence, missing
# snapshot no-op, audit cross-check fail-close), TARGET_ACTIVE_COUNT
# grow/shrink, PENDING exclusion, extra self-bond ranking, one-validator-
# one-vote, insertion-order independence, and DB-fault fail-close.
# Uses NODUS_WITNESS_INTERNAL_API (chain_config cache flag + internal
# witness headers), so it goes through register_witness_test.
register_witness_test(test_vset_boundary)
target_link_libraries(test_vset_boundary crypto)

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

# PR 3 Yol B — schema v16 PBFT-state migration regression.
# Verifies migrate_v12 dispatches into the new sub-step that creates the
# singleton pbft_state table with current_view + last_prepared_blob
# columns. RED until B2 lands the migration.
add_executable(test_witness_pbft_state_persist
                tests/test_witness_pbft_state_persist.c)
target_link_libraries(test_witness_pbft_state_persist nodus dsa nodus)
add_test(NAME test_witness_pbft_state_persist
         COMMAND test_witness_pbft_state_persist)

# O15C-C — BFT liveness regressions: out-of-order vote buffering (D2)
# and view-change join suppression (D1). Root-caused from the frozen
# 2026-08-19 activation-rehearsal round-20 stall evidence.
add_executable(test_bft_liveness tests/test_bft_liveness.c)
target_link_libraries(test_bft_liveness nodus dsa nodus)
add_test(NAME test_bft_liveness COMMAND test_bft_liveness)

# O15H — boundary view-change hardening (D1/D2/D5/D5b). Deterministic
# regressions for defects the 20-node grow rehearsal cannot discriminate.
add_executable(test_bft_view_change_hardening
               tests/test_bft_view_change_hardening.c)
target_link_libraries(test_bft_view_change_hardening nodus dsa nodus)
add_test(NAME test_bft_view_change_hardening
         COMMAND test_bft_view_change_hardening)

# PR 3 Yol B — bootstrap state machine regression.
# Covers HAVE_CHAIN branch: chain DB present → reaches DONE without
# network I/O, sets bootstrap_settle_until_ms in the future (H-4).
# RED until C2 implementation lands.
add_executable(test_witness_bootstrap_state_machine
                tests/test_witness_bootstrap_state_machine.c)
target_link_libraries(test_witness_bootstrap_state_machine nodus dsa nodus)
add_test(NAME test_witness_bootstrap_state_machine
         COMMAND test_witness_bootstrap_state_machine)

# O15B.1 — the seed placeholder node_id must identify an ENDPOINT.
# Deriving it from the IP alone deduplicated every co-located seed down
# to one cluster peer, which collapsed the Kademlia routing table and the
# DHT replication fan-out to one node and stranded a joining witness in
# bootstrap DISCOVER. See nodus/BUGS.md.
add_executable(test_cluster_seed_identity
                tests/test_cluster_seed_identity.c)
target_link_libraries(test_cluster_seed_identity nodus dsa nodus)
add_test(NAME test_cluster_seed_identity
         COMMAND test_cluster_seed_identity)

# O15B.1 — a SIGTERM delivered during nodus_server_init() must not be
# overwritten by nodus_server_run()'s `running = true`. When it was, the
# process ignored the signal forever and hung stagef_up.sh in `wait`.
add_executable(test_server_stop_latch
                tests/test_server_stop_latch.c)
target_link_libraries(test_server_stop_latch nodus dsa nodus)
add_test(NAME test_server_stop_latch
         COMMAND test_server_stop_latch)

# O15B.1 — replay/live attendance parity at an epoch boundary. The sync
# path used to credit attendance a SECOND time after replay_block had
# already computed and committed that block's state_root, mutating two
# columns inside the validator merkle leaf. A node that crashed near a
# boundary then diverged on the next block and safety-halted forever.
add_executable(test_replay_attendance_parity
                tests/test_replay_attendance_parity.c)
target_compile_definitions(test_replay_attendance_parity
                PRIVATE NODUS_WITNESS_INTERNAL_API)
target_link_libraries(test_replay_attendance_parity nodus dsa nodus)
add_test(NAME test_replay_attendance_parity
         COMMAND test_replay_attendance_parity)

# PR 3 / E0 — Orphan bootstrap sentinel cleanup at startup.
# RED until the GREEN commit replaces the no-op stub in nodus_witness.c.
add_executable(test_witness_bootstrap_orphan_sentinel
                tests/test_witness_bootstrap_orphan_sentinel.c)
target_link_libraries(test_witness_bootstrap_orphan_sentinel nodus dsa nodus)
add_test(NAME test_witness_bootstrap_orphan_sentinel
         COMMAND test_witness_bootstrap_orphan_sentinel)

# PR 3 / E5 — H-10 partial-wipe XOR check on the 3 SQLite DBs.
# RED until the GREEN commit replaces the no-op stub in nodus_server.c.
add_executable(test_server_partial_wipe_xor
                tests/test_server_partial_wipe_xor.c)
target_link_libraries(test_server_partial_wipe_xor nodus dsa nodus)
add_test(NAME test_server_partial_wipe_xor
         COMMAND test_server_partial_wipe_xor)

# PR 3 / E4 — H-9 mixed-version cluster detection at bootstrap.
# RED until the GREEN commit replaces the no-op stub in
# nodus_witness_bootstrap.c with the per-peer remote_nodus_version scan.
add_executable(test_witness_bootstrap_mixed_version
                tests/test_witness_bootstrap_mixed_version.c)
target_link_libraries(test_witness_bootstrap_mixed_version nodus dsa nodus)
add_test(NAME test_witness_bootstrap_mixed_version
         COMMAND test_witness_bootstrap_mixed_version)

# PR 3 / E3 — H-1 per-source rate limit on incoming w_chain_q.
# RED until the GREEN commit replaces the always-allow stub with
# the real (now - last >= min_interval) check.
add_executable(test_witness_bootstrap_chain_q_rate_limit
                tests/test_witness_bootstrap_chain_q_rate_limit.c)
target_link_libraries(test_witness_bootstrap_chain_q_rate_limit nodus dsa nodus)
add_test(NAME test_witness_bootstrap_chain_q_rate_limit
         COMMAND test_witness_bootstrap_chain_q_rate_limit)

# C-4 nonce-stale filter (PR 3 / F6 — replaces SKIP-by-default
# integration replay scenario with unit-level coverage of the same
# security property: handle_chain_r drops responses whose nonce
# does not match the current bootstrap_round_nonce, so a captured
# w_chain_r from round N cannot be replayed into round N+1.
add_executable(test_witness_bootstrap_nonce_stale
                tests/test_witness_bootstrap_nonce_stale.c)
target_link_libraries(test_witness_bootstrap_nonce_stale nodus dsa nodus)
add_test(NAME test_witness_bootstrap_nonce_stale
         COMMAND test_witness_bootstrap_nonce_stale)

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

# Ledger V2 K1 — generic ENVELOPE codec + commitment helpers (INACTIVE).
# KATs are pinned from an independent python3 hashlib.sha3_512 oracle.
add_executable(test_env_wire ${SHARED_DIR}/dnac/tests/test_env_wire.c)
target_link_libraries(test_env_wire nodus)
add_test(NAME test_env_wire COMMAND test_env_wire)

# Ledger V2 — generic typed-effect RESULT codec (INACTIVE): canonicality,
# the kind/precondition legality biconditional, reserved-field discipline,
# the total order + cross-kind logical-key uniqueness, the 65536-byte cap
# from both sides, and seeded property batteries.
# KATs are pinned from an independent python3 hashlib.sha3_512 oracle,
# effect_wire_oracle.py.
add_executable(test_effect_wire ${SHARED_DIR}/dnac/tests/test_effect_wire.c)
target_link_libraries(test_effect_wire nodus)
add_test(NAME test_effect_wire COMMAND test_effect_wire)

# Ledger V2 — deterministic envelope PREFLIGHT (INACTIVE): the locked
# expiry comparison against the CANDIDATE height, full 32-byte chain-id
# binding (bytes 16 and 31 are the truncation-regression detectors),
# contextual-ruleset gates, fail-closed zeroing, and seeded property
# batteries. KATs are pinned from env_preflight_oracle.py.
add_executable(test_env_preflight ${SHARED_DIR}/dnac/tests/test_env_preflight.c)
target_link_libraries(test_env_preflight nodus)
add_test(NAME test_env_preflight COMMAND test_env_preflight)

# Ledger V2 — the witness-side envelope preflight SEAM (INACTIVE): derived
# chain-id authority, cross-chain / cross-ruleset identity separation,
# forged-duplicate impossibility, and batch-failure non-publication.
add_executable(test_v2_env_preflight tests/test_v2_env_preflight.c)
target_link_libraries(test_v2_env_preflight nodus dsa nodus)
add_test(NAME test_v2_env_preflight COMMAND test_v2_env_preflight)

# Ledger V2 — deterministic resource METERING + RESERVATION (INACTIVE):
# checked-arithmetic boundaries, the sealed policy snapshot (KAT pinned
# from res_meter_oracle.py), the locked static-units formula from both
# sides of every bound, meter lifecycle + budget isolation, actual-vs-
# declared effect charging, and seeded property batteries against an
# independent hi/lo-u64 wide-arithmetic model.
add_executable(test_res_meter ${SHARED_DIR}/dnac/tests/test_res_meter.c)
target_link_libraries(test_res_meter nodus)
add_test(NAME test_res_meter COMMAND test_res_meter)

# Ledger V2 — the metered seam entry (INACTIVE): base-preflight
# equivalence, sequential batch reservation, budget restore + full-batch
# zeroing on any failure, policy-authority (envelope ceilings cannot
# reprice), and the no-live-caller guarantee.
add_executable(test_v2_env_meter tests/test_v2_env_meter.c)
target_link_libraries(test_v2_env_meter nodus dsa nodus)
add_test(NAME test_v2_env_meter COMMAND test_v2_env_meter)

# Hard-Fork v1 Stage E.2 — tier-3 client helper guard-path tests
add_executable(test_cc_client tests/test_cc_client.c)
target_link_libraries(test_cc_client nodus dsa nodus)
add_test(NAME test_cc_client COMMAND test_cc_client)

# Hard-Fork v1 Stage C.3 — per-proposer rate-limit pure-function tests
add_executable(test_chain_config_rate_limit
    tests/test_chain_config_rate_limit.c)
target_link_libraries(test_chain_config_rate_limit nodus dsa nodus)
add_test(NAME test_chain_config_rate_limit
         COMMAND test_chain_config_rate_limit)

# UTXO state_root determinism tests (Phase 2 / Task 2.5)
add_executable(test_merkle_utxo_root tests/test_merkle_utxo_root.c)
target_link_libraries(test_merkle_utxo_root nodus dsa nodus)
add_test(NAME test_merkle_utxo_root COMMAND test_merkle_utxo_root)

# state_root GOLDEN VECTOR — pins the five-subtree composition to a fixed
# 64-byte value so a format change cannot pass a relational test. Also
# usable as a generator: ./test_merkle_state_root_golden --print-root
add_executable(test_merkle_state_root_golden
    tests/test_merkle_state_root_golden.c)
target_link_libraries(test_merkle_state_root_golden nodus dsa nodus)
add_test(NAME test_merkle_state_root_golden
         COMMAND test_merkle_state_root_golden)

# state_root leaf-scan fail-close tests (K3 / K3b — mid-scan step error
# and malformed row must fail the load, never truncate the leaf set)
add_executable(test_merkle_scan_fail_close tests/test_merkle_scan_fail_close.c)
target_link_libraries(test_merkle_scan_fail_close nodus dsa nodus)
add_test(NAME test_merkle_scan_fail_close COMMAND test_merkle_scan_fail_close)

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

# Witness peer table dedup / slot leak regression tests
register_witness_test(test_witness_peer_dedup)

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

# "My Delegations" query — DB layer test backing dnac_delegations T3 RPC
register_witness_test(test_witness_delegations_query)

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

# K4 — supply_tracking must exist (and be empty) at chain-DB open time,
# not only after nodus_witness_supply_init runs at genesis commit
register_witness_test(test_supply_tracking_schema)

# Round-3 item 6 — chain_config cache must stay COLD after a mid-scan
# step error instead of serving a partial override set as authoritative
add_executable(test_chain_config_cache_failclose
    tests/test_chain_config_cache_failclose.c)
target_link_libraries(test_chain_config_cache_failclose nodus dsa nodus)
add_test(NAME test_chain_config_cache_failclose
         COMMAND test_chain_config_cache_failclose)

# O15J Block 2 / A2 — nodus_chain_config_get_u64 is three-valued: a
# governance row that is genuinely ABSENT still yields the default (which
# is what keeps a pre-genesis or freshly-bootstrapped node starting),
# while a row that cannot be READ is -1 and every consensus consumer —
# committee selection, the validator-set snapshot builder, the emission
# gate — fails closed instead of proceeding on the default. The fault is
# injected structurally (chain_config_history as a VIEW whose flagged row
# raises "integer overflow" at step time), so the code under test is the
# production code and nothing about the test is timing-dependent.
# Links `crypto` for the same reason test_vset_boundary does: it drives
# nodus_witness_vset_commit_genesis.
add_executable(test_chain_config_failclose
    tests/test_chain_config_failclose.c)
target_link_libraries(test_chain_config_failclose nodus dsa nodus crypto)
target_compile_definitions(test_chain_config_failclose PRIVATE
                           NODUS_WITNESS_INTERNAL_API)
add_test(NAME test_chain_config_failclose
         COMMAND test_chain_config_failclose)

# K2 — spend-result failure-path contract: a rolled-back block never
# produces an APPROVED receipt, and the handlers.c:2161 NULL-message
# trap stays pinned
add_executable(test_spend_result_error_status
    tests/test_spend_result_error_status.c)
target_link_libraries(test_spend_result_error_status nodus dsa nodus)
add_test(NAME test_spend_result_error_status
         COMMAND test_spend_result_error_status)

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

# CRIT-3 — AEAD completeness boundary regression test.
# Pins '>= NODUS_CHANNEL_OVERHEAD -> decrypt' / '< OVERHEAD -> fail-closed drop':
# a 28-byte empty AEAD frame is legitimate and MUST decrypt (so "drop <=28" is
# wrong), while anything shorter MUST be rejected. Guards the fix that stops
# short frames from being dispatched raw/unauthenticated on an established
# channel (nodus_tcp.c on_frame, nodus_client.c circ_data).
add_executable(test_channel_crypto_aead_complete tests/test_channel_crypto_aead_complete.c)
target_link_libraries(test_channel_crypto_aead_complete nodus dsa kem nodus)
add_test(NAME test_channel_crypto_aead_complete COMMAND test_channel_crypto_aead_complete)

# B3 fix — per-conn channel_crypto isolation regression test.
# Asserts that two nodus_tcp_conn_t structs have separate inline
# channel_crypto storage (no pointer aliasing), independent counters,
# and clean recycle after conn_free + zero-init.
add_executable(test_inter_conn_crypto_isolation tests/test_inter_conn_crypto_isolation.c)
target_link_libraries(test_inter_conn_crypto_isolation nodus dsa kem nodus)
add_test(NAME test_inter_conn_crypto_isolation COMMAND test_inter_conn_crypto_isolation)

# ── Tools ────────────────────────────────────────────────────────────
#
# Hard-Fork v1 Stage E.3 `chain-config propose` verb needs pure DNAC TX
# wire functions (tx_create / add_input / add_output / compute_hash /
# serialize).  We link the minimal set of dnac source files directly into
# the nodus-cli target instead of the whole libdna.so — keeps nodus's
# "pure C, no libdna" rule: no engine, no DHT, no database in the binary.
#
# Note: these sources live under dnac/src/ and intentionally dependency-free
# on libdna (only pull in dnac headers + crypto primitives already provided
# by libnodus / dsa).  When the tx wire layout changes, `test_cc_wire` and
# the dnac ctest suite catch byte drift on both link sites.
set(DNAC_TX_WIRE_SOURCES
    ${MONOREPO_ROOT}/dnac/src/transaction/transaction.c
    ${MONOREPO_ROOT}/dnac/src/transaction/serialize.c
    ${MONOREPO_ROOT}/dnac/src/ledger/chain_def_codec.c)

add_executable(nodus-cli
    tools/nodus-cli.c
    ${DNAC_TX_WIRE_SOURCES})
target_link_libraries(nodus-cli nodus dsa nodus)
target_compile_options(nodus-cli PRIVATE -Wall -Wextra -Wno-unused-parameter)
target_include_directories(nodus-cli PRIVATE
    ${MONOREPO_ROOT}/dnac/include
    ${MONOREPO_ROOT}/messenger/include)
target_compile_definitions(nodus-cli PRIVATE
    NODUS_CLI_HAS_DNAC=1
    DNAC_TX_BUILDER_ONLY=1)

add_executable(nodus-circ tools/nodus-circ.c)
target_link_libraries(nodus-circ nodus dsa nodus)
target_compile_options(nodus-circ PRIVATE -Wall -Wextra -Wno-unused-parameter)

add_executable(nodus-server tools/nodus-server.c)
target_link_libraries(nodus-server nodus dsa nodus)
target_compile_options(nodus-server PRIVATE -Wall -Wextra -Wno-unused-parameter)
if(JSONC_FOUND)
    target_compile_definitions(nodus-server PRIVATE NODUS_HAS_JSONC)
    target_include_directories(nodus-server PRIVATE ${JSONC_INCLUDE_DIRS})
    target_link_libraries(nodus-server ${JSONC_LIBRARIES})
endif()

# Stake & delegation v1 — stake/committee/timing constants pin
register_witness_test(test_stake_constants)

# Task 12 — validator tree DB CRUD (witness stake v1 / Phase 4)
register_witness_test(test_validator_db)

# v0.16 Stage B.1 — epoch_state table CRUD smoke test
register_witness_test(test_epoch_state)

# v0.16 Stage C.1 — emission_per_block halving-boundary KAT (RT-C2)
register_witness_test(test_emission_boundaries)

# v0.16 Stage D.2 — epoch snapshot empty-chain hash + idempotence smoke
register_witness_test(test_epoch_snapshot)

# O15J Block 2 / A1 — nodus_witness_epoch_snapshot_apply must HALT on a DB
# fault instead of hashing a fabricated input into snapshot_hash, which is
# a state_root leg. Each of the three legs (committee lookup, per-member
# validators row, per-member delegation scan) gets a FAULT case and an
# ABSENT case, and each poison is scoped so exactly ONE leg can observe it
# — otherwise a mutant reverting a single leg would survive behind
# another leg's guard. Faults are injected structurally, by replacing the
# table under test with a VIEW whose flagged row raises "integer overflow"
# at step time; the code under test is unmodified production code.
# Links `crypto` on top of register_witness_test's set for the same reason
# test_vset_boundary does: it drives the committee accessor, which reaches
# the shared validator-set snapshot codec.
add_executable(test_epoch_snapshot_failclose
    tests/test_epoch_snapshot_failclose.c)
target_link_libraries(test_epoch_snapshot_failclose nodus dsa nodus crypto)
target_compile_definitions(test_epoch_snapshot_failclose PRIVATE
                           NODUS_WITNESS_INTERNAL_API)
add_test(NAME test_epoch_snapshot_failclose
         COMMAND test_epoch_snapshot_failclose)

# Task 62 — dnac_committee_query RPC shape (Phase 14)
register_witness_test(test_committee_query_rpc)

# Task 63 — dnac_validator_list_query paged helper (Phase 14)
register_witness_test(test_validator_list_query_rpc)

# Task 29 — SPEND rejects locked UTXO inputs (Rule D)
register_witness_test(test_locked_utxo)

# Task 30 — MIN_TENURE (Rule R) committee eligibility boundary
register_witness_test(test_min_tenure_boundary)

# Task 31 (test_fee_routing) retired in v0.16 stage A.5 — block_fee_pool
# field is gone; Stage C.3's route_tx_fee test will replace coverage.

# Tasks 40-48 apply_* tests retired in v0.16 stage A.3 — the old
# reward-state-touching unit tests are superseded by the Stage E/F
# push-settlement test suite.

# Task 47 — single-SQLite-transaction block commit + rollback on abort
register_witness_test(test_commit_atomicity)

# Task 50 — F-CONS-06 mandatory independent state_root recompute on PREVOTE
register_witness_test(test_prevote_state_root_mutation)

# D1-D4 (2026-07-31) — witness fail-close: every state_root subtree fault
# returns -1 instead of a substituted tagged-empty sentinel, and
# supply_get's three-valued contract keeps a DB error from masquerading as
# pre-genesis. Deterministic fault injection (DROP TABLE on a temp DB).
# See nodus/docs/plans/2026-07-31-witness-failclose-state-root-design.md
register_witness_test(test_witness_state_root_failclose)

# F1a (2026-07-31) — the PRODUCER of those same rows. A mid-scan step
# error must not become "the proposer is not a validator" in
# record_attendance. Same structural fault injection as
# test_merkle_scan_fail_close. Also carries healthy-path
# characterisation for nodus_validator_top_n, whose identical fix is
# PARKED pending its consumers (see the test file's header).
register_witness_test(test_witness_attendance_scan_failclose)

# Task 51 — committee election (post-commit lookback + state_seed tiebreak)
register_witness_test(test_committee_election)

# Task 53 — per-epoch committee cache
register_witness_test(test_committee_cache)

# Tasks 55 + 57 integration/genesis-seed tests retired in v0.16 stage A.3
# (exercised the old reward-table seeding + auto-claim paths).

# 2026-04-19 — Genesis ghost-stake fix: parse_cd_supply helper for Rule P.2
register_witness_test(test_parse_cd_supply)

# Task 59 — BFT roster sourced from committee snapshot (chain-authoritative)
register_witness_test(test_bft_roster_committee)
register_witness_test(test_witness_roster_sorted_leader)
# O15C-D — the forwarding path's leader slot must resolve by rank, not
# by arrival index (the mis-forward behind MED-27's silent timeout).
register_witness_test(test_witness_forward_leader_rank)
# O15C-D — MED-28: the timed-out batch must survive so the NEW_VIEW
# reproposal binding can actually be satisfied.
register_witness_test(test_witness_retained_batch)
# O15C-D.1 — the C5 reproposal rule must arm on the self-advance path a
# node actually takes through a view change, not only via NEW_VIEW.
register_witness_test(test_witness_c5_self_bind)
# O15C-D.2 — the C5 selection must be a canonical total order
# (height, view, tx_hash), never arrival order. Includes a two-instance
# real-signature proof that opposite arrival orders bind identically.
register_witness_test(test_witness_c5_tiebreak)
# O15C-D.3 — a node's own prepared evidence must reach its own decision
# on BOTH view-entry paths, and a conflicting value at a height it
# prepared must be refused (the quorum-intersection refusal).
register_witness_test(test_witness_newview_convergence)
# O15C-D.4 — consensus messages from an incompatible protocol version
# must be rejected before they can change any BFT state.
register_witness_test(test_witness_protocol_version_gate)
# v0.19.24 — IDENT is exempt from the wsig verify, so a peer's advertised
# current_view is unauthenticated: it must never move this node's PBFT
# view counter (which decides leader election AND the signed preimage).
register_witness_test(test_witness_ident_no_view_adopt)
# O15N Faz 2B — the VIEW_OK view-authority primitives (purpose 0x08):
# the 148-byte preimage, the committee set hash the statement is measured
# against, the producer, and the f+1 proof verifier. PRIMITIVES ONLY —
# nothing here is on a handler, tick or commit path, and nothing moves
# w->current_view. Pins the layout, the field bindings, the f+1
# derivation (from the committee governing the CARRIED height, NOT this
# node's bft_config) and the fault-vs-verdict split (-2 vs -1).
register_witness_test(test_view_proof)
# O15C-D — MED-27: an accepted dnac_spend must never end without an
# answer; the 30 s expiry replies instead of dropping the client.
register_witness_test(test_witness_pending_forward_timeout)

# Task 60 — RETIRING validator stays in epoch committee until graduation
register_witness_test(test_retiring_committee_membership)

# ── Faz 1A — commit_t block_height bundle fix (RED state) ────────────
# See nodus/docs/plans/2026-05-02-commit-t-block-height-fix-design.md
# Bug ref: project_witness_commit_height_asymmetry (live cluster
# 2026-05-01: US-1 halted at h=114 — round skip → state_root divergence)
# These tests are stubs returning failure; concrete assertions land
# after Faz 2 (wire format) and Faz 3 (handler updates).
register_witness_test(test_witness_commit_height_skip)
register_witness_test(test_witness_commit_height_match)
register_witness_test(test_witness_commit_height_zero_legacy)
register_witness_test(test_witness_sync_rsp_state_root_verify)

# ── O15O Faz 1 — a DB failure is never a height ──────────────────────
# Bug ref: nodus/BUGS.md O15N-L2. nodus_witness_block_height answered 0
# both for an empty chain and for a failed query, and that 0 reached the
# round anchor, committee resolution, leader election and the signed
# VIEW_OK preimage. Pins the checked accessor's two-valued contract on
# BOTH chain branches (legacy `blocks`, successor `v2_blocks`), that *out
# is untouched on a fault, that the fail-open wrapper still answers 0 and
# logs, and the O15L DG-1 split of a NULL w->db — genuine pre-genesis is
# success at 0 (the arm a fresh cluster needs to reach genesis at all),
# a held-but-unreadable chain is a fault. Needs no compile flag and no
# environment; the fault is a real DROP TABLE, not a mock.
register_witness_test(test_witness_block_height_checked)

# ── O15O Faz 1 — the CONSUMERS of the checked chain-height accessor ──
# The sibling of the test above, and the half that was missing. That one
# pins the ACCESSOR's two-valued contract; this one pins the call sites
# READING it. Measured, not assumed: reverting every fault return in
# nodus_witness_block_height_checked to the old fail-open turned only the
# accessor's own test red — all 214 other tests, every converted consumer
# among them, stayed green. A build that discarded the whole substance of
# the phase was indistinguishable from one that kept it.
# Each consumer gets a PAIR on one fixture — healthy (leads / opens the
# round / accepts) and faulted (refuses) — the fault being a real DROP
# TABLE so sqlite3_prepare_v2 genuinely fails. The healthy leg is the
# anti-vacuity control: "returns -1" proves nothing on its own. The
# fixture chain is EMPTY on purpose, so a fail-open build's 0 equals the
# true tip and no downstream height comparison can mask the difference.
# Bug ref: nodus/BUGS.md O15N-L2. Needs no compile flag and no
# environment; leaves nothing behind (mkdtemp dirs are removed).
register_witness_test(test_witness_height_fault_consumers)

# ── O15O Faz 2 — a quorum of 0 is refused, not obeyed ────────────────
# Bug ref: nodus/BUGS.md (the view-change threshold row), widened by grep
# from one site to six. nodus_witness_bft_config_init writes quorum = 0
# below NODUS_T3_MIN_WITNESSES and calls it "consensus disabled" — but
# every threshold is written `x < quorum`, and `x < 0` is FALSE for every
# x, so the value meaning "I take no part" was the most PERMISSIVE input
# the consensus code could receive: vote quorum on the first vote, a
# view-change quorum on one message, any prepared certificate, a NEW_VIEW
# claiming a reproposal with zero signatures, and a synced block with no
# valid certs.
# Each site gets a PAIR on one fixture — healthy (the threshold is
# reached only AT its real value) and vacuum (quorum forced to 0, the
# site refuses). The healthy leg is the anti-vacuity control, and several
# sections carry TWO of them (below the threshold and at it) so a guard
# that refused unconditionally cannot pass. §4 reaches quorum 0 through
# the PRODUCTION initialiser (a four-member roster), not a hand-set
# field.
# ⚠ FIVE OF SIX SITES ARE COVERED. §2 (the fork-detection DB drop in
# nodus_witness_sync_check) cannot be driven from a fixture: find_peer
# only returns peers STRICTLY ahead of local_height, so the same-height
# branch guarding drop_witness_db is not entered. It is not provably
# dead — a TRANSIENT fault between the function's two fail-open height
# reads would open it — but no fixture can inject one there. The test
# prints an explicit UNREACHED notice rather than hand-calling an inlined
# branch; do not count that row as tested.
# Needs no compile flag and no environment; every fixture chain stays in
# epoch 0, so the assertions hold at DNAC_EPOCH_LENGTH 720 and 15 alike.
# Leaves nothing behind (mkdtemp dirs are removed, capture files are
# unlinked at creation).
register_witness_test(test_witness_quorum_vacuum)

# ── PR 1 (2026-05-03) — bft_config follower-path refresh (C-3 fix) ───
# See docs/plans/2026-05-03-witness-auto-bootstrap-design.md
register_witness_test(test_witness_bft_config_refresh)

# ── PR 2 (2026-05-03) — timestamp determinism (drop from hash preimage) ─
# See docs/plans/2026-05-03-pr2-timestamp-determinism-impl.md
register_witness_test(test_block_hash_timestamp_excluded)

# ── Faz 1B — BLOCKERS (audit B-1, B-2, B-3 + C-4) ────────────────────
register_witness_test(test_block_hash_includes_state_root)
register_witness_test(test_recovery_sentinel_crash_safety)
register_witness_test(test_halt_auto_recover_default_off)
register_witness_test(test_halt_recovery_historical_committee)

# ── Faz 1C — CRITICAL (audit C-1..C-5) ────────────────────────────────
register_witness_test(test_heartbeat_signed_checksum)
register_witness_test(test_precommit_cert_verify_lazy)
register_witness_test(test_sync_check_dos_rate_limit)

# O15J Faz 3 — the `syncing` latch must not be one-way. Every clear of
# sync_state.syncing lives on a response path, so a response that never
# arrives used to wedge a node out of sync permanently and silently.
# Locks: no chain DB never latches · a stalled latch is released · a
# HEALTHY catch-up is not interrupted (the direction a naive watchdog
# breaks) · progress is tracked separately from the rate-limit stamp.
register_witness_test(test_sync_stall_watchdog)
register_witness_test(test_replay_block_historical_committee)
register_witness_test(test_wire_protocol_version_reject)

# ── Faz 1D — MAJOR (audit M-1..M-4, M-6) ─────────────────────────────
register_witness_test(test_commit_batch_toctou)
register_witness_test(test_multi_round_skip_silent_drop)
register_witness_test(test_halt_cooldown_expedite)
register_witness_test(test_halt_entry_phase_reset)
register_witness_test(test_fault_inject_round_skip)
# Faz 5.4 — concrete only when -DQGP_FAULT_INJECT=ON; default build
# returns rc=99 (SKIP). ctest treats rc=99 as Skipped via this prop.
set_tests_properties(test_fault_inject_round_skip
    PROPERTIES SKIP_RETURN_CODE 99)

# Task 81 — supply invariance property test (Phase 17).
# Pure-C simulated state machine — does NOT need the witness internal
# API, only DNAC public enum + constants. Linked without NODUS_WITNESS_INTERNAL_API.
add_executable(test_supply_invariant tests/test_supply_invariant.c)
target_link_libraries(test_supply_invariant nodus dsa nodus)
add_test(NAME test_supply_invariant COMMAND test_supply_invariant)

# Performance benchmark harness (Phase 1 — micro-benchmarks).
# See nodus/docs/plans/2026-04-24-perf-harness-design.md.
# Run with: ctest -L bench
add_subdirectory(tests/bench)
