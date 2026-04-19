/**
 * Nodus — Witness Module (DNAC BFT Consensus)
 *
 * All nodus nodes are automatic witnesses. Provides:
 *   - BFT consensus for DNAC transaction witnessing
 *   - Nullifier/ledger/UTXO/block SQLite storage
 *   - Witness peer mesh over nodus TCP connections
 *   - DNAC client query handlers (dnac_* Tier 2 methods)
 *
 * Roster is dynamically built from DHT pubkey registry + witness peer mesh
 * and refreshed every 60 seconds (epoch tick).
 *
 * All BFT messages use Tier 3 protocol ("w_" prefixed CBOR methods)
 * over dedicated witness TCP port 4004.
 * Single-threaded: all state transitions in the epoll event loop.
 *
 * @file nodus_witness.h
 */

#ifndef NODUS_WITNESS_H
#define NODUS_WITNESS_H

#include "nodus/nodus_types.h"
#include "witness/nodus_witness_mempool.h"
#include "dnac/dnac.h"        /* DNAC_COMMITTEE_SIZE, DNAC_PUBKEY_SIZE */
#include <sqlite3.h>
#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Forward declarations */
struct nodus_server;
struct nodus_tcp_conn;

/* nodus_tcp_t is an anonymous struct typedef in transport/nodus_tcp.h.
 * We cannot forward-declare it, so we use void* for the witness TCP pointer
 * and cast in implementation files where the full type is available. */

/* ── Witness configuration ───────────────────────────────────────── */

typedef struct {
    /* No config needed — all nodes are automatic witnesses.
     * Struct kept for future extensibility (e.g. stake threshold). */
    uint8_t  _reserved;
} nodus_witness_config_t;

/* ── Roster entry ────────────────────────────────────────────────── */

typedef struct {
    uint8_t     witness_id[NODUS_T3_WITNESS_ID_LEN];
    uint8_t     pubkey[NODUS_PK_BYTES];
    char        address[256];
    uint64_t    joined_epoch;
    bool        active;
} nodus_witness_roster_entry_t;

/* ── Roster ──────────────────────────────────────────────────────── */

typedef struct {
    uint32_t    version;
    uint32_t    n_witnesses;
    nodus_witness_roster_entry_t witnesses[NODUS_T3_MAX_WITNESSES];
    uint8_t     signature[NODUS_SIG_BYTES];
} nodus_witness_roster_t;

/* ── Transaction types (DNAC) ────────────────────────────────────── */

#define NODUS_W_TX_GENESIS       0
#define NODUS_W_TX_SPEND         1
#define NODUS_W_TX_BURN          2
#define NODUS_W_TX_TOKEN_CREATE  3
/* Phase 8 — stake & delegation TX types. Values MUST match
 * dnac_tx_type_t in dnac/transaction.h (DNAC_TX_STAKE .. DNAC_TX_VALIDATOR_UPDATE). */
#define NODUS_W_TX_STAKE             4
#define NODUS_W_TX_DELEGATE          5
#define NODUS_W_TX_UNSTAKE           6
#define NODUS_W_TX_UNDELEGATE        7
#define NODUS_W_TX_CLAIM_REWARD      8
#define NODUS_W_TX_VALIDATOR_UPDATE  9
#define NODUS_W_TX_CHAIN_CONFIG     10   /* Hard-Fork v1 parameter change */

/* ── Vote types ──────────────────────────────────────────────────── */

typedef enum {
    NODUS_W_VOTE_APPROVE = 0,
    NODUS_W_VOTE_REJECT  = 1,
} nodus_witness_vote_t;

/* ── BFT configuration (derived from roster size) ────────────────── */

typedef struct {
    uint32_t    n_witnesses;
    uint32_t    f_tolerance;        /* (n-1)/3 */
    uint32_t    quorum;             /* 2f+1 */
    uint32_t    round_timeout_ms;
    uint32_t    viewchg_timeout_ms;
    uint32_t    max_view_changes;
} nodus_witness_bft_config_t;

/* ── BFT consensus phase ─────────────────────────────────────────── */

typedef enum {
    NODUS_W_PHASE_IDLE       = 0,
    NODUS_W_PHASE_PROPOSE    = 1,
    NODUS_W_PHASE_PREVOTE    = 2,
    NODUS_W_PHASE_PRECOMMIT  = 3,
    NODUS_W_PHASE_COMMIT     = 4,
    NODUS_W_PHASE_VIEW_CHANGE = 5,
} nodus_witness_phase_t;

/* ── Vote record ─────────────────────────────────────────────────── */

typedef struct {
    uint8_t     voter_id[NODUS_T3_WITNESS_ID_LEN];
    nodus_witness_vote_t vote;
    uint8_t     signature[NODUS_SIG_BYTES];
} nodus_witness_vote_record_t;

/* ── Round state ─────────────────────────────────────────────────── */

typedef struct {
    uint64_t    round;
    uint32_t    view;
    nodus_witness_phase_t phase;

    /* tx_hash mirrors block_hash for vote message addressing — every
     * round is now batch-shaped (Phase 7), so the two values are equal
     * by construction. Kept as a separate field only so vote message
     * dispatch does not have to know about block_hash semantics. */
    uint8_t     tx_hash[NODUS_T3_TX_HASH_LEN];
    /* tx_type retained for the genesis-quorum-unanimous decision in
     * handle_vote (genesis still requires unanimous approval). Set by
     * bft_start_round_internal from entries[0]->tx_type. */
    uint8_t     tx_type;

    /* Votes */
    nodus_witness_vote_record_t prevotes[NODUS_T3_MAX_WITNESSES];
    int         prevote_count;
    int         prevote_approve_count;

    nodus_witness_vote_record_t precommits[NODUS_T3_MAX_WITNESSES];
    int         precommit_count;
    int         precommit_approve_count;

    /* Timing */
    uint64_t    phase_start_time;

    /* Block production */
    uint64_t    proposal_timestamp;
    uint8_t     proposer_id[NODUS_T3_WITNESS_ID_LEN];

    /* Forwarder info */
    bool        is_forwarded;
    uint8_t     forwarder_id[NODUS_T3_WITNESS_ID_LEN];

    /* Client session (deprecated — entries carry their own conn after Phase 12) */
    struct nodus_tcp_conn *client_conn;
    uint32_t    client_txn_id;

    /* Batch mode (multi-TX block) */
    int                                batch_count;
    nodus_witness_mempool_entry_t     *batch_entries[NODUS_W_MAX_BLOCK_TXS];
    /* Phase 9 / Task 9.4 — tx_root, NOT block_hash. RFC 6962 Merkle
     * root over the batch's tx hashes. */
    uint8_t     tx_root[NODUS_T3_TX_HASH_LEN];
} nodus_witness_round_state_t;

/* ── View change record ──────────────────────────────────────────── */

typedef struct {
    uint32_t    target_view;
    uint8_t     voter_id[NODUS_T3_WITNESS_ID_LEN];
    uint64_t    last_committed_round;
    uint8_t     signature[NODUS_SIG_BYTES];
} nodus_witness_vc_record_t;

/* ── Witness peer connection ─────────────────────────────────────── */

typedef struct {
    uint8_t     witness_id[NODUS_T3_WITNESS_ID_LEN];
    char        address[256];
    struct nodus_tcp_conn *conn;
    bool        identified;                 /* w_ident exchanged */
    uint64_t    last_attempt;               /* Last reconnect attempt */
    int         connect_failures;           /* Exponential backoff counter */

    /* C-02: Outgoing auth state (client-side hello/auth on port 4004) */
    enum { PEER_AUTH_NONE, PEER_AUTH_HELLO_SENT, PEER_AUTH_OK } auth_state;

    /* State sync: peer's chain state from w_ident */
    uint64_t    remote_height;              /* peer's block height */
    uint8_t     remote_checksum[64];        /* peer's UTXO checksum */

    /* Phase 10 / Task 10.4 — clock skew probe.
     * (now - peer.ts_local) seconds, signed. Logged when |skew| > 10. */
    int64_t     last_skew_sec;

    /* Gossip rate limit */
    uint64_t    last_rost_q_time;           /* last w_rost_q sent to this peer */

    /* CC-OPS-002 / Q14 — peer binary + schema version advertised in w_ident.
     * Both 0 for legacy peers (pre hard-fork v1). When either mismatches
     * the local values, handle_ident emits PEER SCHEMA MISMATCH log and
     * marks version_compatible = false. BFT participation gate lives in
     * Q14 v2 — for now this is observability-only so quorum math is not
     * inadvertently degraded. */
    uint32_t    remote_nodus_version;
    uint32_t    remote_chain_config_schema;
    bool        version_compatible;         /* false if schema/version mismatch */
} nodus_witness_peer_t;

/* ── Main witness context ────────────────────────────────────────── */

typedef struct nodus_witness {
    /* Parent server (non-owning) */
    struct nodus_server     *server;

    /* Dedicated witness TCP transport (port 4004, non-owning — owned by server) */
    void                    *tcp;       /* nodus_tcp_t* — cast in .c files */

    /* Configuration */
    nodus_witness_config_t  config;

    /* Identity */
    uint8_t     my_id[NODUS_T3_WITNESS_ID_LEN];
    int         my_index;                   /* Index in roster (-1 if not in) */

    /* Roster */
    nodus_witness_roster_t  roster;

    /* BFT consensus state */
    uint64_t    current_round;
    uint32_t    current_view;
    uint64_t    last_committed_round;
    nodus_witness_round_state_t round_state;

    /* View change tracking */
    nodus_witness_vc_record_t view_changes[NODUS_T3_MAX_WITNESSES];
    int         view_change_count;
    uint32_t    view_change_target;
    bool        view_change_in_progress;

    /* BFT config (computed from roster) */
    nodus_witness_bft_config_t  bft_config;

    /* Dynamic roster — epoch-based refresh */
    uint64_t    last_epoch;                     /* Timestamp of last roster rebuild */
    nodus_witness_roster_t  pending_roster;     /* Built each epoch from DHT + peers */
    nodus_witness_bft_config_t pending_bft_config;
    bool        pending_roster_ready;           /* Pending roster waiting to swap */

    /* Zone chain ID */
    uint8_t     chain_id[32];

    /* CC-OPS-004 / Q16 — chain_config_history lookup cache.
     *
     * Every finalize_block + every proposer round consults
     * nodus_chain_config_get_u64 for param overrides (inflation_start,
     * max_txs_per_block). Without a cache each lookup is a fresh SQLite
     * prepared-statement + row read (~1us). With a cache, lookup is a
     * walk over a short in-memory array (typically < 10 rows per
     * param across a chain's lifetime).
     *
     * Coherence model:
     *   - chain_config_cache_warm = false on startup / after every
     *     successful chain_config_apply INSERT (even before the outer
     *     DB transaction commits — matches CC-OPS-004's
     *     "invalidate-before-commit" mitigation).
     *   - Next lookup with !warm reloads all rows from DB and sets
     *     warm = true. Re-warm cost = single indexed SELECT.
     *   - On crash between INSERT and flag-clear: process is dead;
     *     restart warms from DB which has the (maybe) committed state.
     *     No stale cache can survive a restart.
     *
     * Sized to hold 3 params × 64 rows — far more than any chain
     * governance would ever produce. */
    struct {
        uint64_t new_value;
        uint64_t effective_block;
    }           chain_config_cache[4 /* DNAC_CFG_PARAM_MAX_ID + 1 */][64];
    int         chain_config_cache_count[4];   /* rows per param */
    bool        chain_config_cache_warm;

    /* Startup chain_id quorum verification (Fix 3 — fork detection).
     * Tracks distinct peers that agree/disagree with our local chain_id
     * during the first 300s after activation. If a strict majority of
     * observed peers disagree (and >= 2 dissenters seen), the witness
     * quarantines itself — refuses to participate in BFT consensus until
     * operator intervention. Piggybacks on the chain_id field in every
     * T3 message header (no new wire protocol). */
    uint64_t    activated_at_sec;
    bool        quarantined;
    uint32_t    chain_dissent_count;
    uint32_t    chain_agree_count;
    uint8_t     chain_dissent_ids[NODUS_T3_MAX_WITNESSES][NODUS_T3_WITNESS_ID_LEN];
    uint8_t     chain_agree_ids[NODUS_T3_MAX_WITNESSES][NODUS_T3_WITNESS_ID_LEN];

    /* Transaction ID counter (monotonic) */
    uint32_t    next_txn_id;

    /* Witness peer connections */
    nodus_witness_peer_t    peers[NODUS_T3_MAX_WITNESSES];
    int                     peer_count;

    /* Pending forwards (non-leader → client response routing) */
    struct {
        bool        active;
        uint8_t     tx_hash[NODUS_T3_TX_HASH_LEN];
        struct nodus_tcp_conn *client_conn;
        uint32_t    client_txn_id;
        uint64_t    started_at;     /* H-15: timestamp for timeout (seconds) */
    } pending_forwards[NODUS_W_MAX_PENDING_FWD];
    int pending_forward_count;

    /* Transaction mempool (leader: fee-sorted pending TX queue) */
    nodus_witness_mempool_t mempool;

    /* State sync (block replay from peers) */
    struct {
        bool        syncing;              /* sync in progress */
        int         sync_peer_idx;        /* which peer we're syncing from */
        uint64_t    sync_target_height;   /* peer's height */
        uint64_t    sync_current_height;  /* next block to request */
        uint64_t    last_sync_attempt;    /* rate limit (timestamp) */
    } sync_state;

    /* Phase 10 / Task 10.1 — cached state_root (RFC 6962 Merkle root over
     * the UTXO set), computed by nodus_witness_merkle_compute_utxo_root.
     * Cached to avoid a full table scan on every epoch tick. */
    uint8_t         cached_state_root[64];  /* NODUS_KEY_BYTES */
    bool            cached_state_root_valid;

    /* Phase 6 / Task 31 — per-block fee accumulator.
     *
     * Collected from every SPEND/TOKEN_CREATE TX in the current block.
     * Replaces the legacy "fee → burn UTXO" path: fees are no longer
     * burned to DNAC_BURN_ADDRESS; they accumulate here and Phase 9
     * Task 49 will drain this pool into the committee reward
     * accumulator at block finalize time. Cleared on every successful
     * block commit (finalize_block). Native DNAC only — token-fee
     * handling deferred to a later phase. */
    uint64_t        block_fee_pool;

    /* Phase 10 / Task 53 — per-epoch committee cache.
     *
     * Populated on the first committee query within an epoch by
     * nodus_committee_get_for_block() and reused for every subsequent
     * query in the same epoch. The cache is effectively invalidated
     * when block_height crosses an epoch boundary (the next lookup
     * sees a different e_start and triggers a recompute).
     *
     * cached_committee_epoch_start == UINT64_MAX marks the slot as
     * uninitialised (set at init + on recompute failure). The layout
     * uses raw bytes because the committee member struct is defined
     * in witness/nodus_witness_committee.h, which would be a circular
     * include. Callers MUST go through the get_for_block accessor
     * rather than touching these fields directly.
     *
     * DNAC_COMMITTEE_SIZE (7) members × (2592 pubkey + 8 stake + 2
     * commission + padding) ≈ 18.4 KB. Kept in-struct rather than
     * malloc-d because nodus_witness_t itself is already heap-allocated. */
    uint64_t        cached_committee_epoch_start;
    int             cached_committee_count;
    uint8_t         cached_committee_pubkeys[DNAC_COMMITTEE_SIZE][DNAC_PUBKEY_SIZE];
    uint64_t        cached_committee_stakes[DNAC_COMMITTEE_SIZE];
    uint16_t        cached_committee_commission_bps[DNAC_COMMITTEE_SIZE];

    /* Witness database (separate from DHT storage) */
    sqlite3     *db;
    char        data_path[256];             /* For creating chain DB on genesis */

    /* Phase 9 / Task 47 — single-transaction block commit tracker.
     *
     * Set true in nodus_witness_db_begin(), cleared in
     * nodus_witness_db_commit() / nodus_witness_db_rollback(). Used by
     * debug assertions + tests that verify the block commit path stays
     * inside exactly one outer transaction (design F-STATE-02). */
    bool        in_block_transaction;

    bool        running;
} nodus_witness_t;

/* Phase 4 / Task 4.2 — intra-batch chained-UTXO context.
 *
 * Carried by apply_tx_to_state across the N-TX batch loop so the
 * layer-3 in-memory check (Task 4.3) can detect a TX whose input
 * nullifier matches a previous TX's output future-nullifier. Layer 2
 * (propose_batch, Task 4.1) catches the same pattern at proposal time;
 * layer 3 catches anything that slipped past — bug, attack, or test
 * hook bypass.
 *
 * Sized for the worst case: NODUS_W_MAX_BLOCK_TXS (10) TXs each
 * producing NODUS_T3_MAX_TX_INPUTS (16) outputs = 160 entries.
 *
 * Pass NULL to apply_tx_to_state from single-TX paths and from the
 * SAVEPOINT attribution replay (Task 6.2) — the layer-3 check is
 * skipped under NULL.
 */
typedef struct {
    uint8_t seen_nullifiers[NODUS_W_MAX_BLOCK_TXS * NODUS_T3_MAX_TX_INPUTS]
                          [NODUS_T3_NULLIFIER_LEN];
    int     seen_count;
} nodus_witness_batch_ctx_t;

_Static_assert(sizeof(nodus_witness_batch_ctx_t) < 16384,
               "batch_ctx exceeds 16 KB stack budget");

/* ── Lifecycle ───────────────────────────────────────────────────── */

/**
 * Initialize witness module. Opens witness.db, builds initial roster.
 * Called from nodus_server_init() — all nodes are automatic witnesses.
 *
 * @param witness  Allocated witness context (caller owns)
 * @param server   Parent server
 * @param config   Witness configuration (reserved for future use)
 * @return 0 on success, -1 on failure
 */
int nodus_witness_init(nodus_witness_t *witness,
                       struct nodus_server *server,
                       const nodus_witness_config_t *config);

/**
 * Periodic tick — called from main event loop.
 * Checks BFT timeouts, retries peer connections.
 */
void nodus_witness_tick(nodus_witness_t *witness);

/**
 * Clean up witness resources. Closes DB, clears state.
 */
void nodus_witness_close(nodus_witness_t *witness);

/* ── Dispatch (called from nodus_server.c) ───────────────────────── */

/**
 * Dispatch a Tier 3 witness BFT message ("w_*" methods).
 * These are pre-auth, self-authenticated via Dilithium5 wsig.
 * Raw payload is passed for CBOR re-decode with T3 schema.
 */
void nodus_witness_dispatch_t3(nodus_witness_t *witness,
                               struct nodus_tcp_conn *conn,
                               const uint8_t *payload, size_t len);

/**
 * Dispatch a DNAC client query ("dnac_*" methods).
 * These are post-auth, session-verified.
 * Raw payload passed for CBOR re-decode of DNAC-specific args.
 */
void nodus_witness_dispatch_dnac(nodus_witness_t *witness,
                                 struct nodus_tcp_conn *conn,
                                 const uint8_t *payload, size_t payload_len,
                                 const char *method, uint32_t txn_id);

/**
 * Notify witness module that a TCP connection is being closed.
 * Clears any peer or BFT state references to prevent dangling pointers.
 */
void nodus_witness_peer_conn_closed(nodus_witness_t *witness,
                                     struct nodus_tcp_conn *conn);

/**
 * Create chain-specific witness DB on genesis commit.
 * Filename: witness_<chain_id_hex>.db in data directory.
 * Sets chain_id and opens the new database.
 */
int nodus_witness_create_chain_db(nodus_witness_t *witness,
                                    const uint8_t *chain_id);

/**
 * Phase 6 / Task 31 — read the current block fee pool.
 *
 * Returns the accumulated native DNAC fee amount for the in-progress
 * block. Phase 9 Task 49 will call this inside finalize_block to feed
 * the committee reward accumulator. Callers pass NULL output to just
 * sanity-check the pointer.
 *
 * @param witness  witness context
 * @param out      where to write the accumulator value (may be NULL)
 * @return 0 on success, -1 if witness is NULL
 */
int nodus_witness_get_block_fee_pool(const nodus_witness_t *witness,
                                       uint64_t *out);

#ifdef __cplusplus
}
#endif

#endif /* NODUS_WITNESS_H */
