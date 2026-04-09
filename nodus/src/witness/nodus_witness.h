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
#include <sqlite3.h>
#include <stdbool.h>

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
    uint8_t     tx_hash[NODUS_T3_TX_HASH_LEN];
    uint8_t     nullifiers[NODUS_T3_MAX_TX_INPUTS][NODUS_T3_NULLIFIER_LEN];
    uint8_t     nullifier_count;
    uint8_t     tx_type;
    uint8_t     tx_data[NODUS_T3_MAX_TX_SIZE];
    uint32_t    tx_len;

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

    /* Client request data */
    uint8_t     client_pubkey[NODUS_PK_BYTES];
    uint8_t     client_signature[NODUS_SIG_BYTES];
    uint64_t    fee_amount;

    /* Forwarder info */
    bool        is_forwarded;
    uint8_t     forwarder_id[NODUS_T3_WITNESS_ID_LEN];

    /* Client session (for direct response — single-TX legacy) */
    struct nodus_tcp_conn *client_conn;
    uint32_t    client_txn_id;

    /* Batch mode (multi-TX block) */
    int                                batch_count;
    nodus_witness_mempool_entry_t     *batch_entries[NODUS_W_MAX_BLOCK_TXS];
    uint8_t     block_hash[NODUS_T3_TX_HASH_LEN];  /* SHA3-512(all tx_hashes) */
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

    /* Gossip rate limit */
    uint64_t    last_rost_q_time;           /* last w_rost_q sent to this peer */
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

    /* Cached UTXO checksum (avoid full table scan on every epoch tick) */
    uint8_t         cached_utxo_checksum[64];  /* NODUS_KEY_BYTES */
    bool            cached_utxo_checksum_valid;

    /* Witness database (separate from DHT storage) */
    sqlite3     *db;
    char        data_path[256];             /* For creating chain DB on genesis */

    bool        running;
} nodus_witness_t;

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

#ifdef __cplusplus
}
#endif

#endif /* NODUS_WITNESS_H */
