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
#include "nodus/nodus_chain_config.h"  /* nodus_cc_rate_limit_table_t */
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
    /* 2026-05-02 audit B-3 — halt-recovery auto policy.
     *
     * Default false: when finalize_block latches safety_halt, the node
     * REMAINS halted until an operator clears the recovery sentinel
     * file (Faz 4B) and restarts the service. Default chosen to deny
     * an "all-Byzantine peer" attacker the ability to coerce an
     * isolated honest node into wiping its own (correct) DB and
     * re-syncing from the attacker's chain.
     *
     * When true: halt_recovery_check (Faz 4D-E) evaluates same-height
     * disagreement quorum against the historical committee snapshot
     * pinned at halt_block_height; if quorum is clear the node auto-
     * drops its DB + re-syncs. Use only in trusted-network deployments
     * (test/staging clusters) or after operator review.
     *
     * Wire/JSON key: "halt_auto_recover" (bool). */
    bool     halt_auto_recover;
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
/* Value 8 was NODUS_W_TX_CLAIM_REWARD — removed in v0.16 reward redesign.
 * Left as a gap so VALIDATOR_UPDATE / CHAIN_CONFIG keep their wire values. */
#define NODUS_W_TX_VALIDATOR_UPDATE  9
#define NODUS_W_TX_CHAIN_CONFIG     10   /* Hard-Fork v1 parameter change */
/* Phase-C C2.2 — shielded pool TX (dual-mode V4). MUST equal
 * DNAC_TX_SHIELDED = 11 (dnac/include/dnac/dnac.h:323). Through all of C2
 * the witness admission path REJECTS this type unconditionally
 * (nodus_witness_verify.c verify_shielded_tx) — the reject→accept flip is
 * C3's first commit, atomically with the shielded apply case + state_root
 * v4 (C2 design v2 CRIT-2/G-SEC-7/G-SEC-9). */
#define NODUS_W_TX_SHIELDED         11

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
    /* F17 A1 — voter's Dilithium5 public key. In-memory only; NOT
     * persisted to the commit_certificates table nor carried on the T3
     * wire format (both fields remain witness_id + signature only).
     * Populated at vote-record-write time:
     *   - self-votes: from w->server->identity.pk.bytes
     *   - incoming votes: from gossip roster's pubkey map at handle_vote
     *     time (safe because witness_id = H(pubkey) per
     *     nodus_chain_config.h:157, see F17 design A15).
     * Cert reads from DB (nodus_witness_cert_get) leave this field
     * ZERO — callers on the read path MUST NOT trust pubkey. The read
     * path is used only by sync verification, which resolves pubkey
     * separately via nodus_witness_verify_sync_certs. */
    uint8_t     pubkey[DNAC_PUBKEY_SIZE];
} nodus_witness_vote_record_t;

/* ── Round state ─────────────────────────────────────────────────── */

typedef struct {
    uint64_t    round;
    uint32_t    view;
    nodus_witness_phase_t phase;

    /* A2 fix — proposed block's height for THIS round. Set once at
     * round start (leader: nodus_witness_block_height(w)+1; follower:
     * prop->block_height after sanity check). All callers of
     * compute_prepared_preimage MUST source height from here, not from
     * nodus_witness_block_height(w)+1, so sender and verifier agree on
     * the round's anchor regardless of local-state drift. */
    uint64_t    block_height;

    /* tx_hash mirrors block_hash for vote message addressing — every
     * round is now batch-shaped (Phase 7), so the two values are equal
     * by construction. Kept as a separate field only so vote message
     * dispatch does not have to know about block_hash semantics. */
    uint8_t     tx_hash[NODUS_T3_TX_HASH_LEN];
    /* tx_type carried for diagnostics / future per-type handling. All TX
     * types (including genesis) now use standard BFT 2f+1 quorum — the
     * former genesis-unanimous override was removed because it blocked
     * liveness without providing additional safety. Set by
     * bft_start_round_internal from entries[0]->tx_type. */
    uint8_t     tx_type;

    /* Votes — sized to DNAC_MAX_ACTIVE_VALIDATORS (S3).
     *
     * Consensus is committee-bound, so a vote array holds at most
     * active-set-many entries. Before S3 the active set was fixed at
     * DNAC_COMMITTEE_SIZE and these arrays were sized to it; with a
     * dynamic active set the SEMANTIC bound is the size of the set
     * governing the round, and the STRUCTURAL bound is this release's
     * ceiling. Sizing to the ceiling is required for correctness: at
     * n = 128 the quorum is dna_bft_quorum(128) = 86, so a 7-slot array
     * would make quorum unreachable.
     *
     * The semantic bound is still enforced, and it is enforced BEFORE a
     * vote ever reaches these slots — handle_vote rejects any sender whose
     * pubkey is not in the committee for the round
     * (nodus_witness_bft.c, committee_find_pubkey gate) and dedups by
     * pubkey, so vote_count cannot exceed the committee size. The array
     * bound below is the memory-safety backstop only.
     *
     * nodus_witness_t is HEAP-allocated in production
     * (nodus/src/server/nodus_server.c:6078 calloc) — never a stack
     * object. Test fixtures must do the same (calloc) or use static
     * storage. */
    nodus_witness_vote_record_t prevotes[DNAC_MAX_ACTIVE_VALIDATORS];
    int         prevote_count;
    int         prevote_approve_count;

    nodus_witness_vote_record_t precommits[DNAC_MAX_ACTIVE_VALIDATORS];
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

/** One (voter_id, signature) pair of a PBFT prepared certificate. */
typedef struct {
    uint8_t voter_id[NODUS_T3_WITNESS_ID_LEN];
    uint8_t signature[NODUS_SIG_BYTES];
} nodus_witness_prepared_sig_t;

typedef struct {
    uint32_t    target_view;
    uint8_t     voter_id[NODUS_T3_WITNESS_ID_LEN];
    uint64_t    last_committed_round;
    uint8_t     signature[NODUS_SIG_BYTES];
    /* C5 — prepared cert carried on the VIEW_CHANGE wire. Populated by
     * handle_viewchg only after the incoming prepared_sigs verify
     * against the PREPARED preimage + committee pubkey lookup AND reach
     * 2f+1 quorum. has_prepared stays false if verification fails, if
     * the sender did not carry a prepared cert, or if the cert had
     * fewer than quorum-many valid sigs. Used by the new-leader scan at
     * view-change quorum to pick the PBFT reproposal (highest height).
     *
     * S3 — sigs[] is a HEAP POINTER, not an in-struct array. The record
     * array below grew from DNAC_COMMITTEE_SIZE to
     * DNAC_MAX_ACTIVE_VALIDATORS, and an in-struct
     * sigs[DNAC_MAX_ACTIVE_VALIDATORS] would make the product
     * 128 records × 128 sigs × 4659 B ≈ 76 MB of witness state that is
     * empty in every round that does not view-change.
     *
     * OWNERSHIP: allocated (checked, at most DNAC_MAX_ACTIVE_VALIDATORS
     * entries) by the two sites that accept a prepared cert —
     * nodus_witness_bft_initiate_view_change (self-record into slot 0)
     * and nodus_witness_bft_handle_viewchg (peer cert, after quorum
     * verify). Released ONLY by nodus_witness_vc_record_clear, which is
     * the single replacement for what used to be a memset of the record:
     * every reset / reuse / target-change site and nodus_witness_close
     * call it. n_sigs is 0 whenever sigs is NULL and vice versa.
     *
     * The record is therefore NOT memcpy-able and NOT serializable as
     * raw bytes; nothing persists it (grep: view_changes appears only in
     * nodus_witness_bft.c). Wire format is unchanged and stays
     * NODUS_T3_MAX_WITNESSES-sized (nodus_tier3.h). */
    struct {
        bool       has_prepared;
        uint64_t   height;
        uint32_t   view;
        uint8_t    tx_hash[NODUS_T3_TX_HASH_LEN];
        uint32_t   n_sigs;
        nodus_witness_prepared_sig_t *sigs;   /* heap, n_sigs entries */
    } prepared;
} nodus_witness_vc_record_t;

/**
 * Release a view-change record's heap-owned prepared sigs and zero the
 * record. THE ONLY correct way to reset a nodus_witness_vc_record_t —
 * a bare memset would leak the sigs allocation.
 */
void nodus_witness_vc_record_clear(nodus_witness_vc_record_t *vc);

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

    /* PR 3 / E3 — H-1 per-source rate limit on incoming w_chain_q.
     * A sign-amplification adversary spams w_chain_q expecting a
     * Dilithium5-signed w_chain_r per request — this timestamp records
     * the last response we sent to this peer (monotonic ms) so the
     * bootstrap handler can drop excess requests inside the
     * NODUS_W_BOOTSTRAP_CHAIN_Q_MIN_INTERVAL_MS window. */
    uint64_t    last_chain_q_response_ms;
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
    /* F17 A4 — my_index field removed. Consensus paths resolve
     * self-identity on-demand via committee_find_pubkey against
     * w->server->identity.pk.bytes. Transport paths that need
     * "skip self" use memcmp of witness_id against w->my_id. */

    /* Roster */
    nodus_witness_roster_t  roster;

    /* BFT consensus state */
    uint64_t    current_round;
    uint32_t    current_view;
    uint64_t    last_committed_round;
    nodus_witness_round_state_t round_state;

    /* View change tracking. S3: sized to DNAC_MAX_ACTIVE_VALIDATORS —
     * view-change quorum is dna_bft_quorum(active_set_size), which at
     * n = 128 is 86, so a 7-slot array would make a view change
     * unreachable on a large active set. Each record's prepared.sigs is
     * heap-owned; clear a slot ONLY through
     * nodus_witness_vc_record_clear. */
    nodus_witness_vc_record_t view_changes[DNAC_MAX_ACTIVE_VALIDATORS];
    int         view_change_count;
    uint32_t    view_change_target;
    bool        view_change_in_progress;

    /* BFT config (computed from roster) */
    nodus_witness_bft_config_t  bft_config;

    /* Dynamic roster — epoch-based refresh. F17 A2: transport-only now
     * (peer discovery / witness_id→pubkey lookup). BFT config comes
     * from the chain committee at round-start, not from this roster. */
    uint64_t    last_epoch;                     /* Timestamp of last roster rebuild */
    nodus_witness_roster_t  pending_roster;     /* Built each epoch from DHT + peers */
    bool        pending_roster_ready;           /* Pending roster waiting to swap */

    /* Zone chain ID */
    uint8_t     chain_id[32];

    /* Ledger V2 (INACTIVE) — optional domain-runtime table override.
     * NULL = the compiled production table (nodus_runtime_builtin_table).
     * Tests inject synthetic runtimes here to exercise the GENERIC
     * registry/dispatch boundary; production never sets it. */
    const struct nodus_domain_runtime *v2_runtime_table;
    size_t                             v2_runtime_table_n;

    /* CC-OPS-005 / Q17 — chain_config observability counters.
     *
     * Framework-agnostic: plain uint64_t counters on the witness struct,
     * bumped by the apply path. Ops can poll these via the existing
     * nodus-status surface or a periodic journal dump (see
     * nodus_witness_chain_config_log_stats). Matches the
     * CHAIN_CONFIG_PROPOSAL log literal used as a tripwire elsewhere;
     * these counters provide the "how many" alongside each log line's
     * "which".
     *
     * Not atomic — nodus witness thread model treats these as single-
     * writer from the apply path. */
    uint64_t    chain_config_proposals_committed;   /* INSERT success */
    uint64_t    chain_config_proposals_rejected;    /* apply path rejected */
    uint64_t    chain_config_cache_hits;            /* get_u64 cache hit */
    uint64_t    chain_config_cache_misses;          /* get_u64 cache miss / warm-up */
    uint64_t    chain_config_peer_schema_mismatch;  /* CC-OPS-002 mismatch counter */

    /* CC-OPS-003 / Q15 Stage C.3 — per-proposer rate-limit state for the
     * w_cc_vote_req handler. Embedded (not heap) so it's zero-initialized
     * with the rest of the witness struct and needs no explicit free. */
    nodus_cc_rate_limit_table_t  cc_rate_limit;

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
     * Sized to hold every governed param × 64 rows — far more than any
     * chain governance would ever produce. The first dimension is derived
     * from DNAC_CFG_PARAM_MAX_ID (index 0 is unused, param ids start at 1)
     * so adding a param id cannot leave the new param silently
     * unreachable behind a stale literal. */
    struct {
        uint64_t new_value;
        uint64_t effective_block;
    }           chain_config_cache[DNAC_CFG_PARAM_MAX_ID + 1][64];
    int         chain_config_cache_count[DNAC_CFG_PARAM_MAX_ID + 1]; /* rows per param */
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

    /* v0.16 stage A.5: block_fee_pool field removed — fees no longer
     * accumulate in RAM. Stage C.3 wires route_tx_fee() to burn fees
     * directly into total_burned. */

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
     * S3: sized to DNAC_MAX_ACTIVE_VALIDATORS (128) members ×
     * (2592 pubkey + 8 total_stake + 8 self_stake + 2 commission) ≈
     * 333 KB. Kept in-struct rather than malloc-d because
     * nodus_witness_t itself is already heap-allocated
     * (nodus/src/server/nodus_server.c:6078).
     *
     * cached_committee_self_stakes is the S3 addition that closes the
     * cache's old asymmetry: before it, a cache HIT reported
     * nodus_committee_member_t.self_stake as 0 while a cache MISS
     * reported the real bond. A cache hit must produce the same answer
     * as a cache miss (root CLAUDE.md, "Verify cache symmetry"), so the
     * bond now has its own parallel array and both paths agree. */
    uint64_t        cached_committee_epoch_start;
    int             cached_committee_count;
    uint8_t         cached_committee_pubkeys[DNAC_MAX_ACTIVE_VALIDATORS][DNAC_PUBKEY_SIZE];
    uint64_t        cached_committee_stakes[DNAC_MAX_ACTIVE_VALIDATORS];
    uint64_t        cached_committee_self_stakes[DNAC_MAX_ACTIVE_VALIDATORS];
    uint16_t        cached_committee_commission_bps[DNAC_MAX_ACTIVE_VALIDATORS];

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

    /* C3 fix — safety halt on state_root divergence.
     *
     * Set by commit_batch/finalize_block when the follower's locally
     * computed state_root doesn't match the leader's claim. Once set,
     * every BFT handler refuses to participate: no PREVOTE, no PRECOMMIT,
     * no COMMIT applied, no new PROPOSE issued. The operator must
     * investigate (divergence root cause) and restart the process after
     * remediation. halt_block_height records the height at which the
     * divergence was detected for diagnostics. */
    bool        safety_halt;
    uint64_t    halt_block_height;
    /* 2026-05-02 audit B-3 + C-4 + M-3 — halt-recovery snapshot.
     *
     * Set when finalize_block latches safety_halt. Pinning the
     * committee at halt_block_height defends against an attacker
     * spawning phantom committee members during the halt window to
     * inflate disagree-quorum votes — halt_recovery_check (Faz 4D-E)
     * counts only members of THIS snapshot, not the gossip-current
     * roster. halt_timestamp drives the 60s cooldown gate (M-3
     * expedite). halt_committee_count == 0 means snapshot capture
     * itself failed; halt_recovery_check treats this as inconclusive
     * and blocks auto-drop. */
    uint64_t    halt_timestamp;
    /* Pubkey snapshot only — sufficient for membership check during
     * halt-recovery quorum tally. Mirrors cached_committee_pubkeys
     * pattern below to avoid pulling nodus_committee_member_t into
     * this header. */
    /* S3: sized to DNAC_MAX_ACTIVE_VALIDATORS (≈332 KB in-struct). The
     * halt-recovery quorum is derived from halt_committee_count — the
     * PINNED snapshot's size — not from the live bft_config, because
     * checking a CURRENT quorum against a HISTORICAL membership is the
     * current-set substitution S3 forbids
     * (nodus_witness_sync.c::nodus_witness_halt_recovery_check). */
    uint8_t     halt_committee_pubkeys[DNAC_MAX_ACTIVE_VALIDATORS][DNAC_PUBKEY_SIZE];
    int         halt_committee_count;

    /* C5 — PBFT prepared-cert tracker.
     *
     * When PREVOTE quorum reached for (view, height, tx_hash), populate
     * this slot with the 2f+1 prevoter sigs over PREPARED preimage.
     * Cleared on successful commit_batch of that block, or on a NEW_VIEW
     * that rolls past this height. Carried on VIEW_CHANGE so the new
     * leader respects the "re-propose highest prepared or null" rule.
     *
     * S3 — sigs[] is sized to DNAC_MAX_ACTIVE_VALIDATORS. It used to be a
     * literal 64 (mislabelled "NODUS_T3_MAX_WITNESSES", which is 128), so
     * the populate loop's own bound of NODUS_T3_MAX_WITNESSES was already
     * 2× the array; that was unreachable only because prevote_count was
     * capped at 7. With a dynamic active set both bounds are now the same
     * named constant.
     *
     * ⚠ This one STAYS IN-STRUCT and is deliberately NOT a heap pointer,
     * unlike nodus_witness_vc_record_t::prepared::sigs. The whole struct
     * is persisted as RAW BYTES into pbft_state.last_prepared_blob
     * (nodus_witness_db.c:2095) and restored with memcpy (:2137); a
     * pointer field there would be written to disk and read back dangling.
     * The size change is absorbed by the loader's existing
     * blob_len != sizeof(w->last_prepared) guard (:2136-2147), which
     * discards the row and leaves present=false — the documented
     * migration mechanism for exactly this (:2071-2074). */
    struct {
        bool      present;
        uint64_t  height;
        uint32_t  view;
        uint32_t  round;
        uint8_t   tx_hash[64];                     /* NODUS_T3_TX_HASH_LEN */
        uint32_t  n_sigs;
        struct {
            uint8_t voter_id[32];                 /* NODUS_T3_WITNESS_ID_LEN */
            uint8_t signature[4627];              /* NODUS_SIG_BYTES */
        } sigs[DNAC_MAX_ACTIVE_VALIDATORS];
    } last_prepared;

    /* C5 — NEW_VIEW re-proposal binding.
     *
     * Set in handle_newview when the leader's NEW_VIEW arrives with
     * has_reproposal=true: this witness will only accept a PROPOSE
     * matching reproposal_tx_hash at reproposal_height as the first
     * proposal under the new view. Cleared on first matching PROPOSE
     * (gate satisfied) or on a subsequent NEW_VIEW that resets. */
    bool        reproposal_required;
    uint64_t    reproposal_height;
    uint8_t     reproposal_tx_hash[NODUS_T3_TX_HASH_LEN];

    /* PR 3 Yol B — auto-bootstrap state machine fields.
     *
     * bootstrap_state moves through INIT → HAVE_CHAIN | DISCOVER →
     * FETCH_GENESIS → BOOTSTRAP_CONFIG → DONE during witness startup.
     * After DONE the existing nodus_witness_sync_check + replay path
     * takes over; nothing in steady state mutates these fields.
     *
     * bootstrap_settle_until_ms (H-4 mitigation): wall-clock deadline
     * after which this witness will accept being elected leader. While
     * the field is in the future the leader-election path treats this
     * node as ineligible so a mid-round bootstrap completion does not
     * disrupt an in-flight consensus round on peers. Set when state
     * transitions out of BOOTSTRAP_CONFIG; 0 means "no settle window
     * required" (legacy / pre-bootstrap nodes). */
    int         bootstrap_state;            /* nodus_witness_bootstrap_state_t */
    uint64_t    bootstrap_settle_until_ms;

    /* DISCOVER-state retry + quorum tracking. attempt counts the
     * w_chain_q rounds emitted (1..10); next_attempt_ms is the
     * monotonic wall after which the next w_chain_q broadcast may
     * fire (exponential backoff schedule from design Section 3);
     * round_deadline_ms is the monotonic wall after which the current
     * round's collect window expires. round_nonce is the random 16B
     * seed echoed back in w_chain_r — captured responses with a stale
     * nonce do not count toward quorum. */
    int         bootstrap_attempt;
    uint64_t    bootstrap_next_attempt_ms;
    uint64_t    bootstrap_round_deadline_ms;
    uint8_t     bootstrap_round_nonce[16];   /* NODUS_W_BOOTSTRAP_NONCE_LEN */

    /* PR 3 / E2 — bootstrap observability. discover_entered_ms is the
     * monotonic timestamp at which the state machine first transitioned
     * into DISCOVER (set ONCE per bootstrap_start; not reset across
     * round attempts). last_heartbeat_log_ms is the last hourly stuck-
     * in-DISCOVER heartbeat we emitted; both 0 outside DISCOVER. The
     * heartbeat fires once per hour while DISCOVER persists past the
     * first hour so an operator monitoring journalctl sees a steady
     * pulse rather than going silent. */
    uint64_t    bootstrap_discover_entered_ms;
    uint64_t    bootstrap_last_heartbeat_log_ms;

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

#ifdef QGP_FAULT_INJECT
/**
 * Faz 5.4 — Fault injection: drop-frame predicate.
 *
 * When set, dispatch_t3 calls the predicate against every decoded
 * inbound T3 message. Predicate returning true causes the message
 * to be silently dropped (handler never invoked) — used by stagef
 * harness to simulate network partition / round skip without
 * iptables. Pass NULL to clear.
 *
 * `msg` is a `const nodus_t3_msg_t *` — declared as `void *` in
 * the public header to avoid pulling protocol/nodus_tier3.h into
 * every consumer. Tests cast back to `nodus_t3_msg_t *` when
 * dereferencing fields.
 *
 * Compiled in only when -DQGP_FAULT_INJECT=ON. Release builds
 * reject the flag at CMake time (mirrors NODUS_WITNESS_TEST_HOOKS).
 */
typedef bool (*nodus_witness_drop_predicate_t)(
    const void *msg, const uint8_t *peer_id);

void nodus_witness_test_inject_drop(nodus_witness_drop_predicate_t pred);
#endif /* QGP_FAULT_INJECT */

/**
 * Create chain-specific witness DB on genesis commit.
 * Filename: witness_<chain_id_hex>.db in data directory.
 * Sets chain_id and opens the new database.
 */
int nodus_witness_create_chain_db(nodus_witness_t *witness,
                                    const uint8_t *chain_id);

/**
 * PR 3 / E0 — Orphan bootstrap sentinel check (H-7 startup-side closure).
 *
 * The bootstrap path writes <data_path>/.bootstrap_in_progress BEFORE
 * any chain-DB mutation in handle_genesis_rsp, and unlinks it on the
 * success path. If we boot and the file is still present, a previous
 * FETCH_GENESIS crashed mid-write — partial chain DB may exist with a
 * placeholder block 1 row whose state is NOT authoritative.
 *
 * Action: archive every witness_<hex>.db* file under <data_path> into
 * <data_path>/archive/, unlink the sentinel, and return 1 so the
 * caller knows a recovery occurred. The witness_scan_chain_db() that
 * runs next will then find an empty data_path and the bootstrap state
 * machine will re-run DISCOVER on a clean slate.
 *
 * Returns: 0 if no sentinel present (no-op),
 *          1 if sentinel was present and recovery completed,
 *         -1 on any internal error (caller MUST refuse init).
 */
int nodus_witness_check_orphan_bootstrap_sentinel(const char *data_path);

/**
 * Phase 6 / Task 31 — read the current block fee pool.
 *
 * Returns the accumulated native DNAC fee amount for the in-progress
 * v0.16 stage A.5: nodus_witness_get_block_fee_pool removed with the
 * underlying block_fee_pool field.
 */

#ifdef __cplusplus
}
#endif

#endif /* NODUS_WITNESS_H */
