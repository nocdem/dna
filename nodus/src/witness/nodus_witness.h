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
/* Ledger V2 S9 — pool boundary crossings. MUST equal DNAC_TX_SHIELD = 12 /
 * DNAC_TX_UNSHIELD = 13 (dnac_tx_type_t, dnac/include/dnac/dnac.h). Both are
 * V3-ONLY: they are carried exclusively by the V3 wire and are inadmissible on
 * the legacy V2 wire, whose acceptance set is FROZEN at 0..11. Admission is
 * REJECT-unconditional until activation — nodus_witness_verify.c rejects them
 * by name right after the tx-hash check. Type 14 stays UNASSIGNED. */
#define NODUS_W_TX_SHIELD           12
#define NODUS_W_TX_UNSHIELD         13
/* O15C — Ledger V2 activation authority (legacy-wire governance types).
 * RETIRED by O15J Faz 3, which deleted the activation ceremony: a V2 chain
 * is born V2, so there is no transition for these to schedule or signal.
 * The ids are KEPT DEFINED and PERMANENTLY INADMISSIBLE — no build accepts
 * them, nodus_witness_verify.c rejects both by name right after the
 * tx-hash check, and 15/16 are never reused for a new type. Type 14 stays
 * UNASSIGNED. */
#define NODUS_W_TX_V2_SCHEDULE      15
#define NODUS_W_TX_V2_READY         16
/* O15D — TRANSPORT-LOCAL discriminator for a Ledger V2 ENVELOPE riding
 * the witness mempool / T3 batch surfaces on a SUCCESSOR chain. This is
 * NOT a chain transaction type: the dnac_tx_type_t space is untouched
 * (14 stays UNASSIGNED), no wire walker or verify lane keys on it, and
 * the AUTHORITY for classification is always the envelope's 16-byte
 * wire-family marker at offset 0 ("DNA.ENVWIRE.v1", env_wire.h) — this
 * value only labels an entry whose bytes already carried that marker.
 * Deliberately far outside the chain type space so a collision with a
 * future chain type is impossible to miss. */
#define NODUS_W_TX_V2_ENVELOPE      200

/* O15F Task 3 — TRANSPORT-LOCAL discriminator for a Ledger V2 CLAIM
 * riding the witness mempool / T3 batch surfaces on a SUCCESSOR chain.
 * Like NODUS_W_TX_V2_ENVELOPE this is NOT a chain transaction type: a
 * claim has NO live wire type (the dnac_tx_type_t space and types 11-14
 * are untouched), no wire walker keys on it, and the classification
 * AUTHORITY is byte-driven — an entry whose bytes do NOT begin with the
 * envelope wire-family marker ("DNA.ENVWIRE.v1", env_wire.c:25-27) on a
 * successor is a claim; strict dna_claim_decode + admission decide
 * validity. Deliberately adjacent to 200 and far outside the chain type
 * space so a collision is impossible to miss. */
#define NODUS_W_TX_V2_CLAIM         201

/* O15F Task 1 — the SUCCESSOR active-set maximum.
 *
 * THE INVARIANT: on a successor chain no `validator_set_snapshots` row
 * with active_count > NODUS_V2_ACTIVE_SET_MAX can ever be PERSISTED. The
 * persisted snapshot is the SOLE committee authority
 * (nodus_committee_get_for_block serves it RAW to every live consumer),
 * so bounding every WRITE / SEED / RESOLVE point makes every reader safe
 * WITHOUT a divergence-prone reader clamp. Enforced fail-closed at the
 * target clamps (committee_target_for_epoch / vset_target_for_epoch), the
 * writer (nodus_witness_vset_insert), the resolver
 * (nodus_witness_v2_epoch_authority_for_epoch) and the seam
 * (early v2_successor + terminal-set precondition + carried-CC reject).
 * LEGACY chains keep the DNAC_MAX_ACTIVE_VALIDATORS ceiling byte-for-byte
 * (every guard is gated on w->v2_successor / the seam's successor build).
 * 30 <= 128, so all round-state / QC / vote arrays already fit. */
#define NODUS_V2_ACTIVE_SET_MAX     30
_Static_assert(NODUS_V2_ACTIVE_SET_MAX <= DNAC_MAX_ACTIVE_VALIDATORS,
               "successor active-set max exceeds resource ceiling");

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
    /* O15H — `max_view_changes` REMOVED. It was written by
     * nodus_witness_bft_config_init and read by nothing, anywhere in the
     * tree. Kept next to the new view-change ESCALATION in
     * nodus_witness_bft_check_timeout it would read as the bound on that
     * escalation, which it never was — and a cap there would only
     * restore the dead end the escalation exists to remove. Deleted
     * rather than wired up (No Dead Code). */
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

/* ── O15C-C D2 — pending (out-of-order) vote entry ───────────────────
 * Field-for-field mirror of nodus_t3_vote_t plus the header fields the
 * vote handler consumes; mirrored rather than embedded so this header
 * does not grow a protocol/nodus_tier3.h dependency. bft.c copies
 * field-by-field in both directions (no type punning). */
#define NODUS_W_VOTE_BUFFER_CAP          32
/* Only rounds this close ahead of the live/settled round are buffered;
 * anything further is treated exactly as before (ignored as stale/far). */
#define NODUS_W_VOTE_BUFFER_ROUND_AHEAD  2

typedef struct {
    bool        used;
    uint8_t     msg_type;       /* NODUS_T3_PREVOTE / NODUS_T3_PRECOMMIT */
    uint64_t    round;
    uint32_t    view;
    uint8_t     sender_id[NODUS_T3_WITNESS_ID_LEN];
    uint8_t     vote_target[NODUS_T3_TX_HASH_LEN];
    uint32_t    vote;
    char        reason[256];
    uint8_t     cert_sig[NODUS_SIG_BYTES];
} nodus_witness_pending_vote_t;

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

    /* O15G HIGH-1 — per-peer invalid-cert cooldown (LOCAL liveness-only,
     * NEVER a consensus input). Stamped to time(NULL) + a bounded window
     * when THIS peer served a sync response whose certs were CONSENSUS_INVALID
     * against the committed committee (nodus_witness_sync_handle_rsp). While
     * unexpired, nodus_witness_sync_find_peer / _rotate_peer SKIP this peer, so
     * a Byzantine height-inflating peer that serves an invalid cert is not
     * re-selected while an honest peer (any index) is reachable. It self-expires
     * (a transiently-behind honest peer is never permanently blacklisted) and
     * only steers WHICH peer to ask — it can never change an accept/reject
     * verdict. 0 = not in cooldown. Peer slots may be reused by a different
     * identity across reconnects; the field self-expires, so a stale stamp
     * on a reused slot at worst delays one sync tick. */
    uint64_t    sync_bad_until;             /* time(NULL) deadline; 0 = clear */
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
    /* O15C-C D1 — whether THIS node has broadcast + self-recorded its
     * own VIEW_CHANGE vote for view_change_target. Receiving a peer's
     * VIEW_CHANGE sets view_change_in_progress (the join path), which
     * used to make nodus_witness_bft_initiate_view_change a silent
     * no-op at the joiner's own round timeout — six of seven votes were
     * never sent and view-change quorum was structurally unreachable
     * (2026-08-19 rehearsal, round 20). Cleared whenever the target
     * changes, the view change completes, or the view-change timeout
     * resets to IDLE. In-memory only, never persisted. */
    bool        view_change_voted;

    /* O15I P2 — POST-VIEW-CHANGE PROPOSE-WAIT DEADMAN.
     *
     * Absolute time_ms() deadline by which the new leader must have
     * produced work; 0 means DISARMED. Armed only in the aftermath of a
     * COMPLETED view change, and only on a node that is NOT the new
     * leader (the leader must SEND, not wait — arming it would make it
     * time out against itself).
     *
     * THE HOLE IT CLOSES. Both completion sites put the node back to
     * NODUS_W_PHASE_IDLE (nodus_witness_bft.c: the vc-quorum completion
     * and the NEW_VIEW accept), and nodus_witness_bft_check_timeout
     * returns at its first branch from IDLE — so an IDLE node arms
     * nothing and can never initiate a view change. Only the leader
     * leaves IDLE on its own (nodus_witness.c:1153-1162, mempool-driven).
     * If the rotation lands on a leader that is dead or silent, EVERY
     * node sits IDLE forever and the chain halts with no recovery path:
     * the 20-node terminal state. Two comments in bft.c (:7049, :7623)
     * already promise "our round then times out and rotates the view" —
     * behaviour that could not happen from IDLE.
     *
     * NOT PERSISTED, deliberately: this is consensus-local TIMING state,
     * not a decision. A restart comes up disarmed, which is the correct
     * conservative default — a fresh node has made no observation about
     * the new leader's liveness, and the ordinary round timeout, the
     * peers' VIEW_CHANGEs and the f+1 join all still reach it. Writing a
     * wall-clock deadline through a restart would be the opposite: a
     * stale absolute timestamp deciding a consensus action.
     *
     * NOT part of any signed message, vote, block or state_root — it can
     * only ever decide WHEN this node asks for a rotation, never WHAT it
     * votes. `current_view` is untouched by the whole mechanism. */
    uint64_t    awaiting_propose_deadline_ms;

    /* O15I P3 — DEMAND-ARMED FOLLOWER DEADMAN (the observation pair).
     *
     * `last_seen_tip` is the committed chain height this node last
     * OBSERVED, and `tip_since_ms` the time_ms() instant at which it was
     * first observed to hold. `tip_since_ms == 0` means DISARMED — the
     * window is not running, which is the state of every node with no
     * pending demand.
     *
     * THE HOLE IT CLOSES — the one P2 does not. P2 arms only in the
     * aftermath of a COMPLETED view change. But `leader = (epoch + view)
     * % n` with `epoch = height / DNAC_EPOCH_LENGTH` gives ONE leader an
     * entire epoch (720 heights in production), and only the leader ever
     * leaves IDLE on its own (nodus_witness.c, the mempool-driven block
     * timer). So when the epoch leader dies with NO view change in
     * flight, every node sits IDLE at view 0, check_timeout returns at
     * its first branch, and NOTHING spontaneously initiates a rotation:
     * the 20-node rehearsal's height 43 had ZERO consensus events of any
     * kind and all 20 nodes ended IDLE at view 0. A f+1 join CAN pull an
     * IDLE node in (handle_viewchg has no phase gate) — what was missing
     * is a node willing to ask FIRST.
     *
     * WHY THE PAIR AND NOT A SINGLE STAMP. "The tip has not moved for
     * longer than a round" is the only local, message-free evidence a
     * follower has that the leader is not producing. It needs both the
     * height that is stuck AND when it got stuck; one field cannot carry
     * both, and re-deriving "when" from phase_start_time would read a
     * round that ended long ago.
     *
     * NOT PERSISTED, for P2's reason exactly: this is consensus-local
     * TIMING state, not a decision. A restart comes up disarmed, which
     * is the correct conservative default — a fresh node has made no
     * observation about anyone's liveness.
     *
     * NOT part of any signed message, vote, block or state_root. Like
     * P2's deadline it can only ever decide WHEN this node ASKS for a
     * rotation, never WHAT it votes; `current_view` is untouched by the
     * whole mechanism (only bft.c:7703 moves it on quorum). */
    uint64_t    last_seen_tip;
    uint64_t    tip_since_ms;

    /* O15C-C D2 — bounded out-of-order vote buffer. A PREVOTE/PRECOMMIT
     * that arrives before this node has initialized the round it
     * belongs to (proposal still in flight), or a PRECOMMIT arriving
     * while this node is still in PREVOTE phase of the same round, used
     * to be dropped SILENTLY by handle_vote's round/phase equality
     * checks. Under timing skew that dropped enough votes to make
     * quorum unreachable (2026-08-19 rehearsal round 20: three nodes
     * each missed prevote quorum by exactly one). Near-future votes are
     * parked here and re-fed through the ordinary vote handler when the
     * round/phase catches up; replay and chain-id were checked at first
     * arrival, and cert_sig + committee authorization are checked at
     * drain time by the ordinary handler. */
    nodus_witness_pending_vote_t vote_buffer[NODUS_W_VOTE_BUFFER_CAP];

    /* BFT config (computed from roster) */
    nodus_witness_bft_config_t  bft_config;

    /* Dynamic roster — epoch-based refresh. F17 A2: transport-only now
     * (peer discovery / witness_id→pubkey lookup). BFT config comes
     * from the chain committee at round-start, not from this roster. */
    uint64_t    last_epoch;                     /* Timestamp of last roster rebuild */
    nodus_witness_roster_t  pending_roster;     /* Built each epoch from DHT + peers */
    bool        pending_roster_ready;           /* Pending roster waiting to swap */

    /* O15I V1 — the P3(c) reaper's ONCE-PER-EPOCH latch.
     *
     * The reaper's gate is `nodus_time_now() - last_epoch < 2`, which is a
     * ~2 s WINDOW and not an edge, and the tick runs ~20x/s — so the scan
     * actually ran ~40 times per epoch. That was affordable while the
     * verdict was one indexed nullifier lookup per entry. It is NOT
     * affordable now that a successor class-200 entry costs a strict
     * decode plus the full commitment derivation
     * (nodus_witness_v2_entry_verdict), which cannot be cached on the
     * entry. This field records the `last_epoch` value the reaper last ran
     * FOR, so the window produces exactly one scan.
     *
     * 0 is the correct calloc default rather than a special case:
     * `last_epoch` is 0 until the first epoch tick, and for that whole
     * period `nodus_time_now() - 0 < 2` is false, so the reaper is not
     * reachable and the latch cannot block a pass that would have run.
     *
     * Node-local TIMING state, exactly like the P2/P3 fields above: it
     * decides WHEN this node reaps its own INPUT pool, never what it
     * votes. Not persisted, not signed, not part of any root. */
    uint64_t    last_evict_epoch;

    /* Zone chain ID */
    uint8_t     chain_id[32];

    /* O15G HIGH-2 — the DISCOVER-agreed genesis chain_def hash, persisted from
     * bootstrap (nodus_witness_bootstrap.c, after create_chain_db succeeds) so
     * the legacy genesis-sync leg can bind the synced genesis to the anchor the
     * quorum agreed on. `g_quorum_cdh` is SHA3-512 over the DISCOVER-quorum's
     * chain_def blob (== SHA3-512 of the same verbatim chain_def_blob bytes the
     * genesis TX carries as its trailer). When `g_quorum_cdh_set` is true the
     * genesis-sync leg verifies block-1 certs against the ANCHORED chain_def's
     * own validator set — NOT the DHT roster (design §7.6 / §8.1). A
     * genesis-creating founder or a legacy no-bootstrap fixture leaves it unset,
     * and that path keeps the legacy roster genesis leg. In-memory only:
     * bootstrap → sync is one process, so no DB schema is needed. */
    uint8_t     g_quorum_cdh[64];
    bool        g_quorum_cdh_set;

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
        /* O15J Faz 3 — stall watchdog. Stamped every time a block
         * REQUEST goes out (sync start + each request_next), i.e. every
         * time the sync demonstrably moved forward. Deliberately NOT
         * last_sync_attempt: that one is stamped by sync_check's guard
         * pass and never refreshed by the response path, so a healthy
         * multi-block catch-up would look stalled through it.
         *
         * `syncing` is otherwise a ONE-WAY latch — every clear of it
         * lives on a response path, so a response that never arrives
         * (peer died mid-sync, frame dropped, peer serves nothing)
         * wedges the node out of sync permanently. See
         * SYNC_STALL_TIMEOUT_SEC in nodus_witness_sync.c. */
        uint64_t    sync_last_progress;   /* last request sent (timestamp) */
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
    /* O15C-D.3 — the bound certificate's VIEW. Needed for two things:
     * the D.2 comparator's equal-height discriminator when deciding
     * whether a NEW_VIEW's carried certificate outranks our own binding,
     * and locating the matching record when we are the leader shipping
     * that certificate. Meaningless when reproposal_required is false. */
    uint32_t    reproposal_prepared_view;

    /* MED-28 (O15C-D) — retained batch for NEW_VIEW reproposal.
     *
     * The C5 rule above binds the new view's first PROPOSE to a
     * (height, tx_root) DIGEST. last_prepared carries the cert but NOT
     * the transaction bytes, and the round-timeout path used to free
     * round_state.batch_entries outright — so once a view change
     * completed with a prepared cert, NO node held the bytes needed to
     * satisfy the binding and every proposal at that height was
     * rejected forever. Retaining the timed-out batch here (ownership
     * MOVED out of round_state, not copied) lets the new leader
     * re-propose the exact entries: start_round_from_entries recomputes
     * block_hash from the same tx_hashes in the same order, so the
     * tx_root matches the bound digest by construction.
     *
     * ⚠ Heap pointers — this struct is in-memory only and must NEVER be
     * persisted the way last_prepared is (witness.h:672).
     * Cleared when the chain advances past `height`, or when a newer
     * batch times out. */
    struct {
        bool      present;
        uint64_t  height;
        uint8_t   tx_root[NODUS_T3_TX_HASH_LEN];
        int       count;
        nodus_witness_mempool_entry_t *entries[NODUS_W_MAX_BLOCK_TXS];
    } retained_batch;

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

    /* ── Ledger V2 ingress reachability (O15B) ───────────────────────
     *
     * `v2_ingress_armed` is the ONLY thing that makes a V2 wire message
     * dispatchable on this node. It is set exclusively by
     * nodus_witness_v2_ingress_arm(), which refuses unless the activation
     * gate is OPEN — and the gate can never be OPEN in this build (no
     * committed activation authority exists, and the preflight is
     * structurally never ready). See nodus_witness_v2_gate.h.
     *
     * It is deliberately a RUNTIME field and not a persisted one: a
     * database bit would be an operator override by another name, and the
     * ruling for this season forbids any such bypass. It is also what
     * preflight issue 13 (INGRESS_ENABLED) is COMPUTED from, so the
     * preflight reports what this node is actually doing rather than
     * arguing from the structural claim that ingress code does not exist
     * — a claim O15B itself retired by writing that code.
     *
     * `v2_gate_test_*` exist only in builds that define
     * NODUS_V2_TEST_AUTHORITY (test targets only; absent from libnodus and
     * nodus-server, proven by `nm` in test_v2_gate_linked). They are
     * declared unconditionally so the struct layout does not depend on a
     * build flag — a layout that changed with a test macro would make
     * every test exercise a different object than production does. */
    bool        v2_ingress_armed;
    bool        v2_gate_test_authority;
    bool        v2_gate_test_allow_unready;

    /* ── Ledger V2 successor production (O15D) ────────────────────────
     *
     * `v2_successor` is derived at every database open from COMMITTED
     * state only (the height-0 successor genesis manifest carrying the
     * "DNA.LEGACY.TERM.v1" source binding — the same committed authority
     * the activation gate reads); no env var, flag, config or peer input
     * can set it. While true, this chain's producer/verify/commit paths
     * run the Ledger V2 engine and the LEGACY lanes (genesis, spend
     * apply, legacy sync, legacy cert store) refuse — a successor chain
     * never produces a legacy block.
     *
     * `v2_chain32` caches nodus_witness_v2_chain_id() (derived from the
     * committed genesis BlockID) for the QC-cert preimages and envelope
     * admission; valid only while v2_successor is true.
     *
     * `v2_certpool` is the bounded per-height DNA.CERT.v2 collection for
     * the block currently being finalized — the post-commit certificate
     * exchange that assembles the QC (see nodus_witness_v2_produce.h).
     * RUNTIME state only: it is rebuilt by the ordinary round flow and
     * deliberately not persisted. */
    bool        v2_successor;
    uint8_t     v2_chain32[32];
    struct {
        uint64_t height;                 /* 0 = pool empty               */
        bool     committed;              /* local block at height landed */
        bool     qc_attached;            /* QC persisted for this height */
        uint8_t  local_block_id[64];     /* engine-derived (committed)   */
        uint8_t  vset_hash[64];          /* engine out_vset_hash         */
        uint32_t n;
        struct {
            uint8_t voter_id[NODUS_T3_WITNESS_ID_LEN];
            uint8_t block_id[64];        /* the SENDER's claimed id      */
            uint8_t sig[NODUS_SIG_BYTES];
        } slots[DNAC_MAX_ACTIVE_VALIDATORS];
    } v2_certpool;

    /* O15E Faz B — the successor sync driver's RUNTIME state (never
     * persisted; LOCAL policy only, nothing here is consensus).
     * `req_sent_ms` == 0 means no range request is in flight; a
     * timed-out request simply expires so the next hint can re-arm.
     * `last_head_ms` throttles the w_v2_head broadcast on the tick.
     * O15E Faz C adds `last_qcfetch_ms` (the missing-QC detector's
     * pacing) and `qc_rr` (round-robin peer cursor for w_v2_block). */
    struct {
        uint8_t  req_peer[NODUS_T3_WITNESS_ID_LEN];
        uint64_t req_from;
        uint32_t req_count;
        uint64_t req_sent_ms;            /* monotonic; 0 = idle          */
        uint64_t last_head_ms;
        uint64_t last_serve_ms;          /* H-1 sign-amplification guard */
        uint64_t last_qcfetch_ms;
        uint32_t qc_rr;
    } v2_sync;

    /* O15E Faz D — pinned-genesis joiner bootstrap RUNTIME state. Active
     * only on a fresh node with a local pin and no successor chain yet;
     * cleared the moment the successor DB is adopted (the node then
     * behaves as an ordinary successor). While `active`, the node MUST
     * NOT propose or vote (role safety). Nothing here is persisted. */
    struct {
        int      active;                 /* 1 = fetching/deriving        */
        uint8_t  pin[64];                /* local trust anchor (copy)    */
        uint8_t *acc;                    /* bundle accumulator           */
        size_t   acc_len;                /* bytes received contiguously  */
        size_t   acc_total;              /* expected total (0 = unknown) */
        uint64_t last_req_ms;            /* fetch throttle               */
    } v2_join;
} nodus_witness_t;

/* ── O15G — genesis chain_id derivation (shared by commit_genesis and the
 * legacy genesis-sync anchor check) ──────────────────────────────────────
 *
 * Parse the first-recipient fingerprint out of a serialized genesis TX and
 * derive its chain_id = SHA3-256(fp_bytes(64) || tx_hash(64)). This is the
 * EXACT walk + derivation nodus_witness_commit_genesis performs inline when it
 * bootstraps a fresh chain DB (if(!w->db)); it is factored out so the genesis
 * sync leg can re-derive and cross-check the synced genesis's chain_id against
 * the DISCOVER-agreed chain the joiner bootstrapped onto — commit_genesis
 * SKIPS that check on a bootstrapped joiner (w->db already set). Pure wire
 * walk, no state.
 *
 * @param tx_data       serialized genesis TX
 * @param tx_len        length of tx_data
 * @param tx_hash       the genesis TX hash (64 bytes)
 * @param out_chain_id  32-byte derived chain_id
 * @return 0 on success, -1 on NULL args / truncated tx / bad fingerprint
 */
int nodus_witness_genesis_derive_chain_id(const uint8_t *tx_data,
                                          uint32_t tx_len,
                                          const uint8_t *tx_hash,
                                          uint8_t *out_chain_id);

#ifdef NODUS_WITNESS_INTERNAL_API
/* ── O15G HIGH-1 — sync peer selection (test-visible internals) ───────────
 * Un-static'd from nodus_witness_sync.c so the cooldown behaviour can be unit
 * tested directly. Both SKIP a peer whose sync_bad_until cooldown is unexpired
 * (time(NULL) timebase). find_peer scans all peers for the highest reachable
 * one ABOVE local height; rotate_peer scans FORWARD ONLY (strictly higher
 * index) for another reachable peer at the stuck height. Peer scoring is
 * node-local liveness steering — never a quorum/verdict input. */
int nodus_witness_sync_find_peer(nodus_witness_t *w);
int nodus_witness_sync_rotate_peer(nodus_witness_t *w);
#endif /* NODUS_WITNESS_INTERNAL_API */

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

/** H-15 / MED-27 (O15C-D) — expire pending forwards older than
 * NODUS_W_PENDING_FWD_TIMEOUT_S and send each waiting client an explicit
 * NODUS_ERR_TIMEOUT, so an accepted dnac_spend can never end without an
 * answer. `now_s` is a parameter rather than a clock read so the
 * contract is testable deterministically. @return slots expired. */
int nodus_witness_pending_forward_expire(nodus_witness_t *witness,
                                           uint64_t now_s);

/**
 * O15J A — POOL-THEN-FORWARD: make a non-leader's client demand VISIBLE.
 *
 * ── THE DEFECT THIS EXISTS FOR ────────────────────────────────────────
 * PBFT's client protocol has two halves. Castro & Liskov OSDI 1999 §4.1:
 * "If the client does not receive replies soon enough, it broadcasts the
 * request to all replicas. ... If the primary does not multicast the
 * request to the group, it will eventually be suspected to be faulty by
 * enough replicas to cause a view change." §4.4's half — a backup starts
 * a timer on a request — was implemented. §4.1's half — the request
 * actually REACHES enough replicas — was not.
 *
 * A non-leader's dnac_spend intake took a pending_forwards slot and
 * forwarded, and a pending_forwards slot carries NO transaction bytes
 * (see the struct in this file: active / tx_hash / client_conn /
 * client_txn_id / started_at). When the leader could not be reached the
 * slot was released and the WORK WAS DISCARDED. Both halves of the P3
 * stall predicate (`mempool.count > 0 || pending_forward_count > 0`)
 * therefore read 0 on the one node a client was actually talking to, so
 * the stall detector could not see that anybody was waiting. Measured on
 * the 20-node rehearsal: after block 42 committed, node1 made 44 forward
 * attempts with 0 successes and "P3 committed tip frozen" fired ZERO
 * times; no round for height 43 was ever opened by any of the 14 alive
 * nodes.
 *
 * This pools the work LOCALLY, before and independently of the forward,
 * so the demand survives the forward's failure.
 *
 * ── WHY THE ENTRY IS POOLED ORPHANED (client_conn == NULL) ────────────
 * LOAD-BEARING, not stylistic. nodus_witness_peer_conn_closed runs for
 * CLIENT connections too: it clears pending_forwards by client_conn and
 * then calls nodus_witness_mempool_remove_by_conn, which matches
 * `entries[i]->client_conn == conn` and early-returns on a NULL conn. An
 * entry pooled with the LIVE client conn would therefore be deleted the
 * moment the CLI disconnects — one step after this function ran — and the
 * fix would undo itself. The orphan shape (client_conn NULL,
 * is_forwarded, forwarder_id) is exactly the one
 * nodus_witness_peer_handle_fwd_req already uses for forwarded entries,
 * so nothing downstream sees a new kind of entry. `forwarder_id` is OUR
 * id because we are the node holding the client connection: whichever
 * node ends up committing this answers w_fwd_rsp to us.
 *
 * ── BOTH LANES — O15K §3.1 REVERSED THE SUCCESSOR-ONLY RULE ───────────
 * This function used to decline on a LEGACY chain before it judged
 * anything (`!w->v2_successor -> -1`, NOT_APPLICABLE). That gate is
 * DELETED and legacy demand is pooled here exactly as successor demand
 * is, through the same admission gate.
 *
 * ⚠ THE OLD ARGUMENT, AND WHY IT WAS WRONG. It ran: a legacy peer
 * refuses a non-leader w_fwd_req byte-identically
 * (nodus_witness_peer.c:883), because legacy forward intake is
 * STRUCTURAL only — a nullifier walk, no signature verification — so
 * pooled legacy demand could never recruit the f+1 backers a rotation
 * needs and would only drive lone view changes nobody joins. Both of its
 * legs fall in the SAME change: §3.2 gives legacy forward intake the
 * admission verify it never had AND removes that peer-side refusal (its
 * fourth edit site), and §3.3 opens the dissemination that carries the
 * demand to peers at all — so legacy demand CAN now assemble f+1. And
 * the conclusion was never a safeguard in the first place: leaving
 * legacy unpooled is
 * precisely what let a dead leader wedge the chain INDEFINITELY rather
 * than for one epoch. A halted tip freezes the epoch and the leader is
 * `(epoch + view) % n` (nodus_witness_bft.c:461,504), so leadership stays
 * pinned on the dead node until a view change; the P3 deadman that would
 * start one arms on `mempool.count > 0 || pending_forward_count > 0`
 * (nodus_witness_bft.c:8682), and on the ONE node the client reached
 * BOTH inputs read zero — this gate zeroed the first, and the
 * unreachable-leader branch releases the forward slot in the same call,
 * zeroing the second. Measured: 121 forward attempts, 0 local pools, 0
 * P3 fires, 0 view-change lines on any of 9 nodes.
 *
 * ── §3.4 — A LEGACY ENTRY WITH NO NULLIFIER IS REFUSED ────────────────
 * A legacy entry's only handle is its nullifiers: the P3(c) reaper evicts
 * through a committed-nullifier walk and nodus_witness_v2_entry_verdict
 * answers UNJUDGED for every legacy chain (nodus_witness.c:1112-1114), so
 * one pooled with none is demand NOTHING can ever retire — a view change
 * every round_timeout_ms against a HEALTHY leader, the O15I V1 shape
 * through the legacy door. Refused as -2. Legacy-scoped by necessity: a
 * successor class-200 envelope legitimately carries nullifier_count == 0.
 *
 * ── THE MODE IS ADMISSION ON THIS PATH, DELIBERATELY ──────────────────
 * A direct client submission is where the node-local fee surge
 * (nodus_witness_verify.c:1154) is a meaningful intake policy: the client
 * chose THIS node and can still be told to raise its fee. §3.3a's
 * VALIDATION exemption covers FORWARDED / rebroadcast intake only, where
 * the surge would throttle the cluster's own replication.
 *
 * ── IT ADDS NO AUTHORITY ──────────────────────────────────────────────
 * The bytes pass the SAME NODUS_WITNESS_VERIFY_ADMISSION gate the leader
 * runs on a direct client submission and the same one a successor peer
 * runs on a forward, so nothing unverified reaches the pool.
 * NODUS_W_MAX_MEMPOOL still bounds it and mempool_add still rejects
 * duplicates by tx_hash.
 *
 * ── DETERMINISM ───────────────────────────────────────────────────────
 * `current_view` is NOT written here — it has exactly four write sites
 * (nodus_witness_bft.c round entry, the view-change quorum, the NEW_VIEW
 * accept, nodus_witness_db.c restore; the IDENT adoption that was the
 * fifth is DELETED, v0.19.24) and this adds none. Mempool is INPUT, not
 * consensus state: block content is still chosen by ONE leader and agreed
 * by PREVOTE/PRECOMMIT with an independent state_root recompute, so two
 * nodes holding different pools cannot diverge state. No wire format, no
 * protocol version, no schema change. Reads only the entry bytes and this
 * node's own committed DB; no clock branch, no randomness.
 *
 * ── LIFECYCLE OF WHAT IT POOLS ────────────────────────────────────────
 * Orphaned entries are unreachable by remove_by_conn BY DESIGN, so the
 * O15I P3(c) reaper (nodus_witness_mempool_evict_committed) is what
 * removes them once the chain decides them. Since O15K §3.1 this
 * function feeds it THREE populations, and the reaper routes the
 * "already decided?" question BY ENTRY CLASS — the full contract, and
 * the fault direction, are on its own declaration below:
 *   - a LEGACY entry — the committed-nullifier walk over the legacy
 *     `nullifiers` table. Its nullifiers are the ONLY handle it has,
 *     which is precisely why §3.4 above refuses to pool one that carries
 *     none: it would be demand nothing could ever retire;
 *   - a class-201 CLAIM — the same question asked of the SUCCESSOR's
 *     `v2_claims_spent` table, where a claim's nullifier is actually
 *     committed (V-3). Its nullifier is re-derived below for exactly
 *     this reason;
 *   - a class-200 ENVELOPE — nodus_witness_v2_entry_is_decided, over the
 *     committed intent index.
 *
 * @param witness         witness context.
 * @param tx_data         submitted entry bytes (borrowed; copied on pool).
 * @param tx_len          length of tx_data.
 * @param tx_hash         client-supplied 64-byte tx_hash (the pool key).
 * @param tx_type         byte-derived entry class (200 / 201 on a
 *                        successor — nodus_witness_v2_classify_entry).
 * @param nullifiers      concatenated legacy nullifiers, or NULL.
 * @param nullifier_count number of legacy nullifiers (0 on a successor).
 *                        On a LEGACY chain 0 — or a NULL nullifiers —
 *                        is REFUSED, not pooled; see §3.4 above.
 * @param client_pk       client Dilithium5 pubkey, or NULL. IGNORED by
 *                        the successor admission lane
 *                        (nodus_witness_verify.c casts it to void), but
 *                        carried onto the entry so the commit path can
 *                        answer, exactly as the leader branch does.
 * @param client_sig      client signature, or NULL. Same treatment.
 * @param fee             declared fee.
 * @param reject_reason   [out] filled on return -2; may be NULL.
 * @param reason_size     size of reject_reason.
 * @return  0  pooled now — this node's demand is visible.
 *          1  ALREADY held (duplicate tx_hash). Also visible: this is a
 *             client retry for work we are already carrying, which is why
 *             it is not an error. Answered by an explicit tx_hash
 *             pre-check rather than by letting the retry fall through to
 *             mempool_add, because the two successor entry classes refuse
 *             a retry in DIFFERENT places: the ENVELOPE lane reaches
 *             mempool_add's tx_hash dedup, while the CLAIM lane is caught
 *             earlier by admission's own ADMISSION-mode pending-mempool
 *             check, which keys on the claim NULLIFIER
 *             (nodus_witness_verify.c). Without the pre-check a retrying
 *             claim client would be told its work was not queued when it
 *             is.
 *         -1  RETIRED by O15K §3.1 and NEVER RETURNED. It used to mean
 *             NOT APPLICABLE — legacy chain, nothing pooled by design —
 *             and that gate is exactly what this change deleted. The
 *             value is retired rather than reassigned so no caller can
 *             mistake a new class for the old one, and because the one
 *             call site handled it with a deliberately SILENT branch: a
 *             repurposed -1 would make a real refusal invisible in the
 *             log. A -1 observed here means the fix was reverted.
 *         -2  refused, reject_reason filled. Two producers, and the
 *             string distinguishes them: admission's own verdict on the
 *             bytes (either lane), or §3.4's legacy zero-nullifier guard,
 *             which runs FIRST because a legacy GENESIS never reaches
 *             admission's equivalent check (nodus_witness_verify.c
 *             :952-955 returns before Check 4 at :989-991).
 *         -3  admission refused: nullifier already spent (double-spend).
 *         -4  could not pool: allocation failed, pool full, or the
 *             class-201 nullifier re-derivation failed (fail-closed —
 *             a 201 entry is NEVER enqueued with nullifier_count 0,
 *             because batch dedup and the P3(c) reaper both key on it).
 */
int nodus_witness_pool_local_demand(nodus_witness_t *witness,
                                      const uint8_t *tx_data, uint32_t tx_len,
                                      const uint8_t *tx_hash, uint8_t tx_type,
                                      const uint8_t *nullifiers,
                                      uint8_t nullifier_count,
                                      const uint8_t *client_pk,
                                      const uint8_t *client_sig,
                                      uint64_t fee,
                                      char *reject_reason, size_t reason_size);

/**
 * O15I V1 — can this mempool entry still be included in a block?
 *
 * THE FIVE ANSWERS ARE NOT COLLAPSIBLE. Three of them mean "this entry
 * can never commit, on any node" and two mean "keep it" — but they mean
 * it for DIFFERENT reasons, and a caller that logs a drop, or a reader
 * asking why a stall never cleared, needs the reason. Use
 * nodus_witness_v2_entry_is_decided to collapse them; never open-code the
 * collapse, or the two consumers can drift.
 *
 * ── THE VERDICT SIDE (the entry is finished) ───────────────────────────
 * Each of these is a property of the entry's own bytes against committed
 * state, so every honest node at the same tip reaches the same answer.
 *
 *  COMMITTED  the derived intent_id is already in v2_intent_index. A
 *             committed intent may commit at most ONCE per chain — the
 *             apply engine rejects the whole candidate block that
 *             carries a second one — so inclusion is impossible.
 *  EXPIRED    the preflight answered DNA_ENV_PF_ERR_EXPIRED:
 *             expiry_height is below the candidate height. The tip only
 *             advances, so an expired envelope stays expired forever, on
 *             every node. env_preflight.h:91 classes this as a verdict
 *             ABOUT THE ENVELOPE, deliberately unlike ERR_HASH.
 *  MALFORMED  the strict codec rejected the bytes. dna_env_decode
 *             allocates nothing and is a pure function of its input
 *             (env_wire.h:401-403), so its rejection cannot be
 *             node-local: no node can ever include these bytes.
 *
 * ── THE KEEP SIDE ─────────────────────────────────────────────────────
 *  LIVE       judged, and the chain says it could still be included.
 *  UNJUDGED   THIS NODE could not reach an answer. FAIL-CLOSED, and the
 *             direction is deliberate: a legacy chain, a class-201
 *             claim, a domain missing from the registry, an underivable
 *             chain id, a preflight ERR_HASH (a NODE fault by
 *             env_preflight.h:100-110's own definition — "MUST NOT
 *             translate it into a transaction rejection") or a failed
 *             query all land here. Treating any of them as finished
 *             would let one starved or half-migrated node delete a
 *             client's pending work, which is the unconditional wipe the
 *             reaper replaced. 0 so a zeroed value is the safe answer.
 */
typedef enum {
    NODUS_W_ENTRY_UNJUDGED  = 0,
    NODUS_W_ENTRY_LIVE      = 1,
    NODUS_W_ENTRY_COMMITTED = 2,
    NODUS_W_ENTRY_EXPIRED   = 3,
    NODUS_W_ENTRY_MALFORMED = 4
} nodus_witness_entry_verdict_t;

/**
 * O15I V1 — the verdict on ONE successor class-200 ENVELOPE.
 *
 * THE AUTHORITY IS THE ENGINE'S OWN, not a second opinion. It derives the
 * canonical authorization-witness-independent `intent_id` through the same
 * preflight seam the apply path uses
 * (nodus_witness_v2_env_preflight_batch, over the ruleset table built the
 * way nodus_witness_v2_produce_batch_check builds it) and asks the same
 * committed index with the same statement the apply engine's replay guard
 * asks (nodus_witness_v2_apply.c: "SELECT 1 FROM v2_intent_index WHERE
 * intent_id = ?1"). Expiry is NOT re-implemented here either — it is read
 * back off that seam's status, so the one comparison env_preflight.h
 * locks stays in exactly one place.
 *
 * WHY IT IS NEEDED AT ALL. A successor class-200 envelope is pooled with
 * nullifier_count == 0 (nodus_witness_peer.c skips the legacy nullifier
 * walk on a successor), so the nullifier predicate has nothing to say
 * about it and BOTH consumers used to answer "undecided" forever:
 * nodus_witness_mempool_evict_committed could never reap it, and the P3
 * deadman read it as live demand and rotated the view once per
 * round_timeout_ms against a healthy leader, on a quiet chain, forever.
 *
 * ⚠ ORDERING CAVEAT, stated rather than hidden: the contextual ruleset
 * table has to resolve before the seam can be called at all, so an
 * envelope addressing a domain that is NOT in the registry answers
 * UNJUDGED even if it is also expired. The seam's own frozen order puts
 * expiry first (env_preflight.h step 3, before the context steps), so
 * this helper is strictly more conservative than the seam, never less.
 *
 * COST, and why nothing is cached: the derived id cannot be stored on the
 * mempool entry without touching nodus_witness_mempool.h, so it is
 * derived on demand. That is ~15 KB heap plus a decode and the commitment
 * chain per class-200 entry, which is why BOTH callers bound how often
 * they may ask — P3 by its once-per-round_timeout_ms window re-stamp,
 * the reaper by `last_evict_epoch`.
 *
 * Deterministic and node-local: bytes plus this node's own committed
 * state, no clock, no message, no write.
 *
 * @param tx_data mempool entry bytes (borrowed; nothing is retained).
 * @return one nodus_witness_entry_verdict_t; UNJUDGED for every entry
 *         this node cannot judge, including every non-successor and
 *         every class-201 claim.
 */
nodus_witness_entry_verdict_t nodus_witness_v2_entry_verdict(
        nodus_witness_t *witness, const uint8_t *tx_data, uint32_t tx_len);

/**
 * O15I V1 — THE ONE collapse rule: does this verdict mean the entry can
 * never be included again?
 *
 * It exists so `bft_p3_live_demand` and
 * nodus_witness_mempool_evict_committed cannot drift: what the reaper
 * deletes must be exactly what P3 declines to count as demand, and a
 * second open-coded `== COMMITTED || == EXPIRED` list is precisely how
 * those two would fall out of step. Both keep-side answers (LIVE and the
 * fail-closed UNJUDGED) return false.
 *
 * @return true for COMMITTED / EXPIRED / MALFORMED, false otherwise.
 */
bool nodus_witness_v2_entry_is_decided(nodus_witness_entry_verdict_t v);

/**
 * O15I P3(c) — drop the mempool entries the chain has already decided.
 *
 * PER-ENTRY, and that is the whole point. What used to stand here was an
 * UNCONDITIONAL nodus_witness_mempool_clear on any non-leader once per
 * 60 s epoch tick. Under P3(b) — where a follower now legitimately POOLS
 * forwarded work so a dead leader's demand survives on more than one
 * node — that wipe would delete, once a minute and mid-stall, exactly
 * the entries that arm the P3(a) deadman. Racing it is not an option, so
 * the wipe is replaced by an eviction with a REASON.
 *
 * THE PREDICATE IS THE LEADER'S OWN, in BOTH of its halves. An entry is
 * dropped when any of its nullifiers is already committed — the identical
 * test batch selection applies before proposing (nodus_witness_bft.c,
 * "mempool TX stale (DB double-spend), dropping") — OR, on a successor
 * class-200 envelope, when nodus_witness_v2_entry_verdict says the entry
 * can never be included again: its intent is already in the committed
 * index, its expiry_height is below the candidate, or its bytes no longer
 * decode. So a follower drops exactly what a leader would refuse to
 * propose, and never more.
 *
 * ⚠ "ALREADY COMMITTED" IS TWO DIFFERENT TABLES, ROUTED BY ENTRY CLASS
 * (V-3). A class-201 CLAIM's nullifier is committed to the successor's
 * `v2_claims_spent` (nodus_witness_v2_claims.c), NOT to the legacy
 * `nullifiers` table — whose only writer is nodus_witness_nullifier_add
 * on the legacy commit path. Asking the legacy table about a claim
 * therefore always answered "not spent", so a claim the chain had
 * ALREADY COMMITTED could never be reaped: it read as live demand
 * forever, arming the P3(a) deadman against a HEALTHY leader once per
 * round for the life of the process. The reaper now routes:
 * tx_type == NODUS_W_TX_V2_CLAIM asks the claims table through the
 * shared tri-state helper nodus_witness_v2_claim_nullifier_spent()
 * (1 spent / 0 not spent / -1 fault); every other entry class keeps the
 * legacy nullifier walk, byte-unchanged.
 *
 * ⚠ AND THE SAME -1 MEANS OPPOSITE THINGS IN THE TWO CALLERS. HERE a
 * fault maps to KEEP, because this branch DELETES: a wrong deletion
 * silently loses a transaction a client is still waiting on, and a
 * kept-too-long entry is merely reaped on the next pass. In the
 * ADMISSION double-spend path the same -1 maps to SPENT/REJECT, because
 * that branch decides whether to ADMIT: admitting on a fault is what
 * lets a double-spend through. Same fact, opposite safe directions —
 * read only one of the two call sites and you will get this wrong.
 *
 * This does NOT widen nodus_witness_v2_entry_verdict's class gate: it
 * still answers UNJUDGED for a class-201 claim, and that is correct — a
 * claim has no intent id. The claims-table lookup is an additional,
 * separate question, not a verdict.
 *
 * The original drain's PURPOSE is preserved: forwarded entries carry
 * client_conn == NULL, so no client disconnect ever reaches them through
 * remove_by_conn and without a reaper they leak. They still have one —
 * it now fires on the chain's verdict instead of on the clock, which is
 * also the first thing in this file that removes a follower's copy of a
 * transaction AFTER it commits.
 *
 * ⚠ O15I V1 — WHAT IS STILL NOT JUDGED. An entry that BOTH predicates
 * decline is kept, and that is still the correct direction: "I have no
 * evidence" must never read as "already finished". What remains in that
 * set is a legacy-chain entry with nullifier_count == 0, and a successor
 * class-200 envelope this node could not judge — a domain missing from
 * the registry, an underivable chain id, an ERR_HASH node fault (see
 * NODUS_W_ENTRY_UNJUDGED). Note that the set is NARROWER than "the
 * derivation failed": an expired envelope and one whose bytes no longer
 * decode are both FINISHED, not unjudged, because neither can ever be
 * included by any node. Before V1 the unjudged set contained EVERY
 * successor class-200 envelope, including settled ones — which is what
 * let one sit in a follower's pool forever and arm the P3 deadman
 * against a healthy leader. The leader-side drop (the successor batch
 * pre-check, nodus_witness_bft.c "successor batch entry %d rejected by
 * the seam") remains as a backstop.
 *
 * ⚠ THE ROLE GATE IS GONE. This used to run only on a NON-leader, which
 * meant a node currently leading never cleaned its own pool — stale
 * entries were removed only by burning them through batch selection, one
 * proposal at a time. Measured in the 20-node rehearsal
 * (o15i-ptf-20260826T164744Z): node1 pooled 26 entries, proposed exactly
 * ONCE, and that single proposal had to drop 13 already-committed claims
 * through the seam. A leader now reaps like anyone else; the pool-size,
 * epoch-window and last_evict_epoch gates are unchanged.
 *
 * CALL IT AT MOST ONCE PER EPOCH. The successor half costs a decode plus
 * the full commitment derivation per class-200 entry; the tick's
 * `last_evict_epoch` latch is what keeps the ~2 s gate from running it
 * ~40 times per epoch. This function itself is idempotent and imposes no
 * cadence of its own.
 *
 * Fee ordering is preserved: survivors are compacted in place, keeping
 * their relative order, exactly as mempool_remove_by_conn does.
 *
 * Deterministic and node-local: it reads only this node's own committed
 * chain, emits nothing, and mempool content is per-node INPUT — block
 * content is still chosen by ONE leader and agreed by PREVOTE/PRECOMMIT
 * with an independent state_root recompute, so two nodes evicting
 * different entries cannot diverge state.
 *
 * @return number of entries evicted and freed.
 */
int nodus_witness_mempool_evict_committed(nodus_witness_t *witness);

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

/**
 * O15C-D.1 — install a drop predicate described by the environment.
 *
 * Called from nodus_witness_init. No-op unless NODUS_FAULT_ARM_FILE is
 * set. Lets the stagef harness — seven separate processes — reach the
 * partition scenarios this hook was built for, which previously needed
 * an in-process caller and so were never exercised end to end.
 * See nodus_witness_fault.c for the arm-file rationale.
 */
void nodus_witness_fault_init_from_env(const uint8_t *my_id);
#endif /* QGP_FAULT_INJECT */

/**
 * Create chain-specific witness DB on genesis commit.
 * Filename: witness_<chain_id_hex>.db in data directory.
 * Sets chain_id and opens the new database.
 */
/**
 * ENGINE-INTERNAL, exposed for direct test (the precedent is
 * nodus_witness_v2_local_index_find). The RESTART path: scan
 * `witness->data_path` for a `witness_<32 hex>.db`, adopt the
 * lexicographically smallest valid name, open it, and run the SAME
 * post-open integrity gate `nodus_witness_create_chain_db` runs.
 *
 * O15A made three guarantees testable here: the gate is not skipped on
 * restart; a filename that does not carry exactly 32 hex characters is
 * IGNORED rather than parsed into a zero-padded chain id; and selection
 * follows a stable total order over names instead of readdir order.
 *
 * @return 0 with the database open and `chain_id` set, -1 when no usable
 *         chain database was found (pre-genesis) or the gate refused one.
 */
int nodus_witness_scan_chain_db(nodus_witness_t *witness);

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
