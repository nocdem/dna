/**
 * Nodus — Witness Module (DNAC Consensus)
 *
 * All nodus nodes are automatic witnesses. Provides:
 *   - cometbft @709fd12b consensus for DNAC transaction witnessing on a
 *     version-3 chain (R3 W4 — the legacy PBFT lane this module ran
 *     before is deleted; DNAC client query handlers stay on their
 *     legacy tables per the hub/spoke boundary, unaffected by the port)
 *   - Nullifier/ledger/UTXO/block SQLite storage
 *   - Witness peer mesh over nodus TCP connections
 *   - DNAC client query handlers (dnac_* Tier 2 methods)
 *
 * Roster is dynamically built from DHT pubkey registry + witness peer mesh
 * and refreshed every 60 seconds (epoch tick).
 *
 * Consensus messages use Tier 3 protocol ("w_" prefixed CBOR methods)
 * over dedicated witness TCP port 4004.
 * Single-threaded: all state transitions in the epoll event loop.
 *
 * @file nodus_witness.h
 */

#ifndef NODUS_WITNESS_H
#define NODUS_WITNESS_H

#include "nodus/nodus_types.h"
#include "nodus/nodus_chain_config.h"  /* nodus_cc_rate_limit_table_t */
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
    /* R3 W4 — halt_auto_recover (and the halt_recovery_check it gated)
     * is deleted with the closed consensus lane: the legacy safety_halt
     * / halt_committee snapshot it read no longer exists. The recovery
     * sentinel FILE it used to arm is still checked at boot (witness.c,
     * nodus_witness_init) for the reason recorded there — a stale file
     * from an older binary must still refuse a silent boot — but nothing
     * in this tree can set safety_halt or arm a new sentinel again. */
    char     _reserved;
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
 * 32 <= 128, so all round-state / QC / vote arrays already fit.
 *
 * tokenomics-v3 P3-7 (docs/plans/decisions/2026-09-22-nodus-tokenomics-
 * v3-operator.md §3 2026-09-24 "P3 soruları" (4): "tavan 32 kodda sabit";
 * design docs/plans/2026-09-23-tokenomics-v3-consensus-binding-design.md
 * D-10): 30 -> 32. The same value is the default target
 * (DNAC_TARGET_ACTIVE_DEFAULT, dnac.h) and the top of the governed
 * TARGET_ACTIVE_COUNT range [7, 32] on this lane
 * (nodus_witness_rt_native.c / nodus_witness_chain_config.c); the genesis
 * config array (NODUS_V2_GEN_MAX_VALIDATORS) and the InitChain match
 * table (nodus_witness_cmt_app.c) are sized by it. Going above 32 is a
 * code change plus a separate operator decision. */
#define NODUS_V2_ACTIVE_SET_MAX     32
_Static_assert(NODUS_V2_ACTIVE_SET_MAX <= DNAC_MAX_ACTIVE_VALIDATORS,
               "successor active-set max exceeds resource ceiling");
_Static_assert(DNAC_TARGET_ACTIVE_DEFAULT == NODUS_V2_ACTIVE_SET_MAX,
               "the default target and the V2 active-set ceiling are one "
               "operator number (N = 32)");
_Static_assert(DNAC_COMMITTEE_SIZE <= NODUS_V2_ACTIVE_SET_MAX,
               "the governed minimum must fit under the V2 ceiling");

/* ── Vote types ──────────────────────────────────────────────────── */

typedef enum {
    NODUS_W_VOTE_APPROVE = 0,
    NODUS_W_VOTE_REJECT  = 1,
} nodus_witness_vote_t;

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
     * ZERO — callers on the read path MUST NOT trust pubkey. R3 W4 — the
     * sync verification path that used to resolve pubkey separately
     * (nodus_witness_verify_sync_certs) is deleted with the closed
     * consensus lane; the one surviving reader, handle_dnac_block
     * (nodus_witness_handlers.c), never reads this field at all — it
     * encodes only voter_id and signature to the client. */
    uint8_t     pubkey[DNAC_PUBKEY_SIZE];
} nodus_witness_vote_record_t;

/* R3 W4 — the out-of-order vote buffer (nodus_witness_pending_vote_t,
 * NODUS_W_VOTE_BUFFER_ROUND_AHEAD/_VIEW_AHEAD/_CAP), the round state
 * (nodus_witness_round_state_t, the live PROPOSE/PREVOTE/PRECOMMIT
 * machinery), the view-change record (nodus_witness_vc_record_t,
 * nodus_witness_prepared_sig_t, nodus_witness_vc_record_clear) and the
 * VIEW_OK statement set (nodus_witness_view_ok_set_t) are all DELETED
 * with the closed consensus lane: they existed only to run the legacy
 * PBFT round, view-change and view-authority machinery, none of which
 * this build ever starts (D-17 rev 10 (9)). */

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

    /* State sync: peer's chain state from w_ident. Root-layout round
     * (K3): `remote_checksum` (the peer's advertised legacy state_root)
     * is DELETED — it was written and never read. */
    uint64_t    remote_height;              /* peer's block height */

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

    /* R3 W4 — last_chain_q_response_ms (the legacy w_chain_q bootstrap
     * rate limit) and sync_bad_until (the legacy sync peer-selection
     * cooldown) are deleted with the closed consensus lane: their only
     * readers/writers were nodus_witness_bootstrap.c and
     * nodus_witness_sync.c, both gone. */
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

    /* R3 W4 — the legacy BFT consensus state (current_round,
     * current_view, last_committed_round, round_state), view-change
     * tracking (view_changes[], view_change_count/target/in_progress/
     * voted), the VIEW_OK authority store (viewok_acc/proof/req_sent_ms/
     * rsp_sent_ms), the P2 post-view-change deadman
     * (awaiting_propose_deadline_ms), the P3 demand-armed follower
     * deadman (last_seen_tip, tip_since_ms), the out-of-order vote
     * buffer (vote_buffer[]) and the BFT config derived from the roster
     * (bft_config) are all DELETED with the closed consensus lane: they
     * existed only to run the legacy PBFT round, view-change and
     * view-authority machinery, which this build never starts. The
     * IDENT wire's `current_view` field stays byte-identical (written 0
     * by nodus_witness_peer_send_ident; there is nothing left to adopt
     * it into on receipt). */

    /* Dynamic roster — epoch-based refresh. F17 A2: transport-only now
     * (peer discovery / witness_id→pubkey lookup). BFT config comes
     * from the chain committee at round-start, not from this roster. */
    uint64_t    last_epoch;                     /* Timestamp of last roster rebuild */
    nodus_witness_roster_t  pending_roster;     /* Built each epoch from DHT + peers */

    /* Zone chain ID */
    uint8_t     chain_id[32];

    /* R3 W4 — g_quorum_cdh / g_quorum_cdh_set (the DISCOVER-agreed
     * genesis chain_def anchor for the legacy genesis-sync leg) are
     * deleted with the closed consensus lane: their only writer
     * (nodus_witness_bootstrap.c) and reader (nodus_witness_sync.c) are
     * both gone. */

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

    /* R3 W4 — pending_forwards[]/pending_forward_count (the legacy
     * non-leader forward-response routing table), mempool (the legacy
     * in-memory TX queue) and sync_state (the legacy block-replay
     * driver) are deleted with the closed consensus lane: their only
     * readers/writers were nodus_witness_peer.c's FWD_REQ/FWD_RSP
     * handlers, nodus_witness_handlers.c's leader/forward branch,
     * nodus_witness_mempool.c and nodus_witness_sync.c, all gone. The
     * version-3 lane's mempool is the Comet reactor's own (cmt_mem.c). */

    /* Root-layout round (K3, 2026-09-25): `cached_state_root` /
     * `cached_state_root_valid` are DELETED — no code wrote them, so the
     * two readers (IDENT send, the T2 status reply's legacy branch)
     * always took their fallback. */

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

    /* R3 W4 — safety_halt / halt_block_height / halt_timestamp /
     * halt_committee_pubkeys / halt_committee_count (the C3
     * state_root-divergence halt and its Faz 4D-E recovery snapshot),
     * last_prepared (the C5 PBFT prepared-cert tracker), reproposal_*
     * (the C5 NEW_VIEW re-proposal binding), retained_batch (MED-28's
     * retained reproposal batch), parked_propose (the O15R B′ parked
     * next-view PROPOSE) and the PR 3 Yol B auto-bootstrap state machine
     * fields (bootstrap_state and all bootstrap_* timers) are all
     * DELETED with the closed consensus lane: they existed only to run
     * or recover the legacy PBFT round and the legacy DISCOVER bootstrap,
     * neither of which this build ever starts. */
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
     * R3 W4 — v2_certpool (the bounded per-height DNA.CERT.v2 collection
     * that assembled the closed lane's QC) is DELETED with it: its only
     * producers (nodus_witness_v2_qc_try_attach, _cert_note,
     * _produce_commit) are gone. */
    bool        v2_successor;
    uint8_t     v2_chain32[32];

    /* O15E Faz B — the successor sync driver's RUNTIME state (never
     * persisted; LOCAL policy only, nothing here is consensus). R3 W4 —
     * trimmed to the one field the surviving gbundle serve path uses;
     * req_peer/req_from/req_count/req_sent_ms/last_head_ms/
     * last_qcfetch_ms/qc_rr were the range-request driver's own state
     * (handle_head/_range_q/_tick, deleted with the old-lane V2 block
     * sync verbs 20-23). `last_serve_ms` (H-1 sign-amplification guard)
     * still throttles nodus_witness_v2_sync_handle_gbundle_q. */
    struct {
        uint64_t last_serve_ms;
    } v2_sync;

    /* O15E Faz D — pinned-genesis joiner bootstrap RUNTIME state. Active
     * only on a fresh node with a local pin and no successor chain yet;
     * cleared the moment the successor DB is adopted (the node then
     * behaves as an ordinary successor). While `active`, the node MUST
     * NOT propose or vote (role safety). Nothing here is persisted. */
    struct {
        int      active;                 /* 1 = fetching/deriving        */
        /* R3 W3 (D-24 rev 4 (1)): 32 bytes — the chain id. A version-3
         * chain has no genesis BLOCK to pin a 64-byte BlockID to (D-19
         * rev 6 withdrew it); the chain's only identity is the hash of
         * its stored genesis DOCUMENT (D-18 rev 4). */
        uint8_t  pin[32];                /* local trust anchor (copy)    */
        uint8_t *acc;                    /* bundle accumulator           */
        size_t   acc_len;                /* bytes received contiguously  */
        size_t   acc_total;              /* expected total (0 = unknown) */
        uint64_t last_req_ms;            /* fetch throttle               */
        /* Round-robin cursor over the witness-peer table, added
         * 2026-09-03. Before it, the tick took the FIRST identified peer
         * and broke, so a joiner whose peers[0] would not serve it asked
         * that same peer forever — measured: 1 of 13 simultaneous joiners
         * never adopted, over 9 minutes and again over 4 after a clean
         * restart. Advancing per attempt costs one interval per unhelpful
         * peer instead of the whole join. See nodus/BUGS.md. */
        uint32_t peer_rr;
        /* Rate limit for the "why am I not asking" diagnostic below, so a
         * stuck joiner names its own early return once a minute instead
         * of never (its logs showed the arm line and then silence). */
        uint64_t last_diag_ms;
    } v2_join;

    /* ── FLEET-TM-R3 W3 package C2a — the cometbft server binding ──────
     *
     * `void *` here, DELIBERATELY, not the real pointer types
     * (`nodus_cmt_node_t *`, `nodus_cmt_net_t *`, `cmt_conr_t *`,
     * `cmt_memr_t *`): `nodus_witness_cmt_node.h` and
     * `nodus_witness_cmt_net.h` both `#include "witness/nodus_witness.h"`
     * for `nodus_witness_t`, and `nodus_cmt_net_t` / `cmt_conr_t` /
     * `cmt_memr_t` are anonymous struct typedefs with no tag this header
     * could forward-declare — a real pointer field here would be a
     * circular include. Every site that dereferences these includes the
     * real headers first and casts back (nodus_witness.c, nodus_server.c
     * — never this header).
     *
     * Heap-allocated because none of it belongs on this already-large
     * struct or on any stack: `nodus_cmt_node_t` alone carries three
     * ~1 MB `cmt_state_storage_t` and an ~85 KB application context
     * (nodus_witness_cmt_node.h's own warning), and `nodus_cmt_net_t`
     * embeds several `NODUS_T3_MAX_WITNESSES`-sized arrays plus a 64 MiB
     * receive arena.
     *
     * NULL/false until `nodus_witness_init` constructs them — which it
     * does only when `v2_successor` is true, i.e. only on a chain the
     * post-open gate above accepted as version-3. `cmt_live` becomes true
     * once the tick has started the two reactors (node.go:518-524's
     * genesis-time wait, checked on the tick — see witness_cmt_tick). */
    void    *cmt_node;   /* nodus_cmt_node_t*, owned                      */
    void    *cmt_net;    /* nodus_cmt_net_t*,  owned                      */
    void    *cmt_conr;   /* cmt_conr_t*,       owned                      */
    void    *cmt_memr;   /* cmt_memr_t*,       owned                      */
    bool     cmt_live;
    /* ORCHESTRATOR delta 1, item C (D-23 rev 7 (19)) — the earliest of
     * the glue's and the timer's next deadline, as witness_cmt_tick last
     * returned it (host-clock nanoseconds, cmt_time_unix_nano's units).
     * Read by nodus_witness_tick to narrow the NEXT call's witness TCP
     * poll wait below 50 ms when a deadline is closer than that ("poll
     * wait = min(50 ms, the earliest deadline)"). RUNTIME ONLY: never
     * persisted, never hashed, never a consensus input — it only shapes
     * how promptly THIS node's own event loop notices its own timers,
     * never what it decides. INT64_MAX (nodus_witness_init's explicit
     * set, not the struct's zero-init) means "no deadline yet / lane not
     * live" and leaves the poll at its ordinary fixed 50 ms. */
    int64_t  cmt_next_deadline_ns;
} nodus_witness_t;

/* R3 W4 — nodus_witness_genesis_derive_chain_id (shared by the legacy
 * commit_genesis and the legacy genesis-sync anchor check, both deleted),
 * the NODUS_WITNESS_INTERNAL_API sync-peer-selection pair
 * (nodus_witness_sync_find_peer/_rotate_peer, un-static'd from the now
 * -deleted nodus_witness_sync.c) and nodus_witness_batch_ctx_t (carried
 * across the legacy apply_tx_to_state's N-TX batch loop, bft.c's own) are
 * all DELETED with the closed consensus lane. */

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
 * Retries peer connections (witness_mesh_tick), then drives the cometbft
 * reactor (witness_cmt_tick) on a version-3 chain or the pinned-genesis
 * joiner (nodus_witness_v2_join_tick) otherwise. R3 W4 — no longer checks
 * any legacy BFT round timeout; that lane is deleted.
 */
void nodus_witness_tick(nodus_witness_t *witness);

/* R3 W4 — nodus_witness_pending_forward_expire, nodus_witness_pool_local_demand,
 * nodus_witness_entry_verdict_t / nodus_witness_v2_entry_verdict,
 * nodus_witness_v2_entry_is_decided and nodus_witness_mempool_evict_committed
 * are all DELETED with the closed consensus lane: they judged and drained
 * the legacy `pending_forwards` table and the legacy in-memory mempool,
 * both deleted. See nodus_witness.c's own deletion note at the same names
 * for the full reasoning. */
/**
 * Clean up witness resources. Closes DB, clears state.
 */
void nodus_witness_close(nodus_witness_t *witness);

/* ── Dispatch (called from nodus_server.c) ───────────────────────── */

/**
 * Dispatch a Tier 3 witness message ("w_*" methods): the surviving
 * roster/ident/genesis-bundle verbs and the cometbft envelope verbs
 * (35-39, "verb IS the channel"). R3 W4 — the legacy PBFT verbs these
 * once carried (1-8/12-23/26-27) are retired, never reused.
 * These are pre-auth, self-authenticated via Dilithium5 wsig.
 * Raw payload is passed for CBOR re-decode with T3 schema.
 */
void nodus_witness_dispatch_t3(nodus_witness_t *witness,
                               struct nodus_tcp_conn *conn,
                               const uint8_t *payload, size_t len);

/* R3 W4 — nodus_witness_parked_propose_store / _clear (the O15R B′
 * parked next-view PROPOSE slot) are DELETED with the closed consensus
 * lane: the slot they filled (`parked_propose`) and the round state that
 * read it are both gone from nodus_witness_t. */

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
 * Clears any peer-table references to this connection to prevent
 * dangling pointers. R3 W4 — no longer clears round_state / pending
 * forwards / mempool / batch entries; that state is deleted.
 */
void nodus_witness_peer_conn_closed(nodus_witness_t *witness,
                                     struct nodus_tcp_conn *conn);

/* R3 W4 — the QGP_FAULT_INJECT drop-predicate hook
 * (nodus_witness_drop_predicate_t, nodus_witness_test_inject_drop,
 * nodus_witness_fault_init_from_env) is DELETED with the closed
 * consensus lane: nodus_witness_dispatch_t3 no longer consults any drop
 * predicate, nodus_witness_init no longer arms one, and its only
 * implementation (nodus_witness_fault.c) is gone. tests/test_fault_inject_
 * round_skip.c still calls this API — flagged for the test-package pass,
 * not resolved here (out of this delta's whitelist: sources only). */

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
 * ORCHESTRATOR delta 10 (R3-W3-C2a-18) — EXPORTED, was `static
 * witness_cmt_live_init` (nodus_witness.c). Constructs the cometbft
 * startup table and transport glue for a version-3 chain: the SAME
 * construction `nodus_witness_init` runs on a version-3 chain at process
 * start, now also callable a second way — by the pinned-genesis joiner,
 * immediately after its own `nodus_witness_scan_chain_db(w)` (above)
 * adopts a chain mid-life. Without this second call, an adopted joiner
 * holds the chain (role set by the SAME post-open gate this scan runs)
 * but never runs consensus and never catches up — there is no blocksync
 * in this port; catch-up is the reactor's own stored-part gossip, which
 * needs the reactor this function builds. See the function's own doc
 * comment in nodus_witness.c for the full precondition proof (both
 * callers reach it only after `v2_successor`/`v2_chain32` are set by the
 * SAME gate, with `w->server`/`w->data_path` already populated at
 * process start either way) and why no tick can land between a caller's
 * scan and its call to this function.
 *
 * The entry guard (an already-populated `cmt_node`/`cmt_net`/`cmt_conr`/
 * `cmt_memr` refuses with -1, logged) makes a second call over an
 * existing construction safe to attempt — it will never silently leak
 * or double-construct — but no caller is expected to actually trigger
 * it: each of the two callers reaches this function on a path that runs
 * at most once per witness lifetime.
 *
 * @return 0 on success (`witness->cmt_node`/`net`/`conr`/`memr`
 *         populated, `cmt_live` false); -1 on any failure (including the
 *         entry guard), with every partial allocation released and the
 *         witness fields left NULL.
 */
int nodus_witness_cmt_live_init(nodus_witness_t *witness);

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
