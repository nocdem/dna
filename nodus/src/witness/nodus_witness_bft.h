/**
 * Nodus — Witness BFT Consensus Engine
 *
 * BFT consensus for DNAC transaction witnessing.
 * Ported from dnac/src/bft/consensus.c — single-threaded, CBOR protocol.
 *
 * Key differences from DNAC:
 *   - No pthreads (runs in epoll event loop)
 *   - CBOR via Tier 3 protocol (not binary serialization)
 *   - Direct nodus_witness_db calls (not callbacks)
 *   - Signing/verification handled by T3 encode/decode layer
 *
 * @file nodus_witness_bft.h
 */

#ifndef NODUS_WITNESS_BFT_H
#define NODUS_WITNESS_BFT_H

#include "witness/nodus_witness.h"
#include "protocol/nodus_tier3.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ── Config ──────────────────────────────────────────────────────── */

/** Initialize BFT config from witness count (quorum = 2f+1). */
void nodus_witness_bft_config_init(nodus_witness_bft_config_t *cfg,
                                     uint32_t n_witnesses);

/** Returns true if consensus is active (enough witnesses for quorum). */
bool nodus_witness_bft_consensus_active(const nodus_witness_t *w);

/* ── Leader election ─────────────────────────────────────────────── */

/** Get leader index for given epoch and view. */
int  nodus_witness_bft_leader_index(uint64_t epoch, uint32_t view,
                                      int n_witnesses);

/** Check if this witness is currently leader. */
bool nodus_witness_bft_is_leader(nodus_witness_t *w);

/* ── Roster ──────────────────────────────────────────────────────── */

/** Find witness in roster by ID. Returns index or -1. */
int  nodus_witness_roster_find(const nodus_witness_roster_t *roster,
                                 const uint8_t *witness_id);

/** Add witness to roster (no-op if already present). */
int  nodus_witness_roster_add(nodus_witness_t *w,
                                const nodus_witness_roster_entry_t *entry);

/* ── Consensus ───────────────────────────────────────────────────── */

/**
 * Phase 7 / Task 7.1 — start a BFT round from caller-owned entries.
 *
 * Thin wrapper over the shared batch round-start body. Used by callers
 * that already have mempool entries in hand (e.g. the genesis path,
 * which builds a single-entry array from raw TX args) and do not want
 * to go through the mempool pop/validate cycle.
 *
 * @return 0 success, -1 error
 */
int nodus_witness_bft_start_round_from_entries(nodus_witness_t *w,
                                                 nodus_witness_mempool_entry_t **entries,
                                                 int count);

/**
 * Phase 7 / Task 7.2 — start a BFT round from the mempool.
 *
 * Pops up to NODUS_W_MAX_BLOCK_TXS entries from the mempool, runs the
 * Phase 4 layer-2 chained-UTXO filter and DB-nullifier rechecks, and
 * forwards the survivors to the shared round-start body. On round-start
 * failure the surviving entries are returned to the mempool for retry.
 *
 * Replaces the previous static nodus_witness_propose_batch helper that
 * lived in nodus_witness.c.
 *
 * @return 0 success, -1 error or no valid entries
 */
int nodus_witness_bft_start_round_from_mempool(nodus_witness_t *w);

/** Handle decoded PROPOSAL message. */
int nodus_witness_bft_handle_propose(nodus_witness_t *w,
                                       const nodus_t3_msg_t *msg);

/** Handle decoded PREVOTE or PRECOMMIT message. */
int nodus_witness_bft_handle_vote(nodus_witness_t *w,
                                    const nodus_t3_msg_t *msg);

/** Handle decoded COMMIT message (from remote leader). */
int nodus_witness_bft_handle_commit(nodus_witness_t *w,
                                      const nodus_t3_msg_t *msg);

/** Handle decoded VIEW_CHANGE message. */
int nodus_witness_bft_handle_viewchg(nodus_witness_t *w,
                                       const nodus_t3_msg_t *msg);

/** Handle decoded NEW_VIEW message. */
int nodus_witness_bft_handle_newview(nodus_witness_t *w,
                                       const nodus_t3_msg_t *msg);

/* ── View change ─────────────────────────────────────────────────── */

/** Initiate view change (broadcasts VIEW_CHANGE to peers). */
int nodus_witness_bft_initiate_view_change(nodus_witness_t *w);

/* ── Timeout ─────────────────────────────────────────────────────── */

/** Check for BFT round timeout. Called from nodus_witness_tick(). */
void nodus_witness_bft_check_timeout(nodus_witness_t *w);

/* ── Broadcast ───────────────────────────────────────────────────── */

/**
 * Encode and broadcast a T3 message to all connected witness peers.
 * Fills msg->header with sender identity (round, view, nonce, etc.).
 * Signs with server's Dilithium5 secret key.
 *
 * @return number of peers message was sent to
 */
int nodus_witness_bft_broadcast(nodus_witness_t *w, nodus_t3_msg_t *msg);

/**
 * Write committed block to witness database (replay-safe).
 * Used by BFT COMMIT path and state sync replay.
 * Handles genesis (DB creation) and non-genesis (nullifiers, UTXO).
 *
 * @return 0 on success, -1 on failure
 */
int nodus_witness_commit_block(nodus_witness_t *w,
                                const uint8_t *tx_hash,
                                uint8_t tx_type,
                                const uint8_t *const *nullifiers,
                                uint8_t nullifier_count,
                                uint64_t total_supply,
                                uint64_t proposal_timestamp,
                                const uint8_t *proposer_id,
                                const uint8_t *tx_data,
                                uint32_t tx_len);

#ifdef __cplusplus
}
#endif

#endif /* NODUS_WITNESS_BFT_H */
