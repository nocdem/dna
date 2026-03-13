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
 * Start a new BFT consensus round (leader only).
 * Creates PROPOSAL, broadcasts to peers, records own PREVOTE.
 *
 * The caller (handler) should set w->round_state.client_conn and
 * w->round_state.client_txn_id before calling if a client response
 * is needed on commit.
 *
 * @return 0 success, -1 error, -2 double-spend
 */
int nodus_witness_bft_start_round(nodus_witness_t *w,
                                    const uint8_t *tx_hash,
                                    const uint8_t nullifiers[][NODUS_T3_NULLIFIER_LEN],
                                    uint8_t nullifier_count,
                                    uint8_t tx_type,
                                    const uint8_t *tx_data,
                                    uint32_t tx_len,
                                    const uint8_t *client_pubkey,
                                    const uint8_t *client_sig,
                                    uint64_t fee);

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

#ifdef __cplusplus
}
#endif

#endif /* NODUS_WITNESS_BFT_H */
