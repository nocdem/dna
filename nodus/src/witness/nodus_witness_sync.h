/**
 * Nodus — Witness State Sync
 *
 * Block-by-block sync from peers to recover missed BFT rounds.
 * Handles fork detection (block hash comparison) and resolution
 * (DB rebuild from genesis).
 *
 * Flow:
 *   1. Detect height gap via w_ident exchange
 *   2. Fork check: compare block hashes from genesis forward
 *   3. If fork: drop DB, full resync from genesis
 *   4. Replay missing blocks via w_sync_req/rsp
 *   5. Verify prev_hash chain + commit certificates per block
 *
 * All operations run in the epoll event loop (single-threaded).
 * Sync only during IDLE phase to avoid BFT round conflicts.
 *
 * @file nodus_witness_sync.h
 */

#ifndef NODUS_WITNESS_SYNC_H
#define NODUS_WITNESS_SYNC_H

#include "witness/nodus_witness.h"
#include "protocol/nodus_tier3.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Forward declarations */
struct nodus_tcp_conn;

/* ── Sync lifecycle ─────────────────────────────────────────────── */

/**
 * Check if sync is needed and initiate if so.
 * Called from epoch tick and after w_ident exchange.
 * Only starts if IDLE phase and no sync in progress.
 */
void nodus_witness_sync_check(nodus_witness_t *w);

/**
 * Send w_sync_req for the next block in the sync sequence.
 * Called from sync_check after initiating, and from handle_sync_rsp
 * to continue the chain.
 */
int nodus_witness_sync_request_next(nodus_witness_t *w);

/* ── Message handlers ───────────────────────────────────────────── */

/**
 * Handle incoming w_sync_req: look up block data and respond.
 * Called from nodus_witness_dispatch_t3.
 */
int nodus_witness_sync_handle_req(nodus_witness_t *w,
                                   struct nodus_tcp_conn *conn,
                                   const nodus_t3_msg_t *msg);

/**
 * Handle incoming w_sync_rsp: verify and replay the block.
 * Called from nodus_witness_dispatch_t3.
 */
int nodus_witness_sync_handle_rsp(nodus_witness_t *w,
                                   const nodus_t3_msg_t *msg);

#ifdef __cplusplus
}
#endif

#endif /* NODUS_WITNESS_SYNC_H */
