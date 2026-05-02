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

/* ── Recovery sentinel — audit B-2 fix (2026-05-02) ──────────────────
 *
 * Persisted at <data_path>/.recovery_in_progress to gate any halt-
 * recovery DB drop with crash safety. Written before drop_witness_db
 * (Faz 4D-E callers), cleared after the first successful sync block.
 * Boot path (Faz 4D-E follow-up) must call _check and reject startup
 * when present until an operator manually clears.
 *
 * Format: 40 bytes binary
 *   [0..31]  chain_id  (32 bytes)
 *   [32..39] halt_height (uint64 little-endian)
 */
int nodus_witness_recovery_sentinel_create(nodus_witness_t *w,
                                             uint64_t halt_height);
int nodus_witness_recovery_sentinel_clear(nodus_witness_t *w);
/* Returns 0 if absent (clean), 1 if present (admin clear required),
 * -1 on read error. out_halt_height optional. */
int nodus_witness_recovery_sentinel_check(const char *data_path,
                                            uint64_t *out_halt_height);

#ifdef __cplusplus
}
#endif

#endif /* NODUS_WITNESS_SYNC_H */
