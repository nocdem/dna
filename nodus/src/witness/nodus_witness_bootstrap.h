/**
 * Nodus — Witness Auto-Bootstrap (PR 3 Yol B)
 *
 * State machine that decides whether a freshly-started witness:
 *   - already has a chain DB → enter HAVE_CHAIN, refresh bft_config
 *     from the on-chain committee, then SYNC via the existing
 *     nodus_witness_sync_check / replay_block path; or
 *   - has no chain DB → enter DISCOVER, query peer mesh via the new
 *     T3 bootstrap messages (CHAIN_Q / CHAIN_R / GENESIS_REQ /
 *     GENESIS_RSP), reach 2f+1-of-seed_nodes agreement on
 *     (chain_id, chain_def_hash), fetch the chain_def_blob + genesis
 *     anchor, persist it, then refresh bft_config and SYNC.
 *
 * Single public entry point: nodus_witness_bootstrap_start. It is
 * called once from nodus_witness_init at startup. The function does
 * not block on network — it kicks off the state machine and returns
 * immediately; subsequent ticks drive transitions.
 *
 * See docs/plans/2026-05-03-witness-auto-bootstrap-design.md for the
 * full architecture, threat model, and red-team audit.
 *
 * @file nodus_witness_bootstrap.h
 */

#ifndef NODUS_WITNESS_BOOTSTRAP_H
#define NODUS_WITNESS_BOOTSTRAP_H

#include <stdint.h>

#include "protocol/nodus_tier3.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Forward declarations for types we only handle through pointers, so
 * this header does not need nodus_witness.h or nodus_tcp.h. */
struct nodus_witness;
typedef struct nodus_witness nodus_witness_t;
struct nodus_tcp_conn;

/* Bootstrap state machine values.
 *
 * Encoded as int in nodus_witness_t.bootstrap_state so the witness
 * struct does not need to include this header. The numeric values
 * are stable for diagnostic logging; do NOT renumber. */
typedef enum {
    NODUS_W_BOOTSTRAP_INIT             = 0,
    NODUS_W_BOOTSTRAP_HAVE_CHAIN       = 1,
    NODUS_W_BOOTSTRAP_DISCOVER         = 2,
    NODUS_W_BOOTSTRAP_FETCH_GENESIS    = 3,
    NODUS_W_BOOTSTRAP_BOOTSTRAP_CONFIG = 4,
    NODUS_W_BOOTSTRAP_DONE             = 5,
} nodus_witness_bootstrap_state_t;

/**
 * Kick off the bootstrap state machine.
 *
 * Called exactly once at the end of nodus_witness_init. Decides the
 * branch (HAVE_CHAIN vs DISCOVER) based on whether the witness DB
 * already contains a genesis block.
 *
 * Non-blocking with respect to network I/O. Subsequent state
 * transitions (DISCOVER → FETCH_GENESIS → ...) are driven by the
 * existing tick / dispatch path.
 *
 * @param w  Initialized witness with open DB handle.
 * @return 0 on a successful start (state moved out of INIT), -1 on a
 *         hard configuration error (e.g., NULL handle, malformed seed
 *         list). The HAVE_CHAIN branch returns 0 immediately and the
 *         witness is ready for consensus participation; the DISCOVER
 *         branch returns 0 after enqueuing the first w_chain_q round
 *         and the witness becomes consensus-eligible only after the
 *         state machine reaches DONE.
 */
int nodus_witness_bootstrap_start(nodus_witness_t *w);

/**
 * Drive the bootstrap state machine on each witness tick. No-op when
 * state is not DISCOVER.
 *
 * Responsibilities while in DISCOVER:
 *   - On round-deadline elapsed without quorum: schedule next attempt
 *     with exponential backoff (10s -> 30s -> 60s -> ... -> 300s x5).
 *   - On agree-quorum reached during the in-flight collection window:
 *     transition to FETCH_GENESIS.
 *   - After the 10th attempt fails to reach quorum: log + exit(2) so
 *     systemd's RestartSec / StartLimitBurst envelope handles outer
 *     recovery (H-11 mitigation). */
void nodus_witness_bootstrap_tick(nodus_witness_t *w);

/**
 * T3 dispatch handlers. All four are called from
 * nodus_witness_dispatch_t3 after wsig verify but before any other
 * handler runs. The bootstrap module checks the local bootstrap_state
 * and either responds, drops, or accumulates state as appropriate.
 *
 * - handle_chain_q: respond with cid/tip/cdh if HAVE_CHAIN/DONE; drop
 *                   if DISCOVER (C-2 cabal protection).
 * - handle_chain_r: stale-nonce filter, dedup-by-sender, append to
 *                   round tally; tick checks quorum.
 * - handle_genesis_req: stub in C3, full impl in C5.
 * - handle_genesis_rsp: stub in C3, full impl in C5. */
void nodus_witness_bootstrap_handle_chain_q(nodus_witness_t *w,
                                             struct nodus_tcp_conn *conn,
                                             const nodus_t3_msg_t *msg);
void nodus_witness_bootstrap_handle_chain_r(nodus_witness_t *w,
                                             const nodus_t3_msg_t *msg);
void nodus_witness_bootstrap_handle_genesis_req(nodus_witness_t *w,
                                                 struct nodus_tcp_conn *conn,
                                                 const nodus_t3_msg_t *msg);
void nodus_witness_bootstrap_handle_genesis_rsp(nodus_witness_t *w,
                                                 const nodus_t3_msg_t *msg);

#include <stdbool.h>

/**
 * PR 3 / E4 — H-9 mixed-version cluster detection.
 *
 * Scan w->peers and return true if ANY peer has reported a non-zero
 * remote_nodus_version that is strictly less than `local_nv`. The
 * encoding matches the existing CC-OPS-002 packing:
 *   local_nv = (MAJOR << 16) | (MINOR << 8) | PATCH
 *
 * Peers with remote_nodus_version == 0 (legacy pre-CC-OPS-002 binary
 * OR w_ident not yet completed) are ignored — they are not a positive
 * mixed-version signal.
 *
 * The bootstrap_tick caller treats a true return as "rolling deploy
 * incomplete; refuse to participate in bootstrap" and exits the
 * process with code 3 so systemd / the operator sees a clear signal
 * and can finish the rolling upgrade before relying on bootstrap.
 *
 * Pure scan, no I/O, no state mutation — testable in isolation.
 */
bool nodus_witness_bootstrap_any_peer_older(const nodus_witness_t *w,
                                             uint32_t local_nv);

#ifdef __cplusplus
}
#endif

#endif /* NODUS_WITNESS_BOOTSTRAP_H */
