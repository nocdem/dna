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

#ifdef __cplusplus
extern "C" {
#endif

/* Forward declaration to avoid pulling nodus_witness.h into every TU
 * that #includes this header. */
struct nodus_witness;
typedef struct nodus_witness nodus_witness_t;

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

#ifdef __cplusplus
}
#endif

#endif /* NODUS_WITNESS_BOOTSTRAP_H */
