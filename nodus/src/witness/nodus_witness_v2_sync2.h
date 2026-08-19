/**
 * @file nodus/src/witness/nodus_witness_v2_sync2.h
 * @brief Ledger V2 O15B — bounded catch-up, replay and restart.
 *
 * Named `sync2` because `nodus_witness_sync.{c,h}` is the LEGACY sync path
 * and is untouched by this season. Two files, two lanes, no shared state,
 * no fallback between them.
 *
 * ═══ PRODUCTION-DORMANT ═════════════════════════════════════════════════
 * Every entry point here asks the activation gate first and returns
 * `NODUS_V2_NOT_ACTIVE` while it is closed — which it always is in this
 * build. See nodus_witness_v2_gate.h.
 *
 * ═══ THE ONE PROPERTY THIS MODULE EXISTS TO PRESERVE ════════════════════
 * A block applied by catch-up, by replay, by restart recovery or by live
 * finalization goes through the SAME code and produces the SAME BlockID and
 * the SAME post-state. That is not a convention here — it is structural:
 * every path in this file ends in `nodus_witness_v2_ingress_block()`, which
 * ends in `nodus_witness_v2_finalize_block()`, which is the one engine.
 * This file contains no second verifier, no second apply, no "fast path for
 * historical blocks", and no shortcut that skips a check because the bytes
 * came from a trusted place. There is no trusted place.
 *
 * In particular, a HISTORICAL block is verified against the validator
 * snapshot that governed ITS height, not the current set. That resolution
 * happens inside the engine (`nodus_witness_v2_qc_verify` →
 * `nodus_witness_v2_epoch_authority_for_height`), and this module cannot
 * override it because it has no parameter through which to try.
 *
 * ═══ ADVERTISEMENTS ARE HINTS ═══════════════════════════════════════════
 * A peer's claimed head selects nothing and authorises nothing. It is used
 * only to decide whether asking that peer for a range is worth a round
 * trip, and every byte that comes back is verified as if it were hostile.
 *
 * ═══ WHAT IS NOT HERE, AND WHY ══════════════════════════════════════════
 * There is no reorg path. Finalized history is FINAL: a range whose parent
 * link does not match committed state fails closed and stops at the first
 * bad record. Inventing a reorg would mean inventing a fork-choice rule
 * this chain does not have.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */

#ifndef NODUS_WITNESS_V2_SYNC2_H
#define NODUS_WITNESS_V2_SYNC2_H

#include <stddef.h>
#include <stdint.h>

#include "witness/nodus_witness.h"
#include "witness/nodus_witness_v2_result.h"
#include "protocol/nodus_tier3.h"       /* O15E: verb 20-23 handlers   */

struct nodus_tcp_conn;

#ifdef __cplusplus
extern "C" {
#endif

/* ── Bounds. All LOCAL resource policy; none is consensus. ───────────── */

/** Maximum blocks one range request may ask for or a response may carry. */
#define NODUS_V2_SYNC_MAX_RANGE_BLOCKS  16u
/** Maximum total bytes in one range response. */
#define NODUS_V2_SYNC_MAX_RANGE_BYTES   (8u * 1024u * 1024u)

/**
 * A peer's claimed head. A HINT — never authority.
 *
 * `chain_id` and `genesis_block_id` are what make it worth acting on at
 * all: a peer on another chain is not behind or ahead, it is irrelevant,
 * and establishing that before exchanging blocks is cheaper than
 * discovering it per block. Neither field is trusted afterwards; the engine
 * re-derives chain identity from committed state for every block.
 */
typedef struct {
    uint8_t  chain_id[32];
    uint8_t  genesis_block_id[64];
    uint64_t head_height;
    uint32_t protocol_version;   /**< DNA_BLKW_VERSION the peer speaks */
} nodus_v2_head_hint_t;

/**
 * Is this peer worth syncing from?
 *
 * Compatibility is established BEFORE any block is exchanged: same chain
 * id, same genesis identity, a protocol version this build implements.
 *
 * @return 1 compatible, 0 not (including NULL, and including a fault
 *         deriving our own identity — "we could not tell" is never "yes").
 */
int nodus_witness_v2_sync_peer_compatible(nodus_witness_t *w,
                                          const nodus_v2_head_hint_t *hint);

/**
 * Plan the next bounded range to request.
 *
 * Deterministic: two nodes with the same committed head and the same hint
 * ask for the same range.
 *
 * @param w         witness handle.
 * @param hint      the peer's claimed head (a hint).
 * @param from_out  [out] first height to request.
 * @param count_out [out] how many, 0 when nothing is needed.
 * @return 0 planned (check *count_out), -1 on NULL/fault,
 *         NODUS_V2_NOT_ACTIVE when the gate is closed.
 */
int nodus_witness_v2_sync_plan_range(nodus_witness_t *w,
                                     const nodus_v2_head_hint_t *hint,
                                     uint64_t *from_out,
                                     uint32_t *count_out);

/** Per-range outcome counters. */
typedef struct {
    uint32_t applied;      /**< newly committed                          */
    uint32_t duplicates;   /**< already committed; no second effect      */
    uint32_t deferred;     /**< NOT_YET_LINKABLE — a gap remains         */
    uint32_t rejected;     /**< a deterministic verdict; the range stops */
    uint32_t faults;       /**< node-local; the range stops, peer blameless */
    /** The result that stopped the range, or NODUS_V2_ACCEPTED if none. */
    nodus_v2_result_t stop_reason;
    /** Index of the first block that was not applied; == n on success. */
    uint32_t stop_index;
} nodus_v2_sync_range_result_t;

/**
 * Apply a received range, in order, through the one engine.
 *
 * STOPS AT THE FIRST BAD RECORD. It does not skip and continue: a range is
 * a claim about contiguous history, so the first block that does not apply
 * invalidates everything after it. Continuing would mean applying blocks
 * whose parent was never verified.
 *
 * Duplicates are idempotent — a block already committed produces no second
 * effect and does NOT stop the range, because re-sending is normal.
 *
 * @param w        witness handle.
 * @param peer_id  32-byte peer identity, may be NULL.
 * @param frames   array of `n` encoded BlockMessage v1 frames.
 * @param lens     their lengths.
 * @param n        how many; must be <= NODUS_V2_SYNC_MAX_RANGE_BLOCKS.
 * @param out      [out] counters; zeroed first.
 * @return 0 when the whole range applied or was duplicate,
 *         the stopping `nodus_v2_result_t` otherwise,
 *         NODUS_V2_NOT_ACTIVE when the gate is closed.
 */
int nodus_witness_v2_sync_apply_range(nodus_witness_t *w,
                                      const uint8_t *peer_id,
                                      const uint8_t *const *frames,
                                      const size_t *lens,
                                      uint32_t n,
                                      nodus_v2_sync_range_result_t *out);

/**
 * O15E Faz B — serve ONE committed successor block as an encoded
 * BlockMessage v1.
 *
 * Assembled entirely from committed state: the stored canonical header,
 * the stored verified QC, and the canonical envelope wire bytes the
 * apply engine persisted inside the block's own transaction
 * (v2_tx_bytes, S11). proposer_id and timestamp come from the STORED
 * header — nothing is invented.
 *
 * FAILS CLOSED as a sync source when the block cannot be served
 * faithfully: no committed row at the height, `qc IS NULL` (committed
 * but not yet certified — the live lane's legal window), byte records
 * missing or their count disagreeing with the header's tx_count
 * (pre-S11 heights), or any malformed stored field. Height 0 is NEVER
 * served — the genesis has no QC by construction; a joiner acquires the
 * genesis through the pinned-genesis path, not through BlockMessage.
 *
 * @param w        witness handle.
 * @param height   committed successor height (>= 1).
 * @param buf_out  [out] malloc'd encoded frame; caller frees.
 * @param len_out  [out] frame length.
 * @return 0 served; 1 unavailable (fail-closed, not a fault);
 *         -1 node-local fault; NODUS_V2_NOT_ACTIVE when the gate is
 *         closed.
 */
int nodus_witness_v2_sync_serve_block(nodus_witness_t *w, uint64_t height,
                                      uint8_t **buf_out, size_t *len_out);

/**
 * Restart / crash-recovery integrity check for the V2 lane.
 *
 * Re-derives the BlockID of the committed head from its STORED canonical
 * header bytes and compares it with the stored id. That is the property the
 * O14 `header` column exists to make checkable: if the two disagree, the
 * stored block is not the block its identity claims, and this node must not
 * serve or build on it.
 *
 * Reports the FIRST bad record and stops — it never "repairs", never
 * rebuilds, and never skips a corrupt row to keep going.
 *
 * @param w              witness handle.
 * @param bad_height_out [out] OPTIONAL; height of the first bad record.
 * @return 0 intact (including a chain with no V2 blocks at all),
 *         -1 corruption found, -2 the check could not be performed,
 *         NODUS_V2_NOT_ACTIVE when the gate is closed.
 */
int nodus_witness_v2_sync_restart_check(nodus_witness_t *w,
                                        uint64_t *bad_height_out);

/* ── O15E Faz B — the network seam (verbs 20-23) ─────────────────────
 *
 * All four handlers ask the activation gate BEFORE touching a byte and
 * answer NOTHING while it is closed (the O15B result algebra: no ack,
 * no queue, no peer standing). The dispatch layer has already verified
 * the sender's wsig against the transport roster. Serving is
 * per-sender rate-limited (the chain_q H-1 sign-amplification
 * discipline). Requests this node emits are LOCAL policy driven by the
 * tick — never consensus. */

/** verb 21 — a peer's head advertisement (a HINT). May emit ONE bounded
 *  w_v2_range_q at the sending peer when behind and idle. */
void nodus_witness_v2_sync_handle_head(nodus_witness_t *w,
                                       struct nodus_tcp_conn *conn,
                                       const nodus_t3_msg_t *msg);

/** verb 22 — a bounded range request; serves committed blocks
 *  (ascending, contiguous) within the frame/byte budgets. */
void nodus_witness_v2_sync_handle_range_q(nodus_witness_t *w,
                                          struct nodus_tcp_conn *conn,
                                          const nodus_t3_msg_t *msg);

/** verb 23 — a range response; applies IN ORDER through the one engine
 *  (nodus_witness_v2_sync_apply_range) and re-requests while behind. */
void nodus_witness_v2_sync_handle_range_r(nodus_witness_t *w,
                                          struct nodus_tcp_conn *conn,
                                          const nodus_t3_msg_t *msg);

/** verb 20 — a single-block fetch bound to (chain, height, BlockID);
 *  answers with a verb-23 response carrying exactly one frame. The
 *  request refuses to serve a block whose committed BlockID differs
 *  from the one named — the QC-recovery identity binding. */
void nodus_witness_v2_sync_handle_block_q(nodus_witness_t *w,
                                          struct nodus_tcp_conn *conn,
                                          const nodus_t3_msg_t *msg);

/** verb 24 — a genesis bundle chunk request (O15E Faz D). Serves one
 *  offset chunk of the persisted canonical bundle to a joiner whose pin
 *  equals this successor's committed genesis BlockID. Refuses any other
 *  chain / pin (a bundle is never served for a genesis this node did not
 *  commit). */
void nodus_witness_v2_sync_handle_gbundle_q(nodus_witness_t *w,
                                            struct nodus_tcp_conn *conn,
                                            const nodus_t3_msg_t *msg);

/** The successor sync driver, called from the witness tick. Successor +
 *  armed nodes only; self-throttled by monotonic time: broadcasts the
 *  w_v2_head hint on an interval, expires a timed-out in-flight range
 *  request, and (O15E Faz C) emits a bounded QC-recovery fetch for the
 *  lowest committed height whose stored QC is still NULL. Never blocks,
 *  never loops. */
void nodus_witness_v2_sync_tick(nodus_witness_t *w);

/** O15E Faz C — the lowest committed successor height (>= 1) whose
 *  stored QC is NULL, or 0 if every committed block is certified.
 *  Read-only. The missing-QC detector the tick and startup both use.
 *  @return 0 with *height_out set (0 = none), -1 on fault. */
int nodus_witness_v2_qc_first_missing(nodus_witness_t *w,
                                      uint64_t *height_out);

#ifdef __cplusplus
}
#endif

#endif /* NODUS_WITNESS_V2_SYNC2_H */
