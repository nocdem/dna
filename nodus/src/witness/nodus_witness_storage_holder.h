/**
 * @file nodus_witness_storage_holder.h
 * @brief Storage reward v1 rev 4 (the ARCHIVE reward), package B2b-2 —
 *        the HOLDER's runtime on a live node: which segments this node
 *        must hold, exporting them from its own block store, fetching
 *        them over channel 0x73 when it cannot, deleting them once the
 *        handoff overlap has passed, the retain_blocks warning, and the
 *        0x73 serving side's message handling and budget.
 *        File layout: nodus_witness_storage_segment.h; the 0x73 wire and
 *        admission: nodus_witness_storage_fetch.h.
 *
 * Decisions: docs/plans/decisions/2026-10-05-storage-reward-is-for-
 * archive.md (R = 3, G = 1), 2026-10-05-kurultay-7-archive-reward-
 * summary.md (items 4, 5, 7: exported files; bounded, verified fetch;
 * the outgoing holder keeps serving for an overlap epoch), 2026-10-03-
 * block-pruning-7-paydays.md (the 2026-10-05 rollout change). Design
 * docs/plans/2026-10-05-archive-reward-design.md rev 4 §2 (handoff), §3.
 *
 * ── MUST HOLD (design rev 4 §2; nodus_witness_v2_storage.h
 *    "ELIGIBILITY") ────────────────────────────────────────────────────
 *   At the current epoch H = floor(tip / E) · E this node (node_fp = me)
 *   must hold segment k iff
 *       me ∈ holders(k, H)                         (assigned now — a NEW
 *                                                   holder fetches during
 *                                                   its grace epoch)
 *    or published_height(k) <= H − E  and  me ∈ holders(k, H − E)
 *                                                  (displaced at H: still
 *                                                   probed and paid
 *                                                   through (H, H+E] —
 *                                                   the overlap epoch)
 *   holders(k, X) = bytes item 3 over storage_set(X) with the
 *   fail_streaks frozen at X (nodus_witness_storage_holders). The second
 *   line is exactly the probe's eligibility rule, so a file is never
 *   deleted while a reporter can still sample it.
 *   DELETE segment k's files iff k is a published segment and this node
 *   must not hold it — i.e. no longer a holder AND the overlap epoch has
 *   passed (at H + E the displaced holder is in neither line). Fail-safe:
 *   when storage_set(H) is absent or a read faults, nothing is deleted;
 *   an absent storage_set(H − E) counts as empty (the eligibility
 *   reader's rule).
 *
 * ── THE JOB (one segment at a time, k ascending) ───────────────────────
 *   The smallest must-hold k that is not held is opened
 *   (nodus_seg_build_open — a partial file is resumed, re-verified in
 *   steps of NODUS_STHOLD_SCAN_HEIGHTS); then EXPORT when this node's
 *   block store still has the whole range (nodus_seg_store_has),
 *   NODUS_STHOLD_EXPORT_HEIGHTS heights per pass; else FETCH over 0x73.
 *   Done → atomic publish → held. Every pass is bounded so the witness
 *   thread (which also runs consensus) is never held for a whole segment.
 *
 * ── THE FETCH CLIENT ───────────────────────────────────────────────────
 *   ONE request outstanding (one block in flight, from one peer). The
 *   peer order: the other holders of k (holders(k, H), then holders(k,
 *   H−E); their p2p ID is the hex of the REGISTERED node_fp[0..31]) that
 *   are connected, then every other connected peer — a full archive node
 *   (EU-6, US-1) or any node whose store still has the blocks. An answer
 *   is taken only from that peer for that rq; a refusal, a chunk that
 *   fails verification or NODUS_STFETCH_TIMEOUT_MS of silence moves to
 *   the next peer; a full round of peers without progress waits
 *   NODUS_STFETCH_RETRY_MS. A verified answer is written and the next
 *   request leaves at once. Restart: the partial file is resumed (above).
 *
 * ── THE SERVING SIDE (0x73) ────────────────────────────────────────────
 *   decode (an undecodable message stops the peer) → the requester's
 *   epoch budget not spent → nodus_witness_stfetch_serve (admission, the
 *   piece) → the answer's size (at least NODUS_STFETCH_COST_MIN) charged
 *   to the requester; an admitted refusal costs NODUS_STFETCH_COST_MIN.
 *
 * ── THE retain_blocks WARNING ─────────────────────────────────────────
 *   At every assignment (the first pass after start, then once per
 *   epoch): retain_blocks > 0 while a must-hold segment is not complete
 *   → WARN (decision 2026-10-03-block-pruning-7-paydays.md, rollout
 *   change: pruning a storage node before its segments are complete
 *   makes it fail every probe of a pruned block). The prune loop itself
 *   is unchanged.
 *
 * ── DETERMINISM (design rev 4 §7 D3, D4) ──────────────────────────────
 * Nothing here writes the database or is read by the state machine:
 * the assignment is READ from committed rows; clocks (the tick gap, the
 * fetch timeout and retry), the network and the disk decide only which
 * files this node keeps. The probe and its signed report remain the one
 * path to state.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */

#ifndef NODUS_WITNESS_STORAGE_HOLDER_H
#define NODUS_WITNESS_STORAGE_HOLDER_H

#include "witness/nodus_witness.h"
#include "witness/nodus_witness_storage_fetch.h"

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/** The holder's tick gap (monotonic). ⚠ NOT GROUNDED — local policy. */
#define NODUS_STHOLD_TICK_MS         200
/** Heights exported per pass. ⚠ NOT GROUNDED — local policy: ≈ 32 × 100
 *  KB read and hashed per pass; a segment in ≈ 540 passes. */
#define NODUS_STHOLD_EXPORT_HEIGHTS  32u
/** Heights re-verified per pass of a resume scan. ⚠ NOT GROUNDED. */
#define NODUS_STHOLD_SCAN_HEIGHTS    32u
/** A fetch request unanswered this long moves to the next peer.
 *  ⚠ NOT GROUNDED — one answer is at most ≈ 610 KB. */
#define NODUS_STFETCH_TIMEOUT_MS     10000
/** After a full round of peers without progress. ⚠ NOT GROUNDED. */
#define NODUS_STFETCH_RETRY_MS       30000
/** The most must-hold segments computed (the probe's bound). */
#define NODUS_STHOLD_MAX_SEGS        NODUS_STPROBE_MAX_SEGS
/** The serving side's budget table: one slot per member of a set. */
#define NODUS_STFETCH_SERVE_SLOTS    DNA_V2_STORAGE_SET_MAX

/** This node's segment directory: <data_path>/<segment_dir or
 *  NODUS_SEG_DIR_DEFAULT>. @return 0 / -1 (no data path, a segment_dir
 *  that is not one plain path component, does not fit). */
int nodus_witness_sthold_dir(nodus_witness_t *w, char *out, size_t cap);

/** The segments `me` must hold at epoch H (header "MUST HOLD"), k
 *  ascending, into ks[0..*n_out) (cap entries). @return 0 / 1 no
 *  storage_set(H) (nothing may be deleted) / -1 fault or cap too small. */
int nodus_witness_sthold_must_hold(nodus_witness_t *w, uint64_t H,
                                   const uint8_t me[64], uint64_t *ks,
                                   size_t cap, size_t *n_out);

/** Delete the files of every published segment in `dir` that `me` must
 *  not hold at epoch H (header "MUST HOLD"). Nothing is deleted unless
 *  the must-hold list was computed (return 0 of the function above).
 *  @return the number of segments deleted, or -1. */
int nodus_witness_sthold_gc(nodus_witness_t *w, const char *dir, uint64_t H,
                            const uint8_t me[64]);

/** One pass of the holder (header "THE JOB", "THE FETCH CLIENT"); a no-op
 *  until the node runs a live, caught-up version-3 lane. Called by the
 *  witness tick. */
void nodus_witness_sthold_tick(nodus_witness_t *w);

/**
 * A channel 0x73 message from the connected peer `peer_id`, whose
 * AUTHENTICATED node key hashes to `sender_fp` (64 bytes). A REQUEST is
 * served (header "THE SERVING SIDE"); an ANSWER is taken only by this
 * node's own outstanding request (same peer, same rq), every other answer
 * is dropped (DEBUG — a late honest answer looks the same).
 * @return 0 handled or dropped; -1 the message does not decode (the
 *         caller stops the peer, as for 0x70-0x72).
 */
int nodus_witness_sthold_on_msg(nodus_witness_t *w, const char *peer_id,
                                const uint8_t sender_fp[64],
                                const uint8_t *msg, size_t len);

/** Free the runtime (the witness close, before the p2p host goes); an
 *  open build is closed and its partial file kept. NULL-safe. */
void nodus_witness_sthold_free(nodus_witness_t *w);

#ifdef __cplusplus
}
#endif

#endif /* NODUS_WITNESS_STORAGE_HOLDER_H */
