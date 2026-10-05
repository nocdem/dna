/**
 * @file nodus_witness_storage_reporter.h
 * @brief Storage reward v1 rev 4 (the ARCHIVE reward), package B2b-1 —
 *        the RUNTIME of the archive probe on a live node: the serving
 *        side (a storage member answers probes from its block store) and
 *        the reporter (a seated validator probes every other storage
 *        member once per epoch and submits its STORAGE_REPORT in the
 *        report window). The wire, the checks and the builders:
 *        nodus_witness_storage_probe.h.
 *
 * Decisions: docs/plans/decisions/2026-10-05-storage-reward-is-for-
 * archive.md, 2026-10-05-archive-reward-bytes-approved.md (bytes doc §6),
 * 2026-10-05-kurultay-7-archive-reward-summary.md, 2026-10-04-storage-
 * reward-who-earns.md. Design docs/plans/2026-10-05-archive-reward-
 * design.md rev 4 §4 (probe), rev 2.2 §4 (report, window, expiry).
 *
 * ── TRANSPORT ──────────────────────────────────────────────────────────
 * Channel 0x72 (NODUS_P2P_CH_STPROBE) on the 4004 p2p host, over the
 * EXISTING authenticated connection to the target — the 0x71 approval
 * collection's model (nodus_witness_chain_config.c): no new connection is
 * dialed; a target that is not a connected peer (or does not list 0x72)
 * at its slot is retried at every later pass of the same epoch, and is
 * NOT OK if never reached. The pin: the target's p2p ID is the hex of
 * its REGISTERED node_fp[0..31] (the registry is the source; the p2p ID
 * of a peer is SHA3-512(its authenticated ML-DSA-87 key)[0..31],
 * nodus_witness_p2p.h), and an answer is taken only when SHA3-512 of the
 * SENDER's authenticated key equals the registered node_fp in full (64
 * bytes).
 *
 * ── THE REPORTER (a seated validator) ─────────────────────────────────
 * Runs only on a version-3 chain whose consensus lane is live and caught
 * up (not block-syncing), at most once per NODUS_STPROBE_TICK_MS.
 *   probing epoch H = floor(tip / E) · E, opened ONCE per H when this node
 *     holds a seat in snapshot(H) and storage_set(H) exists with >= 1
 *     member. Targets = every member but this node (F2), in set order;
 *     each one's eligible segments (nodus_witness_storage_eligible_
 *     segments) give B; B == 0 → no probe, bit 0. Target j is first tried
 *     at nodus_stprobe_slot_height (the first 3/4 of the epoch).
 *   a probe: fresh 32-byte nonce (nodus_random — the OS CSPRNG),
 *     deadline_ms = wall clock + NODUS_STPROBE_BUDGET_MS; the three
 *     sampled heights and this node's own v2_blocks hashes at h and h+1
 *     are read BEFORE the request leaves; the answer is judged by
 *     nodus_stprobe_answer_ok against a MONOTONIC deadline of the same
 *     budget. No answer by then = NOT OK.
 *   closing: at tip >= H + E the epoch moves to "reporting"; once no
 *     probe is outstanding, inside the window (H+E, H+E+⌊E/2⌋] the
 *     report (bit i = member i OK) is built, signed by this node's
 *     identity — the seat key — and handed to this node's own mempool
 *     (cmt_mem_check_tx, the dnac_spend path), expiry = min(tip + 100,
 *     window close). Resubmitted when its expiry passed with no committed
 *     (H, seat) row, or NODUS_STPROBE_RESUBMIT_GAP blocks after a refused
 *     CheckTx; given up when the window closes.
 *   A restart loses an epoch's probe results: no report is sent for an
 *   epoch this process did not probe (a missing report only lowers the
 *   reporting power; a report of zeros would be a false attestation).
 *
 * ── THE SERVING SIDE (a storage member) ───────────────────────────────
 * Answers a REQUEST only after, in order: the per-requester gap
 * (NODUS_STPROBE_SERVE_GAP_MS), the request decode, the pure checks
 * (chain, addressed to this node, reporter == the authenticated sender,
 * epoch_start a boundary, deadline not passed by this node's wall clock),
 * storage_set(H) known here with the request's S(H), this node a member
 * with B > 0, and the requester seated in snapshot(H) — then the three
 * samples, each from its own block store (header(h+1) meta, the part and
 * its proof) while the store still has that block, else from its held
 * segment file (package B2b-2, nodus_seg_probe_sample — the same bytes).
 * Any refusal is answered with its code.
 *
 * ── DETERMINISM ───────────────────────────────────────────────────────
 * Nothing here writes state. Clocks (wall: the deadline; monotonic: the
 * waits, the rate limit, the tick gap), the nonce and the network decide
 * only the bits THIS node signs into its report — design rev 4 §7 D3.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */

#ifndef NODUS_WITNESS_STORAGE_REPORTER_H
#define NODUS_WITNESS_STORAGE_REPORTER_H

#include "witness/nodus_witness.h"
#include "witness/nodus_witness_storage_probe.h"

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/** The reporter's tick gap (monotonic). Local policy. */
#define NODUS_STPROBE_TICK_MS          500
/** At most this many probes leave per tick (bounds one pass's work). */
#define NODUS_STPROBE_SENDS_PER_TICK   4u
/** Blocks between two submissions after a refused CheckTx. Local
 *  policy. */
#define NODUS_STPROBE_RESUBMIT_GAP     10u
/** The serving side's requester table (one slot per connectable peer). */
#define NODUS_STPROBE_SERVE_SLOTS      64u

/**
 * The serving side's whole decision for one decoded request from the
 * peer whose authenticated node key hashes to `sender_fp`: the checks in
 * the header's order (the rate limit is the caller's), then the answer
 * read from `store` (may be NULL); a sample the store does not hold is
 * read from the held segment file under the witness data path
 * (nodus_witness_sthold_dir; package B2b-2). `out` / `cap` receive the OK
 * answer (cap >= NODUS_STPROBE_MSG_MAX); a refusal sets no length. `E`
 * the epoch length.
 * Exported for the unit tests; the runtime calls it with the live store.
 * @return NODUS_STPROBE_OK (*len_out set) or the refusal code.
 */
nodus_stprobe_code_t nodus_witness_stprobe_serve(
        nodus_witness_t *w, nodus_cmt_store_t *store,
        const uint8_t sender_fp[64], const nodus_stprobe_req_t *req,
        uint64_t E, uint64_t now_wall_ms,
        uint8_t *out, size_t cap, size_t *len_out);

/** One pass of the reporter (header "THE REPORTER"); a no-op until the
 *  node runs a live, caught-up version-3 lane. Called by the witness tick. */
void nodus_witness_stprobe_tick(nodus_witness_t *w);

/**
 * A channel 0x72 message from the connected peer `peer_id`, whose
 * AUTHENTICATED node key hashes to `sender_fp` (64 bytes). A REQUEST is
 * served (header "THE SERVING SIDE"); an ANSWER is taken only by this
 * node's own outstanding probe with the same `rq` from that same
 * identity, every other answer is dropped (DEBUG — a late honest answer
 * looks the same).
 * @return 0 handled or dropped; -1 the message does not decode (the
 *         caller stops the peer, as for 0x70 / 0x71).
 */
int nodus_witness_stprobe_on_msg(nodus_witness_t *w, const char *peer_id,
                                 const uint8_t sender_fp[64],
                                 const uint8_t *msg, size_t len);

/** Free the runtime state (the witness close, before the p2p host goes).
 *  NULL-safe; idempotent. */
void nodus_witness_stprobe_free(nodus_witness_t *w);

#ifdef __cplusplus
}
#endif

#endif /* NODUS_WITNESS_STORAGE_REPORTER_H */
