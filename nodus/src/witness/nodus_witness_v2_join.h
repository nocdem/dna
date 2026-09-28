/**
 * @file nodus/src/witness/nodus_witness_v2_join.h
 * @brief Ledger V2 O15E Faz D — pinned-genesis joiner bootstrap.
 *
 * A fresh node with an EMPTY data directory and an operator-supplied
 * successor genesis pin acquires the successor chain WITHOUT trusting any
 * peer's claimed genesis:
 *
 *   1. it joins the 4004 p2p network like any other node (P2P-PORT F5):
 *      its NodeInfo network is its pin (the same 32 bytes as the chain
 *      id it expects), it dials its persistent peers, and it is admitted
 *      as an ordinary (unbonded) peer — never into the BFT committee;
 *   2. it pulls the canonical genesis BUNDLE in offset chunks (channel
 *      0x70, the former w_v2_gbundle_q/r) from any connected peer whose
 *      committed genesis equals the pin;
 *   3. it re-derives the genesis from the bundle bytes and requires the
 *      chain id the engine recomputes from those bytes to EQUAL the
 *      LOCAL pin (nodus_witness_v2_bundle_apply) — a version-3 chain has
 *      no genesis BlockID; the pin IS the 32-byte chain id (D-24 rev 4
 *      (1)); a wrong bundle leaves zero trace;
 *   4. it adopts the derived successor DB in place, opens the main
 *      witness on it (the SAME path a restart takes), and — R3 W3 delta 9
 *      — immediately builds the cometbft server binding on that live
 *      handle (`nodus_witness_cmt_live_init`, nodus_witness.h): the
 *      reference has no mid-life adoption, so the honest port of "this
 *      node now starts with this genesis" is to run, right here, the
 *      SAME construction a process start runs. From the next tick on it
 *      is an ordinary successor node whose catch-up runs through the
 *      consensus reactor's own stored-part gossip — there is no
 *      blocksync in this port (D-23 rev 7 item 18).
 *
 * THE PIN IS THE ONLY TRUST ANCHOR, and it is LOCAL: it arrives through
 * node configuration / CLI (nodus_server_config.v2_genesis_pin), never
 * over the wire. No pin → the joiner never adopts anything (fail-closed).
 * A network-supplied genesis that does not re-derive to the pin is
 * rejected. Neither peer majority nor first-seen peer is ever TOFU.
 *
 * ROLE SAFETY: until the node has caught up to a QC-certified head it
 * cannot propose, vote, or act as leader — its committed successor tip is
 * behind the committee's, and the round machinery anchors on that tip.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef NODUS_WITNESS_V2_JOIN_H
#define NODUS_WITNESS_V2_JOIN_H

#include <stddef.h>
#include <stdint.h>

#include "witness/nodus_witness.h"
#include "protocol/nodus_tier3.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Arm the joiner if this node was started with a genesis pin and has no
 * successor chain yet. Called once from witness init, after the chain
 * scan. A node that already holds a successor (or has no pin) is NOT a
 * joiner and this is a no-op.
 *
 * @return 1 joiner armed, 0 not a joiner, -1 fault.
 */
int nodus_witness_v2_join_arm(nodus_witness_t *w);

/** Is the joiner still fetching/deriving (not yet adopted)? While true,
 *  the node MUST NOT propose or vote. */
int nodus_witness_v2_join_active(nodus_witness_t *w);

/**
 * Joiner tick: while armed and at least one p2p peer is connected, send a
 * bounded bundle-chunk request (channel 0x70) at the accumulated offset
 * to this download's ONE source peer (self-throttled, one request per
 * interval). A source whose previous request went unanswered for a whole
 * interval is excluded for this join attempt; a new source is the next
 * non-excluded connected peer in round-robin order and starts from
 * offset 0 (decision 2026-09-27-p2p-fix-2.md (3)). No-op once adopted.
 * Called from the witness tick.
 */
void nodus_witness_v2_join_tick(nodus_witness_t *w);

/** Whether `peer_id` is excluded as a genesis-bundle source for the rest
 *  of this join attempt (its total changed, it refused or left
 *  unanswered a chunk, or its bundle failed at adopt). */
bool nodus_witness_v2_join_is_excluded(const nodus_witness_t *w,
                                       const char *peer_id);

/**
 * Channel 0x70 response (the former verb 25) from the connected peer
 * `peer_id` — accumulate a genesis-bundle chunk, but ONLY when it answers
 * this joiner's one outstanding request (that peer — the download's one
 * source — that offset; nodus_witness_p2p_gb_take); any other response is
 * dropped, its sender never stopped (red-team H2). An answer the download
 * cannot use (another pin, an empty chunk, a total out of range or
 * CHANGED) excludes the source and drops the bytes; so does a complete
 * bundle that fails at adopt (decision 2026-09-27-p2p-fix-2.md (3)). On
 * the final chunk,
 * re-derive the genesis against the local pin and, on a match, adopt the
 * successor DB in place, open the main witness on it and build its
 * cometbft server binding (R3 W3 delta 9 — the node becomes an ordinary,
 * LIVE successor, not merely a chain-holding one). A pin mismatch or any
 * malformed bundle is caught BEFORE the successor DB is renamed into
 * place, so it leaves the node an unadopted joiner with zero durable
 * trace, free to retry. A failure to build the cometbft server binding
 * happens AFTER that rename — the successor DB is already durably
 * adopted and open — so it is fatal joiner state, not a retryable one;
 * see `join_adopt`'s own comment (nodus_witness_v2_join.c) for why.
 */
void nodus_witness_v2_join_handle_gbundle_r(nodus_witness_t *w,
                                            const char *peer_id,
                                            const nodus_t3_w_v2_gbundle_r_t *r);

#ifdef __cplusplus
}
#endif

#endif /* NODUS_WITNESS_V2_JOIN_H */
