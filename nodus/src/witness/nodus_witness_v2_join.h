/**
 * @file nodus/src/witness/nodus_witness_v2_join.h
 * @brief Ledger V2 O15E Faz D — pinned-genesis joiner bootstrap.
 *
 * A fresh node with an EMPTY data directory and an operator-supplied
 * successor genesis pin acquires the successor chain WITHOUT trusting any
 * peer's claimed genesis:
 *
 *   1. it enters the ordinary peer mesh (IDENT), so committee members add
 *      it to their TRANSPORT roster (not the BFT committee — F17);
 *   2. it pulls the canonical genesis BUNDLE in offset chunks
 *      (w_v2_gbundle_q/r) from any peer whose committed genesis equals
 *      the pin;
 *   3. it re-derives the genesis from the bundle bytes and requires the
 *      engine-derived genesis BlockID to EQUAL the LOCAL pin
 *      (nodus_witness_v2_bundle_apply); a wrong bundle leaves zero trace;
 *   4. it adopts the derived successor DB in place and, from then on, is
 *      an ordinary successor node whose Faz B catch-up brings it to head.
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

struct nodus_tcp_conn;

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
 * Joiner tick: while armed and at least one transport peer is known,
 * emit a bounded bundle-chunk request at the accumulated offset
 * (self-throttled). No-op once adopted. Called from the witness tick.
 */
void nodus_witness_v2_join_tick(nodus_witness_t *w);

/**
 * verb 25 — accumulate a genesis-bundle chunk. On the final chunk,
 * re-derive the genesis against the local pin and, on a match, adopt the
 * successor DB in place (the node becomes an ordinary successor). A pin
 * mismatch or any malformed bundle leaves the node an unadopted joiner
 * with zero durable trace, free to retry.
 */
void nodus_witness_v2_join_handle_gbundle_r(nodus_witness_t *w,
                                            struct nodus_tcp_conn *conn,
                                            const nodus_t3_msg_t *msg);

#ifdef __cplusplus
}
#endif

#endif /* NODUS_WITNESS_V2_JOIN_H */
