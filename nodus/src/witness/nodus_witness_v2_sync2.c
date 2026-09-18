/**
 * @file nodus/src/witness/nodus_witness_v2_sync2.c
 * @brief Ledger V2 O15B — bounded catch-up, replay and restart.
 *
 * Contract and the one-engine argument are in nodus_witness_v2_sync2.h.
 * Read that first.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */

#include "witness/nodus_witness_v2_sync2.h"
#include "witness/nodus_witness_v2_gate.h"
#include "witness/nodus_witness_v2_bundle.h"  /* O15E Faz D genesis bundle */
#include "server/nodus_server.h"          /* identity for signed sends   */
#include "transport/nodus_tcp.h"
/* R3 W4 — nodus_witness_v2_ingress.h (file deleted; its ingress_block was
 * the range-apply path's only consumer here, and its blkframe_encode was
 * serve_block's, also deleted), nodus_witness_v2_claims.h (chain_id
 * derivation, used only by the deleted peer_compatible check),
 * nodus_witness_bft.h (file deleted; nodus_witness_bft_broadcast was the
 * old-lane head-hint's only caller), nodus_witness_v2_schema.h (schema
 * version, read only by the deleted serve_block) and dnac/blockmsg_v2.h
 * + crypto/hash/qgp_sha3.h (BlockMessage v1 encode and claim-hash verify,
 * both only in the deleted serve_block) are DROPPED with the closed
 * consensus lane.
 *
 * R3 W4-D (Delta B) — dnac/block_v2.h is ALSO now dropped:
 * nodus_witness_v2_sync_restart_check, its one remaining user
 * (dna_block_header_v2_t / dna_bh2_* / DNA_BH2_*), is itself deleted this
 * delta — its only production callers were already gone (Delta A), and its
 * one surviving caller was test_v2_gate.c's sync section (test_v2_gate.c
 * is CONVERT/STOP territory; see the Delta B report for its exact lines). */

#include <sqlite3.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "crypto/utils/qgp_log.h"

#define LOG_TAG "W_V2SYNC2"

/* ── O15E Faz D local policy knob (never consensus) ──────────────────── */
#define V2SYNC_SERVE_MIN_GAP_MS      100u /* H-1 sign-amplification guard */
/* R3 W4 — V2SYNC_HEAD_INTERVAL_MS, V2SYNC_REQ_TIMEOUT_MS and
 * V2SYNC_QCFETCH_INTERVAL_MS are DELETED with the closed consensus lane:
 * they paced the old-lane head-hint broadcast, range-request timeout and
 * QC-recovery fetch, all deleted above. */

static uint64_t v2sync_monotonic_ms(void) {
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) return 0;
    return (uint64_t)ts.tv_sec * 1000ULL + (uint64_t)ts.tv_nsec / 1000000ULL;
}

/* R3 W4 — v2_head (committed-tip reader), nodus_witness_v2_sync_peer_
 * compatible, nodus_witness_v2_sync_plan_range and nodus_witness_v2_sync_
 * apply_range are DELETED with the closed consensus lane: they drove the
 * old-lane head-hint / bounded-range CATCH-UP driver (T3 verbs 20-23,
 * retired), and apply_range's own engine entry, nodus_witness_v2_ingress_
 * block, is deleted with its file (nodus_witness_v2_ingress.c/.h). A
 * version-3 chain catches up through the cometbft reactor's own stored-
 * part gossip, not through this range protocol. */

/* R3 W4 — nodus_witness_v2_sync_serve_block (serve ONE committed
 * successor block as an encoded BlockMessage v1) is DELETED with the
 * closed consensus lane: its final assembly step called
 * nodus_witness_v2_blkframe_encode, declared AND defined only in
 * nodus_witness_v2_ingress.h/.c, both deleted. Its only production
 * caller, the old-lane range-serve path, is also deleted above. */

/* ── O15E Faz D — the surviving genesis-bundle serve path ────────────── */

/* Successor + armed: the ONE predicate the surviving handler asks first.
 * Anything else answers nothing (no residue).
 *
 * R3 W4 package P (the preflight-per-request cost): this predicate used
 * to ALSO call `nodus_witness_v2_activation_permitted(w)`, which is
 * `nodus_witness_v2_gate_state(w) == OPEN` — the authority probe plus the
 * WHOLE O15A preflight (five S14 store opens, the canonical-strict
 * document decode, the app_hash recomputation against block 1's
 * BlockMeta) — on EVERY genesis-bundle request. `v2_ingress_armed` is
 * already that gate's answer: `nodus_witness_v2_ingress_arm` sets it
 * ONLY when the gate is OPEN (nodus_witness_v2_gate.c) and it is set at
 * exactly one place, the post-open gate (`witness_post_open_gate`,
 * nodus_witness.c — at database open and, since W3 C2a-18, after a
 * joiner's adopt), and cleared by `nodus_witness_v2_ingress_disarm`. The
 * reference decides a node's role ONCE (node.go's startup table); a
 * per-request re-decision is a C-only cost with no reference line. What
 * the re-check incidentally provided — refusing to serve once the
 * preflight has drifted after arming — is not a guarantee anything
 * relied on: the joiner never trusts the served bytes, it re-derives the
 * genesis and adopts only on a byte-identical pin match
 * (nodus_witness_v2_join.c), so a stale or corrupt bundle is refused at
 * the joiner, not here. */
static int v2sync_ready(nodus_witness_t *w) {
    return w && w->db && w->v2_successor &&
           nodus_witness_v2_ingress_is_armed(w);
}

/* Signed unicast on an existing connection, through the 1 MB heap
 * encode path. R3 W4 deleted the range-response verbs this comment
 * used to name (T3 verbs 20-23); the sole surviving caller is the
 * genesis-bundle response (verbs 24-25, handle_gbundle_q below),
 * whose chunk payload (up to NODUS_T3_V2_GBUNDLE_CHUNK_MAX) still
 * needs the heap buffer rather than a stack one. */
static void v2sync_send(nodus_witness_t *w, struct nodus_tcp_conn *conn,
                        nodus_t3_msg_t *msg) {
    if (!conn) return;
    const char *method = nodus_t3_type_to_method(msg->type);
    if (method)
        snprintf(msg->method, sizeof(msg->method), "%s", method);
    msg->header.version = 1;
    memcpy(msg->header.sender_id, w->my_id, NODUS_T3_WITNESS_ID_LEN);
    msg->header.timestamp = (uint64_t)time(NULL);
    memcpy(msg->header.chain_id, w->chain_id, 32);

    uint8_t *buf = malloc(NODUS_W_MAX_SYNC_RSP_SIZE);
    if (!buf) return;
    size_t len = 0;
    if (nodus_t3_encode(msg, &w->server->identity.sk, buf,
                        NODUS_W_MAX_SYNC_RSP_SIZE, &len) == 0)
        (void)nodus_tcp_send(conn, buf, len);
    free(buf);
}

/* R3 W4 — v2sync_genesis_id (already noted DEAD on a version-3 chain by
 * handle_gbundle_q's own comment below), v2sync_request_range,
 * nodus_witness_v2_sync_handle_head, v2sync_serve,
 * nodus_witness_v2_sync_handle_range_q and nodus_witness_v2_sync_handle_
 * block_q are DELETED with the closed consensus lane: the old-lane head-
 * hint / range-request / range-serve / single-block-serve driver (T3
 * verbs 20-23, retired). The surviving genesis-bundle serve path
 * (verbs 24-25) follows. */

void nodus_witness_v2_sync_handle_gbundle_q(nodus_witness_t *w,
                                            struct nodus_tcp_conn *conn,
                                            const nodus_t3_msg_t *msg) {
    if (!v2sync_ready(w) || !msg || !conn) return;

    /* D-24 rev 4 (1): THE PIN IS THE 32-BYTE CHAIN ID. A version-3 chain
     * has no genesis BLOCK to pin a joiner to (D-19 rev 6 withdrew it) —
     * the chain's only identity is the stored genesis DOCUMENT's hash
     * (D-18 rev 4), which is exactly `w->v2_chain32`. `v2sync_genesis_id`
     * (the height-0 `v2_blocks.block_id` reader) is DEAD on a version-3
     * chain and is no longer called here; its other three callers are the
     * closed old lane (verbs 20-23) and are unchanged. The `chain` field
     * and the `pin` field now name the SAME identity — `chain` picks
     * which chain this request is about, `pin` is the requester's own
     * expectation of it — and we serve only when both agree with what we
     * actually run. */
    if (memcmp(msg->w_v2_gbundle_q.chain, w->v2_chain32, 32) != 0) return;
    if (memcmp(msg->w_v2_gbundle_q.pin, w->v2_chain32, 32) != 0) return;

    /* Rate-limit (H-1 sign-amplification). */
    uint64_t now = v2sync_monotonic_ms();
    if (w->v2_sync.last_serve_ms != 0 &&
        now - w->v2_sync.last_serve_ms < V2SYNC_SERVE_MIN_GAP_MS)
        return;

    uint8_t *bundle = NULL;
    size_t blen = 0;
    if (nodus_witness_v2_bundle_get(w, &bundle, &blen) != 0) return;

    uint64_t off = msg->w_v2_gbundle_q.offset;
    if (off > blen) { free(bundle); return; }
    size_t remain = blen - (size_t)off;
    uint32_t chunk = (remain > NODUS_T3_V2_GBUNDLE_CHUNK_MAX)
                         ? NODUS_T3_V2_GBUNDLE_CHUNK_MAX
                         : (uint32_t)remain;

    nodus_t3_msg_t rsp;
    memset(&rsp, 0, sizeof(rsp));
    rsp.type = NODUS_T3_V2_GBUNDLE_RSP;
    memcpy(rsp.w_v2_gbundle_r.chain, w->v2_chain32, 32);
    memcpy(rsp.w_v2_gbundle_r.pin, w->v2_chain32, 32);
    rsp.w_v2_gbundle_r.total     = (uint64_t)blen;
    rsp.w_v2_gbundle_r.offset    = off;
    rsp.w_v2_gbundle_r.chunk     = bundle + off;
    rsp.w_v2_gbundle_r.chunk_len = chunk;
    v2sync_send(w, conn, &rsp);
    free(bundle);
    w->v2_sync.last_serve_ms = now;
    QGP_LOG_INFO(LOG_TAG, "served genesis bundle chunk @%llu (%u/%zu bytes)",
                 (unsigned long long)off, chunk, blen);
}

/* R3 W4 — nodus_witness_v2_sync_handle_range_r, nodus_witness_v2_qc_
 * first_missing, v2sync_fetch_qc and nodus_witness_v2_sync_tick are
 * DELETED with the closed consensus lane: the old-lane range response
 * handler, missing-QC recovery driver and the periodic tick that drove
 * the head-hint broadcast and QC-recovery fetch (T3 verbs 20-23,
 * retired). nodus_witness_tick (nodus_witness.c) no longer calls
 * nodus_witness_v2_sync_tick. */

/* R3 W4-D (Delta B) — nodus_witness_v2_sync_restart_check (the v2_blocks
 * chain-integrity re-scan on restart) is DELETED here: see the deletion
 * note above this file's include block for why. */
