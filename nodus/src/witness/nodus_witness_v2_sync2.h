/**
 * @file nodus/src/witness/nodus_witness_v2_sync2.h
 * @brief Ledger V2 O15B — bounded catch-up, replay and restart.
 *
 * Named `sync2` because `nodus_witness_sync.{c,h}` was the LEGACY sync
 * path; that file is DELETED (R3 W4, closed consensus lane).
 *
 * ═══ R3 W4 — MOST OF THIS MODULE IS DELETED WITH THE CLOSED CONSENSUS
 *     LANE ═══════════════════════════════════════════════════════════════
 * The old-lane head-hint / bounded-range catch-up driver (T3 verbs 20-23:
 * nodus_witness_v2_sync_handle_head/_range_q/_range_r/_block_q,
 * nodus_witness_v2_sync_peer_compatible/_plan_range/_apply_range,
 * nodus_witness_v2_qc_first_missing, nodus_witness_v2_sync_tick and
 * nodus_witness_v2_sync_serve_block — the last because its final
 * assembly step called nodus_witness_v2_blkframe_encode, declared AND
 * defined only in the also-deleted nodus_witness_v2_ingress.h/.c) is
 * gone: a version-3 chain catches up through the cometbft reactor's own
 * stored-part gossip, never through this range protocol. What SURVIVES
 * is the genesis-bundle serve path (verb 24-25,
 * nodus_witness_v2_sync_handle_gbundle_q — this file's only remaining
 * production entry point). R3 W4-D (Delta B) additionally deletes the
 * restart integrity check (nodus_witness_v2_sync_restart_check): its
 * production callers were already gone in Delta A, leaving only a
 * test-only caller (test_v2_gate.c, CONVERT/STOP territory).
 *
 * ═══ ADVERTISEMENTS ARE HINTS (historical — the driver that read them is
 *     gone) ═══════════════════════════════════════════════════════════
 * A peer's claimed head selected nothing and authorised nothing. It was
 * used only to decide whether asking that peer for a range was worth a
 * round trip, and every byte that came back was verified as if it were
 * hostile.
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
#include "protocol/nodus_tier3.h"       /* verb 24-25 gbundle handler  */

struct nodus_tcp_conn;

#ifdef __cplusplus
extern "C" {
#endif

/* R3 W4 — NODUS_V2_SYNC_MAX_RANGE_BLOCKS and NODUS_V2_SYNC_MAX_RANGE_
 * BYTES (the old-lane range request/response bounds) are DELETED with
 * the closed consensus lane: their only readers, nodus_witness_v2_sync_
 * apply_range and the old-lane serve path, are both deleted below. */

/* R3 W4 — nodus_v2_head_hint_t, nodus_witness_v2_sync_peer_compatible,
 * nodus_witness_v2_sync_plan_range, nodus_v2_sync_range_result_t and
 * nodus_witness_v2_sync_apply_range are DELETED with the closed
 * consensus lane: the old-lane head-hint / bounded-range catch-up driver
 * (T3 verbs 20-23, retired) they served. apply_range's own engine entry,
 * nodus_witness_v2_ingress_block, is deleted with its file
 * (nodus_witness_v2_ingress.c/.h). */

/* R3 W4 — nodus_witness_v2_sync_serve_block (serve ONE committed
 * successor block as an encoded BlockMessage v1) is DELETED with the
 * closed consensus lane: its final assembly step called
 * nodus_witness_v2_blkframe_encode, declared AND defined only in
 * nodus_witness_v2_ingress.h/.c, both deleted. Its only production
 * caller, the old-lane range-serve path, is also deleted. */

/* R3 W4-D (Delta B) — nodus_witness_v2_sync_restart_check (the restart /
 * crash-recovery V2-lane integrity check) is DELETED: its production
 * callers were already gone in Delta A, leaving only test_v2_gate.c's
 * sync section (CONVERT/STOP territory, reported not edited). */

/* R3 W4 — nodus_witness_v2_sync_handle_head (verb 21),
 * nodus_witness_v2_sync_handle_range_q (verb 22),
 * nodus_witness_v2_sync_handle_range_r (verb 23) and
 * nodus_witness_v2_sync_handle_block_q (verb 20) are DELETED with the
 * closed consensus lane: T3 verbs 20-23 are retired, never reused. The
 * surviving genesis-bundle handler (verb 24-25) follows. */

/** verb 24 — a genesis bundle chunk request (O15E Faz D). Serves one
 *  offset chunk of the persisted canonical bundle to a joiner whose pin
 *  equals this successor's committed genesis BlockID. Refuses any other
 *  chain / pin (a bundle is never served for a genesis this node did not
 *  commit). */
void nodus_witness_v2_sync_handle_gbundle_q(nodus_witness_t *w,
                                            struct nodus_tcp_conn *conn,
                                            const nodus_t3_msg_t *msg);

/* R3 W4 — nodus_witness_v2_sync_tick (the successor sync driver called
 * from the witness tick) and nodus_witness_v2_qc_first_missing (the
 * missing-QC detector it used) are DELETED with the closed consensus
 * lane: nodus_witness_tick (nodus_witness.c) no longer calls either. */

#ifdef __cplusplus
}
#endif

#endif /* NODUS_WITNESS_V2_SYNC2_H */
