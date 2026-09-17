/**
 * @file nodus/src/witness/nodus_witness_v2_produce.h
 * @brief Ledger V2 O15D — the SUCCESSOR block-production seam: the handoff
 *        between the live BFT round machinery and the ONE V2 engine.
 *
 * ═══ SCOPE ══════════════════════════════════════════════════════════════
 * Runs ONLY on a chain whose handle carries `w->v2_successor` — a fact
 * derived at database open from COMMITTED state (the height-0 successor
 * genesis manifest with the "DNA.LEGACY.TERM.v1" source binding; the same
 * committed authority the activation gate reads). On every other chain the
 * legacy lane is byte-identically untouched, and on non-activation builds
 * the successor cannot exist at all (deriving one is compile-gated).
 *
 * ═══ ONE ENGINE ═════════════════════════════════════════════════════════
 * Execution, ordering (SYSTEM → cross-domain → domain-local ASC), root
 * computation, header/BlockID derivation, atomic persistence and rollback
 * are ALL `nodus_witness_v2_apply_block` (O14): this module builds the
 * block INPUT from the agreed BFT batch and maps the engine's typed result
 * back onto the round. It computes no root, no BlockID and no header of
 * its own, and it opens no transaction.
 *
 * ═══ QC FORMATION — R3 W4: DELETED with the closed consensus lane ═══════
 * This module used to also assemble the shipped post-commit DNA.CERT.v2
 * QC (nodus_witness_v2_cert_note / _qc_try_attach, pooled in
 * `w->v2_certpool`): the legacy PBFT round voted BEFORE execution, so a
 * QC certificate — which binds the engine-derived BlockID and therefore
 * can only be signed AFTER execution — was assembled from per-node
 * COMMIT-broadcast certificates once a committed height had them. A
 * version-3 chain has no PBFT round and no COMMIT broadcast to ride, and
 * this build assembles no replacement DNA.CERT.v2 QC for it — grep
 * confirms nodus_witness_cmt_app.c has no QC handling of its own.
 * `w->v2_certpool` and every function that read or wrote it are deleted;
 * see nodus_witness_v2_produce.c's own deletion notes at the same names.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef NODUS_WITNESS_V2_PRODUCE_H
#define NODUS_WITNESS_V2_PRODUCE_H

#include <stddef.h>
#include <stdint.h>

#include "witness/nodus_witness.h"
/* ORCHESTRATOR delta 1, item B — nodus_v2_batch_check_result_t, for
 * nodus_witness_v2_produce_batch_check_capped's result_out parameter.
 * Included, not edited: this header's own declarations are untouched. */
#include "witness/nodus_witness_v2_env.h"

#ifdef __cplusplus
extern "C" {
#endif

/* R3 W4 — nodus_v2_produce_out_t (the output shape of
 * nodus_witness_v2_produce_commit) is DELETED with the closed consensus
 * lane: its only production user is deleted below. */

/**
 * ORCHESTRATOR delta 2, item A — the LIGHTWEIGHT view
 * `nodus_witness_v2_produce_batch_check_capped` (below) and its shared
 * implementation actually read: `tx_type`, `tx_data`, `tx_len`, nothing
 * else (nodus_witness_v2_produce.c's own citation:
 * nodus_witness_v2_produce.c:369-386 in the pre-delta-2 form). 24 bytes
 * per item (on a 64-bit build: 1 byte + 7 padding + 8-byte pointer +
 * 8-byte size_t), against `nodus_witness_mempool_entry_t`'s ~8.4 KB
 * (dominated by a 2 592-byte public key and a 4 627-byte signature this
 * seam never touches). At the Comet lane's worst case (293 525 items)
 * this view costs ≈ 7 MiB transiently; the heavyweight type at the same
 * count would have cost ≈ 2.3 GiB. `tx_data`/`tx_len` are BORROWED from
 * whatever the caller's own request bytes are — never copied, never
 * owned here.
 */
typedef struct {
    uint8_t        tx_type;
    const uint8_t *tx_data;
    size_t         tx_len;
} nodus_witness_batch_item_t;

/* R3 W4 — nodus_witness_v2_produce_commit (the commit handoff),
 * nodus_witness_v2_cert_note (peer certificate recording) and
 * nodus_witness_v2_qc_try_attach (QC assembly) are DELETED with the
 * closed consensus lane: all three read or wrote `w->v2_certpool`,
 * itself deleted, and their only production trigger was the legacy BFT
 * round's COMMIT path. See nodus_witness_v2_produce.c's own deletion
 * notes at the same names. */

/**
 * The authoritative successor tip height (MAX(global_height) of
 * v2_blocks; 0 with only genesis committed). @return 0 / -1 fault.
 */
int nodus_witness_v2_tip_height(nodus_witness_t *w, uint64_t *height_out);

/**
 * Transport-local classification of a successor mempool entry from its
 * LEADING bytes: an entry beginning with the 16-byte "DNA.ENVWIRE.v1"
 * family marker (env_wire.c:25-27) is a Ledger V2 ENVELOPE
 * (NODUS_W_TX_V2_ENVELOPE); anything else on a successor is a CLAIM
 * (NODUS_W_TX_V2_CLAIM) — strict dna_claim_decode + admission decide its
 * validity. Deterministic and byte-driven: every honest node classifies
 * the identical bytes identically, so admission, ingress and round entry
 * share ONE classification authority. Buffers shorter than the marker
 * cannot carry it, so they classify as CLAIM (and fail their own decode).
 */
uint8_t nodus_witness_v2_classify_entry(const uint8_t *bytes, uint32_t len);

/* R3 W4-D (Delta B) — nodus_witness_v2_claim_entry_nullifier is DELETED:
 * its three production callers (nodus_witness_pool_local_demand,
 * handle_dnac_spend's legacy body, nodus_witness_peer_handle_fwd_req)
 * were all removed with the closed consensus lane in Delta A, leaving it
 * a test-only orphan (test_bft_view_change_hardening.c, itself deleted
 * this delta). nodus_witness_v2_claim_admit stays the one admission
 * function surviving code uses directly (produce_batch_check_impl,
 * below).
 *
 * R3 W4 — nodus_witness_v2_produce_batch_check and
 * nodus_witness_v2_produce_batch_check_ex (nodus_witness_v2_env.h; that
 * stale prototype was deleted in Delta A' once it was found to be in this
 * package's whitelist after all) are DELETED with the closed consensus
 * lane: both took `nodus_witness_mempool_entry_t **`, a type
 * from nodus_witness_mempool.h, itself deleted, and existed only for
 * their one caller, nodus_witness_bft.c's leader batch shaping — also
 * deleted. `_capped` below is the surviving seam call, used by the
 * cometbft application layer. Full seam behavior (strict decode,
 * contextual ruleset match, metering) is documented on this file's own
 * shared implementation, produce_batch_check_impl, in
 * nodus_witness_v2_produce.c. */

/**
 * ORCHESTRATOR delta 1, item B / delta 2, item A (register row
 * R3-C1a-4, CLOSED for the Comet lane) — the engine's pre-commit seam
 * with a CALLER-SUPPLIED capacity AND a CALLER-BUILT lightweight item
 * view (`nodus_witness_batch_item_t`, above) instead of the legacy
 * lane's fixed NODUS_W_MAX_BLOCK_TXS and its heavyweight
 * `nodus_witness_mempool_entry_t **`. Every scratch array behind this
 * call is heap-allocated, sized to `count` itself (delta 2: per-request,
 * never to `cap`'s worst case) — the Comet application
 * (`nodus_witness_cmt_app.c`'s `app_seam_check`) builds `items` itself,
 * per request, from whatever it is currently checking (a PrepareProposal
 * candidate list or a ProcessProposal/FinalizeBlock request), and frees
 * it once this call returns.
 *
 * @param cap the admission ceiling; count > cap is CMT-style refused as
 *            -2 (a caller error / malformed input, not a batch verdict
 *            about a valid-shaped request — the caller turns THAT into
 *            its own verdict, e.g. ProcessProposal's REJECT).
 * @return 0 clean / -1 entry (or capacity) rejected / -2 node-local
 *         fault or a bad `cap`/`count`.
 */
int nodus_witness_v2_produce_batch_check_capped(
        nodus_witness_t *w,
        const nodus_witness_batch_item_t *items,
        int count,
        int cap,
        int *fail_index_out,
        nodus_v2_batch_check_result_t *result_out);

#ifdef __cplusplus
}
#endif

#endif /* NODUS_WITNESS_V2_PRODUCE_H */
