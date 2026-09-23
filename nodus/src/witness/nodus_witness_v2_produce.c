/**
 * @file nodus/src/witness/nodus_witness_v2_produce.c
 * @brief Ledger V2 O15D — successor block production over the ONE engine.
 *
 * Contract, scope and the QC-formation rationale: nodus_witness_v2_produce.h.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: Apache-2.0
 */

#include "witness/nodus_witness_v2_produce.h"
#include "witness/nodus_witness_v2_apply.h"
#include "witness/nodus_witness_v2_result.h"
#include "witness/nodus_witness_v2_env.h"     /* the pre-commit seam    */
#include "witness/nodus_witness_v2_claims.h"  /* claim admit (class 201)*/
/* nodus_witness_domreg.h is deliberately NOT included any more: the
 * contextual ruleset table used to be assembled here from per-leg
 * domreg lookups, and that private assembly is exactly what drifted from
 * the engine. The table now arrives inside the block-start context
 * (nodus_witness_v2_env.h), built by the engine's own body. */

/* R3 W4 — nodus_witness_v2_epoch.h, nodus_witness_v2_qc.h (file deleted),
 * server/nodus_server.h, dnac/block_v2.h, dnac/qc_v2.h, dnac/ledger_ids.h,
 * dnac/vset_wire.h, crypto/hash/qgp_sha3.h and crypto/sign/qgp_dilithium.h
 * are DROPPED with the closed consensus lane: every symbol they supplied
 * (epoch/authority resolution, QC assembly and verify, w->server signing
 * identity, the block-header-v2 decode, DNA_CERT_V2_* preimages, the
 * vset snapshot type, SHA3-512 and Dilithium5 dsa87 sign/verify) was used
 * exclusively by the deleted pool/QC/commit functions above. */
#include "dnac/env_wire.h"                    /* family marker length   */
#include "dnac/manifest_wire.h"               /* claim codec (class 201)*/

#include "crypto/utils/qgp_log.h"

#include <sqlite3.h>
#include <stdlib.h>
#include <string.h>

#define LOG_TAG "W_V2PROD"

/* ── tip ────────────────────────────────────────────────────────────── */

int nodus_witness_v2_tip_height(nodus_witness_t *w, uint64_t *height_out) {
    if (!w || !w->db || !height_out) return -1;
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(w->db,
            "SELECT COALESCE(MAX(global_height),0) FROM v2_blocks",
            -1, &st, NULL) != SQLITE_OK)
        return -1;
    int rc = sqlite3_step(st);
    if (rc != SQLITE_ROW) { sqlite3_finalize(st); return -1; }
    *height_out = (uint64_t)sqlite3_column_int64(st, 0);
    sqlite3_finalize(st);
    return 0;
}

/* R3 W4 — the pool helpers (prod_my_voter_id, prod_pool_reset,
 * prod_pool_insert, prod_cert_cmp), the QC assembly
 * (nodus_witness_v2_qc_try_attach) and cert collection
 * (nodus_witness_v2_cert_note) are DELETED with the closed consensus
 * lane: all five read or wrote `w->v2_certpool`, the bounded per-height
 * DNA.CERT.v2 collection pool, which no longer exists on nodus_witness_t
 * (see its own deletion note in nodus_witness.h). QC assembly for a
 * version-3 chain's committed blocks is now the cometbft reactor's own
 * concern — this file no longer participates in it. */

/* ── transport-local classification + claim nullifier (class 201) ───── */

/* Wire family marker: "DNA.ENVWIRE.v1" (14) + 2 zero bytes — pinned at
 * env_wire.c:25-27; explicit initialisers, padding visible. */
static const uint8_t PROD_ENV_FAMILY[DNA_ENV_WIRE_FAMILY_LEN] = {
    'D','N','A','.','E','N','V','W','I','R','E','.','v','1', 0, 0
};

uint8_t nodus_witness_v2_classify_entry(const uint8_t *bytes, uint32_t len) {
    if (bytes && len >= DNA_ENV_WIRE_FAMILY_LEN &&
        memcmp(bytes, PROD_ENV_FAMILY, DNA_ENV_WIRE_FAMILY_LEN) == 0)
        return NODUS_W_TX_V2_ENVELOPE;
    return NODUS_W_TX_V2_CLAIM;
}

/* R3 W4-D (Delta B) — nodus_witness_v2_claim_entry_nullifier is DELETED:
 * see the deletion note in nodus_witness_v2_produce.h. Its only DB-reading
 * call, nodus_witness_block_height_checked, was the sole reason this file
 * included witness/nodus_witness_db.h; that include is dropped with it. */

/* ── batch pre-check (the engine's seam, at the candidate height) ───── */

/*
 * A successor batch mixes two transport-local classes: ENVELOPEs (200)
 * whose validity is the engine's env-preflight seam, and CLAIMs (201)
 * whose validity is nodus_witness_v2_claim_admit. This pre-check runs
 * BOTH over their respective subsets, mapping every failure back to the
 * offender's index in the original batch. It also rejects two claims with
 * the same committed nullifier IN ONE BATCH — the in-batch dedup the
 * legacy seen_nullifiers machinery cannot be relied on for on the remote-
 * COMMIT path (no such loop there), so the apply-level in-block duplicate
 * reject (nodus_witness_v2_apply.c) stays a BACKSTOP that an honest
 * leader/follower never reaches. Deterministic: bytes + committed state
 * only.
 *
 * ── METERING (capacity season) ────────────────────────────────────────
 * The envelope subset now goes through the SAME entry the commit engine
 * uses — nodus_witness_v2_env_preflight_reserve_batch, fed the SAME
 * block-start context (nodus_witness_v2_block_ctx_build). Before this,
 * the check called the BASE preflight, which takes no policy, no budget
 * and no meters: the unit budgets and the absolute block-byte bound were
 * therefore first evaluated at COMMIT, where a miss is a whole-block
 * verdict. A leader could pop a NODUS_W_MAX_BLOCK_TXS batch the global
 * unit budget cannot pay for, propose it, win the vote, and then have the
 * engine reject the block — one dead round and a DNAC_STATUS_ERROR to
 * every client in it, repeatedly.
 *
 * NOT consensus-visible: nothing here changes which blocks the engine
 * ACCEPTS. It only stops proposing and approving batches the engine would
 * deterministically reject. No wire format, no protocol version, no
 * schema, no activation gate is touched.
 *
 * The reservation is run against a SCRATCH budget (the context's own,
 * which dies with this call) and its meters are discarded: this asks the
 * engine's question, it does not pre-authorize anything and it writes
 * nothing.
 *
 * DETERMINISM: reservation is sequential and ORDER-DEPENDENT (envelope
 * i+1 is judged against the budget after envelope i's debit), so the
 * verdict is a function of the entry bytes AND their relative order. Both
 * this check and the engine derive that order from the same batch array,
 * in the same index order, so honest nodes handed the same proposal on
 * the same committed state reach the same answer.
 */
/**
 * ORCHESTRATOR delta 1, item B / delta 2, item A (register row
 * R3-C1a-4, CLOSED for the Comet lane) — the shared body behind
 * `nodus_witness_v2_produce_batch_check_capped`, the Comet application's
 * own seam call with its larger, byte-budget-derived capacity.
 *
 * R3 W4 — `nodus_witness_v2_produce_batch_check_ex` and its thin wrapper
 * `nodus_witness_v2_produce_batch_check` (the legacy, NODUS_W_MAX_BLOCK_
 * TXS-capped callers this body used to also serve, converting their own
 * `nodus_witness_mempool_entry_t **` into the lightweight view ON THE
 * STACK) are DELETED with the closed consensus lane — see their own
 * deletion note below. This function is now reached through exactly one
 * public wrapper, `_capped`.
 *
 * delta 2 — LIGHTWEIGHT ITEMS: takes `nodus_witness_batch_item_t`
 * (24 B: {tx_type, tx_data, tx_len}), not
 * `nodus_witness_mempool_entry_t **` — that type is ~8.4 KB per item
 * (a 2 592-byte pubkey plus a 4 627-byte signature this seam never
 * reads), so sizing scratch to it at Comet-lane counts (hundreds of
 * thousands) would cost gigabytes. The Comet caller
 * (`nodus_witness_cmt_app.c`'s `app_seam_check`) builds the view array
 * itself, per request, and passes it straight in.
 *
 * `cap` is the ADMISSION ceiling (`count > cap` refuses before any
 * allocation); every scratch array below is sized to `count` itself
 * (delta 2: per-request, not to `cap`'s worst case) — HEAP, never a
 * stack array of the caller's `count`, since a Comet-lane batch can be
 * in the thousands. Every exit path frees everything it allocated;
 * none of the returns below leaks.
 */
static int produce_batch_check_impl(
        nodus_witness_t *w,
        const nodus_witness_batch_item_t *items,
        int count,
        int cap,
        int *fail_index_out,
        nodus_v2_batch_check_result_t *result_out) {
    nodus_v2_envelope_t *envs      = NULL;
    int                  *env_idx  = NULL;
    int                  *claim_idx = NULL;
    uint8_t             (*nuls)[64] = NULL;
    int rc_out = -2;

    if (fail_index_out) *fail_index_out = 0;
    if (result_out) {
        memset(result_out, 0, sizeof(*result_out));
        result_out->kind = NODUS_V2_BATCH_FAIL_FAULT;
    }
    if (!w || !w->db || !w->v2_successor || !items || count <= 0 ||
        cap <= 0 || count > cap)
        return -2;

    /* Split by class; keep each subset entry's ORIGINAL batch index so a
     * seam failure names the offender in the caller's array. Heap,
     * sized to `count` (delta 2: per-request, not to `cap`'s worst
     * case). */
    envs      = (nodus_v2_envelope_t *)calloc((size_t)count, sizeof(*envs));
    env_idx   = (int *)calloc((size_t)count, sizeof(*env_idx));
    claim_idx = (int *)calloc((size_t)count, sizeof(*claim_idx));
    nuls      = calloc((size_t)count, sizeof(*nuls));
    if (!envs || !env_idx || !claim_idx || !nuls) {
        rc_out = -2;
        goto done;
    }
    int n_env = 0;
    int n_claim = 0;
    for (int i = 0; i < count; i++) {
        if (!items[i].tx_data || items[i].tx_len == 0) {
            if (fail_index_out) *fail_index_out = i;
            if (result_out) result_out->kind = NODUS_V2_BATCH_FAIL_ENTRY_INVALID;
            rc_out = -1;
            goto done;
        }
        if (items[i].tx_type == NODUS_W_TX_V2_ENVELOPE) {
            envs[n_env].env_bytes = items[i].tx_data;
            envs[n_env].env_len   = items[i].tx_len;
            env_idx[n_env]        = i;
            n_env++;
        } else if (items[i].tx_type == NODUS_W_TX_V2_CLAIM) {
            claim_idx[n_claim++] = i;
        } else {
            if (fail_index_out) *fail_index_out = i;
            if (result_out) result_out->kind = NODUS_V2_BATCH_FAIL_ENTRY_INVALID;
            rc_out = -1;                          /* unknown entry class    */
            goto done;
        }
    }

    uint64_t candidate = 0;
    if (nodus_witness_v2_tip_height(w, &candidate) != 0) {
        rc_out = -2;
        goto done;
    }
    candidate += 1;

    /* ── ENVELOPE subset: the METERED seam (the engine's own entry) ──── */
    if (n_env > 0) {
        /* The block-start execution context, built by the engine's own
         * body: the ACTIVE-domain ruleset table, the per-domain + global
         * unit budgets and the committed SYSTEM price policy. Building it
         * here rather than deriving a private table from the batch's legs
         * is deliberate — a private table admitted domains the engine's
         * does not (REGISTERED-but-not-ACTIVE, or ACTIVE without a
         * resolvable runtime), so such an entry passed this check and
         * then killed the whole block at apply with ERR_CTX_MISSING.
         * ~5.7 KB — heap, like every other buffer on this path. */
        nodus_witness_v2_block_ctx_t *bctx = calloc(1, sizeof(*bctx));
        if (!bctx) {
            rc_out = -2;
            goto done;
        }
        int bcrc = nodus_witness_v2_block_ctx_build(w, bctx);
        if (bcrc != 0) {
            /* -1 (SYSTEM unusable) is a chain-state condition no entry in
             * this batch caused, and -2 is a node-local read failure.
             * Neither is a verdict about anyone's transaction, so both
             * surface as a FAULT — the producer must requeue, not drop. */
            QGP_LOG_ERROR(LOG_TAG, "batch pre-check could not build the "
                          "block-start context (rc=%d) — no verdict", bcrc);
            free(bctx);
            rc_out = -2;
            goto done;
        }

        dna_env_preflight_t *pf =
            calloc((size_t)n_env, sizeof(dna_env_preflight_t));
        dna_meter_t *meters = calloc((size_t)n_env, sizeof(dna_meter_t));
        if (!pf || !meters) {
            free(pf);
            free(meters);
            free(bctx);
            rc_out = -2;
            goto done;
        }
        size_t fail_i = 0;
        dna_env_preflight_status_t pst = DNA_ENV_PF_OK;
        dna_meter_status_t mst = DNA_METER_OK;
        nodus_v2_env_status_t est =
            nodus_witness_v2_env_preflight_reserve_batch(
                w, candidate, bctx->rulesets, bctx->n_rulesets,
                bctx->policy, &bctx->budget, envs, (size_t)n_env,
                pf, meters, &fail_i, &pst, &mst);
        /* The reservations die with the scratch budget: `meters` is a
         * local array bound to `bctx->budget`, both freed below, and the
         * seam already restored the budget byte-identically on any
         * rejection. Nothing here is durable. */
        free(pf);
        free(meters);
        free(bctx);

        if (est != NODUS_V2_ENV_OK) {
            nodus_v2_batch_fail_kind_t kind =
                nodus_witness_v2_env_fail_kind(est, pst, mst);
            if (result_out) {
                result_out->kind         = kind;
                result_out->env_status   = est;
                result_out->pf_status    = pst;
                result_out->meter_status = mst;
            }
            if (kind == NODUS_V2_BATCH_FAIL_FAULT) {
                QGP_LOG_ERROR(LOG_TAG, "batch pre-check FAULTED on the "
                              "envelope subset (seam=%d pf=%d meter=%d) — "
                              "no verdict", (int)est, (int)pst, (int)mst);
                rc_out = -2;
                goto done;
            }
            /* fail_i maps back to the ORIGINAL batch index. On
             * CAPACITY_BYTES the seam reports 0 for the whole batch and
             * that zero accuses nobody — the caller is told so by `kind`
             * and must not read the index as an offender. */
            if (fail_index_out)
                *fail_index_out =
                    env_idx[fail_i < (size_t)n_env ? fail_i : 0];
            QGP_LOG_WARN(LOG_TAG, "batch pre-check rejected the envelope "
                         "subset at %zu (kind=%d seam=%d pf=%d meter=%d)",
                         fail_i, (int)kind, (int)est, (int)pst, (int)mst);
            rc_out = -1;
            goto done;
        }
    }

    /* ── CLAIM subset: per-claim admission + in-batch nullifier dedup ──
     * Claims are not metered: the engine reserves units for ENVELOPES
     * only (its budget is handed to the envelope seam and to nothing
     * else), so a claim can never be the entry a capacity failure names.
     * That is what makes truncating at a capacity fail_index safe — the
     * surviving prefix is exactly the envelope set that reserved. `nuls`
     * is heap, sized to `count` (delta 8, item B: wording corrected —
     * it was a NODUS_W_MAX_BLOCK_TXS stack array before the seam moved
     * to a per-request view). */
    if (n_claim > 0) {
        for (int ci = 0; ci < n_claim; ci++) {
            int oi = claim_idx[ci];
            dna_claim_t *c = calloc(1, sizeof(*c));   /* large — heap */
            if (!c) {
                rc_out = -2;
                goto done;
            }
            nodus_v2_claim_admit_t adm;
            int drc = dna_claim_decode(items[oi].tx_data, items[oi].tx_len,
                                       c);
            /* TV3-P0 item 2 — claim_admit now answers 0 / -1 VERDICT / -2
             * FAULT; only call it once decode succeeded, so a decode
             * failure (a VERDICT about this entry's own bytes) is never
             * mistaken for the admission helper's answer. */
            int arc = (drc == 0)
                          ? nodus_witness_v2_claim_admit(w, c, candidate,
                                                         &adm)
                          : -1;
            free(c);
            if (drc == 0 && arc == -2) {
                /* NODE-LOCAL: "cannot decide", mirroring the envelope
                 * subset's own NODUS_V2_BATCH_FAIL_FAULT handling just
                 * above — never ENTRY_INVALID, which would accuse a
                 * producer of proposing something this node alone could
                 * not evaluate. */
                if (result_out)
                    result_out->kind = NODUS_V2_BATCH_FAIL_FAULT;
                QGP_LOG_ERROR(LOG_TAG, "batch pre-check FAULTED on claim "
                              "entry %d (admission) — no verdict", oi);
                rc_out = -2;
                goto done;
            }
            if (drc != 0 || arc != 0) {
                if (fail_index_out) *fail_index_out = oi;
                if (result_out)
                    result_out->kind = NODUS_V2_BATCH_FAIL_ENTRY_INVALID;
                QGP_LOG_WARN(LOG_TAG, "batch pre-check rejected claim entry "
                             "%d (admission)", oi);
                rc_out = -1;
                goto done;
            }
            for (int p = 0; p < ci; p++) {
                if (memcmp(nuls[p], adm.nullifier, 64) == 0) {
                    if (fail_index_out) *fail_index_out = oi;
                    if (result_out)
                        result_out->kind = NODUS_V2_BATCH_FAIL_ENTRY_INVALID;
                    QGP_LOG_WARN(LOG_TAG, "batch pre-check: duplicate claim "
                                 "nullifier in one batch (entry %d)", oi);
                    rc_out = -1;
                    goto done;
                }
            }
            memcpy(nuls[ci], adm.nullifier, 64);
        }
    }

    if (result_out) result_out->kind = NODUS_V2_BATCH_FAIL_NONE;
    rc_out = 0;

done:
    free(envs);
    free(env_idx);
    free(claim_idx);
    free(nuls);
    return rc_out;
}

/* R3 W4 — nodus_witness_v2_produce_batch_check_ex and its thin wrapper
 * nodus_witness_v2_produce_batch_check (below the capped variant) are
 * DELETED with the closed consensus lane: both took
 * `nodus_witness_mempool_entry_t **`, a type from nodus_witness_mempool.h,
 * itself deleted, and both existed only for their one caller
 * (nodus_witness_bft.c:5286, the legacy leader — never reached on a
 * version-3 chain, D-17 rev 10 item 9), also deleted. The declaration in
 * nodus_witness_v2_env.h is outside this package's whitelist and is left
 * as an orphaned prototype for a follow-up pass. */

/**
 * ORCHESTRATOR delta 1, item B / delta 2, item A — the Comet lane's own
 * seam call, with a CALLER-SUPPLIED capacity and a CALLER-BUILT
 * lightweight item view: the Comet application
 * (`nodus_witness_cmt_app.c`'s `app_seam_check`) builds `items` itself,
 * per request, sized to `count` — never a
 * `nodus_witness_mempool_entry_t **` conversion here, since that type is
 * what made the pre-delta-2 design cost gigabytes at Comet-lane scale.
 * `cap` is the caller's own admission ceiling (`env_bound` for
 * FinalizeBlock-scale callers; PrepareProposal's own `prep_bound` for
 * its own call).
 * @return 0 clean / -1 entry (or capacity) rejected / -2 node-local
 *         fault or a bad `cap`/`count`.
 */
int nodus_witness_v2_produce_batch_check_capped(
        nodus_witness_t *w,
        const nodus_witness_batch_item_t *items,
        int count,
        int cap,
        int *fail_index_out,
        nodus_v2_batch_check_result_t *result_out) {
    return produce_batch_check_impl(w, items, count, cap, fail_index_out,
                                    result_out);
}

/* R3 W4 — nodus_witness_v2_produce_batch_check (the classification-free
 * entry over the now-deleted _ex) is DELETED with the closed consensus
 * lane, for the same reason as _ex above. */

/* R3 W4 — nodus_witness_v2_produce_commit (the legacy PBFT-successor
 * commit handoff: batch split, engine apply, QC-cert-pool adoption and
 * self-signing) is DELETED with the closed consensus lane: it took
 * `nodus_witness_mempool_entry_t **` (mempool.h, deleted), read/wrote
 * `w->v2_certpool` (deleted) and called nodus_witness_v2_qc_try_attach /
 * prod_pool_reset / prod_pool_insert (all deleted above). A version-3
 * chain's block commit now runs through the cometbft application layer
 * (nodus_witness_cmt_app.c), which calls nodus_witness_v2_apply_block
 * directly and does not route through this function or through any QC
 * cert pool. */
