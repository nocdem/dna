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
#include "witness/nodus_witness_v2_epoch.h"
#include "witness/nodus_witness_v2_qc.h"
#include "witness/nodus_witness_v2_result.h"
#include "witness/nodus_witness_v2_env.h"     /* the pre-commit seam    */
#include "witness/nodus_witness_v2_claims.h"  /* claim admit (class 201)*/
/* nodus_witness_domreg.h is deliberately NOT included any more: the
 * contextual ruleset table used to be assembled here from per-leg
 * domreg lookups, and that private assembly is exactly what drifted from
 * the engine. The table now arrives inside the block-start context
 * (nodus_witness_v2_env.h), built by the engine's own body. */
#include "witness/nodus_witness_db.h"
#include "server/nodus_server.h"       /* w->server->identity (sign key) */

#include "dnac/block_v2.h"
#include "dnac/qc_v2.h"
#include "dnac/ledger_ids.h"
#include "dnac/vset_wire.h"
#include "dnac/env_wire.h"                    /* family marker length   */
#include "dnac/manifest_wire.h"               /* claim codec (class 201)*/

#include "crypto/hash/qgp_sha3.h"
#include "crypto/sign/qgp_dilithium.h"
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

/* ── pool helpers ───────────────────────────────────────────────────── */

/* Our snapshot-convention voter id: SHA3-512(pubkey)[0..31] — the
 * DNA.VSET.v1 entry derivation (vset_wire.h), never the roster id. */
static int prod_my_voter_id(nodus_witness_t *w, uint8_t out[32]) {
    uint8_t full[64];
    if (!w->server) return -1;
    if (qgp_sha3_512(w->server->identity.pk.bytes, NODUS_PK_BYTES,
                     full) != 0)
        return -1;
    memcpy(out, full, 32);
    return 0;
}

static void prod_pool_reset(nodus_witness_t *w, uint64_t height) {
    memset(&w->v2_certpool, 0, sizeof(w->v2_certpool));
    w->v2_certpool.height = height;
}

/* Insert (dedup by voter). Returns 1 inserted, 0 duplicate/full. */
static int prod_pool_insert(nodus_witness_t *w, const uint8_t voter_id[32],
                            const uint8_t block_id[64],
                            const uint8_t sig[NODUS_SIG_BYTES]) {
    for (uint32_t i = 0; i < w->v2_certpool.n; i++) {
        if (memcmp(w->v2_certpool.slots[i].voter_id, voter_id, 32) == 0)
            return 0;                       /* keep-first, one per voter */
    }
    if (w->v2_certpool.n >= DNAC_MAX_ACTIVE_VALIDATORS) return 0;
    uint32_t i = w->v2_certpool.n++;
    memcpy(w->v2_certpool.slots[i].voter_id, voter_id, 32);
    memcpy(w->v2_certpool.slots[i].block_id, block_id, 64);
    memcpy(w->v2_certpool.slots[i].sig, sig, NODUS_SIG_BYTES);
    return 1;
}

static int prod_cert_cmp(const void *a, const void *b) {
    return memcmp(((const dna_qc_v2_cert_t *)a)->voter_id,
                  ((const dna_qc_v2_cert_t *)b)->voter_id,
                  DNA_CERT_V2_VOTER_ID_LEN);
}

/* ── QC assembly ────────────────────────────────────────────────────── */

int nodus_witness_v2_qc_try_attach(nodus_witness_t *w) {
    if (!w || !w->db || !w->v2_successor) return -1;
    if (!w->v2_certpool.committed || w->v2_certpool.height == 0) return 1;
    if (w->v2_certpool.qc_attached) return 0;

    uint64_t h = w->v2_certpool.height;

    /* Committed authority for this height — the O12 resolver. Absent
     * authority here is a node-local condition; never a verdict. */
    dna_vset_snapshot_t *snap = NULL;
    uint32_t n = 0, quorum = 0;
    if (nodus_witness_v2_epoch_authority_for_height(w, h, &snap, &n,
                                                    &quorum) != 0 || !snap)
        return -1;

    /* Verify every pooled cert that matches OUR committed BlockID against
     * the snapshot's frozen pubkeys. Bad entries are skipped, not judged. */
    dna_qc_v2_cert_t *valid = calloc((size_t)n, sizeof(*valid));
    if (!valid) { dna_vset_free(&snap); return -1; }
    uint32_t n_valid = 0;

    for (uint32_t i = 0; i < w->v2_certpool.n && n_valid < n; i++) {
        if (memcmp(w->v2_certpool.slots[i].block_id,
                   w->v2_certpool.local_block_id, 64) != 0)
            continue;                       /* diverged sender — skip    */
        const uint8_t *pk = NULL;
        for (uint16_t e = 0; e < snap->active_count; e++) {
            if (memcmp(snap->entries[e].voter_id,
                       w->v2_certpool.slots[i].voter_id, 32) == 0) {
                pk = snap->entries[e].pubkey;
                break;
            }
        }
        if (!pk) continue;                  /* not a member — skip       */
        uint8_t pre[DNA_CERT_V2_PREIMAGE_LEN];
        if (dna_cert_v2_preimage(w->v2_certpool.local_block_id,
                                 w->v2_certpool.slots[i].voter_id, h,
                                 w->v2_chain32, w->v2_certpool.vset_hash,
                                 pre) != 0)
            continue;
        if (qgp_dsa87_verify(w->v2_certpool.slots[i].sig,
                             DNA_CERT_V2_SIG_LEN, pre, sizeof(pre),
                             pk) != 0)
            continue;                       /* invalid — skip            */
        /* dedup among valid (pool already dedups by voter) */
        memcpy(valid[n_valid].voter_id,
               w->v2_certpool.slots[i].voter_id, 32);
        memcpy(valid[n_valid].sig, w->v2_certpool.slots[i].sig,
               DNA_CERT_V2_SIG_LEN);
        n_valid++;
    }

    if (n_valid < quorum) {
        free(valid);
        dna_vset_free(&snap);
        return 1;                           /* not yet                   */
    }

    /* Canonical QC: strictly ascending voter ids. */
    qsort(valid, (size_t)n_valid, sizeof(valid[0]), prod_cert_cmp);

    int ret = -1;
    dna_qc_v2_t *qc = dna_qc_v2_alloc((uint16_t)n_valid);
    uint8_t *qc_bytes = NULL;
    sqlite3_stmt *st = NULL;
    do {
        if (!qc) break;
        memcpy(qc->certs, valid, (size_t)n_valid * sizeof(valid[0]));

        /* The stored canonical header — decode, then hand the assembled
         * QC to the ONE verifier before anything durable happens. */
        uint8_t hdr_bytes[DNA_BH2_ENC_SIZE];
        if (sqlite3_prepare_v2(w->db,
                "SELECT header, block_id FROM v2_blocks "
                "WHERE global_height = ?1", -1, &st, NULL) != SQLITE_OK)
            break;
        sqlite3_bind_int64(st, 1, (sqlite3_int64)h);
        if (sqlite3_step(st) != SQLITE_ROW ||
            sqlite3_column_bytes(st, 0) != DNA_BH2_ENC_SIZE ||
            sqlite3_column_bytes(st, 1) != 64 ||
            memcmp(sqlite3_column_blob(st, 1),
                   w->v2_certpool.local_block_id, 64) != 0)
            break;
        memcpy(hdr_bytes, sqlite3_column_blob(st, 0), DNA_BH2_ENC_SIZE);
        sqlite3_finalize(st);
        st = NULL;

        dna_block_header_v2_t hdr;
        if (dna_bh2_decode(hdr_bytes, sizeof(hdr_bytes), &hdr) != 0) break;
        if (nodus_witness_v2_qc_verify(w, &hdr, qc) != 0) break;

        size_t cap = dna_qc_v2_encoded_len(qc);
        size_t used = 0;
        if (cap == 0) break;
        qc_bytes = malloc(cap);
        if (!qc_bytes) break;
        if (dna_qc_v2_encode(qc, qc_bytes, cap, &used) != 0) break;

        if (sqlite3_prepare_v2(w->db,
                "UPDATE v2_blocks SET qc = ?1 WHERE global_height = ?2 "
                "AND block_id = ?3 AND qc IS NULL", -1, &st, NULL)
            != SQLITE_OK)
            break;
        sqlite3_bind_blob(st, 1, qc_bytes, (int)used, SQLITE_STATIC);
        sqlite3_bind_int64(st, 2, (sqlite3_int64)h);
        sqlite3_bind_blob(st, 3, w->v2_certpool.local_block_id, 64,
                          SQLITE_STATIC);
        if (sqlite3_step(st) != SQLITE_DONE) break;
        /* changes 0 = a QC is already there (attached earlier / by a
         * replayed drain) — same terminal state, idempotent. */
        w->v2_certpool.qc_attached = true;
        QGP_LOG_INFO(LOG_TAG, "QC attached at height %llu (%u certs, "
                     "quorum %u of %u)", (unsigned long long)h,
                     (unsigned)n_valid, (unsigned)quorum, (unsigned)n);
        ret = 0;
    } while (0);

    if (st) sqlite3_finalize(st);
    free(qc_bytes);
    if (qc) dna_qc_v2_free(&qc);
    free(valid);
    dna_vset_free(&snap);
    return ret == 0 ? 0 : (w->v2_certpool.qc_attached ? 0 : -1);
}

/* ── cert collection ────────────────────────────────────────────────── */

void nodus_witness_v2_cert_note(nodus_witness_t *w,
                                uint64_t height,
                                const uint8_t voter_id[32],
                                const uint8_t block_id[64],
                                const uint8_t sig[NODUS_SIG_BYTES]) {
    if (!w || !w->v2_successor || !voter_id || !block_id || !sig) return;
    if (height == 0) return;

    if (w->v2_certpool.height != height) {
        /* Accept only the next height this node would commit — bounded
         * by construction; anything else is noise or far drift. */
        uint64_t tip = 0;
        if (nodus_witness_v2_tip_height(w, &tip) != 0) return;
        if (height != tip + 1) return;
        /* A superseded pool gets one last assembly chance before reset. */
        if (w->v2_certpool.committed && !w->v2_certpool.qc_attached)
            (void)nodus_witness_v2_qc_try_attach(w);
        prod_pool_reset(w, height);
    }
    (void)prod_pool_insert(w, voter_id, block_id, sig);
    if (w->v2_certpool.committed)
        (void)nodus_witness_v2_qc_try_attach(w);
}

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

int nodus_witness_v2_claim_entry_nullifier(nodus_witness_t *w,
                                           const uint8_t *bytes, uint32_t len,
                                           uint8_t out_nullifier[64]) {
    if (!w || !w->db || !w->v2_successor || !bytes || len == 0 ||
        !out_nullifier)
        return -1;
    dna_claim_t *c = calloc(1, sizeof(*c));   /* large — heap */
    if (!c) return -1;
    int rc = -1;
    if (dna_claim_decode(bytes, (size_t)len, c) == 0) {
        nodus_v2_claim_admit_t adm;
        /* O15O Faz 1 — the candidate height claim_admit judges the
         * claim's height window at. A fault answering 0 would derive the
         * nullifier from an admission decided at height 1; this
         * nullifier is what the mempool and the in-batch dedup key on.
         * Leave rc at its -1 initialiser — this function's existing fault
         * path (the calloc failure above) is the same refusal. */
        uint64_t claim_tip = 0;
        if (nodus_witness_block_height_checked(w, &claim_tip) == 0) {
            uint64_t candidate = claim_tip + 1;
            if (nodus_witness_v2_claim_admit(w, c, candidate, &adm) == 0) {
                memcpy(out_nullifier, adm.nullifier, 64);
                rc = 0;
            }
        } else {
            QGP_LOG_ERROR(LOG_TAG, "claim_entry_nullifier: chain-height "
                          "read faulted — refusing to derive a nullifier "
                          "from an admission at height 1");
        }
    }
    free(c);
    return rc;
}

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
int nodus_witness_v2_produce_batch_check_ex(
        nodus_witness_t *w,
        nodus_witness_mempool_entry_t **entries,
        int count,
        int *fail_index_out,
        nodus_v2_batch_check_result_t *result_out) {
    if (fail_index_out) *fail_index_out = 0;
    if (result_out) {
        memset(result_out, 0, sizeof(*result_out));
        result_out->kind = NODUS_V2_BATCH_FAIL_FAULT;
    }
    if (!w || !w->db || !w->v2_successor || !entries || count <= 0 ||
        count > NODUS_W_MAX_BLOCK_TXS)
        return -2;

    /* Split by class; keep each subset entry's ORIGINAL batch index so a
     * seam failure names the offender in the caller's array. */
    nodus_v2_envelope_t envs[NODUS_W_MAX_BLOCK_TXS];
    int env_idx[NODUS_W_MAX_BLOCK_TXS];
    int n_env = 0;
    int claim_idx[NODUS_W_MAX_BLOCK_TXS];
    int n_claim = 0;
    for (int i = 0; i < count; i++) {
        if (!entries[i] || !entries[i]->tx_data || entries[i]->tx_len == 0) {
            if (fail_index_out) *fail_index_out = i;
            if (result_out) result_out->kind = NODUS_V2_BATCH_FAIL_ENTRY_INVALID;
            return -1;
        }
        if (entries[i]->tx_type == NODUS_W_TX_V2_ENVELOPE) {
            envs[n_env].env_bytes = entries[i]->tx_data;
            envs[n_env].env_len   = entries[i]->tx_len;
            env_idx[n_env]        = i;
            n_env++;
        } else if (entries[i]->tx_type == NODUS_W_TX_V2_CLAIM) {
            claim_idx[n_claim++] = i;
        } else {
            if (fail_index_out) *fail_index_out = i;
            if (result_out) result_out->kind = NODUS_V2_BATCH_FAIL_ENTRY_INVALID;
            return -1;                          /* unknown entry class    */
        }
    }

    uint64_t candidate = 0;
    if (nodus_witness_v2_tip_height(w, &candidate) != 0) return -2;
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
        if (!bctx) return -2;
        int bcrc = nodus_witness_v2_block_ctx_build(w, bctx);
        if (bcrc != 0) {
            /* -1 (SYSTEM unusable) is a chain-state condition no entry in
             * this batch caused, and -2 is a node-local read failure.
             * Neither is a verdict about anyone's transaction, so both
             * surface as a FAULT — the producer must requeue, not drop. */
            QGP_LOG_ERROR(LOG_TAG, "batch pre-check could not build the "
                          "block-start context (rc=%d) — no verdict", bcrc);
            free(bctx);
            return -2;
        }

        dna_env_preflight_t *pf =
            calloc((size_t)n_env, sizeof(dna_env_preflight_t));
        dna_meter_t *meters = calloc((size_t)n_env, sizeof(dna_meter_t));
        if (!pf || !meters) {
            free(pf);
            free(meters);
            free(bctx);
            return -2;
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
                return -2;
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
            return -1;
        }
    }

    /* ── CLAIM subset: per-claim admission + in-batch nullifier dedup ──
     * Claims are not metered: the engine reserves units for ENVELOPES
     * only (its budget is handed to the envelope seam and to nothing
     * else), so a claim can never be the entry a capacity failure names.
     * That is what makes truncating at a capacity fail_index safe — the
     * surviving prefix is exactly the envelope set that reserved. */
    if (n_claim > 0) {
        uint8_t nuls[NODUS_W_MAX_BLOCK_TXS][64];
        for (int ci = 0; ci < n_claim; ci++) {
            int oi = claim_idx[ci];
            dna_claim_t *c = calloc(1, sizeof(*c));   /* large — heap */
            if (!c) return -2;
            nodus_v2_claim_admit_t adm;
            int ok = (dna_claim_decode(entries[oi]->tx_data,
                                       entries[oi]->tx_len, c) == 0) &&
                     (nodus_witness_v2_claim_admit(w, c, candidate,
                                                   &adm) == 0);
            free(c);
            if (!ok) {
                if (fail_index_out) *fail_index_out = oi;
                if (result_out)
                    result_out->kind = NODUS_V2_BATCH_FAIL_ENTRY_INVALID;
                QGP_LOG_WARN(LOG_TAG, "batch pre-check rejected claim entry "
                             "%d (admission)", oi);
                return -1;
            }
            for (int p = 0; p < ci; p++) {
                if (memcmp(nuls[p], adm.nullifier, 64) == 0) {
                    if (fail_index_out) *fail_index_out = oi;
                    if (result_out)
                        result_out->kind = NODUS_V2_BATCH_FAIL_ENTRY_INVALID;
                    QGP_LOG_WARN(LOG_TAG, "batch pre-check: duplicate claim "
                                 "nullifier in one batch (entry %d)", oi);
                    return -1;
                }
            }
            memcpy(nuls[ci], adm.nullifier, 64);
        }
    }

    if (result_out) result_out->kind = NODUS_V2_BATCH_FAIL_NONE;
    return 0;
}

/*
 * The classification-free entry, contract unchanged (produce.h): 0 clean,
 * -1 entry rejected, -2 node-local fault. Every caller that only needs
 * "is this batch admissible" — the FOLLOWER proposal check above all —
 * keeps calling this and keeps its exact verdict semantics: any seam
 * refusal, now including over-budget, is a non-zero return and therefore
 * a REJECT vote. A follower has no batch to shape, so the kind buys it
 * nothing; it must reject a proposal the engine would refuse regardless
 * of WHY the engine would refuse it.
 */
int nodus_witness_v2_produce_batch_check(nodus_witness_t *w,
                                         nodus_witness_mempool_entry_t **entries,
                                         int count,
                                         int *fail_index_out) {
    return nodus_witness_v2_produce_batch_check_ex(w, entries, count,
                                                   fail_index_out, NULL);
}

/* ── the commit handoff ─────────────────────────────────────────────── */

int nodus_witness_v2_produce_commit(nodus_witness_t *w,
                                    nodus_witness_mempool_entry_t **entries,
                                    int count,
                                    uint64_t height,
                                    uint64_t timestamp,
                                    const uint8_t *proposer_id,
                                    const uint8_t *expected_global_root,
                                    nodus_v2_produce_out_t *out) {
    if (!w || !w->db || !w->v2_successor || !entries || count <= 0 ||
        count > NODUS_W_MAX_BLOCK_TXS || !proposer_id || !out)
        return -2;
    memset(out, 0, sizeof(*out));

    /* Split the agreed batch by transport-local class, preserving batch
     * order within each channel: ENVELOPEs (200) feed blk->envs[] (doubly
     * bound via tx_root), CLAIMs (201) are strict-decoded into a heap
     * dna_claim_t array feeding blk->claims[] (bound transitively via each
     * target's claims_root). The engine re-admits and executes; claim
     * order = batch order (canonical, identical on leader and followers
     * via the voted batch + COMMIT frame). */
    nodus_v2_envelope_t envs[NODUS_W_MAX_BLOCK_TXS];
    size_t n_env = 0, n_claim = 0;
    dna_claim_t *claims = NULL;
    int rc = -2;
    for (int i = 0; i < count; i++) {
        nodus_witness_mempool_entry_t *e = entries[i];
        if (!e || !e->tx_data || e->tx_len == 0)
            return -1;                      /* not a successor batch     */
        if (e->tx_type == NODUS_W_TX_V2_ENVELOPE) {
            envs[n_env].env_bytes = e->tx_data;
            envs[n_env].env_len   = e->tx_len;
            n_env++;
        } else if (e->tx_type == NODUS_W_TX_V2_CLAIM) {
            n_claim++;
        } else {
            return -1;                      /* unknown entry class        */
        }
    }
    if (n_claim > NODUS_W_MAX_BLOCK_TXS) return -1;

    if (n_claim > 0) {
        claims = calloc(n_claim, sizeof(*claims));   /* large — heap */
        if (!claims) return -2;
        size_t ci = 0;
        for (int i = 0; i < count; i++) {
            if (entries[i]->tx_type != NODUS_W_TX_V2_CLAIM) continue;
            if (dna_claim_decode(entries[i]->tx_data, entries[i]->tx_len,
                                 &claims[ci]) != 0) {
                free(claims);
                return -1;                  /* strict decode is a verdict */
            }
            ci++;
        }
    }

    /* The engine block: identity is ENGINE-derived; the only header
     * material supplied is what it cannot derive (proposer, timestamp —
     * both agreed by the round, identical on every node). The follower
     * assertion channel carries the COMMIT frame's global root. */
    nodus_v2_block_t *blk = calloc(1, sizeof(*blk));
    if (!blk) { free(claims); return -2; }
    blk->global_height = height;
    blk->epoch         = nodus_v2_epoch_for_height(height);
    memcpy(blk->proposer_id, proposer_id, 32);
    blk->timestamp     = timestamp;
    blk->envs          = n_env ? envs : NULL;
    blk->n_envs        = n_env;
    blk->claims        = claims;            /* NULL when n_claim == 0     */
    blk->n_claims      = n_claim;
    blk->expect_global_root = expected_global_root;

    rc = nodus_witness_v2_apply_block(w, blk);

    /* The engine's own words for WHY it refused. Diagnostic only — it
     * never changes what this function returns. The existing message
     * text is kept verbatim and the reason APPENDED, so log greps that
     * already match "REJECTED by the engine (deterministic verdict)"
     * keep matching. An empty reason is reported as such rather than
     * printed as a blank tail. */
    const char *why = blk->out_reason[0] ? blk->out_reason
                                         : "(no reason recorded)";

    if (rc == NODUS_V2_CONSENSUS_INVALID) {
        QGP_LOG_ERROR(LOG_TAG, "successor block %llu REJECTED by the "
                      "engine (deterministic verdict): %s",
                      (unsigned long long)height, why);
        free(blk);
        free(claims);
        return -1;
    }
    if (rc != NODUS_V2_ACCEPTED && rc != NODUS_V2_ACCEPTED_PRECACHE) {
        /* -2 fault, -3 not-yet-linkable, retired/unsupported cannot
         * arise here — all: this NODE could not commit; stay silent.
         * NOTE the engine's rc 1 (idempotent replay) is UNREACHABLE on
         * this path by construction: it is unlocked only by an
         * expect_block_id assertion, which produce never supplies (the
         * round machinery's already-committed guards sit in front of
         * this call — bft.c handle_vote/handle_commit round checks). */
        QGP_LOG_ERROR(LOG_TAG, "successor block %llu did not commit "
                      "(engine rc=%d — node-local, no verdict): %s",
                      (unsigned long long)height, rc, why);
        free(blk);
        free(claims);
        return -2;
    }

    const uint8_t *global_root = blk->out_global_root;

    for (int i = 0; i < count; i++) {
        entries[i]->committed_block_height = height;
        entries[i]->committed_tx_index     = (uint32_t)i;
    }

    memcpy(out->block_id, blk->out_block_id, 64);
    memcpy(out->global_root, global_root, 64);

    /* Pool: adopt this height (keeping any certs that raced ahead). */
    if (w->v2_certpool.height != height) {
        if (w->v2_certpool.committed && !w->v2_certpool.qc_attached)
            (void)nodus_witness_v2_qc_try_attach(w);
        prod_pool_reset(w, height);
    }
    w->v2_certpool.committed = true;
    memcpy(w->v2_certpool.local_block_id, blk->out_block_id, 64);
    memcpy(w->v2_certpool.vset_hash, blk->out_vset_hash, 64);

    /* Our own DNA.CERT.v2 certificate over the id we DERIVED. A signing
     * failure loses only our certificate — the block stays committed. */
    uint8_t my_voter[32];
    uint8_t pre[DNA_CERT_V2_PREIMAGE_LEN];
    if (prod_my_voter_id(w, my_voter) == 0 &&
        dna_cert_v2_preimage(blk->out_block_id, my_voter, height,
                             w->v2_chain32, blk->out_vset_hash, pre) == 0) {
        uint8_t sig[NODUS_SIG_BYTES];
        size_t  siglen = 0;
        memset(sig, 0, sizeof(sig));
        if (qgp_dsa87_sign(sig, &siglen, pre, sizeof(pre),
                           w->server->identity.sk.bytes) == 0 &&
            siglen <= NODUS_SIG_BYTES) {
            memcpy(out->cert_sig, sig, NODUS_SIG_BYTES);
            out->have_cert = 1;
            (void)prod_pool_insert(w, my_voter, blk->out_block_id, sig);
        }
    }
    if (!out->have_cert)
        QGP_LOG_ERROR(LOG_TAG, "own QC cert signing failed at height "
                      "%llu — block committed, certificate missing",
                      (unsigned long long)height);

    (void)nodus_witness_v2_qc_try_attach(w);

    QGP_LOG_INFO(LOG_TAG, "successor block %llu committed through the V2 "
                 "engine (%zu envelope(s), %zu claim(s))",
                 (unsigned long long)height, n_env, n_claim);
    free(blk);
    free(claims);
    return 0;
}
