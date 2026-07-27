/**
 * @file batch_prover.c
 * @brief Batched STARK prover — Plonky3 batch-stark `prove_batch` mirror
 *        (P2L-d d3). See batch_prover.h for the pipeline map; every step
 *        below cites its prover.rs / hiding_pcs.rs / two_adic_pcs.rs /
 *        fri/prover.rs lines at 82cfad73.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: Apache-2.0
 */

#include "batch_prover.h"

#include <stdlib.h>
#include <string.h>

#include "batch_priming.h"
#include "field_goldilocks.h"
#include "logup.h"
#include "transcript.h"

#define BP_MAX_INSTANCES 32u
/* Proof-struct query ceiling — must be >= the pinned shielded production
 * num_queries (DNAC_SHIELDED_FRI_NUM_QUERIES = 100); the old agg prover used
 * A_MAX_QUERIES = 128. The batched prover was only ever exercised at the
 * 2-query TEST params before the d4.c-2 production re-base, so 64 was latent. */
#define BP_MAX_QUERIES 128u
#define BP_DIM 2u /* GoldFp2 DIMENSION */
#define BP_MAX_TUPLES 16u
#define BP_MAX_TUPLE_W 16u
/* d4.c: decode-side ceiling mirror (DNAC_FRI_WIRE_MAX_SALT_ELEMS); the real
 * pin is the caller's consensus constant (DNAC_SHIELDED_SALT_ELEMS = 2). */
#define BP_MAX_SALT_ELEMS 8u

static size_t bp_log2(size_t n)
{
    size_t l = 0;
    while (((size_t)1 << l) < n) l++;
    return l;
}

/* Aux width (v0.6.2 batch-stark/src/verifier/mod.rs:512-516): num_lookups + 1
 * when the AIR declares any lookup, else 0 — col 0 is the SHARED accumulator
 * and slot c owns fraction column c + 1 (lookup/src/logup.rs:381-382); zero
 * lookups means no permutation trace at all (logup.rs:374-377).
 * At 82cfad73 this was `max(lookup.column) + 1`, i.e. num_lookups with NO
 * accumulator column. Must stay identical to bv_aux_width in batch_verify.c. */
static uint32_t bp_aux_width(const dnac_batch_vinstance_t *inst)
{
    if (inst->num_lookups == 0) return 0;
    return inst->num_lookups + 1u;
}

static void bp_digest_lanes(const dnac_p2_digest_t *d, gold_fp_t out[4])
{
    for (int k = 0; k < 4; k++) out[k] = gold_fp_from_u64(d->lanes[k]);
}

/* ζ_next(i) = ζ · two_adic_generator(base_db) (verifier/mod.rs:306-310). */
static gold_fp2_t bp_zeta_next(gold_fp2_t zeta, uint32_t base_db)
{
    return gold_fp2_mul(
        zeta, gold_fp2_from_base(gold_fp_two_adic_generator((unsigned)base_db)));
}

/* ============================================================================
 * Opaque proof storage
 * ========================================================================== */
struct dnac_batch_proof_s {
    uint32_t n;
    int      is_zk;
    uint32_t nrc;
    dnac_fri_params_t params;

    /* commits */
    dnac_p2_digest_t main_c, quot_c, prep_c, perm_c, rand_c;
    int has_prep, has_perm;
    gold_fp_t main_lanes[4], quot_lanes[4], prep_lanes[4], perm_lanes[4],
        rand_lanes[4];

    /* per-instance opened values (base parts) + metadata */
    dnac_batch_vopened_t opened[BP_MAX_INSTANCES];
    gold_fp2_t *opened_arena;   /* all base opened values                    */
    gold_fp2_t *terminals;      /* [n] ONE lookup terminal per AIR (S2'-c)   */
    char       *names_store;    /* owned copies of bus names                 */

    /* rand-openings (hiding tails), assembly-point order */
    gold_fp2_t         *rand_arena;
    const gold_fp2_t  **rand_ptrs;
    uint32_t           *rand_lens;
    dnac_batch_rand_openings_t rand_op;
    int                 has_rand_op;

    /* preprocessed map */
    uint32_t prep_map[BP_MAX_INSTANCES];
    uint32_t num_prep;

    /* d4.c salted mode (SE>0): query input-opening salts + commit-phase
     * step salts (read from the SAME streams the commits consumed). */
    size_t            salt_elems;
    gold_fp_t        *in_salts;
    const gold_fp_t **in_saltptrs;
    gold_fp_t        *cp_salts;

    /* FRI proof storage */
    dnac_p2_digest_t *cp_commits;
    gold_fp_t        *cp_pow;
    gold_fp2_t       *final_poly;
    size_t            final_poly_len;
    dnac_fri_query_proof_t   *query_proofs;
    dnac_fri_batch_opening_t *batches;   /* nq * num_rounds */
    gold_fp_t        *in_rows;           /* query input rows arena           */
    const gold_fp_t **in_rowptrs;
    size_t           *in_lens;
    dnac_p2_digest_t *in_sibs;
    dnac_fri_commit_phase_proof_step_t *cp_steps;
    gold_fp2_t       *cp_step_sib;
    dnac_p2_digest_t *cp_step_psib;
    dnac_fri_proof_t  proof;

    gold_fp2_t alpha, zeta;
    uint64_t   query_indices[BP_MAX_QUERIES];
    size_t     num_queries;
    size_t     num_fri_rounds;
};

void dnac_batch_proof_free(dnac_batch_proof_t *p)
{
    if (p == NULL) return;
    free(p->opened_arena);
    free(p->terminals);
    free(p->names_store);
    free(p->rand_arena);
    free(p->rand_ptrs);
    free(p->rand_lens);
    free(p->in_salts);
    free(p->in_saltptrs);
    free(p->cp_salts);
    free(p->cp_commits);
    free(p->cp_pow);
    free(p->final_poly);
    free(p->query_proofs);
    free(p->batches);
    free(p->in_rows);
    free(p->in_rowptrs);
    free(p->in_lens);
    free(p->in_sibs);
    free(p->cp_steps);
    free(p->cp_step_sib);
    free(p->cp_step_psib);
    free(p);
}

/* ── accessors ── */
void dnac_batch_proof_commits(const dnac_batch_proof_t *p,
                              dnac_batch_vcommits_t    *out)
{
    memset(out, 0, sizeof(*out));
    out->main_commit = p->main_lanes;
    out->quotient_commit = p->quot_lanes;
    out->preprocessed_commit = p->has_prep ? p->prep_lanes : NULL;
    out->permutation_commit = p->has_perm ? p->perm_lanes : NULL;
    out->random_commit = p->is_zk ? p->rand_lanes : NULL;
}
const dnac_batch_vopened_t *dnac_batch_proof_opened(
    const dnac_batch_proof_t *p, uint32_t instance)
{
    return instance < p->n ? &p->opened[instance] : NULL;
}
const dnac_fri_proof_t *dnac_batch_proof_fri(const dnac_batch_proof_t *p)
{
    return &p->proof;
}
const dnac_batch_rand_openings_t *dnac_batch_proof_rand_openings(
    const dnac_batch_proof_t *p)
{
    return p->has_rand_op ? &p->rand_op : NULL;
}
const uint32_t *dnac_batch_proof_prep_map(const dnac_batch_proof_t *p,
                                          uint32_t *out_num)
{
    if (out_num) *out_num = p->num_prep;
    return p->prep_map;
}
void dnac_batch_proof_alpha_zeta(const dnac_batch_proof_t *p,
                                 gold_fp2_t *alpha, gold_fp2_t *zeta)
{
    if (alpha) *alpha = p->alpha;
    if (zeta) *zeta = p->zeta;
}
size_t dnac_batch_proof_query_indices(const dnac_batch_proof_t *p,
                                      uint64_t *out, size_t max)
{
    if (out) {
        for (size_t i = 0; i < p->num_queries && i < max; i++) {
            out[i] = p->query_indices[i];
        }
    }
    return p->num_queries;
}

/* ============================================================================
 * Draw accounting (batch_prover.h layout; pinned at source in the oracle
 * zk_rng dump — B1 main / [perm] / B2 quotient / B3 R)
 * ========================================================================== */
size_t dnac_batch_prove_num_draws(const dnac_batch_vinstance_t *insts,
                                  uint32_t num_instances, int is_zk,
                                  uint32_t nrc)
{
    if (!insts || num_instances == 0 || num_instances > BP_MAX_INSTANCES) {
        return SIZE_MAX;
    }
    if (!is_zk) return 0;
    if (nrc == 0) return SIZE_MAX;
    size_t total = 0;
    for (uint32_t i = 0; i < num_instances; i++) {
        const uint32_t ext_db = insts[i].degree_bits;
        if (ext_db < 1 || ext_db >= 32) return SIZE_MAX;
        const size_t base_h = (size_t)1 << (ext_db - 1);
        const size_t ext_h = (size_t)1 << ext_db;
        const size_t w = insts[i].air.main_width;
        total += base_h * (w + 2 * (size_t)nrc); /* B1 main */
        if (insts[i].num_lookups > 0) {          /* perm */
            const size_t aw = bp_aux_width(&insts[i]);
            total += base_h * (2 * aw + 2 * (size_t)nrc);
        }
        /* B2 quotient: num_qc chunks of h_chunk = q_size/num_qc rows. */
        const uint32_t nqc = 1u << (insts[i].log_num_qc + 1u);
        const size_t q_size = (size_t)1 << (ext_db + insts[i].log_num_qc);
        const size_t h_chunk = q_size / nqc;
        total += (size_t)nqc * h_chunk * nrc;
        total += (size_t)(nqc - 1) * h_chunk * (BP_DIM + (size_t)nrc);
        total += ext_h * ((size_t)nrc + BP_DIM); /* B3 R */
    }
    return total;
}

/* Stream-A salt total (d4.c): per commit call in prove order (main →
 * quotient → [random iff is_zk]), per matrix in order, lde rows ×
 * salt_elems (hiding_mmcs.rs commit; == the v3 agg layout trace 16h ‖
 * quotient 8×16h ‖ random 16h at SE=2, lb=2). Preprocessed/permutation are
 * FAIL-CLOSED in salted mode (batch_prover.h), so they contribute nothing. */
size_t dnac_batch_prove_num_salt_draws(const dnac_batch_vinstance_t *insts,
                                       uint32_t num_instances, int is_zk,
                                       size_t log_blowup, size_t salt_elems)
{
    if (!insts || num_instances == 0 || num_instances > BP_MAX_INSTANCES ||
        log_blowup == 0 || log_blowup >= 8) {
        return SIZE_MAX;
    }
    if (salt_elems == 0) return 0;
    if (salt_elems > BP_MAX_SALT_ELEMS) return SIZE_MAX;
    size_t total = 0;
    for (uint32_t i = 0; i < num_instances; i++) {
        const uint32_t ext_db = insts[i].degree_bits;
        if (ext_db < 1 || ext_db >= 24) return SIZE_MAX;
        const size_t lde_h = (size_t)1 << (ext_db + log_blowup);
        const uint32_t nqc =
            1u << (insts[i].log_num_qc + (uint32_t)(is_zk ? 1 : 0));
        total += lde_h * salt_elems;                 /* main   */
        total += (size_t)nqc * lde_h * salt_elems;   /* quot   */
        if (is_zk) total += lde_h * salt_elems;      /* random */
    }
    return total;
}

/* ============================================================================
 * Per-point constraint chain over the quotient domain (prover.rs:804-925
 * quotient_values, serial-Horner value-equal form; the d2 batch_verify.c
 * step-7 chain evaluated at every domain point instead of ζ)
 * ========================================================================== */
static dnac_prover_status_t bp_quotient_values(
    const dnac_batch_vinstance_t *di,
    const uint64_t *trace_q,   /* [q_size][w] natural order                  */
    const uint64_t *prep_q,    /* [q_size][pw] or NULL                       */
    const uint64_t *perm_q,    /* [q_size][2*aw] base-flattened or NULL      */
    gold_fp2_t        terminal, /* the AIR's committed lookup terminal       */
    const gold_fp2_t *challenges, /* [2*num_lookups]                         */
    gold_fp2_t alpha,
    const uint64_t *sf, const uint64_t *sl, const uint64_t *st,
    const uint64_t *iv,
    size_t q_size, size_t next_step,
    uint64_t *out_qflat /* [q_size][2] */)
{
    const size_t w = di->air.main_width;
    const uint32_t pw = di->preprocessed_width;
    const uint32_t aw = bp_aux_width(di);
    if (w > DNAC_STARK_MAX_MAIN_WIDTH || aw > 64 || pw > 64) {
        return DNAC_PROVER_ERR_PARAM;
    }

    gold_fp2_t *tl = (gold_fp2_t *)malloc(w * sizeof(gold_fp2_t));
    gold_fp2_t *tn = (gold_fp2_t *)malloc(w * sizeof(gold_fp2_t));
    gold_fp2_t *pv = di->pool_len
                         ? (gold_fp2_t *)malloc(di->pool_len * sizeof(gold_fp2_t))
                         : NULL;
    if (!tl || !tn || (di->pool_len && !pv)) {
        free(tl); free(tn); free(pv);
        return DNAC_PROVER_ERR_PARAM;
    }
    gold_fp2_t pl[64], pn[64], perm_loc[64], perm_nxt[64];
    dnac_prover_status_t rc = DNAC_PROVER_ERR_PARAM;

    for (size_t i = 0; i < q_size; i++) {
        const size_t j = (i + next_step) % q_size; /* wrapped next row
                                                    * (prover.rs:850-868)    */
        for (size_t k = 0; k < w; k++) {
            tl[k] = gold_fp2_from_base(gold_fp_from_u64(trace_q[i * w + k]));
            tn[k] = gold_fp2_from_base(gold_fp_from_u64(trace_q[j * w + k]));
        }
        for (uint32_t k = 0; k < pw; k++) {
            pl[k] = gold_fp2_from_base(gold_fp_from_u64(prep_q[i * pw + k]));
            pn[k] = gold_fp2_from_base(gold_fp_from_u64(prep_q[j * pw + k]));
        }
        for (uint32_t c = 0; c < aw; c++) {
            /* EF recompose from the base-flattened columns [c0,c1]. */
            const gold_fp2_t x = gold_fp2_new(gold_fp_zero(), gold_fp_one());
            gold_fp2_t v0 = gold_fp2_from_base(
                gold_fp_from_u64(perm_q[i * 2 * aw + 2 * c]));
            gold_fp2_t v1 = gold_fp2_from_base(
                gold_fp_from_u64(perm_q[i * 2 * aw + 2 * c + 1]));
            perm_loc[c] = gold_fp2_add(v0, gold_fp2_mul(v1, x));
            v0 = gold_fp2_from_base(
                gold_fp_from_u64(perm_q[j * 2 * aw + 2 * c]));
            v1 = gold_fp2_from_base(
                gold_fp_from_u64(perm_q[j * 2 * aw + 2 * c + 1]));
            perm_nxt[c] = gold_fp2_add(v0, gold_fp2_mul(v1, x));
        }

        dnac_stark_folder_t folder;
        memset(&folder, 0, sizeof(folder));
        folder.trace_local = tl;
        folder.trace_next = tn;
        folder.main_width = w;
        folder.public_values = di->public_values;
        folder.num_public_values = di->num_publics;
        folder.is_first_row = gold_fp2_from_base(gold_fp_from_u64(sf[i]));
        folder.is_last_row = gold_fp2_from_base(gold_fp_from_u64(sl[i]));
        folder.is_transition = gold_fp2_from_base(gold_fp_from_u64(st[i]));
        dnac_stark_fold_init(&folder.fold, alpha);
        folder.preprocessed_local = pw ? pl : NULL;
        folder.preprocessed_next = pw ? pn : NULL;
        folder.prep_width = pw;

        /* air.eval FIRST (protocol.rs:64-81)... */
        di->air.air_eval(&folder);

        /* ...then the lookup residuals in lookup order — ONE fold stream
         * acc = acc·α + x (folder.rs:169-181; serial Horner ≡ the
         * decompose_alpha α^{K−1−i} weights, builder.rs:401-423). */
        if (di->num_lookups > 0) {
            if (di->pool_len > 0 &&
                dnac_logup_eval_pool_window(
                    di->pool, di->pool_len, tl, tn, (uint32_t)w,
                    pw ? pl : NULL, pw ? pn : NULL, pw, di->public_values,
                    di->num_publics, pv) != DNAC_LOGUP_OK) {
                goto out;
            }
            for (uint32_t l = 0; l < di->num_lookups; l++) {
                const dnac_logup_lookup_t *lk = &di->lookups[l];
                const uint32_t col = lk->column;
                if (lk->num_tuples > BP_MAX_TUPLES) goto out;
                gold_fp2_t elem_store[BP_MAX_TUPLES][BP_MAX_TUPLE_W];
                const gold_fp2_t *elem_ptrs[BP_MAX_TUPLES];
                gold_fp2_t mults[BP_MAX_TUPLES];
                for (uint32_t tt = 0; tt < lk->num_tuples; tt++) {
                    const uint32_t tw = lk->tuple_widths[tt];
                    if (tw > BP_MAX_TUPLE_W) goto out;
                    for (uint32_t e = 0; e < tw; e++) {
                        const int32_t idx = lk->tuple_elems[tt][e];
                        if (idx < 0 || (uint32_t)idx >= di->pool_len) goto out;
                        elem_store[tt][e] = pv[idx];
                    }
                    elem_ptrs[tt] = elem_store[tt];
                    const int32_t midx = lk->multiplicities[tt];
                    if (midx < 0 || (uint32_t)midx >= di->pool_len) goto out;
                    mults[tt] = pv[midx];
                }
                gold_fp2_t num, den;
                if (dnac_logup_sum_terms_fp2(elem_ptrs, lk->tuple_widths,
                                             mults, lk->num_tuples,
                                             challenges[2u * col],
                                             challenges[2u * col + 1u], &num,
                                             &den) != DNAC_LOGUP_OK) {
                    goto out;
                }
                /* S2'-c emission order mirrors eval_all (protocol.rs:56-81):
                 * EVERY lookup's fraction pin first, then ONE accumulator
                 * block after the loop. The fraction residual is UNGATED —
                 * "The identity is cyclic in the trace domain, so it does not
                 * need a transition gate" (logup.rs:241-244). Slot c reads
                 * fraction column c + 1; column 0 is the shared accumulator. */
                const gold_fp2_t frac_loc = perm_loc[col + 1u];
                dnac_stark_fold_assert_zero(
                    &folder.fold,
                    gold_fp2_sub(gold_fp2_mul(den, frac_loc), num));
            }
            /* eval_accumulator (logup.rs:258-302), once per row after every
             * fraction: anchor / transition / terminal binding. */
            {
                const gold_fp2_t acc_loc = perm_loc[0];
                const gold_fp2_t acc_nxt = perm_nxt[0];
                gold_fp2_t row_sum = gold_fp2_zero();
                for (uint32_t l = 0; l < di->num_lookups; l++) {
                    row_sum = gold_fp2_add(
                        row_sum, perm_loc[di->lookups[l].column + 1u]);
                }
                dnac_stark_fold_assert_zero(
                    &folder.fold, gold_fp2_mul(folder.is_first_row, acc_loc));
                dnac_stark_fold_assert_zero(
                    &folder.fold,
                    gold_fp2_mul(folder.is_transition,
                                 gold_fp2_sub(gold_fp2_sub(acc_nxt, acc_loc),
                                              row_sum)));
                dnac_stark_fold_assert_zero(
                    &folder.fold,
                    gold_fp2_mul(folder.is_last_row,
                                 gold_fp2_sub(gold_fp2_sub(terminal, acc_loc),
                                              row_sum)));
            }
        }

        /* out[i] = acc · inv_vanishing[i] (prover.rs:911). */
        const gold_fp2_t q = gold_fp2_mul(
            folder.fold.acc, gold_fp2_from_base(gold_fp_from_u64(iv[i])));
        out_qflat[2 * i] = gold_fp_to_u64(q.a);
        out_qflat[2 * i + 1] = gold_fp_to_u64(q.b);
    }
    rc = DNAC_PROVER_OK;
out:
    free(tl); free(tn); free(pv);
    return rc;
}

/* Plain (non-ZK) quotient chunk LDEs (two_adic_pcs.rs:327-349 over the split
 * domains, domain.rs:199-246): chunk c takes global rows {c, c+nqc, ...},
 * lde_shift = GENERATOR / (q_shift·k^c), added_bits = log_blowup, bitrev. */
static dnac_prover_status_t bp_quotient_ldes_plain(
    const uint64_t *qflat, size_t q_size, size_t nqc, unsigned log_blowup,
    uint64_t *out_chunk_ldes /* [nqc][h_chunk<<log_blowup][2] */)
{
    const size_t h = q_size / nqc;
    const size_t lde_h = h << log_blowup;
    const unsigned log_q = (unsigned)bp_log2(q_size);
    const gold_fp_t k = gold_fp_two_adic_generator(log_q);
    const gold_fp_t gen = gold_fp_from_u64(GOLDILOCKS_GENERATOR);
    uint64_t *widened = (uint64_t *)malloc(h * BP_DIM * sizeof(uint64_t));
    if (widened == NULL) return DNAC_PROVER_ERR_PARAM;
    gold_fp_t shift_c = gold_fp_from_u64(GOLDILOCKS_GENERATOR); /* q_shift·k^0 */
    dnac_prover_status_t rc = DNAC_PROVER_OK;
    for (size_t c = 0; c < nqc; c++) {
        for (size_t r = 0; r < h; r++) {
            const size_t gr = r * nqc + c; /* round-robin split_evals */
            widened[r * BP_DIM] = qflat[2 * gr];
            widened[r * BP_DIM + 1] = qflat[2 * gr + 1];
        }
        const gold_fp_t lde_shift = gold_fp_mul(gen, gold_fp_inv(shift_c));
        rc = dnac_prover_coset_lde_bitrev(widened, h, BP_DIM, log_blowup,
                                          gold_fp_to_u64(lde_shift),
                                          &out_chunk_ldes[c * lde_h * BP_DIM]);
        if (rc != DNAC_PROVER_OK) break;
        shift_c = gold_fp_mul(shift_c, k);
    }
    free(widened);
    return rc;
}

/* d4.c: commit a mixed batch, optionally SALTED — leaf = row ‖ SE salt lanes
 * (hiding_mmcs.rs:167-170), salts from stream A at *salt_cur, per matrix in
 * order, rows × SE row-major. Widened matrices are RETAINED in store[] (the
 * query stage opens row‖salt from the tree and splits); caller frees. */
static dnac_prover_status_t bp_commit_mixed_salted(
    const uint64_t *const *mats, const size_t *widths, const size_t *heights,
    size_t nm, const uint64_t *saltA, size_t *salt_cur, size_t salt_avail,
    size_t se, dnac_p2_digest_t *root, dnac_p2_mmcs_tree_t **tree,
    uint64_t **store)
{
    if (se == 0) {
        return dnac_p2_mmcs_commit_mixed(mats, widths, heights, nm, root,
                                         tree) == DNAC_P2M_OK
                   ? DNAC_PROVER_OK
                   : DNAC_PROVER_ERR_PARAM;
    }
    const uint64_t *smats[BP_MAX_INSTANCES * 8];
    size_t swidths[BP_MAX_INSTANCES * 8];
    if (nm > BP_MAX_INSTANCES * 8) return DNAC_PROVER_ERR_PARAM;
    for (size_t m = 0; m < nm; m++) {
        const size_t h = heights[m], w0 = widths[m];
        if (*salt_cur + h * se > salt_avail) return DNAC_PROVER_ERR_PARAM;
        uint64_t *sm = (uint64_t *)malloc(h * (w0 + se) * sizeof(uint64_t));
        if (!sm) return DNAC_PROVER_ERR_PARAM;
        store[m] = sm;
        for (size_t r = 0; r < h; r++) {
            memcpy(&sm[r * (w0 + se)], &mats[m][r * w0],
                   w0 * sizeof(uint64_t));
            for (size_t s = 0; s < se; s++) {
                const uint64_t v = saltA[*salt_cur + r * se + s];
                if (v >= GOLDILOCKS_P) return DNAC_PROVER_ERR_NONCANONICAL;
                sm[r * (w0 + se) + w0 + s] = v;
            }
        }
        *salt_cur += h * se;
        smats[m] = sm;
        swidths[m] = w0 + se;
    }
    return dnac_p2_mmcs_commit_mixed(smats, swidths, heights, nm, root,
                                     tree) == DNAC_P2M_OK
               ? DNAC_PROVER_OK
               : DNAC_PROVER_ERR_PARAM;
}

/* ============================================================================
 * The prove
 * ========================================================================== */

#ifdef DNAC_ZK_ENABLE_TEST_WIRE
/* C2.1 CRIT-1 forge knob (test-wire ONLY — absent from consensus builds,
 * nm-provable; single-threaded KAT use). When set, instance-0's FS/priming
 * publics are the FORGED set while the quotient still folds the TRUE
 * insts[0].public_values, and self-verify is skipped (it would correctly
 * reject). The isolating vector: FRI accepts, ONLY the N-chunk constraint
 * check catches it. Both are NULL/0 on every real path → byte-identical. */
static const gold_fp_t *g_bp_fs_pub_override = NULL;
static int              g_bp_skip_selfverify = 0;
#endif

dnac_prover_status_t dnac_batch_prove(
    const dnac_batch_vinstance_t *insts,
    const dnac_batch_pwitness_t  *wits,
    uint32_t                      n,
    int                           is_zk,
    const dnac_fri_params_t      *fri_params,
    uint32_t                      nrc,
    const uint64_t               *draws,
    size_t                        num_draws,
    const uint64_t               *salt_draws,
    size_t                        num_salt_draws,
    const uint64_t               *fri_salt_draws,
    size_t                        num_fri_salt_draws,
    size_t                        salt_elems,
    dnac_batch_proof_t          **out_proof)
{
    if (!insts || !wits || !fri_params || !out_proof || n == 0 ||
        n > BP_MAX_INSTANCES || (is_zk != 0 && is_zk != 1)) {
        return DNAC_PROVER_ERR_PARAM;
    }
    if (is_zk && (nrc == 0 || draws == NULL)) return DNAC_PROVER_ERR_PARAM;
    if (!is_zk && (nrc != 0 || draws != NULL || num_draws != 0)) {
        return DNAC_PROVER_ERR_PARAM;
    }
    /* d4.c salted-mode contract (batch_prover.h): SE=0 ⇒ no salt args at all
     * (byte-identical unsalted path); SE>0 ⇒ stream A present + coverage. */
    if (salt_elems == 0) {
        if (salt_draws != NULL || num_salt_draws != 0 ||
            fri_salt_draws != NULL || num_fri_salt_draws != 0) {
            return DNAC_PROVER_ERR_PARAM;
        }
    } else {
        if (salt_elems > BP_MAX_SALT_ELEMS || salt_draws == NULL) {
            return DNAC_PROVER_ERR_PARAM;
        }
        if (fri_salt_draws == NULL && num_fri_salt_draws != 0) {
            return DNAC_PROVER_ERR_PARAM;
        }
    }
    const unsigned lb = (unsigned)fri_params->log_blowup;
    if (lb == 0) return DNAC_PROVER_ERR_PARAM;
    {
        const size_t want =
            dnac_batch_prove_num_draws(insts, n, is_zk, nrc);
        if (want == SIZE_MAX || (is_zk && num_draws != want)) {
            return DNAC_PROVER_ERR_PARAM;
        }
    }
    if (salt_elems > 0) {
        const size_t wantA = dnac_batch_prove_num_salt_draws(
            insts, n, is_zk, (size_t)lb, salt_elems);
        if (wantA == SIZE_MAX || num_salt_draws < wantA) {
            return DNAC_PROVER_ERR_PARAM;
        }
        /* FAIL-CLOSE unexercised salted combinations (batch_prover.h):
         * preprocessed commits at SETUP time in the reference (its stream
         * position would be invented); salted+lookups has no byte-match
         * vector yet. */
        for (uint32_t i = 0; i < n; i++) {
            if (insts[i].preprocessed_width > 0 || insts[i].num_lookups > 0) {
                return DNAC_PROVER_ERR_PARAM;
            }
        }
    }

    /* ── derived shapes ── */
    uint32_t base_db[BP_MAX_INSTANCES], ext_db[BP_MAX_INSTANCES];
    size_t base_h[BP_MAX_INSTANCES], ext_h[BP_MAX_INSTANCES];
    size_t w[BP_MAX_INSTANCES], mw[BP_MAX_INSTANCES];
    uint32_t nqc[BP_MAX_INSTANCES];
    size_t q_size[BP_MAX_INSTANCES], h_chunk[BP_MAX_INSTANCES];
    size_t lde_h[BP_MAX_INSTANCES], cw[BP_MAX_INSTANCES];
    uint32_t aw[BP_MAX_INSTANCES], pw[BP_MAX_INSTANCES];
    size_t pmw[BP_MAX_INSTANCES]; /* committed perm width */
    dnac_batch_binding_t bindings[BP_MAX_INSTANCES];
    dnac_logup_bus_view_t views[BP_MAX_INSTANCES];
    uint32_t pre_widths[BP_MAX_INSTANCES];
    const gold_fp_t *pubs[BP_MAX_INSTANCES];
    uint32_t npubs[BP_MAX_INSTANCES];
    uint32_t num_prep = 0, num_perm = 0, total_qc = 0;
    size_t log_gmh = 0;

    for (uint32_t i = 0; i < n; i++) {
        const dnac_batch_vinstance_t *di = &insts[i];
        if (di->degree_bits < (uint32_t)is_zk + 1 || di->degree_bits >= 30 ||
            di->air.main_width == 0 || di->air.air_eval == NULL ||
            wits[i].main_trace == NULL) {
            return DNAC_PROVER_ERR_PARAM;
        }
        ext_db[i] = di->degree_bits;
        base_db[i] = ext_db[i] - (uint32_t)is_zk;
        base_h[i] = (size_t)1 << base_db[i];
        ext_h[i] = (size_t)1 << ext_db[i];
        w[i] = di->air.main_width;
        mw[i] = w[i] + (is_zk ? (size_t)nrc : 0);
        nqc[i] = 1u << (di->log_num_qc + (uint32_t)is_zk);
        q_size[i] = (size_t)1 << (ext_db[i] + di->log_num_qc);
        h_chunk[i] = q_size[i] / nqc[i];
        lde_h[i] = ext_h[i] << lb;
        cw[i] = BP_DIM + (is_zk ? (size_t)nrc : 0);
        aw[i] = bp_aux_width(di);
        pw[i] = di->preprocessed_width;
        pmw[i] = 2 * (size_t)aw[i] + (is_zk ? (size_t)nrc : 0);
        if (di->log_num_qc > lb) return DNAC_PROVER_ERR_PARAM; /* LDE cover */
        if ((h_chunk[i] << (lb + (unsigned)is_zk)) != lde_h[i]) {
            return DNAC_PROVER_ERR_PARAM;
        }
        if (di->num_lookups > 0) num_perm++;
        if (pw[i] > 0) {
            if (wits[i].prep_trace == NULL || num_prep >= BP_MAX_INSTANCES) {
                return DNAC_PROVER_ERR_PARAM;
            }
            num_prep++;
        }
        total_qc += nqc[i];
        if ((size_t)(ext_db[i] + lb) > log_gmh) log_gmh = ext_db[i] + lb;
        bindings[i].log_ext_degree = ext_db[i];
        bindings[i].log_degree = base_db[i];
        bindings[i].width = (uint32_t)w[i];
        bindings[i].num_quotient_chunks = nqc[i];
        views[i] = di->view;
        pre_widths[i] = pw[i];
        pubs[i] = di->public_values;
        npubs[i] = di->num_publics;
        if (di->view.num_locals + di->view.num_globals != di->num_lookups) {
            return DNAC_PROVER_ERR_PARAM;
        }
    }

    if (total_qc > BP_MAX_INSTANCES * 8u) return DNAC_PROVER_ERR_PARAM;

    /* Stream-B coverage: the commit phase consumes Σ(layer rows)·SE <
     * (1<<log_gmh)·SE (halving layers), mirror of the v3
     * DNAC_AGG_PROVER_FRI_SALT_DRAWS bound. */
    if (salt_elems > 0) {
        const size_t bl =
            fri_salt_draws ? num_fri_salt_draws : num_salt_draws;
        if (bl < (salt_elems << log_gmh)) return DNAC_PROVER_ERR_PARAM;
    }

    dnac_prover_status_t rc = DNAC_PROVER_ERR_PARAM;
    dnac_batch_proof_t *p = (dnac_batch_proof_t *)calloc(1, sizeof(*p));
    if (p == NULL) return DNAC_PROVER_ERR_PARAM;
    p->n = n;
    p->is_zk = is_zk;
    p->nrc = nrc;
    p->params = *fri_params;
    p->num_queries = fri_params->num_queries;
    if (p->num_queries == 0 || p->num_queries > BP_MAX_QUERIES) {
        free(p);
        return DNAC_PROVER_ERR_PARAM;
    }

    /* ── scratch (freed at cleanup) ── */
    uint64_t *rand_mat[BP_MAX_INSTANCES] = {0};   /* zk randomized main      */
    uint64_t *main_lde[BP_MAX_INSTANCES] = {0};
    uint64_t *prep_pad[BP_MAX_INSTANCES] = {0};   /* zk zero-interleaved     */
    uint64_t *prep_lde[BP_MAX_INSTANCES] = {0};   /* by prep-matrix index    */
    uint64_t *perm_flat[BP_MAX_INSTANCES] = {0};  /* flattened (+rand) aux   */
    uint64_t *perm_lde[BP_MAX_INSTANCES] = {0};   /* by perm-matrix index    */
    uint64_t *chunk_ldes[BP_MAX_INSTANCES] = {0}; /* per instance, nqc mats  */
    uint64_t *r_mat[BP_MAX_INSTANCES] = {0};
    uint64_t *r_lde[BP_MAX_INSTANCES] = {0};
    /* d4.c salted widened matrices (leaf = row ‖ salts), retained through the
     * query stage. */
    uint64_t *salted_main[BP_MAX_INSTANCES] = {0};
    uint64_t *salted_quot[BP_MAX_INSTANCES * 8] = {0};
    uint64_t *salted_rand[BP_MAX_INSTANCES] = {0};
    size_t salt_cur = 0;                /* stream-A cursor                  */
    const size_t SE = salt_elems;
    const uint64_t *fri_sd =
        (SE > 0) ? (fri_salt_draws ? fri_salt_draws : salt_draws) : NULL;
    gold_fp_t *ctx_main[BP_MAX_INSTANCES] = {0};  /* logup ctx arenas        */
    gold_fp_t *ctx_prep[BP_MAX_INSTANCES] = {0};
    gold_fp2_t *aux_ef[BP_MAX_INSTANCES] = {0};
    dnac_p2_mmcs_tree_t *main_tree = NULL, *prep_tree = NULL,
                        *perm_tree = NULL, *quot_tree = NULL, *rand_tree = NULL;
    gold_fp2_t *ch_flat = NULL;
    gold_fp2_t *ch_ptrs[BP_MAX_INSTANCES] = {0};
    gold_fp2_t *opened_full = NULL;      /* full-width opened vectors arena  */
    const gold_fp2_t **op_full_ptrs = NULL;
    dnac_prover_fri_input_round_t *fri_rounds = NULL;
    gold_fp2_t *pts_store = NULL;
    dnac_transcript_t *t = NULL;
    dnac_prover_fri_result_t fres;
    memset(&fres, 0, sizeof(fres));
    int have_fres = 0;
    uint64_t *sf = NULL, *sl = NULL, *st = NULL, *ivv = NULL, *trace_q = NULL,
             *prep_q = NULL, *perm_q = NULL, *qflat = NULL;
    dnac_p2_mmcs_tree_t *s7_tree = NULL;
    dnac_prover_fri_ro_mixed_t romix;
    memset(&romix, 0, sizeof(romix));
    int have_romix = 0;

    size_t cur = 0; /* draw cursor */

    /* ── priming: instance count + bindings (prover.rs:200-209) ── */
    dnac_duplex_t dx;
    dnac_duplex_init_default(&dx);
    if (dnac_batch_observe_count_and_bindings(&dx, bindings, n) !=
        DNAC_BATCH_OK) {
        goto cleanup;
    }

    /* ── MAIN commit (prover.rs:211-219; hiding commit hiding_pcs.rs:106-132,
     *    plain commit two_adic_pcs.rs:301-325) ── */
    {
        const uint64_t *mats[BP_MAX_INSTANCES];
        size_t widths[BP_MAX_INSTANCES], heights[BP_MAX_INSTANCES];
        for (uint32_t i = 0; i < n; i++) {
            const uint64_t *src = wits[i].main_trace;
            size_t sh = base_h[i];
            if (is_zk) {
                rand_mat[i] =
                    (uint64_t *)malloc(ext_h[i] * mw[i] * sizeof(uint64_t));
                if (!rand_mat[i]) goto cleanup;
                dnac_prover_status_t s = dnac_prover_randomize_trace(
                    wits[i].main_trace, base_h[i], w[i], nrc, draws + cur,
                    rand_mat[i]);
                if (s != DNAC_PROVER_OK) { rc = s; goto cleanup; }
                cur += base_h[i] * (w[i] + 2 * (size_t)nrc);
                src = rand_mat[i];
                sh = ext_h[i];
            }
            main_lde[i] =
                (uint64_t *)malloc(lde_h[i] * mw[i] * sizeof(uint64_t));
            if (!main_lde[i]) goto cleanup;
            dnac_prover_status_t s = dnac_prover_coset_lde_bitrev(
                src, sh, mw[i], lb, GOLDILOCKS_GENERATOR, main_lde[i]);
            if (s != DNAC_PROVER_OK) { rc = s; goto cleanup; }
            mats[i] = main_lde[i];
            widths[i] = mw[i];
            heights[i] = lde_h[i];
        }
        {
            dnac_prover_status_t s = bp_commit_mixed_salted(
                mats, widths, heights, n, salt_draws, &salt_cur,
                num_salt_draws, SE, &p->main_c, &main_tree, salted_main);
            if (s != DNAC_PROVER_OK) { rc = s; goto cleanup; }
        }
        bp_digest_lanes(&p->main_c, p->main_lanes);
    }
    /* FS-publics: the priming observes `pubs` (== true insts[i].public_values)
     * on every consensus path. The C2.1 CRIT-1 forge (test-wire only) swaps
     * instance-0's FS publics for a forged set while the quotient below still
     * folds the TRUE publics — FRI accepts, only the N-chunk check rejects. */
    {
        const gold_fp_t *fs_pubs[BP_MAX_INSTANCES];
        for (uint32_t i = 0; i < n; i++) fs_pubs[i] = pubs[i];
#ifdef DNAC_ZK_ENABLE_TEST_WIRE
        if (g_bp_fs_pub_override) fs_pubs[0] = g_bp_fs_pub_override;
#endif
        if (dnac_batch_observe_main(&dx, p->main_lanes, fs_pubs, npubs, n) !=
            DNAC_BATCH_OK) {
            goto cleanup;
        }
    }

    /* ── PREPROCESSED commit (common.rs:244-256 commit_preprocessing;
     *    zk pads with ZERO rows — hiding_pcs.rs:134-153, no draws) ── */
    if (num_prep > 0) {
        const uint64_t *mats[BP_MAX_INSTANCES];
        size_t widths[BP_MAX_INSTANCES], heights[BP_MAX_INSTANCES];
        uint32_t m = 0;
        for (uint32_t i = 0; i < n; i++) {
            if (pw[i] == 0) continue;
            const uint64_t *src = wits[i].prep_trace;
            size_t sh = base_h[i];
            if (is_zk) {
                prep_pad[m] =
                    (uint64_t *)calloc(ext_h[i] * pw[i], sizeof(uint64_t));
                if (!prep_pad[m]) goto cleanup;
                for (size_t r = 0; r < base_h[i]; r++) {
                    memcpy(&prep_pad[m][(2 * r) * pw[i]],
                           &wits[i].prep_trace[r * pw[i]],
                           pw[i] * sizeof(uint64_t));
                }
                src = prep_pad[m];
                sh = ext_h[i];
            }
            prep_lde[m] =
                (uint64_t *)malloc(lde_h[i] * pw[i] * sizeof(uint64_t));
            if (!prep_lde[m]) goto cleanup;
            dnac_prover_status_t s = dnac_prover_coset_lde_bitrev(
                src, sh, pw[i], lb, GOLDILOCKS_GENERATOR, prep_lde[m]);
            if (s != DNAC_PROVER_OK) { rc = s; goto cleanup; }
            mats[m] = prep_lde[m];
            widths[m] = pw[i];
            heights[m] = lde_h[i];
            p->prep_map[m] = i;
            m++;
        }
        p->num_prep = m;
        if (dnac_p2_mmcs_commit_mixed(mats, widths, heights, m, &p->prep_c,
                                      &prep_tree) != DNAC_P2M_OK) {
            goto cleanup;
        }
        p->has_prep = 1;
        bp_digest_lanes(&p->prep_c, p->prep_lanes);
    }
    if (dnac_batch_observe_preprocessed(
            &dx, pre_widths, n, p->has_prep ? p->prep_lanes : NULL) !=
        DNAC_BATCH_OK) {
        goto cleanup;
    }

    /* ── (α,β) via the bus memo (prover.rs:227 / transcript.rs:74-102) ── */
    {
        uint32_t total_ch = 0;
        for (uint32_t i = 0; i < n; i++) {
            total_ch += 2u * insts[i].num_lookups;
        }
        if (total_ch > 0) {
            ch_flat = (gold_fp2_t *)calloc(total_ch, sizeof(gold_fp2_t));
            if (!ch_flat) goto cleanup;
        }
        uint32_t off = 0;
        for (uint32_t i = 0; i < n; i++) {
            ch_ptrs[i] = insts[i].num_lookups > 0 ? ch_flat + off : NULL;
            off += 2u * insts[i].num_lookups;
        }
        /* W = widest payload tuple in the batch, min 1 (transcript.rs:124,
         * 132-135). It fixes the bus offset beta^W, so it must be computed
         * over EVERY instance's lookups, not per instance.
         *
         * Via the SHARED helper, not a second inline loop: prover and verifier
         * must derive gamma = beta^W from ONE definition or the transcript
         * forks between them. (This was two copies until S2'-c collapsed it.) */
        const dnac_logup_lookup_t *lk_ptrs[BP_MAX_INSTANCES];
        uint32_t                   lk_counts[BP_MAX_INSTANCES];
        for (uint32_t i = 0; i < n; i++) {
            lk_ptrs[i] = insts[i].lookups;
            lk_counts[i] = insts[i].num_lookups;
        }
        const uint32_t mmw =
            dnac_logup_bus_max_message_width(lk_ptrs, lk_counts, n);
        if (dnac_batch_sample_perm_challenges(&dx, views, n, mmw, ch_ptrs) !=
            DNAC_BATCH_OK) {
            goto cleanup;
        }
    }

    /* ── permutation traces + commit (prover.rs:229-302) ── */
    {
        /* ONE terminal per AIR (S2'-c), so the arena is simply [n]. */
        p->terminals = (gold_fp2_t *)calloc(n ? n : 1, sizeof(gold_fp2_t));
        if (!p->terminals) goto cleanup;
    }
    {
        const uint64_t *mats[BP_MAX_INSTANCES];
        size_t widths[BP_MAX_INSTANCES], heights[BP_MAX_INSTANCES];
        uint32_t j = 0;
        for (uint32_t i = 0; i < n; i++) {
            const dnac_batch_vinstance_t *di = &insts[i];
            if (di->num_lookups == 0) continue;
            /* logup ctx over the BASE witness (prover.rs:238-245:
             * generate_permutation on inst.trace + preprocessed_trace). */
            ctx_main[i] =
                (gold_fp_t *)malloc(base_h[i] * w[i] * sizeof(gold_fp_t));
            if (!ctx_main[i]) goto cleanup;
            for (size_t k = 0; k < base_h[i] * w[i]; k++) {
                if (wits[i].main_trace[k] >= GOLDILOCKS_P) {
                    rc = DNAC_PROVER_ERR_NONCANONICAL;
                    goto cleanup;
                }
                ctx_main[i][k] = gold_fp_from_u64(wits[i].main_trace[k]);
            }
            if (pw[i] > 0) {
                ctx_prep[i] = (gold_fp_t *)malloc(base_h[i] * pw[i] *
                                                  sizeof(gold_fp_t));
                if (!ctx_prep[i]) goto cleanup;
                for (size_t k = 0; k < base_h[i] * pw[i]; k++) {
                    ctx_prep[i][k] =
                        gold_fp_from_u64(wits[i].prep_trace[k]);
                }
            }
            dnac_logup_ctx_t ctx;
            memset(&ctx, 0, sizeof(ctx));
            ctx.main = ctx_main[i];
            ctx.main_width = (uint32_t)w[i];
            ctx.prep = ctx_prep[i];
            ctx.prep_width = pw[i];
            ctx.publics = di->public_values;
            ctx.num_publics = di->num_publics;
            ctx.height = (uint32_t)base_h[i];
            ctx.pool = di->pool;
            ctx.pool_len = di->pool_len;

            /* S2'-c: aux is [height][num_lookups + 1] — accumulator + one
             * fraction column per lookup. */
            aux_ef[i] = (gold_fp2_t *)malloc(base_h[i] * (di->num_lookups + 1u) *
                                             sizeof(gold_fp2_t));
            if (!aux_ef[i]) goto cleanup;
            if (dnac_logup_generate_permutation(
                    &ctx, di->lookups, di->num_lookups, ch_ptrs[i],
                    2u * di->num_lookups, aux_ef[i],
                    &p->terminals[i]) != DNAC_LOGUP_OK) {
                goto cleanup;
            }

            /* flatten_to_base ([c0,c1] per EF cell, prover.rs:269) then the
             * hiding randomization (zk) — draws AFTER the challenge phase,
             * in prove_batch call order. */
            const size_t fw = 2 * (size_t)aw[i];
            uint64_t *flat =
                (uint64_t *)malloc(base_h[i] * fw * sizeof(uint64_t));
            if (!flat) goto cleanup;
            for (size_t r = 0; r < base_h[i]; r++) {
                for (uint32_t c = 0; c < aw[i]; c++) {
                    const gold_fp2_t v = aux_ef[i][r * (di->num_lookups + 1u) + c];
                    flat[r * fw + 2 * c] = gold_fp_to_u64(v.a);
                    flat[r * fw + 2 * c + 1] = gold_fp_to_u64(v.b);
                }
            }
            const uint64_t *src = flat;
            size_t sh = base_h[i];
            if (is_zk) {
                perm_flat[j] =
                    (uint64_t *)malloc(ext_h[i] * pmw[i] * sizeof(uint64_t));
                if (!perm_flat[j]) { free(flat); goto cleanup; }
                dnac_prover_status_t s = dnac_prover_randomize_trace(
                    flat, base_h[i], fw, nrc, draws + cur, perm_flat[j]);
                free(flat);
                if (s != DNAC_PROVER_OK) { rc = s; goto cleanup; }
                cur += base_h[i] * (fw + 2 * (size_t)nrc);
                src = perm_flat[j];
                sh = ext_h[i];
            } else {
                perm_flat[j] = flat;
            }
            perm_lde[j] =
                (uint64_t *)malloc(lde_h[i] * pmw[i] * sizeof(uint64_t));
            if (!perm_lde[j]) goto cleanup;
            dnac_prover_status_t s = dnac_prover_coset_lde_bitrev(
                src, sh, pmw[i], lb, GOLDILOCKS_GENERATOR, perm_lde[j]);
            if (s != DNAC_PROVER_OK) { rc = s; goto cleanup; }
            mats[j] = perm_lde[j];
            widths[j] = pmw[i];
            heights[j] = lde_h[i];
            j++;
        }
        if (j > 0) {
            if (dnac_p2_mmcs_commit_mixed(mats, widths, heights, j, &p->perm_c,
                                          &perm_tree) != DNAC_P2M_OK) {
                goto cleanup;
            }
            p->has_perm = 1;
            bp_digest_lanes(&p->perm_c, p->perm_lanes);
        }
    }
    {
        if (dnac_batch_observe_perm_and_sample_alpha(
                &dx, p->has_perm ? p->perm_lanes : NULL, views, p->terminals, n,
                &p->alpha) != DNAC_BATCH_OK) {
            goto cleanup;
        }
    }

    /* ── quotient values + chunk LDEs + ONE mixed commit
     *    (prover.rs:310-421) ── */
    {
        const uint64_t *mats[BP_MAX_INSTANCES * 8];
        size_t widths[BP_MAX_INSTANCES * 8], heights[BP_MAX_INSTANCES * 8];
        uint32_t mi = 0, jperm = 0, mprep = 0;
        uint32_t prep_of[BP_MAX_INSTANCES], perm_of[BP_MAX_INSTANCES];
        for (uint32_t i = 0; i < n; i++) {
            prep_of[i] = pw[i] > 0 ? mprep++ : UINT32_MAX;
            perm_of[i] = insts[i].num_lookups > 0 ? jperm++ : UINT32_MAX;
        }
        for (uint32_t i = 0; i < n; i++) {
            const dnac_batch_vinstance_t *di = &insts[i];
            const size_t qs = q_size[i];
            const size_t next_step = qs >> base_db[i]; /* 1<<qdb,
                                                        * prover.rs:733-734 */
            sf = (uint64_t *)malloc(qs * sizeof(uint64_t));
            sl = (uint64_t *)malloc(qs * sizeof(uint64_t));
            st = (uint64_t *)malloc(qs * sizeof(uint64_t));
            ivv = (uint64_t *)malloc(qs * sizeof(uint64_t));
            trace_q = (uint64_t *)malloc(qs * w[i] * sizeof(uint64_t));
            qflat = (uint64_t *)malloc(qs * 2 * sizeof(uint64_t));
            prep_q = pw[i] ? (uint64_t *)malloc(qs * pw[i] * sizeof(uint64_t))
                           : NULL;
            perm_q = di->num_lookups
                         ? (uint64_t *)malloc(qs * 2 * aw[i] * sizeof(uint64_t))
                         : NULL;
            if (!sf || !sl || !st || !ivv || !trace_q || !qflat ||
                (pw[i] && !prep_q) || (di->num_lookups && !perm_q)) {
                goto cleanup;
            }
            /* selectors_on_coset over the disjoint domain (shift GENERATOR,
             * domain.rs:180-193; prover.rs:729-730). */
            dnac_prover_status_t s = dnac_prover_quotient_selectors(
                (unsigned)base_db[i], (unsigned)(ext_db[i] + di->log_num_qc),
                GOLDILOCKS_GENERATOR, sf, sl, st, ivv);
            if (s != DNAC_PROVER_OK) { rc = s; goto cleanup; }
            s = dnac_prover_trace_on_quotient_domain(main_lde[i], lde_h[i],
                                                     mw[i], qs, w[i], trace_q);
            if (s != DNAC_PROVER_OK) { rc = s; goto cleanup; }
            if (pw[i]) {
                s = dnac_prover_trace_on_quotient_domain(
                    prep_lde[prep_of[i]], lde_h[i], pw[i], qs, pw[i], prep_q);
                if (s != DNAC_PROVER_OK) { rc = s; goto cleanup; }
            }
            if (di->num_lookups) {
                s = dnac_prover_trace_on_quotient_domain(
                    perm_lde[perm_of[i]], lde_h[i], pmw[i], qs, 2 * aw[i],
                    perm_q);
                if (s != DNAC_PROVER_OK) { rc = s; goto cleanup; }
            }
            s = bp_quotient_values(di, trace_q, prep_q, perm_q,
                                   p->terminals[i], ch_ptrs[i],
                                   p->alpha, sf, sl, st, ivv, qs, next_step,
                                   qflat);
            if (s != DNAC_PROVER_OK) { rc = s; goto cleanup; }

            chunk_ldes[i] = (uint64_t *)malloc(nqc[i] * lde_h[i] * cw[i] *
                                               sizeof(uint64_t));
            if (!chunk_ldes[i]) goto cleanup;
            if (is_zk) {
                /* hiding get_quotient_ldes (hiding_pcs.rs:169-257) — the
                 * frozen S7 pipeline; its same-height root/tree is a
                 * throwaway (the REAL commit is the mixed one below). */
                dnac_p2_digest_t droot;
                s = dnac_prover_quotient_commit(
                    qflat, qs, nqc[i], nrc, lb, GOLDILOCKS_GENERATOR,
                    draws + cur,
                    draws + cur + (size_t)nqc[i] * h_chunk[i] * nrc, NULL, 0,
                    chunk_ldes[i], &droot, &s7_tree);
                if (s != DNAC_PROVER_OK) { rc = s; goto cleanup; }
                dnac_p2_mmcs_tree_free(s7_tree);
                s7_tree = NULL;
                cur += (size_t)nqc[i] * h_chunk[i] * nrc +
                       (size_t)(nqc[i] - 1) * h_chunk[i] * (BP_DIM + nrc);
            } else {
                s = bp_quotient_ldes_plain(qflat, qs, nqc[i], lb,
                                           chunk_ldes[i]);
                if (s != DNAC_PROVER_OK) { rc = s; goto cleanup; }
            }
            for (uint32_t c = 0; c < nqc[i]; c++) {
                mats[mi] = &chunk_ldes[i][(size_t)c * lde_h[i] * cw[i]];
                widths[mi] = cw[i];
                heights[mi] = lde_h[i];
                mi++;
            }
            free(sf); free(sl); free(st); free(ivv); free(trace_q);
            free(prep_q); free(perm_q); free(qflat);
            sf = sl = st = ivv = trace_q = prep_q = perm_q = qflat = NULL;
        }
        if (mi != total_qc) goto cleanup;
        {
            dnac_prover_status_t s = bp_commit_mixed_salted(
                mats, widths, heights, mi, salt_draws, &salt_cur,
                num_salt_draws, SE, &p->quot_c, &quot_tree, salted_quot);
            if (s != DNAC_PROVER_OK) { rc = s; goto cleanup; }
        }
        bp_digest_lanes(&p->quot_c, p->quot_lanes);
    }
    dnac_batch_observe_commit(&dx, p->quot_lanes); /* transcript.rs:122-124 */

    /* ── ZK randomization poly R (prover.rs:431-442;
     *    hiding_pcs.rs:404-424) ── */
    if (is_zk) {
        const uint64_t *mats[BP_MAX_INSTANCES];
        size_t widths[BP_MAX_INSTANCES], heights[BP_MAX_INSTANCES];
        for (uint32_t i = 0; i < n; i++) {
            const size_t rw = (size_t)nrc + BP_DIM;
            r_mat[i] = (uint64_t *)malloc(ext_h[i] * rw * sizeof(uint64_t));
            r_lde[i] = (uint64_t *)malloc(lde_h[i] * rw * sizeof(uint64_t));
            if (!r_mat[i] || !r_lde[i]) goto cleanup;
            for (size_t k = 0; k < ext_h[i] * rw; k++) {
                if (draws[cur + k] >= GOLDILOCKS_P) {
                    rc = DNAC_PROVER_ERR_NONCANONICAL;
                    goto cleanup;
                }
                r_mat[i][k] = draws[cur + k];
            }
            cur += ext_h[i] * rw;
            dnac_prover_status_t s = dnac_prover_coset_lde_bitrev(
                r_mat[i], ext_h[i], rw, lb, GOLDILOCKS_GENERATOR, r_lde[i]);
            if (s != DNAC_PROVER_OK) { rc = s; goto cleanup; }
            mats[i] = r_lde[i];
            widths[i] = rw;
            heights[i] = lde_h[i];
        }
        {
            dnac_prover_status_t s = bp_commit_mixed_salted(
                mats, widths, heights, n, salt_draws, &salt_cur,
                num_salt_draws, SE, &p->rand_c, &rand_tree, salted_rand);
            if (s != DNAC_PROVER_OK) { rc = s; goto cleanup; }
        }
        bp_digest_lanes(&p->rand_c, p->rand_lanes);
        dnac_batch_observe_commit(&dx, p->rand_lanes); /* :440-442 */
        if (cur != num_draws) goto cleanup; /* stream fully consumed */
    }

    /* ── ζ (transcript.rs:132-134) ── */
    p->zeta = dnac_batch_sample_zeta(&dx);
    gold_fp2_t zeta_nexts[BP_MAX_INSTANCES];
    for (uint32_t i = 0; i < n; i++) {
        zeta_nexts[i] = bp_zeta_next(p->zeta, base_db[i]);
    }

    /* ── N2 opening rounds: barycentric opens + observes + splits
     *    (prover.rs:450-537; two_adic_pcs.rs:505-553 observe order;
     *    hiding split hiding_pcs.rs:333-358) ── */
    {
        /* enumerate (round, matrix, point) with full widths + ldes. */
        const uint32_t num_rounds = (is_zk ? 1u : 0u) + 1u + 1u +
                                    (p->num_prep > 0 ? 1u : 0u) +
                                    (p->has_perm ? 1u : 0u);
        const uint32_t total_mats = (is_zk ? n : 0u) + n + total_qc +
                                    p->num_prep + num_perm;
        uint32_t total_points = 0;
        size_t full_lanes = 0, base_lanes = 0, tail_lanes = 0;
        {
            if (is_zk) {
                total_points += n;
                for (uint32_t i = 0; i < n; i++) {
                    full_lanes += (size_t)nrc + BP_DIM;
                }
            }
            for (uint32_t i = 0; i < n; i++) {
                const uint32_t np = insts[i].air.main_next ? 2u : 1u;
                total_points += np;
                full_lanes += np * mw[i];
            }
            for (uint32_t i = 0; i < n; i++) {
                total_points += nqc[i];
                full_lanes += (size_t)nqc[i] * cw[i];
            }
            for (uint32_t m = 0; m < p->num_prep; m++) {
                const uint32_t ii = p->prep_map[m];
                const uint32_t np = insts[ii].prep_next ? 2u : 1u;
                total_points += np;
                full_lanes += np * pw[ii];
            }
            for (uint32_t i = 0; i < n; i++) {
                if (insts[i].num_lookups == 0) continue;
                total_points += 2u;
                full_lanes += 2u * pmw[i];
            }
            tail_lanes = is_zk ? (size_t)total_points * nrc : 0;
            /* the preprocessed round carries no tail (split 0). */
            for (uint32_t m = 0; m < p->num_prep && is_zk; m++) {
                const uint32_t ii = p->prep_map[m];
                tail_lanes -= (insts[ii].prep_next ? 2u : 1u) * (size_t)nrc;
            }
            base_lanes = full_lanes - tail_lanes;
        }

        opened_full = (gold_fp2_t *)calloc(full_lanes ? full_lanes : 1,
                                           sizeof(gold_fp2_t));
        op_full_ptrs = (const gold_fp2_t **)calloc(
            total_points, sizeof(gold_fp2_t *));
        p->opened_arena = (gold_fp2_t *)calloc(base_lanes ? base_lanes : 1,
                                               sizeof(gold_fp2_t));
        fri_rounds = (dnac_prover_fri_input_round_t *)calloc(
            total_mats, sizeof(dnac_prover_fri_input_round_t));
        pts_store = (gold_fp2_t *)calloc(total_points, sizeof(gold_fp2_t));
        if (is_zk) {
            p->rand_arena = (gold_fp2_t *)calloc(
                tail_lanes ? tail_lanes : 1, sizeof(gold_fp2_t));
            p->rand_ptrs = (const gold_fp2_t **)calloc(
                total_points, sizeof(gold_fp2_t *));
            p->rand_lens =
                (uint32_t *)calloc(total_points, sizeof(uint32_t));
            if (!p->rand_arena || !p->rand_ptrs || !p->rand_lens) {
                goto cleanup;
            }
        }
        if (!opened_full || !op_full_ptrs || !p->opened_arena || !fri_rounds ||
            !pts_store) {
            goto cleanup;
        }

        t = dnac_transcript_init_from_duplex(&dx);
        if (!t) goto cleanup;

        size_t fo = 0;  /* opened_full cursor  */
        size_t bo = 0;  /* base arena cursor   */
        size_t to = 0;  /* tail arena cursor   */
        uint32_t pi = 0; /* point index         */
        uint32_t mi = 0; /* fri round entry idx */

        /* one (matrix, points...) unit: open FULL width at each point,
         * observe, split base/tail, register the FRI input entry. */
#define BP_OPEN_MAT(LDE, FULLW, BASEW, NPTS, PT0, PT1, SPLIT_TAIL,             \
                    BASE_DST0, BASE_DST1)                                      \
        do {                                                                   \
            const size_t fw_ = (FULLW);                                        \
            const size_t bw_ = (BASEW);                                        \
            const uint32_t np_ = (NPTS);                                       \
            fri_rounds[mi].lde_bitrev = (LDE);                                 \
            fri_rounds[mi].height = lde_h[ii_];                                \
            fri_rounds[mi].width = fw_;                                        \
            fri_rounds[mi].num_points = np_;                                   \
            fri_rounds[mi].points = &pts_store[pi];                            \
            fri_rounds[mi].opened = &op_full_ptrs[pi];                         \
            for (uint32_t pp_ = 0; pp_ < np_; pp_++) {                         \
                const gold_fp2_t z_ = pp_ == 0 ? (PT0) : (PT1);                \
                gold_fp2_t *dst_ = &opened_full[fo];                           \
                if (dnac_prover_open_matrix_at((LDE), lde_h[ii_], fw_, lb, z_, \
                                               dst_) != DNAC_PROVER_OK) {      \
                    goto cleanup;                                              \
                }                                                              \
                dnac_prover_observe_opened(t, dst_, fw_);                      \
                pts_store[pi] = z_;                                            \
                op_full_ptrs[pi] = dst_;                                       \
                gold_fp2_t *bdst_ = &p->opened_arena[bo];                      \
                memcpy(bdst_, dst_, bw_ * sizeof(gold_fp2_t));                 \
                if (pp_ == 0) { *(BASE_DST0) = bdst_; }                        \
                else { *(BASE_DST1) = bdst_; }                                 \
                bo += bw_;                                                     \
                if (is_zk) {                                                   \
                    const uint32_t tl_ = (SPLIT_TAIL) ? nrc : 0u;              \
                    if (tl_ > 0) {                                             \
                        memcpy(&p->rand_arena[to], dst_ + bw_,                 \
                               tl_ * sizeof(gold_fp2_t));                      \
                    }                                                          \
                    p->rand_ptrs[pi] = &p->rand_arena[to];                     \
                    p->rand_lens[pi] = tl_;                                    \
                    to += tl_;                                                 \
                }                                                              \
                fo += fw_;                                                     \
                pi++;                                                          \
            }                                                                  \
            mi++;                                                              \
        } while (0)

        const gold_fp2_t *dummy = NULL;
        (void)dummy;

        /* Round 0 (zk): random @ ζ (prover.rs:453-458). */
        if (is_zk) {
            for (uint32_t i = 0; i < n; i++) {
                const uint32_t ii_ = i;
                BP_OPEN_MAT(r_lde[i], (size_t)nrc + BP_DIM, BP_DIM, 1u,
                            p->zeta, p->zeta, 1,
                            &p->opened[i].random, &dummy);
                p->opened[i].random_len = BP_DIM;
            }
        }
        /* Round 1: main (prover.rs:460-477). */
        for (uint32_t i = 0; i < n; i++) {
            const uint32_t ii_ = i;
            const uint32_t np = insts[i].air.main_next ? 2u : 1u;
            BP_OPEN_MAT(main_lde[i], mw[i], w[i], np, p->zeta, zeta_nexts[i],
                        1, &p->opened[i].trace_local,
                        &p->opened[i].trace_next);
            p->opened[i].trace_local_len = (uint32_t)w[i];
            p->opened[i].trace_next_len =
                np == 2u ? (uint32_t)w[i] : 0u;
        }
        /* Round 2: quotient chunks @ ζ (prover.rs:479-485). */
        for (uint32_t i = 0; i < n; i++) {
            const uint32_t ii_ = i;
            const gold_fp2_t *qc_first = NULL;
            for (uint32_t c = 0; c < nqc[i]; c++) {
                const gold_fp2_t *slot = NULL;
                BP_OPEN_MAT(&chunk_ldes[i][(size_t)c * lde_h[i] * cw[i]],
                            cw[i], BP_DIM, 1u, p->zeta, p->zeta, 1, &slot,
                            &dummy);
                if (c == 0) qc_first = slot;
            }
            p->opened[i].quotient_chunks = qc_first;
            p->opened[i].num_quotient_chunks = nqc[i];
        }
        /* Round 3: preprocessed (prover.rs:487-510; split 0,
         * hiding_pcs.rs:343-348). */
        for (uint32_t m = 0; m < p->num_prep; m++) {
            const uint32_t ii_ = p->prep_map[m];
            const uint32_t np = insts[ii_].prep_next ? 2u : 1u;
            BP_OPEN_MAT(prep_lde[m], pw[ii_], pw[ii_], np, p->zeta,
                        zeta_nexts[ii_], 0,
                        &p->opened[ii_].preprocessed_local,
                        &p->opened[ii_].preprocessed_next);
            p->opened[ii_].preprocessed_local_len = pw[ii_];
            p->opened[ii_].preprocessed_next_len = np == 2u ? pw[ii_] : 0u;
        }
        /* Round 4: permutation @ ζ AND g·ζ (prover.rs:512-530). */
        {
            uint32_t j = 0;
            for (uint32_t i = 0; i < n; i++) {
                if (insts[i].num_lookups == 0) continue;
                const uint32_t ii_ = i;
                BP_OPEN_MAT(perm_lde[j], pmw[i], 2 * (size_t)aw[i], 2u,
                            p->zeta, zeta_nexts[i], 1,
                            &p->opened[i].permutation_local,
                            &p->opened[i].permutation_next);
                p->opened[i].permutation_len = 2u * aw[i];
                j++;
            }
        }
#undef BP_OPEN_MAT
        if (pi != total_points || mi != total_mats || fo != full_lanes ||
            bo != base_lanes || (is_zk && to != tail_lanes)) {
            goto cleanup;
        }
        if (is_zk) {
            p->rand_op.vals = p->rand_ptrs;
            p->rand_op.lens = p->rand_lens;
            p->rand_op.num_entries = total_points;
            p->has_rand_op = 1;
        }

        /* LookupTerminal publication (v0.6.2 BatchProof.lookup_terminals,
         * proof.rs:22). ONE optional value per AIR — present iff the AIR
         * declares any lookup (Option::Some/None; the verifier enforces the
         * same equivalence as TerminalPresenceMismatch).
         *
         * The v3-era arenas are GONE with the concept: there is no list of
         * (bus name, aux column, cumulative sum) records to publish, because
         * v0.6.2 removed bus names and aux columns from the proof entirely. */
        for (uint32_t i = 0; i < n; i++) {
            if (insts[i].num_lookups > 0) {
                p->opened[i].terminal = p->terminals[i];
                p->opened[i].has_terminal = 1;
            } else {
                p->opened[i].terminal = gold_fp2_zero();
                p->opened[i].has_terminal = 0;
            }
        }

        /* ── FRI batch challenge + per-height reduced openings + mixed
         *    commit phase (two_adic_pcs.rs:564-671) ── */
        const gold_fp2_t fri_alpha = dnac_transcript_sample_fp2(t);
        if (dnac_prover_fri_reduced_openings_mixed(
                fri_rounds, total_mats, fri_alpha, &romix) != DNAC_PROVER_OK) {
            goto cleanup;
        }
        have_romix = 1;
        const gold_fp2_t *fri_inputs[GOLDILOCKS_TWO_ADICITY + 1];
        size_t fri_lens[GOLDILOCKS_TWO_ADICITY + 1];
        size_t num_inputs = 0;
        for (int lh = GOLDILOCKS_TWO_ADICITY; lh >= 0; lh--) {
            if (romix.ro[lh] != NULL) { /* descending (:658 rev) */
                fri_inputs[num_inputs] = romix.ro[lh];
                fri_lens[num_inputs] = (size_t)1 << lh;
                num_inputs++;
            }
        }
        if (num_inputs == 0 || fri_lens[0] != ((size_t)1 << log_gmh)) {
            goto cleanup;
        }
        if (dnac_prover_fri_commit_phase_mixed(
                fri_inputs, fri_lens, num_inputs, lb,
                (unsigned)fri_params->log_final_poly_len,
                (unsigned)fri_params->max_log_arity,
                (unsigned)fri_params->commit_proof_of_work_bits,
                (unsigned)fri_params->query_proof_of_work_bits, fri_sd, SE, t,
                &fres) != DNAC_PROVER_OK) {
            goto cleanup;
        }
        have_fres = 1;
        p->num_fri_rounds = fres.num_rounds;
        p->final_poly_len = fres.final_poly_len;

        /* ── query phase (fri/prover.rs:100-131; open_input :357-387) ── */
        const size_t nq = p->num_queries;
        const size_t nr = fres.num_rounds;
        dnac_p2_mmcs_tree_t *round_trees[5];
        uint32_t round_nmats[5];
        {
            uint32_t r = 0;
            if (is_zk) { round_trees[r] = rand_tree; round_nmats[r++] = n; }
            round_trees[r] = main_tree; round_nmats[r++] = n;
            round_trees[r] = quot_tree; round_nmats[r++] = total_qc;
            if (p->num_prep > 0) {
                round_trees[r] = prep_tree;
                round_nmats[r++] = p->num_prep;
            }
            if (p->has_perm) {
                round_trees[r] = perm_tree;
                round_nmats[r++] = num_perm;
            }
            if (r != num_rounds) goto cleanup;
        }
        size_t rows_per_q = 0, mats_per_q = 0, sibs_per_q = 0,
               cp_depth_sum = 0;
        for (uint32_t r = 0; r < num_rounds; r++) {
            const dnac_p2_mmcs_tree_t *T = round_trees[r];
            const size_t nm = dnac_p2_mmcs_tree_num_matrices(T);
            if (nm != round_nmats[r]) goto cleanup;
            for (size_t m2 = 0; m2 < nm; m2++) {
                rows_per_q += dnac_p2_mmcs_tree_width(T, m2);
            }
            mats_per_q += nm;
            sibs_per_q += dnac_p2_mmcs_tree_depth(T);
        }
        for (size_t r = 0; r < nr; r++) {
            cp_depth_sum += bp_log2(fres.layer_heights[r]);
        }
        p->query_proofs = (dnac_fri_query_proof_t *)calloc(
            nq, sizeof(dnac_fri_query_proof_t));
        p->batches = (dnac_fri_batch_opening_t *)calloc(
            nq * num_rounds, sizeof(dnac_fri_batch_opening_t));
        p->in_rows =
            (gold_fp_t *)calloc(nq * rows_per_q, sizeof(gold_fp_t));
        p->in_rowptrs = (const gold_fp_t **)calloc(nq * mats_per_q,
                                                   sizeof(gold_fp_t *));
        p->in_lens = (size_t *)calloc(nq * mats_per_q, sizeof(size_t));
        p->in_sibs = (dnac_p2_digest_t *)calloc(nq * sibs_per_q,
                                                sizeof(dnac_p2_digest_t));
        p->cp_steps = (dnac_fri_commit_phase_proof_step_t *)calloc(
            nq * (nr ? nr : 1), sizeof(dnac_fri_commit_phase_proof_step_t));
        p->cp_step_sib =
            (gold_fp2_t *)calloc(nq * (nr ? nr : 1), sizeof(gold_fp2_t));
        p->cp_step_psib = (dnac_p2_digest_t *)calloc(
            nq * (cp_depth_sum ? cp_depth_sum : 1), sizeof(dnac_p2_digest_t));
        p->cp_commits = (dnac_p2_digest_t *)calloc(nr ? nr : 1,
                                                   sizeof(dnac_p2_digest_t));
        p->cp_pow = (gold_fp_t *)calloc(nr ? nr : 1, sizeof(gold_fp_t));
        p->final_poly = (gold_fp2_t *)calloc(fres.final_poly_len,
                                             sizeof(gold_fp2_t));
        if (!p->query_proofs || !p->batches || !p->in_rows || !p->in_rowptrs ||
            !p->in_lens || !p->in_sibs || !p->cp_steps || !p->cp_step_sib ||
            !p->cp_step_psib || !p->cp_commits || !p->cp_pow ||
            !p->final_poly) {
            goto cleanup;
        }
        if (SE > 0) {
            p->salt_elems = SE;
            p->in_salts = (gold_fp_t *)calloc(nq * mats_per_q * SE,
                                              sizeof(gold_fp_t));
            p->in_saltptrs = (const gold_fp_t **)calloc(
                nq * mats_per_q, sizeof(gold_fp_t *));
            p->cp_salts = (gold_fp_t *)calloc(nq * (nr ? nr : 1) * SE,
                                              sizeof(gold_fp_t));
            if (!p->in_salts || !p->in_saltptrs || !p->cp_salts) {
                goto cleanup;
            }
        }
        for (size_t r = 0; r < nr; r++) {
            p->cp_commits[r] = fres.roots[r];
            p->cp_pow[r] = fres.commit_pow_witnesses[r];
        }
        memcpy(p->final_poly, fres.final_poly,
               fres.final_poly_len * sizeof(gold_fp2_t));

        for (size_t q = 0; q < nq; q++) {
            const uint64_t index =
                dnac_transcript_sample_bits(t, log_gmh);
            p->query_indices[q] = index;
            dnac_fri_batch_opening_t *B = &p->batches[q * num_rounds];
            size_t row_off = q * rows_per_q;
            size_t mat_off = q * mats_per_q;
            size_t sib_off = q * sibs_per_q;
            for (uint32_t r = 0; r < num_rounds; r++) {
                const dnac_p2_mmcs_tree_t *T = round_trees[r];
                const size_t nm = round_nmats[r];
                const size_t depth = dnac_p2_mmcs_tree_depth(T);
                const uint64_t ridx =
                    index >> (log_gmh - depth); /* open_input :379-383 */
                const uint64_t *rows[BP_MAX_INSTANCES * 8];
                dnac_p2_proof_t pr;
                memset(&pr, 0, sizeof(pr));
                pr.siblings = &p->in_sibs[sib_off];
                pr.depth = (uint32_t)depth;
                if (dnac_p2_mmcs_open_mixed(T, ridx, rows, &pr) !=
                    DNAC_P2M_OK) {
                    goto cleanup;
                }
                B[r].opened_values = &p->in_rowptrs[mat_off];
                B[r].opened_values_lens = &p->in_lens[mat_off];
                B[r].num_matrices = nm;
                B[r].opening_proof.leaf_index = 0;
                B[r].opening_proof.depth = (uint32_t)depth;
                B[r].opening_proof.num_matrices = nm;
                B[r].opening_proof.siblings = &p->in_sibs[sib_off];
                if (SE > 0) {
                    B[r].salts = &p->in_saltptrs[mat_off];
                    B[r].salt_elems = SE;
                }
                for (size_t m2 = 0; m2 < nm; m2++) {
                    const size_t rw2 = dnac_p2_mmcs_tree_width(T, m2);
                    /* d4.c salted trees store row ‖ SE salts — split: the
                     * batch opening carries the BASE row; salts go to the
                     * salts field (fri_open_input re-appends them before the
                     * MMCS check). */
                    if (SE > 0 && rw2 < SE) goto cleanup;
                    const size_t bw2 = rw2 - SE;
                    for (size_t k = 0; k < bw2; k++) {
                        p->in_rows[row_off + k] =
                            gold_fp_from_u64(rows[m2][k]);
                    }
                    if (SE > 0) {
                        gold_fp_t *sdst =
                            &p->in_salts[(size_t)mat_off * SE];
                        for (size_t s = 0; s < SE; s++) {
                            sdst[s] = gold_fp_from_u64(rows[m2][bw2 + s]);
                        }
                        p->in_saltptrs[mat_off] = sdst;
                    }
                    p->in_rowptrs[mat_off] = &p->in_rows[row_off];
                    p->in_lens[mat_off] = bw2;
                    row_off += rw2;
                    mat_off++;
                }
                sib_off += depth;
            }
            /* commit-phase openings (answer_query, fri/prover.rs:286-343). */
            uint64_t cq = index;
            size_t psib_off = q * cp_depth_sum;
            size_t cp_salt_off = 0; /* stream-B cumulative offset (layer-major,
                                     * the v3 mirror — MUST read the SAME
                                     * buffer the commit phase consumed) */
            for (size_t r = 0; r < nr; r++) {
                const unsigned a = fres.layer_log_arities[r];
                if (a != 1) goto cleanup; /* arity-2-only sibling math */
                const size_t arity = (size_t)1 << a;
                const uint64_t iig = cq & (arity - 1);
                const uint64_t gid = cq >> a;
                const size_t depth = bp_log2(fres.layer_heights[r]);
                dnac_fri_commit_phase_proof_step_t *S =
                    &p->cp_steps[q * nr + r];
                p->cp_step_sib[q * nr + r] =
                    fres.layer_leaves[r][gid * arity + (1 - iig)];
                dnac_p2_proof_t pr;
                const uint64_t *orow[1] = { NULL };
                memset(&pr, 0, sizeof(pr));
                pr.siblings = &p->cp_step_psib[psib_off];
                pr.depth = (uint32_t)depth;
                if (dnac_p2_mmcs_open_batch(fres.layer_trees[r], gid, orow,
                                            &pr) != DNAC_P2M_OK) {
                    goto cleanup;
                }
                S->log_arity = (uint8_t)a;
                S->sibling_values = &p->cp_step_sib[q * nr + r];
                S->num_sibling_values = arity - 1;
                S->opening_proof.leaf_index = 0;
                S->opening_proof.depth = (uint32_t)depth;
                S->opening_proof.num_matrices = 1;
                S->opening_proof.siblings = &p->cp_step_psib[psib_off];
                if (SE > 0) {
                    /* stream B: layer r's salt for folded row gid at
                     * fri_sd[cp_salt_off + gid·SE] (v3 mirror,
                     * stark_prover_agg.c:1028-1040). */
                    const size_t soff = cp_salt_off + (size_t)gid * SE;
                    gold_fp_t *sdst = &p->cp_salts[(q * nr + r) * SE];
                    for (size_t s = 0; s < SE; s++) {
                        sdst[s] = gold_fp_from_u64(fri_sd[soff + s]);
                    }
                    S->salts = sdst;
                    S->salt_elems = SE;
                }
                cp_salt_off += fres.layer_heights[r] * SE;
                psib_off += depth;
                cq = gid;
            }
            p->query_proofs[q].input_proof = B;
            p->query_proofs[q].num_input_batches = num_rounds;
            p->query_proofs[q].commit_phase_openings = &p->cp_steps[q * nr];
            p->query_proofs[q].num_commit_phase_openings = nr;
        }

        /* ── assemble the FRI proof ── */
        memset(&p->proof, 0, sizeof(p->proof));
        p->proof.commit_phase_commits = p->cp_commits;
        p->proof.num_commit_phase_commits = nr;
        p->proof.commit_pow_witnesses = p->cp_pow;
        p->proof.num_commit_pow_witnesses = nr;
        p->proof.query_proofs = p->query_proofs;
        p->proof.num_query_proofs = nq;
        p->proof.final_poly = p->final_poly;
        p->proof.num_final_poly = fres.final_poly_len;
        p->proof.query_pow_witness = fres.query_pow_witness;
    }

    /* ── SELF-VERIFY (fail-close): the assembled proof must pass the d2
     *    verifier end-to-end (skipped ONLY by the test-wire forge, whose proof
     *    is intentionally constraint-inconsistent at the TRUE publics) ── */
    int bp_do_selfverify = 1;
#ifdef DNAC_ZK_ENABLE_TEST_WIRE
    if (g_bp_skip_selfverify) bp_do_selfverify = 0;
#endif
    if (bp_do_selfverify) {
        dnac_batch_vcommits_t commits;
        dnac_batch_proof_commits(p, &commits);
        dnac_batch_verify_out_t vo;
        memset(&vo, 0, sizeof(vo));
        /* Self-verify states the counts this prover just emitted — that is the
         * point: if the two sides ever drift, the prover fails on its own
         * output instead of shipping a proof only a laxer verifier accepts. */
        if (dnac_batch_verify(insts, p->opened, n, is_zk, &commits,
                              p->num_prep ? p->prep_map : NULL, p->num_prep,
                              &p->params, nrc, salt_elems,
                              &p->proof,
                              p->has_rand_op ? &p->rand_op : NULL,
                              &vo) != DNAC_BV_OK) {
            rc = DNAC_PROVER_ERR_VERIFY;
            goto cleanup;
        }
        /* cross-check the verifier's (α,ζ) against the prover's own. */
        if (gold_fp_to_u64(vo.alpha.a) != gold_fp_to_u64(p->alpha.a) ||
            gold_fp_to_u64(vo.alpha.b) != gold_fp_to_u64(p->alpha.b) ||
            gold_fp_to_u64(vo.zeta.a) != gold_fp_to_u64(p->zeta.a) ||
            gold_fp_to_u64(vo.zeta.b) != gold_fp_to_u64(p->zeta.b)) {
            rc = DNAC_PROVER_ERR_VERIFY;
            goto cleanup;
        }
    }

    rc = DNAC_PROVER_OK;
    *out_proof = p;
    p = NULL; /* ownership transferred */

cleanup:
    for (uint32_t i = 0; i < BP_MAX_INSTANCES; i++) {
        free(rand_mat[i]); free(main_lde[i]); free(prep_pad[i]);
        free(prep_lde[i]); free(perm_flat[i]); free(perm_lde[i]);
        free(chunk_ldes[i]); free(r_mat[i]); free(r_lde[i]);
        free(ctx_main[i]); free(ctx_prep[i]); free(aux_ef[i]);
        free(salted_main[i]); free(salted_rand[i]);
    }
    for (uint32_t i = 0; i < BP_MAX_INSTANCES * 8u; i++) {
        free(salted_quot[i]);
    }
    free(sf); free(sl); free(st); free(ivv); free(trace_q); free(prep_q);
    free(perm_q); free(qflat);
    free(ch_flat);
    free(opened_full);
    free(op_full_ptrs);
    free(fri_rounds);
    free(pts_store);
    if (s7_tree) dnac_p2_mmcs_tree_free(s7_tree);
    if (main_tree) dnac_p2_mmcs_tree_free(main_tree);
    if (prep_tree) dnac_p2_mmcs_tree_free(prep_tree);
    if (perm_tree) dnac_p2_mmcs_tree_free(perm_tree);
    if (quot_tree) dnac_p2_mmcs_tree_free(quot_tree);
    if (rand_tree) dnac_p2_mmcs_tree_free(rand_tree);
    if (have_romix) dnac_prover_fri_ro_mixed_free(&romix);
    if (have_fres) dnac_prover_fri_result_free(&fres);
    if (t) dnac_transcript_free(t);
    if (p) dnac_batch_proof_free(p);
    return rc;
}

#ifdef DNAC_ZK_ENABLE_TEST_WIRE
/* C2.1 CRIT-1 isolating forge (test-wire only). Same as dnac_batch_prove but
 * instance-0's FS/priming publics are `fs_pub_override` (num_publics wide) while
 * the quotient folds the TRUE insts[0].public_values; self-verify skipped. The
 * produced proof passes FRI but FAILS the N-chunk constraint check at the true
 * publics — the vector that proves the constraint step is load-bearing. */
dnac_prover_status_t dnac_batch_prove_forged_fs_testonly(
    const dnac_batch_vinstance_t *insts,
    const dnac_batch_pwitness_t  *wits,
    uint32_t                      n,
    int                           is_zk,
    const dnac_fri_params_t      *fri_params,
    uint32_t                      nrc,
    const uint64_t               *draws,
    size_t                        num_draws,
    const uint64_t               *salt_draws,
    size_t                        num_salt_draws,
    const uint64_t               *fri_salt_draws,
    size_t                        num_fri_salt_draws,
    size_t                        salt_elems,
    const gold_fp_t              *fs_pub_override,
    dnac_batch_proof_t          **out_proof)
{
    g_bp_fs_pub_override = fs_pub_override;
    g_bp_skip_selfverify = 1;
    dnac_prover_status_t rc = dnac_batch_prove(
        insts, wits, n, is_zk, fri_params, nrc, draws, num_draws, salt_draws,
        num_salt_draws, fri_salt_draws, num_fri_salt_draws, salt_elems,
        out_proof);
    g_bp_fs_pub_override = NULL;
    g_bp_skip_selfverify = 0;
    return rc;
}
#endif /* DNAC_ZK_ENABLE_TEST_WIRE */
