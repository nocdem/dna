/**
 * @file logup.c
 * @brief LogUp lookup-argument gadget — port of Plonky3 p3-lookup LogUpGadget.
 *
 * Plonky3 commit pin: 82cfad73cd734d37a0d51953094f970c531817ec.
 * See logup.h for the scope, determinism and convention pins (P2L-a).
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdlib.h>
#include <string.h>

#include "logup.h"

/* ============================================================================
 * Pool validation + evaluation
 * ========================================================================== */

int dnac_logup_pool_validate(const dnac_logup_ctx_t *ctx)
{
    if (!ctx || !ctx->main || (!ctx->pool && ctx->pool_len > 0)) {
        return DNAC_LOGUP_ERR_NULL;
    }
    if (ctx->height == 0 || ctx->main_width == 0) {
        return DNAC_LOGUP_ERR_PARAM;
    }
    for (uint32_t i = 0; i < ctx->pool_len; i++) {
        const dnac_logup_expr_t *e = &ctx->pool[i];
        switch (e->kind) {
        case DNAC_LOGUP_EXPR_CONST:
            break;
        case DNAC_LOGUP_EXPR_MAIN:
            if (e->next > 1 || e->index >= ctx->main_width) {
                return DNAC_LOGUP_ERR_EXPR;
            }
            break;
        case DNAC_LOGUP_EXPR_PREP:
            if (!ctx->prep || e->next > 1 || e->index >= ctx->prep_width) {
                return DNAC_LOGUP_ERR_EXPR;
            }
            break;
        case DNAC_LOGUP_EXPR_PUBLIC:
            if (!ctx->publics || e->index >= ctx->num_publics) {
                return DNAC_LOGUP_ERR_EXPR;
            }
            break;
        case DNAC_LOGUP_EXPR_ADD:
        case DNAC_LOGUP_EXPR_SUB:
        case DNAC_LOGUP_EXPR_MUL:
            /* Topological order: children strictly precede their parent. */
            if (e->x < 0 || (uint32_t)e->x >= i || e->y < 0 ||
                (uint32_t)e->y >= i) {
                return DNAC_LOGUP_ERR_EXPR;
            }
            break;
        case DNAC_LOGUP_EXPR_NEG:
            if (e->x < 0 || (uint32_t)e->x >= i) {
                return DNAC_LOGUP_ERR_EXPR;
            }
            break;
        default:
            return DNAC_LOGUP_ERR_EXPR;
        }
    }
    return DNAC_LOGUP_OK;
}

/* Evaluate the WHOLE pool at `row` into vals[pool_len] (base field).
 * Next-row references WRAP: (row + 1) % height (logup.rs:474 convention;
 * pinned in logup.h). Pool must already be validated. */
static void logup_pool_eval_row(const dnac_logup_ctx_t *ctx, uint32_t row,
                                gold_fp_t *vals)
{
    const uint32_t next_row = (row + 1u) % ctx->height;
    for (uint32_t i = 0; i < ctx->pool_len; i++) {
        const dnac_logup_expr_t *e = &ctx->pool[i];
        switch (e->kind) {
        case DNAC_LOGUP_EXPR_CONST:
            vals[i] = e->cval;
            break;
        case DNAC_LOGUP_EXPR_MAIN: {
            uint32_t r = e->next ? next_row : row;
            vals[i] = ctx->main[(size_t)r * ctx->main_width + e->index];
            break;
        }
        case DNAC_LOGUP_EXPR_PREP: {
            uint32_t r = e->next ? next_row : row;
            vals[i] = ctx->prep[(size_t)r * ctx->prep_width + e->index];
            break;
        }
        case DNAC_LOGUP_EXPR_PUBLIC:
            vals[i] = ctx->publics[e->index];
            break;
        case DNAC_LOGUP_EXPR_ADD:
            vals[i] = gold_fp_add(vals[e->x], vals[e->y]);
            break;
        case DNAC_LOGUP_EXPR_SUB:
            vals[i] = gold_fp_sub(vals[e->x], vals[e->y]);
            break;
        case DNAC_LOGUP_EXPR_MUL:
            vals[i] = gold_fp_mul(vals[e->x], vals[e->y]);
            break;
        case DNAC_LOGUP_EXPR_NEG:
        default:
            vals[i] = gold_fp_neg(vals[e->x]);
            break;
        }
    }
}

int dnac_logup_expr_degree(const dnac_logup_ctx_t *ctx, int32_t idx,
                           uint32_t *out_degree)
{
    if (!out_degree) {
        return DNAC_LOGUP_ERR_NULL;
    }
    int rc = dnac_logup_pool_validate(ctx);
    if (rc != DNAC_LOGUP_OK) {
        return rc;
    }
    if (idx < 0 || (uint32_t)idx >= ctx->pool_len) {
        return DNAC_LOGUP_ERR_EXPR;
    }
    uint32_t *deg = (uint32_t *)malloc(sizeof(uint32_t) * ctx->pool_len);
    if (!deg) {
        return DNAC_LOGUP_ERR_OOM;
    }
    /* Degree rules: air/src/symbolic/expression.rs:43-49 (const 0, main/prep
     * var 1, public 0 via variable.rs:37-47), mod.rs:124 (add/sub = max),
     * mod.rs:159 (neg = same), mod.rs:183 (mul = sum). */
    for (uint32_t i = 0; i < ctx->pool_len; i++) {
        const dnac_logup_expr_t *e = &ctx->pool[i];
        switch (e->kind) {
        case DNAC_LOGUP_EXPR_CONST:
        case DNAC_LOGUP_EXPR_PUBLIC:
            deg[i] = 0;
            break;
        case DNAC_LOGUP_EXPR_MAIN:
        case DNAC_LOGUP_EXPR_PREP:
            deg[i] = 1;
            break;
        case DNAC_LOGUP_EXPR_ADD:
        case DNAC_LOGUP_EXPR_SUB:
            deg[i] = deg[e->x] > deg[e->y] ? deg[e->x] : deg[e->y];
            break;
        case DNAC_LOGUP_EXPR_MUL:
            deg[i] = deg[e->x] + deg[e->y];
            break;
        case DNAC_LOGUP_EXPR_NEG:
        default:
            deg[i] = deg[e->x];
            break;
        }
    }
    *out_degree = deg[idx];
    free(deg);
    return DNAC_LOGUP_OK;
}

/* ============================================================================
 * β-combine (logup.rs:88-93 / 513-523 Horner) — element VALUES already in fp2
 * ========================================================================== */
static gold_fp2_t logup_combine(const gold_fp2_t *elems, uint32_t w,
                                gold_fp2_t beta)
{
    /* acc = 0; acc = acc·β + e_j  =>  e_0·β^{w-1} + … + e_{w-1}.
     * Empty tuple => 0 (logup.rs:518 map_or ZERO). */
    gold_fp2_t acc = gold_fp2_zero();
    for (uint32_t j = 0; j < w; j++) {
        acc = gold_fp2_add(gold_fp2_mul(acc, beta), elems[j]);
    }
    return acc;
}

/* ============================================================================
 * Sum terms — logup.rs:101-146
 * ========================================================================== */
int dnac_logup_sum_terms_fp2(
    const gold_fp2_t *const *elements,
    const uint32_t          *widths,
    const gold_fp2_t        *mults,
    uint32_t                 n,
    gold_fp2_t               alpha,
    gold_fp2_t               beta,
    gold_fp2_t              *numerator,
    gold_fp2_t              *denominator)
{
    if (!numerator || !denominator || (n > 0 && (!elements || !widths || !mults))) {
        return DNAC_LOGUP_ERR_NULL;
    }
    if (n == 0) {
        /* logup.rs:113-114 */
        *numerator = gold_fp2_zero();
        *denominator = gold_fp2_one();
        return DNAC_LOGUP_OK;
    }

    gold_fp2_t *terms = (gold_fp2_t *)malloc(sizeof(gold_fp2_t) * n);
    gold_fp2_t *pref = (gold_fp2_t *)malloc(sizeof(gold_fp2_t) * (n + 1));
    gold_fp2_t *suff = (gold_fp2_t *)malloc(sizeof(gold_fp2_t) * (n + 1));
    if (!terms || !pref || !suff) {
        free(terms);
        free(pref);
        free(suff);
        return DNAC_LOGUP_ERR_OOM;
    }

    /* terms_i = α − combined_i (logup.rs:92-93, 119-120) */
    for (uint32_t i = 0; i < n; i++) {
        terms[i] = gold_fp2_sub(alpha, logup_combine(elements[i], widths[i], beta));
    }

    /* pref[i] = Π_{j<i} terms_j (logup.rs:122-127) */
    pref[0] = gold_fp2_one();
    for (uint32_t i = 0; i < n; i++) {
        pref[i + 1] = gold_fp2_mul(pref[i], terms[i]);
    }
    /* suff[i] = Π_{j>=i} terms_j (logup.rs:129-133) */
    suff[n] = gold_fp2_one();
    for (uint32_t i = n; i-- > 0;) {
        suff[i] = gold_fp2_mul(suff[i + 1], terms[i]);
    }

    /* denominator = pref[n]; numerator = Σ m_i·pref[i]·suff[i+1]
     * (logup.rs:135-145) */
    *denominator = pref[n];
    gold_fp2_t num = gold_fp2_zero();
    for (uint32_t i = 0; i < n; i++) {
        num = gold_fp2_add(
            num, gold_fp2_mul(mults[i], gold_fp2_mul(pref[i], suff[i + 1])));
    }
    *numerator = num;

    free(terms);
    free(pref);
    free(suff);
    return DNAC_LOGUP_OK;
}

/* ============================================================================
 * Shared lookup checks
 * ========================================================================== */
static int logup_lookup_validate(const dnac_logup_ctx_t *ctx,
                                 const dnac_logup_lookup_t *l)
{
    if (!l || (l->num_tuples > 0 &&
               (!l->tuple_widths || !l->tuple_elems || !l->multiplicities))) {
        return DNAC_LOGUP_ERR_NULL;
    }
    for (uint32_t t = 0; t < l->num_tuples; t++) {
        if (l->multiplicities[t] < 0 ||
            (uint32_t)l->multiplicities[t] >= ctx->pool_len) {
            return DNAC_LOGUP_ERR_EXPR;
        }
        if (l->tuple_widths[t] > 0 && !l->tuple_elems[t]) {
            return DNAC_LOGUP_ERR_NULL;
        }
        for (uint32_t j = 0; j < l->tuple_widths[t]; j++) {
            int32_t e = l->tuple_elems[t][j];
            if (e < 0 || (uint32_t)e >= ctx->pool_len) {
                return DNAC_LOGUP_ERR_EXPR;
            }
        }
    }
    return DNAC_LOGUP_OK;
}

/* Row contribution of one lookup: Σ_t m_t / (α − combined_t) with ONE
 * inversion per term (the reference batch-inverts, but inverses are unique
 * field values — output-identical, G-DET-L1). Element/multiplicity values
 * are read from the base-field pool evaluation `vals` (logup.rs:512-529:
 * elements resolve to Val, multiplicities stay base and scale the inverse). */
static int logup_row_contribution(const dnac_logup_ctx_t *ctx,
                                  const dnac_logup_lookup_t *l,
                                  const gold_fp_t *vals, gold_fp2_t alpha,
                                  gold_fp2_t beta, gold_fp2_t *out)
{
    gold_fp2_t acc = gold_fp2_zero();
    for (uint32_t t = 0; t < l->num_tuples; t++) {
        /* combined via Horner over base values lifted to fp2 (logup.rs:513-523) */
        gold_fp2_t comb = gold_fp2_zero();
        for (uint32_t j = 0; j < l->tuple_widths[t]; j++) {
            comb = gold_fp2_add(gold_fp2_mul(comb, beta),
                                gold_fp2_from_base(vals[l->tuple_elems[t][j]]));
        }
        gold_fp2_t denom = gold_fp2_sub(alpha, comb);
        if (gold_fp2_eq(denom, gold_fp2_zero())) {
            /* Mirror of the Plonky3 batch-inversion panic on zero input
             * (field/src/batch_inverse.rs:26) — fail-close. */
            return DNAC_LOGUP_ERR_ZERO_DENOM;
        }
        gold_fp2_t inv = gold_fp2_inv(denom);
        gold_fp2_t m = gold_fp2_from_base(vals[l->multiplicities[t]]);
        acc = gold_fp2_add(acc, gold_fp2_mul(inv, m));
    }
    *out = acc;
    return DNAC_LOGUP_OK;
}

/* ============================================================================
 * Aux-trace generation — logup.rs:370-646 (serial, output-invariant)
 * ========================================================================== */
int dnac_logup_generate_permutation(
    const dnac_logup_ctx_t    *ctx,
    const dnac_logup_lookup_t *lookups,
    uint32_t                   num_lookups,
    const gold_fp2_t          *challenges,
    uint32_t                   num_challenges,
    gold_fp2_t                *aux_out,
    gold_fp2_t                *cumulative_sums,
    uint32_t                   num_globals)
{
    int rc = dnac_logup_pool_validate(ctx);
    if (rc != DNAC_LOGUP_OK) {
        return rc;
    }
    if (num_lookups > 0 && (!lookups || !aux_out)) {
        return DNAC_LOGUP_ERR_NULL;
    }
    /* logup.rs:383-387 — challenge count must be per-lookup (2 each). */
    if (num_challenges != 2u * num_lookups ||
        (num_challenges > 0 && !challenges)) {
        return DNAC_LOGUP_ERR_PARAM;
    }
    /* logup.rs:390-401 — aux column indices unique (and in range: the aux
     * matrix has num_lookups columns, logup.rs:380). Always-on fail-close
     * (the reference guards this with debug assertions only). */
    uint32_t global_count = 0;
    for (uint32_t i = 0; i < num_lookups; i++) {
        if (lookups[i].column >= num_lookups) {
            return DNAC_LOGUP_ERR_PARAM;
        }
        for (uint32_t j = 0; j < i; j++) {
            if (lookups[j].column == lookups[i].column) {
                return DNAC_LOGUP_ERR_PARAM;
            }
        }
        rc = logup_lookup_validate(ctx, &lookups[i]);
        if (rc != DNAC_LOGUP_OK) {
            return rc;
        }
        if (lookups[i].is_global) {
            global_count++;
        }
    }
    /* logup.rs:644 debug_assert — lookup_data entries == global lookups. */
    if (global_count != num_globals ||
        (num_globals > 0 && !cumulative_sums)) {
        return DNAC_LOGUP_ERR_PARAM;
    }
    if (num_lookups == 0) {
        return DNAC_LOGUP_OK;
    }

    const uint32_t height = ctx->height;
    gold_fp_t *vals = (gold_fp_t *)malloc(sizeof(gold_fp_t) * (ctx->pool_len ? ctx->pool_len : 1));
    gold_fp2_t *row_sums =
        (gold_fp2_t *)malloc(sizeof(gold_fp2_t) * (size_t)height * num_lookups);
    if (!vals || !row_sums) {
        free(vals);
        free(row_sums);
        return DNAC_LOGUP_ERR_OOM;
    }

    /* Phase 1+2+3 fused, serial (logup.rs:449-558): per (row, lookup)
     * contribution Σ_t m_t/(α − combined_t). */
    for (uint32_t r = 0; r < height; r++) {
        logup_pool_eval_row(ctx, r, vals);
        for (uint32_t i = 0; i < num_lookups; i++) {
            /* α, β indexed by the lookup's aux column (logup.rs:421-425). */
            gold_fp2_t alpha = challenges[2u * lookups[i].column];
            gold_fp2_t beta = challenges[2u * lookups[i].column + 1u];
            rc = logup_row_contribution(ctx, &lookups[i], vals, alpha, beta,
                                        &row_sums[(size_t)r * num_lookups + i]);
            if (rc != DNAC_LOGUP_OK) {
                free(vals);
                free(row_sums);
                return rc;
            }
        }
    }

    /* Exclusive running sum per lookup column (logup.rs:560-634):
     * s[0] = 0, s[r] = Σ_{j<r} contribution[j]. Cumulative sum (global
     * lookups, lookup order) = inclusive total (logup.rs:636-640). */
    uint32_t perm_counter = 0;
    for (uint32_t i = 0; i < num_lookups; i++) {
        const uint32_t col = lookups[i].column;
        gold_fp2_t run = gold_fp2_zero();
        for (uint32_t r = 0; r < height; r++) {
            aux_out[(size_t)r * num_lookups + col] = run;
            run = gold_fp2_add(run, row_sums[(size_t)r * num_lookups + i]);
        }
        if (lookups[i].is_global) {
            cumulative_sums[perm_counter++] = run;
        }
    }

    free(vals);
    free(row_sums);
    return DNAC_LOGUP_OK;
}

/* ============================================================================
 * Constraint residuals — logup.rs:158-265 (concrete, selector-multiplied)
 * ========================================================================== */
int dnac_logup_eval_row(
    const dnac_logup_ctx_t    *ctx,
    const dnac_logup_lookup_t *lookup,
    const gold_fp2_t          *aux,
    uint32_t                   aux_width,
    const gold_fp2_t          *challenges,
    uint32_t                   num_challenges,
    uint32_t                   row,
    const gold_fp2_t          *cumulative_sum,
    gold_fp2_t                 residuals[3],
    uint32_t                  *num_residuals)
{
    if (!aux || !challenges || !residuals || !num_residuals) {
        return DNAC_LOGUP_ERR_NULL;
    }
    int rc = dnac_logup_pool_validate(ctx);
    if (rc != DNAC_LOGUP_OK) {
        return rc;
    }
    rc = logup_lookup_validate(ctx, lookup);
    if (rc != DNAC_LOGUP_OK) {
        return rc;
    }
    if (row >= ctx->height || lookup->column >= aux_width) {
        return DNAC_LOGUP_ERR_PARAM;
    }
    /* logup.rs:201-203 — challenge array must cover this lookup's pair. */
    if (num_challenges < 2u * (lookup->column + 1u)) {
        return DNAC_LOGUP_ERR_PARAM;
    }
    /* logup.rs:239-241 / 254-256 — kind must match cumulative_sum presence. */
    if ((cumulative_sum != NULL) != (lookup->is_global != 0)) {
        return DNAC_LOGUP_ERR_PARAM;
    }

    const gold_fp2_t alpha = challenges[2u * lookup->column];
    const gold_fp2_t beta = challenges[2u * lookup->column + 1u];

    /* s_local / s_next with the WRAP next-row convention (logup.h pin). */
    const uint32_t next_row = (row + 1u) % ctx->height;
    const gold_fp2_t s_local = aux[(size_t)row * aux_width + lookup->column];
    const gold_fp2_t s_next = aux[(size_t)next_row * aux_width + lookup->column];

    /* Row selectors as base-field 0/1 (tests.rs:188-199 concrete builder);
     * the filtered builder multiplies residual · condition
     * (air/src/filtered.rs:78-86). */
    const gold_fp2_t sel_first =
        gold_fp2_from_base(row == 0 ? gold_fp_one() : gold_fp_zero());
    const gold_fp2_t sel_last = gold_fp2_from_base(
        row + 1u == ctx->height ? gold_fp_one() : gold_fp_zero());
    const gold_fp2_t sel_trans = gold_fp2_from_base(
        row + 1u < ctx->height ? gold_fp_one() : gold_fp_zero());

    /* Resolve elements + multiplicities at this row (base → fp2;
     * logup.rs:180-194). */
    gold_fp_t *vals =
        (gold_fp_t *)malloc(sizeof(gold_fp_t) * (ctx->pool_len ? ctx->pool_len : 1));
    if (!vals) {
        return DNAC_LOGUP_ERR_OOM;
    }
    logup_pool_eval_row(ctx, row, vals);

    const uint32_t n = lookup->num_tuples;
    gold_fp2_t num, den;
    {
        /* Assemble the concrete element/mult value arrays for sum_terms. */
        uint32_t total = 0;
        for (uint32_t t = 0; t < n; t++) {
            total += lookup->tuple_widths[t];
        }
        gold_fp2_t *flat =
            (gold_fp2_t *)malloc(sizeof(gold_fp2_t) * (total ? total : 1));
        const gold_fp2_t **ptrs =
            (const gold_fp2_t **)malloc(sizeof(gold_fp2_t *) * (n ? n : 1));
        gold_fp2_t *mults =
            (gold_fp2_t *)malloc(sizeof(gold_fp2_t) * (n ? n : 1));
        if (!flat || !ptrs || !mults) {
            free(flat);
            free((void *)ptrs);
            free(mults);
            free(vals);
            return DNAC_LOGUP_ERR_OOM;
        }
        uint32_t off = 0;
        for (uint32_t t = 0; t < n; t++) {
            ptrs[t] = &flat[off];
            for (uint32_t j = 0; j < lookup->tuple_widths[t]; j++) {
                flat[off++] = gold_fp2_from_base(vals[lookup->tuple_elems[t][j]]);
            }
            mults[t] = gold_fp2_from_base(vals[lookup->multiplicities[t]]);
        }
        rc = dnac_logup_sum_terms_fp2(ptrs, lookup->tuple_widths, mults, n,
                                      alpha, beta, &num, &den);
        free(flat);
        free((void *)ptrs);
        free(mults);
    }
    free(vals);
    if (rc != DNAC_LOGUP_OK) {
        return rc;
    }

    /* residual[0]: when_first_row().assert_zero_ext(s_local) (logup.rs:226). */
    residuals[0] = gold_fp2_mul(s_local, sel_first);

    /* (s_next − s_local)·D − N */
    gold_fp2_t trans =
        gold_fp2_sub(gold_fp2_mul(gold_fp2_sub(s_next, s_local), den), num);

    if (cumulative_sum) {
        /* Global (logup.rs:237-251): transition-gated + last-row final. */
        residuals[1] = gold_fp2_mul(trans, sel_trans);
        gold_fp2_t fin = gold_fp2_sub(
            gold_fp2_mul(gold_fp2_sub(*cumulative_sum, s_local), den), num);
        residuals[2] = gold_fp2_mul(fin, sel_last);
        *num_residuals = 3;
    } else {
        /* Local (logup.rs:252-264): full-domain (wrap covers the last row). */
        residuals[1] = trans;
        *num_residuals = 2;
    }
    return DNAC_LOGUP_OK;
}

/* ============================================================================
 * Global-sum check — logup.rs:314-324 (FLAT sum; per-bus grouping is the
 * caller's job — see logup.h warning / G-DET-L4)
 * ========================================================================== */
int dnac_logup_eval_pool_window(
    const dnac_logup_expr_t *pool, uint32_t pool_len,
    const gold_fp2_t *main_local, const gold_fp2_t *main_next,
    uint32_t          main_width,
    const gold_fp2_t *prep_local, const gold_fp2_t *prep_next,
    uint32_t          prep_width,
    const gold_fp_t  *publics, uint32_t num_publics,
    gold_fp2_t       *vals)
{
    if ((!pool && pool_len > 0) || !vals) return DNAC_LOGUP_ERR_NULL;
    if (pool_len > 0 && (!main_local || main_width == 0)) {
        return DNAC_LOGUP_ERR_NULL;
    }
    for (uint32_t i = 0; i < pool_len; i++) {
        const dnac_logup_expr_t *e = &pool[i];
        switch (e->kind) {
        case DNAC_LOGUP_EXPR_CONST:
            vals[i] = gold_fp2_from_base(e->cval);
            break;
        case DNAC_LOGUP_EXPR_MAIN:
            if (e->next > 1 || e->index >= main_width ||
                (e->next && !main_next)) {
                return DNAC_LOGUP_ERR_EXPR;
            }
            vals[i] = e->next ? main_next[e->index] : main_local[e->index];
            break;
        case DNAC_LOGUP_EXPR_PREP:
            if (!prep_local || e->next > 1 || e->index >= prep_width ||
                (e->next && !prep_next)) {
                return DNAC_LOGUP_ERR_EXPR;
            }
            vals[i] = e->next ? prep_next[e->index] : prep_local[e->index];
            break;
        case DNAC_LOGUP_EXPR_PUBLIC:
            if (!publics || e->index >= num_publics) {
                return DNAC_LOGUP_ERR_EXPR;
            }
            vals[i] = gold_fp2_from_base(publics[e->index]);
            break;
        case DNAC_LOGUP_EXPR_ADD:
        case DNAC_LOGUP_EXPR_SUB:
        case DNAC_LOGUP_EXPR_MUL:
            if (e->x < 0 || (uint32_t)e->x >= i || e->y < 0 ||
                (uint32_t)e->y >= i) {
                return DNAC_LOGUP_ERR_EXPR;
            }
            vals[i] = (e->kind == DNAC_LOGUP_EXPR_ADD)
                          ? gold_fp2_add(vals[e->x], vals[e->y])
                          : (e->kind == DNAC_LOGUP_EXPR_SUB)
                                ? gold_fp2_sub(vals[e->x], vals[e->y])
                                : gold_fp2_mul(vals[e->x], vals[e->y]);
            break;
        case DNAC_LOGUP_EXPR_NEG:
            if (e->x < 0 || (uint32_t)e->x >= i) return DNAC_LOGUP_ERR_EXPR;
            vals[i] = gold_fp2_neg(vals[e->x]);
            break;
        default:
            return DNAC_LOGUP_ERR_EXPR;
        }
    }
    return DNAC_LOGUP_OK;
}

int dnac_logup_verify_global_sum(const gold_fp2_t *sums, uint32_t n)
{
    if (n > 0 && !sums) {
        return DNAC_LOGUP_ERR_NULL;
    }
    gold_fp2_t total = gold_fp2_zero();
    for (uint32_t i = 0; i < n; i++) {
        total = gold_fp2_add(total, sums[i]);
    }
    return gold_fp2_eq(total, gold_fp2_zero()) ? DNAC_LOGUP_OK
                                               : DNAC_LOGUP_ERR_GLOBAL_SUM;
}

/* ============================================================================
 * Constraint degree — logup.rs:339-367
 * ========================================================================== */
int dnac_logup_constraint_degree(const dnac_logup_ctx_t    *ctx,
                                 const dnac_logup_lookup_t *lookup,
                                 uint32_t                  *out_degree)
{
    if (!out_degree) {
        return DNAC_LOGUP_ERR_NULL;
    }
    int rc = dnac_logup_pool_validate(ctx);
    if (rc != DNAC_LOGUP_OK) {
        return rc;
    }
    rc = logup_lookup_validate(ctx, lookup);
    if (rc != DNAC_LOGUP_OK) {
        return rc;
    }

    const uint32_t n = lookup->num_tuples;
    uint32_t deg_sum = 0;
    uint32_t *degs = (uint32_t *)malloc(sizeof(uint32_t) * (n ? n : 1));
    if (!degs) {
        return DNAC_LOGUP_ERR_OOM;
    }
    /* degs[i] = max element degree in tuple i (logup.rs:345-355). */
    for (uint32_t t = 0; t < n; t++) {
        uint32_t d = 0;
        for (uint32_t j = 0; j < lookup->tuple_widths[t]; j++) {
            uint32_t dj;
            rc = dnac_logup_expr_degree(ctx, lookup->tuple_elems[t][j], &dj);
            if (rc != DNAC_LOGUP_OK) {
                free(degs);
                return rc;
            }
            if (dj > d) {
                d = dj;
            }
        }
        degs[t] = d;
        deg_sum += d;
    }
    /* 1 + degree(denominator) (logup.rs:357-358). */
    uint32_t deg_denom_constr = 1u + deg_sum;
    /* degree(numerator) = max_i (deg(m_i) + deg_sum − degs[i])
     * (logup.rs:360-364; 0 when n == 0). */
    uint32_t deg_num = 0;
    for (uint32_t t = 0; t < n; t++) {
        uint32_t dm;
        rc = dnac_logup_expr_degree(ctx, lookup->multiplicities[t], &dm);
        if (rc != DNAC_LOGUP_OK) {
            free(degs);
            return rc;
        }
        uint32_t v = dm + deg_sum - degs[t];
        if (v > deg_num) {
            deg_num = v;
        }
    }
    free(degs);
    *out_degree =
        deg_denom_constr > deg_num ? deg_denom_constr : deg_num;
    return DNAC_LOGUP_OK;
}
