/**
 * @file conf_balance_air.c
 * @brief Confidential balance-conservation + selector AIR — DNAC-original, is_zk=0.
 *
 * See conf_balance_air.h for the full row model + constraint spec. Built (not
 * asserted) so the row-type/row-count/one-amount-cell soundness is a FACT, per
 * the B1 v3.1 re-red-team + the v2 meta-conclusion.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: Apache-2.0
 */

#include "conf_balance_air.h"

#include "field_goldilocks.h"

static inline gold_fp_t fp(uint64_t v) { return gold_fp_from_u64(v); }
static inline gold_fp_t add(gold_fp_t a, gold_fp_t b) { return gold_fp_add(a, b); }
static inline gold_fp_t sub(gold_fp_t a, gold_fp_t b) { return gold_fp_sub(a, b); }
static inline gold_fp_t mul(gold_fp_t a, gold_fp_t b) { return gold_fp_mul(a, b); }

/* coeff = is_output + is_fee − is_claimed, as a field element (∈ {−1,0,+1}). */
static gold_fp_t coeff_fp(gold_fp_t is_out, gold_fp_t is_claimed, gold_fp_t is_fee) {
    return sub(add(is_out, is_fee), is_claimed);
}

bool conf_balance_air_generate(const uint64_t *outputs, size_t n_out,
                               uint64_t claimed, uint64_t fee,
                               unsigned log_height, uint64_t *trace_out) {
    if (log_height == 0 || log_height > CONF_BAL_MAX_LOG_HEIGHT) return false;
    const size_t rows = (size_t)1 << log_height;
    if (n_out == 0 || n_out + 2 > rows) return false; /* need N outputs + claimed + fee */
    if (!outputs || !trace_out) return false;

    /* Bounds the honest prover must respect (soundness is enforced by eval). */
    for (size_t i = 0; i < n_out; i++)
        if (outputs[i] >= (uint64_t)1 << CONF_BAL_OUTPUT_BITS) return false;
    if (fee >= (uint64_t)1 << CONF_BAL_OUTPUT_BITS) return false;
    if (claimed >= (uint64_t)1 << CONF_BAL_RANGE_BITS) return false;

    for (size_t i = 0; i < rows * CONF_BAL_WIDTH; i++) trace_out[i] = 0;

    gold_fp_t bal = gold_fp_zero();
    uint64_t n_claimed = 0, n_fee = 0;

    for (size_t r = 0; r < rows; r++) {
        uint64_t *row = trace_out + r * CONF_BAL_WIDTH;
        uint64_t amount;
        uint64_t is_out = 0, is_claimed = 0, is_fee = 0;

        if (r < n_out) { amount = outputs[r]; is_out = 1; }
        else if (r == n_out) { amount = claimed; is_claimed = 1; }
        else if (r == n_out + 1) { amount = fee; is_fee = 1; }
        else { amount = 0; } /* padding */

        row[CONF_BAL_AMOUNT_OFF] = amount;
        for (unsigned j = 0; j < CONF_BAL_RANGE_BITS; j++)
            row[CONF_BAL_BITS_OFF + j] = (amount >> j) & 1u;
        row[CONF_BAL_IS_OUTPUT_OFF] = is_out;
        row[CONF_BAL_IS_CLAIMED_OFF] = is_claimed;
        row[CONF_BAL_IS_FEE_OFF] = is_fee;
        row[CONF_BAL_IS_REAL_OFF] = is_out + is_claimed + is_fee;

        n_claimed += is_claimed;
        n_fee += is_fee;
        gold_fp_t c = coeff_fp(fp(is_out), fp(is_claimed), fp(is_fee));
        bal = add(bal, mul(c, fp(amount)));

        row[CONF_BAL_N_CLAIMED_OFF] = n_claimed;
        row[CONF_BAL_N_FEE_OFF] = n_fee;
        row[CONF_BAL_BAL_OFF] = gold_fp_to_u64(bal);
    }
    return true;
}

/* Boolean residual s·(s−1) (== 0 iff s ∈ {0,1}). */
static gold_fp_t bool_res(gold_fp_t s) {
    return mul(s, sub(s, gold_fp_one()));
}

int conf_balance_air_eval(const uint64_t *trace, size_t n_rows) {
    if (!trace || n_rows == 0) return 1;
    int viol = 0;

    /* Precompute 2^j. */
    gold_fp_t pow2[CONF_BAL_RANGE_BITS];
    pow2[0] = gold_fp_one();
    for (unsigned j = 1; j < CONF_BAL_RANGE_BITS; j++)
        pow2[j] = add(pow2[j - 1], pow2[j - 1]);

    for (size_t r = 0; r < n_rows; r++) {
        const uint64_t *row = trace + r * CONF_BAL_WIDTH;
        gold_fp_t amount = fp(row[CONF_BAL_AMOUNT_OFF]);
        gold_fp_t is_out = fp(row[CONF_BAL_IS_OUTPUT_OFF]);
        gold_fp_t is_claimed = fp(row[CONF_BAL_IS_CLAIMED_OFF]);
        gold_fp_t is_fee = fp(row[CONF_BAL_IS_FEE_OFF]);
        gold_fp_t is_real = fp(row[CONF_BAL_IS_REAL_OFF]);

        /* Booleanity: selectors + bits. */
        if (!gold_fp_is_zero(bool_res(is_out))) viol++;
        if (!gold_fp_is_zero(bool_res(is_claimed))) viol++;
        if (!gold_fp_is_zero(bool_res(is_fee))) viol++;
        if (!gold_fp_is_zero(bool_res(is_real))) viol++;
        gold_fp_t recomp = gold_fp_zero();
        for (unsigned j = 0; j < CONF_BAL_RANGE_BITS; j++) {
            gold_fp_t bit = fp(row[CONF_BAL_BITS_OFF + j]);
            if (!gold_fp_is_zero(bool_res(bit))) viol++;
            recomp = add(recomp, mul(bit, pow2[j]));
        }

        /* Selector sum: is_real = is_out + is_claimed + is_fee. */
        if (!gold_fp_eq(is_real, add(add(is_out, is_claimed), is_fee))) viol++;

        /* Padding-zero: (1 − is_real)·amount = 0. */
        if (!gold_fp_is_zero(mul(sub(gold_fp_one(), is_real), amount))) viol++;

        /* Range recomposition: Σ bit_j·2^j = amount. */
        if (!gold_fp_eq(recomp, amount)) viol++;

        /* 52-bit gate: (is_out + is_fee)·bit_j = 0 for j ∈ [52,62). */
        gold_fp_t out_or_fee = add(is_out, is_fee);
        for (unsigned j = CONF_BAL_OUTPUT_BITS; j < CONF_BAL_RANGE_BITS; j++) {
            gold_fp_t bit = fp(row[CONF_BAL_BITS_OFF + j]);
            if (!gold_fp_is_zero(mul(out_or_fee, bit))) viol++;
        }

        gold_fp_t bal = fp(row[CONF_BAL_BAL_OFF]);
        gold_fp_t n_claimed = fp(row[CONF_BAL_N_CLAIMED_OFF]);
        gold_fp_t n_fee = fp(row[CONF_BAL_N_FEE_OFF]);
        gold_fp_t c = coeff_fp(is_out, is_claimed, is_fee);
        gold_fp_t contrib = mul(c, amount);

        if (r == 0) {
            /* First row: accumulators == this row's contribution. */
            if (!gold_fp_eq(bal, contrib)) viol++;
            if (!gold_fp_eq(n_claimed, is_claimed)) viol++;
            if (!gold_fp_eq(n_fee, is_fee)) viol++;
        } else {
            /* Transition r−1 → r: acc_r = acc_{r−1} + contribution_r. */
            const uint64_t *prev = trace + (r - 1) * CONF_BAL_WIDTH;
            gold_fp_t bal_p = fp(prev[CONF_BAL_BAL_OFF]);
            gold_fp_t nc_p = fp(prev[CONF_BAL_N_CLAIMED_OFF]);
            gold_fp_t nf_p = fp(prev[CONF_BAL_N_FEE_OFF]);
            if (!gold_fp_eq(bal, add(bal_p, contrib))) viol++;
            if (!gold_fp_eq(n_claimed, add(nc_p, is_claimed))) viol++;
            if (!gold_fp_eq(n_fee, add(nf_p, is_fee))) viol++;
        }

        if (r == n_rows - 1) {
            /* Last row: balance conserved, exactly one claimed + one fee. */
            if (!gold_fp_is_zero(bal)) viol++;
            if (!gold_fp_eq(n_claimed, gold_fp_one())) viol++;
            if (!gold_fp_eq(n_fee, gold_fp_one())) viol++;
        }
    }
    return viol;
}
