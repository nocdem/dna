/**
 * @file range_air.c
 * @brief 64-bit range proof AIR — trace generation + constraint evaluation.
 *
 * See range_air.h for spec.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: Apache-2.0
 */

#include "range_air.h"

void range_air_generate_trace(uint64_t amount,
                              range_air_row_t trace[RANGE_AIR_NUM_BITS]) {
    uint64_t acc = 0;
    for (uint32_t i = 0; i < RANGE_AIR_NUM_BITS; i++) {
        uint64_t bit = (amount >> i) & 1ULL;
        acc += bit << i;
        trace[i].bit = gold_fp2_from_base(gold_fp_from_u64(bit));
        trace[i].acc = gold_fp2_from_base(gold_fp_from_u64(acc));
    }
}

uint64_t range_air_recover_amount(const range_air_row_t trace[RANGE_AIR_NUM_BITS]) {
    /* Final accumulator = amount when trace is valid. */
    return gold_fp_to_u64(trace[RANGE_AIR_NUM_BITS - 1].acc.a);
}

/* Helper: returns true if x represents the multiplicative zero of fp2. */
static inline bool fp2_is_zero(gold_fp2_t x) {
    return gold_fp2_eq(x, gold_fp2_zero());
}

bool range_air_check_constraints(const range_air_row_t trace[RANGE_AIR_NUM_BITS],
                                 char *out_first_failing_constraint,
                                 uint32_t *out_first_failing_row) {
    if (out_first_failing_constraint) *out_first_failing_constraint = 0;
    if (out_first_failing_row) *out_first_failing_row = 0;

    /* C1: bit_i * (1 - bit_i) = 0 for all i */
    gold_fp2_t one = gold_fp2_one();
    for (uint32_t i = 0; i < RANGE_AIR_NUM_BITS; i++) {
        gold_fp2_t one_minus_bit = gold_fp2_sub(one, trace[i].bit);
        gold_fp2_t prod = gold_fp2_mul(trace[i].bit, one_minus_bit);
        if (!fp2_is_zero(prod)) {
            if (out_first_failing_constraint) *out_first_failing_constraint = '1';
            if (out_first_failing_row) *out_first_failing_row = i;
            return false;
        }
    }

    /* C2: acc_0 - bit_0 = 0 (boundary) */
    if (!gold_fp2_eq(trace[0].acc, trace[0].bit)) {
        if (out_first_failing_constraint) *out_first_failing_constraint = '2';
        if (out_first_failing_row) *out_first_failing_row = 0;
        return false;
    }

    /* C3: acc_{i+1} - acc_i - bit_{i+1} * 2^{i+1} = 0 for i in [0, 62] */
    for (uint32_t i = 0; i < RANGE_AIR_NUM_BITS - 1; i++) {
        /* 2^{i+1} fits in u64 for i+1 ≤ 63 */
        uint64_t pow2_val = 1ULL << (i + 1);
        gold_fp2_t pow2 = gold_fp2_from_base(gold_fp_from_u64(pow2_val));
        gold_fp2_t bit_times_pow = gold_fp2_mul(trace[i + 1].bit, pow2);
        gold_fp2_t expected = gold_fp2_add(trace[i].acc, bit_times_pow);
        if (!gold_fp2_eq(trace[i + 1].acc, expected)) {
            if (out_first_failing_constraint) *out_first_failing_constraint = '3';
            if (out_first_failing_row) *out_first_failing_row = i + 1;
            return false;
        }
    }

    return true;
}
