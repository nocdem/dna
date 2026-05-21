/**
 * @file sum_balance.c
 * @brief Multi-output range + sum-balance AIR (Sub-sprint 3.2).
 *
 * See sum_balance.h for spec.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: Apache-2.0
 */

#include "sum_balance.h"

#include <stddef.h>

int sum_balance_generate_witness(const uint64_t *amounts,
                                 uint32_t num_outputs,
                                 uint64_t fee,
                                 uint64_t claimed_input_sum,
                                 range_air_row_t (*output_traces)[RANGE_AIR_NUM_BITS],
                                 sum_balance_witness_t *out) {
    if (!amounts || !output_traces || !out) return -1;
    if (num_outputs == 0 || num_outputs > SUM_BALANCE_MAX_OUTPUTS) return -1;

    for (uint32_t i = 0; i < num_outputs; i++) {
        range_air_generate_trace(amounts[i], output_traces[i]);
    }
    out->num_outputs = num_outputs;
    out->output_traces = output_traces;
    out->fee = fee;
    out->claimed_input_sum = claimed_input_sum;
    return 0;
}

bool sum_balance_check(const sum_balance_witness_t *w,
                       uint32_t *out_first_failing_output,
                       char *out_first_failing_constraint,
                       uint32_t *out_first_failing_row) {
    if (out_first_failing_output)     *out_first_failing_output = 0;
    if (out_first_failing_constraint) *out_first_failing_constraint = 0;
    if (out_first_failing_row)        *out_first_failing_row = 0;

    if (!w || w->num_outputs == 0 || w->num_outputs > SUM_BALANCE_MAX_OUTPUTS) {
        if (out_first_failing_output)     *out_first_failing_output = UINT32_MAX;
        if (out_first_failing_constraint) *out_first_failing_constraint = '?';
        return false;
    }

    /* Per-output: range sub-AIR constraints. */
    for (uint32_t i = 0; i < w->num_outputs; i++) {
        char fc = 0;
        uint32_t fr = 0;
        if (!range_air_check_constraints(w->output_traces[i], &fc, &fr)) {
            if (out_first_failing_output)     *out_first_failing_output = i;
            if (out_first_failing_constraint) *out_first_failing_constraint = fc;
            if (out_first_failing_row)        *out_first_failing_row = fr;
            return false;
        }
    }

    /* C4: sum balance.
     *   Σ_i acc_{63,i} (output amounts) + fee == claimed_input_sum
     * All arithmetic in Goldilocks² (b component should be zero by construction). */
    gold_fp2_t sum = gold_fp2_zero();
    for (uint32_t i = 0; i < w->num_outputs; i++) {
        sum = gold_fp2_add(sum, w->output_traces[i][RANGE_AIR_NUM_BITS - 1].acc);
    }
    gold_fp2_t fee_fp = gold_fp2_from_base(gold_fp_from_u64(w->fee));
    sum = gold_fp2_add(sum, fee_fp);

    gold_fp2_t expected = gold_fp2_from_base(gold_fp_from_u64(w->claimed_input_sum));
    if (!gold_fp2_eq(sum, expected)) {
        if (out_first_failing_output)     *out_first_failing_output = UINT32_MAX;
        if (out_first_failing_constraint) *out_first_failing_constraint = '4';
        if (out_first_failing_row)        *out_first_failing_row = 0;
        return false;
    }

    return true;
}
