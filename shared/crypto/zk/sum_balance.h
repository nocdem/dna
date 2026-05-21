/**
 * @file sum_balance.h
 * @brief Multi-output range + sum-balance AIR composition (DNAC v3, Sub-sprint 3.2)
 *
 * Composes M parallel range-decomposition AIRs (one per TX output) and adds
 * a TX-level conservation constraint: Σ output_amounts + fee == claimed_input_sum.
 *
 * AIR layout:
 *   trace[output_i][bit_j] for i ∈ [0, M), j ∈ [0, 63)
 *   Each output's sub-trace is a standard range_air (64 rows, 2 cols).
 *
 * Constraint set:
 *   For each output i:
 *     C1_i: bit_j × (1 − bit_j) = 0 for j ∈ [0, 63)
 *     C2_i: acc_0 = bit_0 (boundary)
 *     C3_i: acc_{j+1} = acc_j + bit_{j+1} × 2^{j+1} (transition)
 *   TX-level:
 *     C4: Σ_i acc_{63,i} + fee == claimed_input_sum    (sum balance)
 *
 * Public inputs (witness sees them):
 *   - fee
 *   - claimed_input_sum
 * Private inputs (only prover):
 *   - output amounts (encoded in each sub-trace)
 *
 * Field bound: same as range_air — each output_amount must be < Goldilocks p.
 * For DNAC supply 10^17 ≈ 2^57, this is comfortable.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef DNAC_ZK_SUM_BALANCE_H
#define DNAC_ZK_SUM_BALANCE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "range_air.h"

#ifdef __cplusplus
extern "C" {
#endif

/** Maximum supported TX outputs (covers typical DNAC TX shapes). */
#define SUM_BALANCE_MAX_OUTPUTS 16

/**
 * @brief Witness data for a multi-output sum-balance AIR.
 *
 * Caller allocates the per-output sub-traces. We store pointers + public inputs.
 */
typedef struct {
    uint32_t num_outputs;
    /** Per-output sub-traces (one range_air trace each). Length = num_outputs. */
    range_air_row_t (*output_traces)[RANGE_AIR_NUM_BITS];
    uint64_t fee;
    uint64_t claimed_input_sum;
} sum_balance_witness_t;

/**
 * @brief Generate the full witness for a TX shape.
 *
 * Caller allocates output_traces[num_outputs][NUM_BITS] (e.g., flat or 2D).
 * We populate each sub-trace from the corresponding amount.
 *
 * @param amounts             Per-output amounts (private).
 * @param num_outputs         Number of outputs in TX (≥ 1, ≤ MAX_OUTPUTS).
 * @param fee                 Transaction fee (public).
 * @param claimed_input_sum   Public input — claimed sum of input amounts.
 * @param output_traces       Caller-allocated 2D buffer: num_outputs × NUM_BITS rows.
 * @param out                 Output witness struct to populate.
 * @return 0 on success, -1 on invalid args.
 */
int sum_balance_generate_witness(const uint64_t *amounts,
                                 uint32_t num_outputs,
                                 uint64_t fee,
                                 uint64_t claimed_input_sum,
                                 range_air_row_t (*output_traces)[RANGE_AIR_NUM_BITS],
                                 sum_balance_witness_t *out);

/**
 * @brief Check all constraints (range sub-AIRs + sum balance).
 *
 * @param w                              Witness to validate.
 * @param out_first_failing_output       If non-NULL, set to first failing output
 *                                       index when returning false. Set to UINT32_MAX
 *                                       if the sum-balance check failed (not output-specific).
 * @param out_first_failing_constraint   '1'/'2'/'3' for range sub-constraints (per-output),
 *                                       '4' for sum balance.
 * @param out_first_failing_row          Row within sub-trace (or 0 for C4).
 * @return true iff all constraints pass.
 */
bool sum_balance_check(const sum_balance_witness_t *w,
                       uint32_t *out_first_failing_output,
                       char *out_first_failing_constraint,
                       uint32_t *out_first_failing_row);

#ifdef __cplusplus
}
#endif

#endif /* DNAC_ZK_SUM_BALANCE_H */
