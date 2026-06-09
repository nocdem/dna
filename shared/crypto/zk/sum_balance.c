/**
 * @file sum_balance.c
 * @brief Output sum-balance AIR — port of Plonky3 fib_air pattern.
 *
 * Reference: Plonky3 commit 82cfad73,
 *   `uni-stark/tests/fib_air.rs::FibonacciAir::eval` (lines 44-72)
 *
 * The Plonky3 idiom — boundary + transition + boundary AIR with public_values
 * — is transcribed verbatim into Goldilocks arithmetic. Each constraint
 * residual is computed using the existing field_goldilocks primitives; no
 * new arithmetic is introduced.
 *
 * Per design doc § 9 F19 + feedback_no_kafadan_crypto.md: this implementation
 * was written with fib_air.rs open. Cross-validation: oracle byte-match in
 * tools/vectors/sum_balance.json.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: Apache-2.0
 */

#include "sum_balance.h"

#include "field_goldilocks.h"
#include "range_air.h"

/* ============================================================================
 * Trace construction
 *
 * Step 1: delegate range_air's portion (bit cols 0..63 + amount col 64).
 * Step 2: fill the accumulator col (65) as the cumulative sum of amount cells.
 *
 * The accumulator is computed by adding amount[i] (Goldilocks canonical, as
 * range_air placed it) into a running sum, written into col 65 row-by-row.
 * ========================================================================== */

void sum_balance_build_trace(const uint64_t *amounts,
                             size_t n,
                             uint64_t *out_trace,
                             size_t row_stride) {
    if (n == 0) {
        return;
    }

    /* Step 1: fill range_air's columns (0..64). The row stride passes through
     * so subsequent rows are placed at the correct offset for our 66-wide
     * unified trace. */
    range_air_build_trace(amounts, n, out_trace, row_stride);

    /* Step 2: fill the accumulator column. acc[i] = Sum_{j=0..=i} amount[j]
     * over Goldilocks (matches the oracle's `running_acc = running_acc +
     * amount_field` loop in dump_sum_balance). */
    gold_fp_t running_acc = gold_fp_zero();
    for (size_t i = 0; i < n; i++) {
        uint64_t *cells = &out_trace[i * row_stride];
        const gold_fp_t amount = gold_fp_from_u64(cells[RANGE_AIR_AMOUNT_OFF]);
        running_acc = gold_fp_add(running_acc, amount);
        cells[SUM_BALANCE_ACC_OFF] = gold_fp_to_u64(running_acc);
    }
}

/* ============================================================================
 * Constraint evaluation
 *
 * Mirrors fib_air.rs::FibonacciAir::eval lines 56-70 exactly:
 *
 *     when_first_row.assert_eq(local.left,  pi_a);     ← I: acc[0] == amount[0]
 *     when_transition.assert_eq(local.right, next.left); ← U: acc[next] == acc[local] + amount[next]
 *                                                          (rearranged as acc[next] - acc[local] - amount[next] == 0)
 *     builder.when_last_row().assert_eq(local.right, pi_x);  ← F: acc[last] == claimed_input_sum - committed_fee
 *
 * `claimed - fee` is computed once outside the row loop. All arithmetic in
 * scalar Goldilocks via field_goldilocks.c (no SIMD per design doc § 10 F10).
 * ========================================================================== */

bool sum_balance_check_constraints(const uint64_t *trace,
                                   size_t n_rows,
                                   size_t row_stride,
                                   const sum_balance_public_t *pub_in,
                                   char *out_first_failing_constraint,
                                   size_t *out_first_failing_row) {
    /* Empty trace: no first row, no transitions, no last row — vacuously
     * satisfied. Matches range_air's behavior. */
    if (n_rows == 0) {
        return true;
    }

    /* I constraint — first row. */
    {
        const uint64_t *row0 = &trace[0];
        const gold_fp_t acc0 = gold_fp_from_u64(row0[SUM_BALANCE_ACC_OFF]);
        const gold_fp_t amt0 = gold_fp_from_u64(row0[RANGE_AIR_AMOUNT_OFF]);
        const gold_fp_t residual = gold_fp_sub(acc0, amt0);
        if (!gold_fp_is_zero(residual)) {
            if (out_first_failing_constraint) {
                *out_first_failing_constraint = SUM_BALANCE_CONSTRAINT_INIT;
            }
            if (out_first_failing_row) {
                *out_first_failing_row = 0;
            }
            return false;
        }
    }

    /* U constraints — per transition. */
    for (size_t i = 0; i + 1 < n_rows; i++) {
        const uint64_t *row_local = &trace[i * row_stride];
        const uint64_t *row_next = &trace[(i + 1) * row_stride];
        const gold_fp_t acc_local = gold_fp_from_u64(row_local[SUM_BALANCE_ACC_OFF]);
        const gold_fp_t acc_next = gold_fp_from_u64(row_next[SUM_BALANCE_ACC_OFF]);
        const gold_fp_t amt_next = gold_fp_from_u64(row_next[RANGE_AIR_AMOUNT_OFF]);
        /* residual = acc_next - acc_local - amount_next */
        const gold_fp_t delta = gold_fp_sub(acc_next, acc_local);
        const gold_fp_t residual = gold_fp_sub(delta, amt_next);
        if (!gold_fp_is_zero(residual)) {
            if (out_first_failing_constraint) {
                *out_first_failing_constraint = SUM_BALANCE_CONSTRAINT_UPDATE;
            }
            if (out_first_failing_row) {
                *out_first_failing_row = i;
            }
            return false;
        }
    }

    /* F constraint — last row. target = claimed_input_sum - committed_fee. */
    {
        const uint64_t *row_last = &trace[(n_rows - 1) * row_stride];
        const gold_fp_t acc_last = gold_fp_from_u64(row_last[SUM_BALANCE_ACC_OFF]);
        const gold_fp_t claimed = gold_fp_from_u64(pub_in->claimed_input_sum);
        const gold_fp_t fee = gold_fp_from_u64(pub_in->committed_fee);
        const gold_fp_t target = gold_fp_sub(claimed, fee);
        const gold_fp_t residual = gold_fp_sub(acc_last, target);
        if (!gold_fp_is_zero(residual)) {
            if (out_first_failing_constraint) {
                *out_first_failing_constraint = SUM_BALANCE_CONSTRAINT_FINAL;
            }
            if (out_first_failing_row) {
                *out_first_failing_row = n_rows - 1;
            }
            return false;
        }
    }

    return true;
}

/* ============================================================================
 * Exhaustive residual computation (matches the oracle byte-by-byte)
 * ========================================================================== */

void sum_balance_compute_residuals(const uint64_t *trace,
                                   size_t n_rows,
                                   size_t row_stride,
                                   const sum_balance_public_t *pub_in,
                                   uint64_t *out_init_residual,
                                   uint64_t *out_update_residuals,
                                   uint64_t *out_final_residual) {
    /* I residual. */
    {
        const uint64_t *row0 = &trace[0];
        const gold_fp_t acc0 = gold_fp_from_u64(row0[SUM_BALANCE_ACC_OFF]);
        const gold_fp_t amt0 = gold_fp_from_u64(row0[RANGE_AIR_AMOUNT_OFF]);
        *out_init_residual = gold_fp_to_u64(gold_fp_sub(acc0, amt0));
    }

    /* U residuals — one per transition. */
    for (size_t i = 0; i + 1 < n_rows; i++) {
        const uint64_t *row_local = &trace[i * row_stride];
        const uint64_t *row_next = &trace[(i + 1) * row_stride];
        const gold_fp_t acc_local = gold_fp_from_u64(row_local[SUM_BALANCE_ACC_OFF]);
        const gold_fp_t acc_next = gold_fp_from_u64(row_next[SUM_BALANCE_ACC_OFF]);
        const gold_fp_t amt_next = gold_fp_from_u64(row_next[RANGE_AIR_AMOUNT_OFF]);
        const gold_fp_t delta = gold_fp_sub(acc_next, acc_local);
        out_update_residuals[i] = gold_fp_to_u64(gold_fp_sub(delta, amt_next));
    }

    /* F residual. */
    {
        const uint64_t *row_last = &trace[(n_rows - 1) * row_stride];
        const gold_fp_t acc_last = gold_fp_from_u64(row_last[SUM_BALANCE_ACC_OFF]);
        const gold_fp_t claimed = gold_fp_from_u64(pub_in->claimed_input_sum);
        const gold_fp_t fee = gold_fp_from_u64(pub_in->committed_fee);
        const gold_fp_t target = gold_fp_sub(claimed, fee);
        *out_final_residual = gold_fp_to_u64(gold_fp_sub(acc_last, target));
    }
}
