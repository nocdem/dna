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
 * Step 1: delegate range_air's portion (bit cols 0..RANGE_AIR_BITS-1 + amount
 *         col RANGE_AIR_AMOUNT_OFF).
 * Step 2: fill the accumulator col (SUM_BALANCE_ACC_OFF) as the cumulative sum
 *         of amount cells.
 *
 * The accumulator is computed by adding amount[i] (Goldilocks canonical, as
 * range_air placed it) into a running sum, written into SUM_BALANCE_ACC_OFF row-by-row.
 * ========================================================================== */

void sum_balance_build_trace(const uint64_t *amounts,
                             size_t n,
                             uint64_t *out_trace,
                             size_t row_stride) {
    if (n == 0) {
        return;
    }

    /* Step 1: fill range_air's columns (0..RANGE_AIR_AMOUNT_OFF). The row stride
     * passes through so subsequent rows are placed at the correct offset for our
     * SUM_BALANCE_WIDTH-wide
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
    /* Empty trace: no outputs means the F balance equation is never evaluated,
     * so claimed/fee would be entirely unconstrained — a vacuous accept. For a
     * money-conservation check that is a hole, not a benign no-op, so fail
     * closed. (range_air returns true for n==0 because it has nothing to
     * range-check; sum_balance MUST assert the balance identity, which needs at
     * least one row.) */
    if (n_rows == 0) {
        if (out_first_failing_constraint) {
            *out_first_failing_constraint = SUM_BALANCE_CONSTRAINT_PUBBOUND;
        }
        if (out_first_failing_row) {
            *out_first_failing_row = 0;
        }
        return false;
    }

    /* Public-input bound (soundness, 2026-07-12 red-team fix). The F constraint
     * acc == claimed_input_sum - committed_fee is a mod-p equation; a near-p
     * committed_fee (or claimed_input_sum) wraps it and mints value even when the
     * outputs are perfectly range-checked. claimed and fee are PUBLIC, so bound
     * them directly (see SUM_BALANCE_TERM_MAX). Both < 2^62 with acc < 2^62 makes
     * the field equation equal the integer equation. */
    if (pub_in->claimed_input_sum >= SUM_BALANCE_TERM_MAX ||
        pub_in->committed_fee >= SUM_BALANCE_TERM_MAX) {
        if (out_first_failing_constraint) {
            *out_first_failing_constraint = SUM_BALANCE_CONSTRAINT_PUBBOUND;
        }
        if (out_first_failing_row) {
            *out_first_failing_row = n_rows - 1;
        }
        return false;
    }

    /* N constraint — aggregate count bound (soundness, 2026-07-11 audit fix).
     * With each amount < 2^RANGE_AIR_BITS and n_rows <= SUM_BALANCE_MAX_OUTPUTS,
     * Sum(outputs) < SUM_BALANCE_MAX_OUTPUTS * 2^RANGE_AIR_BITS < p, so the mod-p
     * accumulator equals the integer sum and cannot wrap. Reject any proof that
     * declares more rows than this wraparound-safe maximum. */
    if (n_rows > SUM_BALANCE_MAX_OUTPUTS) {
        if (out_first_failing_constraint) {
            *out_first_failing_constraint = SUM_BALANCE_CONSTRAINT_COUNT;
        }
        if (out_first_failing_row) {
            *out_first_failing_row = SUM_BALANCE_MAX_OUTPUTS;
        }
        return false;
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

/* ============================================================================
 * Composed range + balance verify — the only sound money-gating entry.
 * ========================================================================== */

bool range_balance_verify(const uint64_t *trace,
                          size_t n_rows,
                          size_t row_stride,
                          const sum_balance_public_t *pub_in,
                          char *out_first_failing_constraint,
                          size_t *out_first_failing_row) {
    /* Step 1 — RANGE (B/S): prove every output amount is a genuine value
     * < 2^RANGE_AIR_BITS. This is what rejects the mint witness (out = p-1, which
     * balance-alone accepts, KAT E2). Run FIRST so an out-of-range amount is
     * rejected before the accumulator sum is trusted. */
    size_t fail_bit = 0;
    if (!range_air_check_constraints(trace, n_rows, row_stride,
                                     out_first_failing_constraint,
                                     out_first_failing_row, &fail_bit)) {
        return false;
    }

    /* Step 2 — BALANCE (N/P/I/U/F): count bound, public-input (fee/claimed)
     * bound, and cumulative conservation on the same trace. Fails closed on
     * n_rows == 0 (range returns true for the empty trace; balance rejects it
     * with 'P'). */
    if (!sum_balance_check_constraints(trace, n_rows, row_stride, pub_in,
                                       out_first_failing_constraint,
                                       out_first_failing_row)) {
        return false;
    }

    return true;
}
