/**
 * @file range_air.c
 * @brief 64-bit range check AIR — port of Plonky3 keccak-air bit-decomp pattern.
 *
 * Reference: Plonky3 commit 82cfad73:
 *   - air/src/utils.rs:59         — u64_to_bits_le helper.
 *   - keccak-air/src/air.rs:102-125 — production assert_bools + limb recompose.
 *
 * Both constraints (B boolean, S recomposition) evaluate over Goldilocks. No
 * extension field, no aux trace, no challenges. Matches the C convention of
 * field_goldilocks.{c,h} which is itself Plonky3-byte-matched.
 *
 * Per design doc § 9 F19 + feedback_no_kafadan_crypto.md: this implementation
 * was written with keccak-air/src/air.rs open. Each constraint was transcribed,
 * not adapted. Cross-validation: tools/vectors/range_air.json byte-match.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: Apache-2.0
 */

#include "range_air.h"

#include "field_goldilocks.h"

/* ============================================================================
 * Trace construction
 * ========================================================================== */

void range_air_build_trace(const uint64_t *amounts,
                           size_t n,
                           uint64_t *out_trace,
                           size_t row_stride) {
    if (n == 0) {
        return;
    }
    for (size_t row = 0; row < n; row++) {
        const uint64_t amount = amounts[row];
        uint64_t *cells = &out_trace[row * row_stride];

        /* Bit columns: little-endian (bit 0 at offset 0). Each cell is 0 or 1,
         * both of which are Goldilocks canonical. */
        for (size_t i = 0; i < 64; i++) {
            cells[RANGE_AIR_BIT_OFF(i)] = (amount >> i) & UINT64_C(1);
        }

        /* Amount column: canonical Goldilocks form of amount.
         * For amount < p this is identity; for amount in [p, 2^64) this is
         * amount - p (handled by gold_fp_from_u64). */
        cells[RANGE_AIR_AMOUNT_OFF] = gold_fp_to_u64(gold_fp_from_u64(amount));
    }
}

/* ============================================================================
 * Constraint evaluation
 *
 * Constraint algebra mirrors Plonky3 keccak-air/src/air.rs:102-125 exactly:
 *   B: for each bit cell b, the polynomial b * (b - 1) must vanish.
 *   S: the recomposition Σ b_i * 2^i minus the amount cell must vanish.
 * Both are evaluated as Goldilocks residuals; failure ⇔ residual != 0.
 * ========================================================================== */

bool range_air_check_constraints(const uint64_t *trace,
                                 size_t n_rows,
                                 size_t row_stride,
                                 char *out_first_failing_constraint,
                                 size_t *out_first_failing_row,
                                 size_t *out_first_failing_bit) {
    const gold_fp_t one = gold_fp_one();
    const gold_fp_t two = gold_fp_from_u64(2);

    for (size_t row = 0; row < n_rows; row++) {
        const uint64_t *cells = &trace[row * row_stride];

        /* Constraint B: bit_i * (bit_i - 1) ≡ 0 (mod p) for every bit column. */
        for (size_t i = 0; i < 64; i++) {
            const gold_fp_t b = gold_fp_from_u64(cells[RANGE_AIR_BIT_OFF(i)]);
            const gold_fp_t b_minus_1 = gold_fp_sub(b, one);
            const gold_fp_t residual = gold_fp_mul(b, b_minus_1);
            if (!gold_fp_is_zero(residual)) {
                if (out_first_failing_constraint) {
                    *out_first_failing_constraint = RANGE_AIR_CONSTRAINT_BOOL;
                }
                if (out_first_failing_row) {
                    *out_first_failing_row = row;
                }
                if (out_first_failing_bit) {
                    *out_first_failing_bit = i;
                }
                return false;
            }
        }

        /* Constraint S: Σ_{i=0..64} bit_i * 2^i - amount ≡ 0 (mod p).
         * Accumulation order matches the oracle (low-bit-first; pow starts at 1,
         * doubles each iteration). Goldilocks is commutative/associative so any
         * order yields the same field result, but matching the oracle's order
         * keeps any future intermediate-state cross-check byte-identical. */
        gold_fp_t sum = gold_fp_zero();
        gold_fp_t pow_of_2 = gold_fp_one();
        for (size_t i = 0; i < 64; i++) {
            const gold_fp_t b = gold_fp_from_u64(cells[RANGE_AIR_BIT_OFF(i)]);
            sum = gold_fp_add(sum, gold_fp_mul(b, pow_of_2));
            if (i < 63) {
                pow_of_2 = gold_fp_mul(pow_of_2, two);
            }
        }
        const gold_fp_t amount_in_trace =
            gold_fp_from_u64(cells[RANGE_AIR_AMOUNT_OFF]);
        const gold_fp_t residual = gold_fp_sub(sum, amount_in_trace);
        if (!gold_fp_is_zero(residual)) {
            if (out_first_failing_constraint) {
                *out_first_failing_constraint = RANGE_AIR_CONSTRAINT_RECOMP;
            }
            if (out_first_failing_row) {
                *out_first_failing_row = row;
            }
            if (out_first_failing_bit) {
                *out_first_failing_bit = 0;
            }
            return false;
        }
    }
    return true;
}

uint64_t range_air_amount_from_row(const uint64_t *row) {
    return row[RANGE_AIR_AMOUNT_OFF];
}

void range_air_compute_residuals(const uint64_t *row,
                                 uint64_t *out_bool_residuals,
                                 uint64_t *out_recompose) {
    const gold_fp_t one = gold_fp_one();
    const gold_fp_t two = gold_fp_from_u64(2);

    /* Per-bit boolean residual. */
    for (size_t i = 0; i < 64; i++) {
        const gold_fp_t b = gold_fp_from_u64(row[RANGE_AIR_BIT_OFF(i)]);
        const gold_fp_t b_minus_1 = gold_fp_sub(b, one);
        const gold_fp_t r = gold_fp_mul(b, b_minus_1);
        out_bool_residuals[i] = gold_fp_to_u64(r);
    }

    /* Recomposition residual — same order as range_air_check_constraints. */
    gold_fp_t sum = gold_fp_zero();
    gold_fp_t pow_of_2 = gold_fp_one();
    for (size_t i = 0; i < 64; i++) {
        const gold_fp_t b = gold_fp_from_u64(row[RANGE_AIR_BIT_OFF(i)]);
        sum = gold_fp_add(sum, gold_fp_mul(b, pow_of_2));
        if (i < 63) {
            pow_of_2 = gold_fp_mul(pow_of_2, two);
        }
    }
    const gold_fp_t amount_in_trace =
        gold_fp_from_u64(row[RANGE_AIR_AMOUNT_OFF]);
    const gold_fp_t residual = gold_fp_sub(sum, amount_in_trace);
    *out_recompose = gold_fp_to_u64(residual);
}
