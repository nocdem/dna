/**
 * @file sum_balance.h
 * @brief Output sum-balance AIR (Sprint 3.2 — fib_air pattern port).
 *
 * Extends the range_air trace with a single accumulator column at offset 65,
 * enforcing the conservation claim from design doc § 6.1 / F8:
 *
 *     Sum_{i=0..N-1} output_amount[i] + committed_fee == claimed_input_sum.
 *
 * Three constraints over Goldilocks (matching `uni-stark/tests/fib_air.rs`
 * boundary + transition + boundary AIR pattern verbatim):
 *
 *     I (first row):  acc[0] - amount[0] = 0
 *     U (transition): acc[next] - acc[local] - amount[next] = 0
 *     F (last row):   acc[last] - (claimed_input_sum - committed_fee) = 0
 *
 * Reference: Plonky3 commit 82cfad73, `uni-stark/tests/fib_air.rs::
 * FibonacciAir::eval` lines 44-72 (canonical when_first_row + when_transition
 * + when_last_row + public_values idiom).
 *
 * Per design doc § 12.4 item 2 + feedback_no_kafadan_crypto.md: NO separate
 * sub-witness struct. The accumulator is a column of the SAME unified trace
 * that range_air operates on. Cols 0..64 are range_air's; col 65 is this
 * module's; both check_constraints functions can be called on the same
 * composed trace without interfering.
 *
 * Determinism (per design doc § 4.1 D1): every constraint residual is a
 * Goldilocks canonical u64 in [0, p). Cross-validated by oracle byte-match
 * against tools/vectors/sum_balance.json.
 *
 * Binding contract (per § 9 F7):
 *   - SUM_BALANCE_ACC_OFF == 65
 *   - SUM_BALANCE_WIDTH   == 66
 * test_air_column_layout_sum_balance asserts these at compile time and
 * at runtime.
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

/* ============================================================================
 * Column-layout binding contract (extends range_air)
 *
 * Cols 0..63 = bit columns (range_air)
 * Col 64     = amount column (range_air, RANGE_AIR_AMOUNT_OFF)
 * Col 65     = accumulator column (sum_balance, SUM_BALANCE_ACC_OFF)
 * Total width = 66 (SUM_BALANCE_WIDTH).
 * ========================================================================== */

/** Offset of the accumulator cell within a row. */
#define SUM_BALANCE_ACC_OFF         ((size_t)65)

/** Number of columns per row when composed with range_air. */
#define SUM_BALANCE_WIDTH           ((size_t)66)

/* ============================================================================
 * Constraint identifiers
 * ========================================================================== */

/** Init (first row): acc - amount = 0. */
#define SUM_BALANCE_CONSTRAINT_INIT     'I'

/** Update (transition): acc[next] - acc[local] - amount[next] = 0. */
#define SUM_BALANCE_CONSTRAINT_UPDATE   'U'

/** Final (last row): acc - (claimed_input_sum - committed_fee) = 0. */
#define SUM_BALANCE_CONSTRAINT_FINAL    'F'

/* ============================================================================
 * Public input bundle (the AIR's pi[] analog from fib_air)
 *
 * Both fields are interpreted as Goldilocks canonical u64s; values >= p are
 * reduced by sum_balance_check_constraints internally.
 * ========================================================================== */

/**
 * @brief Public inputs to the sum-balance constraint check.
 *
 * Per design doc § 6.1 + F8 fix:
 *   - claimed_input_sum is the sender-declared total of input amounts.
 *     The witness MUST cross-check this against the cleartext input record
 *     amount fields on the TX wire BEFORE invoking range proof verify.
 *   - committed_fee is the TX-wire fee field.
 */
typedef struct {
    uint64_t claimed_input_sum;
    uint64_t committed_fee;
} sum_balance_public_t;

/* ============================================================================
 * API
 * ========================================================================== */

/**
 * @brief Build the unified range_air + sum_balance trace for n amounts.
 *
 * Each row encodes one amount:
 *   row[RANGE_AIR_BIT_OFF(i)] = (amount >> i) & 1   for i in [0, 64)
 *   row[RANGE_AIR_AMOUNT_OFF] = amount mod p
 *   row[SUM_BALANCE_ACC_OFF]  = Sum_{j=0..=row_idx} amount[j] mod p
 *
 * All cells written are Goldilocks canonical u64s in [0, p).
 *
 * @param amounts     Array of n u64 values. May be NULL only if n == 0.
 * @param n           Number of amounts (and trace rows). Must be >= 1 for
 *                    constraints to be meaningful.
 * @param out_trace   Output buffer; caller owns. Must hold at least
 *                    n * row_stride uint64_t cells.
 * @param row_stride  Stride between rows; MUST be >= SUM_BALANCE_WIDTH.
 */
void sum_balance_build_trace(const uint64_t *amounts,
                             size_t n,
                             uint64_t *out_trace,
                             size_t row_stride);

/**
 * @brief Check sum-balance constraints across the trace.
 *
 * Per the fib_air idiom (boundary + transition + boundary):
 *   I (first row):  acc[0] - amount[0] = 0
 *   U (transition): acc[next] - acc[local] - amount[next] = 0  for each i
 *   F (last row):   acc[last] - (claimed_input_sum - committed_fee) = 0
 *
 * range_air's B/S constraints are NOT checked here — call
 * range_air_check_constraints on the same trace for those.
 *
 * @param trace                          n_rows * row_stride canonical cells.
 * @param n_rows                         Number of rows; must be >= 1.
 * @param row_stride                     Stride between rows; MUST be >=
 *                                       SUM_BALANCE_WIDTH.
 * @param pub_in                         Public input bundle (claimed_input_sum,
 *                                       committed_fee). MUST NOT be NULL.
 * @param out_first_failing_constraint   If non-NULL, set to 'I'/'U'/'F' on
 *                                       failure; left untouched on success.
 * @param out_first_failing_row          If non-NULL, set to row index of first
 *                                       failure (0 for F failures); left
 *                                       untouched on success.
 * @return true iff every constraint holds at every row / row-pair.
 */
bool sum_balance_check_constraints(const uint64_t *trace,
                                   size_t n_rows,
                                   size_t row_stride,
                                   const sum_balance_public_t *pub_in,
                                   char *out_first_failing_constraint,
                                   size_t *out_first_failing_row);

/**
 * @brief Compute every constraint residual exhaustively (debug / byte-match).
 *
 * Like range_air_compute_residuals — fills the full residual arrays without
 * short-circuiting. Used by the oracle cross-validation test to byte-match
 * every per-transition residual against tools/vectors/sum_balance.json.
 *
 * @param trace                  n_rows * row_stride canonical cells.
 * @param n_rows                 Number of rows; must be >= 1.
 * @param row_stride             Stride between rows; >= SUM_BALANCE_WIDTH.
 * @param pub_in                 Public input bundle. MUST NOT be NULL.
 * @param out_init_residual      1 cell; receives I residual.
 * @param out_update_residuals   n_rows-1 cells; receives U residuals
 *                               (transition 0->1 at index 0, etc.). May be
 *                               NULL when n_rows == 1.
 * @param out_final_residual     1 cell; receives F residual.
 */
void sum_balance_compute_residuals(const uint64_t *trace,
                                   size_t n_rows,
                                   size_t row_stride,
                                   const sum_balance_public_t *pub_in,
                                   uint64_t *out_init_residual,
                                   uint64_t *out_update_residuals,
                                   uint64_t *out_final_residual);

#ifdef __cplusplus
}
#endif

#endif /* DNAC_ZK_SUM_BALANCE_H */
