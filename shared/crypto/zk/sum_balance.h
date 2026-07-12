/**
 * @file sum_balance.h
 * @brief Output sum-balance AIR (Sprint 3.2 — fib_air pattern port).
 *
 * Extends the range_air trace with a single accumulator column at SUM_BALANCE_ACC_OFF (53),
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
 * that range_air operates on. Cols 0..RANGE_AIR_AMOUNT_OFF are range_air's; the next col is this
 * module's; both check_constraints functions can be called on the same
 * composed trace without interfering.
 *
 * Determinism (per design doc § 4.1 D1): every constraint residual is a
 * Goldilocks canonical u64 in [0, p). Cross-validated by oracle byte-match
 * against tools/vectors/sum_balance.json.
 *
 * SOUNDNESS — aggregate bound (2026-07-11 audit fix). A mod-p cumulative sum
 * equals the INTEGER sum only if the sum cannot wrap p. range_air bounds each
 * amount to < 2^RANGE_AIR_BITS (= 2^52); this module additionally bounds the row
 * count to <= SUM_BALANCE_MAX_OUTPUTS so that
 *   (SUM_BALANCE_MAX_OUTPUTS) * 2^RANGE_AIR_BITS < p.
 * Together these guarantee Sum(outputs) < p, so the field accumulator IS the
 * integer sum and no mint-by-wraparound is possible. Without both bounds the
 * balance check is only mod p and a prover can mint multiples of p.
 *
 * Binding contract:
 *   - SUM_BALANCE_ACC_OFF == RANGE_AIR_WIDTH (== 53)
 *   - SUM_BALANCE_WIDTH   == RANGE_AIR_WIDTH + 1 (== 54)
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
 * Cols 0..RANGE_AIR_BITS-1 = bit columns (range_air)
 * Col RANGE_AIR_AMOUNT_OFF  = amount column (range_air)
 * Col SUM_BALANCE_ACC_OFF   = accumulator column (sum_balance)
 * Total width = SUM_BALANCE_WIDTH.
 * ========================================================================== */

/** Offset of the accumulator cell within a row (immediately after range_air's
 *  columns). Derived from RANGE_AIR_WIDTH so the two layouts stay consistent. */
#define SUM_BALANCE_ACC_OFF         (RANGE_AIR_WIDTH)

/** Number of columns per row when composed with range_air. */
#define SUM_BALANCE_WIDTH           (RANGE_AIR_WIDTH + (size_t)1)

/** Maximum number of output rows per proof. Chosen with RANGE_AIR_BITS so that
 *  SUM_BALANCE_MAX_OUTPUTS * 2^RANGE_AIR_BITS < Goldilocks p, guaranteeing the
 *  accumulator cannot wrap the field: 1024 * 2^52 = 2^62 < p ≈ 2^64. Raising
 *  RANGE_AIR_BITS requires lowering this so the product stays below p. */
#define SUM_BALANCE_MAX_OUTPUTS     ((size_t)1024)

/** Wrap-safe ceiling for the F-constraint public inputs (claimed_input_sum,
 *  committed_fee). = SUM_BALANCE_MAX_OUTPUTS * 2^RANGE_AIR_BITS = 2^62.
 *
 *  SOUNDNESS (2026-07-12 red-team fix — the mint the 07-11 fix left open). The
 *  final constraint F is a mod-p equation acc == claimed_input_sum - committed_fee.
 *  Range-checking the OUTPUT amounts is necessary but NOT sufficient: claimed and
 *  fee are separate terms in that equation, and if either is a near-p field
 *  element (e.g. committed_fee = p - A, a valid canonical Goldilocks value) then
 *  (claimed - fee) mod p wraps to a small value the accumulator matches — minting
 *  A base units while the INTEGER identity Sum(outputs) + fee == claimed fails.
 *  Because claimed and fee are PUBLIC inputs, the verifier bounds them directly
 *  in software (no in-circuit range proof needed). With acc < 2^62, and both
 *  publics < 2^62 < p:
 *    - claimed >= fee: (claimed - fee) in [0, 2^62); acc == it forces the INTEGER
 *      identity (two canonical reps equal mod p and both < p are equal).
 *    - claimed <  fee: (claimed - fee) mod p in (p - 2^62, p) >> 2^62 > acc, so
 *      no accumulator can match — correctly rejected (fee exceeding inputs).
 *  Hence the field equation equals the integer equation and no mint-by-wraparound
 *  survives on the fee/claimed side either. */
#define SUM_BALANCE_TERM_MAX        (((uint64_t)SUM_BALANCE_MAX_OUTPUTS) << RANGE_AIR_BITS)

/* ============================================================================
 * Constraint identifiers
 * ========================================================================== */

/** Init (first row): acc - amount = 0. */
#define SUM_BALANCE_CONSTRAINT_INIT     'I'

/** Update (transition): acc[next] - acc[local] - amount[next] = 0. */
#define SUM_BALANCE_CONSTRAINT_UPDATE   'U'

/** Final (last row): acc - (claimed_input_sum - committed_fee) = 0. */
#define SUM_BALANCE_CONSTRAINT_FINAL    'F'

/** Count bound: n_rows <= SUM_BALANCE_MAX_OUTPUTS. Failure means the proof
 *  declares more output rows than the wraparound-safe maximum, so the mod-p
 *  accumulator could no longer be trusted to equal the integer sum. */
#define SUM_BALANCE_CONSTRAINT_COUNT    'N'

/** Public-input bound: claimed_input_sum and committed_fee must each be
 *  < SUM_BALANCE_TERM_MAX (= 2^62). Failure means a public input could wrap the
 *  mod-p F equation and mint value (see SUM_BALANCE_TERM_MAX rationale). Also
 *  raised when n_rows == 0 (an empty output set leaves F unevaluated, so the
 *  balance identity would be vacuously "satisfied" — fail closed instead). */
#define SUM_BALANCE_CONSTRAINT_PUBBOUND 'P'

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
 * Each row encodes one amount (canon = amount mod p, per range_air):
 *   row[RANGE_AIR_BIT_OFF(i)] = (canon >> i) & 1    for i in [0, RANGE_AIR_BITS)
 *   row[RANGE_AIR_AMOUNT_OFF] = canon
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
 * Per the fib_air idiom (boundary + transition + boundary) plus the aggregate
 * count bound:
 *   N (count):      n_rows <= SUM_BALANCE_MAX_OUTPUTS  (checked once, up front)
 *   I (first row):  acc[0] - amount[0] = 0
 *   U (transition): acc[next] - acc[local] - amount[next] = 0  for each i
 *   F (last row):   acc[last] - (claimed_input_sum - committed_fee) = 0
 *
 * N is the wraparound guard: with range_air bounding each amount < 2^52 and
 * n_rows <= 1024, Sum(outputs) < 2^62 < p, so acc IS the integer sum.
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
