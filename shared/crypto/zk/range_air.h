/**
 * @file range_air.h
 * @brief 64-bit range check AIR (Sprint 3.1 — keccak-air pattern port).
 *
 * Range-checks DNAC amount fields to [0, 2^64). Each row of the AIR trace
 * encodes ONE amount as 64 little-endian bit columns plus 1 amount column.
 * Two constraints per row:
 *   B (boolean):       bit_i * (bit_i - 1) = 0       for each i in [0, 64)
 *   S (recomposition): Sum_{i=0..64} bit_i * 2^i - amount = 0
 *
 * Both constraints evaluated over the Goldilocks base field (p = 2^64 - 2^32 + 1).
 * No extension field, no aux/permutation trace, no Fiat-Shamir challenges.
 *
 * Reference: Plonky3 commit 82cfad73 (pinned per design doc § 11 + RESUME.md).
 *   - p3_air::utils::u64_to_bits_le (air/src/utils.rs:59) — bit decomposition.
 *   - p3_keccak_air::KeccakAir::eval (keccak-air/src/air.rs:102-125) — the
 *     PRODUCTION assert_bool + limb recomposition idiom this module ports.
 *
 * Determinism invariant: every constraint residual is computed as a Goldilocks
 * canonical u64 in [0, p). Two implementations starting from the same trace
 * MUST produce byte-identical residuals (per design doc § 4.1 D1). Verified by
 * oracle byte-match in tools/vectors/range_air.json.
 *
 * Binding contract (per design doc § 9 F7 / § 4.5):
 *   - RANGE_AIR_BIT_OFF(0) == 0       (least-significant bit at offset 0)
 *   - RANGE_AIR_BIT_OFF(63) == 63
 *   - RANGE_AIR_AMOUNT_OFF == 64
 *   - RANGE_AIR_WIDTH      == 65
 * test_air_column_layout_range_air asserts these statically and at runtime.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef DNAC_ZK_RANGE_AIR_H
#define DNAC_ZK_RANGE_AIR_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ============================================================================
 * Column-layout binding contract (design doc § 4.5)
 *
 * F7 fix per § 12.4 item 1: every drift detector for this AIR MUST anchor on
 * these symbols, NOT on raw integer literals. Drift = silently broken
 * cross-version proof acceptance.
 * ========================================================================== */

/** Offset of bit i within a row. i must be in [0, 64). */
#define RANGE_AIR_BIT_OFF(i)        ((size_t)(i))

/** Offset of the amount cell within a row. */
#define RANGE_AIR_AMOUNT_OFF        ((size_t)64)

/** Number of columns per row. */
#define RANGE_AIR_WIDTH             ((size_t)65)

/* ============================================================================
 * Constraint identifiers (returned via out_first_failing_constraint)
 * ========================================================================== */

/** Boolean check: bit_i * (bit_i - 1) = 0. Failure here means a "bit" column
 *  held a value not in {0, 1}. */
#define RANGE_AIR_CONSTRAINT_BOOL   'B'

/** Recomposition check: Sum_{i=0..64} bit_i * 2^i - amount = 0 over Goldilocks.
 *  Failure means the bit columns and the amount column disagree mod p. */
#define RANGE_AIR_CONSTRAINT_RECOMP 'S'

/* ============================================================================
 * API
 * ========================================================================== */

/**
 * @brief Build the AIR trace for n amounts.
 *
 * Each row encodes one amount:
 *   row[RANGE_AIR_BIT_OFF(i)] = (amount >> i) & 1     for i in [0, 64)
 *   row[RANGE_AIR_AMOUNT_OFF] = amount mod p          (Goldilocks canonical)
 *
 * All cells written are Goldilocks canonical u64s in [0, p).
 *
 * @param amounts     Array of n u64 values to range-check. May be NULL only if n == 0.
 * @param n           Number of amounts (and trace rows).
 * @param out_trace   Output buffer. Caller owns. Must hold at least
 *                    n * row_stride uint64_t cells.
 * @param row_stride  Stride between consecutive rows in cells. MUST be >=
 *                    RANGE_AIR_WIDTH. Use RANGE_AIR_WIDTH for the standalone
 *                    trace; use a larger stride when embedding range_air rows
 *                    inside a wider AIR (e.g., future range_proof_air).
 */
void range_air_build_trace(const uint64_t *amounts,
                           size_t n,
                           uint64_t *out_trace,
                           size_t row_stride);

/**
 * @brief Check AIR constraints across the trace.
 *
 * Per row enforces:
 *   B: bit_i * (bit_i - 1) ≡ 0 (mod p)              for each i in [0, 64)
 *   S: Sum_{i=0..64} bit_i * 2^i - amount ≡ 0 (mod p)
 *
 * Both checks run in scalar __uint128_t arithmetic only (no SIMD reduction-
 * order ambiguity per design doc § 10 F10 mitigation).
 *
 * @param trace                          n_rows * row_stride canonical u64 cells.
 * @param n_rows                         Number of rows to check.
 * @param row_stride                     Stride between rows; MUST be >= RANGE_AIR_WIDTH.
 * @param out_first_failing_constraint   If non-NULL, set to 'B' or 'S' on
 *                                       failure; left untouched on success.
 * @param out_first_failing_row          If non-NULL, set to row index of first
 *                                       failure; left untouched on success.
 * @param out_first_failing_bit          If non-NULL, set to the bit position
 *                                       (0..63) of a 'B' failure, or 0 for 'S';
 *                                       left untouched on success.
 * @return true iff every constraint holds at every row.
 */
bool range_air_check_constraints(const uint64_t *trace,
                                 size_t n_rows,
                                 size_t row_stride,
                                 char *out_first_failing_constraint,
                                 size_t *out_first_failing_row,
                                 size_t *out_first_failing_bit);

/**
 * @brief Read the amount cell from a single row.
 *
 * Convenience accessor for callers iterating over a flat trace.
 *
 * @param row Pointer to row[0..]; must have at least RANGE_AIR_WIDTH cells.
 * @return    row[RANGE_AIR_AMOUNT_OFF] verbatim.
 */
uint64_t range_air_amount_from_row(const uint64_t *row);

/**
 * @brief Compute every constraint residual for one row, exhaustively.
 *
 * Unlike range_air_check_constraints (which short-circuits on first failure),
 * this fills the full residual arrays for the row. Used by the oracle
 * cross-validation test to byte-match per-bit and recomposition residuals
 * against tools/vectors/range_air.json.
 *
 * Both arrays are written with Goldilocks canonical u64 values:
 *   out_bool_residuals[i] = bit_i * (bit_i - 1) mod p
 *   *out_recompose         = (Sum_{i=0..64} bit_i * 2^i - amount) mod p
 *
 * The arithmetic order matches range_air_check_constraints exactly, so the
 * residuals are byte-identical to the values that function would compute.
 *
 * @param row                 Pointer to a row of RANGE_AIR_WIDTH cells.
 * @param out_bool_residuals  64 cells; receives bool residual per bit.
 * @param out_recompose       Single cell; receives the recomposition residual.
 */
void range_air_compute_residuals(const uint64_t *row,
                                 uint64_t *out_bool_residuals,
                                 uint64_t *out_recompose);

#ifdef __cplusplus
}
#endif

#endif /* DNAC_ZK_RANGE_AIR_H */
