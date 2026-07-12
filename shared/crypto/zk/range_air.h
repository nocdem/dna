/**
 * @file range_air.h
 * @brief 52-bit range check AIR (keccak-air pattern port).
 *
 * Range-checks DNAC amount fields to [0, 2^52). Each row of the AIR trace
 * encodes ONE amount as 52 little-endian bit columns plus 1 amount column.
 * Two constraints per row:
 *   B (boolean):       bit_i * (bit_i - 1) = 0       for each i in [0, 52)
 *   S (recomposition): Sum_{i=0..52} bit_i * 2^i - amount = 0
 *
 * Both constraints evaluated over the Goldilocks base field (p = 2^64 - 2^32 + 1).
 * No extension field, no aux/permutation trace, no Fiat-Shamir challenges.
 *
 * WHY 52 BITS, NOT 64 (soundness — see 2026-07-11 audit + fix design doc):
 * Goldilocks p = 2^64 - 2^32 + 1 is LESS than 2^64. A 64-bit decomposition
 * recomposed into a single field element is therefore VACUOUS — every field
 * element already fits in 64 bits, so the constraint imposes no restriction and
 * a value like p-1 = 2^64 - 2^32 passes, which enables a mint attack when these
 * amounts are summed (mod-p wraparound). A meaningful range check needs
 * 2^BITS < p so the recomposition is injective on [0, 2^BITS) and cannot wrap.
 * BITS = 52 caps a single amount at ~45M DNAC (supply/32) while leaving 2^12
 * headroom below p so a sum of up to 1024 amounts (sum_balance) still cannot
 * reach p. This mirrors Plonky3 keccak-air, which recomposes 16-bit limbs
 * (BITS_PER_LIMB=16, keccak-air/src/columns.rs) precisely to stay well below p.
 * Revisit trigger: to allow single amounts > 45M DNAC, raise BITS (e.g. 56 →
 * ~720M DNAC) and lower sum_balance's max output count so 2^BITS * N_max < p.
 *
 * Reference: Plonky3 commit 82cfad73 (pinned per RESUME.md).
 *   - p3_air::utils::u64_to_bits_le (air/src/utils.rs:59) — bit decomposition.
 *   - p3_keccak_air::KeccakAir::eval (keccak-air/src/air.rs:102-125) — the
 *     PRODUCTION assert_bool + limb recomposition idiom this module ports.
 *
 * Determinism invariant: every constraint residual is computed as a Goldilocks
 * canonical u64 in [0, p). Two implementations starting from the same trace
 * MUST produce byte-identical residuals. With 2^52 < p the recomposition value
 * is unique in [0, 2^52) with no mod-p folding, so range membership is itself
 * deterministic. Verified by oracle byte-match in tools/vectors/range_air.json.
 *
 * Binding contract:
 *   - RANGE_AIR_BIT_OFF(0)  == 0       (least-significant bit at offset 0)
 *   - RANGE_AIR_BIT_OFF(51) == 51
 *   - RANGE_AIR_AMOUNT_OFF  == 52
 *   - RANGE_AIR_WIDTH       == 53
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
 * Column-layout binding contract
 *
 * Every drift detector for this AIR MUST anchor on these symbols, NOT on raw
 * integer literals. Drift = silently broken cross-version proof acceptance.
 * ========================================================================== */

/** Number of bit columns = the range bound exponent. Amounts are proven to lie
 *  in [0, 2^RANGE_AIR_BITS). MUST satisfy 2^RANGE_AIR_BITS < Goldilocks p so the
 *  recomposition is injective and non-wrapping (see file header rationale). */
#define RANGE_AIR_BITS              ((size_t)52)

/** Offset of bit i within a row. i must be in [0, RANGE_AIR_BITS). */
#define RANGE_AIR_BIT_OFF(i)        ((size_t)(i))

/** Offset of the amount cell within a row. */
#define RANGE_AIR_AMOUNT_OFF        (RANGE_AIR_BITS)

/** Number of columns per row. */
#define RANGE_AIR_WIDTH             (RANGE_AIR_BITS + (size_t)1)

/* ============================================================================
 * Constraint identifiers (returned via out_first_failing_constraint)
 * ========================================================================== */

/** Boolean check: bit_i * (bit_i - 1) = 0. Failure here means a "bit" column
 *  held a value not in {0, 1}. */
#define RANGE_AIR_CONSTRAINT_BOOL   'B'

/** Recomposition check: Sum_{i=0..RANGE_AIR_BITS} bit_i * 2^i - amount = 0 over
 *  Goldilocks. Failure means the bit columns and the amount column disagree, i.e.
 *  the amount does not fit in RANGE_AIR_BITS bits (out of range) or the columns
 *  were tampered. */
#define RANGE_AIR_CONSTRAINT_RECOMP 'S'

/* ============================================================================
 * API
 * ========================================================================== */

/**
 * @brief Build the AIR trace for n amounts.
 *
 * Each row encodes one amount. Bits are taken from the SAME canonical value
 * stored in the amount cell (canon = amount mod p), so the bit columns and the
 * amount column can never disagree by a hidden mod-p fold:
 *   canon                     = amount mod p          (Goldilocks canonical)
 *   row[RANGE_AIR_BIT_OFF(i)] = (canon >> i) & 1      for i in [0, RANGE_AIR_BITS)
 *   row[RANGE_AIR_AMOUNT_OFF] = canon
 *
 * If canon >= 2^RANGE_AIR_BITS the low-bit recomposition cannot equal canon, so
 * range_air_check_constraints rejects the row (out-of-range amount). All cells
 * written are Goldilocks canonical u64s in [0, p).
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
 *   B: bit_i * (bit_i - 1) ≡ 0 (mod p)              for each i in [0, RANGE_AIR_BITS)
 *   S: Sum_{i=0..RANGE_AIR_BITS} bit_i * 2^i - amount ≡ 0 (mod p)
 *
 * Because 2^RANGE_AIR_BITS < p, S accepts iff the amount cell is < 2^RANGE_AIR_BITS
 * (a genuine range check, not the vacuous 64-bit form). Both checks run in scalar
 * arithmetic only (no SIMD reduction-order ambiguity).
 *
 * @param trace                          n_rows * row_stride canonical u64 cells.
 * @param n_rows                         Number of rows to check.
 * @param row_stride                     Stride between rows; MUST be >= RANGE_AIR_WIDTH.
 * @param out_first_failing_constraint   If non-NULL, set to 'B' or 'S' on
 *                                       failure; left untouched on success.
 * @param out_first_failing_row          If non-NULL, set to row index of first
 *                                       failure; left untouched on success.
 * @param out_first_failing_bit          If non-NULL, set to the bit position
 *                                       (0..RANGE_AIR_BITS-1) of a 'B' failure,
 *                                       or 0 for 'S'; left untouched on success.
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
 *   *out_recompose         = (Sum_{i=0..RANGE_AIR_BITS} bit_i * 2^i - amount) mod p
 *
 * The arithmetic order matches range_air_check_constraints exactly, so the
 * residuals are byte-identical to the values that function would compute.
 *
 * @param row                 Pointer to a row of RANGE_AIR_WIDTH cells.
 * @param out_bool_residuals  RANGE_AIR_BITS cells; receives bool residual per bit.
 * @param out_recompose       Single cell; receives the recomposition residual.
 */
void range_air_compute_residuals(const uint64_t *row,
                                 uint64_t *out_bool_residuals,
                                 uint64_t *out_recompose);

#ifdef __cplusplus
}
#endif

#endif /* DNAC_ZK_RANGE_AIR_H */
