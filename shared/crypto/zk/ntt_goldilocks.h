/**
 * @file ntt_goldilocks.h
 * @brief Number-Theoretic Transform over Goldilocks (DNAC v3, Sub-sprint 3.5a)
 *
 * Radix-2 Cooley-Tukey NTT / iNTT over GF(p) and GF(p²) where
 * p = 2⁶⁴ − 2³² + 1. Used to convert between coefficient and evaluation forms
 * for polynomial commitment / LDE / quotient construction in later sub-sprints
 * (3.5b through 3.5g).
 *
 * Convention (matches standard math, NOT bit-reversed):
 *
 *   Forward NTT: input  = coefficients c[0..N) (natural order)
 *                output = evaluations    e[k]  =  Σⱼ c[j] · ωʲᵏ  at k = 0..N-1
 *                where ω = `gold_fp_two_adic_generator(log_n)`.
 *
 *   Inverse NTT: input  = evaluations e[0..N) (natural order)
 *                output = coefficients c[j]  = (1/N) · Σₖ e[k] · ω⁻ʲᵏ
 *
 * Algorithm: in-place DIT (decimation-in-time). We bit-reverse the input
 * permutation first, then perform `log_n` butterfly passes. Output is in
 * natural order. Symmetric for iNTT (bit-reverse → butterflies with inverse
 * twiddles → multiply by N⁻¹).
 *
 * Determinism:
 *   - All twiddles derived from `gold_fp_two_adic_generator(log_n)`.
 *   - Inverse twiddle = `gold_fp_inv(omega)`, not table lookup.
 *   - 1/N multiplier = `gold_fp_inv(N)`.
 *   - No SIMD; scalar in-place butterflies only.
 *
 * Size limits:
 *   - Base field: log_n ∈ [0, GOLDILOCKS_TWO_ADICITY] = [0, 32].
 *   - Extension : log_n ∈ [0, GOLDILOCKS_EXT_TWO_ADICITY] = [0, 33].
 *     (Same butterfly structure; twiddles live in base field for log_n ≤ 32.
 *      log_n == 33 would need an ext-field primitive root — out of scope until
 *      3.5c shows we actually need it; current cap = 32 for both.)
 *
 * Validation in Sub-sprint 3.5a tests:
 *   - Round-trip: iNTT(NTT(x)) == x for many random vectors and sizes.
 *   - Cross-check against brute-force O(N²) DFT for sizes 2..512.
 *   - Linearity, convolution theorem, edge cases (all-zero, constant).
 *   - No Rust dependency for 3.5a; Plonky3 oracle comparison deferred until
 *     3.5c when we need to byte-match LDE outputs.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef DNAC_ZK_NTT_GOLDILOCKS_H
#define DNAC_ZK_NTT_GOLDILOCKS_H

#include <stdint.h>

#include "field_goldilocks.h"

#ifdef __cplusplus
extern "C" {
#endif

/** Upper cap on log_n for both base and extension paths in this sub-sprint. */
#define NTT_GOLDILOCKS_MAX_LOG_N GOLDILOCKS_TWO_ADICITY  /* 32 */

/**
 * @brief Reverse the low `log_n` bits of `x`.
 *
 * E.g. log_n=3, x=0b001 → 0b100; x=0b110 → 0b011.
 */
uint32_t ntt_bit_reverse_u32(uint32_t x, unsigned log_n);

/**
 * @brief In-place bit-reversal permutation of a base-field array of length 2^log_n.
 */
void ntt_bit_reverse_permute(gold_fp_t *vals, unsigned log_n);

/**
 * @brief In-place bit-reversal permutation of an ext-field array of length 2^log_n.
 */
void ntt_bit_reverse_permute_ext(gold_fp2_t *vals, unsigned log_n);

/**
 * @brief Forward NTT over base field, in place.
 *
 * @param vals   Array of 2^log_n coefficients (input) → evaluations (output, natural order).
 * @param log_n  log₂ of array length. Must satisfy 0 ≤ log_n ≤ NTT_GOLDILOCKS_MAX_LOG_N.
 *               log_n == 0 is a no-op (single-element array; NTT is identity).
 */
void ntt_goldilocks_forward(gold_fp_t *vals, unsigned log_n);

/**
 * @brief Inverse NTT over base field, in place.
 *
 * @param vals   Array of 2^log_n evaluations (input) → coefficients (output, natural order).
 * @param log_n  log₂ of array length.
 */
void ntt_goldilocks_inverse(gold_fp_t *vals, unsigned log_n);

/**
 * @brief Forward NTT over extension field, in place.
 *
 * Same butterfly structure as base; twiddles are base-field elements lifted
 * into the extension via `gold_fp2_from_base`.
 */
void ntt_goldilocks_ext_forward(gold_fp2_t *vals, unsigned log_n);

/**
 * @brief Inverse NTT over extension field, in place.
 */
void ntt_goldilocks_ext_inverse(gold_fp2_t *vals, unsigned log_n);

#ifdef __cplusplus
}
#endif

#endif /* DNAC_ZK_NTT_GOLDILOCKS_H */
