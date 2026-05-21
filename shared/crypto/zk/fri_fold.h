/**
 * @file fri_fold.h
 * @brief FRI arity-2 fold for STARK low-degree test (DNAC v3, Sub-sprint 2.1)
 *
 * Implements one layer of FRI folding. Input: 2H Goldilocks² values on a
 * coset of size 2H. Output: H Goldilocks² values that lie on the coset of
 * size H (the squares).
 *
 * DNAC-internal convention (natural pairing, NOT Plonky3 bit-reversed layout):
 *   Row i of "matrix": (lo, hi) = (values[2i], values[2i+1])
 *   For each i in [0, H):
 *     out[i] = (lo + hi) / 2 + (lo - hi) * beta * (g^{-i} / 2)
 *   where g is the primitive 2H-th root of unity in Goldilocks.
 *
 * The caller provides halve_inv_powers[H] = (g^{-i} / 2) for i = 0..H-1.
 * This avoids requiring the C side to know Plonky3's specific generator
 * table — the values come from the oracle test vector. In production
 * code (Sub-sprint 2.x), gold_fp_two_adic_generator drives the same values.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef DNAC_ZK_FRI_FOLD_H
#define DNAC_ZK_FRI_FOLD_H

#include <stddef.h>
#include <stdint.h>

#include "field_goldilocks.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Compute one arity-2 FRI fold layer.
 *
 * @param values            Input array of 2*h Goldilocks² values. row_i = (values[2i], values[2i+1]).
 * @param halve_inv_powers  Precomputed (g^{-i} / 2) sequence of h base-field elements.
 *                           Caller responsible for correct values.
 * @param beta              Folding challenge in Goldilocks².
 * @param h                 Output size (must be ≥ 1). Input size is 2*h.
 * @param out               Output buffer of h Goldilocks² elements.
 */
void fri_fold_arity2(const gold_fp2_t *values,
                     const gold_fp_t  *halve_inv_powers,
                     gold_fp2_t        beta,
                     size_t            h,
                     gold_fp2_t       *out);

#ifdef __cplusplus
}
#endif

#endif /* DNAC_ZK_FRI_FOLD_H */
