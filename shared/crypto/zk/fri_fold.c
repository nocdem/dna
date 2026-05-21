/**
 * @file fri_fold.c
 * @brief FRI arity-2 fold implementation (Sub-sprint 2.1).
 *
 * out[i] = (lo + hi)/2 + (lo - hi) * beta * halve_inv_power[i]
 *
 * Cross-validated against tools/vectors/fri_fold.json (Plonky3 reference).
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: Apache-2.0
 */

#include "fri_fold.h"

void fri_fold_arity2(const gold_fp2_t *values,
                     const gold_fp_t  *halve_inv_powers,
                     gold_fp2_t        beta,
                     size_t            h,
                     gold_fp2_t       *out) {
    if (!values || !halve_inv_powers || !out || h == 0) return;

    for (size_t i = 0; i < h; i++) {
        gold_fp2_t lo = values[2 * i];
        gold_fp2_t hi = values[2 * i + 1];

        /* Embed halve_inv_powers[i] (base) into extension. */
        gold_fp2_t hip_ext = gold_fp2_from_base(halve_inv_powers[i]);

        /* (lo + hi) / 2: multiply by halve (1/2 in base), embedded.
         * halve_inv_powers[0] = 1/2 (since g^0 = 1, so g^0 / 2 = 1/2).
         * BUT we cannot rely on values[0] for "halve" because subsequent
         * indices have g^{-i}/2 not just 1/2. We need 1/2 separately.
         *
         * Workaround: derive 1/2 from halve_inv_powers[0] (= g^0/2 = 1/2). */
        gold_fp2_t half_ext = gold_fp2_from_base(halve_inv_powers[0]); /* = 1/2 */

        gold_fp2_t term1 = gold_fp2_mul(gold_fp2_add(lo, hi), half_ext);
        gold_fp2_t term2 = gold_fp2_mul(gold_fp2_mul(gold_fp2_sub(lo, hi), beta), hip_ext);
        out[i] = gold_fp2_add(term1, term2);
    }
}
