/**
 * @file fri_fold.h
 * @brief FRI fold primitives — port of Plonky3 TwoAdicFriFolding.
 *
 * Plonky3 commit pin: 82cfad73cd734d37a0d51953094f970c531817ec.
 *
 * Scope (all GREEN, oracle byte-matched against Plonky3 82cfad73):
 *   - Phase D.1: static lagrange_interpolate_at_fp_fp2 (test wrapper exposed below).
 *   - Phase D.2: fri_fold_row_fp2 (Plonky3 two_adic_pcs.rs:109-132).
 *   - Phase D.3: fri_fold_matrix_fp2 log_arity == 1 (Plonky3 two_adic_pcs.rs:135-162).
 *   - Phase D.4: fri_fold_matrix_fp2 generic log_arity > 1 (Plonky3 two_adic_pcs.rs:163-213).
 *
 * Field choice (per DNAC v3 ZK design): F = Goldilocks, EF = Goldilocks².
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef DNAC_FRI_FOLD_H
#define DNAC_FRI_FOLD_H

#include <stddef.h>
#include <stdint.h>

#include "field_goldilocks.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ============================================================================
 * Phase D.1 — test-only wrapper for lagrange_interpolate_at_fp_fp2
 *
 * The implementation `lagrange_interpolate_at_fp_fp2` is `static` in fri_fold.c
 * (matching Plonky3's `fn lagrange_interpolate_at` private-to-module visibility
 * at fri/src/two_adic_pcs.rs:220). This wrapper exists ONLY so the C test
 * harness can drive the function during Phase D.1; downstream callers are
 * fri_fold_row_fp2 (Phase D.2) which is in the same translation unit and
 * uses the static directly.
 *
 * Contract (matches Plonky3 lagrange_interpolate_at signature):
 *   - xs: n base-field points; assumed to be a coset of the 2^log2(n)-th
 *         roots of unity (Plonky3 two_adic_pcs.rs:241 invariant). Caller
 *         must ensure xs[0] != 0 (otherwise weight_scale inversion is UB).
 *   - ys: n ext-field values, one per xs point
 *   - n:  number of interpolation points (must be a power of two)
 *   - z:  ext-field evaluation point
 *
 * Returns EF::ZERO if n == 0 (Plonky3 two_adic_pcs.rs:229).
 * Returns ys[i] if z == xs[i] for some i (Plonky3 two_adic_pcs.rs:233-237).
 * ========================================================================== */
gold_fp2_t fri_fold_test_lagrange_at_fp_fp2(
    const gold_fp_t  *xs,
    const gold_fp2_t *ys,
    size_t            n,
    gold_fp2_t        z);

/* ============================================================================
 * Phase D.2 — fri_fold_row_fp2
 *
 * Plonky3 reference: TwoAdicFriFolding::fold_row, fri/src/two_adic_pcs.rs:109-132.
 *
 * Contract:
 *   - evals_len must equal (1u << log_arity)
 *   - F = Goldilocks, EF = Goldilocks² (BinomialExtensionField<Goldilocks, 2>)
 *   - Returns the value of the unique polynomial of degree < arity through the
 *     (xs[i], evals[i]) points, evaluated at beta.
 *
 * Aborts on allocation failure (matches Plonky3 Vec panic semantics).
 * ========================================================================== */
gold_fp2_t fri_fold_row_fp2(
    size_t            index,
    unsigned          log_height,
    unsigned          log_arity,
    gold_fp2_t        beta,
    const gold_fp2_t *evals,
    size_t            evals_len);

/* ============================================================================
 * Phase D.3 + D.4 — fri_fold_matrix_fp2 (arity-2 optimized + generic)
 *
 * Plonky3 reference: TwoAdicFriFolding::fold_matrix
 *   - log_arity == 1 optimized arity-2 path: fri/src/two_adic_pcs.rs:135-162.
 *   - log_arity > 1 generic decomposition path: fri/src/two_adic_pcs.rs:163-213.
 *
 * Contract:
 *   - log_arity must be >= 1 (asserts otherwise)
 *   - Matrix layout: row-major, height × (1u << log_arity) columns
 *   - matrix length must be height * (1u << log_arity)
 *   - out_vec length must be height (caller-allocated)
 *   - F = Goldilocks, EF = Goldilocks² (BinomialExtensionField<Goldilocks, 2>)
 *
 * Both branches oracle-byte-matched against Plonky3 82cfad73
 * (fri_fold_matrix_loga1.json + fri_fold_matrix.json).
 *
 * Aborts on allocation failure (matches Plonky3 Vec panic semantics).
 * ========================================================================== */
void fri_fold_matrix_fp2(
    gold_fp2_t        beta,
    unsigned          log_arity,
    size_t            height,
    const gold_fp2_t *matrix,
    gold_fp2_t       *out_vec);

#ifdef __cplusplus
}
#endif

#endif /* DNAC_FRI_FOLD_H */
