/**
 * @file fri_fold.c
 * @brief FRI fold — port of Plonky3 TwoAdicFriFolding (commit 82cfad73).
 *
 * Phases D.1 + D.2 + D.3 + D.4: lagrange_interpolate_at_fp_fp2 (static),
 * fri_fold_row_fp2, fri_fold_matrix_fp2 (log_arity == 1 + generic).
 * All branches oracle-byte-matched against Plonky3 82cfad73
 * (fri_fold_row.json + fri_fold_matrix_loga1.json + fri_fold_matrix.json).
 *
 * Every non-trivial block cites its Plonky3 source line range. If a line is
 * not traceable to Plonky3, it is a bug.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: Apache-2.0
 */

#include "fri_fold.h"

#include <stdlib.h>
#include <assert.h>

#include "zk_field_helpers.h"

/* ============================================================================
 * Local helper: fp2 is_zero
 *
 * Plonky3 Field::is_zero default (field/src/field.rs:989-991):
 *   fn is_zero(&self) -> bool { *self == Self::ZERO }
 * For BinomialExtensionField<F, 2>, Self::ZERO = [F::ZERO, F::ZERO], so
 * is_zero() == (a == 0 && b == 0). Both components canonical in [0, p) per
 * field_goldilocks.h invariant.
 * ========================================================================== */
static inline bool fp2_is_zero(gold_fp2_t x) {
    return gold_fp_is_zero(x.a) && gold_fp_is_zero(x.b);
}

/* ============================================================================
 * lagrange_interpolate_at_fp_fp2
 *
 * Plonky3 fri/src/two_adic_pcs.rs:220-260 birebir aktarım.
 *
 * Signature: F = Goldilocks, EF = BinomialExtensionField<Goldilocks, 2>.
 *   fn lagrange_interpolate_at<F: TwoAdicField, EF: ExtensionField<F>>(
 *       xs: &[F], ys: &[EF], z: EF) -> EF
 *
 * Assumption (Plonky3 line 241): xs lie in a coset of the 2^log2(n)-th roots
 * of unity. Caller must guarantee this; the weight_scale formula relies on it.
 *
 * Cross-field operation mappings (EF over F via Algebra<F>):
 *   - z - xs[i]:  EF - F  → via gold_fp2_sub(z, gold_fp2_from_base(xs[i]))
 *                 Plonky3 BinomialExtensionField Sub<A> (binomial_extension.rs:505-518)
 *                 routes through (a, b) - a' = (a - a', b), equivalent to subtracting
 *                 from the constant term. gold_fp2_from_base(xs[i]) = (xs[i], 0), so
 *                 fp2_sub gives (z.a - xs[i], z.b - 0) = (z.a - xs[i], z.b). Same value.
 *   - y * weight: EF * F  → via gold_fp2_mul(y, gold_fp2_from_base(weight))
 *                 Plonky3 BinomialExtensionField Mul<A> (binomial_extension.rs:562-573)
 *                 calls binomial_base_mul: (y.a * w, y.b * w). Our fp2_mul on
 *                 (y, (w,0)) via quadratic_mul (binomial_extension.rs:744-761):
 *                   res[0] = dot_product([y.a, y.b], [w, 0*W]) = y.a*w
 *                   res[1] = dot_product([y.a, y.b], [0, w])   = y.b*w
 *                 Same value.
 *
 * Output canonical (in [0, p) per gold_fp_t invariant); equality semantics
 * match Plonky3 PartialEq via as_canonical_u64.
 * ========================================================================== */
static gold_fp2_t lagrange_interpolate_at_fp_fp2(
    const gold_fp_t  *xs,
    const gold_fp2_t *ys,
    size_t            n,
    gold_fp2_t        z)
{
    /* Plonky3 line 225: debug_assert_eq!(xs.len(), ys.len());
       Mirrored: n is the single length parameter; caller's contract. */

    /* Plonky3 lines 228-230:
         if n == 0 { return EF::ZERO; } */
    if (n == 0) {
        return gold_fp2_zero();
    }

    /* Plonky3 lines 232-237:
         for i in 0..n {
             if (z - xs[i]).is_zero() { return ys[i]; }
         } */
    for (size_t i = 0; i < n; i++) {
        gold_fp2_t diff = gold_fp2_sub(z, gold_fp2_from_base(xs[i]));
        if (fp2_is_zero(diff)) {
            return ys[i];
        }
    }

    /* Plonky3 line 239: let log_n = log2_strict_usize(n); */
    size_t log_n = log2_strict_usize(n);

    /* Plonky3 line 242: let coset_power = xs[0].exp_power_of_2(log_n);
       Field::exp_power_of_2 default (field/src/field.rs:264-270):
         let mut res = self.dup();
         for _ in 0..power_log { res = res.square(); }
         res */
    gold_fp_t coset_power = xs[0];
    for (size_t i = 0; i < log_n; i++) {
        coset_power = gold_fp_sqr(coset_power);
    }

    /* Plonky3 line 243:
         let weight_scale = (F::from_usize(n) * coset_power).inverse(); */
    gold_fp_t n_fp = gold_fp_from_usize(n);
    gold_fp_t weight_scale = gold_fp_inv(gold_fp_mul(n_fp, coset_power));

    /* Plonky3 line 246:
         let diffs: Vec<_> = xs.iter().map(|&x| z - x).collect(); */
    gold_fp2_t *diffs = (gold_fp2_t *)malloc(sizeof(gold_fp2_t) * n);
    if (!diffs) {
        /* Plonky3 Vec allocation failure aborts; match that semantically. */
        abort();
    }
    for (size_t i = 0; i < n; i++) {
        diffs[i] = gold_fp2_sub(z, gold_fp2_from_base(xs[i]));
    }

    /* Plonky3 line 247:
         let diff_invs = batch_multiplicative_inverse(&diffs); */
    gold_fp2_t *diff_invs = (gold_fp2_t *)malloc(sizeof(gold_fp2_t) * n);
    if (!diff_invs) {
        free(diffs);
        abort();
    }
    gold_fp2_batch_inv_general(diffs, diff_invs, n);

    /* Plonky3 line 250:
         let l_z = diffs.iter().copied().product::<EF>();
       Plonky3 BinomialExtensionField Product (binomial_extension.rs:597-606):
         iter.reduce(|acc, x| acc * x).unwrap_or(Self::ONE)
       For n > 0 (guaranteed here), reduce starts with diffs[0]. */
    gold_fp2_t l_z = diffs[0];
    for (size_t i = 1; i < n; i++) {
        l_z = gold_fp2_mul(l_z, diffs[i]);
    }

    /* Plonky3 lines 253-258:
         let mut result = EF::ZERO;
         for ((&x, &y), &diff_inv) in xs.iter().zip(ys).zip(diff_invs.iter()) {
             let weight = x * weight_scale;
             result += y * weight * diff_inv;
         } */
    gold_fp2_t result = gold_fp2_zero();
    for (size_t i = 0; i < n; i++) {
        gold_fp_t  weight   = gold_fp_mul(xs[i], weight_scale);          /* F * F → F */
        gold_fp2_t y_weight = gold_fp2_mul(ys[i], gold_fp2_from_base(weight)); /* EF * F → EF (via from_base lift) */
        gold_fp2_t term     = gold_fp2_mul(y_weight, diff_invs[i]);      /* EF * EF → EF */
        result = gold_fp2_add(result, term);
    }

    /* Plonky3 line 259: result * l_z */
    gold_fp2_t out = gold_fp2_mul(result, l_z);

    free(diffs);
    free(diff_invs);
    return out;
}

/* ============================================================================
 * Phase D.1 test wrapper — calls the static lagrange_interpolate_at_fp_fp2
 * so test_fri_fold.c can drive it through the public ABI.
 * ========================================================================== */
gold_fp2_t fri_fold_test_lagrange_at_fp_fp2(
    const gold_fp_t  *xs,
    const gold_fp2_t *ys,
    size_t            n,
    gold_fp2_t        z)
{
    return lagrange_interpolate_at_fp_fp2(xs, ys, n, z);
}

/* ============================================================================
 * fri_fold_row_fp2 — Plonky3 two_adic_pcs.rs:109-132 birebir aktarım.
 *
 * Original Rust body:
 *   let arity = 1 << log_arity;
 *   let evals: Vec<_> = evals.collect();
 *   assert_eq!(evals.len(), arity, "Expected {} evaluations", arity);
 *
 *   let subgroup_start = F::two_adic_generator(log_height + log_arity)
 *       .exp_u64(reverse_bits_len(index, log_height) as u64);
 *   let mut xs: Vec<F> = F::two_adic_generator(log_arity)
 *       .shifted_powers(subgroup_start)
 *       .take(arity)
 *       .collect();
 *   reverse_slice_index_bits(&mut xs);
 *
 *   lagrange_interpolate_at(&xs, &evals, beta)
 * ========================================================================== */
gold_fp2_t fri_fold_row_fp2(
    size_t            index,
    unsigned          log_height,
    unsigned          log_arity,
    gold_fp2_t        beta,
    const gold_fp2_t *evals,
    size_t            evals_len)
{
    /* Plonky3 line 117: let arity = 1 << log_arity; */
    size_t arity = (size_t)1u << log_arity;

    /* Plonky3 line 119: assert_eq!(evals.len(), arity, "Expected {} evaluations", arity); */
    assert(evals_len == arity && "fri_fold_row_fp2: evals_len must equal 1u << log_arity");

    /* Plonky3 lines 122-123:
         let subgroup_start = F::two_adic_generator(log_height + log_arity)
             .exp_u64(reverse_bits_len(index, log_height) as u64);

       Note: Plonky3 uses (log_height + log_arity), NOT log_height alone. */
    gold_fp_t two_adic_g_combined = gold_fp_two_adic_generator(log_height + log_arity);
    uint64_t  rev = reverse_bits_len_u64((uint64_t)index, log_height);
    gold_fp_t subgroup_start = gold_fp_pow(two_adic_g_combined, rev);

    /* Plonky3 lines 124-127:
         let mut xs: Vec<F> = F::two_adic_generator(log_arity)
             .shifted_powers(subgroup_start)
             .take(arity)
             .collect();

       gold_fp_shifted_powers fills xs[i] = subgroup_start * g_arity^i for i in 0..arity. */
    gold_fp_t two_adic_g_arity = gold_fp_two_adic_generator(log_arity);
    gold_fp_t *xs = (gold_fp_t *)malloc(sizeof(gold_fp_t) * arity);
    if (!xs) {
        /* Plonky3 Vec allocation failure aborts. */
        abort();
    }
    gold_fp_shifted_powers(subgroup_start, two_adic_g_arity, xs, arity);

    /* Plonky3 line 128: reverse_slice_index_bits(&mut xs); */
    reverse_slice_index_bits_fp(xs, arity);

    /* Plonky3 line 131: lagrange_interpolate_at(&xs, &evals, beta) */
    gold_fp2_t result = lagrange_interpolate_at_fp_fp2(xs, evals, arity, beta);

    free(xs);
    return result;
}

/* ============================================================================
 * fri_fold_matrix_fp2 (log_arity == 1 optimized arity-2 path)
 *
 * Plonky3 fri/src/two_adic_pcs.rs:135-162 birebir aktarım (optimized branch).
 *
 * Original Rust body (log_arity == 1 branch):
 *   let g_inv = F::two_adic_generator(log2_strict_usize(m.height()) + 1).inverse();
 *   let mut halve_inv_powers = g_inv.shifted_powers(F::ONE.halve()).collect_n(m.height());
 *   reverse_slice_index_bits(&mut halve_inv_powers);
 *   m.par_rows()
 *       .zip(halve_inv_powers)
 *       .map(|(mut row, halve_inv_power)| {
 *           let (lo, hi) = row.next_tuple().unwrap();
 *           (lo + hi).halve() + (lo - hi) * beta * halve_inv_power
 *       })
 *       .collect()
 *
 * Math: out[i] = (lo + hi)/2 + (lo - hi) * beta * halve_inv_power[i]
 * where halve_inv_power[i] = (1/2) * g_inv^i (after bit-reversal).
 *
 * Phase D.3 implements ONLY this branch; log_arity > 1 (Plonky3 lines 163-213)
 * is deferred to Phase D.4.
 * ========================================================================== */
void fri_fold_matrix_fp2(
    gold_fp2_t        beta,
    unsigned          log_arity,
    size_t            height,
    const gold_fp2_t *matrix,
    gold_fp2_t       *out_vec)
{
    /* Plonky3 fri/src/two_adic_pcs.rs:135 expects log_arity >= 1. */
    assert(log_arity >= 1 && "fri_fold_matrix_fp2: log_arity must be >= 1");

    /* Height == 0 would produce an empty output; Plonky3 par_rows on an
       empty matrix yields an empty Vec. Match that semantics. */
    if (height == 0) {
        return;
    }

    if (log_arity == 1) {
        /* ====================================================================
         * Plonky3 fri/src/two_adic_pcs.rs:135-162 — optimized arity-2 path.
         *
         * Phase D.3 byte-verified (fri_fold_matrix_loga1.json, 330/330 PASS).
         * Body unchanged in Phase D.4.
         * ==================================================================== */

        /* Plonky3 line 149:
             let g_inv = F::two_adic_generator(log2_strict_usize(m.height()) + 1).inverse(); */
        size_t lb_h = log2_strict_usize(height);
        gold_fp_t g     = gold_fp_two_adic_generator((unsigned)(lb_h + 1));
        gold_fp_t g_inv = gold_fp_inv(g);

        /* Plonky3 line 153:
             let mut halve_inv_powers = g_inv.shifted_powers(F::ONE.halve()).collect_n(m.height()); */
        gold_fp_t *halve_inv_powers = (gold_fp_t *)malloc(sizeof(gold_fp_t) * height);
        if (!halve_inv_powers) {
            abort();
        }
        gold_fp_t one_halve = gold_fp_halve(gold_fp_one());
        gold_fp_shifted_powers(one_halve, g_inv, halve_inv_powers, height);

        /* Plonky3 line 154: reverse_slice_index_bits(&mut halve_inv_powers); */
        reverse_slice_index_bits_fp(halve_inv_powers, height);

        /* Plonky3 lines 156-162: fold loop. */
        for (size_t i = 0; i < height; i++) {
            gold_fp2_t lo = matrix[2 * i];
            gold_fp2_t hi = matrix[2 * i + 1];

            gold_fp2_t sum_half  = gold_fp2_halve(gold_fp2_add(lo, hi));
            gold_fp2_t diff      = gold_fp2_sub(lo, hi);
            gold_fp2_t diff_beta = gold_fp2_mul(diff, beta);
            gold_fp2_t diff_beta_h = gold_fp2_mul(diff_beta, gold_fp2_from_base(halve_inv_powers[i]));

            out_vec[i] = gold_fp2_add(sum_half, diff_beta_h);
        }

        free(halve_inv_powers);
        return;
    }

    /* ============================================================================
     * Plonky3 fri/src/two_adic_pcs.rs:163-213 — generic decomposition branch.
     *
     * Decompose arity-2^k fold into k sequential arity-2 folds with challenges
     * beta, beta^2, beta^4, ..., beta^{2^{k-1}}. Phase D.4 implementation.
     *
     * Original Rust body (top of else branch):
     *   let mut data = m.to_row_major_matrix().values;
     *   let initial_height = data.len() / 2;
     *   let g_inv = F::two_adic_generator(log2_strict_usize(initial_height) + 1).inverse();
     *   let mut halve_inv_powers = g_inv
     *       .shifted_powers(F::ONE.halve())
     *       .collect_n(initial_height);
     *   reverse_slice_index_bits(&mut halve_inv_powers);
     *
     *   let two = F::ONE + F::ONE;
     *   let mut current_beta = beta;
     *   let mut next_data = EF::zero_vec(initial_height);
     *
     *   for step in 0..log_arity {
     *       let current_len = data.len();
     *       let height = current_len / 2;
     *       if step > 0 {
     *           for j in 0..height {
     *               halve_inv_powers[j] = two * halve_inv_powers[j << 1].square();
     *           }
     *       }
     *       next_data[..height]
     *           .par_iter_mut()
     *           .zip(data.par_chunks_exact(2))
     *           .zip(&halve_inv_powers[..height])
     *           .for_each(|((out, chunk), &halve_inv_power)| {
     *               let lo = chunk[0];
     *               let hi = chunk[1];
     *               *out = (lo + hi).halve() + (lo - hi) * current_beta * halve_inv_power;
     *           });
     *       current_beta = current_beta.square();
     *       data.truncate(height);
     *       data.copy_from_slice(&next_data[..height]);
     *   }
     *   data
     * ============================================================================ */

    /* Plonky3 line 172: let mut data = m.to_row_major_matrix().values;
       Input matrix is row-major with height × arity columns; data length = height * arity. */
    size_t arity        = (size_t)1u << log_arity;
    size_t data_len     = height * arity;
    gold_fp2_t *data = (gold_fp2_t *)malloc(sizeof(gold_fp2_t) * data_len);
    if (!data) abort();
    /* C analog of taking ownership of the row-major Vec. */
    for (size_t i = 0; i < data_len; i++) data[i] = matrix[i];

    /* Plonky3 line 174: let initial_height = data.len() / 2; */
    size_t initial_height = data_len / 2;

    /* Plonky3 line 175:
         let g_inv = F::two_adic_generator(log2_strict_usize(initial_height) + 1).inverse(); */
    size_t lb_ih  = log2_strict_usize(initial_height);
    gold_fp_t g     = gold_fp_two_adic_generator((unsigned)(lb_ih + 1));
    gold_fp_t g_inv = gold_fp_inv(g);

    /* Plonky3 lines 176-178:
         let mut halve_inv_powers = g_inv.shifted_powers(F::ONE.halve()).collect_n(initial_height); */
    gold_fp_t *halve_inv_powers = (gold_fp_t *)malloc(sizeof(gold_fp_t) * initial_height);
    if (!halve_inv_powers) { free(data); abort(); }
    gold_fp_t one_halve = gold_fp_halve(gold_fp_one());
    gold_fp_shifted_powers(one_halve, g_inv, halve_inv_powers, initial_height);

    /* Plonky3 line 179: reverse_slice_index_bits(&mut halve_inv_powers); */
    reverse_slice_index_bits_fp(halve_inv_powers, initial_height);

    /* Plonky3 line 181: let two = F::ONE + F::ONE; */
    gold_fp_t two = gold_fp_add(gold_fp_one(), gold_fp_one());

    /* Plonky3 line 182: let mut current_beta = beta; */
    gold_fp2_t current_beta = beta;

    /* Plonky3 line 183: let mut next_data = EF::zero_vec(initial_height); */
    gold_fp2_t *next_data = (gold_fp2_t *)malloc(sizeof(gold_fp2_t) * initial_height);
    if (!next_data) { free(halve_inv_powers); free(data); abort(); }
    for (size_t i = 0; i < initial_height; i++) next_data[i] = gold_fp2_zero();

    /* Track current data length as it shrinks through iterations
       (Rust's Vec::truncate + copy_from_slice pattern). */
    size_t current_len = data_len;

    /* Plonky3 line 185: for step in 0..log_arity { */
    for (unsigned step = 0; step < log_arity; step++) {
        /* Plonky3 lines 186-187:
             let current_len = data.len();
             let height = current_len / 2; */
        size_t step_height = current_len / 2;

        /* Plonky3 lines 189-193:
             if step > 0 {
                 for j in 0..height {
                     halve_inv_powers[j] = two * halve_inv_powers[j << 1].square();
                 }
             } */
        if (step > 0) {
            for (size_t j = 0; j < step_height; j++) {
                gold_fp_t sq = gold_fp_sqr(halve_inv_powers[j << 1]);
                halve_inv_powers[j] = gold_fp_mul(two, sq);
            }
        }

        /* Plonky3 lines 194-204: fold loop into next_data[..height].
           Sequential equivalent of the par_iter_mut / par_chunks_exact / zip chain.
           IndexedParallelIterator::zip is order-preserving, so sequential output
           is byte-identical. */
        for (size_t j = 0; j < step_height; j++) {
            gold_fp2_t lo = data[2 * j];
            gold_fp2_t hi = data[2 * j + 1];

            /* *out = (lo + hi).halve() + (lo - hi) * current_beta * halve_inv_power; */
            gold_fp2_t sum_half  = gold_fp2_halve(gold_fp2_add(lo, hi));
            gold_fp2_t diff      = gold_fp2_sub(lo, hi);
            gold_fp2_t diff_beta = gold_fp2_mul(diff, current_beta);
            gold_fp2_t diff_beta_h = gold_fp2_mul(diff_beta,
                                                  gold_fp2_from_base(halve_inv_powers[j]));
            next_data[j] = gold_fp2_add(sum_half, diff_beta_h);
        }

        /* Plonky3 line 205: current_beta = current_beta.square(); */
        current_beta = gold_fp2_sqr(current_beta);

        /* Plonky3 lines 208-209:
             data.truncate(height);
             data.copy_from_slice(&next_data[..height]);
           In C we just shrink the logical length tracker and overwrite the prefix. */
        current_len = step_height;
        for (size_t j = 0; j < step_height; j++) data[j] = next_data[j];
    }

    /* Plonky3 line 212: data (returned as Vec<EF>).
       After log_arity iterations the active length equals m.height(). */
    assert(current_len == height && "fri_fold_matrix_fp2: invariant violation: final data length != height");
    for (size_t i = 0; i < height; i++) out_vec[i] = data[i];

    free(next_data);
    free(halve_inv_powers);
    free(data);
}
