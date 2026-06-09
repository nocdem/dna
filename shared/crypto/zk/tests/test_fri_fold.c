/**
 * @file test_fri_fold.c
 * @brief Phase D.1 sanity tests for lagrange_interpolate_at_fp_fp2.
 *
 * Plonky3's `lagrange_interpolate_at` is `fn` (file-private) in
 * fri/src/two_adic_pcs.rs, so we cannot call it directly from the Rust oracle
 * to byte-match. Standalone tests in this phase verify algebraic correctness
 * using known properties:
 *
 *   - n == 0 returns EF::ZERO (Plonky3 line 229)
 *   - z == xs[i] returns ys[i] (Plonky3 lines 233-237 early return)
 *   - Lagrange of polynomial p evaluated at coset xs reproduces p(z) for any
 *     polynomial of degree < n (mathematical contract; coset xs assumed)
 *
 * Byte-match against Plonky3 will be performed indirectly via fri_fold_row
 * oracle vectors in Phase D.2.
 *
 * Exit codes:
 *   0  all cases passed
 *   1  at least one mismatch
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <inttypes.h>
#include <stdbool.h>

#include "../field_goldilocks.h"
#include "../zk_field_helpers.h"
#include "../fri_fold.h"

static int g_passed = 0;
static int g_failed = 0;

static void check_fp2_eq(const char *label, gold_fp2_t got, gold_fp2_t want) {
    if (gold_fp2_eq(got, want)) {
        g_passed++;
        printf("  %-60s PASS\n", label);
    } else {
        g_failed++;
        printf("  %-60s FAIL  got=(%" PRIu64 ",%" PRIu64
               ") want=(%" PRIu64 ",%" PRIu64 ")\n",
               label, got.a.v, got.b.v, want.a.v, want.b.v);
    }
}

/* Build xs = [1, ω, ω², ..., ω^(n-1)] where ω = two_adic_generator(log_n).
   This is the n-th roots-of-unity subgroup — a valid coset (shift = 1)
   per Plonky3's lagrange_interpolate_at invariant (two_adic_pcs.rs:241). */
static void build_subgroup_xs(gold_fp_t *xs, size_t n, unsigned log_n) {
    gold_fp_t omega = gold_fp_two_adic_generator(log_n);
    gold_fp_shifted_powers(gold_fp_one(), omega, xs, n);
}

/* Evaluate polynomial p(x) = c0 + c1*x at fp2 z, with c0,c1 in fp2 and x in F. */
static gold_fp2_t poly_deg1_at_z(gold_fp2_t c0, gold_fp2_t c1, gold_fp2_t z) {
    return gold_fp2_add(c0, gold_fp2_mul(c1, z));
}

/* Evaluate polynomial p(x) = c0 + c1*x at F point x (lifted to fp2). */
static gold_fp2_t poly_deg1_at_x(gold_fp2_t c0, gold_fp2_t c1, gold_fp_t x_fp) {
    gold_fp2_t x_lifted = gold_fp2_from_base(x_fp);
    return gold_fp2_add(c0, gold_fp2_mul(c1, x_lifted));
}

/* ============================================================================
 * T1: n == 0 returns EF::ZERO  (Plonky3 two_adic_pcs.rs:229)
 * ========================================================================== */
static void test_n0_returns_zero(void) {
    printf("\nT1: lagrange(n=0) returns EF::ZERO\n");
    gold_fp2_t z = gold_fp2_new(gold_fp_from_u64(7), gold_fp_from_u64(11));
    gold_fp2_t got = fri_fold_test_lagrange_at_fp_fp2(NULL, NULL, 0, z);
    check_fp2_eq("lagrange(n=0)", got, gold_fp2_zero());
}

/* ============================================================================
 * T2: z == xs[i] returns ys[i]  (Plonky3 two_adic_pcs.rs:233-237)
 * ========================================================================== */
static void test_early_return(void) {
    printf("\nT2: lagrange(z = xs[i]) == ys[i] (early return)\n");
    const struct {
        size_t n;
        unsigned log_n;
        size_t check_index;
    } cases[] = {
        { 2, 1, 0 }, { 2, 1, 1 },
        { 4, 2, 0 }, { 4, 2, 2 }, { 4, 2, 3 },
        { 8, 3, 0 }, { 8, 3, 5 }, { 8, 3, 7 },
        { 16, 4, 0 }, { 16, 4, 9 }, { 16, 4, 15 },
    };
    for (size_t c = 0; c < sizeof(cases) / sizeof(cases[0]); c++) {
        size_t n = cases[c].n;
        unsigned log_n = cases[c].log_n;
        size_t k = cases[c].check_index;

        gold_fp_t *xs = (gold_fp_t *)malloc(sizeof(gold_fp_t) * n);
        gold_fp2_t *ys = (gold_fp2_t *)malloc(sizeof(gold_fp2_t) * n);
        if (!xs || !ys) { free(xs); free(ys); g_failed++; continue; }

        build_subgroup_xs(xs, n, log_n);
        for (size_t i = 0; i < n; i++) {
            /* Deterministic distinct ys. */
            ys[i] = gold_fp2_new(
                gold_fp_from_u64(0xC0FFEE00ULL + (uint64_t)i),
                gold_fp_from_u64(0xDEADBEEFULL + (uint64_t)i * 31));
        }
        /* z = xs[k] lifted to fp2 — triggers early return. */
        gold_fp2_t z = gold_fp2_from_base(xs[k]);
        gold_fp2_t got = fri_fold_test_lagrange_at_fp_fp2(xs, ys, n, z);

        char label[80];
        snprintf(label, sizeof(label), "early-return n=%zu k=%zu", n, k);
        check_fp2_eq(label, got, ys[k]);

        free(xs); free(ys);
    }
}

/* ============================================================================
 * T3: Lagrange of constant polynomial = constant
 *
 * If ys[i] = c for all i, the interpolating polynomial is p(x) = c
 * (degree 0 < n). lagrange(xs, ys, z) must equal c for any z.
 * ========================================================================== */
static void test_constant_polynomial(void) {
    printf("\nT3: lagrange(constant ys) == constant for any z\n");
    const struct { size_t n; unsigned log_n; } cases[] = {
        { 2, 1 }, { 4, 2 }, { 8, 3 }, { 16, 4 },
    };
    for (size_t c = 0; c < sizeof(cases) / sizeof(cases[0]); c++) {
        size_t n = cases[c].n;
        unsigned log_n = cases[c].log_n;
        gold_fp_t  *xs = (gold_fp_t *)malloc(sizeof(gold_fp_t) * n);
        gold_fp2_t *ys = (gold_fp2_t *)malloc(sizeof(gold_fp2_t) * n);
        if (!xs || !ys) { free(xs); free(ys); g_failed++; continue; }

        build_subgroup_xs(xs, n, log_n);
        gold_fp2_t constant = gold_fp2_new(
            gold_fp_from_u64(0x12345678ULL),
            gold_fp_from_u64(0x9ABCDEF0ULL));
        for (size_t i = 0; i < n; i++) ys[i] = constant;

        /* z is non-coset fp2 (b != 0) to avoid accidentally matching xs[i]. */
        gold_fp2_t z = gold_fp2_new(
            gold_fp_from_u64(0xAAAAAAULL),
            gold_fp_from_u64(0xBBBBBBULL));
        gold_fp2_t got = fri_fold_test_lagrange_at_fp_fp2(xs, ys, n, z);

        char label[80];
        snprintf(label, sizeof(label), "constant-poly n=%zu", n);
        check_fp2_eq(label, got, constant);

        free(xs); free(ys);
    }
}

/* ============================================================================
 * T4: Lagrange of degree-1 polynomial reproduces p(z)
 *
 * For p(x) = c0 + c1*x with c0, c1 in fp2, and ys[i] = p(xs[i]):
 *   lagrange(xs, ys, z) == p(z)  for any z, when n >= 2.
 * ========================================================================== */
static void test_degree1_polynomial(void) {
    printf("\nT4: lagrange(degree-1 poly evaluations) == p(z)\n");
    const struct { size_t n; unsigned log_n; } cases[] = {
        { 2, 1 }, { 4, 2 }, { 8, 3 }, { 16, 4 },
    };
    /* Fixed deterministic polynomial coefficients. */
    gold_fp2_t c0 = gold_fp2_new(gold_fp_from_u64(3),  gold_fp_from_u64(5));
    gold_fp2_t c1 = gold_fp2_new(gold_fp_from_u64(7),  gold_fp_from_u64(11));

    /* Fixed deterministic z (extension-field, b != 0). */
    gold_fp2_t z = gold_fp2_new(
        gold_fp_from_u64(0x10000001ULL),
        gold_fp_from_u64(0x20000002ULL));

    for (size_t c = 0; c < sizeof(cases) / sizeof(cases[0]); c++) {
        size_t n = cases[c].n;
        unsigned log_n = cases[c].log_n;
        gold_fp_t  *xs = (gold_fp_t *)malloc(sizeof(gold_fp_t) * n);
        gold_fp2_t *ys = (gold_fp2_t *)malloc(sizeof(gold_fp2_t) * n);
        if (!xs || !ys) { free(xs); free(ys); g_failed++; continue; }

        build_subgroup_xs(xs, n, log_n);
        for (size_t i = 0; i < n; i++) {
            ys[i] = poly_deg1_at_x(c0, c1, xs[i]);
        }
        gold_fp2_t expected = poly_deg1_at_z(c0, c1, z);
        gold_fp2_t got = fri_fold_test_lagrange_at_fp_fp2(xs, ys, n, z);

        char label[80];
        snprintf(label, sizeof(label), "degree-1 poly n=%zu", n);
        check_fp2_eq(label, got, expected);

        free(xs); free(ys);
    }
}

/* ============================================================================
 * T5: Random fp2 ys with the early-return path (sanity that the function
 * returns coherent fp2 values without crashing for varied inputs).
 *
 * This is a smoke check; correctness is established by T1-T4.
 * ========================================================================== */
static void test_random_smoke(void) {
    printf("\nT5: random fp2 ys, varied n — smoke check\n");
    const size_t sizes[] = { 2, 4, 8, 16 };
    const unsigned logs[] = { 1, 2, 3, 4 };

    for (size_t c = 0; c < sizeof(sizes) / sizeof(sizes[0]); c++) {
        size_t n = sizes[c];
        unsigned log_n = logs[c];
        gold_fp_t  *xs = (gold_fp_t *)malloc(sizeof(gold_fp_t) * n);
        gold_fp2_t *ys = (gold_fp2_t *)malloc(sizeof(gold_fp2_t) * n);
        if (!xs || !ys) { free(xs); free(ys); g_failed++; continue; }

        build_subgroup_xs(xs, n, log_n);
        for (size_t i = 0; i < n; i++) {
            uint64_t a = ((uint64_t)i * 0x9E3779B97F4A7C15ULL) ^ 0xCAFEULL;
            uint64_t b = ((uint64_t)i * 0xBF58476D1CE4E5B9ULL) ^ 0xBABEULL;
            ys[i] = gold_fp2_new(gold_fp_from_u64(a), gold_fp_from_u64(b));
        }
        gold_fp2_t z = gold_fp2_new(
            gold_fp_from_u64(0x0F0F0F0FULL),
            gold_fp_from_u64(0xF0F0F0F0ULL));
        gold_fp2_t got = fri_fold_test_lagrange_at_fp_fp2(xs, ys, n, z);

        /* Smoke: result is a valid fp2 element. Both components must be
           canonical [0, p); gold_fp_to_u64 enforces this. */
        uint64_t a = gold_fp_to_u64(got.a);
        uint64_t b = gold_fp_to_u64(got.b);
        if (a < GOLDILOCKS_P && b < GOLDILOCKS_P) {
            g_passed++;
            char label[80];
            snprintf(label, sizeof(label),
                     "smoke n=%zu returns canonical fp2", n);
            printf("  %-60s PASS\n", label);
        } else {
            g_failed++;
            printf("  smoke n=%zu non-canonical fp2 (a=%" PRIu64 ", b=%" PRIu64 ")\n",
                   n, a, b);
        }
        free(xs); free(ys);
    }
}

int main(void) {
    printf("============================================================\n");
    printf("Phase D.1 — lagrange_interpolate_at_fp_fp2 sanity tests\n");
    printf("Plonky3 pin: 82cfad73cd734d37a0d51953094f970c531817ec\n");
    printf("Plonky3 source: fri/src/two_adic_pcs.rs:220-260\n");
    printf("============================================================\n");

    test_n0_returns_zero();
    test_early_return();
    test_constant_polynomial();
    test_degree1_polynomial();
    test_random_smoke();

    printf("\n--------------------------------------------------\n");
    printf("Total: %d passed, %d failed\n", g_passed, g_failed);
    printf("PHASE D.1 GATE: %s — lagrange_interpolate_at_fp_fp2\n",
           g_failed == 0 ? "GREEN" : "RED");

    return g_failed == 0 ? 0 : 1;
}
