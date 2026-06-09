/**
 * @file test_ntt_goldilocks.c
 * @brief Goldilocks NTT/iNTT self-test (Sub-sprint 3.5a).
 *
 * No Plonky3 oracle in this sub-sprint — we validate via:
 *   T0: bit-reverse function (hand-computed cases)
 *   T1: round-trip iNTT(NTT(x)) == x, base + ext, sizes 1..2^14
 *   T2: brute-force O(N²) DFT cross-check, base + ext, sizes 2..256
 *   T3: linearity NTT(α·a + β·b) == α·NTT(a) + β·NTT(b)
 *   T4: convolution theorem (cyclic): NTT(a ⊛ b) == NTT(a) ⊙ NTT(b)
 *   T5: edges — all-zero, constant vector, log_n=0 identity
 *
 * Plonky3 oracle byte-match is deferred to Sub-sprint 3.5c where LDE outputs
 * meet the prover wire format; at this layer the convention (natural-order
 * input, natural-order output, ω from gold_fp_two_adic_generator) is what
 * the future fri_verifier wiring will consume, and round-trip + brute-force
 * pin it. (Note: the legacy fri_commit/fri_query modules were deleted on
 * 2026-05-23 per SUBAGENT_AUDIT_2026_05_23.md.)
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
#include "../ntt_goldilocks.h"

static int total_passed = 0;
static int total_failed = 0;

static void assert_pass(const char *label, bool ok) {
    if (ok) { total_passed++; printf("  %-58s PASS\n", label); }
    else    { total_failed++; printf("  %-58s FAIL\n", label); }
}

/* ===== xorshift64 PRNG for deterministic random input generation ===== */
static uint64_t prng_state;
static void prng_seed(uint64_t seed) { prng_state = seed ? seed : 1ULL; }
static uint64_t prng_next(void) {
    prng_state ^= prng_state << 13;
    prng_state ^= prng_state >> 7;
    prng_state ^= prng_state << 17;
    return prng_state;
}

static gold_fp_t prng_fp(void) {
    return gold_fp_from_u64(prng_next());
}
static gold_fp2_t prng_fp2(void) {
    return gold_fp2_new(prng_fp(), prng_fp());
}

/* ===== Brute-force O(N²) DFT (base field) ===== */
static void brute_dft_fp(const gold_fp_t *x, gold_fp_t *y, unsigned log_n) {
    if (log_n == 0u) { y[0] = x[0]; return; }
    uint32_t n = 1u << log_n;
    gold_fp_t omega = gold_fp_two_adic_generator(log_n);
    for (uint32_t k = 0; k < n; k++) {
        gold_fp_t sum = gold_fp_zero();
        gold_fp_t omega_k = gold_fp_pow(omega, (uint64_t)k);
        gold_fp_t omega_jk = gold_fp_one();
        for (uint32_t j = 0; j < n; j++) {
            sum = gold_fp_add(sum, gold_fp_mul(x[j], omega_jk));
            omega_jk = gold_fp_mul(omega_jk, omega_k);
        }
        y[k] = sum;
    }
}

/* ===== Brute-force O(N²) DFT (extension field) ===== */
static void brute_dft_fp2(const gold_fp2_t *x, gold_fp2_t *y, unsigned log_n) {
    if (log_n == 0u) { y[0] = x[0]; return; }
    uint32_t n = 1u << log_n;
    gold_fp_t  omega_base = gold_fp_two_adic_generator(log_n);
    for (uint32_t k = 0; k < n; k++) {
        gold_fp2_t sum = gold_fp2_zero();
        gold_fp_t  omega_k_base = gold_fp_pow(omega_base, (uint64_t)k);
        gold_fp2_t omega_k = gold_fp2_from_base(omega_k_base);
        gold_fp2_t omega_jk = gold_fp2_one();
        for (uint32_t j = 0; j < n; j++) {
            sum = gold_fp2_add(sum, gold_fp2_mul(x[j], omega_jk));
            omega_jk = gold_fp2_mul(omega_jk, omega_k);
        }
        y[k] = sum;
    }
}

/* ===== Helpers ===== */
static bool fp_arr_eq(const gold_fp_t *a, const gold_fp_t *b, uint32_t n) {
    for (uint32_t i = 0; i < n; i++) if (!gold_fp_eq(a[i], b[i])) return false;
    return true;
}
static bool fp2_arr_eq(const gold_fp2_t *a, const gold_fp2_t *b, uint32_t n) {
    for (uint32_t i = 0; i < n; i++) if (!gold_fp2_eq(a[i], b[i])) return false;
    return true;
}

/* ===== T0: bit-reverse function ===== */
static void test_bit_reverse(void) {
    /* log_n=3: 0b001 → 0b100 = 4; 0b110 → 0b011 = 3 */
    assert_pass("bit_reverse(0b001, 3) == 4", ntt_bit_reverse_u32(1u, 3) == 4u);
    assert_pass("bit_reverse(0b110, 3) == 3", ntt_bit_reverse_u32(6u, 3) == 3u);
    /* log_n=4: 0b0001 → 0b1000 = 8 */
    assert_pass("bit_reverse(0b0001, 4) == 8", ntt_bit_reverse_u32(1u, 4) == 8u);
    /* log_n=0: identity (no bits) */
    assert_pass("bit_reverse(*, 0) == 0", ntt_bit_reverse_u32(123u, 0) == 0u);
    /* Involution: reverse(reverse(x)) == x */
    bool involution = true;
    for (uint32_t x = 0; x < 1024; x++) {
        if (ntt_bit_reverse_u32(ntt_bit_reverse_u32(x, 10), 10) != x) {
            involution = false; break;
        }
    }
    assert_pass("bit_reverse is involution (log_n=10)", involution);
}

/* ===== T1: round-trip ===== */
static void test_roundtrip_fp(unsigned log_n) {
    uint32_t n = 1u << log_n;
    gold_fp_t *a = (gold_fp_t *)malloc(n * sizeof(gold_fp_t));
    gold_fp_t *b = (gold_fp_t *)malloc(n * sizeof(gold_fp_t));
    prng_seed(0x5EEDULL ^ ((uint64_t)log_n * 0xDEADBEEFULL));
    for (uint32_t i = 0; i < n; i++) a[i] = prng_fp();
    memcpy(b, a, n * sizeof(gold_fp_t));
    ntt_goldilocks_forward(b, log_n);
    ntt_goldilocks_inverse(b, log_n);
    char lbl[64]; snprintf(lbl, sizeof(lbl), "round-trip fp log_n=%u (N=%u)", log_n, n);
    assert_pass(lbl, fp_arr_eq(a, b, n));
    free(a); free(b);
}

static void test_roundtrip_fp2(unsigned log_n) {
    uint32_t n = 1u << log_n;
    gold_fp2_t *a = (gold_fp2_t *)malloc(n * sizeof(gold_fp2_t));
    gold_fp2_t *b = (gold_fp2_t *)malloc(n * sizeof(gold_fp2_t));
    prng_seed(0xC0DEULL ^ ((uint64_t)log_n * 0x12345ULL));
    for (uint32_t i = 0; i < n; i++) a[i] = prng_fp2();
    memcpy(b, a, n * sizeof(gold_fp2_t));
    ntt_goldilocks_ext_forward(b, log_n);
    ntt_goldilocks_ext_inverse(b, log_n);
    char lbl[64]; snprintf(lbl, sizeof(lbl), "round-trip fp2 log_n=%u (N=%u)", log_n, n);
    assert_pass(lbl, fp2_arr_eq(a, b, n));
    free(a); free(b);
}

/* ===== T2: brute-force cross-check ===== */
static void test_bruteforce_fp(unsigned log_n) {
    uint32_t n = 1u << log_n;
    gold_fp_t *a   = (gold_fp_t *)malloc(n * sizeof(gold_fp_t));
    gold_fp_t *via_ntt   = (gold_fp_t *)malloc(n * sizeof(gold_fp_t));
    gold_fp_t *via_brute = (gold_fp_t *)malloc(n * sizeof(gold_fp_t));
    prng_seed(0xBEEFULL ^ ((uint64_t)log_n * 0x9999ULL));
    for (uint32_t i = 0; i < n; i++) a[i] = prng_fp();
    memcpy(via_ntt, a, n * sizeof(gold_fp_t));
    ntt_goldilocks_forward(via_ntt, log_n);
    brute_dft_fp(a, via_brute, log_n);
    char lbl[64]; snprintf(lbl, sizeof(lbl), "bruteforce match fp log_n=%u (N=%u)", log_n, n);
    assert_pass(lbl, fp_arr_eq(via_ntt, via_brute, n));
    free(a); free(via_ntt); free(via_brute);
}

static void test_bruteforce_fp2(unsigned log_n) {
    uint32_t n = 1u << log_n;
    gold_fp2_t *a   = (gold_fp2_t *)malloc(n * sizeof(gold_fp2_t));
    gold_fp2_t *via_ntt   = (gold_fp2_t *)malloc(n * sizeof(gold_fp2_t));
    gold_fp2_t *via_brute = (gold_fp2_t *)malloc(n * sizeof(gold_fp2_t));
    prng_seed(0xCAFEULL ^ ((uint64_t)log_n * 0x4242ULL));
    for (uint32_t i = 0; i < n; i++) a[i] = prng_fp2();
    memcpy(via_ntt, a, n * sizeof(gold_fp2_t));
    ntt_goldilocks_ext_forward(via_ntt, log_n);
    brute_dft_fp2(a, via_brute, log_n);
    char lbl[64]; snprintf(lbl, sizeof(lbl), "bruteforce match fp2 log_n=%u (N=%u)", log_n, n);
    assert_pass(lbl, fp2_arr_eq(via_ntt, via_brute, n));
    free(a); free(via_ntt); free(via_brute);
}

/* ===== T3: linearity ===== */
static void test_linearity_fp(unsigned log_n) {
    uint32_t n = 1u << log_n;
    gold_fp_t *a    = (gold_fp_t *)malloc(n * sizeof(gold_fp_t));
    gold_fp_t *b    = (gold_fp_t *)malloc(n * sizeof(gold_fp_t));
    gold_fp_t *sum1 = (gold_fp_t *)malloc(n * sizeof(gold_fp_t));
    gold_fp_t *sum2 = (gold_fp_t *)malloc(n * sizeof(gold_fp_t));
    prng_seed(0xABCDULL ^ ((uint64_t)log_n * 0x77ULL));
    for (uint32_t i = 0; i < n; i++) { a[i] = prng_fp(); b[i] = prng_fp(); }

    /* sum1 = NTT(a + b) */
    for (uint32_t i = 0; i < n; i++) sum1[i] = gold_fp_add(a[i], b[i]);
    ntt_goldilocks_forward(sum1, log_n);

    /* sum2 = NTT(a) + NTT(b) */
    gold_fp_t *ta = (gold_fp_t *)malloc(n * sizeof(gold_fp_t));
    gold_fp_t *tb = (gold_fp_t *)malloc(n * sizeof(gold_fp_t));
    memcpy(ta, a, n * sizeof(gold_fp_t));
    memcpy(tb, b, n * sizeof(gold_fp_t));
    ntt_goldilocks_forward(ta, log_n);
    ntt_goldilocks_forward(tb, log_n);
    for (uint32_t i = 0; i < n; i++) sum2[i] = gold_fp_add(ta[i], tb[i]);

    char lbl[64]; snprintf(lbl, sizeof(lbl), "linearity fp log_n=%u", log_n);
    assert_pass(lbl, fp_arr_eq(sum1, sum2, n));
    free(a); free(b); free(sum1); free(sum2); free(ta); free(tb);
}

/* ===== T4: cyclic convolution theorem ===== */
/* NTT(a ⊛ b) == NTT(a) ⊙ NTT(b)  where ⊛ is cyclic convolution mod x^N - 1. */
static void test_convolution_fp(unsigned log_n) {
    uint32_t n = 1u << log_n;
    gold_fp_t *a = (gold_fp_t *)malloc(n * sizeof(gold_fp_t));
    gold_fp_t *b = (gold_fp_t *)malloc(n * sizeof(gold_fp_t));
    gold_fp_t *c_direct = (gold_fp_t *)calloc(n, sizeof(gold_fp_t));
    gold_fp_t *c_via_ntt = (gold_fp_t *)malloc(n * sizeof(gold_fp_t));
    prng_seed(0xC0CADAULL ^ ((uint64_t)log_n * 0x88ULL));
    for (uint32_t i = 0; i < n; i++) { a[i] = prng_fp(); b[i] = prng_fp(); }

    /* Direct cyclic convolution: c[k] = Σ_{j} a[j] * b[(k-j) mod N] */
    for (uint32_t k = 0; k < n; k++) {
        gold_fp_t sum = gold_fp_zero();
        for (uint32_t j = 0; j < n; j++) {
            uint32_t idx = (k + n - j) % n;
            sum = gold_fp_add(sum, gold_fp_mul(a[j], b[idx]));
        }
        c_direct[k] = sum;
    }

    /* Via NTT: c = iNTT( NTT(a) .* NTT(b) ) */
    gold_fp_t *ta = (gold_fp_t *)malloc(n * sizeof(gold_fp_t));
    gold_fp_t *tb = (gold_fp_t *)malloc(n * sizeof(gold_fp_t));
    memcpy(ta, a, n * sizeof(gold_fp_t));
    memcpy(tb, b, n * sizeof(gold_fp_t));
    ntt_goldilocks_forward(ta, log_n);
    ntt_goldilocks_forward(tb, log_n);
    for (uint32_t i = 0; i < n; i++) c_via_ntt[i] = gold_fp_mul(ta[i], tb[i]);
    ntt_goldilocks_inverse(c_via_ntt, log_n);

    char lbl[64]; snprintf(lbl, sizeof(lbl), "cyclic conv fp log_n=%u", log_n);
    assert_pass(lbl, fp_arr_eq(c_direct, c_via_ntt, n));
    free(a); free(b); free(c_direct); free(c_via_ntt); free(ta); free(tb);
}

/* ===== T5: edges ===== */
static void test_edges(void) {
    /* All-zero input → all-zero output. */
    gold_fp_t z[8] = {0};
    for (int i = 0; i < 8; i++) z[i] = gold_fp_zero();
    ntt_goldilocks_forward(z, 3);
    bool z_ok = true;
    for (int i = 0; i < 8; i++) if (!gold_fp_is_zero(z[i])) { z_ok = false; break; }
    assert_pass("all-zero input → all-zero output (N=8)", z_ok);

    /* Constant vector c → DC bin: y[0] = N*c, y[1..] = 0. */
    gold_fp_t c[8];
    gold_fp_t val = gold_fp_from_u64(42);
    for (int i = 0; i < 8; i++) c[i] = val;
    ntt_goldilocks_forward(c, 3);
    gold_fp_t expected_dc = gold_fp_from_u64(8u * 42u);
    bool dc_ok = gold_fp_eq(c[0], expected_dc);
    for (int i = 1; i < 8; i++) if (!gold_fp_is_zero(c[i])) { dc_ok = false; break; }
    assert_pass("constant vector → only DC bin nonzero (N=8)", dc_ok);

    /* Single-element (log_n=0) is no-op. */
    gold_fp_t single[1] = { gold_fp_from_u64(12345) };
    ntt_goldilocks_forward(single, 0);
    assert_pass("forward NTT log_n=0 is identity",
                gold_fp_eq(single[0], gold_fp_from_u64(12345)));
    ntt_goldilocks_inverse(single, 0);
    assert_pass("inverse NTT log_n=0 is identity",
                gold_fp_eq(single[0], gold_fp_from_u64(12345)));
}

int main(void) {
    printf("Sub-sprint 3.5a — ntt_goldilocks self-test\n");
    printf("============================================================\n\n");

    printf("T0: bit-reverse helper\n");
    test_bit_reverse();

    printf("\nT1: round-trip iNTT(NTT(x)) == x  (base + ext, log_n = 1..14)\n");
    for (unsigned k = 1; k <= 14; k++) test_roundtrip_fp(k);
    for (unsigned k = 1; k <= 14; k++) test_roundtrip_fp2(k);

    printf("\nT2: brute-force DFT match  (base + ext, log_n = 1..8)\n");
    for (unsigned k = 1; k <= 8; k++) test_bruteforce_fp(k);
    for (unsigned k = 1; k <= 8; k++) test_bruteforce_fp2(k);

    printf("\nT3: linearity NTT(a+b) == NTT(a)+NTT(b)\n");
    for (unsigned k = 1; k <= 10; k++) test_linearity_fp(k);

    printf("\nT4: cyclic convolution theorem\n");
    for (unsigned k = 1; k <= 8; k++) test_convolution_fp(k);

    printf("\nT5: edge cases\n");
    test_edges();

    printf("\n--------------------------------------------------\n");
    printf("Total: %d passed, %d failed\n", total_passed, total_failed);
    if (total_failed == 0) {
        printf("SUB-SPRINT 3.5a (ntt_goldilocks) GATE: GREEN — NTT/iNTT pinned\n");
        return 0;
    }
    printf("SUB-SPRINT 3.5a (ntt_goldilocks) GATE: RED — %d failures\n", total_failed);
    return 1;
}
