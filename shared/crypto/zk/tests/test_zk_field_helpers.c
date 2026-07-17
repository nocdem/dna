/**
 * @file test_zk_field_helpers.c
 * @brief Phase A minimal unit tests for zk_field_helpers.
 *
 * Coverage:
 *   - bits_u64 (KAT + edge: 0, 1, powers of two, max)
 *   - log2_strict_usize (KAT for powers of two)
 *   - reverse_bits_len_u64 (KAT for known bit patterns + identity properties)
 *   - gold_fp_halve (KAT + property: 2 * halve(x) == x)
 *   - gold_fp2_halve (per-component property)
 *   - gold_fp_from_usize (KAT + canonicalization)
 *
 * These direct tests check each helper's defining property (no standalone oracle
 * JSON). The Plonky3-consuming helpers (reverse_slice_index_bits, halve,
 * batch_inv, shifted_powers) are ALSO transitively oracle-gated: fri_fold.c and
 * stark_prover.c consume them and are byte-matched to real Plonky3 vectors
 * (test_fri_fold_*_oracle.c, test_prover_prove.c) — an error here breaks those.
 *
 * Exit codes:
 *   0  all cases passed
 *   1  at least one failure
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <inttypes.h>

#include "../field_goldilocks.h"
#include "../zk_field_helpers.h"

/* Pass/fail counters. */
static int g_passed = 0;
static int g_failed = 0;

#define CHECK_EQ_U64(label, got, want) do {                                    \
    uint64_t _g = (uint64_t)(got);                                             \
    uint64_t _w = (uint64_t)(want);                                            \
    if (_g == _w) {                                                            \
        g_passed++;                                                            \
        printf("  %-60s PASS\n", (label));                                     \
    } else {                                                                   \
        g_failed++;                                                            \
        printf("  %-60s FAIL  got=%" PRIu64 " want=%" PRIu64 "\n",             \
               (label), _g, _w);                                               \
    }                                                                          \
} while (0)

#define CHECK_EQ_SIZE(label, got, want) do {                                   \
    size_t _g = (size_t)(got);                                                 \
    size_t _w = (size_t)(want);                                                \
    if (_g == _w) {                                                            \
        g_passed++;                                                            \
        printf("  %-60s PASS\n", (label));                                     \
    } else {                                                                   \
        g_failed++;                                                            \
        printf("  %-60s FAIL  got=%zu want=%zu\n", (label), _g, _w);           \
    }                                                                          \
} while (0)

/* ============================================================================
 * bits_u64 — Plonky3 field/src/exponentiation.rs:3-5
 * ========================================================================== */
static void test_bits_u64(void) {
    printf("\nT1: bits_u64\n");
    CHECK_EQ_SIZE("bits_u64(0)",              bits_u64(0),                       0);
    CHECK_EQ_SIZE("bits_u64(1)",              bits_u64(1),                       1);
    CHECK_EQ_SIZE("bits_u64(2)",              bits_u64(2),                       2);
    CHECK_EQ_SIZE("bits_u64(3)",              bits_u64(3),                       2);
    CHECK_EQ_SIZE("bits_u64(4)",              bits_u64(4),                       3);
    CHECK_EQ_SIZE("bits_u64(7)",              bits_u64(7),                       3);
    CHECK_EQ_SIZE("bits_u64(8)",              bits_u64(8),                       4);
    CHECK_EQ_SIZE("bits_u64(255)",            bits_u64(255),                     8);
    CHECK_EQ_SIZE("bits_u64(256)",            bits_u64(256),                     9);
    CHECK_EQ_SIZE("bits_u64(0xFFFFFFFFFFFFFFFF)",
                  bits_u64(0xFFFFFFFFFFFFFFFFULL), 64);
    CHECK_EQ_SIZE("bits_u64(1ULL << 63)",
                  bits_u64(1ULL << 63), 64);
}

/* ============================================================================
 * log2_strict_usize — Plonky3 util/src/lib.rs:78-87
 * ========================================================================== */
static void test_log2_strict_usize(void) {
    printf("\nT2: log2_strict_usize (only powers of two)\n");
    CHECK_EQ_SIZE("log2_strict_usize(1)",     log2_strict_usize(1),              0);
    CHECK_EQ_SIZE("log2_strict_usize(2)",     log2_strict_usize(2),              1);
    CHECK_EQ_SIZE("log2_strict_usize(4)",     log2_strict_usize(4),              2);
    CHECK_EQ_SIZE("log2_strict_usize(8)",     log2_strict_usize(8),              3);
    CHECK_EQ_SIZE("log2_strict_usize(1024)",  log2_strict_usize(1024),          10);
    CHECK_EQ_SIZE("log2_strict_usize(1<<20)", log2_strict_usize(1ULL << 20),    20);
    CHECK_EQ_SIZE("log2_strict_usize(1<<32)", log2_strict_usize(1ULL << 32),    32);
    CHECK_EQ_SIZE("log2_strict_usize(1<<62)", log2_strict_usize(1ULL << 62),    62);
    /* Note: log2_strict_usize(0) and non-power-of-two inputs trigger assert();
       not covered here (Plonky3 panic behavior is matched but untestable
       without separate process). */
}

/* ============================================================================
 * reverse_bits_len_u64 — Plonky3 util/src/lib.rs:203-211
 * ========================================================================== */
static void test_reverse_bits_len(void) {
    printf("\nT3: reverse_bits_len_u64\n");
    /* KAT — direct check that the bottom bit_len bits get reversed. */
    CHECK_EQ_U64("reverse_bits_len(0b001, 3)",
                 reverse_bits_len_u64(0b001, 3), 0b100);
    CHECK_EQ_U64("reverse_bits_len(0b110, 3)",
                 reverse_bits_len_u64(0b110, 3), 0b011);
    CHECK_EQ_U64("reverse_bits_len(0b1011, 4)",
                 reverse_bits_len_u64(0b1011, 4), 0b1101);
    CHECK_EQ_U64("reverse_bits_len(0b00010000, 8)",
                 reverse_bits_len_u64(0b00010000, 8), 0b00001000);
    /* All-ones — symmetric, reverses to itself. */
    CHECK_EQ_U64("reverse_bits_len(0xFF, 8)",
                 reverse_bits_len_u64(0xFFULL, 8), 0xFFULL);
    CHECK_EQ_U64("reverse_bits_len(0xFFFF, 16)",
                 reverse_bits_len_u64(0xFFFFULL, 16), 0xFFFFULL);
    /* Single bit at the high end of the field. */
    CHECK_EQ_U64("reverse_bits_len(1, 32)",
                 reverse_bits_len_u64(1ULL, 32), 1ULL << 31);
    /* Plonky3-documented zero case. */
    CHECK_EQ_U64("reverse_bits_len(0, 0)",
                 reverse_bits_len_u64(0ULL, 0), 0ULL);

    /* Involution property: reverse_bits_len is its own inverse. */
    printf("\nT3b: reverse_bits_len_u64 involution\n");
    for (unsigned bit_len = 1; bit_len <= 32; bit_len++) {
        uint64_t mask = (bit_len == 64) ? ~0ULL : ((1ULL << bit_len) - 1ULL);
        /* Try a few representative values per bit_len. */
        uint64_t samples[] = { 0ULL, 1ULL, mask, mask ^ 1ULL,
                               (uint64_t)0xA5A5A5A5A5A5A5A5ULL & mask };
        for (size_t s = 0; s < sizeof(samples) / sizeof(samples[0]); s++) {
            uint64_t x = samples[s];
            uint64_t y = reverse_bits_len_u64(x, bit_len);
            uint64_t z = reverse_bits_len_u64(y, bit_len);
            if (z != x) {
                char label[80];
                snprintf(label, sizeof(label),
                         "involution bit_len=%u x=%" PRIu64, bit_len, x);
                CHECK_EQ_U64(label, z, x);
            }
        }
    }
    /* If the involution loop produced no failures we record one composite PASS. */
    if (g_failed == 0) {
        g_passed++;
        printf("  %-60s PASS\n", "involution holds across bit_len in [1,32]");
    }
}

/* ============================================================================
 * gold_fp_halve — Plonky3 goldilocks/src/goldilocks.rs:235-244
 * ========================================================================== */
static void test_gold_fp_halve(void) {
    printf("\nT4: gold_fp_halve\n");
    /* halve(0) == 0 */
    {
        gold_fp_t h = gold_fp_halve(gold_fp_zero());
        CHECK_EQ_U64("halve(0)", h.v, 0);
    }
    /* halve(2) == 1 */
    {
        gold_fp_t h = gold_fp_halve(gold_fp_from_u64(2));
        CHECK_EQ_U64("halve(2)", h.v, 1);
    }
    /* halve(4) == 2 */
    {
        gold_fp_t h = gold_fp_halve(gold_fp_from_u64(4));
        CHECK_EQ_U64("halve(4)", h.v, 2);
    }
    /* halve(1) == (P+1)/2 = 0x7FFFFFFF80000001 */
    {
        gold_fp_t h = gold_fp_halve(gold_fp_one());
        CHECK_EQ_U64("halve(1) == (P+1)/2", h.v, 0x7FFFFFFF80000001ULL);
    }
    /* halve(P-1) == (P-1)/2 = 0x7FFFFFFF80000000 (P-1 is even) */
    {
        gold_fp_t h = gold_fp_halve(gold_fp_from_u64(GOLDILOCKS_P - 1));
        CHECK_EQ_U64("halve(P-1) == (P-1)/2", h.v, 0x7FFFFFFF80000000ULL);
    }

    /* Property: 2 * halve(x) == x for a spread of inputs. */
    printf("\nT4b: 2 * halve(x) == x property\n");
    uint64_t samples[] = {
        0ULL, 1ULL, 2ULL, 3ULL, 7ULL, 100ULL,
        GOLDILOCKS_P / 2ULL,
        GOLDILOCKS_P - 1ULL,
        0x123456789ABCDEFULL,
        0xFFFFFFFFULL,
        0x0000FFFFFFFFFFFFULL,
    };
    gold_fp_t two = gold_fp_from_u64(2);
    int prop_ok = 1;
    for (size_t i = 0; i < sizeof(samples)/sizeof(samples[0]); i++) {
        uint64_t s = samples[i];
        if (s >= GOLDILOCKS_P) continue;     /* Skip non-canonical samples. */
        gold_fp_t x   = gold_fp_from_u64(s);
        gold_fp_t h   = gold_fp_halve(x);
        gold_fp_t y   = gold_fp_mul(h, two);
        if (!gold_fp_eq(y, x)) {
            prop_ok = 0;
            g_failed++;
            printf("  %-60s FAIL  s=%" PRIu64 " y=%" PRIu64 "\n",
                   "2*halve(x)==x", s, y.v);
        }
    }
    if (prop_ok) {
        g_passed++;
        printf("  %-60s PASS\n", "2 * halve(x) == x across all samples");
    }
}

/* ============================================================================
 * gold_fp2_halve — Plonky3 binomial_extension.rs:254-256
 * ========================================================================== */
static void test_gold_fp2_halve(void) {
    printf("\nT5: gold_fp2_halve (per-component)\n");
    {
        /* halve([0, 0]) == [0, 0] */
        gold_fp2_t z = gold_fp2_zero();
        gold_fp2_t h = gold_fp2_halve(z);
        CHECK_EQ_U64("halve_fp2([0,0]).a", h.a.v, 0);
        CHECK_EQ_U64("halve_fp2([0,0]).b", h.b.v, 0);
    }
    {
        /* halve([2, 4]) == [1, 2] */
        gold_fp2_t x = gold_fp2_new(gold_fp_from_u64(2), gold_fp_from_u64(4));
        gold_fp2_t h = gold_fp2_halve(x);
        CHECK_EQ_U64("halve_fp2([2,4]).a", h.a.v, 1);
        CHECK_EQ_U64("halve_fp2([2,4]).b", h.b.v, 2);
    }
    {
        /* halve([1, 1]) == [(P+1)/2, (P+1)/2] */
        gold_fp2_t x = gold_fp2_new(gold_fp_one(), gold_fp_one());
        gold_fp2_t h = gold_fp2_halve(x);
        CHECK_EQ_U64("halve_fp2([1,1]).a", h.a.v, 0x7FFFFFFF80000001ULL);
        CHECK_EQ_U64("halve_fp2([1,1]).b", h.b.v, 0x7FFFFFFF80000001ULL);
    }
}

/* ============================================================================
 * gold_fp_from_usize — Plonky3 chain integers.rs:23-39 + 417-468 + goldilocks.rs:445
 * ========================================================================== */
static void test_gold_fp_from_usize(void) {
    printf("\nT6: gold_fp_from_usize\n");
    {
        gold_fp_t f = gold_fp_from_usize(0);
        CHECK_EQ_U64("from_usize(0)", f.v, 0);
    }
    {
        gold_fp_t f = gold_fp_from_usize(1);
        CHECK_EQ_U64("from_usize(1)", f.v, 1);
    }
    {
        gold_fp_t f = gold_fp_from_usize(42);
        CHECK_EQ_U64("from_usize(42)", f.v, 42);
    }
    {
        gold_fp_t f = gold_fp_from_usize((size_t)1024);
        CHECK_EQ_U64("from_usize(1024)", f.v, 1024);
    }
    /* Identity with gold_fp_from_u64 for canonical-range values. */
    {
        gold_fp_t a = gold_fp_from_usize((size_t)0x12345678);
        gold_fp_t b = gold_fp_from_u64((uint64_t)0x12345678);
        CHECK_EQ_U64("from_usize == from_u64 (small)", a.v, b.v);
    }
    /* Match canonicalization with from_u64 for any 64-bit value. */
    if (sizeof(size_t) >= 8) {
        size_t big = (size_t)0xFFFFFFFFFFFFFFFFULL;
        gold_fp_t a = gold_fp_from_usize(big);
        gold_fp_t b = gold_fp_from_u64((uint64_t)big);
        CHECK_EQ_U64("from_usize == from_u64 (max u64)", a.v, b.v);
    }
}

/* ============================================================================
 * Phase B
 *
 *   T7  gold_fp_shifted_powers   — Plonky3 field.rs:305-310 + 1209-1217 + 1246-1248
 *   T8  gold_fp2_shifted_powers
 *   T9  gold_fp_batch_inv_general  — Plonky3 batch_inverse.rs:81-104
 *   T10 gold_fp2_batch_inv_general
 *   T11 reverse_slice_index_bits_fp  — Plonky3 util/lib.rs:334-346 (aarch64-form)
 *   T12 reverse_slice_index_bits_fp2
 * ========================================================================== */

/* T7: gold_fp_shifted_powers */
static void test_gold_fp_shifted_powers(void) {
    printf("\nT7: gold_fp_shifted_powers\n");
    {
        /* n=0: no-op. Allocate buffer to detect any write; verify untouched. */
        gold_fp_t out[1] = { { .v = 0xDEADBEEFCAFEBABEULL } };
        gold_fp_shifted_powers(gold_fp_one(), gold_fp_from_u64(2), out, 0);
        CHECK_EQ_U64("shifted_powers n=0 no-op",
                     out[0].v, 0xDEADBEEFCAFEBABEULL);
    }
    {
        /* n=1, start=5, g=anything: out[0] = 5. */
        gold_fp_t out[1];
        gold_fp_shifted_powers(gold_fp_from_u64(5), gold_fp_from_u64(2), out, 1);
        CHECK_EQ_U64("shifted_powers n=1 out[0]==start", out[0].v, 5);
    }
    {
        /* start=1, g=2, n=4 → [1, 2, 4, 8]. */
        gold_fp_t out[4];
        gold_fp_shifted_powers(gold_fp_one(), gold_fp_from_u64(2), out, 4);
        CHECK_EQ_U64("shifted_powers start=1 g=2 out[0]", out[0].v, 1);
        CHECK_EQ_U64("shifted_powers start=1 g=2 out[1]", out[1].v, 2);
        CHECK_EQ_U64("shifted_powers start=1 g=2 out[2]", out[2].v, 4);
        CHECK_EQ_U64("shifted_powers start=1 g=2 out[3]", out[3].v, 8);
    }
    {
        /* start=3, g=2, n=4 → [3, 6, 12, 24]. */
        gold_fp_t out[4];
        gold_fp_shifted_powers(gold_fp_from_u64(3), gold_fp_from_u64(2), out, 4);
        CHECK_EQ_U64("shifted_powers start=3 g=2 out[0]", out[0].v, 3);
        CHECK_EQ_U64("shifted_powers start=3 g=2 out[1]", out[1].v, 6);
        CHECK_EQ_U64("shifted_powers start=3 g=2 out[2]", out[2].v, 12);
        CHECK_EQ_U64("shifted_powers start=3 g=2 out[3]", out[3].v, 24);
    }
    {
        /* Property: out[i] == start * g^i (verified via gold_fp_pow). */
        gold_fp_t start = gold_fp_from_u64(7);   /* Goldilocks GENERATOR */
        gold_fp_t g     = gold_fp_from_u64(11);
        const size_t n  = 16;
        gold_fp_t out[16];
        gold_fp_shifted_powers(start, g, out, n);
        int prop_ok = 1;
        for (size_t i = 0; i < n; i++) {
            gold_fp_t expected = gold_fp_mul(start, gold_fp_pow(g, (uint64_t)i));
            if (!gold_fp_eq(out[i], expected)) {
                prop_ok = 0;
                g_failed++;
                printf("  %-60s FAIL  i=%zu got=%" PRIu64 " want=%" PRIu64 "\n",
                       "shifted_powers property i'th",
                       i, out[i].v, expected.v);
            }
        }
        if (prop_ok) {
            g_passed++;
            printf("  %-60s PASS\n",
                   "shifted_powers property out[i] == start * g^i for n=16");
        }
    }
}

/* T8: gold_fp2_shifted_powers */
static void test_gold_fp2_shifted_powers(void) {
    printf("\nT8: gold_fp2_shifted_powers\n");
    {
        /* start = [1,0], g = [0,1], n=4.
           In Goldilocks² with X²=W=7: g^2 = X² = 7.
           Sequence: out[0] = 1, out[1] = X, out[2] = 7, out[3] = 7X. */
        gold_fp2_t start = gold_fp2_one();
        gold_fp2_t g     = gold_fp2_new(gold_fp_zero(), gold_fp_one());
        gold_fp2_t out[4];
        gold_fp2_shifted_powers(start, g, out, 4);
        CHECK_EQ_U64("fp2 shifted_powers out[0].a", out[0].a.v, 1);
        CHECK_EQ_U64("fp2 shifted_powers out[0].b", out[0].b.v, 0);
        CHECK_EQ_U64("fp2 shifted_powers out[1].a", out[1].a.v, 0);
        CHECK_EQ_U64("fp2 shifted_powers out[1].b", out[1].b.v, 1);
        CHECK_EQ_U64("fp2 shifted_powers out[2].a", out[2].a.v, GOLDILOCKS_EXT_W);
        CHECK_EQ_U64("fp2 shifted_powers out[2].b", out[2].b.v, 0);
        CHECK_EQ_U64("fp2 shifted_powers out[3].a", out[3].a.v, 0);
        CHECK_EQ_U64("fp2 shifted_powers out[3].b", out[3].b.v, GOLDILOCKS_EXT_W);
    }
    {
        /* Property: out[i] == start * g^i (verified via repeated multiplication). */
        gold_fp2_t start = gold_fp2_new(gold_fp_from_u64(3), gold_fp_from_u64(5));
        gold_fp2_t g     = gold_fp2_new(gold_fp_from_u64(2), gold_fp_from_u64(7));
        const size_t n   = 10;
        gold_fp2_t out[10];
        gold_fp2_shifted_powers(start, g, out, n);
        int prop_ok = 1;
        gold_fp2_t expected = start;
        for (size_t i = 0; i < n; i++) {
            if (!gold_fp2_eq(out[i], expected)) {
                prop_ok = 0;
                g_failed++;
                printf("  fp2 shifted_powers property FAIL at i=%zu\n", i);
            }
            expected = gold_fp2_mul(expected, g);
        }
        if (prop_ok) {
            g_passed++;
            printf("  %-60s PASS\n",
                   "fp2 shifted_powers property holds for n=10");
        }
    }
}

/* T9: gold_fp_batch_inv_general */
static void test_gold_fp_batch_inv_general(void) {
    printf("\nT9: gold_fp_batch_inv_general\n");
    {
        /* n=0 no-op. */
        gold_fp_batch_inv_general(NULL, NULL, 0);
        g_passed++;
        printf("  %-60s PASS\n", "batch_inv n=0 no-op (no crash)");
    }
    {
        /* n=1, x[0]=7: result[0] = 7^-1. Verify 7 * result[0] == 1. */
        gold_fp_t x[1] = { gold_fp_from_u64(7) };
        gold_fp_t r[1];
        gold_fp_batch_inv_general(x, r, 1);
        gold_fp_t prod = gold_fp_mul(x[0], r[0]);
        CHECK_EQ_U64("batch_inv n=1 x*result==1", prod.v, 1);
    }
    {
        /* n=4 with x=[2, 3, 5, 7]: each x[i] * result[i] == 1. */
        gold_fp_t x[4] = {
            gold_fp_from_u64(2), gold_fp_from_u64(3),
            gold_fp_from_u64(5), gold_fp_from_u64(7),
        };
        gold_fp_t r[4];
        gold_fp_batch_inv_general(x, r, 4);
        int prop_ok = 1;
        for (size_t i = 0; i < 4; i++) {
            gold_fp_t prod = gold_fp_mul(x[i], r[i]);
            if (prod.v != 1ULL) {
                prop_ok = 0;
                g_failed++;
                printf("  batch_inv n=4 i=%zu prod=%" PRIu64 "\n", i, prod.v);
            }
        }
        if (prop_ok) {
            g_passed++;
            printf("  %-60s PASS\n", "batch_inv n=4 all x*result==1");
        }
    }
    {
        /* n=64 with deterministic nonzero inputs. */
        gold_fp_t x[64];
        gold_fp_t r[64];
        for (size_t i = 0; i < 64; i++) {
            /* Mix bits so values span the field; +1 to avoid zero. */
            x[i] = gold_fp_from_u64(((uint64_t)i * 0x9E3779B97F4A7C15ULL) ^ 0x123ULL);
            /* The xor shouldn't yield zero canonically; if it ever does at one
               index we'd skip — but for our seed pattern it won't. */
        }
        gold_fp_batch_inv_general(x, r, 64);
        int prop_ok = 1;
        for (size_t i = 0; i < 64; i++) {
            gold_fp_t prod = gold_fp_mul(x[i], r[i]);
            if (prod.v != 1ULL) {
                prop_ok = 0;
                g_failed++;
                printf("  batch_inv n=64 i=%zu prod=%" PRIu64 "\n", i, prod.v);
            }
        }
        if (prop_ok) {
            g_passed++;
            printf("  %-60s PASS\n", "batch_inv n=64 all x*result==1");
        }
    }
}

/* T10: gold_fp2_batch_inv_general */
static void test_gold_fp2_batch_inv_general(void) {
    printf("\nT10: gold_fp2_batch_inv_general\n");
    {
        /* n=0 no-op. */
        gold_fp2_batch_inv_general(NULL, NULL, 0);
        g_passed++;
        printf("  %-60s PASS\n", "fp2 batch_inv n=0 no-op (no crash)");
    }
    {
        /* n=4 with simple nonzero fp2 elements; property x[i]*r[i] == fp2_one. */
        gold_fp2_t x[4] = {
            gold_fp2_new(gold_fp_from_u64(2), gold_fp_from_u64(3)),
            gold_fp2_new(gold_fp_from_u64(5), gold_fp_from_u64(7)),
            gold_fp2_new(gold_fp_from_u64(11), gold_fp_from_u64(0)),  /* base-only */
            gold_fp2_new(gold_fp_from_u64(0), gold_fp_from_u64(13)),  /* X-component-only */
        };
        gold_fp2_t r[4];
        gold_fp2_batch_inv_general(x, r, 4);
        gold_fp2_t one = gold_fp2_one();
        int prop_ok = 1;
        for (size_t i = 0; i < 4; i++) {
            gold_fp2_t prod = gold_fp2_mul(x[i], r[i]);
            if (!gold_fp2_eq(prod, one)) {
                prop_ok = 0;
                g_failed++;
                printf("  fp2 batch_inv n=4 i=%zu prod=(%" PRIu64 ", %" PRIu64 ")\n",
                       i, prod.a.v, prod.b.v);
            }
        }
        if (prop_ok) {
            g_passed++;
            printf("  %-60s PASS\n", "fp2 batch_inv n=4 all x*result==one");
        }
    }
    {
        /* n=32 deterministic nonzero fp2 elements. */
        gold_fp2_t x[32];
        gold_fp2_t r[32];
        for (size_t i = 0; i < 32; i++) {
            uint64_t a = ((uint64_t)i * 0x9E3779B97F4A7C15ULL) ^ 0xABCULL;
            uint64_t b = ((uint64_t)i * 0xBF58476D1CE4E5B9ULL) ^ 0xDEFULL;
            x[i] = gold_fp2_new(gold_fp_from_u64(a), gold_fp_from_u64(b));
        }
        gold_fp2_batch_inv_general(x, r, 32);
        gold_fp2_t one = gold_fp2_one();
        int prop_ok = 1;
        for (size_t i = 0; i < 32; i++) {
            gold_fp2_t prod = gold_fp2_mul(x[i], r[i]);
            if (!gold_fp2_eq(prod, one)) {
                prop_ok = 0;
                g_failed++;
                printf("  fp2 batch_inv n=32 i=%zu prod=(%" PRIu64 ", %" PRIu64 ")\n",
                       i, prod.a.v, prod.b.v);
            }
        }
        if (prop_ok) {
            g_passed++;
            printf("  %-60s PASS\n", "fp2 batch_inv n=32 all x*result==one");
        }
    }
}

/* Helper for T11/T12: verify that after applying reverse_slice_index_bits to
   vals = [0, 1, ..., n-1] (each cast through the field), vals[i] equals the
   bit-reverse of i over log2(n) bits. */
static int check_reverse_perm_fp(size_t n) {
    if (n == 0) return 1;
    gold_fp_t *vals = (gold_fp_t *)malloc(sizeof(gold_fp_t) * n);
    if (!vals) {
        g_failed++;
        printf("  malloc fail at n=%zu\n", n);
        return 0;
    }
    for (size_t i = 0; i < n; i++) {
        vals[i] = gold_fp_from_u64((uint64_t)i);
    }
    reverse_slice_index_bits_fp(vals, n);
    unsigned lb_n = (unsigned)log2_strict_usize(n);
    int ok = 1;
    for (size_t i = 0; i < n; i++) {
        uint64_t expected = reverse_bits_len_u64((uint64_t)i, lb_n);
        if (vals[i].v != expected) {
            ok = 0;
            printf("  fp reverse n=%zu i=%zu got=%" PRIu64
                   " want=%" PRIu64 "\n", n, i, vals[i].v, expected);
            break;
        }
    }
    free(vals);
    return ok;
}

static int check_reverse_perm_fp2(size_t n) {
    if (n == 0) return 1;
    gold_fp2_t *vals = (gold_fp2_t *)malloc(sizeof(gold_fp2_t) * n);
    if (!vals) {
        g_failed++;
        printf("  malloc fail at n=%zu\n", n);
        return 0;
    }
    /* Use the index as the .a component, fixed sentinel in .b for distinguishability. */
    for (size_t i = 0; i < n; i++) {
        vals[i] = gold_fp2_new(gold_fp_from_u64((uint64_t)i),
                               gold_fp_from_u64((uint64_t)(0xABCDEF00ULL + i)));
    }
    reverse_slice_index_bits_fp2(vals, n);
    unsigned lb_n = (unsigned)log2_strict_usize(n);
    int ok = 1;
    for (size_t i = 0; i < n; i++) {
        uint64_t expected_a = reverse_bits_len_u64((uint64_t)i, lb_n);
        uint64_t expected_b = 0xABCDEF00ULL + expected_a;
        if (vals[i].a.v != expected_a || vals[i].b.v != expected_b) {
            ok = 0;
            printf("  fp2 reverse n=%zu i=%zu got=(%" PRIu64 ",%" PRIu64
                   ") want=(%" PRIu64 ",%" PRIu64 ")\n",
                   n, i, vals[i].a.v, vals[i].b.v, expected_a, expected_b);
            break;
        }
    }
    free(vals);
    return ok;
}

/* T11: reverse_slice_index_bits_fp */
static void test_reverse_slice_index_bits_fp(void) {
    printf("\nT11: reverse_slice_index_bits_fp (reference permutation check)\n");
    const size_t sizes[] = { 1, 2, 4, 8, 16, 32, 64, 256 };
    for (size_t s = 0; s < sizeof(sizes) / sizeof(sizes[0]); s++) {
        size_t n = sizes[s];
        char label[80];
        snprintf(label, sizeof(label), "fp reverse permutation n=%zu", n);
        if (check_reverse_perm_fp(n)) {
            g_passed++;
            printf("  %-60s PASS\n", label);
        } else {
            g_failed++;
            printf("  %-60s FAIL\n", label);
        }
    }
}

/* T12: reverse_slice_index_bits_fp2 */
static void test_reverse_slice_index_bits_fp2(void) {
    printf("\nT12: reverse_slice_index_bits_fp2 (reference permutation check)\n");
    const size_t sizes[] = { 1, 2, 4, 8, 16, 32, 64, 256 };
    for (size_t s = 0; s < sizeof(sizes) / sizeof(sizes[0]); s++) {
        size_t n = sizes[s];
        char label[80];
        snprintf(label, sizeof(label), "fp2 reverse permutation n=%zu", n);
        if (check_reverse_perm_fp2(n)) {
            g_passed++;
            printf("  %-60s PASS\n", label);
        } else {
            g_failed++;
            printf("  %-60s FAIL\n", label);
        }
    }
}

int main(void) {
    printf("============================================================\n");
    printf("Phase A + B — zk_field_helpers unit tests\n");
    printf("Plonky3 pin: 82cfad73cd734d37a0d51953094f970c531817ec\n");
    printf("============================================================\n");

    /* Phase A */
    test_bits_u64();
    test_log2_strict_usize();
    test_reverse_bits_len();
    test_gold_fp_halve();
    test_gold_fp2_halve();
    test_gold_fp_from_usize();

    /* Phase B */
    test_gold_fp_shifted_powers();
    test_gold_fp2_shifted_powers();
    test_gold_fp_batch_inv_general();
    test_gold_fp2_batch_inv_general();
    test_reverse_slice_index_bits_fp();
    test_reverse_slice_index_bits_fp2();

    printf("\n--------------------------------------------------\n");
    printf("Total: %d passed, %d failed\n", g_passed, g_failed);
    printf("PHASE A+B GATE: %s — zk_field_helpers\n",
           g_failed == 0 ? "GREEN" : "RED");

    return g_failed == 0 ? 0 : 1;
}
