/**
 * @file field_goldilocks.c
 * @brief Goldilocks prime field arithmetic — clean-room C implementation.
 *
 * Algorithms mirror Plonky3 commit 82cfad73 (goldilocks/src/goldilocks.rs).
 * Plonky3 is the reference oracle; this code is written to byte-match its
 * outputs for all test vectors in tools/vectors/field_ops.json.
 *
 * Determinism invariant D1 (design doc § 4.1):
 *   - Inputs may be non-canonical in [0, 2^64); outputs are canonical [0, p).
 *   - No SIMD / no parallel reduction.
 *   - inv(0) is undefined behavior — caller MUST check.
 *
 * Math foundations:
 *   p = 2^64 - 2^32 + 1 = 0xFFFFFFFF00000001
 *   NEG_ORDER = 2^64 - p = 2^32 - 1 = 0xFFFFFFFF
 *   2^64 ≡ NEG_ORDER (mod p)
 *   2^96 ≡ -1 (mod p)        (used in reduce128)
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: Apache-2.0
 */

#include "field_goldilocks.h"

/* ============================================================================
 * Internal constants
 * ========================================================================== */

#define ORDER       ((uint64_t)0xFFFFFFFF00000001ULL)  /* = GOLDILOCKS_P     */
#define NEG_ORDER   ((uint64_t)0x00000000FFFFFFFFULL)  /* = 2^64 - p         */

/* ============================================================================
 * Canonicalization helper
 * ========================================================================== */

/** Bring value into canonical range [0, p).
 *  Input may be in [0, 2^64). Result in [0, p). */
static inline uint64_t canonicalize_u64(uint64_t x) {
    return x >= ORDER ? x - ORDER : x;
}

/* ============================================================================
 * Identities + constructors
 * ========================================================================== */

gold_fp_t gold_fp_zero(void) { return (gold_fp_t){.v = 0}; }
gold_fp_t gold_fp_one(void)  { return (gold_fp_t){.v = 1}; }

gold_fp_t gold_fp_from_u64(uint64_t x) {
    return (gold_fp_t){.v = canonicalize_u64(x)};
}

uint64_t gold_fp_to_u64(gold_fp_t x) {
    return canonicalize_u64(x.v);
}

/* ============================================================================
 * Addition / Subtraction / Negation
 *
 * Algorithm (mirrors Plonky3 const_add):
 *   (sum, over1)  = a + b           (u64 overflow flag)
 *   (sum, over2)  = sum + over1*NEG_ORDER
 *   if (over2):     sum += NEG_ORDER
 *   canonical:    sum mod p
 * ========================================================================== */

gold_fp_t gold_fp_add(gold_fp_t a, gold_fp_t b) {
    /* Step 1: a + b, possibly overflowing u64. */
    __uint128_t s1 = (__uint128_t)a.v + (__uint128_t)b.v;
    uint64_t sum_lo = (uint64_t)s1;
    uint64_t carry1 = (uint64_t)(s1 >> 64); /* 0 or 1 */

    /* Step 2: sum + carry1 * NEG_ORDER. */
    __uint128_t s2 = (__uint128_t)sum_lo + (__uint128_t)(carry1 * NEG_ORDER);
    uint64_t sum2 = (uint64_t)s2;
    uint64_t carry2 = (uint64_t)(s2 >> 64);

    /* Step 3: rare double-overflow case. */
    if (carry2) sum2 += NEG_ORDER;

    return (gold_fp_t){.v = canonicalize_u64(sum2)};
}

gold_fp_t gold_fp_sub(gold_fp_t a, gold_fp_t b) {
    /* Canonicalize inputs first so subtraction is well-defined on [0, p). */
    uint64_t a_c = canonicalize_u64(a.v);
    uint64_t b_c = canonicalize_u64(b.v);
    if (a_c >= b_c) {
        return (gold_fp_t){.v = a_c - b_c};
    }
    /* a < b: result = a - b + p, no overflow because a, b in [0, p). */
    return (gold_fp_t){.v = a_c + (ORDER - b_c)};
}

gold_fp_t gold_fp_neg(gold_fp_t a) {
    uint64_t c = canonicalize_u64(a.v);
    return (gold_fp_t){.v = c == 0 ? 0 : ORDER - c};
}

/* ============================================================================
 * Multiplication via reduce128
 *
 * 128-bit product reduction:
 *   x = x_lo + 2^64 * x_hi
 *   x_hi = x_hi_lo + 2^32 * x_hi_hi
 *   x mod p ≡ x_lo + NEG_ORDER * x_hi_lo - x_hi_hi   (mod p)
 *
 * Because 2^96 ≡ -1 (mod p), the high-high 32 bits become a subtraction.
 * Result fits in u64 but may be non-canonical (>= p, < 2^64).
 * ========================================================================== */

static gold_fp_t reduce128(__uint128_t x) {
    uint64_t x_lo    = (uint64_t)x;
    uint64_t x_hi    = (uint64_t)(x >> 64);
    uint64_t x_hi_hi = x_hi >> 32;
    uint64_t x_hi_lo = x_hi & NEG_ORDER;

    /* t0 = x_lo - x_hi_hi, with explicit borrow correction. */
    uint64_t t0;
    int borrow = (x_lo < x_hi_hi);
    t0 = x_lo - x_hi_hi;            /* u64 wrapping */
    if (borrow) {
        t0 -= NEG_ORDER;            /* cannot underflow because of canonical inputs */
    }

    /* t1 = x_hi_lo * NEG_ORDER. Both are 32-bit so product fits in u64. */
    uint64_t t1 = x_hi_lo * NEG_ORDER;

    /* t2 = t0 + t1, may overflow once. */
    __uint128_t s = (__uint128_t)t0 + (__uint128_t)t1;
    uint64_t t2 = (uint64_t)s;
    uint64_t carry = (uint64_t)(s >> 64);
    if (carry) t2 += NEG_ORDER;

    return (gold_fp_t){.v = canonicalize_u64(t2)};
}

gold_fp_t gold_fp_mul(gold_fp_t a, gold_fp_t b) {
    return reduce128((__uint128_t)a.v * (__uint128_t)b.v);
}

gold_fp_t gold_fp_sqr(gold_fp_t a) {
    return gold_fp_mul(a, a);
}

/* ============================================================================
 * Exponentiation via square-and-multiply (LSB to MSB)
 * ========================================================================== */

gold_fp_t gold_fp_pow(gold_fp_t a, uint64_t k) {
    if (k == 0) return gold_fp_one();
    gold_fp_t result = gold_fp_one();
    gold_fp_t base = a;
    while (k != 0) {
        if (k & 1u) {
            result = gold_fp_mul(result, base);
        }
        k >>= 1;
        if (k != 0) {
            base = gold_fp_sqr(base);
        }
    }
    return result;
}

/* ============================================================================
 * Multiplicative inverse via Fermat's little theorem
 *
 *   For prime p: a^(p-2) = a^(-1) mod p when a != 0.
 *   p - 2 = 0xFFFFFFFEFFFFFFFF.
 *
 *   inv(0) is undefined — caller MUST check (returns 0 silently here).
 * ========================================================================== */

gold_fp_t gold_fp_inv(gold_fp_t a) {
    if (canonicalize_u64(a.v) == 0) {
        return gold_fp_zero();  /* undefined; caller's responsibility */
    }
    return gold_fp_pow(a, ORDER - 2);
}

/* ============================================================================
 * Predicates
 * ========================================================================== */

bool gold_fp_eq(gold_fp_t a, gold_fp_t b) {
    return canonicalize_u64(a.v) == canonicalize_u64(b.v);
}

bool gold_fp_is_zero(gold_fp_t a) {
    return canonicalize_u64(a.v) == 0;
}

/* ============================================================================
 * Two-adic generator
 *
 * Goldilocks has p - 1 = 2^32 · (2^32 - 1).
 * Plonky3 commits 7 as a 2^32-th primitive root of unity.
 * A 2^bits-th root is then 7^(2^(32 - bits)) mod p.
 *
 * For Faz 1 this is a STUB — implementation deferred to Sprint 1.4 or later
 * (currently called only by header-declared consistency checks).
 * ========================================================================== */

gold_fp_t gold_fp_two_adic_generator(unsigned bits) {
    if (bits == 0 || bits > GOLDILOCKS_TWO_ADICITY) {
        return gold_fp_one();
    }
    /* Generator of order 2^32 — Plonky3 uses 7^(p-1)/2^32.
     * For Sprint 1.2 we hardcode the result for the most common case (bits=32)
     * and compute by repeated squaring otherwise. Full implementation in
     * Sprint 1.3+ once test vectors are dumped. */
    gold_fp_t g32 = (gold_fp_t){.v = 1753635133440165772ULL};  /* Plonky3 const */
    if (bits == GOLDILOCKS_TWO_ADICITY) return g32;
    /* g_bits = g32 ^ (2^(32 - bits)) */
    unsigned squarings = GOLDILOCKS_TWO_ADICITY - bits;
    gold_fp_t g = g32;
    for (unsigned i = 0; i < squarings; i++) {
        g = gold_fp_sqr(g);
    }
    return g;
}

/* ============================================================================
 * Extension field Goldilocks² (Sprint 1.3 SCOPE — declared, not implemented)
 *
 * STUB only: returns zeros / identities. Sprint 1.3 fills these in once
 * dump-field-ext oracle vectors are available.
 * ========================================================================== */

gold_fp2_t gold_fp2_zero(void) { return (gold_fp2_t){gold_fp_zero(), gold_fp_zero()}; }
gold_fp2_t gold_fp2_one(void)  { return (gold_fp2_t){gold_fp_one(),  gold_fp_zero()}; }
gold_fp2_t gold_fp2_new(gold_fp_t a, gold_fp_t b)   { return (gold_fp2_t){a, b}; }
gold_fp2_t gold_fp2_from_base(gold_fp_t a)          { return (gold_fp2_t){a, gold_fp_zero()}; }

gold_fp2_t gold_fp2_add(gold_fp2_t a, gold_fp2_t b) {
    return (gold_fp2_t){gold_fp_add(a.a, b.a), gold_fp_add(a.b, b.b)};
}
gold_fp2_t gold_fp2_sub(gold_fp2_t a, gold_fp2_t b) {
    return (gold_fp2_t){gold_fp_sub(a.a, b.a), gold_fp_sub(a.b, b.b)};
}
gold_fp2_t gold_fp2_neg(gold_fp2_t a) {
    return (gold_fp2_t){gold_fp_neg(a.a), gold_fp_neg(a.b)};
}
gold_fp2_t gold_fp2_mul(gold_fp2_t a, gold_fp2_t b) {
    /* (a0 + a1·X)(b0 + b1·X) = (a0·b0 + W·a1·b1) + (a0·b1 + a1·b0)·X, W=7. */
    gold_fp_t a0b0 = gold_fp_mul(a.a, b.a);
    gold_fp_t a1b1 = gold_fp_mul(a.b, b.b);
    gold_fp_t a0b1 = gold_fp_mul(a.a, b.b);
    gold_fp_t a1b0 = gold_fp_mul(a.b, b.a);
    gold_fp_t W = gold_fp_from_u64(GOLDILOCKS_EXT_W);
    gold_fp_t Wa1b1 = gold_fp_mul(W, a1b1);
    return (gold_fp2_t){gold_fp_add(a0b0, Wa1b1), gold_fp_add(a0b1, a1b0)};
}
gold_fp2_t gold_fp2_sqr(gold_fp2_t a) {
    return gold_fp2_mul(a, a);
}
gold_fp2_t gold_fp2_inv(gold_fp2_t a) {
    /* Frobenius-style: (a0 - a1·X) / (a0² - W·a1²) */
    gold_fp_t a0sq = gold_fp_sqr(a.a);
    gold_fp_t a1sq = gold_fp_sqr(a.b);
    gold_fp_t W = gold_fp_from_u64(GOLDILOCKS_EXT_W);
    gold_fp_t Wa1sq = gold_fp_mul(W, a1sq);
    gold_fp_t norm = gold_fp_sub(a0sq, Wa1sq);
    gold_fp_t norm_inv = gold_fp_inv(norm);
    return (gold_fp2_t){gold_fp_mul(a.a, norm_inv), gold_fp_neg(gold_fp_mul(a.b, norm_inv))};
}

bool gold_fp2_eq(gold_fp2_t a, gold_fp2_t b) {
    return gold_fp_eq(a.a, b.a) && gold_fp_eq(a.b, b.b);
}

bool gold_fp2_irreducible_consistency_check(void) {
    /* Confirms compile-time constants match design doc. */
    if (GOLDILOCKS_EXT_W != 7)            return false;
    if (GOLDILOCKS_P != ORDER)            return false;
    if (GOLDILOCKS_TWO_ADICITY != 32)     return false;
    if (GOLDILOCKS_EXT_TWO_ADICITY != 33) return false;
    return true;
}
