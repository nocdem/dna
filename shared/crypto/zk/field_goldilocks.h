/**
 * @file field_goldilocks.h
 * @brief Goldilocks prime field arithmetic for STARK range proofs (DNAC v3)
 *
 * Field: GF(p) where p = 2^64 - 2^32 + 1 = 18446744069414584321
 * Extension: GF(p^2) over irreducible x^2 - 7 (W = 7)
 *
 * Reference: Plonky3 commit 82cfad73 (goldilocks/src/extension.rs).
 *
 * Determinism invariant D1 (per design doc § 4.1):
 *   - Every operation produces a unique canonical representative in [0, p).
 *   - No SIMD reductions that change accumulation order.
 *   - inv(0) is undefined behavior — caller MUST check.
 *
 * Faz 1 scope (Faz 0 design doc § 8): API skeleton only. Implementation TBD.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef DNAC_ZK_FIELD_GOLDILOCKS_H
#define DNAC_ZK_FIELD_GOLDILOCKS_H

#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ============================================================================
 * Constants
 * ========================================================================== */

/** Goldilocks prime modulus: 2^64 - 2^32 + 1 */
#define GOLDILOCKS_P ((uint64_t)0xFFFFFFFF00000001ULL)

/** Goldilocks² irreducible polynomial constant: x^2 - W where W = 7.
 *  Pinned 2026-05-21 from Plonky3 82cfad73 goldilocks/src/extension.rs. */
#define GOLDILOCKS_EXT_W ((uint64_t)7)

/** Multiplicative order of two-adic generator in base field.
 *  Goldilocks has 2^32 | (p-1), so two-adicity = 32. */
#define GOLDILOCKS_TWO_ADICITY 32

/** Goldilocks² two-adicity = 33 (from Plonky3 HasTwoAdicBinomialExtension<2>). */
#define GOLDILOCKS_EXT_TWO_ADICITY 33

/* ============================================================================
 * Base field types
 * ========================================================================== */

/**
 * @brief Goldilocks base field element.
 *
 * Stored canonically in [0, p). Public API functions MUST return canonical;
 * internal scratch may temporarily exceed p but MUST canonicalize before
 * returning to caller.
 */
typedef struct {
    uint64_t v;
} gold_fp_t;

/**
 * @brief Goldilocks² extension field element.
 *
 * Represents a + b·X where X² = W = 7. Both a, b stored canonically in [0, p).
 */
typedef struct {
    gold_fp_t a;  /**< constant term */
    gold_fp_t b;  /**< coefficient of X */
} gold_fp2_t;

/* ============================================================================
 * Base field API (Faz 1)
 * ========================================================================== */

/** Identity element 0 in base field. */
gold_fp_t gold_fp_zero(void);

/** Identity element 1 in base field. */
gold_fp_t gold_fp_one(void);

/** Construct from arbitrary u64; canonicalizes to [0, p). */
gold_fp_t gold_fp_from_u64(uint64_t x);

/** Export canonical u64; result is in [0, p). */
uint64_t gold_fp_to_u64(gold_fp_t x);

/** Addition: (a + b) mod p. */
gold_fp_t gold_fp_add(gold_fp_t a, gold_fp_t b);

/** Subtraction: (a - b) mod p. */
gold_fp_t gold_fp_sub(gold_fp_t a, gold_fp_t b);

/** Multiplication: (a * b) mod p, using sparse-prime reduction trick. */
gold_fp_t gold_fp_mul(gold_fp_t a, gold_fp_t b);

/** Negation: (p - a) mod p. */
gold_fp_t gold_fp_neg(gold_fp_t a);

/** Square: shortcut for mul(a, a). */
gold_fp_t gold_fp_sqr(gold_fp_t a);

/**
 * @brief Multiplicative inverse: a^-1 mod p.
 *
 * @note inv(0) is undefined; caller MUST check.
 *
 * @param a Non-zero field element.
 * @return Field element b such that a * b == 1 (mod p).
 */
gold_fp_t gold_fp_inv(gold_fp_t a);

/** Exponentiation: a^k mod p. Standard square-and-multiply. */
gold_fp_t gold_fp_pow(gold_fp_t a, uint64_t k);

/** Equality predicate. */
bool gold_fp_eq(gold_fp_t a, gold_fp_t b);

/** Predicate: is a == 0? */
bool gold_fp_is_zero(gold_fp_t a);

/**
 * @brief Two-adic generator of order 2^bits.
 *
 * For bits in [1, 32], returns g such that g^(2^bits) == 1 and
 * g^(2^(bits-1)) != 1.
 *
 * @param bits Order exponent in [1, 32].
 * @return Generator of subgroup of order 2^bits.
 */
gold_fp_t gold_fp_two_adic_generator(unsigned bits);

/* ============================================================================
 * Extension field API (Faz 1)
 * ========================================================================== */

/** Identity element 0 in extension field. */
gold_fp2_t gold_fp2_zero(void);

/** Identity element 1 (= 1 + 0·X) in extension field. */
gold_fp2_t gold_fp2_one(void);

/** Construct extension element a + b·X. */
gold_fp2_t gold_fp2_new(gold_fp_t a, gold_fp_t b);

/** Embed base element a as extension element a + 0·X. */
gold_fp2_t gold_fp2_from_base(gold_fp_t a);

/** Extension addition: componentwise. */
gold_fp2_t gold_fp2_add(gold_fp2_t a, gold_fp2_t b);

/** Extension subtraction: componentwise. */
gold_fp2_t gold_fp2_sub(gold_fp2_t a, gold_fp2_t b);

/**
 * @brief Extension multiplication.
 *
 * (a₀ + a₁·X)(b₀ + b₁·X) = (a₀b₀ + W·a₁b₁) + (a₀b₁ + a₁b₀)·X
 * where W = 7 (GOLDILOCKS_EXT_W).
 */
gold_fp2_t gold_fp2_mul(gold_fp2_t a, gold_fp2_t b);

/** Extension negation: componentwise. */
gold_fp2_t gold_fp2_neg(gold_fp2_t a);

/** Extension squaring. */
gold_fp2_t gold_fp2_sqr(gold_fp2_t a);

/**
 * @brief Extension inverse.
 *
 * For a = a₀ + a₁·X:
 *   norm = a₀² - W·a₁² (Frobenius norm)
 *   a^-1 = (a₀ - a₁·X) / norm
 *
 * @note inv(0) undefined; caller MUST check both components.
 */
gold_fp2_t gold_fp2_inv(gold_fp2_t a);

/** Extension equality. */
bool gold_fp2_eq(gold_fp2_t a, gold_fp2_t b);

/* ============================================================================
 * Test-vector self-check (debug, Faz 1)
 * ========================================================================== */

/**
 * @brief Sanity check: verify irreducible polynomial matches Plonky3.
 *
 * Asserts GOLDILOCKS_EXT_W == 7 and that x² - 7 is the polynomial used
 * in Plonky3 commit 82cfad73. Called from ctest_field_goldilocks; not
 * exposed in release builds.
 *
 * @return true if consistent with pinned Plonky3 source, false otherwise.
 */
bool gold_fp2_irreducible_consistency_check(void);

#ifdef __cplusplus
}
#endif

#endif /* DNAC_ZK_FIELD_GOLDILOCKS_H */
