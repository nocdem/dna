/**
 * @file keccak_air_bits.c
 * @brief Keccak-AIR bit decomposition + XOR-in-field building blocks.
 *
 * See keccak_air_bits.h for algorithm spec.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: Apache-2.0
 */

#include "keccak_air_bits.h"

/* ============================================================================
 * Bit ↔ Lane conversion
 * ========================================================================== */

void keccak_air_lane_to_bits(uint64_t lane,
                             gold_fp2_t bits[KECCAK_BITS_PER_LANE]) {
    for (unsigned i = 0; i < KECCAK_BITS_PER_LANE; i++) {
        uint64_t b = (lane >> i) & 1ULL;
        bits[i] = gold_fp2_from_base(gold_fp_from_u64(b));
    }
}

uint64_t keccak_air_bits_to_lane(const gold_fp2_t bits[KECCAK_BITS_PER_LANE]) {
    uint64_t out = 0;
    for (unsigned i = 0; i < KECCAK_BITS_PER_LANE; i++) {
        /* Use the a-component canonical value as the bit. */
        uint64_t b = gold_fp_to_u64(bits[i].a);
        if (b & 1ULL) {
            out |= (1ULL << i);
        }
    }
    return out;
}

/* ============================================================================
 * Constraint helpers
 * ========================================================================== */

static inline bool fp2_is_zero(gold_fp2_t x) {
    return gold_fp2_eq(x, gold_fp2_zero());
}

bool keccak_air_check_bits_binary(const gold_fp2_t *bits, size_t n) {
    gold_fp2_t one = gold_fp2_one();
    for (size_t i = 0; i < n; i++) {
        gold_fp2_t one_minus = gold_fp2_sub(one, bits[i]);
        gold_fp2_t prod = gold_fp2_mul(bits[i], one_minus);
        if (!fp2_is_zero(prod)) return false;
    }
    return true;
}

gold_fp2_t keccak_air_xor2(gold_fp2_t a, gold_fp2_t b) {
    /* a + b - 2*a*b */
    gold_fp2_t ab = gold_fp2_mul(a, b);
    gold_fp2_t two = gold_fp2_from_base(gold_fp_from_u64(2));
    gold_fp2_t two_ab = gold_fp2_mul(two, ab);
    return gold_fp2_sub(gold_fp2_add(a, b), two_ab);
}

bool keccak_air_check_xor2(gold_fp2_t a,
                           gold_fp2_t b,
                           gold_fp2_t result) {
    gold_fp2_t expected = keccak_air_xor2(a, b);
    return gold_fp2_eq(result, expected);
}

void keccak_air_xor5(const gold_fp2_t bits[5],
                     gold_fp2_t *result,
                     gold_fp2_t *witness) {
    /* Compute sum in field. */
    gold_fp2_t sum = gold_fp2_zero();
    for (unsigned i = 0; i < 5; i++) {
        sum = gold_fp2_add(sum, bits[i]);
    }
    /* sum's canonical u64 value is in [0, 5] given bits are binary.
     * result = sum & 1; witness = sum / 2. */
    uint64_t s = gold_fp_to_u64(sum.a); /* sum's base-field component */
    uint64_t r = s & 1ULL;
    uint64_t w = s >> 1;
    *result = gold_fp2_from_base(gold_fp_from_u64(r));
    *witness = gold_fp2_from_base(gold_fp_from_u64(w));
}

bool keccak_air_check_xor5(const gold_fp2_t bits[5],
                           gold_fp2_t result,
                           gold_fp2_t witness) {
    gold_fp2_t one = gold_fp2_one();
    gold_fp2_t two = gold_fp2_from_base(gold_fp_from_u64(2));

    /* C1: result * (1 - result) = 0  (binary) */
    {
        gold_fp2_t r1 = gold_fp2_sub(one, result);
        gold_fp2_t p = gold_fp2_mul(result, r1);
        if (!fp2_is_zero(p)) return false;
    }
    /* C2: w * (w-1) * (w-2) = 0  (range {0,1,2}) */
    {
        gold_fp2_t w_minus_1 = gold_fp2_sub(witness, one);
        gold_fp2_t w_minus_2 = gold_fp2_sub(witness, two);
        gold_fp2_t prod = gold_fp2_mul(gold_fp2_mul(witness, w_minus_1), w_minus_2);
        if (!fp2_is_zero(prod)) return false;
    }
    /* C3: sum == result + 2*w */
    {
        gold_fp2_t sum = gold_fp2_zero();
        for (unsigned i = 0; i < 5; i++) {
            sum = gold_fp2_add(sum, bits[i]);
        }
        gold_fp2_t two_w = gold_fp2_mul(two, witness);
        gold_fp2_t expected = gold_fp2_add(result, two_w);
        if (!gold_fp2_eq(sum, expected)) return false;
    }
    return true;
}
