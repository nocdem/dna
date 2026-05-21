/**
 * @file keccak_air_chi.c
 * @brief Keccak χ step AIR encoding implementation.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: Apache-2.0
 */

#include "keccak_air_chi.h"
#include "keccak_air_bits.h"

#include <string.h>

static inline unsigned chi_next1(unsigned L) {
    unsigned x = L % 5, y = L / 5;
    return ((x + 1) % 5) + 5 * y;
}

static inline unsigned chi_next2(unsigned L) {
    unsigned x = L % 5, y = L / 5;
    return ((x + 2) % 5) + 5 * y;
}

void keccak_air_chi_build_witness(const uint64_t input_lanes[KECCAK_NUM_LANES],
                                  const uint64_t output_lanes[KECCAK_NUM_LANES],
                                  keccak_air_chi_witness_t *w) {
    for (unsigned L = 0; L < KECCAK_NUM_LANES; L++) {
        keccak_air_lane_to_bits(input_lanes[L],
                                &w->input_bits[L * KECCAK_BITS_PER_LANE]);
        keccak_air_lane_to_bits(output_lanes[L],
                                &w->output_bits[L * KECCAK_BITS_PER_LANE]);
    }
    /* Compute t[L, z] = (1 - input[next1, z]) * input[next2, z]. */
    gold_fp2_t one = gold_fp2_one();
    for (unsigned L = 0; L < KECCAK_NUM_LANES; L++) {
        unsigned n1 = chi_next1(L);
        unsigned n2 = chi_next2(L);
        for (unsigned z = 0; z < KECCAK_BITS_PER_LANE; z++) {
            gold_fp2_t b = w->input_bits[n1 * KECCAK_BITS_PER_LANE + z];
            gold_fp2_t c = w->input_bits[n2 * KECCAK_BITS_PER_LANE + z];
            gold_fp2_t one_minus_b = gold_fp2_sub(one, b);
            w->t_bits[L * KECCAK_BITS_PER_LANE + z] =
                gold_fp2_mul(one_minus_b, c);
        }
    }
}

bool keccak_air_chi_check_constraints(const keccak_air_chi_witness_t *w,
                                      char *out_first_failing_constraint,
                                      uint32_t *out_first_failing_index) {
    if (out_first_failing_constraint) *out_first_failing_constraint = 0;
    if (out_first_failing_index) *out_first_failing_index = 0;

    /* Binary constraints. */
    if (!keccak_air_check_bits_binary(w->input_bits, KECCAK_STATE_BITS)) {
        if (out_first_failing_constraint) *out_first_failing_constraint = 'A';
        return false;
    }
    if (!keccak_air_check_bits_binary(w->output_bits, KECCAK_STATE_BITS)) {
        if (out_first_failing_constraint) *out_first_failing_constraint = 'O';
        return false;
    }
    if (!keccak_air_check_bits_binary(w->t_bits, KECCAK_STATE_BITS)) {
        if (out_first_failing_constraint) *out_first_failing_constraint = 'T';
        return false;
    }

    /* t formula: t = c - b*c    (= (1-b)*c). */
    for (unsigned L = 0; L < KECCAK_NUM_LANES; L++) {
        unsigned n1 = chi_next1(L);
        unsigned n2 = chi_next2(L);
        for (unsigned z = 0; z < KECCAK_BITS_PER_LANE; z++) {
            gold_fp2_t b = w->input_bits[n1 * KECCAK_BITS_PER_LANE + z];
            gold_fp2_t c = w->input_bits[n2 * KECCAK_BITS_PER_LANE + z];
            gold_fp2_t bc = gold_fp2_mul(b, c);
            gold_fp2_t expected_t = gold_fp2_sub(c, bc);
            gold_fp2_t t = w->t_bits[L * KECCAK_BITS_PER_LANE + z];
            if (!gold_fp2_eq(t, expected_t)) {
                if (out_first_failing_constraint) *out_first_failing_constraint = 'F';
                if (out_first_failing_index) *out_first_failing_index = L * KECCAK_BITS_PER_LANE + z;
                return false;
            }
        }
    }

    /* output XOR formula: output = a + t - 2*a*t. */
    for (unsigned L = 0; L < KECCAK_NUM_LANES; L++) {
        for (unsigned z = 0; z < KECCAK_BITS_PER_LANE; z++) {
            gold_fp2_t a = w->input_bits[L * KECCAK_BITS_PER_LANE + z];
            gold_fp2_t t = w->t_bits[L * KECCAK_BITS_PER_LANE + z];
            gold_fp2_t expected = keccak_air_xor2(a, t);
            gold_fp2_t got = w->output_bits[L * KECCAK_BITS_PER_LANE + z];
            if (!gold_fp2_eq(got, expected)) {
                if (out_first_failing_constraint) *out_first_failing_constraint = 'X';
                if (out_first_failing_index) *out_first_failing_index = L * KECCAK_BITS_PER_LANE + z;
                return false;
            }
        }
    }

    return true;
}
