/**
 * @file keccak_air_iota.c
 * @brief Keccak ι step AIR encoding.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: Apache-2.0
 */

#include "keccak_air_iota.h"
#include "keccak_air_bits.h"

#include <string.h>

void keccak_air_iota_build_witness(const uint64_t input_lanes[KECCAK_NUM_LANES],
                                   const uint64_t output_lanes[KECCAK_NUM_LANES],
                                   keccak_air_iota_witness_t *w) {
    for (unsigned L = 0; L < KECCAK_NUM_LANES; L++) {
        keccak_air_lane_to_bits(input_lanes[L],
                                &w->input_bits[L * KECCAK_BITS_PER_LANE]);
        keccak_air_lane_to_bits(output_lanes[L],
                                &w->output_bits[L * KECCAK_BITS_PER_LANE]);
    }
}

bool keccak_air_iota_check_constraints(const keccak_air_iota_witness_t *w,
                                       uint64_t round_constant,
                                       char *out_first_failing_constraint,
                                       uint32_t *out_first_failing_index) {
    if (out_first_failing_constraint) *out_first_failing_constraint = 0;
    if (out_first_failing_index) *out_first_failing_index = 0;

    if (!keccak_air_check_bits_binary(w->input_bits, KECCAK_STATE_BITS)) {
        if (out_first_failing_constraint) *out_first_failing_constraint = 'A';
        return false;
    }
    if (!keccak_air_check_bits_binary(w->output_bits, KECCAK_STATE_BITS)) {
        if (out_first_failing_constraint) *out_first_failing_constraint = 'O';
        return false;
    }

    /* Lane 0: output = input XOR rc_bit (XOR-2 per bit). */
    for (unsigned z = 0; z < KECCAK_BITS_PER_LANE; z++) {
        uint64_t rc_bit = (round_constant >> z) & 1ULL;
        gold_fp2_t rc_b = gold_fp2_from_base(gold_fp_from_u64(rc_bit));
        gold_fp2_t a = w->input_bits[z];
        gold_fp2_t expected = keccak_air_xor2(a, rc_b);
        gold_fp2_t got = w->output_bits[z];
        if (!gold_fp2_eq(got, expected)) {
            if (out_first_failing_constraint) *out_first_failing_constraint = 'X';
            if (out_first_failing_index) *out_first_failing_index = z;
            return false;
        }
    }

    /* Lanes 1..24: identity. */
    for (unsigned L = 1; L < KECCAK_NUM_LANES; L++) {
        for (unsigned z = 0; z < KECCAK_BITS_PER_LANE; z++) {
            gold_fp2_t in_b  = w->input_bits[L * KECCAK_BITS_PER_LANE + z];
            gold_fp2_t out_b = w->output_bits[L * KECCAK_BITS_PER_LANE + z];
            if (!gold_fp2_eq(in_b, out_b)) {
                if (out_first_failing_constraint) *out_first_failing_constraint = 'I';
                if (out_first_failing_index) *out_first_failing_index = L * KECCAK_BITS_PER_LANE + z;
                return false;
            }
        }
    }

    return true;
}
