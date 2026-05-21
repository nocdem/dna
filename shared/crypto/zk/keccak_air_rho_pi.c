/**
 * @file keccak_air_rho_pi.c
 * @brief ρ ∘ π step AIR encoding.
 *
 * Mapping (FIPS-202 §3.2.2 + §3.2.3):
 *   src_lane = x + 5*y                     (x, y ∈ [0, 5))
 *   dst_lane = y + 5*((2x + 3y) mod 5)
 *   output_bits[dst_lane * 64 + z] = input_bits[src_lane * 64 + ((z + 64 - rot[src_lane]) mod 64)]
 *
 * The rotation goes "left by rot[src]", equivalently bit at output position z
 * came from input position (z − rot[src]) mod 64.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: Apache-2.0
 */

#include "keccak_air_rho_pi.h"
#include "keccak_air_bits.h"

#include <string.h>

/* FIPS-202 ρ rotation offsets, indexed by src_lane = x + 5*y. */
static const unsigned RHO_OFF[KECCAK_NUM_LANES] = {
     0,  1, 62, 28, 27,    /* y = 0 */
    36, 44,  6, 55, 20,    /* y = 1 */
     3, 10, 43, 25, 39,    /* y = 2 */
    41, 45, 15, 21,  8,    /* y = 3 */
    18,  2, 61, 56, 14     /* y = 4 */
};

/* Compute π destination lane for each source lane. */
static unsigned pi_dst_lane(unsigned src_lane) {
    unsigned x = src_lane % 5;
    unsigned y = src_lane / 5;
    return y + 5 * ((2 * x + 3 * y) % 5);
}

void keccak_air_rho_pi_build_witness(const uint64_t input_lanes[KECCAK_NUM_LANES],
                                     const uint64_t output_lanes[KECCAK_NUM_LANES],
                                     keccak_air_rho_pi_witness_t *w) {
    for (unsigned L = 0; L < KECCAK_NUM_LANES; L++) {
        keccak_air_lane_to_bits(input_lanes[L],
                                &w->input_bits[L * KECCAK_BITS_PER_LANE]);
        keccak_air_lane_to_bits(output_lanes[L],
                                &w->output_bits[L * KECCAK_BITS_PER_LANE]);
    }
}

bool keccak_air_rho_pi_check_constraints(const keccak_air_rho_pi_witness_t *w,
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

    /* Identity equations: for each src_lane, output[dst][z] == input[src][(z − rot[src]) mod 64]. */
    for (unsigned src = 0; src < KECCAK_NUM_LANES; src++) {
        unsigned dst = pi_dst_lane(src);
        unsigned rot = RHO_OFF[src];
        for (unsigned z = 0; z < KECCAK_BITS_PER_LANE; z++) {
            unsigned src_z = (z + KECCAK_BITS_PER_LANE - rot) % KECCAK_BITS_PER_LANE;
            gold_fp2_t expected = w->input_bits[src * KECCAK_BITS_PER_LANE + src_z];
            gold_fp2_t actual   = w->output_bits[dst * KECCAK_BITS_PER_LANE + z];
            if (!gold_fp2_eq(expected, actual)) {
                if (out_first_failing_constraint) *out_first_failing_constraint = '=';
                if (out_first_failing_index) *out_first_failing_index = dst * KECCAK_BITS_PER_LANE + z;
                return false;
            }
        }
    }

    return true;
}
