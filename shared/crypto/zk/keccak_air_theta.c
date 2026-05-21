/**
 * @file keccak_air_theta.c
 * @brief Keccak θ step AIR encoding — witness builder + constraint checker.
 *
 * See keccak_air_theta.h for spec.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: Apache-2.0
 */

#include "keccak_air_theta.h"
#include "keccak_air_bits.h"

#include <string.h>

/* ============================================================================
 * Index helpers
 * ========================================================================== */

static inline size_t input_idx(unsigned lane, unsigned z) {
    return (size_t)lane * KECCAK_BITS_PER_LANE + z;
}
static inline size_t cd_idx(unsigned x, unsigned z) {
    return (size_t)x * KECCAK_BITS_PER_LANE + z;
}

static inline bool fp2_is_zero_local(gold_fp2_t v) {
    return gold_fp2_eq(v, gold_fp2_zero());
}

/* ============================================================================
 * Witness builder
 * ========================================================================== */

void keccak_air_theta_build_witness(const uint64_t input_lanes[KECCAK_NUM_LANES],
                                    const uint64_t output_lanes[KECCAK_NUM_LANES],
                                    keccak_air_theta_witness_t *w) {
    /* Decompose input + output lanes into bits. */
    for (unsigned L = 0; L < KECCAK_NUM_LANES; L++) {
        keccak_air_lane_to_bits(input_lanes[L],
                                &w->input_bits[L * KECCAK_BITS_PER_LANE]);
        keccak_air_lane_to_bits(output_lanes[L],
                                &w->output_bits[L * KECCAK_BITS_PER_LANE]);
    }

    /* Compute C[x][z] = XOR over y of input[x + 5*y][z], and its XOR-5 witness. */
    for (unsigned x = 0; x < 5; x++) {
        for (unsigned z = 0; z < KECCAK_BITS_PER_LANE; z++) {
            gold_fp2_t bits5[5];
            for (unsigned y = 0; y < 5; y++) {
                bits5[y] = w->input_bits[input_idx(x + 5 * y, z)];
            }
            gold_fp2_t result, witness;
            keccak_air_xor5(bits5, &result, &witness);
            w->c_bits[cd_idx(x, z)] = result;
            w->c_xor5_witness[cd_idx(x, z)] = witness;
        }
    }

    /* Compute D[x][z] = C[(x-1)%5][z] XOR C[(x+1)%5][(z-1) mod 64]. */
    for (unsigned x = 0; x < 5; x++) {
        for (unsigned z = 0; z < KECCAK_BITS_PER_LANE; z++) {
            unsigned x_m1 = (x + 4) % 5;
            unsigned x_p1 = (x + 1) % 5;
            unsigned z_m1 = (z + KECCAK_BITS_PER_LANE - 1) % KECCAK_BITS_PER_LANE;
            gold_fp2_t a = w->c_bits[cd_idx(x_m1, z)];
            gold_fp2_t b = w->c_bits[cd_idx(x_p1, z_m1)];
            w->d_bits[cd_idx(x, z)] = keccak_air_xor2(a, b);
        }
    }
}

/* ============================================================================
 * Constraint checker
 * ========================================================================== */

bool keccak_air_theta_check_constraints(const keccak_air_theta_witness_t *w,
                                        char *out_first_failing_constraint,
                                        uint32_t *out_first_failing_index) {
    if (out_first_failing_constraint) *out_first_failing_constraint = 0;
    if (out_first_failing_index) *out_first_failing_index = 0;

    /* C-binary: every input bit ∈ {0, 1}. */
    if (!keccak_air_check_bits_binary(w->input_bits, KECCAK_STATE_BITS)) {
        if (out_first_failing_constraint) *out_first_failing_constraint = 'A';
        if (out_first_failing_index) *out_first_failing_index = 0;
        return false;
    }
    /* Output bits ∈ {0, 1}. */
    if (!keccak_air_check_bits_binary(w->output_bits, KECCAK_STATE_BITS)) {
        if (out_first_failing_constraint) *out_first_failing_constraint = 'O';
        return false;
    }
    /* C bits ∈ {0, 1}. */
    if (!keccak_air_check_bits_binary(w->c_bits, KECCAK_THETA_C_BITS)) {
        if (out_first_failing_constraint) *out_first_failing_constraint = 'C';
        return false;
    }
    /* D bits ∈ {0, 1}. */
    if (!keccak_air_check_bits_binary(w->d_bits, KECCAK_THETA_D_BITS)) {
        if (out_first_failing_constraint) *out_first_failing_constraint = 'D';
        return false;
    }

    /* C XOR-5 constraint: each C[x][z] equals XOR of input column bits with valid witness. */
    for (unsigned x = 0; x < 5; x++) {
        for (unsigned z = 0; z < KECCAK_BITS_PER_LANE; z++) {
            gold_fp2_t bits5[5];
            for (unsigned y = 0; y < 5; y++) {
                bits5[y] = w->input_bits[input_idx(x + 5 * y, z)];
            }
            if (!keccak_air_check_xor5(bits5, w->c_bits[cd_idx(x, z)],
                                        w->c_xor5_witness[cd_idx(x, z)])) {
                if (out_first_failing_constraint) *out_first_failing_constraint = '5';
                if (out_first_failing_index) *out_first_failing_index = (uint32_t)cd_idx(x, z);
                return false;
            }
        }
    }

    /* D XOR-2 constraint: D[x][z] == XOR(C[(x-1)%5][z], C[(x+1)%5][(z-1)%64]). */
    for (unsigned x = 0; x < 5; x++) {
        for (unsigned z = 0; z < KECCAK_BITS_PER_LANE; z++) {
            unsigned x_m1 = (x + 4) % 5;
            unsigned x_p1 = (x + 1) % 5;
            unsigned z_m1 = (z + KECCAK_BITS_PER_LANE - 1) % KECCAK_BITS_PER_LANE;
            gold_fp2_t a = w->c_bits[cd_idx(x_m1, z)];
            gold_fp2_t b = w->c_bits[cd_idx(x_p1, z_m1)];
            if (!keccak_air_check_xor2(a, b, w->d_bits[cd_idx(x, z)])) {
                if (out_first_failing_constraint) *out_first_failing_constraint = '2';
                if (out_first_failing_index) *out_first_failing_index = (uint32_t)cd_idx(x, z);
                return false;
            }
        }
    }

    /* State update XOR-2: output[L][z] == XOR(input[L][z], D[x][z])
     * where L = x + 5*y, so D index is x = L % 5. */
    for (unsigned L = 0; L < KECCAK_NUM_LANES; L++) {
        unsigned x = L % 5;
        for (unsigned z = 0; z < KECCAK_BITS_PER_LANE; z++) {
            gold_fp2_t in_b = w->input_bits[input_idx(L, z)];
            gold_fp2_t d_b  = w->d_bits[cd_idx(x, z)];
            gold_fp2_t expected = keccak_air_xor2(in_b, d_b);
            if (!gold_fp2_eq(w->output_bits[input_idx(L, z)], expected)) {
                if (out_first_failing_constraint) *out_first_failing_constraint = 'U';
                if (out_first_failing_index) *out_first_failing_index = (uint32_t)input_idx(L, z);
                return false;
            }
        }
    }

    return true;
}
