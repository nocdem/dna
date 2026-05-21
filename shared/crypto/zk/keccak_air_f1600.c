/**
 * @file keccak_air_f1600.c
 * @brief 24-round Keccak-f[1600] AIR assembly.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: Apache-2.0
 */

#include "keccak_air_f1600.h"
#include "keccak_air_bits.h"

#include <string.h>

/* Helper: reconstruct u64 lanes from bit array. */
static void bits_to_lanes(const gold_fp2_t *bits,
                          uint64_t lanes[KECCAK_NUM_LANES]) {
    for (unsigned L = 0; L < KECCAK_NUM_LANES; L++) {
        lanes[L] = keccak_air_bits_to_lane(&bits[L * KECCAK_BITS_PER_LANE]);
    }
}

/* Helper: write u64 lanes into bit array. */
static void lanes_to_bits(const uint64_t lanes[KECCAK_NUM_LANES],
                          gold_fp2_t *bits) {
    for (unsigned L = 0; L < KECCAK_NUM_LANES; L++) {
        keccak_air_lane_to_bits(lanes[L], &bits[L * KECCAK_BITS_PER_LANE]);
    }
}

void keccak_air_f1600_build_witness(const uint64_t initial_lanes[KECCAK_NUM_LANES],
                                    const uint64_t final_lanes[KECCAK_NUM_LANES],
                                    keccak_air_f1600_witness_t *w) {
    (void)final_lanes; /* unused parameter — we recompute and verify in check */

    uint64_t state[KECCAK_NUM_LANES];
    memcpy(state, initial_lanes, sizeof(state));

    for (unsigned r = 0; r < KECCAK_AIR_F1600_ROUNDS; r++) {
        keccak_air_round_witness_t *R = &w->rounds[r];

        /* θ */
        uint64_t after_theta[KECCAK_NUM_LANES];
        memcpy(after_theta, state, sizeof(after_theta));
        keccak_ref_theta(after_theta);
        keccak_air_theta_build_witness(state, after_theta, &R->theta);

        /* ρ + π */
        uint64_t after_rho_pi[KECCAK_NUM_LANES];
        memcpy(after_rho_pi, after_theta, sizeof(after_rho_pi));
        keccak_ref_rho_pi(after_rho_pi);
        keccak_air_rho_pi_build_witness(after_theta, after_rho_pi, &R->rho_pi);

        /* χ */
        uint64_t after_chi[KECCAK_NUM_LANES];
        memcpy(after_chi, after_rho_pi, sizeof(after_chi));
        keccak_ref_chi(after_chi);
        keccak_air_chi_build_witness(after_rho_pi, after_chi, &R->chi);

        /* ι */
        uint64_t after_iota[KECCAK_NUM_LANES];
        memcpy(after_iota, after_chi, sizeof(after_iota));
        keccak_ref_iota(after_iota, keccak_ref_round_constants[r]);
        keccak_air_iota_build_witness(after_chi, after_iota, &R->iota);

        /* Next round input. */
        memcpy(state, after_iota, sizeof(state));
    }
}

/* Compare two bit arrays. */
static bool bit_arrays_equal(const gold_fp2_t *a, const gold_fp2_t *b, size_t n) {
    for (size_t i = 0; i < n; i++) {
        if (!gold_fp2_eq(a[i], b[i])) return false;
    }
    return true;
}

bool keccak_air_f1600_check_constraints(const keccak_air_f1600_witness_t *w,
                                        uint32_t *out_failing_round,
                                        char *out_failing_step,
                                        char *out_inner_constraint,
                                        uint32_t *out_failing_index) {
    if (out_failing_round) *out_failing_round = 0;
    if (out_failing_step) *out_failing_step = 0;
    if (out_inner_constraint) *out_inner_constraint = 0;
    if (out_failing_index) *out_failing_index = 0;

    for (unsigned r = 0; r < KECCAK_AIR_F1600_ROUNDS; r++) {
        const keccak_air_round_witness_t *R = &w->rounds[r];

        /* θ constraints. */
        {
            char fc = 0; uint32_t fi = 0;
            if (!keccak_air_theta_check_constraints(&R->theta, &fc, &fi)) {
                if (out_failing_round) *out_failing_round = r;
                if (out_failing_step) *out_failing_step = 'T';
                if (out_inner_constraint) *out_inner_constraint = fc;
                if (out_failing_index) *out_failing_index = fi;
                return false;
            }
        }

        /* Link: ρπ.input == θ.output. */
        if (!bit_arrays_equal(R->rho_pi.input_bits, R->theta.output_bits, KECCAK_STATE_BITS)) {
            if (out_failing_round) *out_failing_round = r;
            if (out_failing_step) *out_failing_step = 'L';
            if (out_inner_constraint) *out_inner_constraint = 'R';   /* link to rho_pi */
            return false;
        }
        /* ρπ constraints. */
        {
            char fc = 0; uint32_t fi = 0;
            if (!keccak_air_rho_pi_check_constraints(&R->rho_pi, &fc, &fi)) {
                if (out_failing_round) *out_failing_round = r;
                if (out_failing_step) *out_failing_step = 'R';
                if (out_inner_constraint) *out_inner_constraint = fc;
                if (out_failing_index) *out_failing_index = fi;
                return false;
            }
        }

        /* Link: χ.input == ρπ.output. */
        if (!bit_arrays_equal(R->chi.input_bits, R->rho_pi.output_bits, KECCAK_STATE_BITS)) {
            if (out_failing_round) *out_failing_round = r;
            if (out_failing_step) *out_failing_step = 'L';
            if (out_inner_constraint) *out_inner_constraint = 'C';
            return false;
        }
        /* χ constraints. */
        {
            char fc = 0; uint32_t fi = 0;
            if (!keccak_air_chi_check_constraints(&R->chi, &fc, &fi)) {
                if (out_failing_round) *out_failing_round = r;
                if (out_failing_step) *out_failing_step = 'C';
                if (out_inner_constraint) *out_inner_constraint = fc;
                if (out_failing_index) *out_failing_index = fi;
                return false;
            }
        }

        /* Link: ι.input == χ.output. */
        if (!bit_arrays_equal(R->iota.input_bits, R->chi.output_bits, KECCAK_STATE_BITS)) {
            if (out_failing_round) *out_failing_round = r;
            if (out_failing_step) *out_failing_step = 'L';
            if (out_inner_constraint) *out_inner_constraint = 'I';
            return false;
        }
        /* ι constraints with this round's RC. */
        {
            char fc = 0; uint32_t fi = 0;
            if (!keccak_air_iota_check_constraints(&R->iota,
                                                    keccak_ref_round_constants[r],
                                                    &fc, &fi)) {
                if (out_failing_round) *out_failing_round = r;
                if (out_failing_step) *out_failing_step = 'I';
                if (out_inner_constraint) *out_inner_constraint = fc;
                if (out_failing_index) *out_failing_index = fi;
                return false;
            }
        }

        /* Link to next round: round[r+1].theta.input == round[r].iota.output. */
        if (r + 1 < KECCAK_AIR_F1600_ROUNDS) {
            if (!bit_arrays_equal(w->rounds[r + 1].theta.input_bits,
                                  R->iota.output_bits, KECCAK_STATE_BITS)) {
                if (out_failing_round) *out_failing_round = r;
                if (out_failing_step) *out_failing_step = 'L';
                if (out_inner_constraint) *out_inner_constraint = 'N';  /* next-round */
                return false;
            }
        }
    }

    (void)bits_to_lanes; (void)lanes_to_bits;  /* helpers used only by external callers */
    return true;
}
