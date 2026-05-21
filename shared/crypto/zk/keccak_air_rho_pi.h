/**
 * @file keccak_air_rho_pi.h
 * @brief Keccak ρ + π steps AIR encoding (DNAC v3, Sub-sprint 3.3b.3)
 *
 * ρ (rho) step:    each lane is left-rotated by a fixed offset r[x + 5*y].
 * π (pi) step:     lane positions are permuted: dst = y + 5*((2x + 3y) mod 5).
 *
 * Combined ρ ∘ π acting on bit-decomposed state:
 *   output_bits[dst_lane][z] = input_bits[src_lane][(z − r[src_lane]) mod 64]
 *
 * AIR constraints (~4,800 per step — much simpler than θ):
 *   - 1600 input bits binary
 *   - 1600 output bits binary
 *   - 1600 identity equations: output[dst, z] == input[src, (z - rot[src]) mod 64]
 *
 * No XOR, no non-linear operation, no auxiliary witnesses.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef DNAC_ZK_KECCAK_AIR_RHO_PI_H
#define DNAC_ZK_KECCAK_AIR_RHO_PI_H

#include <stdbool.h>
#include <stdint.h>

#include "field_goldilocks.h"
#include "keccak_air_theta.h"  /* re-use KECCAK_STATE_BITS */

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Witness for one ρ ∘ π step.
 */
typedef struct {
    gold_fp2_t input_bits[KECCAK_STATE_BITS];
    gold_fp2_t output_bits[KECCAK_STATE_BITS];
} keccak_air_rho_pi_witness_t;

/**
 * @brief Build witness from a u64 state pair.
 *
 * @param input_lanes    25-lane state before ρ ∘ π.
 * @param output_lanes   25-lane state after  ρ ∘ π.
 * @param w              Witness to populate.
 */
void keccak_air_rho_pi_build_witness(const uint64_t input_lanes[KECCAK_NUM_LANES],
                                     const uint64_t output_lanes[KECCAK_NUM_LANES],
                                     keccak_air_rho_pi_witness_t *w);

/**
 * @brief Verify constraints for ρ ∘ π.
 *
 * @return true iff: (a) all bits binary, (b) every output bit matches the
 *         expected input bit per the FIPS-202 ρ/π mapping.
 */
bool keccak_air_rho_pi_check_constraints(const keccak_air_rho_pi_witness_t *w,
                                         char *out_first_failing_constraint,
                                         uint32_t *out_first_failing_index);

#ifdef __cplusplus
}
#endif

#endif /* DNAC_ZK_KECCAK_AIR_RHO_PI_H */
