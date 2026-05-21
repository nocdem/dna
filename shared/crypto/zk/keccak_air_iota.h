/**
 * @file keccak_air_iota.h
 * @brief Keccak ι (iota) step AIR encoding (DNAC v3, Sub-sprint 3.3b.5)
 *
 * ι step: A'[0][0] = A[0][0] XOR round_constant; other 24 lanes pass through.
 *
 * The round constant is a PUBLIC input (one of 24 hardcoded values per round
 * — see keccak_ref_round_constants[]). Verifier knows the round index and
 * thus the constant, so no auxiliary witness is needed.
 *
 * Constraints (~3,200 per ι step, all degree ≤ 2):
 *   - 1600 input bits binary
 *   - 1600 output bits binary
 *   - 64 XOR-2 constraints for lane 0 (output[z] = input[z] + rc_bit[z] - 2*input*rc_bit[z])
 *   - 1536 identity constraints for lanes 1..24
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef DNAC_ZK_KECCAK_AIR_IOTA_H
#define DNAC_ZK_KECCAK_AIR_IOTA_H

#include <stdbool.h>
#include <stdint.h>

#include "field_goldilocks.h"
#include "keccak_air_theta.h"  /* KECCAK_STATE_BITS */

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    gold_fp2_t input_bits[KECCAK_STATE_BITS];
    gold_fp2_t output_bits[KECCAK_STATE_BITS];
} keccak_air_iota_witness_t;

void keccak_air_iota_build_witness(const uint64_t input_lanes[KECCAK_NUM_LANES],
                                   const uint64_t output_lanes[KECCAK_NUM_LANES],
                                   keccak_air_iota_witness_t *w);

/**
 * @brief Verify ι constraints given the round constant.
 *
 * @param w                              Witness.
 * @param round_constant                 Public RC for this round.
 * @param out_first_failing_constraint   'A'/'O' binary, 'X' XOR fail, 'I' identity fail.
 * @param out_first_failing_index        Bit index.
 */
bool keccak_air_iota_check_constraints(const keccak_air_iota_witness_t *w,
                                       uint64_t round_constant,
                                       char *out_first_failing_constraint,
                                       uint32_t *out_first_failing_index);

#ifdef __cplusplus
}
#endif

#endif /* DNAC_ZK_KECCAK_AIR_IOTA_H */
