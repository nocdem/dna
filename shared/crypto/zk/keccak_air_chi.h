/**
 * @file keccak_air_chi.h
 * @brief Keccak χ (chi) step AIR encoding (DNAC v3, Sub-sprint 3.3b.4)
 *
 * χ step (FIPS-202 §3.2.4) — the only non-linear step in Keccak-f.
 * Acts row-wise (constant y):
 *
 *   A'[x][y][z] = A[x][y][z] ⊕ ((NOT A[(x+1) mod 5][y][z]) AND A[(x+2) mod 5][y][z])
 *
 * AIR encoding strategy: introduce auxiliary witness `t` per output bit:
 *
 *   t = (1 − b) * c       where b = A[(x+1)%5][y][z], c = A[(x+2)%5][y][z]
 *   output = XOR(a, t)    where a = A[x][y][z]
 *                         = a + t − 2*a*t  (binary XOR in field)
 *
 * Constraints per output bit (5 total):
 *   1. a ∈ {0, 1}        (input bit binary — already enforced at trace level)
 *   2. t ∈ {0, 1}        (aux witness binary)
 *   3. output ∈ {0, 1}   (output bit binary)
 *   4. t = c − b*c       (degree-2 polynomial — closed-form for (1-b)*c)
 *   5. output = a + t − 2*a*t  (XOR-2 closed-form, degree-2)
 *
 * Total χ constraints: ~8,000 (1600 t binary + 1600 t formula + 1600 output formula
 * + already-covered input/output binary = additional ~4,800 unique).
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef DNAC_ZK_KECCAK_AIR_CHI_H
#define DNAC_ZK_KECCAK_AIR_CHI_H

#include <stdbool.h>
#include <stdint.h>

#include "field_goldilocks.h"
#include "keccak_air_theta.h"   /* for KECCAK_STATE_BITS */

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Witness for one χ step.
 *
 * t_bits is auxiliary: t[L*64 + z] = (1 − input[next1, z]) * input[next2, z]
 * where next1 = ((L%5)+1)%5 + 5*(L/5), next2 = ((L%5)+2)%5 + 5*(L/5).
 */
typedef struct {
    gold_fp2_t input_bits[KECCAK_STATE_BITS];
    gold_fp2_t output_bits[KECCAK_STATE_BITS];
    gold_fp2_t t_bits[KECCAK_STATE_BITS];   /* auxiliary: (1-b)*c per output bit */
} keccak_air_chi_witness_t;

void keccak_air_chi_build_witness(const uint64_t input_lanes[KECCAK_NUM_LANES],
                                  const uint64_t output_lanes[KECCAK_NUM_LANES],
                                  keccak_air_chi_witness_t *w);

bool keccak_air_chi_check_constraints(const keccak_air_chi_witness_t *w,
                                      char *out_first_failing_constraint,
                                      uint32_t *out_first_failing_index);

#ifdef __cplusplus
}
#endif

#endif /* DNAC_ZK_KECCAK_AIR_CHI_H */
