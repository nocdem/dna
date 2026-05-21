/**
 * @file keccak_air_theta.h
 * @brief Keccak θ (theta) step AIR encoding (DNAC v3, Sub-sprint 3.3b.2)
 *
 * θ step (FIPS-202 § 3.2.1) acting on the 5×5×64 bit state:
 *   C[x][z] = A[x][0][z] ⊕ A[x][1][z] ⊕ A[x][2][z] ⊕ A[x][3][z] ⊕ A[x][4][z]
 *   D[x][z] = C[(x-1) mod 5][z] ⊕ C[(x+1) mod 5][(z-1) mod 64]
 *   A'[x][y][z] = A[x][y][z] ⊕ D[x][z]
 *
 * AIR encoding (witness):
 *   - Input bits: 1600 (25 lanes × 64 bits)        — binary
 *   - C bits:     320 (5 columns × 64)             — binary
 *   - C xor5 witness: 320 (auxiliary, ∈ {0,1,2})
 *   - D bits:     320 (5 × 64)                     — binary
 *   - Output bits: 1600                            — binary
 *
 * Constraint count per θ step:
 *   - Bit binary: 1600 + 320 + 320 + 1600 = 3,840
 *   - C XOR-5: 320 × 3 (result_binary + w_range + sum_eq) = 960
 *   - D XOR-2: 320 (result = a + b - 2ab)
 *   - State update XOR-2: 1600
 *   Total: ~6,720 constraints per θ step.
 *
 * Indexing convention (consistent with keccak_air_bits):
 *   - Lane index L = x + 5*y  ∈ [0, 25)
 *   - Input bits indexed: input_bits[L * 64 + z]  (z = bit position)
 *   - C bits indexed: c_bits[x * 64 + z]
 *   - D bits indexed: d_bits[x * 64 + z]
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef DNAC_ZK_KECCAK_AIR_THETA_H
#define DNAC_ZK_KECCAK_AIR_THETA_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "field_goldilocks.h"
#include "keccak_ref.h"

#ifdef __cplusplus
extern "C" {
#endif

/** Number of bits in the full Keccak state. */
#define KECCAK_STATE_BITS    (KECCAK_NUM_LANES * KECCAK_BITS_PER_LANE)   /* 1600 */

/** Number of column-parity bits (C[x][z]). */
#define KECCAK_THETA_C_BITS  (5 * KECCAK_BITS_PER_LANE)                  /* 320 */

/** Number of D-vector bits (D[x][z]). */
#define KECCAK_THETA_D_BITS  (5 * KECCAK_BITS_PER_LANE)                  /* 320 */

/** Bits per lane (re-exported from keccak_air_bits). */
#ifndef KECCAK_BITS_PER_LANE
#define KECCAK_BITS_PER_LANE 64
#endif

/**
 * @brief Full witness for one θ step.
 *
 * Caller fills in input_bits + output_bits (from u64 state pair), then calls
 * keccak_air_theta_build_aux to populate C, c_xor5_witness, D. Then
 * keccak_air_theta_check_constraints verifies all constraints.
 */
typedef struct {
    /** 1600 input state bits (read-only after construction). */
    gold_fp2_t input_bits[KECCAK_STATE_BITS];
    /** 1600 output state bits (= θ(input_bits) in field). */
    gold_fp2_t output_bits[KECCAK_STATE_BITS];
    /** 320 column parity bits C[x][z]. */
    gold_fp2_t c_bits[KECCAK_THETA_C_BITS];
    /** 320 auxiliary XOR-5 witnesses w ∈ {0,1,2}, one per C bit. */
    gold_fp2_t c_xor5_witness[KECCAK_THETA_C_BITS];
    /** 320 D-vector bits D[x][z]. */
    gold_fp2_t d_bits[KECCAK_THETA_D_BITS];
} keccak_air_theta_witness_t;

/**
 * @brief Build complete witness from a u64 state pair.
 *
 * Performs bit decomposition of input/output and populates all auxiliary
 * columns. The output_lanes must equal θ(input_lanes); if they don't,
 * the constraint check will fail.
 *
 * @param input_lanes   25-lane u64 state before θ.
 * @param output_lanes  25-lane u64 state after θ.
 * @param w             Witness to populate.
 */
void keccak_air_theta_build_witness(const uint64_t input_lanes[KECCAK_NUM_LANES],
                                    const uint64_t output_lanes[KECCAK_NUM_LANES],
                                    keccak_air_theta_witness_t *w);

/**
 * @brief Verify all θ-step constraints over the witness.
 *
 * Checks ~6,720 constraint equations. Returns true iff every one is zero.
 *
 * @param w                              Filled witness.
 * @param out_first_failing_constraint   Optional: 'A' = binary bit,
 *                                       'C' = column parity, 'D' = D xor,
 *                                       'U' = state update.
 * @param out_first_failing_index        Optional: bit/column index of failure.
 * @return true iff constraints satisfied.
 */
bool keccak_air_theta_check_constraints(const keccak_air_theta_witness_t *w,
                                        char *out_first_failing_constraint,
                                        uint32_t *out_first_failing_index);

#ifdef __cplusplus
}
#endif

#endif /* DNAC_ZK_KECCAK_AIR_THETA_H */
