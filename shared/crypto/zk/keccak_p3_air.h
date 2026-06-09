/**
 * @file keccak_p3_air.h
 * @brief Plonky3-style Keccak-f AIR constraint check (Sub-sprint 3.4r).
 *
 * Operates on a sequence of N rows (N = 24 × num_permutations). Verifies every
 * AIR constraint, including cross-row transitions. A "valid" trace satisfies
 * every constraint at every row pair (local_i, local_{i+1}).
 *
 * Constraint ID legend (out_first_failing_constraint):
 *   'R' — round flag (first row or rotation)
 *   'P' — preimage (first-row match or persistence)
 *   'E' — export flag (bool or zero-on-non-final)
 *   'C' — c[x] bool / c_prime[x][z] xor3 identity
 *   'A' — a_prime bool / a[y][x] limb reconstruction
 *   'p' — parity (sum of 5 a_prime bits minus c_prime ∈ {0,2,4})
 *   'X' — χ limb reconstruction for a_prime_prime
 *   'B' — a_prime_prime_0_0_bits bool / limb consistency
 *   'I' — ι (a_prime_prime_prime_0_0 == xor(a_prime_prime_0_0_bits, RC_BITS))
 *   'T' — round transition (a''' of row r == a of row r+1)
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef DNAC_ZK_KECCAK_P3_AIR_H
#define DNAC_ZK_KECCAK_P3_AIR_H

#include <stdbool.h>
#include <stdint.h>

#include "keccak_p3_cols.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Check AIR constraints across the trace.
 *
 * @param rows                          Array of `num_rows` rows.
 * @param num_rows                      Total rows in trace (typically
 *                                      `24 * num_permutations`).
 * @param out_first_failing_constraint  If non-NULL, set to the constraint ID
 *                                      of the first failure; 0 on success.
 * @param out_first_failing_row         If non-NULL, set to the row index of
 *                                      the first failure; 0 on success.
 * @param out_first_failing_index       If non-NULL, set to a per-constraint
 *                                      sub-index (e.g., (y*5+x)*64+z); 0 on
 *                                      success.
 * @return true iff every constraint holds at every row / row-pair.
 */
bool keccak_p3_check_constraints(const keccak_p3_cols_t *rows,
                                 uint32_t num_rows,
                                 char *out_first_failing_constraint,
                                 uint32_t *out_first_failing_row,
                                 uint32_t *out_first_failing_index);

#ifdef __cplusplus
}
#endif

#endif /* DNAC_ZK_KECCAK_P3_AIR_H */
