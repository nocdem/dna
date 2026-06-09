/**
 * @file keccak_p3_trace.h
 * @brief Plonky3-style Keccak-f AIR trace generation (Sub-sprint 3.4r).
 *
 * Generates the 24-row trace for one Keccak-f[1600] permutation, in the
 * column layout defined by `keccak_p3_cols.h`.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef DNAC_ZK_KECCAK_P3_TRACE_H
#define DNAC_ZK_KECCAK_P3_TRACE_H

#include <stdint.h>

#include "field_goldilocks.h"
#include "keccak_p3_cols.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Generate the 24-row trace for one Keccak-f[1600] permutation.
 *
 * Indexing convention (matches Plonky3 keccak-air for byte-portable trace):
 *   - `input` is the 25-lane state in standard Keccak indexing:
 *     `input[x + 5*y]` corresponds to state lane (x, y).
 *   - Each `rows[r]` describes round r.
 *
 * Caller allocates `rows[24]`; this function fills every field.
 *
 * Witness sized ~50 KB (24 × 2633 × 8 bytes); stack-safe.
 */
void keccak_p3_generate_trace_one_perm(
    keccak_p3_cols_t rows[KECCAK_P3_NUM_ROUNDS],
    const uint64_t input[25]);

/**
 * @brief Extract the post-permutation 25-lane state from a generated trace.
 *
 * Reads from the last row. Lane (0,0) comes from a_prime_prime_prime_0_0,
 * everything else from a_prime_prime[y][x].
 *
 * Output: `out[x + 5*y]` = post-Keccak-f state lane (x, y).
 */
void keccak_p3_extract_output(
    const keccak_p3_cols_t rows[KECCAK_P3_NUM_ROUNDS],
    uint64_t out[25]);

/**
 * @brief Extract the input preimage from a generated trace's first row.
 *
 * Used to validate that the input was stored correctly. Output indexed
 * the same way as `keccak_p3_generate_trace_one_perm`'s input.
 */
void keccak_p3_extract_input(
    const keccak_p3_cols_t rows[KECCAK_P3_NUM_ROUNDS],
    uint64_t out[25]);

#ifdef __cplusplus
}
#endif

#endif /* DNAC_ZK_KECCAK_P3_TRACE_H */
