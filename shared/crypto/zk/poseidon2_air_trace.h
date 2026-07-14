/**
 * @file poseidon2_air_trace.h
 * @brief Poseidon2 AIR single-permutation trace-row generation (DNAC v3, FP1c.2).
 *
 * Port of Plonky3 `poseidon2-air` `generate_trace_rows_for_perm`
 * (poseidon2-air/src/generation.rs @ 82cfad73), specialized to the Goldilocks
 * WIDTH=8, SBOX_REGISTERS=1 (deg-3) instance. Fills one P2AIR_NUM_COLS-wide
 * trace row from an 8-element permutation input:
 *
 *   1. inputs[i]              = raw input (before any linear layer)
 *   2. leading external linear layer applied to the working state
 *   3. beginning full rounds  (add_rc + committed-x^3 S-box + external MDS)
 *   4. partial rounds         (lane-0 add_rc + S-box + internal matmul)
 *   5. ending full rounds
 *
 * The S-box column stores the committed x^3; `post`/`post_sbox` store the state
 * after the round's linear layer (full) or the lane-0 S-box output (partial).
 *
 * Reuses the SAME linear layers + round constants as the permutation
 * (poseidon2_goldilocks.{c,h}) — one grounded implementation, one audit surface.
 * Ground truth: the row byte-matches the REAL Plonky3 generate_trace_rows
 * (tools/vectors/poseidon2_air_trace.json).
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef DNAC_ZK_POSEIDON2_AIR_TRACE_H
#define DNAC_ZK_POSEIDON2_AIR_TRACE_H

#include <stdint.h>

#include "poseidon2_air_cols.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Generate one Poseidon2-AIR trace row for a single permutation.
 *
 * @param input Permutation input: 8 canonical Goldilocks elements in [0, p).
 * @param row   Output: P2AIR_NUM_COLS (=180) canonical Goldilocks columns.
 *
 * Determinism: pure function of `input`; every column is a canonical u64.
 * The final ending-round `post` columns equal the permutation output
 * (poseidon2_goldilocks8_permute(input)).
 */
void poseidon2_air_generate_row(const uint64_t input[P2AIR_WIDTH],
                                uint64_t row[P2AIR_NUM_COLS]);

#ifdef __cplusplus
}
#endif

#endif /* DNAC_ZK_POSEIDON2_AIR_TRACE_H */
