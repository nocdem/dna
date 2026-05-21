/**
 * @file fri_query.h
 * @brief FRI query phase — prover and verifier (DNAC v3, Sub-sprint 2.3)
 *
 * After fri_commit_phase produces layer roots + final values, the prover
 * MUST open Merkle paths at queried positions and the verifier reconstructs
 * the same openings to assert fold consistency between layers.
 *
 * Protocol (DNAC-internal arity-2 FRI):
 *   1. Both sides derive `num_queries` query indices via
 *      transcript_challenge_query_index(transcript, 2^initial_log_size).
 *      Transcript must be in post-commit state (after all layer roots absorbed).
 *   2. For each query q_0:
 *      For each layer i ∈ [0, num_layers):
 *        - q_i = q_0 >> i               (position in this layer of size 2^(initial-i))
 *        - lo = layer_i[q_i & ~1u]
 *        - hi = layer_i[q_i | 1u]
 *        - Open Merkle path for lo and hi in layer_i's tree (depth = initial-i)
 *      Final layer values are already published in commit output.
 *   3. Verifier checks:
 *        - Each Merkle path verifies against the layer root.
 *        - fold((lo, hi), beta_i, halve_inv_powers[q_i/2]) == (next_layer value at q_i/2)
 *        - For the last fold step, the "next" is the final_values array
 *          published in commit output.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef DNAC_ZK_FRI_QUERY_H
#define DNAC_ZK_FRI_QUERY_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "field_goldilocks.h"
#include "fri_commit.h"
#include "merkle_smt.h"
#include "transcript.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief A single layer's opening for one query.
 *
 * Contains the queried pair (lo, hi) and both Merkle paths within that layer.
 * The pair indices in the layer are (lo_index = q & ~1, hi_index = q | 1)
 * where q is the position in the current layer.
 */
typedef struct {
    uint32_t   lo_index;
    uint32_t   hi_index;
    gold_fp2_t lo_value;
    gold_fp2_t hi_value;
    merkle_smt_proof_t lo_path;
    merkle_smt_proof_t hi_path;
} fri_query_layer_opening_t;

/**
 * @brief Full opening for one query — one layer-opening per FRI layer.
 */
typedef struct {
    uint32_t initial_position;  /**< q_0 ∈ [0, 2^initial_log_size) */
    uint32_t num_layers;        /**< Same as commit output's num_layers */
    fri_query_layer_opening_t layers[FRI_COMMIT_MAX_LAYERS];
} fri_query_proof_t;

/**
 * @brief Generate per-query openings.
 *
 * @param transcript   Transcript in post-commit state (output of fri_commit_phase).
 *                     Mutated: query indices are drawn from it via
 *                     transcript_challenge_query_index.
 * @param all_layers   Array of pointers to each layer's values (caller-owned).
 *                     all_layers[i] is values BEFORE fold i (size = 2^(initial - i)).
 *                     all_layers[num_layers] = final_values (size = 2^cap_height_log).
 * @param initial_log_size  log2 of initial layer size.
 * @param cap_height_log    log2 of final layer size.
 * @param num_queries  Number of queries to draw + open.
 * @param out_proofs   Output array of num_queries proofs (caller-allocated).
 * @return 0 on success, -1 on error.
 */
int fri_query_open(transcript_t *transcript,
                   gold_fp2_t * const *all_layers,
                   uint32_t initial_log_size,
                   uint32_t cap_height_log,
                   uint32_t num_queries,
                   fri_query_proof_t *out_proofs);

/**
 * @brief Verifier: check all query proofs against commit output.
 *
 * Verifier reconstructs transcript challenges from commit output (the layer
 * roots), then verifies each query proof:
 *   1. Merkle paths (lo + hi) verify against the layer root.
 *   2. Fold equation holds: fold(lo, hi) at q_i/2 == next layer's value there.
 *      For the last layer i = num_layers-1, "next" is commit_output.final_values.
 *
 * @param transcript Post-commit transcript (must be in same state as prover's).
 *                   Mutated: query indices are re-derived.
 * @param commit_out FRI commit output (layer roots, betas, final values).
 * @param proofs     num_queries query proofs.
 * @param num_queries Number of query proofs.
 * @return true if ALL queries verify, false on any failure.
 */
bool fri_query_verify(transcript_t *transcript,
                      const fri_commit_output_t *commit_out,
                      const fri_query_proof_t *proofs,
                      uint32_t num_queries);

#ifdef __cplusplus
}
#endif

#endif /* DNAC_ZK_FRI_QUERY_H */
