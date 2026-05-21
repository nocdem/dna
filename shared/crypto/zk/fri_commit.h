/**
 * @file fri_commit.h
 * @brief FRI multi-layer commit phase (DNAC v3, Sub-sprint 2.2)
 *
 * Layer-by-layer fold loop:
 *   1. Compute Merkle root over current layer values (SHA3-512 leaves via
 *      merkle_smt module).
 *   2. transcript_absorb(root).
 *   3. beta = transcript_challenge_fp2(transcript).
 *   4. Compute halve_inv_powers from gold_fp_two_adic_generator(current_log_size).
 *   5. fri_fold_arity2(layer, halve_inv_powers, beta) → next layer (half size).
 * Stop when layer log_size ≤ cap_height_log; emit final layer as proof tail.
 *
 * Cross-validated against tools/vectors/fri_commit.json.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef DNAC_ZK_FRI_COMMIT_H
#define DNAC_ZK_FRI_COMMIT_H

#include <stddef.h>
#include <stdint.h>

#include "field_goldilocks.h"
#include "merkle_smt.h"
#include "transcript.h"

#ifdef __cplusplus
extern "C" {
#endif

/** Maximum number of FRI layers the commit phase will produce.
 *  Cap (= 24) covers initial layer log_size up to 2^32 in worst case. */
#define FRI_COMMIT_MAX_LAYERS 24

/**
 * @brief Output of FRI commit phase.
 *
 * num_layers entries in layer_roots[] and layer_betas[].
 * final_values[] has 2^cap_height_log elements.
 * Caller owns memory; final_values capacity must be ≥ 2^cap_height_log.
 */
typedef struct {
    uint32_t num_layers;
    uint8_t  layer_roots[FRI_COMMIT_MAX_LAYERS][MERKLE_SMT_HASH_SIZE];
    gold_fp2_t layer_betas[FRI_COMMIT_MAX_LAYERS];
    /* final_values must be allocated by caller, size = 2^cap_height_log */
    gold_fp2_t *final_values;
    uint32_t final_log_size;
} fri_commit_output_t;

/**
 * @brief Run the FRI multi-layer commit phase.
 *
 * @param transcript      Caller-initialized transcript (already absorbed init params).
 *                        This function mutates it by absorbing layer roots and
 *                        deriving betas. Returns transcript in post-commit state.
 * @param initial_values  Input layer (size = 2^initial_log_size).
 * @param initial_log_size  log2 of initial layer size.
 * @param cap_height_log  Stop folding when layer log_size ≤ cap_height_log.
 * @param scratch_layer   Workspace of size ≥ 2^(initial_log_size - 1) Goldilocks² elements.
 *                        Used as the second buffer in ping-pong folding.
 * @param out             Output structure to populate.
 * @return 0 on success, -1 on invalid arguments.
 */
int fri_commit_phase(transcript_t *transcript,
                     const gold_fp2_t *initial_values,
                     uint32_t initial_log_size,
                     uint32_t cap_height_log,
                     gold_fp2_t *scratch_layer,
                     fri_commit_output_t *out);

#ifdef __cplusplus
}
#endif

#endif /* DNAC_ZK_FRI_COMMIT_H */
