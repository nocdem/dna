/**
 * @file shielded_fri_params.c
 * @brief Consensus-constant shielded FRI params (S0/C5). See header for grounding.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: Apache-2.0
 */

#include "shielded_fri_params.h"

/* The single pinned instance. Static storage → one address, immutable. */
static const dnac_fri_params_t k_shielded_fri_params = {
    .log_blowup                = DNAC_SHIELDED_FRI_LOG_BLOWUP,
    .log_final_poly_len        = DNAC_SHIELDED_FRI_LOG_FINAL_POLY_LEN,
    .max_log_arity             = DNAC_SHIELDED_FRI_MAX_LOG_ARITY,
    .num_queries               = DNAC_SHIELDED_FRI_NUM_QUERIES,
    .commit_proof_of_work_bits = DNAC_SHIELDED_FRI_COMMIT_POW_BITS,
    .query_proof_of_work_bits  = DNAC_SHIELDED_FRI_QUERY_POW_BITS,
};

const dnac_fri_params_t *dnac_shielded_fri_params(void)
{
    return &k_shielded_fri_params;
}

bool dnac_fri_params_eq(const dnac_fri_params_t *a, const dnac_fri_params_t *b)
{
    if (!a || !b) return false;
    return a->log_blowup == b->log_blowup &&
           a->log_final_poly_len == b->log_final_poly_len &&
           a->max_log_arity == b->max_log_arity &&
           a->num_queries == b->num_queries &&
           a->commit_proof_of_work_bits == b->commit_proof_of_work_bits &&
           a->query_proof_of_work_bits == b->query_proof_of_work_bits;
}
