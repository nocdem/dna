/**
 * @file bulletproofs.c
 * @brief Bulletproofs range proof implementation
 *
 * TODO: Implement using secp256k1-zkp or custom implementation
 */

#include "dnac/range_proof.h"

static int g_initialized = 0;

int dnac_range_proof_init(void) {
    if (g_initialized) return 0;
    /* TODO: Initialize Bulletproof generators */
    g_initialized = 1;
    return 0;
}

void dnac_range_proof_shutdown(void) {
    g_initialized = 0;
}

int dnac_range_proof_create(const uint8_t *commitment,
                            uint64_t value,
                            const uint8_t *blinding,
                            uint8_t *proof_out,
                            size_t *proof_len_out,
                            size_t max_proof_len) {
    (void)commitment;
    (void)value;
    (void)blinding;
    (void)proof_out;
    (void)max_proof_len;
    if (proof_len_out) *proof_len_out = 0;
    return -1; /* Not implemented */
}

bool dnac_range_proof_verify(const uint8_t *commitment,
                             const uint8_t *proof,
                             size_t proof_len) {
    (void)commitment;
    (void)proof;
    (void)proof_len;
    return false;
}

bool dnac_range_proof_batch_verify(const uint8_t (*commitments)[33],
                                   const uint8_t **proofs,
                                   const size_t *proof_lens,
                                   int count) {
    (void)commitments;
    (void)proofs;
    (void)proof_lens;
    (void)count;
    return false;
}

int dnac_range_proof_aggregate(const uint8_t (*commitments)[33],
                               const uint64_t *values,
                               const uint8_t (*blindings)[32],
                               int count,
                               uint8_t *proof_out,
                               size_t *proof_len_out,
                               size_t max_proof_len) {
    (void)commitments;
    (void)values;
    (void)blindings;
    (void)count;
    (void)proof_out;
    (void)max_proof_len;
    if (proof_len_out) *proof_len_out = 0;
    return -1;
}

bool dnac_range_proof_aggregate_verify(const uint8_t (*commitments)[33],
                                       int count,
                                       const uint8_t *proof,
                                       size_t proof_len) {
    (void)commitments;
    (void)count;
    (void)proof;
    (void)proof_len;
    return false;
}
