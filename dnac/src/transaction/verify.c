/**
 * @file verify.c
 * @brief Transaction verification
 */

#include "dnac/transaction.h"
#include "dnac/commitment.h"
#include "dnac/range_proof.h"
#include "dnac/nodus.h"

/**
 * @brief Verify all range proofs in transaction
 */
static int verify_range_proofs(const dnac_transaction_t *tx) {
    for (int i = 0; i < tx->output_count; i++) {
        const dnac_tx_output_internal_t *out = &tx->outputs[i];
        if (!dnac_range_proof_verify(out->commitment,
                                     out->range_proof,
                                     out->range_proof_len)) {
            return DNAC_ERROR_INVALID_PROOF;
        }
    }
    return DNAC_SUCCESS;
}

/**
 * @brief Verify balance proof (sum inputs = sum outputs)
 */
static int verify_balance_proof(const dnac_transaction_t *tx) {
    /* TODO: Verify that:
     * sum(input_commitments) - sum(output_commitments) = excess_commitment
     * And excess_signature is valid for excess_commitment
     */
    (void)tx;
    return DNAC_ERROR_NOT_INITIALIZED;
}

/**
 * @brief Verify anchor signatures
 */
static int verify_anchors(const dnac_transaction_t *tx) {
    if (tx->anchor_count < DNAC_ANCHORS_REQUIRED) {
        return DNAC_ERROR_ANCHOR_FAILED;
    }

    /* TODO: Verify each anchor signature against known Nodus public keys */

    return DNAC_ERROR_NOT_INITIALIZED;
}

/**
 * @brief Verify sender signature
 */
static int verify_sender_signature(const dnac_transaction_t *tx) {
    /* TODO: Verify Dilithium5 signature on tx_hash */
    (void)tx;
    return DNAC_ERROR_NOT_INITIALIZED;
}

/**
 * @brief Full transaction verification
 */
int dnac_tx_verify_full(const dnac_transaction_t *tx) {
    int rc;

    if (!tx) return DNAC_ERROR_INVALID_PARAM;

    /* 1. Verify range proofs */
    rc = verify_range_proofs(tx);
    if (rc != DNAC_SUCCESS) return rc;

    /* 2. Verify balance proof */
    rc = verify_balance_proof(tx);
    if (rc != DNAC_SUCCESS) return rc;

    /* 3. Verify anchors */
    rc = verify_anchors(tx);
    if (rc != DNAC_SUCCESS) return rc;

    /* 4. Verify sender signature */
    rc = verify_sender_signature(tx);
    if (rc != DNAC_SUCCESS) return rc;

    return DNAC_SUCCESS;
}
