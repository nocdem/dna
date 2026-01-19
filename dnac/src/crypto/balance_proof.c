/**
 * @file balance_proof.c
 * @brief Balance proof (inputs = outputs) implementation
 *
 * **PROTOCOL VERSION: v2 ONLY**
 *
 * v1 (current): Balance verified by sum(inputs) == sum(outputs) in plaintext.
 * v2 (future): Uses homomorphic commitment property for ZK balance proof.
 */

#include "dnac/dnac.h"
#include "dnac/transaction.h"

/**
 * @brief Create balance proof for transaction (v2 only)
 *
 * Not implemented in v1 - amounts are transparent.
 */
int dnac_balance_proof_create(const dnac_transaction_t *tx,
                              const uint8_t (*input_blindings)[32],
                              const uint8_t (*output_blindings)[32],
                              uint8_t *excess_commitment,
                              uint8_t *excess_signature) {
    (void)tx;
    (void)input_blindings;
    (void)output_blindings;
    (void)excess_commitment;
    (void)excess_signature;

    /* v1: Not used - balance verified by plaintext sum */
    return DNAC_ERROR_INVALID_PARAM;
}

/**
 * @brief Verify balance proof (v2 only)
 *
 * Not implemented in v1 - use dnac_tx_verify() instead.
 */
int dnac_balance_proof_verify(const dnac_transaction_t *tx) {
    (void)tx;

    /* v1: Not used - balance verified by plaintext sum */
    return DNAC_ERROR_INVALID_PARAM;
}
