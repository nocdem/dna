/**
 * @file serialize.c
 * @brief Transaction serialization
 */

#include "dnac/transaction.h"
#include <string.h>

int dnac_tx_serialize(const dnac_transaction_t *tx,
                      uint8_t *buffer,
                      size_t buffer_len,
                      size_t *written_out) {
    if (!tx || !buffer || !written_out) return DNAC_ERROR_INVALID_PARAM;

    /* TODO: Implement wire format serialization */
    /*
     * Format:
     * - version (1 byte)
     * - type (1 byte)
     * - timestamp (8 bytes)
     * - tx_hash (64 bytes)
     * - input_count (1 byte)
     * - inputs[]: nullifier (64) + key_image (32)
     * - output_count (1 byte)
     * - outputs[]: commitment (33) + pubkey (2592) + encrypted (128) + range_proof (var)
     * - excess_commitment (33 bytes)
     * - excess_signature (64 bytes)
     * - anchor_count (1 byte)
     * - anchors[]: nodus_id (32) + signature (4627) + timestamp (8)
     * - sender_signature (4627 bytes)
     * - sender_pubkey (2592 bytes)
     */

    (void)buffer_len;
    *written_out = 0;
    return DNAC_ERROR_NOT_INITIALIZED;
}

int dnac_tx_deserialize(const uint8_t *buffer,
                        size_t buffer_len,
                        dnac_transaction_t **tx_out) {
    if (!buffer || !tx_out) return DNAC_ERROR_INVALID_PARAM;
    (void)buffer_len;

    /* TODO: Implement deserialization */

    *tx_out = NULL;
    return DNAC_ERROR_NOT_INITIALIZED;
}

int dnac_tx_compute_hash(const dnac_transaction_t *tx, uint8_t *hash_out) {
    if (!tx || !hash_out) return DNAC_ERROR_INVALID_PARAM;

    /* TODO: SHA3-512 of transaction data (excluding signatures) */

    memset(hash_out, 0, DNAC_TX_HASH_SIZE);
    return DNAC_ERROR_NOT_INITIALIZED;
}
