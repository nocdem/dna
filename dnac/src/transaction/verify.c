/**
 * @file verify.c
 * @brief Transaction verification (v1 transparent)
 *
 * v1: Amounts are transparent, verification is straightforward.
 * v2: Would also verify range proofs and balance proof.
 */

#include "dnac/transaction.h"
#include "dnac/nodus.h"
#include <string.h>

/* libdna crypto utilities */
#include "crypto/utils/qgp_dilithium.h"

/**
 * @brief Verify balance (v1: plaintext sum check)
 */
static int verify_balance_v1(const dnac_transaction_t *tx) {
    uint64_t total_in = dnac_tx_total_input(tx);
    uint64_t total_out = dnac_tx_total_output(tx);

    if (total_in != total_out) {
        return DNAC_ERROR_INVALID_PROOF;
    }
    return DNAC_SUCCESS;
}

/**
 * @brief Verify anchor signatures
 *
 * Each anchor contains the server's public key. We verify the signature
 * over: tx_hash || nodus_id || timestamp
 */
static int verify_anchors(const dnac_transaction_t *tx) {
    if (tx->anchor_count < DNAC_ANCHORS_REQUIRED) {
        return DNAC_ERROR_ANCHOR_FAILED;
    }

    for (int i = 0; i < tx->anchor_count; i++) {
        const dnac_anchor_t *anchor = &tx->anchors[i];

        /* Build signed data: tx_hash + nodus_id + timestamp */
        uint8_t signed_data[DNAC_TX_HASH_SIZE + 32 + 8];
        memcpy(signed_data, tx->tx_hash, DNAC_TX_HASH_SIZE);
        memcpy(signed_data + DNAC_TX_HASH_SIZE, anchor->nodus_id, 32);

        /* Little-endian timestamp */
        for (int j = 0; j < 8; j++) {
            signed_data[DNAC_TX_HASH_SIZE + 32 + j] = (anchor->timestamp >> (j * 8)) & 0xFF;
        }

        /* Verify Dilithium5 signature */
        int ret = qgp_dsa87_verify(anchor->signature, DNAC_SIGNATURE_SIZE,
                                   signed_data, sizeof(signed_data),
                                   anchor->server_pubkey);
        if (ret != 0) {
            return DNAC_ERROR_ANCHOR_FAILED;
        }
    }

    return DNAC_SUCCESS;
}

/**
 * @brief Verify sender signature
 *
 * Verifies the Dilithium5 signature on tx_hash using sender's public key.
 */
static int verify_sender_signature(const dnac_transaction_t *tx) {
    int ret = qgp_dsa87_verify(tx->sender_signature, DNAC_SIGNATURE_SIZE,
                               tx->tx_hash, DNAC_TX_HASH_SIZE,
                               tx->sender_pubkey);
    return (ret == 0) ? DNAC_SUCCESS : DNAC_ERROR_INVALID_SIGNATURE;
}

/**
 * @brief Full transaction verification (v1)
 */
int dnac_tx_verify_full(const dnac_transaction_t *tx) {
    int rc;

    if (!tx) return DNAC_ERROR_INVALID_PARAM;

    /* 1. Verify balance (v1: plaintext sum) */
    rc = verify_balance_v1(tx);
    if (rc != DNAC_SUCCESS) return rc;

    /* 2. Verify anchors (2+ required) */
    rc = verify_anchors(tx);
    if (rc != DNAC_SUCCESS) return rc;

    /* 3. Verify sender signature */
    rc = verify_sender_signature(tx);
    if (rc != DNAC_SUCCESS) return rc;

    /* v2: Would also verify range proofs and commitment balance proof */

    return DNAC_SUCCESS;
}
