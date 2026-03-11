/**
 * @file verify.c
 * @brief Transaction verification
 *
 * Protocol v1: Transparent amounts (current implementation).
 * v2 will add PQ ZK (STARKs) for hidden amounts when available.
 */

#include "dnac/transaction.h"
#include "dnac/nodus.h"
#include <string.h>
#include <stdio.h>
#include <stdbool.h>

/* libdna crypto utilities */
#include "crypto/sign/qgp_dilithium.h"
#include "crypto/utils/qgp_log.h"

#define LOG_TAG "DNAC_VERIFY"

/**
 * @brief Verify balance (v1: plaintext sum check)
 *
 * GENESIS: no inputs, outputs create coins from nothing (3-of-3 witness authorized)
 * SPEND: sum(inputs) == sum(outputs)
 */
static int verify_balance_v1(const dnac_transaction_t *tx) {
    /* GENESIS: no inputs, outputs create coins from nothing (v0.5.0) */
    if (tx->type == DNAC_TX_GENESIS) {
        if (tx->input_count != 0) {
            return DNAC_ERROR_INVALID_PROOF;
        }
        /* Genesis supply is validated by witnesses - no local cap check */
        return DNAC_SUCCESS;
    }

    /* SPEND: sum(inputs) >= sum(outputs), difference is burned fee */
    uint64_t total_in = dnac_tx_total_input(tx);
    uint64_t total_out = dnac_tx_total_output(tx);
    if (total_in < total_out) {
        return DNAC_ERROR_INVALID_PROOF;
    }
    return DNAC_SUCCESS;
}

/**
 * @brief Verify witness signatures
 *
 * Each witness contains the server's public key. We verify the signature
 * over: tx_hash || witness_id || timestamp
 *
 * With BFT consensus, 1 valid witness attestation proves quorum was reached
 * (the witness only signs after 2f+1 agreement). We require at least 1 valid.
 */
int verify_witnesses(const dnac_transaction_t *tx) {
    /* BFT mode: 1 attestation proves consensus (quorum agreement happened internally) */
    if (tx->witness_count < 1) {
        return DNAC_ERROR_WITNESS_FAILED;
    }

    int valid_witnesses = 0;

    for (int i = 0; i < tx->witness_count; i++) {
        const dnac_witness_sig_t *witness = &tx->witnesses[i];

        QGP_LOG_DEBUG(LOG_TAG, "witness %d: id=%.8s..., ts=%llu",
                     i, (const char*)witness->witness_id, (unsigned long long)witness->timestamp);

        /* Gap 12 Fix (v0.6.0): Check if entire pubkey is all zeros (placeholder/invalid)
         * If not zero, always attempt verification - let Dilithium5 validate the key format.
         * The previous heuristic only checked first 64 of 2592 bytes, allowing bypass. */
        bool is_all_zeros = true;
        for (int k = 0; k < DNAC_PUBKEY_SIZE && is_all_zeros; k++) {
            if (witness->server_pubkey[k] != 0) is_all_zeros = false;
        }
        if (is_all_zeros) {
            QGP_LOG_DEBUG(LOG_TAG, "  skipping witness with zero pubkey (placeholder)");
            continue;
        }

        /* Build signed data: tx_hash + witness_id + timestamp */
        uint8_t signed_data[DNAC_TX_HASH_SIZE + 32 + 8];
        memcpy(signed_data, tx->tx_hash, DNAC_TX_HASH_SIZE);
        memcpy(signed_data + DNAC_TX_HASH_SIZE, witness->witness_id, 32);

        /* Little-endian timestamp */
        for (int j = 0; j < 8; j++) {
            signed_data[DNAC_TX_HASH_SIZE + 32 + j] = (witness->timestamp >> (j * 8)) & 0xFF;
        }

        /* Verify Dilithium5 signature */
        int ret = qgp_dsa87_verify(witness->signature, DNAC_SIGNATURE_SIZE,
                                   signed_data, sizeof(signed_data),
                                   witness->server_pubkey);
        QGP_LOG_DEBUG(LOG_TAG, "  qgp_dsa87_verify returned: %d", ret);

        if (ret == 0) {
            valid_witnesses++;
            QGP_LOG_DEBUG(LOG_TAG, "  valid! (total valid: %d)", valid_witnesses);
        }
    }

    /* BFT mode: require at least 1 valid witness signature */
    if (valid_witnesses >= 1) {
        QGP_LOG_DEBUG(LOG_TAG, "success: %d valid witness(es)", valid_witnesses);
        return DNAC_SUCCESS;
    }

    QGP_LOG_ERROR(LOG_TAG, "failed: no valid witnesses (checked %d)", tx->witness_count);
    return DNAC_ERROR_WITNESS_FAILED;
}

/**
 * @brief Verify sender signature
 *
 * Verifies the Dilithium5 signature on tx_hash using sender's public key.
 */
int verify_sender_signature(const dnac_transaction_t *tx) {
    int ret = qgp_dsa87_verify(tx->sender_signature, DNAC_SIGNATURE_SIZE,
                               tx->tx_hash, DNAC_TX_HASH_SIZE,
                               tx->sender_pubkey);
    return (ret == 0) ? DNAC_SUCCESS : DNAC_ERROR_INVALID_SIGNATURE;
}

/**
 * @brief Full transaction verification
 */
int dnac_tx_verify_full(const dnac_transaction_t *tx) {
    int rc;

    if (!tx) return DNAC_ERROR_INVALID_PARAM;

    /* 1. Verify balance (or mint rules) */
    rc = verify_balance_v1(tx);
    if (rc != DNAC_SUCCESS) return rc;

    /* 2. Verify witnesses (required for both SPEND and GENESIS) */
    rc = verify_witnesses(tx);
    if (rc != DNAC_SUCCESS) return rc;

    /* 3. Sender signature (skip for GENESIS - witnesses authorize) */
    if (tx->type != DNAC_TX_GENESIS) {
        rc = verify_sender_signature(tx);
        if (rc != DNAC_SUCCESS) return rc;
    }

    return DNAC_SUCCESS;
}
