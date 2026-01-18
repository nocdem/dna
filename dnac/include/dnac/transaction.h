/**
 * @file transaction.h
 * @brief DNAC Transaction types and functions
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */

#ifndef DNAC_TRANSACTION_H
#define DNAC_TRANSACTION_H

#include "dnac.h"
#include "commitment.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ============================================================================
 * Transaction Wire Format Constants
 * ========================================================================== */

#define DNAC_TX_VERSION             1
#define DNAC_TX_MAX_INPUTS          16
#define DNAC_TX_MAX_OUTPUTS         16
#define DNAC_TX_MAX_ANCHORS         3

/* ============================================================================
 * Transaction Structures
 * ========================================================================== */

/**
 * @brief Transaction input
 */
typedef struct {
    uint8_t nullifier[DNAC_NULLIFIER_SIZE];     /**< Nullifier (reveals nothing about UTXO) */
    uint8_t key_image[32];                       /**< Key image for linkability detection */
} dnac_tx_input_t;

/**
 * @brief Transaction output
 */
typedef struct {
    uint8_t commitment[DNAC_COMMITMENT_SIZE];   /**< Pedersen commitment to amount */
    uint8_t owner_pubkey[DNAC_PUBKEY_SIZE];     /**< Owner's encryption public key */
    uint8_t encrypted_data[DNAC_ENCRYPTED_DATA_SIZE]; /**< Encrypted amount + blinding */
    uint8_t range_proof[DNAC_RANGE_PROOF_MAX_SIZE];   /**< Bulletproof range proof */
    size_t range_proof_len;                      /**< Actual range proof length */
} dnac_tx_output_internal_t;

/**
 * @brief Nodus anchor signature
 */
typedef struct {
    uint8_t nodus_id[32];                        /**< Nodus server ID */
    uint8_t signature[DNAC_SIGNATURE_SIZE];      /**< Dilithium5 signature */
    uint64_t timestamp;                          /**< Anchor timestamp */
} dnac_anchor_t;

/**
 * @brief Full transaction structure
 */
struct dnac_transaction {
    /* Header */
    uint8_t version;
    dnac_tx_type_t type;
    uint64_t timestamp;
    uint8_t tx_hash[DNAC_TX_HASH_SIZE];

    /* Inputs */
    dnac_tx_input_t inputs[DNAC_TX_MAX_INPUTS];
    int input_count;

    /* Outputs */
    dnac_tx_output_internal_t outputs[DNAC_TX_MAX_OUTPUTS];
    int output_count;

    /* Balance proof (inputs - outputs = 0) */
    uint8_t excess_commitment[DNAC_COMMITMENT_SIZE];
    uint8_t excess_signature[64];  /* Schnorr signature proving knowledge of excess */

    /* Anchor proofs (2 required) */
    dnac_anchor_t anchors[DNAC_TX_MAX_ANCHORS];
    int anchor_count;

    /* Sender authorization */
    uint8_t sender_signature[DNAC_SIGNATURE_SIZE];
    uint8_t sender_pubkey[DNAC_PUBKEY_SIZE];
};

/* ============================================================================
 * Transaction Functions
 * ========================================================================== */

/**
 * @brief Create new transaction
 *
 * @param type Transaction type
 * @return New transaction or NULL on failure
 */
dnac_transaction_t* dnac_tx_create(dnac_tx_type_t type);

/**
 * @brief Add input to transaction
 *
 * @param tx Transaction
 * @param utxo UTXO being spent
 * @return DNAC_SUCCESS or error code
 */
int dnac_tx_add_input(dnac_transaction_t *tx, const dnac_utxo_t *utxo);

/**
 * @brief Add output to transaction
 *
 * @param tx Transaction
 * @param recipient_fingerprint Recipient's fingerprint
 * @param recipient_pubkey Recipient's encryption public key
 * @param amount Amount
 * @param blinding_out Output blinding factor (for recipient)
 * @return DNAC_SUCCESS or error code
 */
int dnac_tx_add_output(dnac_transaction_t *tx,
                       const char *recipient_fingerprint,
                       const uint8_t *recipient_pubkey,
                       uint64_t amount,
                       uint8_t *blinding_out);

/**
 * @brief Finalize transaction
 *
 * Computes balance proof, hash, and signs.
 *
 * @param tx Transaction
 * @param sender_privkey Sender's Dilithium5 private key
 * @return DNAC_SUCCESS or error code
 */
int dnac_tx_finalize(dnac_transaction_t *tx, const uint8_t *sender_privkey);

/**
 * @brief Add anchor to transaction
 *
 * @param tx Transaction
 * @param anchor Anchor signature from Nodus
 * @return DNAC_SUCCESS or error code
 */
int dnac_tx_add_anchor(dnac_transaction_t *tx, const dnac_anchor_t *anchor);

/**
 * @brief Verify transaction
 *
 * Verifies all proofs, signatures, and anchors.
 *
 * @param tx Transaction
 * @return DNAC_SUCCESS if valid, error code otherwise
 */
int dnac_tx_verify(const dnac_transaction_t *tx);

/**
 * @brief Serialize transaction to bytes
 *
 * @param tx Transaction
 * @param buffer Output buffer
 * @param buffer_len Buffer length
 * @param written_out Bytes written
 * @return DNAC_SUCCESS or error code
 */
int dnac_tx_serialize(const dnac_transaction_t *tx,
                      uint8_t *buffer,
                      size_t buffer_len,
                      size_t *written_out);

/**
 * @brief Deserialize transaction from bytes
 *
 * @param buffer Input buffer
 * @param buffer_len Buffer length
 * @param tx_out Output transaction
 * @return DNAC_SUCCESS or error code
 */
int dnac_tx_deserialize(const uint8_t *buffer,
                        size_t buffer_len,
                        dnac_transaction_t **tx_out);

/**
 * @brief Compute transaction hash
 *
 * @param tx Transaction
 * @param hash_out Output hash (DNAC_TX_HASH_SIZE bytes)
 * @return DNAC_SUCCESS or error code
 */
int dnac_tx_compute_hash(const dnac_transaction_t *tx, uint8_t *hash_out);

#ifdef __cplusplus
}
#endif

#endif /* DNAC_TRANSACTION_H */
