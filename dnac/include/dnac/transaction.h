/**
 * @file transaction.h
 * @brief DNAC Transaction types and functions
 *
 * Protocol Versions:
 * - v1: Transparent amounts in outputs
 * - v2: ZK amounts with commitments and range proofs (future)
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */

#ifndef DNAC_TRANSACTION_H
#define DNAC_TRANSACTION_H

#include "dnac.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ============================================================================
 * Transaction Wire Format Constants
 * ========================================================================== */

#define DNAC_TX_MAX_INPUTS          16
#define DNAC_TX_MAX_OUTPUTS         16
#define DNAC_TX_MAX_ANCHORS         3

/* ============================================================================
 * Transaction Structures
 * ========================================================================== */

/**
 * @brief Transaction input
 *
 * Inputs reference UTXOs by nullifier (hides which UTXO is spent).
 */
typedef struct {
    uint8_t nullifier[DNAC_NULLIFIER_SIZE];     /**< Nullifier (SHA3-512 hash) */
    uint64_t amount;                             /**< Amount (v1 only, for verification) */
} dnac_tx_input_t;

/**
 * @brief Transaction output (v1 transparent)
 *
 * v1: Amount is plaintext, no commitments or range proofs.
 * v2: Would add commitment and range_proof fields.
 */
typedef struct {
    uint8_t version;                             /**< Output version (1 or 2) */
    char owner_fingerprint[DNAC_FINGERPRINT_SIZE]; /**< Recipient's fingerprint */
    uint64_t amount;                             /**< Amount (v1: plaintext) */
    uint8_t nullifier_seed[32];                  /**< Seed for recipient to derive nullifier */

    /* v2 ZK fields (unused in v1, reserved for future) */
    uint8_t commitment[DNAC_COMMITMENT_SIZE];   /**< Pedersen commitment (v2 only) */
    uint8_t range_proof[DNAC_RANGE_PROOF_MAX_SIZE]; /**< Bulletproof (v2 only) */
    size_t range_proof_len;                      /**< Range proof length (v2 only) */
} dnac_tx_output_internal_t;

/**
 * @brief Nodus anchor signature
 *
 * Anchors from 2+ Nodus servers prevent double-spending.
 */
typedef struct {
    uint8_t nodus_id[32];                        /**< Nodus server ID */
    uint8_t signature[DNAC_SIGNATURE_SIZE];      /**< Dilithium5 signature */
    uint8_t server_pubkey[DNAC_PUBKEY_SIZE];     /**< Server's Dilithium5 public key */
    uint64_t timestamp;                          /**< Anchor timestamp */
} dnac_anchor_t;

/**
 * @brief Full transaction structure
 *
 * v1 transactions have transparent amounts.
 * v2 transactions (future) will have ZK proofs.
 */
struct dnac_transaction {
    /* Header */
    uint8_t version;                             /**< Protocol version (1 or 2) */
    dnac_tx_type_t type;                         /**< MINT, SPEND, or BURN */
    uint64_t timestamp;                          /**< Unix timestamp */
    uint8_t tx_hash[DNAC_TX_HASH_SIZE];         /**< SHA3-512 of transaction */

    /* Inputs */
    dnac_tx_input_t inputs[DNAC_TX_MAX_INPUTS];
    int input_count;

    /* Outputs */
    dnac_tx_output_internal_t outputs[DNAC_TX_MAX_OUTPUTS];
    int output_count;

    /* Anchor proofs (2 required for valid transaction) */
    dnac_anchor_t anchors[DNAC_TX_MAX_ANCHORS];
    int anchor_count;

    /* Sender authorization (Dilithium5 signature) */
    uint8_t sender_pubkey[DNAC_PUBKEY_SIZE];
    uint8_t sender_signature[DNAC_SIGNATURE_SIZE];

    /* v2 ZK fields (unused in v1) */
    uint8_t excess_commitment[DNAC_COMMITMENT_SIZE]; /**< Balance proof (v2 only) */
    uint8_t excess_signature[64];                    /**< Schnorr signature (v2 only) */
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
 * @brief Add output to transaction (v1 transparent)
 *
 * @param tx Transaction
 * @param recipient_fingerprint Recipient's fingerprint
 * @param amount Amount to send
 * @param nullifier_seed_out Output nullifier seed for recipient (32 bytes)
 * @return DNAC_SUCCESS or error code
 */
int dnac_tx_add_output(dnac_transaction_t *tx,
                       const char *recipient_fingerprint,
                       uint64_t amount,
                       uint8_t *nullifier_seed_out);

/**
 * @brief Finalize transaction
 *
 * Computes hash and signs with sender's Dilithium5 key.
 * For v1: verifies sum(inputs) == sum(outputs) + fee.
 * For v2: would also create balance proof.
 *
 * @param tx Transaction
 * @param sender_privkey Sender's Dilithium5 private key
 * @param sender_pubkey Sender's Dilithium5 public key
 * @return DNAC_SUCCESS or error code
 */
int dnac_tx_finalize(dnac_transaction_t *tx,
                     const uint8_t *sender_privkey,
                     const uint8_t *sender_pubkey);

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
 * Verifies:
 * - v1: sum(inputs) == sum(outputs), signature valid, 2+ anchors
 * - v2: also verifies balance proof and range proofs
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

/**
 * @brief Get total input amount (v1 only)
 *
 * @param tx Transaction
 * @return Total input amount
 */
uint64_t dnac_tx_total_input(const dnac_transaction_t *tx);

/**
 * @brief Get total output amount (v1 only)
 *
 * @param tx Transaction
 * @return Total output amount
 */
uint64_t dnac_tx_total_output(const dnac_transaction_t *tx);

#ifdef __cplusplus
}
#endif

#endif /* DNAC_TRANSACTION_H */
