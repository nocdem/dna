/**
 * @file transaction.h
 * @brief DNAC Transaction types and functions
 *
 * Protocol v1: Transparent amounts (current implementation).
 * v2 will add PQ ZK (STARKs) for hidden amounts when available.
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
#define DNAC_TX_MAX_WITNESSES       3

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
    uint8_t token_id[DNAC_TOKEN_ID_SIZE];       /**< Token ID (zeros = native DNAC) */
} dnac_tx_input_t;

/**
 * @brief Transaction output (v1 transparent)
 *
 * Protocol v1: Amount is plaintext.
 * v2 will add PQ ZK fields when STARKs are integrated.
 */
typedef struct {
    uint8_t version;                             /**< Output version */
    char owner_fingerprint[DNAC_FINGERPRINT_SIZE]; /**< Recipient's fingerprint */
    uint64_t amount;                             /**< Amount in smallest units */
    uint8_t token_id[DNAC_TOKEN_ID_SIZE];        /**< Token ID (zeros = native DNAC) */
    uint8_t nullifier_seed[32];                  /**< Seed for recipient to derive nullifier */
    char memo[DNAC_MEMO_MAX_SIZE];               /**< Optional memo (Gap 25: v0.6.0) */
    uint8_t memo_len;                            /**< Memo length */
} dnac_tx_output_internal_t;

/**
 * @brief Witness signature (attestation)
 *
 * Signatures from 2+ witness servers prevent double-spending.
 *
 * Phase 12 / Task 13.1 — the receipt now binds the block_height,
 * tx_index, and chain_id the witness committed against. These fields
 * are required for client-side preimage reconstruction (the witness
 * Dilithium5-signs the 221-byte spndrslt preimage that includes them).
 * They are NOT serialized into the on-chain TX; serialize.c only
 * persists witness_id/signature/timestamp/server_pubkey.
 */
typedef struct {
    uint8_t witness_id[32];                      /**< Witness server ID */
    uint8_t signature[DNAC_SIGNATURE_SIZE];      /**< Dilithium5 signature */
    uint8_t server_pubkey[DNAC_PUBKEY_SIZE];     /**< Server's Dilithium5 public key */
    uint64_t timestamp;                          /**< Witness timestamp */
    /* Receipt-only fields (not in TX serialization) */
    uint64_t block_height;                       /**< Block the TX committed in */
    uint32_t tx_index;                           /**< Per-block tx_index */
    uint8_t  chain_id[32];                       /**< Chain identifier */
} dnac_witness_sig_t;

/**
 * @brief Full transaction structure
 *
 * Protocol v1: Transparent amounts.
 * v2 will add PQ ZK fields when STARKs are integrated.
 */
struct dnac_transaction {
    /* Header */
    uint8_t version;                             /**< Protocol version */
    dnac_tx_type_t type;                         /**< MINT, SPEND, or BURN */
    uint64_t timestamp;                          /**< Unix timestamp */
    uint8_t tx_hash[DNAC_TX_HASH_SIZE];         /**< SHA3-512 of transaction */

    /* Inputs */
    dnac_tx_input_t inputs[DNAC_TX_MAX_INPUTS];
    int input_count;

    /* Outputs */
    dnac_tx_output_internal_t outputs[DNAC_TX_MAX_OUTPUTS];
    int output_count;

    /* Witness signatures (2 required for valid transaction) */
    dnac_witness_sig_t witnesses[DNAC_TX_MAX_WITNESSES];
    int witness_count;

    /* Sender authorization (Dilithium5 signature) */
    uint8_t sender_pubkey[DNAC_PUBKEY_SIZE];
    uint8_t sender_signature[DNAC_SIGNATURE_SIZE];
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
 * @brief Add output to transaction with memo (Gap 25: v0.6.0)
 *
 * @param tx Transaction
 * @param recipient_fingerprint Recipient's fingerprint
 * @param amount Amount to send
 * @param nullifier_seed_out Output nullifier seed for recipient (32 bytes)
 * @param memo Optional memo (can be NULL)
 * @param memo_len Memo length (0 if no memo)
 * @return DNAC_SUCCESS or error code
 */
int dnac_tx_add_output_with_memo(dnac_transaction_t *tx,
                                  const char *recipient_fingerprint,
                                  uint64_t amount,
                                  uint8_t *nullifier_seed_out,
                                  const char *memo,
                                  uint8_t memo_len);

/**
 * @brief Finalize transaction
 *
 * Computes hash and signs with sender's Dilithium5 key.
 * Verifies sum(inputs) == sum(outputs).
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
 * @brief Add witness signature to transaction
 *
 * @param tx Transaction
 * @param witness Witness signature from witness server
 * @return DNAC_SUCCESS or error code
 */
int dnac_tx_add_witness(dnac_transaction_t *tx, const dnac_witness_sig_t *witness);

/**
 * @brief Verify transaction
 *
 * Verifies sum(inputs) == sum(outputs), signature valid, 2+ witnesses.
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

/* ============================================================================
 * Genesis Transactions (v0.5.0)
 *
 * MINT transactions have been removed. All token creation happens via
 * a one-time GENESIS event. See include/dnac/genesis.h for the Genesis API.
 *
 * - dnac_tx_create_genesis()    - Create genesis with multiple recipients
 * - dnac_tx_authorize_genesis() - Get 3-of-3 witness approval (unanimous)
 * - dnac_tx_broadcast_genesis() - Send genesis tokens via DHT
 * ========================================================================== */

#ifdef __cplusplus
}
#endif

#endif /* DNAC_TRANSACTION_H */
