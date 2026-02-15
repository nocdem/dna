/**
 * @file commitment.h
 * @brief DNAC UTXO Commitment System
 *
 * Global UTXO commitment tracking via Sparse Merkle Tree.
 * Enables:
 * - Proof that a UTXO exists
 * - Wallet recovery without DHT
 * - Offline receiving (proof that payment was made)
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */

#ifndef DNAC_COMMITMENT_H
#define DNAC_COMMITMENT_H

#include "dnac.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ============================================================================
 * Constants
 * ========================================================================== */

/** UTXO commitment size (SHA3-512) */
#define DNAC_UTXO_COMMITMENT_SIZE    64

/** SMT key size (SHA3-512) */
#define DNAC_SMT_KEY_SIZE            64

/** Maximum SMT proof depth */
#define DNAC_SMT_MAX_DEPTH           512

/* ============================================================================
 * Data Types
 * ========================================================================== */

/**
 * @brief UTXO commitment stored by witnesses
 */
typedef struct {
    uint8_t commitment[DNAC_UTXO_COMMITMENT_SIZE]; /**< SHA3-512 commitment */
    uint8_t tx_hash[DNAC_TX_HASH_SIZE];            /**< Creating transaction */
    uint32_t output_index;                          /**< Output index in TX */
    uint64_t amount;                                /**< Amount (for supply audit) */
    uint8_t owner_commitment[64];                   /**< SHA3-512(fingerprint || salt) */
    uint64_t created_epoch;                         /**< When created */
    uint64_t spent_epoch;                           /**< When spent (0 if unspent) */
} dnac_utxo_commitment_t;

/**
 * @brief SMT inclusion/exclusion proof
 */
typedef struct {
    uint8_t key[DNAC_SMT_KEY_SIZE];                /**< Key being proven */
    uint8_t value[DNAC_UTXO_COMMITMENT_SIZE];      /**< Value (zeros if exclusion) */
    bool exists;                                    /**< True if inclusion proof */
    uint8_t siblings[DNAC_SMT_MAX_DEPTH][64];      /**< Sibling hashes */
    uint8_t path_bits[DNAC_SMT_MAX_DEPTH / 8];     /**< Path from root */
    int proof_length;                               /**< Actual proof length */
    uint8_t root[64];                               /**< Expected root */
    uint64_t epoch;                                 /**< Epoch of this root */
} dnac_smt_proof_t;

/**
 * @brief Epoch root snapshot
 *
 * Each epoch (1 hour) serves as a "macro-block" with sequence boundaries.
 * first_sequence and last_sequence define the range of transactions
 * committed during this epoch, enabling efficient chain synchronization.
 */
typedef struct {
    uint64_t epoch;                                 /**< Epoch number */
    uint64_t first_sequence;                        /**< First TX sequence in epoch (v0.7.0) */
    uint64_t last_sequence;                         /**< Last TX sequence in epoch (v0.7.0) */
    uint8_t utxo_root[64];                         /**< UTXO SMT root */
    uint8_t ledger_root[64];                       /**< Ledger Merkle root */
    uint64_t utxo_count;                           /**< Total unspent UTXOs */
    uint64_t total_supply;                         /**< Current supply */
    uint64_t timestamp;                            /**< Snapshot timestamp */
} dnac_epoch_root_t;

/* ============================================================================
 * Witness-Side UTXO Functions
 * ========================================================================== */

/**
 * @brief Initialize UTXO commitment system
 * @return 0 on success
 */
int witness_utxo_init(void *user_data);

/**
 * @brief Shutdown UTXO commitment system
 */
void witness_utxo_shutdown(void);

/**
 * @brief Add new UTXO commitment
 *
 * Called when outputs are created by a committed transaction.
 *
 * @param commitment UTXO commitment to add
 * @return 0 on success
 */
int witness_utxo_add(const dnac_utxo_commitment_t *commitment, void *user_data);

/**
 * @brief Mark UTXO as spent
 *
 * Called when an input is consumed by a committed transaction.
 *
 * @param commitment_hash The commitment being spent
 * @param spent_epoch Epoch when spent
 * @return 0 on success, -1 if not found
 */
int witness_utxo_mark_spent(const uint8_t *commitment_hash, uint64_t spent_epoch, void *user_data);

/**
 * @brief Check if UTXO exists and is unspent
 *
 * @param commitment_hash Commitment to check
 * @return true if exists and unspent
 */
bool witness_utxo_exists(const uint8_t *commitment_hash, void *user_data);

/**
 * @brief Get current UTXO root
 *
 * @param root_out Output buffer for root (64 bytes)
 * @return 0 on success
 */
int witness_utxo_get_root(uint8_t *root_out, void *user_data);

/**
 * @brief Get proof for UTXO
 *
 * @param commitment_hash Commitment to prove
 * @param proof_out Output proof
 * @return 0 on success
 */
int witness_utxo_get_proof(const uint8_t *commitment_hash,
                            dnac_smt_proof_t *proof_out, void *user_data);

/**
 * @brief Get UTXOs for an owner
 *
 * Used for wallet recovery.
 *
 * @param owner_commitment Owner's commitment hash
 * @param commitments_out Output array
 * @param max_count Maximum entries to return
 * @return Number of UTXOs found, or -1 on error
 */
int witness_utxo_get_by_owner(const uint8_t *owner_commitment,
                               dnac_utxo_commitment_t *commitments_out,
                               int max_count, void *user_data);

/**
 * @brief Save epoch root snapshot
 *
 * Called at end of each epoch to create signed snapshot.
 *
 * @param epoch_root Epoch root to save
 * @return 0 on success
 */
int witness_epoch_root_save(const dnac_epoch_root_t *epoch_root, void *user_data);

/**
 * @brief Get epoch root by epoch number
 *
 * @param epoch Epoch number
 * @param root_out Output epoch root
 * @return 0 on success, -1 if not found
 */
int witness_epoch_root_get(uint64_t epoch, dnac_epoch_root_t *root_out, void *user_data);

/**
 * @brief v0.7.1: Sign epoch root with witness private key
 *
 * Creates a BFT signature on the epoch root data and stores it.
 * Called by each witness to contribute to BFT trust anchoring.
 *
 * @param epoch Epoch number to sign
 * @param ledger_root Ledger Merkle root for this epoch
 * @param witness_id This witness's ID
 * @param privkey Witness private key (Dilithium5)
 * @param privkey_size Private key size
 * @return 0 on success, -1 on error
 */
int witness_epoch_root_sign(uint64_t epoch,
                             const uint8_t *ledger_root,
                             const uint8_t *witness_id,
                             const uint8_t *privkey,
                             size_t privkey_size,
                             void *user_data);

/* ============================================================================
 * Client Functions
 * ========================================================================== */

/**
 * @brief Recover wallet UTXOs from witnesses
 *
 * Queries witnesses for UTXOs belonging to our identity.
 *
 * @param ctx DNAC context
 * @param recovered_count Output: number of UTXOs recovered
 * @param total_amount Output: total amount recovered
 * @return DNAC_SUCCESS or error code
 */
int dnac_wallet_recover_from_witnesses(dnac_context_t *ctx,
                                        int *recovered_count,
                                        uint64_t *total_amount);

/**
 * @brief Get proof that UTXO exists
 *
 * @param ctx DNAC context
 * @param commitment Commitment to prove
 * @param proof_out Output proof
 * @return DNAC_SUCCESS or error code
 */
int dnac_utxo_get_proof(dnac_context_t *ctx,
                        const uint8_t *commitment,
                        dnac_smt_proof_t *proof_out);

/**
 * @brief Verify SMT proof locally
 *
 * @param proof Proof to verify
 * @return true if valid
 */
bool dnac_smt_verify_proof(const dnac_smt_proof_t *proof);

/* ============================================================================
 * Utility Functions
 * ========================================================================== */

/**
 * @brief Compute UTXO commitment
 *
 * commitment = SHA3-512(tx_hash || output_index || amount || owner_commitment)
 *
 * @param tx_hash Transaction hash
 * @param output_index Output index
 * @param amount Amount
 * @param owner_commitment Owner's commitment
 * @param commitment_out Output commitment (64 bytes)
 * @return 0 on success
 */
int dnac_compute_utxo_commitment(const uint8_t *tx_hash,
                                  uint32_t output_index,
                                  uint64_t amount,
                                  const uint8_t *owner_commitment,
                                  uint8_t *commitment_out);

/**
 * @brief Compute owner commitment
 *
 * owner_commitment = SHA3-512(fingerprint || salt)
 *
 * @param fingerprint Owner's fingerprint
 * @param salt Random salt (32 bytes)
 * @param commitment_out Output commitment (64 bytes)
 * @return 0 on success
 */
int dnac_compute_owner_commitment(const char *fingerprint,
                                   const uint8_t *salt,
                                   uint8_t *commitment_out);

#ifdef __cplusplus
}
#endif

#endif /* DNAC_COMMITMENT_H */
