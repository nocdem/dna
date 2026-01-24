/**
 * @file ledger.h
 * @brief DNAC Transaction Ledger API
 *
 * The transaction ledger provides a permanent, auditable record of all
 * transactions with Merkle proofs for verification.
 *
 * Features:
 * - Sequential transaction numbering
 * - Incremental Merkle tree for chain integrity
 * - Supply tracking (genesis, burned, current)
 * - Transaction existence proofs
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */

#ifndef DNAC_LEDGER_H
#define DNAC_LEDGER_H

#include "dnac.h"
#include "dnac/transaction.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ============================================================================
 * Constants
 * ========================================================================== */

/** Merkle root size (SHA3-512) */
#define DNAC_MERKLE_ROOT_SIZE       64

/** Maximum Merkle proof depth (log2 of max transactions) */
#define DNAC_MERKLE_MAX_DEPTH       64

/** Output commitment size */
#define DNAC_OUTPUT_COMMITMENT_SIZE 64

/* ============================================================================
 * Data Types
 * ========================================================================== */

/**
 * @brief Ledger entry for a committed transaction
 */
typedef struct {
    uint64_t sequence_number;                       /**< Unique sequential ID */
    uint8_t tx_hash[DNAC_TX_HASH_SIZE];            /**< Transaction hash */
    uint8_t tx_type;                                /**< GENESIS=0, SPEND=1, BURN=2 */
    uint8_t nullifiers[DNAC_TX_MAX_INPUTS][DNAC_NULLIFIER_SIZE]; /**< Input nullifiers */
    uint8_t nullifier_count;                        /**< Number of nullifiers */
    uint8_t output_commitment[DNAC_OUTPUT_COMMITMENT_SIZE]; /**< Hash of outputs */
    uint8_t merkle_root[DNAC_MERKLE_ROOT_SIZE];    /**< Running Merkle root after this TX */
    uint64_t timestamp;                             /**< Unix timestamp */
    uint64_t epoch;                                 /**< Epoch number */
} dnac_ledger_entry_t;

/**
 * @brief Supply tracking state
 */
typedef struct {
    uint64_t genesis_supply;                        /**< Fixed at genesis (never changes) */
    uint64_t total_burned;                          /**< Cumulative burned amount */
    uint64_t current_supply;                        /**< genesis_supply - total_burned */
    uint8_t last_tx_hash[DNAC_TX_HASH_SIZE];       /**< Last transaction hash */
    uint64_t last_sequence;                         /**< Last sequence number */
} dnac_supply_state_t;

/**
 * @brief Merkle proof for transaction existence
 */
typedef struct {
    uint8_t leaf_hash[DNAC_MERKLE_ROOT_SIZE];      /**< Hash of the leaf (tx data) */
    uint64_t leaf_index;                            /**< Index in the tree */
    uint8_t siblings[DNAC_MERKLE_MAX_DEPTH][DNAC_MERKLE_ROOT_SIZE]; /**< Sibling hashes */
    uint8_t directions[DNAC_MERKLE_MAX_DEPTH];     /**< 0=left, 1=right */
    int proof_length;                               /**< Number of siblings */
    uint8_t root[DNAC_MERKLE_ROOT_SIZE];           /**< Expected root */
} dnac_merkle_proof_t;

/* ============================================================================
 * Witness-Side Ledger Functions
 * ========================================================================== */

/**
 * @brief Initialize ledger database
 *
 * Called during witness startup. Creates tables if needed.
 *
 * @return 0 on success, -1 on error
 */
int witness_ledger_init(void);

/**
 * @brief Shutdown ledger database
 */
void witness_ledger_shutdown(void);

/**
 * @brief Add entry to ledger
 *
 * Called when a transaction is committed by consensus.
 * Updates the Merkle tree and supply tracking.
 *
 * @param entry Ledger entry to add
 * @return 0 on success, -1 on error
 */
int witness_ledger_add_entry(const dnac_ledger_entry_t *entry);

/**
 * @brief Get next sequence number
 *
 * @return Next sequence number (1-based), or 0 on error
 */
uint64_t witness_ledger_get_next_seq(void);

/**
 * @brief Get current Merkle root
 *
 * @param root_out Output buffer for root (DNAC_MERKLE_ROOT_SIZE bytes)
 * @return 0 on success, -1 if no entries
 */
int witness_ledger_get_root(uint8_t *root_out);

/**
 * @brief Get ledger entry by sequence number
 *
 * @param seq Sequence number
 * @param entry_out Output entry
 * @return 0 on success, -1 if not found
 */
int witness_ledger_get_entry(uint64_t seq, dnac_ledger_entry_t *entry_out);

/**
 * @brief Get ledger entry by transaction hash
 *
 * @param tx_hash Transaction hash
 * @param entry_out Output entry
 * @return 0 on success, -1 if not found
 */
int witness_ledger_get_entry_by_hash(const uint8_t *tx_hash,
                                      dnac_ledger_entry_t *entry_out);

/**
 * @brief Get Merkle proof for transaction
 *
 * @param seq Sequence number of transaction
 * @param proof_out Output proof
 * @return 0 on success, -1 on error
 */
int witness_ledger_get_proof(uint64_t seq, dnac_merkle_proof_t *proof_out);

/**
 * @brief P0-2 (v0.7.0): Get range of ledger entries
 *
 * Retrieves a range of ledger entries for chain synchronization.
 *
 * @param from_seq Start sequence (inclusive)
 * @param to_seq End sequence (inclusive), 0 = up to latest
 * @param entries Output entry array
 * @param max_entries Maximum entries to return
 * @param count_out Actual number of entries returned
 * @return 0 on success, -1 on error
 */
int witness_ledger_get_range(uint64_t from_seq,
                              uint64_t to_seq,
                              dnac_ledger_entry_t *entries,
                              int max_entries,
                              int *count_out);

/**
 * @brief P0-2 (v0.7.0): Get total ledger entry count
 *
 * @return Total number of entries, or 0 if empty/error
 */
uint64_t witness_ledger_get_total_entries(void);

/* ============================================================================
 * Supply Tracking Functions
 * ========================================================================== */

/**
 * @brief Initialize supply at genesis
 *
 * Called once when genesis transaction is committed.
 *
 * @param total_supply Total supply from genesis
 * @param genesis_tx_hash Genesis transaction hash
 * @return 0 on success, -1 on error
 */
int witness_supply_init(uint64_t total_supply, const uint8_t *genesis_tx_hash);

/**
 * @brief Record a burn transaction
 *
 * Reduces current supply by burned amount.
 *
 * @param burn_amount Amount burned
 * @param tx_hash Burn transaction hash
 * @return 0 on success, -1 on error
 */
int witness_supply_record_burn(uint64_t burn_amount, const uint8_t *tx_hash);

/**
 * @brief Get current supply state
 *
 * @param state_out Output supply state
 * @return 0 on success, -1 if no genesis
 */
int witness_supply_get_state(dnac_supply_state_t *state_out);

/* ============================================================================
 * Client Query Functions
 * ========================================================================== */

/**
 * @brief Query transaction existence with proof
 *
 * @param ctx DNAC context
 * @param tx_hash Transaction hash to query
 * @param entry_out Output ledger entry (optional, can be NULL)
 * @param proof_out Output Merkle proof (optional, can be NULL)
 * @return DNAC_SUCCESS or error code
 */
int dnac_ledger_query_tx(dnac_context_t *ctx,
                         const uint8_t *tx_hash,
                         dnac_ledger_entry_t *entry_out,
                         dnac_merkle_proof_t *proof_out);

/**
 * @brief Get supply information from witnesses
 *
 * @param ctx DNAC context
 * @param genesis_out Output genesis supply
 * @param burned_out Output total burned
 * @param current_out Output current supply
 * @return DNAC_SUCCESS or error code
 */
int dnac_ledger_get_supply(dnac_context_t *ctx,
                           uint64_t *genesis_out,
                           uint64_t *burned_out,
                           uint64_t *current_out);

/**
 * @brief Verify Merkle proof locally
 *
 * @param proof Proof to verify
 * @return true if proof is valid
 */
bool dnac_merkle_verify_proof(const dnac_merkle_proof_t *proof);

/**
 * @brief P0-2 (v0.7.0): Sync ledger entries in range from witnesses
 *
 * Queries witness servers for a range of ledger entries.
 * Used for chain synchronization.
 *
 * @param ctx DNAC context
 * @param from_seq Start sequence (inclusive)
 * @param to_seq End sequence (inclusive), 0 = up to latest
 * @param entries_out Output entry array (caller-allocated)
 * @param max_entries Maximum entries to receive
 * @param count_out Actual count returned
 * @param total_out Total entries available on witnesses (can be NULL)
 * @return DNAC_SUCCESS or error code
 */
int dnac_ledger_sync_range(dnac_context_t *ctx,
                            uint64_t from_seq,
                            uint64_t to_seq,
                            dnac_ledger_entry_t *entries_out,
                            int max_entries,
                            int *count_out,
                            uint64_t *total_out);

#ifdef __cplusplus
}
#endif

#endif /* DNAC_LEDGER_H */
