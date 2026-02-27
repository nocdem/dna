/**
 * @file utxo_set.h
 * @brief Shared UTXO Set for Validator-Side Transaction Validation (v0.8.0)
 *
 * This module maintains the authoritative UTXO set that all validators
 * keep in sync. It is the primary defense against counterfeiting:
 * - Every TX input must reference an existing UTXO in this set
 * - Every COMMIT adds new UTXOs (from outputs) and removes spent UTXOs (from inputs)
 * - Only genesis can create UTXOs from nothing
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */

#ifndef DNAC_UTXO_SET_H
#define DNAC_UTXO_SET_H

#include <stdint.h>
#include <stddef.h>
#include "dnac.h"
#include "dnac/transaction.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Look up a UTXO by its nullifier
 *
 * @param nullifier The nullifier to look up (DNAC_NULLIFIER_SIZE bytes)
 * @param amount_out Output: amount stored in this UTXO (can be NULL)
 * @param owner_out Output: owner fingerprint (DNAC_FINGERPRINT_SIZE buffer, can be NULL)
 * @return 0 if found, -1 if not found or error
 */
int witness_utxo_set_lookup(const uint8_t *nullifier,
                             uint64_t *amount_out,
                             char *owner_out, void *user_data);

/**
 * @brief Add a new UTXO to the set (from TX output on COMMIT)
 *
 * @param nullifier Derived nullifier for this output
 * @param owner Owner's fingerprint
 * @param amount Amount in smallest units
 * @param tx_hash Creating transaction hash
 * @param index Output index within the creating TX
 * @param block_height Block height when created (0 for genesis)
 * @return 0 on success, -1 on error
 */
int witness_utxo_set_add(const uint8_t *nullifier,
                          const char *owner,
                          uint64_t amount,
                          const uint8_t *tx_hash,
                          uint32_t index,
                          uint64_t block_height, void *user_data);

/**
 * @brief Remove a spent UTXO from the set (on COMMIT)
 *
 * @param nullifier Nullifier of the spent UTXO
 * @return 0 on success, -1 if not found
 */
int witness_utxo_set_remove(const uint8_t *nullifier, void *user_data);

/**
 * @brief Populate the UTXO set from a genesis transaction
 *
 * Called when genesis TX commits. Creates UTXO entries for all
 * genesis outputs. This is the only legitimate entry point for value.
 *
 * @param genesis_tx The genesis transaction
 * @param tx_hash The genesis transaction hash
 * @return 0 on success, -1 on error
 */
int witness_utxo_set_genesis(const dnac_transaction_t *genesis_tx,
                              const uint8_t *tx_hash, void *user_data);

/**
 * @brief Get count of UTXOs in the set (for diagnostics)
 *
 * @param count_out Output: number of UTXOs
 * @return 0 on success
 */
int witness_utxo_set_count(uint64_t *count_out);

/**
 * @brief Initialize UTXO state root from DB (v0.9.0)
 *
 * Rebuilds the rolling state root by iterating all UTXOs sorted by
 * (tx_hash, output_index). Must be called on startup before any
 * transactions are processed.
 *
 * @return 0 on success, -1 on error
 */
int witness_utxo_set_init(void);

/**
 * @brief Get current UTXO state root (v0.9.0)
 *
 * Returns the rolling SHA3-512 hash representing the current UTXO set state.
 * All witnesses with identical UTXO sets produce identical roots.
 *
 * @param root_out Output buffer (64 bytes)
 * @return 0 on success, -1 on error
 */
int witness_utxo_set_get_root(uint8_t *root_out);

/**
 * @brief Get UTXO state root with zone context (v0.10.0)
 *
 * @param user_data Zone pointer (or NULL for global)
 * @param root_out Output buffer (64 bytes)
 * @return 0 on success, -1 on error
 */
int witness_utxo_set_get_root_ctx(void *user_data, uint8_t *root_out);

#ifdef __cplusplus
}
#endif

#endif /* DNAC_UTXO_SET_H */
