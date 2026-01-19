/**
 * @file db.h
 * @brief DNAC Database Functions
 *
 * SQLite database operations for UTXO storage, transaction history,
 * and pending spend tracking.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */

#ifndef DNAC_DB_H
#define DNAC_DB_H

#include "dnac.h"
#include <sqlite3.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ============================================================================
 * Database Initialization
 * ========================================================================== */

/**
 * @brief Initialize database schema
 *
 * Creates tables if they don't exist, runs migrations if needed.
 *
 * @param db SQLite database handle
 * @return DNAC_SUCCESS or error code
 */
int dnac_db_init(sqlite3 *db);

/* ============================================================================
 * UTXO Functions
 * ========================================================================== */

/**
 * @brief Store a UTXO in the database
 *
 * @param db SQLite database handle
 * @param utxo UTXO to store
 * @return DNAC_SUCCESS or error code
 */
int dnac_db_store_utxo(sqlite3 *db, const dnac_utxo_t *utxo);

/**
 * @brief Get unspent UTXOs for an owner
 *
 * Returns UTXOs sorted by amount (smallest first).
 *
 * @param db SQLite database handle
 * @param owner_fp Owner's fingerprint
 * @param utxos_out Output array (caller must free)
 * @param count_out Output count
 * @return DNAC_SUCCESS or error code
 */
int dnac_db_get_unspent_utxos(sqlite3 *db,
                              const char *owner_fp,
                              dnac_utxo_t **utxos_out,
                              int *count_out);

/**
 * @brief Mark a UTXO as spent
 *
 * @param db SQLite database handle
 * @param nullifier Nullifier of the UTXO
 * @param spent_in_tx Transaction hash that spent it (can be NULL)
 * @return DNAC_SUCCESS or error code
 */
int dnac_db_mark_utxo_spent(sqlite3 *db,
                            const uint8_t *nullifier,
                            const uint8_t *spent_in_tx);

/**
 * @brief Get UTXO by commitment (debug)
 *
 * @param db SQLite database handle
 * @param commitment Commitment to look up
 * @param utxo Output UTXO
 * @return DNAC_SUCCESS or error code
 */
int dnac_db_get_utxo_by_commitment(sqlite3 *db,
                                    const uint8_t *commitment,
                                    dnac_utxo_t *utxo);

/**
 * @brief Clear all UTXOs for an owner (for wallet recovery)
 *
 * @param db SQLite database handle
 * @param owner_fp Owner's fingerprint
 * @return DNAC_SUCCESS or error code
 */
int dnac_db_clear_utxos(sqlite3 *db, const char *owner_fp);

/* ============================================================================
 * Transaction Functions
 * ========================================================================== */

/**
 * @brief Store a transaction
 *
 * @param db SQLite database handle
 * @param tx_hash Transaction hash
 * @param raw_tx Serialized transaction
 * @param raw_tx_len Length of serialized transaction
 * @param type Transaction type
 * @param counterparty_fp Counterparty fingerprint (can be NULL)
 * @param amount_in Total input amount
 * @param amount_out Total output amount
 * @param amount_fee Fee amount
 * @return DNAC_SUCCESS or error code
 */
int dnac_db_store_transaction(sqlite3 *db,
                               const uint8_t *tx_hash,
                               const uint8_t *raw_tx,
                               size_t raw_tx_len,
                               dnac_tx_type_t type,
                               const char *counterparty_fp,
                               uint64_t amount_in,
                               uint64_t amount_out,
                               uint64_t amount_fee);

/**
 * @brief Get transaction by hash
 *
 * @param db SQLite database handle
 * @param tx_hash Transaction hash
 * @param raw_tx_out Output serialized transaction (caller must free)
 * @param raw_tx_len_out Output length
 * @return DNAC_SUCCESS or error code
 */
int dnac_db_get_transaction(sqlite3 *db,
                             const uint8_t *tx_hash,
                             uint8_t **raw_tx_out,
                             size_t *raw_tx_len_out);

/**
 * @brief Mark transaction as confirmed
 *
 * @param db SQLite database handle
 * @param tx_hash Transaction hash
 * @return DNAC_SUCCESS or error code
 */
int dnac_db_confirm_transaction(sqlite3 *db, const uint8_t *tx_hash);

/**
 * @brief Get transaction history
 *
 * @param db SQLite database handle
 * @param history_out Output array (caller must free)
 * @param count_out Output count
 * @param limit Maximum entries (0 for all)
 * @return DNAC_SUCCESS or error code
 */
int dnac_db_get_transactions(sqlite3 *db,
                              dnac_tx_history_t **history_out,
                              int *count_out,
                              int limit);

/* ============================================================================
 * Pending Spend Functions
 * ========================================================================== */

/**
 * @brief Store a pending spend
 *
 * @param db SQLite database handle
 * @param tx_hash Transaction hash
 * @param nullifier Nullifier being spent
 * @param anchors_needed Number of anchors required
 * @param expires_at Expiration timestamp
 * @return DNAC_SUCCESS or error code
 */
int dnac_db_store_pending_spend(sqlite3 *db,
                                 const uint8_t *tx_hash,
                                 const uint8_t *nullifier,
                                 int anchors_needed,
                                 uint64_t expires_at);

/**
 * @brief Update pending spend with new anchor
 *
 * @param db SQLite database handle
 * @param tx_hash Transaction hash
 * @param anchor_sig Anchor signature to append
 * @param anchor_sig_len Signature length
 * @return DNAC_SUCCESS or error code
 */
int dnac_db_update_pending_anchor(sqlite3 *db,
                                   const uint8_t *tx_hash,
                                   const uint8_t *anchor_sig,
                                   size_t anchor_sig_len);

/**
 * @brief Get pending spend info
 *
 * @param db SQLite database handle
 * @param tx_hash Transaction hash
 * @param anchors_received Output anchors received (can be NULL)
 * @param anchors_needed Output anchors needed (can be NULL)
 * @param anchor_sigs Output signatures (caller must free, can be NULL)
 * @param anchor_sigs_len Output signatures length (can be NULL)
 * @return DNAC_SUCCESS or error code
 */
int dnac_db_get_pending_spend(sqlite3 *db,
                               const uint8_t *tx_hash,
                               int *anchors_received,
                               int *anchors_needed,
                               uint8_t **anchor_sigs,
                               size_t *anchor_sigs_len);

/**
 * @brief Mark pending spend as complete
 *
 * @param db SQLite database handle
 * @param tx_hash Transaction hash
 * @return DNAC_SUCCESS or error code
 */
int dnac_db_complete_pending_spend(sqlite3 *db, const uint8_t *tx_hash);

/**
 * @brief Expire old pending spends
 *
 * @param db SQLite database handle
 * @return DNAC_SUCCESS or error code
 */
int dnac_db_expire_pending_spends(sqlite3 *db);

#ifdef __cplusplus
}
#endif

#endif /* DNAC_DB_H */
