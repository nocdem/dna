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
 * @brief Clear all UTXOs for an owner (for wallet recovery)
 *
 * @param db SQLite database handle
 * @param owner_fp Owner's fingerprint
 * @return DNAC_SUCCESS or error code
 */
int dnac_db_clear_utxos(sqlite3 *db, const char *owner_fp);

/**
 * Delete all entries from dnac_transactions (cache clear).
 */
int dnac_db_clear_transactions(sqlite3 *db);

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
 * @brief Upsert a history entry from remote with explicit timestamp
 *
 * Used by dnac_get_remote_history to persist remote-seen entries
 * (especially incoming TXs that the local wallet never produced) into
 * the local history cache. INSERT OR REPLACE — safe to call repeatedly.
 * Unlike dnac_db_store_transaction, this preserves the TX's real
 * timestamp instead of writing "now".
 *
 * amount_delta semantics: stored as amount_in=max(delta,0),
 * amount_out=max(-delta,0) so dnac_db_get_transactions' computation
 * (amount_in - amount_out) round-trips correctly.
 */
int dnac_db_upsert_history_entry(sqlite3 *db,
                                  const uint8_t *tx_hash,
                                  dnac_tx_type_t type,
                                  const char *counterparty_fp,
                                  int64_t amount_delta,
                                  uint64_t amount_fee,
                                  int64_t tx_timestamp);

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
 * @param witnesses_needed Number of witnesses required
 * @param expires_at Expiration timestamp
 * @return DNAC_SUCCESS or error code
 */
int dnac_db_store_pending_spend(sqlite3 *db,
                                 const uint8_t *tx_hash,
                                 const uint8_t *nullifier,
                                 int witnesses_needed,
                                 uint64_t expires_at);

/**
 * @brief Update pending spend with new witness signature
 *
 * @param db SQLite database handle
 * @param tx_hash Transaction hash
 * @param witness_sig Witness signature to append
 * @param witness_sig_len Signature length
 * @return DNAC_SUCCESS or error code
 */
int dnac_db_update_pending_witness(sqlite3 *db,
                                   const uint8_t *tx_hash,
                                   const uint8_t *witness_sig,
                                   size_t witness_sig_len);

/**
 * @brief Get pending spend info
 *
 * @param db SQLite database handle
 * @param tx_hash Transaction hash
 * @param witnesses_received Output witnesses received (can be NULL)
 * @param witnesses_needed Output witnesses needed (can be NULL)
 * @param witness_sigs Output signatures (caller must free, can be NULL)
 * @param witness_sigs_len Output signatures length (can be NULL)
 * @return DNAC_SUCCESS or error code
 */
int dnac_db_get_pending_spend(sqlite3 *db,
                               const uint8_t *tx_hash,
                               int *witnesses_received,
                               int *witnesses_needed,
                               uint8_t **witness_sigs,
                               size_t *witness_sigs_len);

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

/**
 * @brief Persist serialized TX for retry-safe re-broadcast (Fix #4 B)
 *
 * Attaches the full serialized transaction, recipient, amount, and
 * token_id to an existing ACTIVE pending_spend row so a subsequent
 * dnac_send retry can locate and re-broadcast the SAME tx_hash via
 * dnac_db_find_active_broadcast(), instead of rebuilding a fresh TX
 * with a different tx_hash (which would collide on nullifiers).
 *
 * @return DNAC_SUCCESS or error code
 */
int dnac_db_store_pending_broadcast(sqlite3 *db,
                                     const uint8_t *tx_hash,
                                     const uint8_t *tx_data, size_t tx_data_len,
                                     const char *recipient_fp,
                                     uint64_t amount,
                                     const uint8_t token_id[32],
                                     uint64_t expires_at);

/**
 * @brief Look up an active pending broadcast by (recipient, amount, token_id)
 *
 * Returns DNAC_SUCCESS if a non-expired ACTIVE row exists with matching
 * fields and tx_data populated, writing tx_hash (64 bytes) and
 * heap-allocated tx_data into the out parameters. Caller frees
 * *tx_data_out. Returns DNAC_ERROR_NOT_FOUND if no match.
 */
int dnac_db_find_active_broadcast(sqlite3 *db,
                                    const char *recipient_fp,
                                    uint64_t amount,
                                    const uint8_t token_id[32],
                                    uint8_t *tx_hash_out,
                                    uint8_t **tx_data_out,
                                    size_t *tx_data_len_out);

/* ============================================================================
 * Token Registry Functions
 * ========================================================================== */

/**
 * @brief Store or update a token in the registry
 *
 * @param db SQLite database handle
 * @param token Token to store
 * @return DNAC_SUCCESS or error code
 */
int dnac_db_store_token(sqlite3 *db, const dnac_token_t *token);

/**
 * @brief Get a token by its ID
 *
 * @param db SQLite database handle
 * @param token_id Token ID (64 bytes)
 * @param out Output token struct
 * @return DNAC_SUCCESS, DNAC_ERROR_NOT_FOUND, or error code
 */
int dnac_db_get_token(sqlite3 *db, const uint8_t *token_id, dnac_token_t *out);

/**
 * @brief List all known tokens
 *
 * @param db SQLite database handle
 * @param out Output array (caller-allocated)
 * @param max Maximum entries to return
 * @param count Output count of entries written
 * @return DNAC_SUCCESS or error code
 */
int dnac_db_list_tokens(sqlite3 *db, dnac_token_t *out, int max, int *count);

/* ============================================================================
 * P0-4 (v0.7.0): Confirmation Tracking Functions
 * ========================================================================== */

/**
 * @brief Update transaction confirmation data from ledger
 *
 * @param db SQLite database handle
 * @param tx_hash Transaction hash
 * @param ledger_seq Ledger sequence number
 * @param ledger_epoch Epoch when committed
 * @return DNAC_SUCCESS or error code
 */
int dnac_db_update_tx_confirmation(sqlite3 *db, const uint8_t *tx_hash,
                                    uint64_t ledger_seq, uint64_t ledger_epoch);

/**
 * @brief Get transaction confirmation data
 *
 * @param db SQLite database handle
 * @param tx_hash Transaction hash
 * @param ledger_seq_out Output sequence number (can be NULL)
 * @param ledger_epoch_out Output epoch (can be NULL)
 * @return DNAC_SUCCESS, DNAC_ERROR_NOT_FOUND if not confirmed, or error code
 */
int dnac_db_get_tx_confirmation(sqlite3 *db, const uint8_t *tx_hash,
                                 uint64_t *ledger_seq_out, uint64_t *ledger_epoch_out);

/**
 * @brief Update UTXO confirmation data from ledger
 *
 * @param db SQLite database handle
 * @param tx_hash Transaction hash that created the UTXO
 * @param output_index Output index within the transaction
 * @param ledger_seq Ledger sequence number
 * @param ledger_epoch Epoch when committed
 * @return DNAC_SUCCESS or error code
 */
int dnac_db_update_utxo_confirmation(sqlite3 *db, const uint8_t *tx_hash,
                                      uint32_t output_index,
                                      uint64_t ledger_seq, uint64_t ledger_epoch);

/* ============================================================================
 * Wallet Config Functions (Gap 22: v0.6.0)
 * ========================================================================== */

/**
 * @brief Get owner salt from wallet config
 *
 * @param db SQLite database handle
 * @param salt_out Output salt buffer (32 bytes)
 * @return DNAC_SUCCESS, DNAC_ERROR_NOT_FOUND if not set, or error code
 */
int dnac_db_get_owner_salt(sqlite3 *db, uint8_t *salt_out);

/**
 * @brief Set owner salt in wallet config
 *
 * @param db SQLite database handle
 * @param salt Salt to store (32 bytes)
 * @return DNAC_SUCCESS or error code
 */
int dnac_db_set_owner_salt(sqlite3 *db, const uint8_t *salt);

/**
 * @brief Get stored chain_id from wallet config
 *
 * Used to detect chain resets: if the stored chain_id differs from the
 * current witness chain_id, the local transaction cache is stale and
 * must be wiped.
 *
 * @param db SQLite database handle
 * @param chain_id_out Output buffer (32 bytes)
 * @return DNAC_SUCCESS, DNAC_ERROR_NOT_FOUND if never set, or error code
 */
int dnac_db_get_stored_chain_id(sqlite3 *db, uint8_t *chain_id_out);

/**
 * @brief Set stored chain_id in wallet config
 *
 * @param db SQLite database handle
 * @param chain_id Chain ID to store (32 bytes)
 * @return DNAC_SUCCESS or error code
 */
int dnac_db_set_stored_chain_id(sqlite3 *db, const uint8_t *chain_id);

#ifdef __cplusplus
}
#endif

#endif /* DNAC_DB_H */
