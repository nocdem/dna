/**
 * @file wallet.h
 * @brief DNAC Wallet internal types and functions
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */

#ifndef DNAC_WALLET_H
#define DNAC_WALLET_H

#include "dnac.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ============================================================================
 * Internal Wallet Functions
 * ========================================================================== */

/**
 * @brief Initialize wallet subsystem
 *
 * Called internally by dnac_init().
 *
 * @param ctx DNAC context
 * @param db_path Path to wallet database
 * @return DNAC_SUCCESS or error code
 */
int dnac_wallet_init(dnac_context_t *ctx, const char *db_path);

/**
 * @brief Shutdown wallet subsystem
 */
void dnac_wallet_shutdown(dnac_context_t *ctx);

/**
 * @brief Store received UTXO
 *
 * @param ctx DNAC context
 * @param utxo UTXO to store
 * @return DNAC_SUCCESS or error code
 */
int dnac_wallet_store_utxo(dnac_context_t *ctx, const dnac_utxo_t *utxo);

/**
 * @brief Mark UTXO as spent
 *
 * @param ctx DNAC context
 * @param nullifier Nullifier of spent UTXO
 * @param spent_in_tx Transaction that spent it
 * @return DNAC_SUCCESS or error code
 */
int dnac_wallet_mark_spent(dnac_context_t *ctx,
                           const uint8_t *nullifier,
                           const uint8_t *spent_in_tx);

/**
 * @brief Get unspent UTXOs for spending
 *
 * Returns UTXOs sorted by amount (smallest first for privacy).
 *
 * @param ctx DNAC context
 * @param utxos Output array
 * @param count Output count
 * @return DNAC_SUCCESS or error code
 */
int dnac_wallet_get_unspent(dnac_context_t *ctx, dnac_utxo_t **utxos, int *count);

/**
 * @brief Select UTXOs for transaction
 *
 * Implements coin selection algorithm.
 *
 * @param ctx DNAC context
 * @param target_amount Amount needed
 * @param selected Output selected UTXOs
 * @param selected_count Output count
 * @param change_amount Output change amount (if any)
 * @return DNAC_SUCCESS or error code
 */
int dnac_wallet_select_utxos(dnac_context_t *ctx,
                             uint64_t target_amount,
                             dnac_utxo_t **selected,
                             int *selected_count,
                             uint64_t *change_amount);

/**
 * @brief Calculate total balance
 *
 * @param ctx DNAC context
 * @param balance Output balance
 * @return DNAC_SUCCESS or error code
 */
int dnac_wallet_calculate_balance(dnac_context_t *ctx, dnac_balance_t *balance);

#ifdef __cplusplus
}
#endif

#endif /* DNAC_WALLET_H */
