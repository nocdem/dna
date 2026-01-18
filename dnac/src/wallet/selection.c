/**
 * @file selection.c
 * @brief UTXO selection algorithms
 */

#include "dnac/wallet.h"
#include <stdlib.h>

/**
 * @brief Select UTXOs for spending
 *
 * Uses a simple greedy algorithm: smallest UTXOs first to minimize change
 * and improve privacy.
 */
int dnac_wallet_select_utxos(dnac_context_t *ctx,
                             uint64_t target_amount,
                             dnac_utxo_t **selected,
                             int *selected_count,
                             uint64_t *change_amount) {
    if (!ctx || !selected || !selected_count || !change_amount) {
        return DNAC_ERROR_INVALID_PARAM;
    }

    *selected = NULL;
    *selected_count = 0;
    *change_amount = 0;

    /* Get all unspent UTXOs */
    dnac_utxo_t *utxos = NULL;
    int count = 0;
    int rc = dnac_wallet_get_unspent(ctx, &utxos, &count);
    if (rc != DNAC_SUCCESS) return rc;

    if (count == 0) {
        return DNAC_ERROR_INSUFFICIENT_FUNDS;
    }

    /* TODO: Sort UTXOs by amount (smallest first) */
    /* TODO: Select UTXOs until target is met */
    /* TODO: Calculate change */

    dnac_free_utxos(utxos, count);
    return DNAC_ERROR_NOT_INITIALIZED;
}
