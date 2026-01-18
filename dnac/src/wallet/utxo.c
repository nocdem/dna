/**
 * @file utxo.c
 * @brief UTXO handling
 */

#include "dnac/wallet.h"
#include <string.h>

int dnac_wallet_store_utxo(dnac_context_t *ctx, const dnac_utxo_t *utxo) {
    if (!ctx || !utxo) return DNAC_ERROR_INVALID_PARAM;
    /* TODO: Store in database */
    return DNAC_ERROR_NOT_INITIALIZED;
}

int dnac_wallet_mark_spent(dnac_context_t *ctx,
                           const uint8_t *nullifier,
                           const uint8_t *spent_in_tx) {
    if (!ctx || !nullifier) return DNAC_ERROR_INVALID_PARAM;
    (void)spent_in_tx;
    /* TODO: Update database */
    return DNAC_ERROR_NOT_INITIALIZED;
}

int dnac_wallet_get_unspent(dnac_context_t *ctx,
                            dnac_utxo_t **utxos,
                            int *count) {
    if (!ctx || !utxos || !count) return DNAC_ERROR_INVALID_PARAM;
    *utxos = NULL;
    *count = 0;
    /* TODO: Query database */
    return DNAC_SUCCESS;
}
