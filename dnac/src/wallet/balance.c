/**
 * @file balance.c
 * @brief Balance calculation
 */

#include "dnac/wallet.h"

int dnac_wallet_calculate_balance(dnac_context_t *ctx, dnac_balance_t *balance) {
    if (!ctx || !balance) return DNAC_ERROR_INVALID_PARAM;

    balance->confirmed = 0;
    balance->pending = 0;
    balance->locked = 0;
    balance->utxo_count = 0;

    /* TODO: Sum up UTXOs from database */

    return DNAC_SUCCESS;
}
