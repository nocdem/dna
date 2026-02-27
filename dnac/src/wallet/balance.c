/**
 * @file balance.c
 * @brief Balance calculation (v1 transparent)
 */

#include "dnac/wallet.h"
#include "dnac/db.h"
#include <stdlib.h>

int dnac_wallet_calculate_balance(dnac_context_t *ctx, dnac_balance_t *balance) {
    if (!ctx || !balance) return DNAC_ERROR_INVALID_PARAM;

    sqlite3 *db = dnac_get_db(ctx);
    const char *owner_fp = dnac_get_owner_fingerprint(ctx);

    if (!db || !owner_fp) return DNAC_ERROR_NOT_INITIALIZED;

    /* Initialize balance */
    balance->confirmed = 0;
    balance->pending = 0;
    balance->locked = 0;
    balance->utxo_count = 0;

    /* Get all unspent UTXOs */
    dnac_utxo_t *utxos = NULL;
    int count = 0;

    int rc = dnac_db_get_unspent_utxos(db, owner_fp, &utxos, &count);
    if (rc != DNAC_SUCCESS) {
        return rc;
    }

    /* Sum up balances by status */
    for (int i = 0; i < count; i++) {
        switch (utxos[i].status) {
            case DNAC_UTXO_UNSPENT:
                balance->confirmed += utxos[i].amount;
                break;
            case DNAC_UTXO_PENDING:
                balance->locked += utxos[i].amount;
                break;
            default:
                /* SPENT - shouldn't be returned by get_unspent, but ignore */
                break;
        }
    }

    balance->utxo_count = count;

    free(utxos);
    return DNAC_SUCCESS;
}
