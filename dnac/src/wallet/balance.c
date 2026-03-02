/**
 * @file balance.c
 * @brief Balance calculation (v1 transparent)
 */

#include "dnac/wallet.h"
#include "dnac/db.h"
#include "dnac/safe_math.h"
#include "crypto/utils/qgp_log.h"
#include <stdlib.h>

#define LOG_TAG "BALANCE"

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
                /* HIGH-8: Safe overflow check on balance */
                if (safe_add_u64(balance->confirmed, utxos[i].amount,
                                 &balance->confirmed) != 0) {
                    QGP_LOG_ERROR(LOG_TAG, "Balance overflow at UTXO %d", i);
                    free(utxos);
                    return DNAC_ERROR_OVERFLOW;
                }
                break;
            case DNAC_UTXO_PENDING:
                if (safe_add_u64(balance->locked, utxos[i].amount,
                                 &balance->locked) != 0) {
                    QGP_LOG_ERROR(LOG_TAG, "Locked balance overflow at UTXO %d", i);
                    free(utxos);
                    return DNAC_ERROR_OVERFLOW;
                }
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
