/**
 * @file utxo.c
 * @brief UTXO handling (v1 transparent)
 */

#include "dnac/wallet.h"
#include "dnac/db.h"
#include <string.h>

int dnac_wallet_store_utxo(dnac_context_t *ctx, const dnac_utxo_t *utxo) {
    if (!ctx || !utxo) return DNAC_ERROR_INVALID_PARAM;

    sqlite3 *db = dnac_get_db(ctx);
    if (!db) return DNAC_ERROR_NOT_INITIALIZED;

    return dnac_db_store_utxo(db, utxo);
}

int dnac_wallet_mark_spent(dnac_context_t *ctx,
                           const uint8_t *nullifier,
                           const uint8_t *spent_in_tx) {
    if (!ctx || !nullifier) return DNAC_ERROR_INVALID_PARAM;

    sqlite3 *db = dnac_get_db(ctx);
    if (!db) return DNAC_ERROR_NOT_INITIALIZED;

    return dnac_db_mark_utxo_spent(db, nullifier, spent_in_tx);
}

int dnac_wallet_get_unspent(dnac_context_t *ctx,
                            dnac_utxo_t **utxos,
                            int *count) {
    if (!ctx || !utxos || !count) return DNAC_ERROR_INVALID_PARAM;

    sqlite3 *db = dnac_get_db(ctx);
    const char *owner_fp = dnac_get_owner_fingerprint(ctx);

    if (!db || !owner_fp) return DNAC_ERROR_NOT_INITIALIZED;

    return dnac_db_get_unspent_utxos(db, owner_fp, utxos, count);
}
