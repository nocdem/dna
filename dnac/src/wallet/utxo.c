/**
 * @file utxo.c
 * @brief UTXO handling (v1 transparent)
 */

#include "dnac/wallet.h"
#include "dnac/db.h"
#include <string.h>
#include "crypto/utils/qgp_safe_string.h"   /* Phase 03: unsafe-string poison guard */

int dnac_wallet_get_unspent(dnac_context_t *ctx,
                            dnac_utxo_t **utxos,
                            int *count) {
    if (!ctx || !utxos || !count) return DNAC_ERROR_INVALID_PARAM;

    sqlite3 *db = dnac_get_db(ctx);
    const char *owner_fp = dnac_get_owner_fingerprint(ctx);

    if (!db || !owner_fp) return DNAC_ERROR_NOT_INITIALIZED;

    return dnac_db_get_unspent_utxos(db, owner_fp, utxos, count);
}
