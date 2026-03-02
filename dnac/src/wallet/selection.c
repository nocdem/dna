/**
 * @file selection.c
 * @brief UTXO selection algorithms (v1 transparent)
 *
 * Implements coin selection for transaction building.
 * Uses smallest-first greedy algorithm for privacy (minimizes change).
 */

#include "dnac/wallet.h"
#include "dnac/db.h"
#include "dnac/safe_math.h"
#include <stdlib.h>
#include <string.h>

/**
 * @brief Compare UTXOs by amount (for qsort)
 */
static int compare_utxo_amount(const void *a, const void *b) {
    const dnac_utxo_t *ua = (const dnac_utxo_t *)a;
    const dnac_utxo_t *ub = (const dnac_utxo_t *)b;

    if (ua->amount < ub->amount) return -1;
    if (ua->amount > ub->amount) return 1;
    return 0;
}

/**
 * @brief Select UTXOs for spending
 *
 * Strategy: Smallest-first greedy selection
 * - Minimizes change output
 * - Consolidates small UTXOs
 * - Good for privacy (change is smaller)
 *
 * @param ctx DNAC context
 * @param target_amount Amount needed (including fee)
 * @param selected Output: selected UTXOs (caller must free)
 * @param selected_count Output: number of selected UTXOs
 * @param change_amount Output: change amount (0 if exact match)
 * @return DNAC_SUCCESS or error code
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

    if (target_amount == 0) {
        return DNAC_ERROR_INVALID_PARAM;
    }

    /* Get all unspent UTXOs */
    dnac_utxo_t *utxos = NULL;
    int count = 0;

    int rc = dnac_wallet_get_unspent(ctx, &utxos, &count);
    if (rc != DNAC_SUCCESS) {
        return rc;
    }

    if (count == 0) {
        return DNAC_ERROR_INSUFFICIENT_FUNDS;
    }

    /* Sort by amount (smallest first) */
    qsort(utxos, count, sizeof(dnac_utxo_t), compare_utxo_amount);

    /* Calculate total available */
    uint64_t total_available = 0;
    for (int i = 0; i < count; i++) {
        if (safe_add_u64(total_available, utxos[i].amount, &total_available) != 0) {
            free(utxos);
            return DNAC_ERROR_OVERFLOW;
        }
    }

    if (total_available < target_amount) {
        free(utxos);
        return DNAC_ERROR_INSUFFICIENT_FUNDS;
    }

    /* Select UTXOs until target is met */
    uint64_t accumulated = 0;
    int num_selected = 0;

    for (int i = 0; i < count && accumulated < target_amount; i++) {
        if (safe_add_u64(accumulated, utxos[i].amount, &accumulated) != 0) {
            free(utxos);
            return DNAC_ERROR_OVERFLOW;
        }
        num_selected++;
    }

    /* Allocate output array */
    dnac_utxo_t *result = calloc(num_selected, sizeof(dnac_utxo_t));
    if (!result) {
        free(utxos);
        return DNAC_ERROR_OUT_OF_MEMORY;
    }

    /* Copy selected UTXOs */
    memcpy(result, utxos, num_selected * sizeof(dnac_utxo_t));

    *selected = result;
    *selected_count = num_selected;
    *change_amount = accumulated - target_amount;

    free(utxos);
    return DNAC_SUCCESS;
}
