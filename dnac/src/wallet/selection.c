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
#include "crypto/utils/qgp_safe_string.h"   /* Phase 03: unsafe-string poison guard */

/**
 * @brief Compare UTXOs by amount (for qsort)
 *
 * DETERMINISM: amount alone is not a total order — two coins of equal value
 * would sort in an implementation-defined relative order, so two wallets
 * holding the same coin set could build different (both valid) transactions.
 * The nullifier is unique per coin, so it breaks every tie and makes the
 * order total. (nodus/CLAUDE.md forbids selection that depends on unordered
 * iteration; `dnac/CLAUDE.md` names coin selection explicitly.)
 */
static int compare_utxo_amount(const void *a, const void *b) {
    const dnac_utxo_t *ua = (const dnac_utxo_t *)a;
    const dnac_utxo_t *ub = (const dnac_utxo_t *)b;

    if (ua->amount < ub->amount) return -1;
    if (ua->amount > ub->amount) return 1;
    return memcmp(ua->nullifier, ub->nullifier, DNAC_NULLIFIER_SIZE);
}

/**
 * @brief Drop coins consensus would refuse as inputs, in place.
 *
 * O15B §7. A coin whose `unlock_block` exceeds the chain height is still
 * inside its post-UNSTAKE cooldown; EVERY honest validator rejects a
 * transaction that spends it (Rule D, nodus_witness_verify.c:730). Selecting
 * one produces a transaction that cannot commit at any timeout, on any node —
 * the failure surfaces to the user as "Operation timed out" with no
 * diagnosis, forever, on every retry.
 *
 * The height comes from the wallet's last observed sync, which is the same
 * response the coins came from. If no sync has ever run, `height` is 0 and
 * only coins with `unlock_block == 0` survive — the conservative reading, and
 * the correct one: with no view of the chain we cannot claim any lock has
 * expired.
 *
 * @return the number of spendable coins left at the front of `utxos`.
 */
static int filter_spendable(dnac_utxo_t *utxos, int count, uint64_t height) {
    int kept = 0;
    for (int i = 0; i < count; i++) {
        if (utxos[i].unlock_block > height) continue;   /* still locked */
        if (kept != i) utxos[kept] = utxos[i];
        kept++;
    }
    return kept;
}

/** Best-effort read of the last synced chain height; 0 when unknown. */
static uint64_t observed_height(dnac_context_t *ctx) {
    sqlite3 *db = dnac_get_db(ctx);
    if (!db) return 0;
    uint64_t h = 0;
    if (dnac_db_get_observed_height(db, &h) != DNAC_SUCCESS) return 0;
    return h;
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

    /* O15B §7 — drop coins consensus would refuse BEFORE any arithmetic, so
     * neither the availability total nor the selection can see them. */
    count = filter_spendable(utxos, count, observed_height(ctx));
    if (count == 0) {
        free(utxos);
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

/**
 * @brief Select UTXOs for spending a specific token
 *
 * Filters unspent UTXOs by token_id before applying smallest-first
 * greedy selection. If token_id is NULL or all-zeros, selects native DNAC.
 */
int dnac_wallet_select_utxos_token(dnac_context_t *ctx,
                                    uint64_t target_amount,
                                    const uint8_t *token_id,
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

    /* Determine if we're looking for native (all-zeros) or custom token */
    static const uint8_t zero_token[DNAC_TOKEN_ID_SIZE] = {0};
    const uint8_t *match_token = (token_id != NULL) ? token_id : zero_token;

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

    /* O15B §7 — locked coins are unspendable regardless of which token they
     * carry, so the cooldown filter runs FIRST and the token filter narrows
     * what survives it. */
    count = filter_spendable(utxos, count, observed_height(ctx));
    if (count == 0) {
        free(utxos);
        return DNAC_ERROR_INSUFFICIENT_FUNDS;
    }

    /* Filter UTXOs by token_id — compact in-place */
    int filtered_count = 0;
    for (int i = 0; i < count; i++) {
        if (memcmp(utxos[i].token_id, match_token, DNAC_TOKEN_ID_SIZE) == 0) {
            if (filtered_count != i) {
                utxos[filtered_count] = utxos[i];
            }
            filtered_count++;
        }
    }

    if (filtered_count == 0) {
        free(utxos);
        return DNAC_ERROR_INSUFFICIENT_FUNDS;
    }

    /* Sort by amount (smallest first) */
    qsort(utxos, filtered_count, sizeof(dnac_utxo_t), compare_utxo_amount);

    /* Calculate total available */
    uint64_t total_available = 0;
    for (int i = 0; i < filtered_count; i++) {
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

    for (int i = 0; i < filtered_count && accumulated < target_amount; i++) {
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
