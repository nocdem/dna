/**
 * @file rewards_query.c
 * @brief Pending-rewards query API (Phase 14 Task 64 — wired).
 *
 * Public API (see dnac.h):
 *   - dnac_get_pending_rewards()
 *
 * Calls the witness-side dnac_pending_rewards_query RPC (Task 61). When
 * claimant_pubkey is NULL we substitute the caller's own signing pubkey
 * via dna_engine_get_signing_public_key.
 *
 * The callback parameter is retained in the public signature but is not
 * used by this synchronous implementation — Flutter callers pass NULL.
 * Async delivery is deferred until the engine dispatcher owns this API
 * (Phase 14.2 / post-genesis tightening).
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */

#include "dnac/dnac.h"
#include "dnac/wallet.h"

#include <dna/dna_engine.h>

#include "crypto/utils/qgp_log.h"
#include "nodus/nodus.h"

#include <string.h>

#define LOG_TAG "DNAC_REWARDS_QUERY"

/* Nodus singleton accessors (defined in messenger/dht/shared/nodus_init.c). */
extern nodus_client_t *nodus_singleton_get(void);
extern void nodus_singleton_lock(void);
extern void nodus_singleton_unlock(void);

int dnac_get_pending_rewards(dnac_context_t *ctx,
                             const uint8_t *claimant_pubkey,
                             uint64_t *total_pending_out,
                             dnac_callback_t callback,
                             void *user_data) {
    (void)callback;
    (void)user_data;

    if (!total_pending_out) return DNAC_ERROR_INVALID_PARAM;
    *total_pending_out = 0;

    if (!ctx) return DNAC_ERROR_INVALID_PARAM;

    /* Resolve claimant pubkey — default to our own signing key. */
    uint8_t self_pk[DNAC_PUBKEY_SIZE];
    const uint8_t *pk_to_use = claimant_pubkey;
    if (!pk_to_use) {
        dna_engine_t *engine = dnac_get_engine(ctx);
        if (!engine) return DNAC_ERROR_NOT_INITIALIZED;
        int rc = dna_engine_get_signing_public_key(engine, self_pk,
                                                     DNAC_PUBKEY_SIZE);
        if (rc < 0) {
            QGP_LOG_ERROR(LOG_TAG, "cannot fetch own pubkey: %d", rc);
            return DNAC_ERROR_CRYPTO;
        }
        pk_to_use = self_pk;
    }

    nodus_client_t *client = nodus_singleton_get();
    if (!client) return DNAC_ERROR_NOT_INITIALIZED;

    nodus_singleton_lock();
    nodus_dnac_pending_rewards_result_t result;
    int rc = nodus_client_dnac_pending_rewards(client, pk_to_use, &result);
    nodus_singleton_unlock();

    if (rc != 0) {
        QGP_LOG_ERROR(LOG_TAG, "pending_rewards RPC failed: %d", rc);
        return DNAC_ERROR_NETWORK;
    }

    *total_pending_out = result.total;
    QGP_LOG_DEBUG(LOG_TAG,
                   "pending_rewards: total=%llu entries=%d",
                   (unsigned long long)result.total, result.count);

    nodus_client_free_pending_rewards_result(&result);
    return DNAC_SUCCESS;
}
