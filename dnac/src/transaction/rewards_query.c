/**
 * @file rewards_query.c
 * @brief Pending-rewards query API (Phase 7, Task 38 — STUB).
 *
 * Public API (see dnac.h):
 *   - dnac_get_pending_rewards() — stub returning DNAC_ERROR_NOT_IMPLEMENTED
 *
 * The witness-side RPC handler (`dnac_pending_rewards_query`) lands in
 * Phase 14 Task 61. Until then this file exists so CLI + Flutter can
 * forward-declare against the API shape and gate UI on the
 * DNAC_ERROR_NOT_IMPLEMENTED return code. When Phase 14 ships, the stub
 * body here will be replaced with a Tier-2 RPC call — the public
 * signature stays stable.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */

#include "dnac/dnac.h"

#include "crypto/utils/qgp_log.h"

#define LOG_TAG "DNAC_REWARDS_QUERY"

int dnac_get_pending_rewards(dnac_context_t *ctx,
                             const uint8_t *claimant_pubkey,
                             uint64_t *total_pending_out,
                             dnac_callback_t callback,
                             void *user_data) {
    (void)ctx;
    (void)claimant_pubkey;
    (void)callback;
    (void)user_data;

    if (!total_pending_out) return DNAC_ERROR_INVALID_PARAM;

    /* Always zero the output before returning — prevents callers from
     * acting on an uninitialised stack value if they forget to check
     * the return code. */
    *total_pending_out = 0;

    QGP_LOG_WARN(LOG_TAG,
                 "dnac_get_pending_rewards: not implemented "
                 "(Phase 14 Task 61 wires the witness RPC)");

    return DNAC_ERROR_NOT_IMPLEMENTED;
}
