/**
 * @file validator_queries.c
 * @brief Validator + committee query API (Phase 14 Task 64 — wired).
 *
 * Public API (see dnac.h):
 *   - dnac_validator_list() — calls dnac_validator_list_query RPC (Task 63)
 *   - dnac_get_committee()  — calls dnac_committee_query RPC (Task 62)
 *
 * Both walk the Nodus client SDK synchronously. The returned entries
 * are projected onto dnac_validator_list_entry_t (see dnac.h §Stake &
 * Delegation queries), which is a subset of the witness-side record.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */

#include "dnac/dnac.h"

#include "crypto/utils/qgp_log.h"
#include "nodus/nodus.h"

#include <string.h>

#define LOG_TAG "DNAC_VALIDATOR_QUERIES"

/* Nodus singleton accessors. */
extern nodus_client_t *nodus_singleton_get(void);
extern void nodus_singleton_lock(void);
extern void nodus_singleton_unlock(void);

int dnac_validator_list(dnac_context_t *ctx,
                        int filter_status,
                        dnac_validator_list_entry_t *out,
                        int max_entries,
                        int *count_out) {
    (void)ctx;

    if (!count_out) return DNAC_ERROR_INVALID_PARAM;
    if (out && max_entries <= 0)  return DNAC_ERROR_INVALID_PARAM;
    if (!out && max_entries != 0) return DNAC_ERROR_INVALID_PARAM;

    *count_out = 0;
    if (out && max_entries > 0) {
        memset(out, 0, (size_t)max_entries * sizeof(*out));
    }

    nodus_client_t *client = nodus_singleton_get();
    if (!client) return DNAC_ERROR_NOT_INITIALIZED;

    nodus_singleton_lock();
    nodus_dnac_validator_list_result_t result;
    int rc = nodus_client_dnac_validator_list(client, filter_status,
                                                /*offset=*/0,
                                                /*limit=*/max_entries,
                                                &result);
    nodus_singleton_unlock();

    if (rc != 0) {
        QGP_LOG_ERROR(LOG_TAG, "validator_list RPC failed: %d", rc);
        return DNAC_ERROR_NETWORK;
    }

    int n = result.count < max_entries ? result.count : max_entries;
    for (int i = 0; i < n; i++) {
        nodus_dnac_validator_list_entry_t *src = &result.entries[i];
        dnac_validator_list_entry_t *dst = &out[i];
        memcpy(dst->pubkey, src->pubkey, DNAC_PUBKEY_SIZE);
        dst->self_stake         = src->self_stake;
        dst->total_delegated    = src->total_delegated;
        dst->commission_bps     = src->commission_bps;
        dst->status             = src->status;
        dst->active_since_block = src->active_since_block;
    }
    *count_out = n;

    nodus_client_free_validator_list_result(&result);
    return DNAC_SUCCESS;
}

int dnac_get_committee(dnac_context_t *ctx,
                       dnac_validator_list_entry_t *out,
                       int *count_out) {
    (void)ctx;

    if (!out)       return DNAC_ERROR_INVALID_PARAM;
    if (!count_out) return DNAC_ERROR_INVALID_PARAM;

    *count_out = 0;
    memset(out, 0, (size_t)DNAC_COMMITTEE_SIZE * sizeof(*out));

    nodus_client_t *client = nodus_singleton_get();
    if (!client) return DNAC_ERROR_NOT_INITIALIZED;

    nodus_singleton_lock();
    nodus_dnac_committee_result_t result;
    int rc = nodus_client_dnac_committee(client, &result);
    nodus_singleton_unlock();

    if (rc != 0) {
        QGP_LOG_ERROR(LOG_TAG, "committee RPC failed: %d", rc);
        return DNAC_ERROR_NETWORK;
    }

    int n = result.count < DNAC_COMMITTEE_SIZE ?
             result.count : DNAC_COMMITTEE_SIZE;
    for (int i = 0; i < n; i++) {
        nodus_dnac_committee_entry_t *src = &result.entries[i];
        dnac_validator_list_entry_t *dst = &out[i];
        memcpy(dst->pubkey, src->pubkey, DNAC_PUBKEY_SIZE);
        dst->self_stake         = 0;   /* committee entry reports aggregate */
        dst->total_delegated    = src->total_stake;
        dst->commission_bps     = src->commission_bps;
        dst->status             = src->status;
        dst->active_since_block = 0;
    }
    *count_out = n;

    return DNAC_SUCCESS;
}
