/**
 * @file validator_queries.c
 * @brief Validator + committee query API (Phase 7, Task 39 — STUBS).
 *
 * Public API (see dnac.h):
 *   - dnac_validator_list() — stub returning DNAC_ERROR_NOT_IMPLEMENTED
 *   - dnac_get_committee()  — stub returning DNAC_ERROR_NOT_IMPLEMENTED
 *
 * The witness-side RPC handlers land in Phase 14:
 *   - Task 62 wires the committee query
 *   - Task 63 wires the validator-list query
 *
 * Until then these stubs exist so CLI + Flutter can forward-declare
 * against the API shape and gate UI on the DNAC_ERROR_NOT_IMPLEMENTED
 * return code. When Phase 14 ships, each stub body is replaced with a
 * Tier-2 RPC call — the public signatures stay stable.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */

#include "dnac/dnac.h"

#include "crypto/utils/qgp_log.h"

#include <string.h>

#define LOG_TAG "DNAC_VALIDATOR_QUERIES"

int dnac_validator_list(dnac_context_t *ctx,
                        int filter_status,
                        dnac_validator_list_entry_t *out,
                        int max_entries,
                        int *count_out) {
    (void)ctx;
    (void)filter_status;

    if (!count_out) return DNAC_ERROR_INVALID_PARAM;
    /* It's legal to pass NULL `out` with max_entries == 0 to simply
     * probe the API — but a non-NULL `out` demands a positive capacity,
     * and vice-versa. */
    if (out && max_entries <= 0)  return DNAC_ERROR_INVALID_PARAM;
    if (!out && max_entries != 0) return DNAC_ERROR_INVALID_PARAM;

    /* Always zero the output range + count before returning so callers
     * can't act on uninitialised memory if they forget to check rc. */
    *count_out = 0;
    if (out && max_entries > 0) {
        memset(out, 0, (size_t)max_entries * sizeof(*out));
    }

    QGP_LOG_WARN(LOG_TAG,
                 "dnac_validator_list: not implemented "
                 "(Phase 14 Task 63 wires the witness RPC)");

    return DNAC_ERROR_NOT_IMPLEMENTED;
}

int dnac_get_committee(dnac_context_t *ctx,
                       dnac_validator_list_entry_t *out,
                       int *count_out) {
    (void)ctx;

    if (!out)       return DNAC_ERROR_INVALID_PARAM;
    if (!count_out) return DNAC_ERROR_INVALID_PARAM;

    *count_out = 0;
    memset(out, 0, (size_t)DNAC_COMMITTEE_SIZE * sizeof(*out));

    QGP_LOG_WARN(LOG_TAG,
                 "dnac_get_committee: not implemented "
                 "(Phase 14 Task 62 wires the witness RPC)");

    return DNAC_ERROR_NOT_IMPLEMENTED;
}
