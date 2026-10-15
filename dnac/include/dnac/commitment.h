/**
 * @file commitment.h
 * @brief DNAC wallet recovery from witnesses
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */

#ifndef DNAC_COMMITMENT_H
#define DNAC_COMMITMENT_H

#include "dnac.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ============================================================================
 * Client Functions
 * ========================================================================== */

/**
 * @brief Recover wallet UTXOs from witnesses
 *
 * Queries witnesses for UTXOs belonging to our identity.
 *
 * @param ctx DNAC context
 * @param recovered_count Output: number of UTXOs recovered
 * @param total_amount Output: total amount recovered
 * @return DNAC_SUCCESS or error code
 */
int dnac_wallet_recover_from_witnesses(dnac_context_t *ctx,
                                        int *recovered_count,
                                        uint64_t *total_amount);

#ifdef __cplusplus
}
#endif

#endif /* DNAC_COMMITMENT_H */
