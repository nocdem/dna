/**
 * @file client.c
 * @brief Nodus RPC client
 */

#include "dnac/nodus.h"
#include <string.h>

int dnac_nodus_init(dnac_context_t *ctx) {
    if (!ctx) return -1;
    /* TODO: Initialize connection state */
    return 0;
}

void dnac_nodus_shutdown(dnac_context_t *ctx) {
    if (!ctx) return;
    /* TODO: Close connections */
}

int dnac_nodus_request_anchors(dnac_context_t *ctx,
                               const dnac_spend_request_t *request,
                               dnac_anchor_t *anchors_out,
                               int *anchor_count_out) {
    if (!ctx || !request || !anchors_out || !anchor_count_out) {
        return DNAC_ERROR_INVALID_PARAM;
    }

    *anchor_count_out = 0;

    /* TODO: Send request to all known Nodus servers in parallel */
    /* TODO: Wait for responses with timeout */
    /* TODO: Collect valid anchor signatures */

    return DNAC_ERROR_NOT_INITIALIZED;
}

int dnac_nodus_check_nullifier(dnac_context_t *ctx,
                               const uint8_t *nullifier,
                               bool *is_spent_out) {
    if (!ctx || !nullifier || !is_spent_out) {
        return DNAC_ERROR_INVALID_PARAM;
    }

    *is_spent_out = false;

    /* TODO: Query Nodus servers for nullifier status */

    return DNAC_ERROR_NOT_INITIALIZED;
}

bool dnac_nodus_verify_anchor(const dnac_anchor_t *anchor,
                              const uint8_t *tx_hash,
                              const uint8_t *nodus_pubkey) {
    if (!anchor || !tx_hash || !nodus_pubkey) return false;

    /* TODO: Verify Dilithium5 signature */

    return false;
}

uint64_t dnac_nodus_calculate_fee(uint64_t amount) {
    /* 0.1% fee (10 basis points) */
    uint64_t fee = (amount * DNAC_FEE_RATE_BPS) / 10000;
    return fee > 0 ? fee : 1;  /* Minimum 1 unit */
}

int dnac_nodus_ping(dnac_context_t *ctx,
                    const uint8_t *server_id,
                    int *latency_ms_out) {
    if (!ctx || !server_id || !latency_ms_out) {
        return -1;
    }

    *latency_ms_out = -1;

    /* TODO: Send ping, measure roundtrip */

    return -1;
}
