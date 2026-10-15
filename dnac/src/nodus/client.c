/**
 * @file client.c
 * @brief Witness client — Nodus SDK based
 *
 * All witness operations go through the Nodus client SDK
 * (nodus_client_dnac_*) which communicates with witnesses
 * via CBOR over Nodus TCP.
 */

#include "dnac/nodus.h"
#include "dnac/wallet.h"
#include <string.h>
#include <stdlib.h>
#include <pthread.h>

/* libdna crypto utilities */
#include "crypto/utils/qgp_log.h"

/* Nodus client SDK (public API) */
#include "nodus/nodus.h"
#include "crypto/utils/qgp_safe_string.h"   /* Phase 03: unsafe-string poison guard */

/* Nodus singleton access (not on DNAC include path, use extern) */
extern nodus_client_t *nodus_singleton_get(void);
extern void nodus_singleton_lock(void);
extern void nodus_singleton_unlock(void);

#define LOG_TAG "DNAC_NODUS"

/* ============================================================================
 * Internal State
 * ========================================================================== */

/* Cached witness server list (shared with discovery.c) */
dnac_witness_info_t *g_witness_servers = NULL;
int g_witness_count = 0;
uint64_t g_witness_cache_time = 0;
pthread_mutex_t g_witness_cache_mutex = PTHREAD_MUTEX_INITIALIZER;  /* M-30 */
#define WITNESS_CACHE_TTL_SEC 300  /* 5 minute cache */

/* ============================================================================
 * Public Functions
 * ========================================================================== */

int dnac_witness_request(dnac_context_t *ctx,
                         const dnac_spend_request_t *request,
                         dnac_witness_sig_t *witnesses_out,
                         int *witness_count_out) {
    if (!ctx || !request || !witnesses_out || !witness_count_out) {
        return DNAC_ERROR_INVALID_PARAM;
    }

    *witness_count_out = 0;

    nodus_client_t *client = nodus_singleton_get();
    if (!client) {
        QGP_LOG_ERROR(LOG_TAG, "Nodus singleton not initialized");
        return DNAC_ERROR_NOT_INITIALIZED;
    }

    nodus_singleton_lock();

    /* Build nodus types from DNAC request */
    nodus_pubkey_t sender_pk;
    memcpy(sender_pk.bytes, request->sender_pubkey, NODUS_PK_BYTES);
    nodus_sig_t sender_sig;
    memcpy(sender_sig.bytes, request->signature, NODUS_SIG_BYTES);

    nodus_dnac_spend_result_t result;
    int rc = nodus_client_dnac_spend(client,
                                      request->tx_hash,
                                      request->tx_data,
                                      request->tx_len,
                                      &sender_pk,
                                      &sender_sig,
                                      request->fee_amount,
                                      &result);

    nodus_singleton_unlock();

    if (rc != 0) {
        if (rc == NODUS_ERR_TIMEOUT) {
            QGP_LOG_ERROR(LOG_TAG, "Witness request timed out");
            return DNAC_ERROR_TIMEOUT;
        }
        if (rc == NODUS_ERR_ALREADY_EXISTS) {
            QGP_LOG_WARN(LOG_TAG, "Genesis already exists");
            return DNAC_ERROR_GENESIS_EXISTS;
        }
        if (rc == NODUS_ERR_DOUBLE_SPEND) {
            QGP_LOG_WARN(LOG_TAG, "Double-spend detected");
            return DNAC_ERROR_DOUBLE_SPEND;
        }
        QGP_LOG_ERROR(LOG_TAG, "Witness request failed: %d", rc);
        return DNAC_ERROR_WITNESS_FAILED;
    }

    if (result.status != NODUS_DNAC_APPROVED) {
        QGP_LOG_WARN(LOG_TAG, "Witness rejected: status=%d", result.status);
        return DNAC_ERROR_DOUBLE_SPEND;
    }

    /* Copy witness signature */
    memcpy(witnesses_out[0].witness_id, result.witness_id, 32);
    memcpy(witnesses_out[0].signature, result.signature, NODUS_SIG_BYTES);
    memcpy(witnesses_out[0].server_pubkey, result.witness_pubkey, NODUS_PK_BYTES);
    witnesses_out[0].timestamp = result.timestamp;
    /* Phase 13 / Task 13.1 — receipt fields (block_height, tx_index,
     * chain_id) needed for client-side spndrslt preimage verification. */
    witnesses_out[0].block_height = result.block_height;
    witnesses_out[0].tx_index = result.tx_index;
    memcpy(witnesses_out[0].chain_id, result.chain_id, 32);

    *witness_count_out = 1;

    QGP_LOG_INFO(LOG_TAG, "BFT consensus approved transaction");
    return DNAC_SUCCESS;
}

int dnac_get_current_fee(dnac_context_t *ctx, uint64_t *fee_out) {
    if (!ctx || !fee_out) return DNAC_ERROR_INVALID_PARAM;

    nodus_client_t *client = nodus_singleton_get();
    if (!client) return DNAC_ERROR_NOT_INITIALIZED;

    nodus_singleton_lock();

    nodus_dnac_fee_info_t info;
    int rc = nodus_client_dnac_fee_info(client, &info);

    nodus_singleton_unlock();

    if (rc != 0) {
        /* Fallback: use base fee if witness unreachable */
        *fee_out = 1000000;  /* 0.01 DNAC */
        return DNAC_SUCCESS;
    }

    *fee_out = info.min_fee;

    /* Perf-harness override (2026-04-24): DNA_BENCH_FEE_MULT env
     * multiplies the dynamic fee. Lets bench clients out-pay the
     * query→submit surge race. Ignored when unset or <1; capped at
     * 100 so a stray env cannot blow past reason. No production
     * effect unless the env var is explicitly set. */
    const char *mult_env = getenv("DNA_BENCH_FEE_MULT");
    if (mult_env && *mult_env) {
        char *end = NULL;
        unsigned long mult = strtoul(mult_env, &end, 10);
        if (end && *end == '\0' && mult > 1 && mult <= 100) {
            *fee_out *= mult;
        }
    }
    return DNAC_SUCCESS;
}

/* dnac_witness_replay (dnac_spend_replay RPC) and the genesis fetch —
 * dnac_request_genesis / dnac_request_genesis_quorum (dnac_genesis RPC) —
 * are deleted with those RPCs (2026-10-15): both read legacy tables no
 * version-3 chain writes, so replay always answered "not committed" and
 * the genesis fetch always answered "no genesis row". */
