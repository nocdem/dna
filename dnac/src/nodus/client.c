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

/* libdna crypto utilities */
#include "crypto/utils/qgp_dilithium.h"
#include "crypto/utils/qgp_log.h"

/* Nodus client SDK (public API) */
#include "nodus/nodus.h"

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
#define WITNESS_CACHE_TTL_SEC 300  /* 5 minute cache */

/* ============================================================================
 * Public Functions
 * ========================================================================== */

int dnac_witness_init(dnac_context_t *ctx) {
    if (!ctx) return -1;

    /* Clear cached server list */
    if (g_witness_servers) {
        dnac_free_witness_list(g_witness_servers, g_witness_count);
        g_witness_servers = NULL;
        g_witness_count = 0;
    }
    g_witness_cache_time = 0;

    return 0;
}

void dnac_witness_shutdown(dnac_context_t *ctx) {
    (void)ctx;

    /* Free cached server list */
    if (g_witness_servers) {
        dnac_free_witness_list(g_witness_servers, g_witness_count);
        g_witness_servers = NULL;
        g_witness_count = 0;
    }
}

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

    *witness_count_out = 1;

    QGP_LOG_INFO(LOG_TAG, "BFT consensus approved transaction");
    return DNAC_SUCCESS;
}

int dnac_witness_check_nullifier(dnac_context_t *ctx,
                                 const uint8_t *nullifier,
                                 bool *is_spent_out) {
    if (!ctx || !nullifier || !is_spent_out) {
        return DNAC_ERROR_INVALID_PARAM;
    }

    *is_spent_out = false;

    nodus_client_t *client = nodus_singleton_get();
    if (!client) return DNAC_ERROR_NOT_INITIALIZED;

    nodus_singleton_lock();

    nodus_dnac_nullifier_result_t result;
    int rc = nodus_client_dnac_nullifier(client, nullifier, &result);

    nodus_singleton_unlock();

    if (rc != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Nullifier check failed: %d", rc);
        return DNAC_ERROR_NETWORK;
    }

    *is_spent_out = result.is_spent;

    QGP_LOG_DEBUG(LOG_TAG, "Nullifier check result: is_spent=%d",
                  result.is_spent);
    return DNAC_SUCCESS;
}

bool dnac_witness_verify(const dnac_witness_sig_t *witness,
                         const uint8_t *tx_hash,
                         const uint8_t *witness_pubkey) {
    if (!witness || !tx_hash || !witness_pubkey) return false;

    /* Build signed data: tx_hash + witness_id + timestamp */
    uint8_t signed_data[DNAC_TX_HASH_SIZE + 32 + 8];
    memcpy(signed_data, tx_hash, DNAC_TX_HASH_SIZE);
    memcpy(signed_data + DNAC_TX_HASH_SIZE, witness->witness_id, 32);

    /* Little-endian timestamp */
    for (int i = 0; i < 8; i++) {
        signed_data[DNAC_TX_HASH_SIZE + 32 + i] =
            (witness->timestamp >> (i * 8)) & 0xFF;
    }

    /* Verify Dilithium5 signature */
    int ret = qgp_dsa87_verify(witness->signature, DNAC_SIGNATURE_SIZE,
                               signed_data, sizeof(signed_data),
                               witness_pubkey);
    return (ret == 0);
}

uint64_t dnac_witness_calculate_fee(uint64_t amount) {
    /* 0.1% fee (10 basis points)
     * Use amount/1000 instead of (amount*10)/10000 to avoid overflow.
     * For amounts < 1000, this gives 0, so min_fee=1 applies. */
    uint64_t fee = amount / 1000;
    return fee > 0 ? fee : 1;  /* Minimum 1 unit */
}

int dnac_witness_ping(dnac_context_t *ctx,
                      const uint8_t *server_id,
                      int *latency_ms_out) {
    (void)ctx; (void)server_id;

    if (!latency_ms_out) return -1;
    *latency_ms_out = -1;

    /* Ping is handled by Nodus SDK connection-level keepalive.
     * For health checking, use nodus_client_is_ready(). */
    nodus_client_t *client = nodus_singleton_get();
    if (!client || !nodus_client_is_ready(client)) return -1;

    *latency_ms_out = 0;
    return 0;
}
