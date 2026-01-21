/**
 * @file server.c
 * @brief Witness server DHT polling and request handling
 *
 * Handles incoming SpendRequests from clients, validates them,
 * checks nullifiers, and sends signed witness responses.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */

#include "dnac/witness.h"
#include "dnac/nodus.h"
#include "dnac/epoch.h"
#include "dnac/version.h"
#include "config.h"

#include <string.h>
#include <time.h>
#include <pthread.h>
#include <openssl/evp.h>

#include "crypto/utils/qgp_dilithium.h"
#include "crypto/utils/qgp_log.h"

#define LOG_TAG "WITNESS_SRV"

/* ============================================================================
 * Response Queue (avoid calling dht_put from within listener callback)
 * ========================================================================== */

#define MAX_PENDING_RESPONSES 32

typedef struct {
    dnac_spend_request_t request;
    dnac_spend_response_t response;
    bool valid;
} pending_response_t;

static pending_response_t g_response_queue[MAX_PENDING_RESPONSES];
static pthread_mutex_t g_response_mutex = PTHREAD_MUTEX_INITIALIZER;
static int g_response_count = 0;

/* Queue a response to be sent from main thread */
static int queue_response(const dnac_spend_request_t *request,
                          const dnac_spend_response_t *response) {
    pthread_mutex_lock(&g_response_mutex);
    if (g_response_count >= MAX_PENDING_RESPONSES) {
        pthread_mutex_unlock(&g_response_mutex);
        QGP_LOG_WARN(LOG_TAG, "Response queue full, dropping response");
        return -1;
    }
    memcpy(&g_response_queue[g_response_count].request, request, sizeof(*request));
    memcpy(&g_response_queue[g_response_count].response, response, sizeof(*response));
    g_response_queue[g_response_count].valid = true;
    g_response_count++;
    QGP_LOG_DEBUG(LOG_TAG, "Queued response (%d pending)", g_response_count);
    pthread_mutex_unlock(&g_response_mutex);
    return 0;
}

/**
 * Check if nullifier is all zeros (indicates MINT request)
 */
static bool is_mint_request(const uint8_t *nullifier) {
    for (int i = 0; i < DNAC_NULLIFIER_SIZE; i++) {
        if (nullifier[i] != 0) return false;
    }
    return true;
}

/* Forward declare DHT context type */
typedef struct dht_context dht_context_t;

/* DHT functions from libdna */
extern void* dna_engine_get_dht_context(dna_engine_t *engine);
extern int dht_put_signed_permanent(dht_context_t *ctx,
                                    const uint8_t *key, size_t key_len,
                                    const uint8_t *value, size_t value_len,
                                    uint64_t value_id,
                                    const char *caller);
extern int dht_get(dht_context_t *ctx,
                   const uint8_t *key, size_t key_len,
                   uint8_t **value_out, size_t *value_len_out);

/* DHT listen callback type */
typedef bool (*dht_listen_callback_t)(
    const uint8_t *value,
    size_t value_len,
    bool expired,
    void *user_data
);

/* DHT listen functions from libdna */
extern size_t dht_listen(dht_context_t *ctx,
                         const uint8_t *key, size_t key_len,
                         dht_listen_callback_t callback,
                         void *user_data);
extern void dht_cancel_listen(dht_context_t *ctx, size_t token);

/* DNA engine functions */
extern const char* dna_engine_get_fingerprint(dna_engine_t *engine);
extern int dna_engine_sign_data(dna_engine_t *engine,
                                const uint8_t *data, size_t data_len,
                                uint8_t *signature_out, size_t *sig_len_out);
extern int dna_engine_get_signing_public_key(dna_engine_t *engine,
                                             uint8_t *pubkey_out,
                                             size_t pubkey_out_len);

/**
 * Compute SHA3-512 hash
 */
static int compute_sha3_512(const uint8_t *data, size_t len, uint8_t *hash_out) {
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx) return -1;

    if (EVP_DigestInit_ex(ctx, EVP_sha3_512(), NULL) != 1 ||
        EVP_DigestUpdate(ctx, data, len) != 1 ||
        EVP_DigestFinal_ex(ctx, hash_out, NULL) != 1) {
        EVP_MD_CTX_free(ctx);
        return -1;
    }

    EVP_MD_CTX_free(ctx);
    return 0;
}

/**
 * Build DHT key for incoming requests
 * Key: SHA3-512("dnac:nodus:request:" + our_fingerprint + ":" + requester_info)
 */
static int build_request_poll_key(const char *our_fingerprint, uint8_t *key_out) {
    uint8_t key_data[512];
    size_t offset = 0;

    memcpy(key_data + offset, WITNESS_REQUEST_PREFIX, strlen(WITNESS_REQUEST_PREFIX));
    offset += strlen(WITNESS_REQUEST_PREFIX);

    size_t fp_len = strlen(our_fingerprint);
    memcpy(key_data + offset, our_fingerprint, fp_len);
    offset += fp_len;

    return compute_sha3_512(key_data, offset, key_out);
}

/**
 * Build DHT key for response
 * Key: SHA3-512("dnac:nodus:response:" + tx_hash + ":" + requester_fingerprint)
 */
static int build_response_key(const uint8_t *tx_hash,
                              const char *requester_fp,
                              uint8_t *key_out) {
    uint8_t key_data[512];
    size_t offset = 0;

    memcpy(key_data + offset, WITNESS_RESPONSE_PREFIX, strlen(WITNESS_RESPONSE_PREFIX));
    offset += strlen(WITNESS_RESPONSE_PREFIX);

    memcpy(key_data + offset, tx_hash, 64);
    offset += 64;

    key_data[offset++] = ':';

    size_t fp_len = strlen(requester_fp);
    memcpy(key_data + offset, requester_fp, fp_len);
    offset += fp_len;

    return compute_sha3_512(key_data, offset, key_out);
}

/**
 * Build permanent announcement key
 * Key: SHA3-512("dnac:witness:announce:" + witness_fingerprint)
 */
static int build_announcement_key(const char *witness_fp, uint8_t *key_out) {
    uint8_t key_data[256];
    size_t offset = 0;

    memcpy(key_data, WITNESS_ANNOUNCE_PREFIX, strlen(WITNESS_ANNOUNCE_PREFIX));
    offset += strlen(WITNESS_ANNOUNCE_PREFIX);

    size_t fp_len = strlen(witness_fp);
    memcpy(key_data + offset, witness_fp, fp_len);
    offset += fp_len;

    return compute_sha3_512(key_data, offset, key_out);
}

/**
 * Build epoch-based request inbox key
 * Key: SHA3-512("dnac:nodus:epoch:request:" + witness_fp + ":" + epoch)
 */
static int build_epoch_request_key(const char *witness_fp, uint64_t epoch,
                                   uint8_t *key_out) {
    uint8_t key_data[256];
    size_t offset = 0;

    memcpy(key_data, WITNESS_EPOCH_REQUEST_PREFIX,
           strlen(WITNESS_EPOCH_REQUEST_PREFIX));
    offset += strlen(WITNESS_EPOCH_REQUEST_PREFIX);

    size_t fp_len = strlen(witness_fp);
    memcpy(key_data + offset, witness_fp, fp_len);
    offset += fp_len;

    key_data[offset++] = ':';

    /* Append epoch as 8-byte little-endian */
    for (int i = 0; i < 8; i++) {
        key_data[offset++] = (epoch >> (i * 8)) & 0xFF;
    }

    return compute_sha3_512(key_data, offset, key_out);
}

int witness_publish_identity(dna_engine_t *engine) {
    if (!engine) return -1;

    dht_context_t *dht = (dht_context_t *)dna_engine_get_dht_context(engine);
    if (!dht) {
        QGP_LOG_ERROR(LOG_TAG, "DHT context not available");
        return -1;
    }

    const char *fingerprint = dna_engine_get_fingerprint(engine);
    if (!fingerprint) {
        QGP_LOG_ERROR(LOG_TAG, "No fingerprint available");
        return -1;
    }

    /* Get our public key */
    uint8_t pubkey[DNAC_PUBKEY_SIZE];
    int ret = dna_engine_get_signing_public_key(engine, pubkey, sizeof(pubkey));
    if (ret < 0) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to get signing public key");
        return -1;
    }

    /* Build identity key */
    uint8_t key_data[256];
    size_t offset = 0;
    memcpy(key_data, WITNESS_IDENTITY_PREFIX, strlen(WITNESS_IDENTITY_PREFIX));
    offset = strlen(WITNESS_IDENTITY_PREFIX);
    memcpy(key_data + offset, fingerprint, strlen(fingerprint));
    offset += strlen(fingerprint);

    uint8_t identity_key[64];
    if (compute_sha3_512(key_data, offset, identity_key) != 0) {
        return -1;
    }

    /* Publish pubkey to DHT (permanent) */
    ret = dht_put_signed_permanent(dht, identity_key, 64, pubkey, DNAC_PUBKEY_SIZE,
                                   1, "witness_identity");
    if (ret != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to publish identity to DHT");
        return -1;
    }

    QGP_LOG_INFO(LOG_TAG, "Published witness server identity: %.32s...", fingerprint);
    return 0;
}

int witness_process_requests(dna_engine_t *engine) {
    if (!engine) return -1;

    int processed = 0;
    dnac_spend_request_t request;

    while (witness_get_next_request(engine, &request) == 0) {
        dnac_spend_response_t response;
        memset(&response, 0, sizeof(response));
        response.software_version[0] = DNAC_VERSION_MAJOR;
        response.software_version[1] = DNAC_VERSION_MINOR;
        response.software_version[2] = DNAC_VERSION_PATCH;

        /* Get our identity info */
        const char *our_fp = dna_engine_get_fingerprint(engine);
        if (!our_fp) continue;

        /* Convert fingerprint to witness_id bytes (first 32 bytes of fingerprint hex) */
        for (int i = 0; i < 32 && our_fp[i*2]; i++) {
            sscanf(&our_fp[i*2], "%2hhx", &response.witness_id[i]);
        }

        /* Check for MINT request (zero nullifier) */
        bool is_mint = is_mint_request(request.nullifier);

        /* For SPEND: check if nullifier already spent */
        if (!is_mint && witness_nullifier_exists(request.nullifier)) {
            response.status = DNAC_NODUS_STATUS_REJECTED;
            snprintf(response.error_message, sizeof(response.error_message),
                     "Nullifier already spent");
            QGP_LOG_WARN(LOG_TAG, "Rejected: nullifier already spent");
        } else {
            /* For SPEND: Record nullifier. For MINT: skip (no nullifier to record) */
            if (!is_mint && witness_nullifier_add(request.nullifier, request.tx_hash) != 0) {
                response.status = DNAC_NODUS_STATUS_ERROR;
                snprintf(response.error_message, sizeof(response.error_message),
                         "Database error");
                QGP_LOG_ERROR(LOG_TAG, "Failed to record nullifier");
            } else {
                /* Build data to sign: tx_hash || witness_id || timestamp */
                response.timestamp = (uint64_t)time(NULL);

                uint8_t sign_data[64 + 32 + 8];
                memcpy(sign_data, request.tx_hash, 64);
                memcpy(sign_data + 64, response.witness_id, 32);

                /* Little-endian timestamp */
                for (int i = 0; i < 8; i++) {
                    sign_data[64 + 32 + i] = (response.timestamp >> (i * 8)) & 0xFF;
                }

                /* Sign with our Dilithium5 key */
                size_t sig_len = 0;
                int ret = dna_engine_sign_data(engine, sign_data, sizeof(sign_data),
                                               response.signature, &sig_len);
                if (ret != 0) {
                    response.status = DNAC_NODUS_STATUS_ERROR;
                    snprintf(response.error_message, sizeof(response.error_message),
                             "Signing failed");
                    QGP_LOG_ERROR(LOG_TAG, "Failed to sign witness attestation");
                } else {
                    /* Include our public key in response */
                    dna_engine_get_signing_public_key(engine, response.server_pubkey,
                                                      DNAC_PUBKEY_SIZE);

                    response.status = DNAC_NODUS_STATUS_APPROVED;
                    QGP_LOG_INFO(LOG_TAG, "Approved %s request",
                                 is_mint ? "MINT" : "SPEND");

                    /* Queue nullifier for replication (skip for MINT) */
                    if (!is_mint) {
                        witness_replicate_nullifier(request.nullifier, request.tx_hash);
                    }
                }
            }
        }

        /* Send response */
        witness_send_response(engine, &request, &response);
        processed++;
    }

    return processed;
}

int witness_get_next_request(dna_engine_t *engine, dnac_spend_request_t *request) {
    if (!engine || !request) return -1;

    dht_context_t *dht = (dht_context_t *)dna_engine_get_dht_context(engine);
    if (!dht) return -1;

    const char *our_fp = dna_engine_get_fingerprint(engine);
    if (!our_fp) return -1;

    /* Build poll key */
    uint8_t poll_key[64];
    if (build_request_poll_key(our_fp, poll_key) != 0) {
        return -1;
    }

    /* GET from DHT */
    uint8_t *data = NULL;
    size_t data_len = 0;

    int rc = dht_get(dht, poll_key, 64, &data, &data_len);
    if (rc != 0 || !data || data_len == 0) {
        return 1; /* No requests available */
    }

    /* Deserialize request */
    rc = dnac_spend_request_deserialize(data, data_len, request);
    free(data);

    if (rc != 0) {
        QGP_LOG_WARN(LOG_TAG, "Failed to deserialize request");
        return -1;
    }

    return 0;
}

int witness_send_response(dna_engine_t *engine,
                          const dnac_spend_request_t *request,
                          const dnac_spend_response_t *response) {
    if (!engine || !request || !response) {
        QGP_LOG_ERROR(LOG_TAG, "send_response: null param");
        return -1;
    }

    dht_context_t *dht = (dht_context_t *)dna_engine_get_dht_context(engine);
    if (!dht) {
        QGP_LOG_ERROR(LOG_TAG, "send_response: no DHT");
        return -1;
    }

    /* Get requester fingerprint from pubkey (would need to derive or have in request) */
    /* For now, use a simplified approach - derive from sender_pubkey hash */
    uint8_t fp_hash[64];
    compute_sha3_512(request->sender_pubkey, DNAC_PUBKEY_SIZE, fp_hash);

    char requester_fp[129];
    for (int i = 0; i < 64; i++) {
        sprintf(&requester_fp[i*2], "%02x", fp_hash[i]);
    }
    requester_fp[128] = '\0';

    QGP_LOG_DEBUG(LOG_TAG, "send_response: requester_fp=%.32s...", requester_fp);

    /* Build response key */
    uint8_t response_key[64];
    if (build_response_key(request->tx_hash, requester_fp, response_key) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "send_response: build_response_key failed");
        return -1;
    }

    QGP_LOG_DEBUG(LOG_TAG, "send_response: key=%02x%02x%02x%02x...",
                  response_key[0], response_key[1], response_key[2], response_key[3]);

    /* Serialize response */
    uint8_t buffer[16384];
    size_t written = 0;
    int rc = dnac_spend_response_serialize(response, buffer, sizeof(buffer), &written);
    if (rc != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to serialize response");
        return -1;
    }

    QGP_LOG_DEBUG(LOG_TAG, "send_response: serialized %zu bytes", written);

    /* PUT to DHT (permanent) */
    QGP_LOG_DEBUG(LOG_TAG, "send_response: calling dht_put_signed_permanent...");
    rc = dht_put_signed_permanent(dht, response_key, 64, buffer, written,
                                  response->timestamp % 10000,
                                  "witness_response");
    QGP_LOG_DEBUG(LOG_TAG, "send_response: dht_put_signed_permanent returned %d", rc);
    if (rc != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to PUT response to DHT (rc=%d)", rc);
        return -1;
    }

    QGP_LOG_INFO(LOG_TAG, "Response sent to %.32s...", requester_fp);
    return 0;
}

/**
 * Process pending responses from the queue
 * Call this from main thread, not from callbacks
 */
int witness_process_pending_responses(dna_engine_t *engine) {
    if (!engine) return 0;

    pthread_mutex_lock(&g_response_mutex);
    int count = g_response_count;
    pending_response_t local_queue[MAX_PENDING_RESPONSES];
    if (count > 0) {
        memcpy(local_queue, g_response_queue, count * sizeof(pending_response_t));
        g_response_count = 0;
    }
    pthread_mutex_unlock(&g_response_mutex);

    if (count == 0) return 0;

    QGP_LOG_DEBUG(LOG_TAG, "Processing %d queued responses", count);

    int sent = 0;
    for (int i = 0; i < count; i++) {
        if (local_queue[i].valid) {
            if (witness_send_response(engine, &local_queue[i].request,
                                      &local_queue[i].response) == 0) {
                sent++;
            }
        }
    }

    return sent;
}

/* ============================================================================
 * Event-Driven Request Listener
 * ========================================================================== */

/**
 * DHT listener callback for incoming witness requests
 */
static bool request_listener_callback(const uint8_t *value, size_t value_len,
                                      bool expired, void *user_data) {
    witness_request_ctx_t *ctx = (witness_request_ctx_t *)user_data;
    if (!ctx || expired || !value || value_len == 0) return true;

    /* Deserialize request */
    dnac_spend_request_t request;
    if (dnac_spend_request_deserialize(value, value_len, &request) != 0) {
        QGP_LOG_WARN(LOG_TAG, "Failed to deserialize incoming request");
        return true;  /* Continue listening */
    }

    QGP_LOG_DEBUG(LOG_TAG, "Received witness request via listener");

    /* Process the request */
    dnac_spend_response_t response;
    memset(&response, 0, sizeof(response));
        response.software_version[0] = DNAC_VERSION_MAJOR;
        response.software_version[1] = DNAC_VERSION_MINOR;
        response.software_version[2] = DNAC_VERSION_PATCH;

    /* Get our identity info */
    const char *our_fp = dna_engine_get_fingerprint(ctx->engine);
    if (!our_fp) {
        return true;  /* Continue listening */
    }

    /* Convert fingerprint to witness_id bytes (first 32 bytes of fingerprint hex) */
    for (int i = 0; i < 32 && our_fp[i*2]; i++) {
        sscanf(&our_fp[i*2], "%2hhx", &response.witness_id[i]);
    }

    /* Check for MINT request (zero nullifier) */
    bool is_mint = is_mint_request(request.nullifier);

    /* For SPEND: check if nullifier already spent */
    if (!is_mint && witness_nullifier_exists(request.nullifier)) {
        response.status = DNAC_NODUS_STATUS_REJECTED;
        snprintf(response.error_message, sizeof(response.error_message),
                 "Nullifier already spent");
        QGP_LOG_WARN(LOG_TAG, "Rejected: nullifier already spent");
    } else {
        /* For SPEND: Record nullifier. For MINT: skip (no nullifier to record) */
        if (!is_mint && witness_nullifier_add(request.nullifier, request.tx_hash) != 0) {
            response.status = DNAC_NODUS_STATUS_ERROR;
            snprintf(response.error_message, sizeof(response.error_message),
                     "Database error");
            QGP_LOG_ERROR(LOG_TAG, "Failed to record nullifier");
        } else {
            /* Build data to sign: tx_hash || witness_id || timestamp */
            response.timestamp = (uint64_t)time(NULL);

            uint8_t sign_data[64 + 32 + 8];
            memcpy(sign_data, request.tx_hash, 64);
            memcpy(sign_data + 64, response.witness_id, 32);

            /* Little-endian timestamp */
            for (int i = 0; i < 8; i++) {
                sign_data[64 + 32 + i] = (response.timestamp >> (i * 8)) & 0xFF;
            }

            /* Sign with our Dilithium5 key */
            size_t sig_len = 0;
            int ret = dna_engine_sign_data(ctx->engine, sign_data, sizeof(sign_data),
                                           response.signature, &sig_len);
            if (ret != 0) {
                response.status = DNAC_NODUS_STATUS_ERROR;
                snprintf(response.error_message, sizeof(response.error_message),
                         "Signing failed");
                QGP_LOG_ERROR(LOG_TAG, "Failed to sign witness attestation");
            } else {
                /* Include our public key in response */
                dna_engine_get_signing_public_key(ctx->engine, response.server_pubkey,
                                                  DNAC_PUBKEY_SIZE);

                response.status = DNAC_NODUS_STATUS_APPROVED;
                QGP_LOG_INFO(LOG_TAG, "Approved %s request (listener)",
                             is_mint ? "MINT" : "SPEND");

                /* Queue nullifier for replication (skip for MINT) */
                if (!is_mint) {
                    witness_replicate_nullifier(request.nullifier, request.tx_hash);
                }
            }
        }
    }

    /* Queue response (can't call dht_put from callback due to mutex) */
    queue_response(&request, &response);

    /* Signal main thread that work was done */
    pthread_mutex_lock(ctx->mutex);
    (*ctx->pending_count)++;
    pthread_cond_signal(ctx->cond);
    pthread_mutex_unlock(ctx->mutex);

    return true;  /* Continue listening */
}

size_t witness_start_request_listener(dna_engine_t *engine,
                                      witness_request_ctx_t *ctx) {
    if (!engine || !ctx) return 0;

    dht_context_t *dht = (dht_context_t *)dna_engine_get_dht_context(engine);
    if (!dht) {
        QGP_LOG_ERROR(LOG_TAG, "DHT context not available");
        return 0;
    }

    const char *our_fp = dna_engine_get_fingerprint(engine);
    if (!our_fp) {
        QGP_LOG_ERROR(LOG_TAG, "No fingerprint available");
        return 0;
    }

    /* Build request listen key */
    uint8_t listen_key[64];
    if (build_request_poll_key(our_fp, listen_key) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to build request listen key");
        return 0;
    }

    /* Start listening */
    size_t token = dht_listen(dht, listen_key, 64,
                              request_listener_callback, ctx);
    if (token == 0) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to start request listener");
        return 0;
    }

    QGP_LOG_INFO(LOG_TAG, "Started request listener for %.32s...", our_fp);
    return token;
}

void witness_stop_request_listener(dna_engine_t *engine, size_t token) {
    if (!engine || token == 0) return;

    dht_context_t *dht = (dht_context_t *)dna_engine_get_dht_context(engine);
    if (!dht) return;

    dht_cancel_listen(dht, token);
    QGP_LOG_INFO(LOG_TAG, "Stopped request listener");
}

/* ============================================================================
 * Epoch Announcement Functions
 * ========================================================================== */

int witness_publish_announcement(dna_engine_t *engine) {
    if (!engine) return -1;

    dht_context_t *dht = (dht_context_t *)dna_engine_get_dht_context(engine);
    if (!dht) {
        QGP_LOG_ERROR(LOG_TAG, "DHT context not available");
        return -1;
    }

    const char *fingerprint = dna_engine_get_fingerprint(engine);
    if (!fingerprint) {
        QGP_LOG_ERROR(LOG_TAG, "No fingerprint available");
        return -1;
    }

    /* Build announcement */
    dnac_witness_announcement_t announcement;
    memset(&announcement, 0, sizeof(announcement));

    announcement.version = 2;  /* v2 includes software version */
    announcement.current_epoch = dnac_get_current_epoch();
    announcement.software_version[0] = DNAC_VERSION_MAJOR;
    announcement.software_version[1] = DNAC_VERSION_MINOR;
    announcement.software_version[2] = DNAC_VERSION_PATCH;
    announcement.epoch_duration = DNAC_EPOCH_DURATION_SEC;
    announcement.timestamp = (uint64_t)time(NULL);

    /* Fill witness_id from fingerprint (first 32 bytes of hex fingerprint) */
    for (int i = 0; i < 32 && fingerprint[i*2]; i++) {
        sscanf(&fingerprint[i*2], "%2hhx", &announcement.witness_id[i]);
    }

    /* Get public key */
    int ret = dna_engine_get_signing_public_key(engine, announcement.witness_pubkey,
                                                 DNAC_PUBKEY_SIZE);
    if (ret < 0) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to get signing public key");
        return -1;
    }

    /* Sign announcement (all fields except signature) */
    size_t sign_len = sizeof(announcement) - DNAC_SIGNATURE_SIZE;
    size_t sig_out_len = 0;
    ret = dna_engine_sign_data(engine, (uint8_t*)&announcement, sign_len,
                               announcement.signature, &sig_out_len);
    if (ret != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to sign announcement");
        return -1;
    }

    /* Serialize announcement */
    uint8_t buffer[8192];
    size_t written = 0;
    ret = witness_announcement_serialize(&announcement, buffer, sizeof(buffer), &written);
    if (ret != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to serialize announcement");
        return -1;
    }

    /* Build announcement key */
    uint8_t announce_key[64];
    if (build_announcement_key(fingerprint, announce_key) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to build announcement key");
        return -1;
    }

    /* PUT to DHT (permanent) */
    ret = dht_put_signed_permanent(dht, announce_key, 64, buffer, written,
                                   announcement.current_epoch,  /* value_id = epoch */
                                   "witness_announcement");
    if (ret != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to publish announcement to DHT");
        return -1;
    }

    QGP_LOG_INFO(LOG_TAG, "Published epoch %lu announcement for %.32s...",
                 (unsigned long)announcement.current_epoch, fingerprint);
    return 0;
}

/* ============================================================================
 * Epoch-Based Request Listener
 * ========================================================================== */

/**
 * DHT listener callback for epoch-based requests
 */
static bool epoch_request_listener_callback(const uint8_t *value, size_t value_len,
                                            bool expired, void *user_data) {
    witness_request_ctx_t *ctx = (witness_request_ctx_t *)user_data;
    if (!ctx || expired || !value || value_len == 0) return true;

    /* Deserialize request */
    dnac_spend_request_t request;
    if (dnac_spend_request_deserialize(value, value_len, &request) != 0) {
        QGP_LOG_WARN(LOG_TAG, "Failed to deserialize incoming epoch request");
        return true;  /* Continue listening */
    }

    QGP_LOG_DEBUG(LOG_TAG, "Received witness request via epoch listener");

    /* Process the request */
    dnac_spend_response_t response;
    memset(&response, 0, sizeof(response));
        response.software_version[0] = DNAC_VERSION_MAJOR;
        response.software_version[1] = DNAC_VERSION_MINOR;
        response.software_version[2] = DNAC_VERSION_PATCH;

    /* Get our identity info */
    const char *our_fp = dna_engine_get_fingerprint(ctx->engine);
    if (!our_fp) {
        return true;  /* Continue listening */
    }

    /* Convert fingerprint to witness_id bytes */
    for (int i = 0; i < 32 && our_fp[i*2]; i++) {
        sscanf(&our_fp[i*2], "%2hhx", &response.witness_id[i]);
    }

    /* Check for MINT request (zero nullifier) */
    bool is_mint = is_mint_request(request.nullifier);

    /* For SPEND: check if nullifier already spent */
    if (!is_mint && witness_nullifier_exists(request.nullifier)) {
        response.status = DNAC_NODUS_STATUS_REJECTED;
        snprintf(response.error_message, sizeof(response.error_message),
                 "Nullifier already spent");
        QGP_LOG_WARN(LOG_TAG, "Rejected: nullifier already spent");
    } else {
        /* For SPEND: Record nullifier. For MINT: skip (no nullifier to record) */
        if (!is_mint && witness_nullifier_add(request.nullifier, request.tx_hash) != 0) {
            response.status = DNAC_NODUS_STATUS_ERROR;
            snprintf(response.error_message, sizeof(response.error_message),
                     "Database error");
            QGP_LOG_ERROR(LOG_TAG, "Failed to record nullifier");
        } else {
            /* Build data to sign: tx_hash || witness_id || timestamp */
            response.timestamp = (uint64_t)time(NULL);

            uint8_t sign_data[64 + 32 + 8];
            memcpy(sign_data, request.tx_hash, 64);
            memcpy(sign_data + 64, response.witness_id, 32);

            /* Little-endian timestamp */
            for (int i = 0; i < 8; i++) {
                sign_data[64 + 32 + i] = (response.timestamp >> (i * 8)) & 0xFF;
            }

            /* Sign with our Dilithium5 key */
            size_t sig_len = 0;
            int ret = dna_engine_sign_data(ctx->engine, sign_data, sizeof(sign_data),
                                           response.signature, &sig_len);
            if (ret != 0) {
                response.status = DNAC_NODUS_STATUS_ERROR;
                snprintf(response.error_message, sizeof(response.error_message),
                         "Signing failed");
                QGP_LOG_ERROR(LOG_TAG, "Failed to sign witness attestation");
            } else {
                /* Include our public key in response */
                dna_engine_get_signing_public_key(ctx->engine, response.server_pubkey,
                                                  DNAC_PUBKEY_SIZE);

                response.status = DNAC_NODUS_STATUS_APPROVED;
                QGP_LOG_INFO(LOG_TAG, "Approved %s request (epoch-based)",
                             is_mint ? "MINT" : "SPEND");

                /* Queue nullifier for replication (skip for MINT) */
                if (!is_mint) {
                    witness_replicate_nullifier(request.nullifier, request.tx_hash);
                }
            }
        }
    }

    /* Queue response (can't call dht_put from callback due to mutex) */
    queue_response(&request, &response);

    /* Signal main thread that work was done */
    pthread_mutex_lock(ctx->mutex);
    (*ctx->pending_count)++;
    pthread_cond_signal(ctx->cond);
    pthread_mutex_unlock(ctx->mutex);

    return true;  /* Continue listening */
}

size_t witness_start_epoch_request_listener(dna_engine_t *engine,
                                            witness_request_ctx_t *ctx,
                                            uint64_t current_epoch) {
    if (!engine || !ctx) return 0;

    dht_context_t *dht = (dht_context_t *)dna_engine_get_dht_context(engine);
    if (!dht) {
        QGP_LOG_ERROR(LOG_TAG, "DHT context not available");
        return 0;
    }

    const char *our_fp = dna_engine_get_fingerprint(engine);
    if (!our_fp) {
        QGP_LOG_ERROR(LOG_TAG, "No fingerprint available");
        return 0;
    }

    /* Build epoch request key for current epoch */
    uint8_t listen_key[64];
    if (build_epoch_request_key(our_fp, current_epoch, listen_key) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to build epoch request key");
        return 0;
    }

    /* Start listening */
    size_t token = dht_listen(dht, listen_key, 64,
                              epoch_request_listener_callback, ctx);
    if (token == 0) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to start epoch request listener");
        return 0;
    }

    QGP_LOG_INFO(LOG_TAG, "Started epoch %lu request listener for %.32s...",
                 (unsigned long)current_epoch, our_fp);
    return token;
}

void witness_stop_epoch_request_listener(dna_engine_t *engine, size_t token) {
    if (!engine || token == 0) return;

    dht_context_t *dht = (dht_context_t *)dna_engine_get_dht_context(engine);
    if (!dht) return;

    dht_cancel_listen(dht, token);
    QGP_LOG_INFO(LOG_TAG, "Stopped epoch request listener");
}
