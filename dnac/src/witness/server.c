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
#include "config.h"

#include <string.h>
#include <time.h>
#include <openssl/evp.h>

#include "crypto/utils/qgp_dilithium.h"
#include "crypto/utils/qgp_log.h"

#define LOG_TAG "WITNESS_SRV"

/* Forward declare DHT context type */
typedef struct dht_context dht_context_t;

/* DHT functions from libdna */
extern void* dna_engine_get_dht_context(dna_engine_t *engine);
extern int dht_put_signed(dht_context_t *ctx,
                          const uint8_t *key, size_t key_len,
                          const uint8_t *value, size_t value_len,
                          uint64_t value_id,
                          unsigned int ttl_seconds,
                          const char *caller);
extern int dht_get(dht_context_t *ctx,
                   const uint8_t *key, size_t key_len,
                   uint8_t **value_out, size_t *value_len_out);

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

    /* Publish pubkey to DHT */
    ret = dht_put_signed(dht, identity_key, 64, pubkey, DNAC_PUBKEY_SIZE,
                         1, WITNESS_IDENTITY_TTL_SEC, "witness_identity");
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

        /* Get our identity info */
        const char *our_fp = dna_engine_get_fingerprint(engine);
        if (!our_fp) continue;

        /* Convert fingerprint to witness_id bytes (first 32 bytes of fingerprint hex) */
        for (int i = 0; i < 32 && our_fp[i*2]; i++) {
            sscanf(&our_fp[i*2], "%2hhx", &response.witness_id[i]);
        }

        /* Check if nullifier already spent */
        if (witness_nullifier_exists(request.nullifier)) {
            response.status = DNAC_NODUS_STATUS_REJECTED;
            snprintf(response.error_message, sizeof(response.error_message),
                     "Nullifier already spent");
            QGP_LOG_WARN(LOG_TAG, "Rejected: nullifier already spent");
        } else {
            /* Record nullifier */
            if (witness_nullifier_add(request.nullifier, request.tx_hash) != 0) {
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
                    QGP_LOG_INFO(LOG_TAG, "Approved witness request");

                    /* Queue nullifier for replication */
                    witness_replicate_nullifier(request.nullifier, request.tx_hash);
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
    if (!engine || !request || !response) return -1;

    dht_context_t *dht = (dht_context_t *)dna_engine_get_dht_context(engine);
    if (!dht) return -1;

    /* Get requester fingerprint from pubkey (would need to derive or have in request) */
    /* For now, use a simplified approach - derive from sender_pubkey hash */
    uint8_t fp_hash[64];
    compute_sha3_512(request->sender_pubkey, DNAC_PUBKEY_SIZE, fp_hash);

    char requester_fp[129];
    for (int i = 0; i < 64; i++) {
        sprintf(&requester_fp[i*2], "%02x", fp_hash[i]);
    }
    requester_fp[128] = '\0';

    /* Build response key */
    uint8_t response_key[64];
    if (build_response_key(request->tx_hash, requester_fp, response_key) != 0) {
        return -1;
    }

    /* Serialize response */
    uint8_t buffer[16384];
    size_t written = 0;
    int rc = dnac_spend_response_serialize(response, buffer, sizeof(buffer), &written);
    if (rc != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to serialize response");
        return -1;
    }

    /* PUT to DHT */
    rc = dht_put_signed(dht, response_key, 64, buffer, written,
                        response->timestamp % 10000,
                        WITNESS_RESPONSE_TTL_SEC,
                        "witness_response");
    if (rc != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to PUT response to DHT");
        return -1;
    }

    return 0;
}
