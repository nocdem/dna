/**
 * @file replication.c
 * @brief Nullifier replication to peer witness servers
 *
 * Replicates nullifiers via DHT to ensure all witness servers
 * have consistent state for double-spend prevention.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */

#include "dnac/witness.h"
#include "config.h"

#include <string.h>
#include <stdlib.h>
#include <pthread.h>
#include <openssl/evp.h>

#include "crypto/utils/qgp_log.h"

#define LOG_TAG "WITNESS_REP"

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

/* Global engine reference for replication (set by main) */
static dna_engine_t *g_replication_engine = NULL;

void witness_set_replication_engine(dna_engine_t *engine) {
    g_replication_engine = engine;
}

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
 * Build DHT key for nullifier replication
 * Key: SHA3-512("dnac:witness:nullifier:" + peer_fingerprint + ":" + nullifier)
 */
static int build_replication_key(const char *peer_fingerprint,
                                  const uint8_t *nullifier,
                                  uint8_t *key_out) {
    uint8_t key_data[512];
    size_t offset = 0;

    memcpy(key_data + offset, WITNESS_NULLIFIER_PREFIX, strlen(WITNESS_NULLIFIER_PREFIX));
    offset += strlen(WITNESS_NULLIFIER_PREFIX);

    size_t fp_len = strlen(peer_fingerprint);
    memcpy(key_data + offset, peer_fingerprint, fp_len);
    offset += fp_len;

    key_data[offset++] = ':';

    memcpy(key_data + offset, nullifier, 64);
    offset += 64;

    return compute_sha3_512(key_data, offset, key_out);
}

int witness_replicate_nullifier(const uint8_t *nullifier, const uint8_t *tx_hash) {
    if (!nullifier || !tx_hash) return -1;

    if (!g_replication_engine) {
        QGP_LOG_WARN(LOG_TAG, "Replication engine not set, skipping replication");
        return 0; /* Not an error, just skip */
    }

    dht_context_t *dht = (dht_context_t *)dna_engine_get_dht_context(g_replication_engine);
    if (!dht) {
        QGP_LOG_ERROR(LOG_TAG, "DHT context not available");
        return -1;
    }

    /* Build replication payload: nullifier + tx_hash */
    uint8_t payload[128];
    memcpy(payload, nullifier, 64);
    memcpy(payload + 64, tx_hash, 64);

    int replicated = 0;

    /* Replicate to each peer */
    for (int i = 0; WITNESS_PEERS[i] != NULL; i++) {
        const char *peer_fp = WITNESS_PEERS[i];

        uint8_t rep_key[64];
        if (build_replication_key(peer_fp, nullifier, rep_key) != 0) {
            continue;
        }

        int rc = dht_put_signed(dht, rep_key, 64, payload, sizeof(payload),
                                1, 3600, /* 1 hour TTL */
                                "nullifier_rep");
        if (rc == 0) {
            replicated++;
        }
    }

    if (replicated > 0) {
        witness_nullifier_mark_replicated(nullifier);
        QGP_LOG_DEBUG(LOG_TAG, "Replicated nullifier to %d peers", replicated);
    }

    return replicated > 0 ? 0 : -1;
}

int witness_process_replications(dna_engine_t *engine) {
    if (!engine) return -1;

    dht_context_t *dht = (dht_context_t *)dna_engine_get_dht_context(engine);
    if (!dht) return -1;

    extern const char* dna_engine_get_fingerprint(dna_engine_t *engine);
    const char *our_fp = dna_engine_get_fingerprint(engine);
    if (!our_fp) return -1;

    int received = 0;

    /* Poll for replicated nullifiers addressed to us */
    /* Build base key for our replication inbox */
    uint8_t base_key_data[256];
    size_t offset = 0;

    memcpy(base_key_data, WITNESS_NULLIFIER_PREFIX, strlen(WITNESS_NULLIFIER_PREFIX));
    offset = strlen(WITNESS_NULLIFIER_PREFIX);
    memcpy(base_key_data + offset, our_fp, strlen(our_fp));
    offset += strlen(our_fp);

    uint8_t inbox_key[64];
    if (compute_sha3_512(base_key_data, offset, inbox_key) != 0) {
        return -1;
    }

    /* GET from DHT */
    uint8_t *data = NULL;
    size_t data_len = 0;

    int rc = dht_get(dht, inbox_key, 64, &data, &data_len);
    if (rc == 0 && data && data_len == 128) {
        /* Extract nullifier and tx_hash */
        uint8_t *nullifier = data;
        uint8_t *tx_hash = data + 64;

        /* Add to our database if not exists */
        if (!witness_nullifier_exists(nullifier)) {
            if (witness_nullifier_add(nullifier, tx_hash) == 0) {
                /* Mark as already replicated (we received it) */
                witness_nullifier_mark_replicated(nullifier);
                received++;
                QGP_LOG_DEBUG(LOG_TAG, "Received replicated nullifier from peer");
            }
        }

        free(data);
    }

    return received;
}

/* ============================================================================
 * Event-Driven Replication Listener
 * ========================================================================== */

/**
 * Build DHT key for our replication inbox
 * Key: SHA3-512("dnac:witness:nullifier:" + our_fingerprint)
 */
static int build_replication_inbox_key(const char *our_fingerprint, uint8_t *key_out) {
    uint8_t key_data[256];
    size_t offset = 0;

    memcpy(key_data, WITNESS_NULLIFIER_PREFIX, strlen(WITNESS_NULLIFIER_PREFIX));
    offset = strlen(WITNESS_NULLIFIER_PREFIX);
    memcpy(key_data + offset, our_fingerprint, strlen(our_fingerprint));
    offset += strlen(our_fingerprint);

    return compute_sha3_512(key_data, offset, key_out);
}

/**
 * DHT listener callback for incoming nullifier replications
 */
static bool replication_listener_callback(const uint8_t *value, size_t value_len,
                                          bool expired, void *user_data) {
    witness_replication_ctx_t *ctx = (witness_replication_ctx_t *)user_data;
    if (!ctx || expired || !value || value_len != 128) return true;

    /* Extract nullifier and tx_hash from payload */
    const uint8_t *nullifier = value;
    const uint8_t *tx_hash = value + 64;

    /* Add to our database if not exists */
    if (!witness_nullifier_exists(nullifier)) {
        if (witness_nullifier_add(nullifier, tx_hash) == 0) {
            /* Mark as already replicated (we received it) */
            witness_nullifier_mark_replicated(nullifier);
            QGP_LOG_DEBUG(LOG_TAG, "Received replicated nullifier via listener");

            /* Signal main thread that work was done */
            pthread_mutex_lock(ctx->mutex);
            (*ctx->pending_count)++;
            pthread_cond_signal(ctx->cond);
            pthread_mutex_unlock(ctx->mutex);
        }
    }

    return true;  /* Continue listening */
}

size_t witness_start_replication_listener(dna_engine_t *engine,
                                          witness_replication_ctx_t *ctx) {
    if (!engine || !ctx) return 0;

    dht_context_t *dht = (dht_context_t *)dna_engine_get_dht_context(engine);
    if (!dht) {
        QGP_LOG_ERROR(LOG_TAG, "DHT context not available");
        return 0;
    }

    extern const char* dna_engine_get_fingerprint(dna_engine_t *engine);
    const char *our_fp = dna_engine_get_fingerprint(engine);
    if (!our_fp) {
        QGP_LOG_ERROR(LOG_TAG, "No fingerprint available");
        return 0;
    }

    /* Build replication inbox key */
    uint8_t inbox_key[64];
    if (build_replication_inbox_key(our_fp, inbox_key) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to build replication inbox key");
        return 0;
    }

    /* Start listening */
    size_t token = dht_listen(dht, inbox_key, 64,
                              replication_listener_callback, ctx);
    if (token == 0) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to start replication listener");
        return 0;
    }

    QGP_LOG_INFO(LOG_TAG, "Started replication listener for %.32s...", our_fp);
    return token;
}

void witness_stop_replication_listener(dna_engine_t *engine, size_t token) {
    if (!engine || token == 0) return;

    dht_context_t *dht = (dht_context_t *)dna_engine_get_dht_context(engine);
    if (!dht) return;

    dht_cancel_listen(dht, token);
    QGP_LOG_INFO(LOG_TAG, "Stopped replication listener");
}
