/**
 * Transport Implementation
 *
 * Modular Architecture:
 * - internal/transport_core.h      Shared type definitions
 * - internal/transport_helpers.c   Helper functions (JSON, SHA3)
 * - internal/transport_discovery.c DHT presence registration
 * - internal/transport_offline.c   Spillway offline queue (sender outboxes)
 *
 * This file provides high-level initialization, lifecycle management.
 */

#include "transport.h"
#include "internal/transport_core.h"
#include "crypto/utils/qgp_log.h"
#include "crypto/utils/qgp_platform.h"

#define LOG_TAG "TRANSPORT"

// ============================================================================
// Core Lifecycle Management
// ============================================================================

transport_t* transport_init(
    const transport_config_t *config,
    const uint8_t *my_privkey_dilithium,
    const uint8_t *my_pubkey_dilithium,
    const uint8_t *my_kyber_key,
    transport_message_callback_t message_callback,
    void *callback_user_data)
{
    if (!config || !my_privkey_dilithium || !my_pubkey_dilithium || !my_kyber_key) {
        return NULL;
    }

    transport_t *ctx = (transport_t*)calloc(1, sizeof(transport_t));
    if (!ctx) {
        return NULL;
    }

    // Copy configuration
    memcpy(&ctx->config, config, sizeof(transport_config_t));

    // Copy keys (NIST Category 5 key sizes)
    memcpy(ctx->my_private_key, my_privkey_dilithium, 4896);  // Dilithium5 (ML-DSA-87) private key
    memcpy(ctx->my_public_key, my_pubkey_dilithium, 2592);    // Dilithium5 (ML-DSA-87) public key
    memcpy(ctx->my_kyber_key, my_kyber_key, 3168);            // Kyber1024 (ML-KEM-1024) private key

    // Compute my fingerprint (SHA3-512 hex)
    uint8_t my_dht_key[64];  // SHA3-512 = 64 bytes
    sha3_512_hash(my_pubkey_dilithium, 2592, my_dht_key);
    for (int i = 0; i < 64; i++) {
        snprintf(ctx->my_fingerprint + (i * 2), 3, "%02x", my_dht_key[i]);
    }
    ctx->my_fingerprint[128] = '\0';

    QGP_LOG_INFO(LOG_TAG, "My fingerprint: %.32s...\n", ctx->my_fingerprint);

    // Callbacks
    ctx->message_callback = message_callback;
    ctx->callback_user_data = callback_user_data;

    // Initialize mutex
    pthread_mutex_init(&ctx->callback_mutex, NULL);

    // Verify DHT singleton is available (required for presence and messaging)
    if (!dht_singleton_is_initialized()) {
        QGP_LOG_ERROR(LOG_TAG, "Global DHT not initialized! Call dht_singleton_init() at app startup.\n");
        free(ctx);
        return NULL;
    }

    QGP_LOG_INFO(LOG_TAG, "DHT singleton available for transport\n");

    ctx->running = false;

    QGP_LOG_INFO(LOG_TAG, "Transport initialized (using global DHT)\n");

    return ctx;
}

int transport_start(transport_t *ctx) {
    if (!ctx || ctx->running) {
        return -1;
    }

    // DHT is already running (global singleton)
    QGP_LOG_INFO(LOG_TAG, "Using global DHT (already running)\n");

    ctx->running = true;

    QGP_LOG_INFO(LOG_TAG, "Transport started (DHT-only mode)\n");
    return 0;
}

void transport_stop(transport_t *ctx) {
    if (!ctx || !ctx->running) {
        return;
    }

    QGP_LOG_INFO(LOG_TAG, "Stopping transport...\n");
    ctx->running = false;

    // Don't stop DHT - it's a global singleton managed at app level

    QGP_LOG_INFO(LOG_TAG, "Transport stopped\n");
}

void transport_free(transport_t *ctx) {
    if (!ctx) {
        return;
    }

    transport_stop(ctx);

    // Destroy mutex
    pthread_mutex_destroy(&ctx->callback_mutex);

    // Clear sensitive keys
    qgp_secure_memzero(ctx->my_private_key, sizeof(ctx->my_private_key));
    qgp_secure_memzero(ctx->my_kyber_key, sizeof(ctx->my_kyber_key));

    free(ctx);
}

int transport_deliver_message(
    transport_t *ctx,
    const uint8_t *peer_pubkey,
    const uint8_t *data,
    size_t len)
{
    if (!ctx || !data || len == 0) {
        return -1;
    }

    // Thread-safe callback invocation
    pthread_mutex_lock(&ctx->callback_mutex);
    if (ctx->message_callback) {
        ctx->message_callback(peer_pubkey, NULL, data, len, ctx->callback_user_data);
        pthread_mutex_unlock(&ctx->callback_mutex);
        return 0;
    }
    pthread_mutex_unlock(&ctx->callback_mutex);

    return -1;  // No callback registered
}
