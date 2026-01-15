#ifndef __ANDROID__
#define _GNU_SOURCE  // Required for pthread_timedjoin_np (Linux only)
#endif

/**
 * P2P Transport Implementation (FACADE)
 *
 * Modular Architecture:
 * - transport/transport_core.h      Shared type definitions
 * - transport/transport_helpers.c   Helper functions (IP detection, JSON, SHA3)
 * - transport/transport_tcp.c       TCP listener and connections
 * - transport/transport_discovery.c DHT peer discovery and direct messaging
 * - transport/transport_offline.c   Spillway offline queue (sender outboxes)
 *
 * This file provides high-level initialization, lifecycle management, and statistics.
 * All implementation details delegated to focused modules.
 */

#include "p2p_transport.h"
#include "transport/transport_core.h"
#include "crypto/utils/qgp_log.h"
#include "crypto/utils/qgp_platform.h"

#define LOG_TAG "P2P"

// ============================================================================
// Core Lifecycle Management
// ============================================================================

p2p_transport_t* p2p_transport_init(
    const p2p_config_t *config,
    const uint8_t *my_privkey_dilithium,
    const uint8_t *my_pubkey_dilithium,
    const uint8_t *my_kyber_key,
    p2p_message_callback_t message_callback,
    p2p_connection_callback_t connection_callback,
    void *callback_user_data)
{
    if (!config || !my_privkey_dilithium || !my_pubkey_dilithium || !my_kyber_key) {
        return NULL;
    }

    p2p_transport_t *ctx = (p2p_transport_t*)calloc(1, sizeof(p2p_transport_t));
    if (!ctx) {
        return NULL;
    }

    // Copy configuration
    memcpy(&ctx->config, config, sizeof(p2p_config_t));

    // Copy keys (NIST Category 5 key sizes)
    memcpy(ctx->my_private_key, my_privkey_dilithium, 4896);  // Dilithium5 (ML-DSA-87) private key
    memcpy(ctx->my_public_key, my_pubkey_dilithium, 2592);    // Dilithium5 (ML-DSA-87) public key
    memcpy(ctx->my_kyber_key, my_kyber_key, 3168);            // Kyber1024 (ML-KEM-1024) private key

    // Compute my fingerprint (SHA3-512 hex) for ICE DHT keys
    uint8_t my_dht_key[64];  // SHA3-512 = 64 bytes
    sha3_512_hash(my_pubkey_dilithium, 2592, my_dht_key);
    for (int i = 0; i < 64; i++) {
        snprintf(ctx->my_fingerprint + (i * 2), 3, "%02x", my_dht_key[i]);
    }
    ctx->my_fingerprint[128] = '\0';

    QGP_LOG_INFO(LOG_TAG, "My fingerprint: %.32s...\n", ctx->my_fingerprint);

    // Callbacks
    ctx->message_callback = message_callback;
    ctx->connection_callback = connection_callback;
    ctx->callback_user_data = callback_user_data;

    // Initialize mutexes
    pthread_mutex_init(&ctx->connections_mutex, NULL);
    pthread_mutex_init(&ctx->callback_mutex, NULL);

    // Verify DHT singleton is available (required for presence and messaging)
    // DHT is accessed via dht_singleton_get() - not stored in p2p_transport
    if (!dht_singleton_is_initialized()) {
        QGP_LOG_ERROR(LOG_TAG, "Global DHT not initialized! Call dht_singleton_init() at app startup.\n");
        free(ctx);
        return NULL;
    }

    QGP_LOG_INFO(LOG_TAG, "DHT singleton available for P2P transport\n");

    ctx->listen_sockfd = -1;
    ctx->running = false;

    QGP_LOG_INFO(LOG_TAG, "Transport initialized (TCP port: %d, using global DHT)\n",
           config->listen_port);

    return ctx;
}

int p2p_transport_start(p2p_transport_t *ctx) {
    if (!ctx || ctx->running) {
        return -1;
    }

    // DHT is already running (global singleton)
    // No need to start it here
    QGP_LOG_INFO(LOG_TAG, "Using global DHT (already running)\n");

    // Create TCP listening socket
    if (tcp_create_listener(ctx) != 0) {
        return -1;
    }

    // Start listener thread
    if (tcp_start_listener_thread(ctx) != 0) {
        close(ctx->listen_sockfd);
        return -1;
    }

    // ICE/STUN/TURN removed in v0.4.61 for privacy
    // No external IP addresses are discovered or published
    // All messaging uses DHT-only path
    QGP_LOG_INFO(LOG_TAG, "✓ P2P transport started (DHT-only mode, privacy-preserving)\n");
    return 0;
}

void p2p_transport_stop(p2p_transport_t *ctx) {
    if (!ctx || !ctx->running) {
        return;
    }

    QGP_LOG_INFO(LOG_TAG, "Stopping transport...\n");
    ctx->running = false;

    // Close all peer connections (TCP only)
    pthread_mutex_lock(&ctx->connections_mutex);
    for (size_t i = 0; i < 256; i++) {
        if (ctx->connections[i]) {
            p2p_connection_t *conn = ctx->connections[i];
            conn->active = false;

            if (conn->sockfd >= 0) {
                close(conn->sockfd);
            }

            // Wait for receive thread to finish (with timeout on Linux)
            if (conn->recv_thread) {
#if defined(__ANDROID__) || defined(_WIN32)
                // Android/Windows: pthread_timedjoin_np not available, use regular join
                pthread_join(conn->recv_thread, NULL);
#else
                struct timespec timeout;
                clock_gettime(CLOCK_REALTIME, &timeout);
                timeout.tv_sec += 1;  // 1 second timeout
                pthread_timedjoin_np(conn->recv_thread, NULL, &timeout);
#endif
            }

            free(conn);
            ctx->connections[i] = NULL;
        }
    }
    ctx->connection_count = 0;
    pthread_mutex_unlock(&ctx->connections_mutex);

    // Stop TCP listener
    tcp_stop_listener(ctx);

    // Don't stop DHT - it's a global singleton managed at app level

    QGP_LOG_INFO(LOG_TAG, "Transport stopped\n");
}

void p2p_transport_free(p2p_transport_t *ctx) {
    if (!ctx) {
        return;
    }

    p2p_transport_stop(ctx);

    // DHT is a global singleton - not stored in p2p_transport, nothing to clean up

    // Destroy mutexes
    pthread_mutex_destroy(&ctx->connections_mutex);
    pthread_mutex_destroy(&ctx->callback_mutex);

    // Clear sensitive keys
    qgp_secure_memzero(ctx->my_private_key, sizeof(ctx->my_private_key));
    qgp_secure_memzero(ctx->my_kyber_key, sizeof(ctx->my_kyber_key));

    free(ctx);
}

// NOTE: p2p_transport_get_dht_context() removed in Phase 14 refactoring (v0.3.122)
// Use dht_singleton_get() directly instead

int p2p_transport_deliver_message(
    p2p_transport_t *ctx,
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

// ============================================================================
// Connection Management
// ============================================================================

int p2p_get_connected_peers(
    p2p_transport_t *ctx,
    uint8_t (*pubkeys)[2592],  // Dilithium5 public keys
    size_t max_peers,
    size_t *count)
{
    if (!ctx || !pubkeys || !count) {
        return -1;
    }

    pthread_mutex_lock(&ctx->connections_mutex);
    *count = ctx->connection_count < max_peers ? ctx->connection_count : max_peers;

    size_t idx = 0;
    for (size_t i = 0; i < 256 && idx < *count; i++) {
        if (ctx->connections[i] && ctx->connections[i]->active) {
            memcpy(pubkeys[idx], ctx->connections[i]->peer_pubkey, 2592);  // Dilithium5 public key size
            idx++;
        }
    }
    pthread_mutex_unlock(&ctx->connections_mutex);

    return 0;
}

int p2p_disconnect_peer(
    p2p_transport_t *ctx,
    const uint8_t *peer_pubkey)
{
    if (!ctx || !peer_pubkey) {
        return -1;
    }

    pthread_mutex_lock(&ctx->connections_mutex);
    for (size_t i = 0; i < 256; i++) {
        if (ctx->connections[i] &&
            memcmp(ctx->connections[i]->peer_pubkey, peer_pubkey, 2592) == 0) {  // Dilithium5 public key size
            ctx->connections[i]->active = false;
            close(ctx->connections[i]->sockfd);
            pthread_join(ctx->connections[i]->recv_thread, NULL);
            free(ctx->connections[i]);
            ctx->connections[i] = NULL;
            ctx->connection_count--;
            pthread_mutex_unlock(&ctx->connections_mutex);
            return 0;
        }
    }
    pthread_mutex_unlock(&ctx->connections_mutex);

    return -1; // Not found
}

// ============================================================================
// Statistics
// ============================================================================

int p2p_get_stats(
    p2p_transport_t *ctx,
    size_t *connections_active,
    size_t *messages_sent,
    size_t *messages_received,
    size_t *offline_queued)
{
    if (!ctx) {
        return -1;
    }

    if (connections_active) {
        pthread_mutex_lock(&ctx->connections_mutex);
        *connections_active = ctx->connection_count;
        pthread_mutex_unlock(&ctx->connections_mutex);
    }

    if (messages_sent) *messages_sent = ctx->messages_sent;
    if (messages_received) *messages_received = ctx->messages_received;
    if (offline_queued) *offline_queued = ctx->offline_queued;

    return 0;
}
