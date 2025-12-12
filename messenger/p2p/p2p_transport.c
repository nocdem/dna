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

    // Copy keys
    memcpy(ctx->my_private_key, my_privkey_dilithium, 4016);
    memcpy(ctx->my_public_key, my_pubkey_dilithium, 2592);  // Dilithium5 public key size
    memcpy(ctx->my_kyber_key, my_kyber_key, 2400);

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

    // Initialize ICE state (Phase 11 FIX)
    ctx->ice_context = NULL;
    ctx->ice_ready = false;

    // Use global DHT singleton (initialized at app startup)
    // No need to create/start DHT here - it's already running
    ctx->dht = dht_singleton_get();
    if (!ctx->dht) {
        QGP_LOG_INFO(LOG_TAG, "ERROR: Global DHT not initialized! Call dht_singleton_init() at app startup.\n");
        free(ctx);
        return NULL;
    }

    QGP_LOG_INFO(LOG_TAG, "Using global DHT singleton for P2P transport\n");

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

    // Initialize ICE context for NAT traversal (libjuice)
    QGP_LOG_INFO(LOG_TAG, "Initializing ICE for NAT traversal (libjuice)...\n");

    pthread_mutex_init(&ctx->ice_mutex, NULL);
    pthread_mutex_lock(&ctx->ice_mutex);

    ctx->ice_context = ice_context_new();
    if (!ctx->ice_context) {
        QGP_LOG_ERROR(LOG_TAG, "WARNING: ICE initialization failed (NAT traversal unavailable)\n");
        QGP_LOG_ERROR(LOG_TAG, "Continuing with TCP-only mode...\n");
        pthread_mutex_unlock(&ctx->ice_mutex);
        return 0;  // Not fatal - continue with TCP-only mode
    }

    // Gather ICE candidates (try multiple STUN servers)
    int gathered = 0;
    const char *stun_servers[] = {"stun.l.google.com", "stun1.l.google.com", "stun.cloudflare.com"};
    const uint16_t stun_ports[] = {19302, 19302, 3478};

    for (size_t i = 0; i < 3 && !gathered; i++) {
        QGP_LOG_INFO(LOG_TAG, "Trying STUN server: %s:%d\n", stun_servers[i], stun_ports[i]);
        if (ice_gather_candidates(ctx->ice_context, stun_servers[i], stun_ports[i]) == 0) {
            gathered = 1;
            QGP_LOG_INFO(LOG_TAG, "✓ Successfully gathered ICE candidates via %s:%d\n", stun_servers[i], stun_ports[i]);
            break;
        }
    }

    if (!gathered) {
        QGP_LOG_ERROR(LOG_TAG, "WARNING: Failed to gather candidates from all STUN servers\n");
        ice_context_free(ctx->ice_context);
        ctx->ice_context = NULL;
        pthread_mutex_unlock(&ctx->ice_mutex);
        return 0;  // Not fatal - continue with TCP-only mode
    }

    // Publish ICE candidates to DHT
    if (ice_publish_to_dht(ctx->ice_context, ctx->my_fingerprint) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "WARNING: Failed to publish ICE candidates to DHT\n");
        ice_context_free(ctx->ice_context);
        ctx->ice_context = NULL;
        pthread_mutex_unlock(&ctx->ice_mutex);
        return 0;  // Not fatal - continue with TCP-only mode
    }

    QGP_LOG_INFO(LOG_TAG, "✓ Published ICE candidates to DHT (key: %s:ice_candidates)\n", ctx->my_fingerprint);
    ctx->ice_ready = true;
    pthread_mutex_unlock(&ctx->ice_mutex);

    QGP_LOG_INFO(LOG_TAG, "✓ ICE ready for NAT traversal\n");
    return 0;
}

void p2p_transport_stop(p2p_transport_t *ctx) {
    if (!ctx || !ctx->running) {
        return;
    }

    QGP_LOG_INFO(LOG_TAG, "Stopping transport...\n");
    ctx->running = false;

    // Close all peer connections (TCP and ICE)
    pthread_mutex_lock(&ctx->connections_mutex);
    for (size_t i = 0; i < 256; i++) {
        if (ctx->connections[i]) {
            p2p_connection_t *conn = ctx->connections[i];
            conn->active = false;

            if (conn->type == CONNECTION_TYPE_TCP) {
                if (conn->sockfd >= 0) {
                    close(conn->sockfd);
                }
            } else if (conn->type == CONNECTION_TYPE_ICE) {
                if (conn->ice_ctx) {
                    QGP_LOG_INFO(LOG_TAG, "Shutting down ICE connection to %.16s...\n", conn->peer_fingerprint);
                    ice_shutdown(conn->ice_ctx);
                    ice_context_free(conn->ice_ctx);
                    conn->ice_ctx = NULL;
                }
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

    // Shutdown persistent ICE context
    if (ctx->ice_ready) {
        QGP_LOG_INFO(LOG_TAG, "Shutting down persistent ICE...\n");
        pthread_mutex_lock(&ctx->ice_mutex);
        if (ctx->ice_context) {
            ice_shutdown(ctx->ice_context);
            ice_context_free(ctx->ice_context);
            ctx->ice_context = NULL;
        }
        ctx->ice_ready = false;
        pthread_mutex_unlock(&ctx->ice_mutex);
    }

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

    // Don't free DHT - it's a global singleton managed at app level
    ctx->dht = NULL;

    // Destroy mutexes
    pthread_mutex_destroy(&ctx->connections_mutex);
    pthread_mutex_destroy(&ctx->callback_mutex);

    // Clear sensitive keys
    memset(ctx->my_private_key, 0, sizeof(ctx->my_private_key));
    memset(ctx->my_kyber_key, 0, sizeof(ctx->my_kyber_key));

    free(ctx);
}

dht_context_t* p2p_transport_get_dht_context(p2p_transport_t *ctx) {
    if (!ctx) {
        return NULL;
    }
    return ctx->dht;
}

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
