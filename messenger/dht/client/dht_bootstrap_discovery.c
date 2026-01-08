/**
 * DHT Bootstrap Discovery Implementation
 * Client-side discovery of bootstrap nodes from DHT registry
 */

#include "dht_bootstrap_discovery.h"
#include "../core/dht_bootstrap_registry.h"
#include "bootstrap_cache.h"
#include "crypto/utils/qgp_log.h"
#include "crypto/utils/qgp_platform.h"
#include <pthread.h>
#include <stdatomic.h>
#include <string.h>
#include <stdlib.h>

#define LOG_TAG "DHT_DISCOVERY"

// Background discovery thread state
static pthread_t g_discovery_thread;
static atomic_bool g_discovery_running = false;
static dht_context_t *g_discovery_dht_ctx = NULL;

// Callback for discovery completion
static dht_discovery_callback_t g_discovery_callback = NULL;
static void *g_discovery_user_data = NULL;

/**
 * Background discovery thread function
 */
static void* discovery_thread_func(void *arg) {
    (void)arg;

    QGP_LOG_INFO(LOG_TAG, "Bootstrap discovery thread started");

    // Wait for DHT to stabilize (1 second)
    qgp_platform_sleep_ms(1000);

    if (!atomic_load(&g_discovery_running)) {
        QGP_LOG_INFO(LOG_TAG, "Discovery thread: shutdown requested before start");
        return NULL;
    }

    // Run discovery
    int result = dht_bootstrap_discovery_run_sync(g_discovery_dht_ctx);

    // Fire callback if set
    if (g_discovery_callback) {
        g_discovery_callback(result, g_discovery_user_data);
    }

    atomic_store(&g_discovery_running, false);
    QGP_LOG_INFO(LOG_TAG, "Bootstrap discovery thread finished");
    return NULL;
}

int dht_bootstrap_from_cache(dht_config_t *dht_config, size_t max_nodes) {
    if (!dht_config || max_nodes == 0) {
        return 0;
    }

    bootstrap_cache_entry_t *best_nodes = NULL;
    size_t count = 0;

    // Get best nodes from cache (sorted by reliability)
    if (bootstrap_cache_get_best(max_nodes, &best_nodes, &count) != 0) {
        QGP_LOG_WARN(LOG_TAG, "Failed to get cached bootstrap nodes");
        return 0;
    }

    if (count == 0 || !best_nodes) {
        QGP_LOG_DEBUG(LOG_TAG, "No cached bootstrap nodes available");
        return 0;
    }

    // Skip nodes with >50% failure rate (and at least 4 attempts)
    size_t added = 0;
    for (size_t i = 0; i < count && added < max_nodes; i++) {
        // Skip unreliable nodes (>50% failure rate with sufficient samples)
        if (best_nodes[i].connection_attempts >= 4) {
            float fail_rate = (float)best_nodes[i].connection_failures /
                              (float)best_nodes[i].connection_attempts;
            if (fail_rate > 0.5f) {
                QGP_LOG_DEBUG(LOG_TAG, "Skipping unreliable node: %s:%d (%d/%d = %.0f%% failures)",
                             best_nodes[i].ip, best_nodes[i].port,
                             best_nodes[i].connection_failures,
                             best_nodes[i].connection_attempts,
                             fail_rate * 100);
                continue;
            }
        }

        // Format as "ip:port"
        snprintf(dht_config->bootstrap_nodes[added],
                sizeof(dht_config->bootstrap_nodes[added]),
                "%s:%d", best_nodes[i].ip, best_nodes[i].port);

        QGP_LOG_INFO(LOG_TAG, "Using cached bootstrap node: %s (%d/%d attempts ok)",
                    dht_config->bootstrap_nodes[added],
                    best_nodes[i].connection_attempts - best_nodes[i].connection_failures,
                    best_nodes[i].connection_attempts);
        added++;
    }

    bootstrap_cache_free_entries(best_nodes);

    dht_config->bootstrap_count = (int)added;
    return (int)added;
}

int dht_bootstrap_discovery_start(dht_context_t *dht_ctx) {
    if (!dht_ctx) {
        QGP_LOG_ERROR(LOG_TAG, "NULL DHT context");
        return -1;
    }

    if (atomic_load(&g_discovery_running)) {
        QGP_LOG_DEBUG(LOG_TAG, "Discovery already running");
        return 0;
    }

    g_discovery_dht_ctx = dht_ctx;
    atomic_store(&g_discovery_running, true);

    int rc = pthread_create(&g_discovery_thread, NULL, discovery_thread_func, NULL);
    if (rc != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to start discovery thread: %d", rc);
        atomic_store(&g_discovery_running, false);
        return -1;
    }

    // Detach thread - we don't need to join it
    pthread_detach(g_discovery_thread);

    QGP_LOG_INFO(LOG_TAG, "Background discovery started");
    return 0;
}

void dht_bootstrap_discovery_stop(void) {
    if (atomic_load(&g_discovery_running)) {
        QGP_LOG_INFO(LOG_TAG, "Stopping discovery thread...");
        atomic_store(&g_discovery_running, false);
        // Thread will exit on next check
    }
}

bool dht_bootstrap_discovery_is_running(void) {
    return atomic_load(&g_discovery_running);
}

void dht_bootstrap_discovery_set_callback(dht_discovery_callback_t callback, void *user_data) {
    g_discovery_callback = callback;
    g_discovery_user_data = user_data;
}

int dht_bootstrap_discovery_run_sync(dht_context_t *dht_ctx) {
    if (!dht_ctx) {
        QGP_LOG_ERROR(LOG_TAG, "NULL DHT context for discovery");
        return -1;
    }

    QGP_LOG_INFO(LOG_TAG, "Starting bootstrap registry discovery...");

    // Fetch registry from DHT
    bootstrap_registry_t registry;
    memset(&registry, 0, sizeof(registry));

    if (dht_bootstrap_registry_fetch(dht_ctx, &registry) != 0) {
        QGP_LOG_WARN(LOG_TAG, "Failed to fetch bootstrap registry from DHT");
        return -1;
    }

    QGP_LOG_INFO(LOG_TAG, "Fetched %zu nodes from DHT registry", registry.node_count);

    // Filter stale nodes (> 15 minutes)
    dht_bootstrap_registry_filter_active(&registry);
    QGP_LOG_INFO(LOG_TAG, "After filtering: %zu active nodes", registry.node_count);

    if (registry.node_count == 0) {
        QGP_LOG_INFO(LOG_TAG, "No active bootstrap nodes found in registry");
        return 0;
    }

    int connected = 0;
    int saved = 0;

    for (size_t i = 0; i < registry.node_count; i++) {
        // Check if shutdown requested (for background thread)
        if (!atomic_load(&g_discovery_running) && g_discovery_running) {
            QGP_LOG_INFO(LOG_TAG, "Discovery interrupted by shutdown");
            break;
        }

        bootstrap_node_entry_t *node = &registry.nodes[i];

        // Save to SQLite cache
        if (bootstrap_cache_put(node->ip, node->port, node->node_id,
                               node->version, node->last_seen) == 0) {
            saved++;
        }

        // Try to connect to node at runtime
        int rc = dht_context_bootstrap_runtime(dht_ctx, node->ip, node->port);
        if (rc == 0) {
            bootstrap_cache_mark_connected(node->ip, node->port);
            connected++;
            QGP_LOG_INFO(LOG_TAG, "Connected to: %s:%d (%s)",
                        node->ip, node->port, node->version);
        } else {
            bootstrap_cache_mark_failed(node->ip, node->port);
            QGP_LOG_DEBUG(LOG_TAG, "Failed to connect to: %s:%d",
                         node->ip, node->port);
        }
    }

    QGP_LOG_INFO(LOG_TAG, "Discovery complete: %d saved, %d connected", saved, connected);
    return connected;
}
