/*
 * DNA Messenger - Global DHT Singleton Implementation
 */

#include "dht_singleton.h"
#include "../core/dht_context.h"
#include "../core/dht_bootstrap_registry.h"
#include "crypto/utils/qgp_log.h"
#include "dna_config.h"
#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/types.h>

#ifdef _WIN32
#include <windows.h>
#include <direct.h>
#define mkdir(path, mode) _mkdir(path)
#else
#include <unistd.h>
#endif

#define LOG_TAG "DHT"

// Global DHT context (singleton)
static dht_context_t *g_dht_context = NULL;

// Global config (loaded once)
static dna_config_t g_config = {0};
static bool g_config_loaded = false;

static void ensure_config(void) {
    if (!g_config_loaded) {
        dna_config_load(&g_config);
        g_config_loaded = true;
    }
}

int dht_singleton_init(void)
{
    if (g_dht_context != NULL) {
        QGP_LOG_WARN(LOG_TAG, "Already initialized");
        return 0;  // Already initialized, not an error
    }

    // Load config
    ensure_config();

    QGP_LOG_INFO(LOG_TAG, "Initializing global DHT context...");

    // Configure DHT
    dht_config_t dht_config = {0};
    dht_config.port = 0;  // Let OS assign random port (clients don't need fixed port)
    dht_config.is_bootstrap = false;
    strncpy(dht_config.identity, "dna-global", sizeof(dht_config.identity) - 1);

    // STEP 1: Bootstrap to first node from config for cold start
    if (g_config.bootstrap_count > 0) {
        QGP_LOG_INFO(LOG_TAG, "Using seed node for cold start: %s", g_config.bootstrap_nodes[0]);
        strncpy(dht_config.bootstrap_nodes[0], g_config.bootstrap_nodes[0],
                sizeof(dht_config.bootstrap_nodes[0]) - 1);
        dht_config.bootstrap_count = 1;
    } else {
        QGP_LOG_ERROR(LOG_TAG, "No bootstrap nodes configured");
        return -1;
    }

    // NO PERSISTENCE for client DHT (only bootstrap nodes need persistence)
    // Client DHT is temporary and should not republish stored values
    dht_config.persistence_path[0] = '\0';  // Empty = no persistence

    QGP_LOG_INFO(LOG_TAG, "Client DHT mode (no persistence)");

    // Create DHT context
    g_dht_context = dht_context_new(&dht_config);
    if (!g_dht_context) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to create DHT context");
        return -1;
    }

    // Start DHT and bootstrap
    if (dht_context_start(g_dht_context) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to start DHT context");
        dht_context_free(g_dht_context);
        g_dht_context = NULL;
        return -1;
    }

    QGP_LOG_INFO(LOG_TAG, "DHT started, bootstrapping to network...");

    // Wait for DHT to be ready with reduced polling frequency
    // Check every 250ms for up to 3 seconds maximum (reduces overhead)
    int max_attempts = 12;  // 12 * 250ms = 3s max
    int attempts = 0;

    while (!dht_context_is_ready(g_dht_context) && attempts < max_attempts) {
        #ifdef _WIN32
        Sleep(250);  // Windows: 250ms
        #else
        usleep(250000);  // Unix: 250ms
        #endif
        attempts++;
    }

    if (dht_context_is_ready(g_dht_context)) {
        QGP_LOG_INFO(LOG_TAG, "Global DHT ready! (took %dms)", attempts * 250);

        // STEP 2: Query bootstrap registry for dynamic node discovery
        QGP_LOG_INFO(LOG_TAG, "Querying bootstrap registry for active nodes...");
        bootstrap_registry_t registry;

        if (dht_bootstrap_registry_fetch(g_dht_context, &registry) == 0) {
            // Filter stale nodes (last_seen > 15 minutes)
            dht_bootstrap_registry_filter_active(&registry);

            if (registry.node_count > 0) {
                QGP_LOG_INFO(LOG_TAG, "Discovered %zu active bootstrap nodes from registry",
                       registry.node_count);

                // Bootstrap to discovered nodes for better connectivity
                for (size_t i = 0; i < registry.node_count && i < 10; i++) {
                    char node_addr[128];
                    snprintf(node_addr, sizeof(node_addr), "%s:%d",
                             registry.nodes[i].ip, registry.nodes[i].port);

                    QGP_LOG_DEBUG(LOG_TAG, "  -> %s (node_id: %.16s..., uptime: %lus)",
                           node_addr, registry.nodes[i].node_id,
                           (unsigned long)registry.nodes[i].uptime);

                    // Bootstrap to this node at runtime
                    if (dht_context_bootstrap_runtime(g_dht_context, registry.nodes[i].ip,
                                                      registry.nodes[i].port) == 0) {
                        QGP_LOG_DEBUG(LOG_TAG, "    Bootstrapped to %s", node_addr);
                    } else {
                        QGP_LOG_WARN(LOG_TAG, "    Failed to bootstrap to %s", node_addr);
                    }
                }

                QGP_LOG_INFO(LOG_TAG, "Using %zu dynamically discovered nodes",
                       registry.node_count < 10 ? registry.node_count : 10);
            } else {
                QGP_LOG_WARN(LOG_TAG, "Registry has no active nodes, using fallback nodes");
            }
        } else {
            QGP_LOG_WARN(LOG_TAG, "Failed to query registry, using fallback nodes");
        }

        // RACE CONDITION FIX: Wait for nodes to establish stable connections
        // Even though dht_context_is_ready() returns true (good_nodes > 0),
        // the DHT may not be ready to accept PUT operations yet.
        // Give it 1 second to fully stabilize all connections before allowing PUT operations.
        QGP_LOG_INFO(LOG_TAG, "Waiting for DHT connections to stabilize (1000ms)...");
        #ifdef _WIN32
        Sleep(1000);
        #else
        usleep(1000000);  // 1000ms = 1 second
        #endif
    } else {
        QGP_LOG_WARN(LOG_TAG, "DHT bootstrap timeout, continuing anyway...");
        // Don't return error - DHT may still work for some operations
    }

    return 0;
}

dht_context_t* dht_singleton_get(void)
{
    return g_dht_context;
}

bool dht_singleton_is_initialized(void)
{
    return (g_dht_context != NULL);
}

int dht_singleton_init_with_identity(dht_identity_t *user_identity)
{
    if (!user_identity) {
        QGP_LOG_ERROR(LOG_TAG, "NULL identity");
        return -1;
    }

    if (g_dht_context != NULL) {
        QGP_LOG_WARN(LOG_TAG, "Already initialized");
        return 0;  // Already initialized, not an error
    }

    // Load config
    ensure_config();

    QGP_LOG_INFO(LOG_TAG, "Initializing global DHT with user identity...");

    // Configure DHT
    dht_config_t dht_config = {0};
    dht_config.port = 0;  // Let OS assign random port (clients don't need fixed port)
    dht_config.is_bootstrap = false;
    strncpy(dht_config.identity, "dna-user", sizeof(dht_config.identity) - 1);

    // STEP 1: Bootstrap to first node from config for cold start
    if (g_config.bootstrap_count > 0) {
        QGP_LOG_INFO(LOG_TAG, "Using seed node for cold start: %s", g_config.bootstrap_nodes[0]);
        strncpy(dht_config.bootstrap_nodes[0], g_config.bootstrap_nodes[0],
                sizeof(dht_config.bootstrap_nodes[0]) - 1);
        dht_config.bootstrap_count = 1;
    } else {
        QGP_LOG_ERROR(LOG_TAG, "No bootstrap nodes configured");
        return -1;
    }

    // NO PERSISTENCE for client DHT
    dht_config.persistence_path[0] = '\0';

    QGP_LOG_INFO(LOG_TAG, "Client DHT mode (no persistence)");

    // Create DHT context
    g_dht_context = dht_context_new(&dht_config);
    if (!g_dht_context) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to create DHT context");
        return -1;
    }

    // Start DHT with user-provided identity
    if (dht_context_start_with_identity(g_dht_context, user_identity) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to start DHT with identity");
        dht_context_free(g_dht_context);
        g_dht_context = NULL;
        return -1;
    }

    QGP_LOG_INFO(LOG_TAG, "DHT started, bootstrapping to network...");

    // Wait for DHT to be ready with reduced polling frequency
    // Check every 250ms for up to 3 seconds maximum (reduces overhead)
    int max_attempts = 12;  // 12 * 250ms = 3s max
    int attempts = 0;

    while (!dht_context_is_ready(g_dht_context) && attempts < max_attempts) {
        #ifdef _WIN32
        Sleep(250);  // Windows: 250ms
        #else
        usleep(250000);  // Unix: 250ms
        #endif
        attempts++;
    }

    if (dht_context_is_ready(g_dht_context)) {
        QGP_LOG_INFO(LOG_TAG, "Global DHT ready with user identity! (took %dms)", attempts * 250);

        // STEP 2: Query bootstrap registry for dynamic node discovery
        QGP_LOG_INFO(LOG_TAG, "Querying bootstrap registry for active nodes...");
        bootstrap_registry_t registry;

        if (dht_bootstrap_registry_fetch(g_dht_context, &registry) == 0) {
            // Filter stale nodes (last_seen > 15 minutes)
            dht_bootstrap_registry_filter_active(&registry);

            if (registry.node_count > 0) {
                QGP_LOG_INFO(LOG_TAG, "Discovered %zu active bootstrap nodes from registry",
                       registry.node_count);

                // Bootstrap to discovered nodes for better connectivity
                for (size_t i = 0; i < registry.node_count && i < 10; i++) {
                    char node_addr[128];
                    snprintf(node_addr, sizeof(node_addr), "%s:%d",
                             registry.nodes[i].ip, registry.nodes[i].port);

                    QGP_LOG_DEBUG(LOG_TAG, "  -> %s (node_id: %.16s..., uptime: %lus)",
                           node_addr, registry.nodes[i].node_id,
                           (unsigned long)registry.nodes[i].uptime);

                    // Bootstrap to this node at runtime
                    if (dht_context_bootstrap_runtime(g_dht_context, registry.nodes[i].ip,
                                                      registry.nodes[i].port) == 0) {
                        QGP_LOG_DEBUG(LOG_TAG, "    Bootstrapped to %s", node_addr);
                    } else {
                        QGP_LOG_WARN(LOG_TAG, "    Failed to bootstrap to %s", node_addr);
                    }
                }

                QGP_LOG_INFO(LOG_TAG, "Using %zu dynamically discovered nodes",
                       registry.node_count < 10 ? registry.node_count : 10);
            } else {
                QGP_LOG_WARN(LOG_TAG, "Registry has no active nodes, using fallback nodes");
            }
        } else {
            QGP_LOG_WARN(LOG_TAG, "Failed to query registry, using fallback nodes");
        }

        // RACE CONDITION FIX: Wait for nodes to establish stable connections
        // Even though dht_context_is_ready() returns true (good_nodes > 0),
        // the DHT may not be ready to accept PUT operations yet.
        // Give it 1 second to fully stabilize all connections before allowing PUT operations.
        QGP_LOG_INFO(LOG_TAG, "Waiting for DHT connections to stabilize (1000ms)...");
        #ifdef _WIN32
        Sleep(1000);
        #else
        usleep(1000000);  // 1000ms = 1 second
        #endif
    } else {
        QGP_LOG_WARN(LOG_TAG, "DHT bootstrap timeout, continuing anyway...");
        // Don't return error - DHT may still work for some operations
    }
    return 0;
}

void dht_singleton_cleanup(void)
{
    if (g_dht_context) {
        QGP_LOG_INFO(LOG_TAG, "Shutting down global DHT context...");
        dht_context_free(g_dht_context);
        g_dht_context = NULL;
        QGP_LOG_INFO(LOG_TAG, "DHT shutdown complete");
    }
}
