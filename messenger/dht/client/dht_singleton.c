/*
 * DNA Messenger - Global DHT Singleton Implementation
 */

#include "dht_singleton.h"
#include "../core/dht_context.h"
#include "../core/dht_bootstrap_registry.h"
#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/types.h>

/* Redirect printf/fprintf to Android logcat */
#define QGP_LOG_TAG "DHT"
#define QGP_LOG_REDIRECT_STDIO 1
#include "crypto/utils/qgp_log.h"

#ifdef _WIN32
#include <windows.h>
#include <direct.h>
#define mkdir(path, mode) _mkdir(path)
#else
#include <unistd.h>
#endif

// Global DHT context (singleton)
static dht_context_t *g_dht_context = NULL;

// Bootstrap node addresses (SEED NODE for cold start + fallback)
static const char *SEED_NODE = "154.38.182.161:4000";  // US-1 (always available)
static const char *FALLBACK_NODES[] = {
    "154.38.182.161:4000",  // dna-bootstrap-us-1
    "164.68.105.227:4000",  // dna-bootstrap-eu-1
    "164.68.116.180:4000"   // dna-bootstrap-eu-2
};
static const size_t FALLBACK_COUNT = 3;

int dht_singleton_init(void)
{
    if (g_dht_context != NULL) {
        fprintf(stderr, "[DHT_SINGLETON] Already initialized\n");
        return 0;  // Already initialized, not an error
    }

    printf("[DHT_SINGLETON] Initializing global DHT context...\n");

    // Configure DHT
    dht_config_t dht_config = {0};
    dht_config.port = 0;  // Let OS assign random port (clients don't need fixed port)
    dht_config.is_bootstrap = false;
    strncpy(dht_config.identity, "dna-global", sizeof(dht_config.identity) - 1);

    // STEP 1: Bootstrap to seed node for cold start
    printf("[DHT_SINGLETON] Using seed node for cold start: %s\n", SEED_NODE);
    strncpy(dht_config.bootstrap_nodes[0], SEED_NODE,
            sizeof(dht_config.bootstrap_nodes[0]) - 1);
    dht_config.bootstrap_count = 1;

    // NO PERSISTENCE for client DHT (only bootstrap nodes need persistence)
    // Client DHT is temporary and should not republish stored values
    dht_config.persistence_path[0] = '\0';  // Empty = no persistence

    printf("[DHT_SINGLETON] Client DHT mode (no persistence)\n");

    // Create DHT context
    g_dht_context = dht_context_new(&dht_config);
    if (!g_dht_context) {
        fprintf(stderr, "[DHT_SINGLETON] ERROR: Failed to create DHT context\n");
        return -1;
    }

    // Start DHT and bootstrap
    if (dht_context_start(g_dht_context) != 0) {
        fprintf(stderr, "[DHT_SINGLETON] ERROR: Failed to start DHT context\n");
        dht_context_free(g_dht_context);
        g_dht_context = NULL;
        return -1;
    }

    printf("[DHT_SINGLETON] DHT started, bootstrapping to network...\n");

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
        printf("[DHT_SINGLETON] ✓ Global DHT ready! (took %dms)\n", attempts * 250);

        // STEP 2: Query bootstrap registry for dynamic node discovery
        printf("[DHT_SINGLETON] Querying bootstrap registry for active nodes...\n");
        bootstrap_registry_t registry;

        if (dht_bootstrap_registry_fetch(g_dht_context, &registry) == 0) {
            // Filter stale nodes (last_seen > 15 minutes)
            dht_bootstrap_registry_filter_active(&registry);

            if (registry.node_count > 0) {
                printf("[DHT_SINGLETON] ✓ Discovered %zu active bootstrap nodes from registry\n",
                       registry.node_count);

                // Bootstrap to discovered nodes for better connectivity
                for (size_t i = 0; i < registry.node_count && i < 10; i++) {
                    char node_addr[128];
                    snprintf(node_addr, sizeof(node_addr), "%s:%d",
                             registry.nodes[i].ip, registry.nodes[i].port);

                    printf("[DHT_SINGLETON]   → %s (node_id: %.16s..., uptime: %lus)\n",
                           node_addr, registry.nodes[i].node_id,
                           (unsigned long)registry.nodes[i].uptime);

                    // Bootstrap to this node at runtime
                    if (dht_context_bootstrap_runtime(g_dht_context, registry.nodes[i].ip,
                                                      registry.nodes[i].port) == 0) {
                        printf("[DHT_SINGLETON]     ✓ Bootstrapped to %s\n", node_addr);
                    } else {
                        printf("[DHT_SINGLETON]     ✗ Failed to bootstrap to %s\n", node_addr);
                    }
                }

                printf("[DHT_SINGLETON] ✓ Using %zu dynamically discovered nodes\n",
                       registry.node_count < 10 ? registry.node_count : 10);
            } else {
                printf("[DHT_SINGLETON] ⚠ Registry has no active nodes, using fallback nodes\n");
            }
        } else {
            printf("[DHT_SINGLETON] ⚠ Failed to query registry, using fallback nodes\n");
        }

        // RACE CONDITION FIX: Wait for nodes to establish stable connections
        // Even though dht_context_is_ready() returns true (good_nodes > 0),
        // the DHT may not be ready to accept PUT operations yet.
        // Give it 1 second to fully stabilize all connections before allowing PUT operations.
        printf("[DHT_SINGLETON] Waiting for DHT connections to stabilize (1000ms)...\n");
        #ifdef _WIN32
        Sleep(1000);
        #else
        usleep(1000000);  // 1000ms = 1 second
        #endif
    } else {
        printf("[DHT_SINGLETON] ⚠ DHT bootstrap timeout, continuing anyway...\n");
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
        fprintf(stderr, "[DHT_SINGLETON] ERROR: NULL identity\n");
        return -1;
    }

    if (g_dht_context != NULL) {
        fprintf(stderr, "[DHT_SINGLETON] Already initialized\n");
        return 0;  // Already initialized, not an error
    }

    printf("[DHT_SINGLETON] Initializing global DHT with user identity...\n");

    // Configure DHT
    dht_config_t dht_config = {0};
    dht_config.port = 0;  // Let OS assign random port (clients don't need fixed port)
    dht_config.is_bootstrap = false;
    strncpy(dht_config.identity, "dna-user", sizeof(dht_config.identity) - 1);

    // STEP 1: Bootstrap to seed node for cold start
    printf("[DHT_SINGLETON] Using seed node for cold start: %s\n", SEED_NODE);
    strncpy(dht_config.bootstrap_nodes[0], SEED_NODE,
            sizeof(dht_config.bootstrap_nodes[0]) - 1);
    dht_config.bootstrap_count = 1;

    // NO PERSISTENCE for client DHT
    dht_config.persistence_path[0] = '\0';

    printf("[DHT_SINGLETON] Client DHT mode (no persistence)\n");

    // Create DHT context
    g_dht_context = dht_context_new(&dht_config);
    if (!g_dht_context) {
        fprintf(stderr, "[DHT_SINGLETON] ERROR: Failed to create DHT context\n");
        return -1;
    }

    // Start DHT with user-provided identity
    if (dht_context_start_with_identity(g_dht_context, user_identity) != 0) {
        fprintf(stderr, "[DHT_SINGLETON] ERROR: Failed to start DHT with identity\n");
        dht_context_free(g_dht_context);
        g_dht_context = NULL;
        return -1;
    }

    printf("[DHT_SINGLETON] DHT started, bootstrapping to network...\n");

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
        printf("[DHT_SINGLETON] ✓ Global DHT ready with user identity! (took %dms)\n", attempts * 250);

        // STEP 2: Query bootstrap registry for dynamic node discovery
        printf("[DHT_SINGLETON] Querying bootstrap registry for active nodes...\n");
        bootstrap_registry_t registry;

        if (dht_bootstrap_registry_fetch(g_dht_context, &registry) == 0) {
            // Filter stale nodes (last_seen > 15 minutes)
            dht_bootstrap_registry_filter_active(&registry);

            if (registry.node_count > 0) {
                printf("[DHT_SINGLETON] ✓ Discovered %zu active bootstrap nodes from registry\n",
                       registry.node_count);

                // Bootstrap to discovered nodes for better connectivity
                for (size_t i = 0; i < registry.node_count && i < 10; i++) {
                    char node_addr[128];
                    snprintf(node_addr, sizeof(node_addr), "%s:%d",
                             registry.nodes[i].ip, registry.nodes[i].port);

                    printf("[DHT_SINGLETON]   → %s (node_id: %.16s..., uptime: %lus)\n",
                           node_addr, registry.nodes[i].node_id,
                           (unsigned long)registry.nodes[i].uptime);

                    // Bootstrap to this node at runtime
                    if (dht_context_bootstrap_runtime(g_dht_context, registry.nodes[i].ip,
                                                      registry.nodes[i].port) == 0) {
                        printf("[DHT_SINGLETON]     ✓ Bootstrapped to %s\n", node_addr);
                    } else {
                        printf("[DHT_SINGLETON]     ✗ Failed to bootstrap to %s\n", node_addr);
                    }
                }

                printf("[DHT_SINGLETON] ✓ Using %zu dynamically discovered nodes\n",
                       registry.node_count < 10 ? registry.node_count : 10);
            } else {
                printf("[DHT_SINGLETON] ⚠ Registry has no active nodes, using fallback nodes\n");
            }
        } else {
            printf("[DHT_SINGLETON] ⚠ Failed to query registry, using fallback nodes\n");
        }

        // RACE CONDITION FIX: Wait for nodes to establish stable connections
        // Even though dht_context_is_ready() returns true (good_nodes > 0),
        // the DHT may not be ready to accept PUT operations yet.
        // Give it 1 second to fully stabilize all connections before allowing PUT operations.
        printf("[DHT_SINGLETON] Waiting for DHT connections to stabilize (1000ms)...\n");
        #ifdef _WIN32
        Sleep(1000);
        #else
        usleep(1000000);  // 1000ms = 1 second
        #endif
    } else {
        printf("[DHT_SINGLETON] ⚠ DHT bootstrap timeout, continuing anyway...\n");
        // Don't return error - DHT may still work for some operations
    }
    return 0;
}

void dht_singleton_cleanup(void)
{
    if (g_dht_context) {
        printf("[DHT_SINGLETON] Shutting down global DHT context...\n");
        dht_context_free(g_dht_context);
        g_dht_context = NULL;
        printf("[DHT_SINGLETON] ✓ DHT shutdown complete\n");
    }
}
