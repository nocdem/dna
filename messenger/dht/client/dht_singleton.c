/*
 * DNA Messenger - Global DHT Singleton Implementation
 */

#include "dht_singleton.h"
#include "../core/dht_context.h"
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

// Global DHT context (singleton)
static dht_context_t *g_dht_context = NULL;

// Bootstrap node addresses
static const char *BOOTSTRAP_NODES[] = {
    "154.38.182.161:4000",  // dna-bootstrap-us-1
    "164.68.105.227:4000",  // dna-bootstrap-eu-1
    "164.68.116.180:4000"   // dna-bootstrap-eu-2
};
static const size_t BOOTSTRAP_COUNT = 3;

int dht_singleton_init(void)
{
    if (g_dht_context != NULL) {
        fprintf(stderr, "[DHT_SINGLETON] Already initialized\n");
        return 0;  // Already initialized, not an error
    }

    printf("[DHT_SINGLETON] Initializing global DHT context...\n");

    // Configure DHT
    dht_config_t dht_config = {0};
    dht_config.port = 4000;  // DHT port (not P2P TCP port)
    dht_config.is_bootstrap = false;
    strncpy(dht_config.identity, "dna-global", sizeof(dht_config.identity) - 1);

    // Add bootstrap nodes
    for (size_t i = 0; i < BOOTSTRAP_COUNT; i++) {
        strncpy(dht_config.bootstrap_nodes[i], BOOTSTRAP_NODES[i],
                sizeof(dht_config.bootstrap_nodes[i]) - 1);
    }
    dht_config.bootstrap_count = BOOTSTRAP_COUNT;

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

    // Wait for DHT to be ready with faster polling for better responsiveness
    // Check every 100ms for up to 3 seconds maximum
    int max_attempts = 30;  // 30 * 100ms = 3s max
    int attempts = 0;
    
    while (!dht_context_is_ready(g_dht_context) && attempts < max_attempts) {
        #ifdef _WIN32
        Sleep(100);  // Windows: 100ms
        #else
        usleep(100000);  // Unix: 100ms
        #endif
        attempts++;
    }
    
    if (dht_context_is_ready(g_dht_context)) {
        printf("[DHT_SINGLETON] ✓ Global DHT ready! (took %dms)\n", attempts * 100);
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
    dht_config.port = 4000;  // DHT port
    dht_config.is_bootstrap = false;
    strncpy(dht_config.identity, "dna-user", sizeof(dht_config.identity) - 1);

    // Add bootstrap nodes
    for (size_t i = 0; i < BOOTSTRAP_COUNT; i++) {
        strncpy(dht_config.bootstrap_nodes[i], BOOTSTRAP_NODES[i],
                sizeof(dht_config.bootstrap_nodes[i]) - 1);
    }
    dht_config.bootstrap_count = BOOTSTRAP_COUNT;

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

    // Wait for DHT to be ready with faster polling for better responsiveness
    // Check every 100ms for up to 3 seconds maximum
    int max_attempts = 30;  // 30 * 100ms = 3s max
    int attempts = 0;
    
    while (!dht_context_is_ready(g_dht_context) && attempts < max_attempts) {
        #ifdef _WIN32
        Sleep(100);  // Windows: 100ms
        #else
        usleep(100000);  // Unix: 100ms
        #endif
        attempts++;
    }
    
    if (dht_context_is_ready(g_dht_context)) {
        printf("[DHT_SINGLETON] ✓ Global DHT ready with user identity! (took %dms)\n", attempts * 100);
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
