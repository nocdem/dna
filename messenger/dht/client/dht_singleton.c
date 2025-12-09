/*
 * DNA Messenger - Global DHT Singleton Implementation
 */

#include "dht_singleton.h"
#include "../core/dht_context.h"
#include "crypto/utils/qgp_log.h"
#include "dna_config.h"
#include <stdio.h>
#include <string.h>
#include <stdbool.h>

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

    // Non-blocking: DHT bootstraps in its own background threads
    // Operations will wait/retry as needed when DHT becomes ready
    QGP_LOG_INFO(LOG_TAG, "DHT started (bootstrapping in background)");
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

    // Non-blocking: DHT bootstraps in its own background threads
    // Operations will wait/retry as needed when DHT becomes ready
    QGP_LOG_INFO(LOG_TAG, "DHT started with identity (bootstrapping in background)");
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

void dht_singleton_set_status_callback(dht_status_callback_t callback, void *user_data)
{
    if (!g_dht_context) {
        QGP_LOG_WARN(LOG_TAG, "DHT not initialized, cannot set status callback");
        return;
    }
    dht_context_set_status_callback(g_dht_context, callback, user_data);
}
