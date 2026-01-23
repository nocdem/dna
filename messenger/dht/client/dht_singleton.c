/*
 * DNA Messenger - Global DHT Singleton Implementation
 *
 * v0.6.20: Refactored to reduce code duplication
 */

#include "dht_singleton.h"
#include "dht_identity.h"
#include "dht_bootstrap_discovery.h"
#include "../core/dht_context.h"
#include "../core/dht_listen.h"
#include "crypto/utils/qgp_log.h"
#include "crypto/utils/qgp_platform.h"
#include "dna_config.h"
#include "bootstrap_cache.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>

#define LOG_TAG "DHT"

/* Default timeout for waiting for DHT to become ready (milliseconds) */
#define DHT_READY_TIMEOUT_MS 5000

/* Global DHT context (singleton) */
static dht_context_t *g_dht_context = NULL;

/* v0.6.0+: Flag to track if context is "borrowed" from engine (don't free on cleanup) */
static bool g_context_borrowed = false;

/* Global config (loaded once) */
static dna_config_t g_config = {0};
static bool g_config_loaded = false;

/* Stored callback for re-registration after reinit */
static dht_status_callback_t g_status_callback = NULL;
static void *g_status_callback_user_data = NULL;

/* Stored identity buffer for reinit after network change */
static uint8_t *g_identity_buffer = NULL;
static size_t g_identity_buffer_size = 0;

/* ============================================================================
 * HELPER FUNCTIONS
 * ============================================================================ */

/**
 * Ensure config is loaded (lazy initialization)
 */
static void ensure_config(void) {
    if (!g_config_loaded) {
        dna_config_load(&g_config);
        g_config_loaded = true;

        /* Initialize bootstrap cache for decentralized node discovery */
        if (bootstrap_cache_init(NULL) != 0) {
            QGP_LOG_WARN(LOG_TAG, "Failed to initialize bootstrap cache (discovery disabled)");
        }
    }
}

/**
 * Create a client DHT config with bootstrap nodes.
 * Returns 0 on success, -1 if no bootstrap nodes available.
 */
static int create_client_dht_config(dht_config_t *config, const char *identity_name) {
    if (!config) return -1;

    memset(config, 0, sizeof(dht_config_t));
    config->port = 0;  /* Let OS assign random port */
    config->is_bootstrap = false;
    config->persistence_path[0] = '\0';  /* No persistence for clients */

    if (identity_name) {
        strncpy(config->identity, identity_name, sizeof(config->identity) - 1);
    }

    /* Try cached bootstrap nodes first (decentralization) */
    int cached_count = dht_bootstrap_from_cache(config, 3);
    if (cached_count > 0) {
        QGP_LOG_INFO(LOG_TAG, "Using %d cached bootstrap nodes", cached_count);
        return 0;
    }

    /* Fall back to hardcoded nodes */
    ensure_config();
    if (g_config.bootstrap_count > 0) {
        QGP_LOG_INFO(LOG_TAG, "No cached nodes, using hardcoded: %s", g_config.bootstrap_nodes[0]);
        strncpy(config->bootstrap_nodes[0], g_config.bootstrap_nodes[0],
                sizeof(config->bootstrap_nodes[0]) - 1);
        config->bootstrap_count = 1;
        return 0;
    }

    QGP_LOG_ERROR(LOG_TAG, "No bootstrap nodes configured");
    return -1;
}

/**
 * Register status callback on context and fire if already connected.
 */
static void register_status_callback(dht_context_t *ctx) {
    if (!ctx || !g_status_callback) return;

    dht_context_set_status_callback(ctx, g_status_callback, g_status_callback_user_data);

    /* Fire callback immediately if already connected */
    if (dht_context_is_ready(ctx)) {
        QGP_LOG_INFO(LOG_TAG, "DHT already connected, firing callback");
        g_status_callback(true, g_status_callback_user_data);
    }
}

/**
 * Store identity for reinit after network change.
 */
static void store_identity_for_reinit(dht_identity_t *identity) {
    if (!identity) return;

    /* Free previous buffer */
    if (g_identity_buffer) {
        free(g_identity_buffer);
        g_identity_buffer = NULL;
        g_identity_buffer_size = 0;
    }

    if (dht_identity_export_to_buffer(identity, &g_identity_buffer, &g_identity_buffer_size) != 0) {
        QGP_LOG_WARN(LOG_TAG, "Failed to store identity for reinit");
    } else {
        QGP_LOG_DEBUG(LOG_TAG, "Stored identity for network change reinit (%zu bytes)", g_identity_buffer_size);
    }
}

/* ============================================================================
 * PUBLIC API
 * ============================================================================ */

int dht_singleton_init(void)
{
    if (g_dht_context != NULL) {
        QGP_LOG_WARN(LOG_TAG, "Already initialized");
        return 0;
    }

    QGP_LOG_INFO(LOG_TAG, "Initializing global DHT context (no identity)...");

    dht_config_t config;
    if (create_client_dht_config(&config, "dna-global") != 0) {
        return -1;
    }

    g_dht_context = dht_context_new(&config);
    if (!g_dht_context) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to create DHT context");
        return -1;
    }

    if (dht_context_start(g_dht_context) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to start DHT context");
        dht_context_free(g_dht_context);
        g_dht_context = NULL;
        return -1;
    }

    QGP_LOG_INFO(LOG_TAG, "DHT started (bootstrapping in background)");
    return 0;
}

dht_context_t* dht_singleton_get(void)
{
    /* If DHT doesn't exist or is stopped, wait for it to become ready */
    if (!g_dht_context || !dht_context_is_running(g_dht_context)) {
        QGP_LOG_DEBUG(LOG_TAG, "dht_singleton_get: DHT not ready, waiting...");

        if (!dht_context_wait_for_ready(g_dht_context, DHT_READY_TIMEOUT_MS)) {
            QGP_LOG_WARN(LOG_TAG, "DHT not available after %dms wait", DHT_READY_TIMEOUT_MS);
            return NULL;
        }
    }
    return g_dht_context;
}

bool dht_singleton_is_initialized(void)
{
    return (g_dht_context != NULL);
}

bool dht_singleton_is_ready(void)
{
    return g_dht_context && dht_context_is_ready(g_dht_context);
}

int dht_singleton_init_with_identity(dht_identity_t *user_identity)
{
    if (!user_identity) {
        QGP_LOG_ERROR(LOG_TAG, "NULL identity");
        return -1;
    }

    if (g_dht_context != NULL) {
        QGP_LOG_WARN(LOG_TAG, "Already initialized");
        return 0;
    }

    QGP_LOG_INFO(LOG_TAG, "Initializing global DHT with user identity...");

    /* Store identity for reinit after network change (before DHT takes ownership) */
    store_identity_for_reinit(user_identity);

    dht_config_t config;
    if (create_client_dht_config(&config, "dna-user") != 0) {
        return -1;
    }

    g_dht_context = dht_context_new(&config);
    if (!g_dht_context) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to create DHT context");
        return -1;
    }

    if (dht_context_start_with_identity(g_dht_context, user_identity) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to start DHT with identity");
        dht_context_free(g_dht_context);
        g_dht_context = NULL;
        return -1;
    }

    /* Register stored status callback */
    register_status_callback(g_dht_context);

    /* Wait for DHT to connect */
    QGP_LOG_INFO(LOG_TAG, "Waiting for DHT connection...");
    if (dht_context_wait_for_ready(g_dht_context, DHT_READY_TIMEOUT_MS)) {
        QGP_LOG_INFO(LOG_TAG, "DHT connected");

        /* Start background discovery of additional bootstrap nodes */
        dht_bootstrap_discovery_start(g_dht_context);

        /* Fire connected callback */
        if (g_status_callback) {
            g_status_callback(true, g_status_callback_user_data);
        }
    } else {
        QGP_LOG_WARN(LOG_TAG, "DHT not connected after %dms (will retry in background)", DHT_READY_TIMEOUT_MS);
    }

    return 0;
}

void dht_singleton_cleanup(void)
{
    /* Stop discovery thread first */
    dht_bootstrap_discovery_stop();

    if (g_dht_context) {
        QGP_LOG_INFO(LOG_TAG, "Cleaning up DHT context (borrowed=%d)", g_context_borrowed);

        if (g_context_borrowed) {
            /* Context is borrowed from engine - don't free it */
            g_dht_context = NULL;
            g_context_borrowed = false;
        } else {
            dht_context_free(g_dht_context);
            g_dht_context = NULL;
        }
    }

    /* Free stored identity buffer */
    if (g_identity_buffer) {
        free(g_identity_buffer);
        g_identity_buffer = NULL;
        g_identity_buffer_size = 0;
    }

    /* Cleanup bootstrap cache */
    bootstrap_cache_cleanup();
}

int dht_singleton_reinit(void)
{
    QGP_LOG_INFO(LOG_TAG, "Network change detected, restarting DHT...");

    if (!g_identity_buffer || g_identity_buffer_size == 0) {
        QGP_LOG_ERROR(LOG_TAG, "No stored identity for reinit - cannot restart DHT");
        return -1;
    }

    /* Suspend all DHT listeners before stopping */
    dht_suspend_all_listeners(g_dht_context);

    /* Stop and free current DHT context */
    if (g_dht_context) {
        dht_context_free(g_dht_context);
        g_dht_context = NULL;
    }

    /* Import identity from stored buffer */
    dht_identity_t *identity = NULL;
    if (dht_identity_import_from_buffer(g_identity_buffer, g_identity_buffer_size, &identity) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to restore identity from buffer");
        return -1;
    }

    QGP_LOG_DEBUG(LOG_TAG, "Identity restored, creating new DHT context...");

    dht_config_t config;
    if (create_client_dht_config(&config, "dna-user") != 0) {
        dht_identity_free(identity);
        return -1;
    }

    g_dht_context = dht_context_new(&config);
    if (!g_dht_context) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to create new DHT context");
        dht_identity_free(identity);
        return -1;
    }

    if (dht_context_start_with_identity(g_dht_context, identity) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to start DHT with restored identity");
        dht_context_free(g_dht_context);
        g_dht_context = NULL;
        return -1;
    }

    /* Re-register status callback */
    register_status_callback(g_dht_context);

    /* Wait for DHT to connect */
    QGP_LOG_INFO(LOG_TAG, "Waiting for DHT reconnection...");
    if (dht_context_wait_for_ready(g_dht_context, DHT_READY_TIMEOUT_MS)) {
        QGP_LOG_INFO(LOG_TAG, "DHT reconnected after network change");

        /* Clear suspended listeners - engine callback will recreate them */
        dht_cancel_all_listeners(g_dht_context);

        /* Start background discovery */
        dht_bootstrap_discovery_start(g_dht_context);

        /* Fire connected callback */
        if (g_status_callback) {
            g_status_callback(true, g_status_callback_user_data);
        }
    } else {
        QGP_LOG_WARN(LOG_TAG, "DHT not connected after %dms (will retry in background)", DHT_READY_TIMEOUT_MS);
    }

    return 0;
}

void dht_singleton_set_status_callback(dht_status_callback_t callback, void *user_data)
{
    g_status_callback = callback;
    g_status_callback_user_data = user_data;

    if (g_dht_context) {
        register_status_callback(g_dht_context);
    } else {
        QGP_LOG_DEBUG(LOG_TAG, "Status callback stored (will register when DHT starts)");
    }
}

dht_context_t* dht_create_context_with_identity(dht_identity_t *user_identity) {
    if (!user_identity) {
        QGP_LOG_ERROR(LOG_TAG, "dht_create_context_with_identity: NULL identity");
        return NULL;
    }

    QGP_LOG_INFO(LOG_TAG, "Creating engine-owned DHT context with identity...");

    dht_config_t config;
    if (create_client_dht_config(&config, "dna-user") != 0) {
        return NULL;
    }

    dht_context_t *ctx = dht_context_new(&config);
    if (!ctx) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to create DHT context");
        return NULL;
    }

    if (dht_context_start_with_identity(ctx, user_identity) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to start DHT with identity");
        dht_context_free(ctx);
        return NULL;
    }

    /* Wait for DHT to connect */
    QGP_LOG_INFO(LOG_TAG, "Waiting for engine DHT connection...");
    if (dht_context_wait_for_ready(ctx, DHT_READY_TIMEOUT_MS)) {
        QGP_LOG_INFO(LOG_TAG, "Engine DHT connected");
        dht_bootstrap_discovery_start(ctx);
    } else {
        QGP_LOG_WARN(LOG_TAG, "Engine DHT not connected after %dms (will retry in background)", DHT_READY_TIMEOUT_MS);
    }

    return ctx;
}

void dht_singleton_set_borrowed_context(dht_context_t *ctx) {
    if (g_dht_context && !g_context_borrowed) {
        QGP_LOG_WARN(LOG_TAG, "Replacing owned context with borrowed one");
        dht_context_free(g_dht_context);
    }

    g_dht_context = ctx;
    g_context_borrowed = (ctx != NULL);

    if (ctx) {
        QGP_LOG_DEBUG(LOG_TAG, "Singleton now uses borrowed context");
        register_status_callback(ctx);
    } else {
        QGP_LOG_DEBUG(LOG_TAG, "Singleton context cleared");
    }
}
