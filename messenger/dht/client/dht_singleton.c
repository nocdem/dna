/*
 * DNA Messenger - Global DHT Singleton Implementation
 */

#include "dht_singleton.h"
#include "dht_identity.h"
#include "../core/dht_context.h"
#include "../core/dht_listen.h"
#include "crypto/utils/qgp_log.h"
#include "crypto/utils/qgp_platform.h"
#include "dna_config.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>

#define LOG_TAG "DHT"

// Global DHT context (singleton)
static dht_context_t *g_dht_context = NULL;

// Global config (loaded once)
static dna_config_t g_config = {0};
static bool g_config_loaded = false;

// Stored callback for re-registration after reinit
static dht_status_callback_t g_status_callback = NULL;
static void *g_status_callback_user_data = NULL;

// Stored identity buffer for reinit after network change
static uint8_t *g_identity_buffer = NULL;
static size_t g_identity_buffer_size = 0;

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

    QGP_LOG_INFO(LOG_TAG, "DHT started (bootstrapping in background)");
    return 0;
}

dht_context_t* dht_singleton_get(void)
{
    // Debug: log every call
    bool ctx_exists = (g_dht_context != NULL);
    bool ctx_running = ctx_exists ? dht_context_is_running(g_dht_context) : false;
    (void)ctx_running;  // Used only in debug builds
    QGP_LOG_DEBUG(LOG_TAG, "dht_singleton_get: ctx=%p exists=%d running=%d",
                  (void*)g_dht_context, ctx_exists, ctx_running);

    // If DHT doesn't exist or is stopped, wait for it to become ready
    // This handles race conditions during DHT reinit (identity loading)
    if (!g_dht_context || !dht_context_is_running(g_dht_context)) {
        QGP_LOG_INFO(LOG_TAG, "dht_singleton_get: DHT not ready, waiting...");
        // Wait up to 5 seconds for DHT to become ready
        int wait_count = 0;
        while (wait_count < 50) {
            if (g_dht_context && dht_context_is_running(g_dht_context)) {
                QGP_LOG_INFO(LOG_TAG, "DHT became ready after %d00ms wait", wait_count);
                break;
            }
            qgp_platform_sleep_ms(100);  // 100ms
            wait_count++;
        }

        // Still not ready after timeout
        if (!g_dht_context || !dht_context_is_running(g_dht_context)) {
            QGP_LOG_WARN(LOG_TAG, "DHT not available after 5s wait (ctx=%p)", (void*)g_dht_context);
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
    if (!g_dht_context) {
        return false;
    }
    return dht_context_is_ready(g_dht_context);
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

    // Store identity for reinit after network change
    // Export BEFORE starting DHT (which takes ownership of identity)
    if (g_identity_buffer) {
        free(g_identity_buffer);
        g_identity_buffer = NULL;
        g_identity_buffer_size = 0;
    }
    if (dht_identity_export_to_buffer(user_identity, &g_identity_buffer, &g_identity_buffer_size) != 0) {
        QGP_LOG_WARN(LOG_TAG, "Failed to store identity for reinit (will need app restart on network change)");
        // Continue anyway - just means reinit won't work
    } else {
        QGP_LOG_INFO(LOG_TAG, "Stored identity for network change reinit (%zu bytes)", g_identity_buffer_size);
    }

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

    // Re-register stored status callback on new context
    if (g_status_callback) {
        dht_context_set_status_callback(g_dht_context, g_status_callback, g_status_callback_user_data);
        QGP_LOG_WARN(LOG_TAG, "Re-registered status callback on new context");
    } else {
        QGP_LOG_WARN(LOG_TAG, "No status callback to re-register");
    }

    // Wait for DHT to connect (max 5 seconds)
    // This prevents "Broken promise" errors from operations starting before DHT is ready
    QGP_LOG_WARN(LOG_TAG, "Waiting for DHT connection...");
    int wait_count = 0;
    while (!dht_context_is_ready(g_dht_context) && wait_count < 50) {
        qgp_platform_sleep_ms(100);  // 100ms
        wait_count++;
    }

    if (dht_context_is_ready(g_dht_context)) {
        QGP_LOG_WARN(LOG_TAG, "DHT connected after %d00ms", wait_count);
        // Fire connected callback manually - OpenDHT's setOnStatusChanged doesn't
        // reliably fire for disconnected->connected transitions
        if (g_status_callback) {
            QGP_LOG_WARN(LOG_TAG, "Firing connected callback");
            g_status_callback(true, g_status_callback_user_data);
        }
    } else {
        QGP_LOG_WARN(LOG_TAG, "DHT not connected after 5s (will retry in background)");
    }

    return 0;
}

void dht_singleton_cleanup(void)
{
    if (g_dht_context) {
        QGP_LOG_WARN(LOG_TAG, ">>> CLEANUP START (ctx=%p) <<<", (void*)g_dht_context);
        dht_context_free(g_dht_context);
        g_dht_context = NULL;
        QGP_LOG_WARN(LOG_TAG, ">>> CLEANUP DONE <<<");
    } else {
        QGP_LOG_WARN(LOG_TAG, ">>> CLEANUP: no context to clean <<<");
    }

    // Free stored identity buffer
    if (g_identity_buffer) {
        free(g_identity_buffer);
        g_identity_buffer = NULL;
        g_identity_buffer_size = 0;
    }
}

int dht_singleton_reinit(void)
{
    QGP_LOG_WARN(LOG_TAG, ">>> REINIT: Network change detected, restarting DHT <<<");

    // Check if we have a stored identity
    if (!g_identity_buffer || g_identity_buffer_size == 0) {
        QGP_LOG_ERROR(LOG_TAG, "No stored identity for reinit - cannot restart DHT");
        return -1;
    }

    // Cancel all DHT listeners before stopping
    if (g_dht_context) {
        dht_cancel_all_listeners(g_dht_context);
    }

    // Stop and free current DHT context (but keep identity buffer)
    if (g_dht_context) {
        QGP_LOG_INFO(LOG_TAG, "Stopping current DHT context...");
        dht_context_free(g_dht_context);
        g_dht_context = NULL;
    }

    // Small delay to allow network to stabilize
    qgp_platform_sleep_ms(500);

    // Import identity from stored buffer
    dht_identity_t *identity = NULL;
    if (dht_identity_import_from_buffer(g_identity_buffer, g_identity_buffer_size, &identity) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to restore identity from buffer");
        return -1;
    }

    QGP_LOG_INFO(LOG_TAG, "Identity restored, creating new DHT context...");

    // Configure new DHT
    dht_config_t dht_config = {0};
    dht_config.port = 0;
    dht_config.is_bootstrap = false;
    strncpy(dht_config.identity, "dna-user", sizeof(dht_config.identity) - 1);

    if (g_config.bootstrap_count > 0) {
        strncpy(dht_config.bootstrap_nodes[0], g_config.bootstrap_nodes[0],
                sizeof(dht_config.bootstrap_nodes[0]) - 1);
        dht_config.bootstrap_count = 1;
    } else {
        QGP_LOG_ERROR(LOG_TAG, "No bootstrap nodes configured");
        dht_identity_free(identity);
        return -1;
    }

    dht_config.persistence_path[0] = '\0';

    // Create new DHT context
    g_dht_context = dht_context_new(&dht_config);
    if (!g_dht_context) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to create new DHT context");
        dht_identity_free(identity);
        return -1;
    }

    // Start DHT with restored identity
    if (dht_context_start_with_identity(g_dht_context, identity) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to start DHT with restored identity");
        dht_context_free(g_dht_context);
        g_dht_context = NULL;
        // Note: identity is freed by dht_context_free on failure
        return -1;
    }

    // Re-register status callback
    if (g_status_callback) {
        dht_context_set_status_callback(g_dht_context, g_status_callback, g_status_callback_user_data);
        QGP_LOG_INFO(LOG_TAG, "Re-registered status callback");
    }

    // Wait for DHT to connect
    QGP_LOG_INFO(LOG_TAG, "Waiting for DHT reconnection...");
    int wait_count = 0;
    while (!dht_context_is_ready(g_dht_context) && wait_count < 50) {
        qgp_platform_sleep_ms(100);
        wait_count++;
    }

    if (dht_context_is_ready(g_dht_context)) {
        QGP_LOG_WARN(LOG_TAG, ">>> REINIT SUCCESS: DHT reconnected after %d00ms <<<", wait_count);

        // Resubscribe all listeners
        size_t resubscribed = dht_resubscribe_all_listeners(g_dht_context);
        QGP_LOG_INFO(LOG_TAG, "Resubscribed %zu listeners", resubscribed);

        // Fire connected callback
        if (g_status_callback) {
            g_status_callback(true, g_status_callback_user_data);
        }
        return 0;
    } else {
        QGP_LOG_WARN(LOG_TAG, "DHT not connected after 5s (will retry in background)");
        return 0;  // Still return success - connection may happen later
    }
}

void dht_singleton_set_status_callback(dht_status_callback_t callback, void *user_data)
{
    // Store callback for re-registration after reinit
    g_status_callback = callback;
    g_status_callback_user_data = user_data;

    // Register on current context if available
    if (g_dht_context) {
        dht_context_set_status_callback(g_dht_context, callback, user_data);

        // Check if already connected and fire callback
        // Don't block - if not ready, callback will fire later via OpenDHT
        if (callback && dht_context_is_ready(g_dht_context)) {
            QGP_LOG_INFO(LOG_TAG, "DHT already connected, firing callback");
            callback(true, user_data);
        }
    } else {
        QGP_LOG_INFO(LOG_TAG, "Status callback stored (will register when DHT starts)");
    }
}
