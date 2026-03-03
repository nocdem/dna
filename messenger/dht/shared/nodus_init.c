/**
 * Nodus v5 — Messenger Init/Lifecycle Module Implementation
 *
 * Replaces dht_singleton.c (427 lines) with a simpler, leak-free design.
 *
 * Key differences:
 * - Identity stored as value type (no malloc/free → no ASAN leak)
 * - Always calls nodus_singleton_close() on cleanup (shutdown leak fix)
 * - Single init/close path (no borrowed context complexity)
 * - nodus_ops_dispatch is the only value_changed callback
 *
 * @file nodus_init.c
 */

#include "nodus_init.h"
#include "nodus_ops.h"
#include "client/nodus_singleton.h"
#include "crypto/nodus_identity.h"
#include "nodus/nodus.h"
#include "crypto/utils/qgp_log.h"
#include "crypto/utils/qgp_platform.h"
#include "dna_config.h"
#include "bootstrap_cache.h"

#include <string.h>
#include <stdlib.h>
#include <stdbool.h>

#define LOG_TAG "NODUS_INIT"

/* ── State ──────────────────────────────────────────────────────── */

static nodus_identity_t g_stored_identity;      /* Value type — no heap alloc */
static bool g_initialized = false;
static bool g_config_loaded = false;
static dna_config_t g_config = {0};

/* Status callback */
static nodus_messenger_status_cb_t g_status_cb = NULL;
static void *g_status_cb_data = NULL;

/* ── Helpers ────────────────────────────────────────────────────── */

static void ensure_config(void) {
    if (!g_config_loaded) {
        dna_config_load(&g_config);
        g_config_loaded = true;

        if (bootstrap_cache_init(NULL) != 0) {
            QGP_LOG_WARN(LOG_TAG, "Failed to initialize bootstrap cache");
        }
    }
}

/**
 * Parse hardcoded bootstrap nodes from g_config into nconfig.
 */
static void load_hardcoded_nodes(nodus_client_config_t *nconfig) {
    nconfig->server_count = 0;
    for (int i = 0; i < g_config.bootstrap_count && nconfig->server_count < NODUS_CLIENT_MAX_SERVERS; i++) {
        const char *node = g_config.bootstrap_nodes[i];
        const char *colon = strrchr(node, ':');
        if (colon) {
            size_t ip_len = (size_t)(colon - node);
            if (ip_len >= sizeof(nconfig->servers[0].ip))
                ip_len = sizeof(nconfig->servers[0].ip) - 1;
            memcpy(nconfig->servers[nconfig->server_count].ip, node, ip_len);
            nconfig->servers[nconfig->server_count].ip[ip_len] = '\0';
            nconfig->servers[nconfig->server_count].port = (uint16_t)atoi(colon + 1);
        } else {
            strncpy(nconfig->servers[nconfig->server_count].ip, node,
                    sizeof(nconfig->servers[0].ip) - 1);
            nconfig->servers[nconfig->server_count].port = NODUS_DEFAULT_TCP_PORT;
        }
        nconfig->server_count++;
    }
}

/**
 * Nodus client on_state_change callback — fires messenger status callback.
 */
static void on_state_change(nodus_client_state_t old_state,
                            nodus_client_state_t new_state,
                            void *user_data) {
    (void)old_state;
    (void)user_data;
    bool connected = (new_state == NODUS_CLIENT_READY);
    if (g_status_cb) {
        g_status_cb(connected, g_status_cb_data);
    }
}

/* ── Public API ─────────────────────────────────────────────────── */

int nodus_messenger_init(const nodus_identity_t *identity) {
    if (!identity) {
        QGP_LOG_ERROR(LOG_TAG, "NULL identity");
        return -1;
    }

    if (g_initialized) {
        QGP_LOG_WARN(LOG_TAG, "Already initialized");
        return 0;
    }

    /* Store identity (value copy — no heap, no leak) */
    g_stored_identity = *identity;

    /* Load bootstrap config */
    ensure_config();

    /* Build Nodus client config from bootstrap nodes */
    nodus_client_config_t nconfig;
    memset(&nconfig, 0, sizeof(nconfig));
    nconfig.auto_reconnect = true;
    nconfig.on_value_changed = nodus_ops_dispatch;
    nconfig.on_state_change = on_state_change;

    /* Try cached bootstrap nodes first */
    bool used_cache = false;
    bootstrap_cache_entry_t *cached_nodes = NULL;
    size_t cached_count = 0;
    if (bootstrap_cache_get_best(3, &cached_nodes, &cached_count) == 0 && cached_count > 0) {
        QGP_LOG_INFO(LOG_TAG, "Using %zu cached bootstrap nodes", cached_count);
        for (size_t i = 0; i < cached_count && nconfig.server_count < NODUS_CLIENT_MAX_SERVERS; i++) {
            strncpy(nconfig.servers[nconfig.server_count].ip, cached_nodes[i].ip,
                    sizeof(nconfig.servers[0].ip) - 1);
            nconfig.servers[nconfig.server_count].port = cached_nodes[i].port;
            nconfig.server_count++;
        }
        free(cached_nodes);
        used_cache = true;
    }

    /* Fall back to hardcoded nodes if no cache */
    if (nconfig.server_count == 0 && g_config.bootstrap_count > 0) {
        QGP_LOG_INFO(LOG_TAG, "No cached nodes, using %d hardcoded bootstrap nodes",
                     g_config.bootstrap_count);
        load_hardcoded_nodes(&nconfig);
    }

    if (nconfig.server_count == 0) {
        QGP_LOG_ERROR(LOG_TAG, "No bootstrap nodes configured");
        return -1;
    }

    /* Initialize and connect */
    int rc = nodus_singleton_init(&nconfig, &g_stored_identity);
    if (rc != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Singleton init failed");
        return -1;
    }

    rc = nodus_singleton_connect();

    /* If cached nodes failed, retry with hardcoded nodes */
    if (rc != 0 && used_cache && g_config.bootstrap_count > 0) {
        QGP_LOG_WARN(LOG_TAG, "Cached nodes failed, retrying with hardcoded bootstrap nodes");
        nodus_singleton_close();

        /* Expire all stale cache entries */
        bootstrap_cache_expire(0);

        /* Rebuild config with hardcoded nodes */
        memset(&nconfig, 0, sizeof(nconfig));
        nconfig.auto_reconnect = true;
        nconfig.on_value_changed = nodus_ops_dispatch;
        nconfig.on_state_change = on_state_change;
        load_hardcoded_nodes(&nconfig);

        rc = nodus_singleton_init(&nconfig, &g_stored_identity);
        if (rc != 0) {
            QGP_LOG_ERROR(LOG_TAG, "Singleton init failed (hardcoded fallback)");
            return -1;
        }
        rc = nodus_singleton_connect();
    }

    if (rc != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Singleton connect failed");
        nodus_singleton_close();
        return -1;
    }

    g_initialized = true;

    /* Wait briefly for connection */
    int elapsed = 0;
    while (!nodus_singleton_is_ready() && elapsed < 500) {
        nodus_singleton_poll(100);
        elapsed += 100;
    }

    if (nodus_singleton_is_ready()) {
        QGP_LOG_INFO(LOG_TAG, "Connected");
        if (g_status_cb) {
            g_status_cb(true, g_status_cb_data);
        }
    } else {
        QGP_LOG_WARN(LOG_TAG, "Not connected after 500ms (will retry in background)");
    }

    return 0;
}

void nodus_messenger_close(void) {
    if (!g_initialized) return;

    QGP_LOG_INFO(LOG_TAG, "Closing");

    /* Cancel all nodus_ops listeners first */
    nodus_ops_cancel_all();

    /* Close the singleton (disconnects TCP, frees client) */
    nodus_singleton_close();

    /* Clear stored identity */
    nodus_identity_clear(&g_stored_identity);

    /* Cleanup bootstrap cache */
    bootstrap_cache_cleanup();

    g_initialized = false;
}

int nodus_messenger_reinit(void) {
    QGP_LOG_INFO(LOG_TAG, "Network change, reinitializing...");

    if (!g_initialized) {
        QGP_LOG_ERROR(LOG_TAG, "Not initialized, cannot reinit");
        return -1;
    }

    /* Save identity before close */
    nodus_identity_t saved = g_stored_identity;

    /* Close current connection */
    nodus_ops_cancel_all();
    nodus_singleton_close();
    g_initialized = false;

    /* Re-init with saved identity */
    return nodus_messenger_init(&saved);
}

bool nodus_messenger_is_ready(void) {
    return g_initialized && nodus_singleton_is_ready();
}

bool nodus_messenger_is_initialized(void) {
    return g_initialized;
}

void nodus_messenger_set_status_callback(nodus_messenger_status_cb_t cb, void *user_data) {
    g_status_cb = cb;
    g_status_cb_data = user_data;

    /* Fire immediately if already connected */
    if (g_initialized && nodus_singleton_is_ready() && cb) {
        cb(true, user_data);
    }
}

bool nodus_messenger_wait_for_ready(int timeout_ms) {
    int elapsed = 0;
    while (!nodus_messenger_is_ready() && elapsed < timeout_ms) {
        nodus_singleton_poll(100);
        elapsed += 100;
    }
    return nodus_messenger_is_ready();
}
