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

/* Hardcoded fallback bootstrap nodes (compiled into binary) */
static const char *g_fallback_nodes[] = {
    "161.97.85.25:4001",
    "156.67.24.125:4001",
    "156.67.25.251:4001",
};
static const int g_fallback_count = 3;

/**
 * Parse "ip:port" node list into nconfig server entries.
 */
static void parse_nodes_into(nodus_client_config_t *nconfig,
                             const char *nodes[], int count) {
    nconfig->server_count = 0;
    for (int i = 0; i < count && nconfig->server_count < NODUS_CLIENT_MAX_SERVERS; i++) {
        const char *node = nodes[i];
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
 * Load config file bootstrap nodes into nconfig.
 */
static void load_config_nodes(nodus_client_config_t *nconfig) {
    const char *nodes[DNA_MAX_BOOTSTRAP_NODES];
    for (int i = 0; i < g_config.bootstrap_count; i++)
        nodes[i] = g_config.bootstrap_nodes[i];
    parse_nodes_into(nconfig, nodes, g_config.bootstrap_count);
}

/**
 * Load hardcoded fallback nodes into nconfig.
 */
static void load_fallback_nodes(nodus_client_config_t *nconfig) {
    parse_nodes_into(nconfig, g_fallback_nodes, g_fallback_count);
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

    /* ── Try sources in order: cache → config → hardcoded fallback ── */

    /* Source 1: Cached bootstrap nodes */
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

    /* Source 2: Config file nodes (if no cache) */
    if (nconfig.server_count == 0 && g_config.bootstrap_count > 0) {
        QGP_LOG_INFO(LOG_TAG, "Using %d config bootstrap nodes", g_config.bootstrap_count);
        load_config_nodes(&nconfig);
    }

    /* Source 3: Hardcoded fallback (if nothing else) */
    if (nconfig.server_count == 0) {
        QGP_LOG_INFO(LOG_TAG, "Using %d hardcoded fallback nodes", g_fallback_count);
        load_fallback_nodes(&nconfig);
    }

    if (nconfig.server_count == 0) {
        QGP_LOG_ERROR(LOG_TAG, "No bootstrap nodes available");
        return -1;
    }

    /* Log servers to stderr for debugging */
    for (int i = 0; i < nconfig.server_count; i++) {
        fprintf(stderr, "[NODUS_INIT] Server %d: %s:%d\n",
                i, nconfig.servers[i].ip, nconfig.servers[i].port);
    }

    /* ── Try connect, fall back on failure ── */

    int rc = nodus_singleton_init(&nconfig, &g_stored_identity);
    if (rc != 0) {
        fprintf(stderr, "[NODUS_INIT] Singleton init failed (rc=%d)\n", rc);
        QGP_LOG_ERROR(LOG_TAG, "Singleton init failed");
        return -1;
    }

    rc = nodus_singleton_connect();
    fprintf(stderr, "[NODUS_INIT] Singleton connect rc=%d\n", rc);

    /* If cache/config nodes failed, retry with hardcoded fallback */
    if (rc != 0) {
        QGP_LOG_WARN(LOG_TAG, "Connect failed, retrying with hardcoded fallback nodes");
        nodus_singleton_close();

        if (used_cache) bootstrap_cache_expire(0);

        memset(&nconfig, 0, sizeof(nconfig));
        nconfig.auto_reconnect = true;
        nconfig.on_value_changed = nodus_ops_dispatch;
        nconfig.on_state_change = on_state_change;
        load_fallback_nodes(&nconfig);

        for (int i = 0; i < nconfig.server_count; i++) {
            fprintf(stderr, "[NODUS_INIT] Fallback server %d: %s:%d\n",
                    i, nconfig.servers[i].ip, nconfig.servers[i].port);
        }

        rc = nodus_singleton_init(&nconfig, &g_stored_identity);
        if (rc != 0) {
            QGP_LOG_ERROR(LOG_TAG, "Singleton init failed (fallback)");
            return -1;
        }
        rc = nodus_singleton_connect();
        fprintf(stderr, "[NODUS_INIT] Fallback connect rc=%d\n", rc);
    }

    if (rc != 0) {
        QGP_LOG_ERROR(LOG_TAG, "All bootstrap sources failed");
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
