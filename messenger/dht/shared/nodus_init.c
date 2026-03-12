/**
 * Nodus — Messenger Init/Lifecycle Module Implementation
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
/* #include "bootstrap_cache.h" — disabled, stale port data caused startup delay */

#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdio.h>
#include <errno.h>
#include <pthread.h>
#include <sys/time.h>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>
#include <poll.h>
#endif

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

        /* bootstrap_cache disabled — stale port 4000 entries caused startup delay */
    }
}

/* Hardcoded fallback bootstrap nodes (compiled into binary) */
static const char *g_fallback_nodes[] = {
    "154.38.182.161:4001",
    "164.68.105.227:4001",
    "164.68.116.180:4001",
    "161.97.85.25:4001",
    "156.67.24.125:4001",
    "156.67.25.251:4001",
};
static const int g_fallback_count = 6;

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

/* ── Preferred Node Cache (flat file) ───────────────────────────── */

/**
 * Get path to preferred_node file: <data_dir>/preferred_node
 */
static int get_preferred_node_path(char *path, size_t path_size) {
    const char *data_dir = qgp_platform_app_data_dir();
    if (!data_dir) return -1;
    snprintf(path, path_size, "%s/preferred_node", data_dir);
    return 0;
}

/**
 * Load preferred node from file. Format: "ip:port|rtt_ms\n"
 * Returns true if a valid entry was loaded.
 */
static bool load_preferred_node(char *ip_out, size_t ip_size,
                                uint16_t *port_out, int *rtt_out) {
    char path[512];
    if (get_preferred_node_path(path, sizeof(path)) != 0) return false;

    FILE *f = fopen(path, "r");
    if (!f) return false;

    char line[128];
    if (!fgets(line, sizeof(line), f)) { fclose(f); return false; }
    fclose(f);

    /* Parse "ip:port|rtt_ms" */
    char *pipe = strchr(line, '|');
    if (!pipe) return false;
    *pipe = '\0';
    int rtt = atoi(pipe + 1);

    char *colon = strrchr(line, ':');
    if (!colon) return false;
    *colon = '\0';
    uint16_t port = (uint16_t)atoi(colon + 1);

    if (port == 0 || strlen(line) == 0) return false;

    strncpy(ip_out, line, ip_size - 1);
    ip_out[ip_size - 1] = '\0';
    *port_out = port;
    if (rtt_out) *rtt_out = rtt;

    QGP_LOG_INFO(LOG_TAG, "Loaded preferred node: %s:%d (RTT %dms)", ip_out, port, rtt);
    return true;
}

/**
 * Save preferred node to file.
 */
static void save_preferred_node(const char *ip, uint16_t port, int rtt_ms) {
    char path[512];
    if (get_preferred_node_path(path, sizeof(path)) != 0) return;

    FILE *f = fopen(path, "w");
    if (!f) {
        QGP_LOG_WARN(LOG_TAG, "Cannot write preferred_node: %s", strerror(errno));
        return;
    }
    fprintf(f, "%s:%d|%d\n", ip, port, rtt_ms);
    fclose(f);
    QGP_LOG_INFO(LOG_TAG, "Saved preferred node: %s:%d (RTT %dms)", ip, port, rtt_ms);
}

/**
 * Move a matching node to servers[0], shifting others down.
 */
static void prioritize_server(nodus_client_config_t *nconfig,
                              const char *ip, uint16_t port) {
    for (int i = 1; i < nconfig->server_count; i++) {
        if (strcmp(nconfig->servers[i].ip, ip) == 0 &&
            nconfig->servers[i].port == port) {
            /* Swap with [0] */
            nodus_server_endpoint_t tmp = nconfig->servers[0];
            nconfig->servers[0] = nconfig->servers[i];
            nconfig->servers[i] = tmp;
            QGP_LOG_INFO(LOG_TAG, "Prioritized preferred node %s:%d to slot 0", ip, port);
            return;
        }
    }
    /* Not found in list — it might be a new node from get_servers().
     * Insert at [0], shift everything else down. */
    if (nconfig->server_count < NODUS_CLIENT_MAX_SERVERS) {
        for (int i = nconfig->server_count; i > 0; i--) {
            nconfig->servers[i] = nconfig->servers[i - 1];
        }
        nconfig->server_count++;
    } else {
        /* List full — overwrite last slot, then swap to [0] */
        for (int i = nconfig->server_count - 1; i > 0; i--) {
            nconfig->servers[i] = nconfig->servers[i - 1];
        }
    }
    memset(&nconfig->servers[0], 0, sizeof(nconfig->servers[0]));
    strncpy(nconfig->servers[0].ip, ip, sizeof(nconfig->servers[0].ip) - 1);
    nconfig->servers[0].port = port;
    QGP_LOG_INFO(LOG_TAG, "Inserted preferred node %s:%d at slot 0", ip, port);
}

/* ── Background RTT Probe ──────────────────────────────────────── */

/**
 * Measure TCP connect RTT to ip:port (connect + immediate close).
 * Returns RTT in ms, or -1 on failure.
 */
static int measure_tcp_rtt(const char *ip, uint16_t port) {
#ifdef _WIN32
    /* TODO: Windows implementation */
    (void)ip; (void)port;
    return -1;
#else
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;

    /* Set non-blocking */
    int flags = fcntl(fd, F_GETFL, 0);
    fcntl(fd, F_SETFL, flags | O_NONBLOCK);

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    if (inet_pton(AF_INET, ip, &addr.sin_addr) != 1) {
        close(fd);
        return -1;
    }

    struct timeval start, end;
    gettimeofday(&start, NULL);

    int rc = connect(fd, (struct sockaddr *)&addr, sizeof(addr));
    if (rc == 0) {
        /* Immediate connect (unlikely for remote) */
        gettimeofday(&end, NULL);
        close(fd);
        int ms = (int)((end.tv_sec - start.tv_sec) * 1000 +
                        (end.tv_usec - start.tv_usec) / 1000);
        return ms;
    }

    if (errno != EINPROGRESS) {
        close(fd);
        return -1;
    }

    /* Wait for connect with 3s timeout */
    struct pollfd pfd = { .fd = fd, .events = POLLOUT };
    rc = poll(&pfd, 1, 3000);
    if (rc <= 0) {
        close(fd);
        return -1;
    }

    /* Check for connect error */
    int err = 0;
    socklen_t elen = sizeof(err);
    getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &elen);
    close(fd);

    if (err != 0) return -1;

    gettimeofday(&end, NULL);
    int ms = (int)((end.tv_sec - start.tv_sec) * 1000 +
                    (end.tv_usec - start.tv_usec) / 1000);
    return ms;
#endif
}

typedef struct {
    nodus_server_endpoint_t servers[NODUS_CLIENT_MAX_SERVERS];
    int server_count;
} rtt_probe_ctx_t;

static void *rtt_probe_thread(void *arg) {
    rtt_probe_ctx_t *ctx = (rtt_probe_ctx_t *)arg;
    if (!ctx) return NULL;

    QGP_LOG_INFO(LOG_TAG, "[RTT] Probing %d nodes...", ctx->server_count);

    char best_ip[64] = {0};
    uint16_t best_port = 0;
    int best_rtt = 999999;

    for (int i = 0; i < ctx->server_count; i++) {
        const char *ip = ctx->servers[i].ip;
        uint16_t port = ctx->servers[i].port;

        int rtt = measure_tcp_rtt(ip, port);
        if (rtt >= 0) {
            QGP_LOG_INFO(LOG_TAG, "[RTT] %s:%d = %dms", ip, port, rtt);
            if (rtt < best_rtt) {
                best_rtt = rtt;
                strncpy(best_ip, ip, sizeof(best_ip) - 1);
                best_port = port;
            }
        } else {
            QGP_LOG_WARN(LOG_TAG, "[RTT] %s:%d = UNREACHABLE", ip, port);
        }
    }

    if (best_port > 0) {
        save_preferred_node(best_ip, best_port, best_rtt);
    }

    free(ctx);
    return NULL;
}

/**
 * Spawn background thread to probe all known nodes and save the fastest.
 * Merges hardcoded list with get_servers() results.
 */

/** Returns true if IP is invalid for client use (0.0.0.0, private, loopback) */
static bool is_invalid_server_ip(const char *ip) {
    if (!ip || !ip[0]) return true;
    if (strcmp(ip, "0.0.0.0") == 0) return true;
    if (strcmp(ip, "127.0.0.1") == 0) return true;
    if (strncmp(ip, "10.", 3) == 0) return true;
    if (strncmp(ip, "192.168.", 8) == 0) return true;
    /* 172.16.0.0 – 172.31.255.255 */
    if (strncmp(ip, "172.", 4) == 0) {
        int second = atoi(ip + 4);
        if (second >= 16 && second <= 31) return true;
    }
    return false;
}

static void start_rtt_probe(void) {
    rtt_probe_ctx_t *ctx = calloc(1, sizeof(rtt_probe_ctx_t));
    if (!ctx) return;

    /* Start with hardcoded fallback nodes */
    for (int i = 0; i < g_fallback_count && ctx->server_count < NODUS_CLIENT_MAX_SERVERS; i++) {
        const char *node = g_fallback_nodes[i];
        const char *colon = strrchr(node, ':');
        if (!colon) continue;
        size_t ip_len = (size_t)(colon - node);
        if (ip_len >= sizeof(ctx->servers[0].ip)) continue;
        memcpy(ctx->servers[ctx->server_count].ip, node, ip_len);
        ctx->servers[ctx->server_count].ip[ip_len] = '\0';
        ctx->servers[ctx->server_count].port = (uint16_t)atoi(colon + 1);
        ctx->server_count++;
    }

    /* Try to discover additional nodes via get_servers() */
    nodus_client_t *client = nodus_singleton_get();
    if (client && nodus_client_is_ready(client)) {
        nodus_server_endpoint_t discovered[NODUS_CLIENT_MAX_SERVERS];
        int disc_count = 0;
        if (nodus_client_get_servers(client, discovered, NODUS_CLIENT_MAX_SERVERS, &disc_count) == 0 && disc_count > 0) {
            for (int d = 0; d < disc_count && ctx->server_count < NODUS_CLIENT_MAX_SERVERS; d++) {
                /* Check for duplicates */
                bool dup = false;
                for (int e = 0; e < ctx->server_count; e++) {
                    if (strcmp(ctx->servers[e].ip, discovered[d].ip) == 0 &&
                        ctx->servers[e].port == discovered[d].port) {
                        dup = true;
                        break;
                    }
                }
                if (!dup && !is_invalid_server_ip(discovered[d].ip)) {
                    ctx->servers[ctx->server_count] = discovered[d];
                    ctx->server_count++;
                    QGP_LOG_INFO(LOG_TAG, "[RTT] Discovered new node: %s:%d",
                                 discovered[d].ip, discovered[d].port);
                } else if (!dup) {
                    QGP_LOG_WARN(LOG_TAG, "[RTT] Ignoring invalid server IP: %s:%d",
                                 discovered[d].ip, discovered[d].port);
                }
            }
        }
        nodus_singleton_release();
    } else if (client) {
        nodus_singleton_release();
    }

    pthread_t thread;
    if (pthread_create(&thread, NULL, rtt_probe_thread, ctx) == 0) {
        pthread_detach(thread);
        QGP_LOG_INFO(LOG_TAG, "[RTT] Background probe started (%d nodes)", ctx->server_count);
    } else {
        free(ctx);
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

    /* ── Try sources in order: config → hardcoded fallback ── */
    /* Note: bootstrap_cache disabled — nobody writes to it, and stale entries
       with wrong port (4000 instead of 4001) caused ~1.5s startup delay. */

    /* Source 1: Config file nodes */
    if (g_config.bootstrap_count > 0) {
        QGP_LOG_INFO(LOG_TAG, "Using %d config bootstrap nodes", g_config.bootstrap_count);
        load_config_nodes(&nconfig);
    }

    /* Source 2: Hardcoded fallback (if no config) */
    if (nconfig.server_count == 0) {
        QGP_LOG_INFO(LOG_TAG, "Using %d hardcoded fallback nodes", g_fallback_count);
        load_fallback_nodes(&nconfig);
    }

    if (nconfig.server_count == 0) {
        QGP_LOG_ERROR(LOG_TAG, "No bootstrap nodes available");
        return -1;
    }

    /* Check preferred node file and prioritize if valid */
    {
        char pref_ip[64] = {0};
        uint16_t pref_port = 0;
        int pref_rtt = 0;
        if (load_preferred_node(pref_ip, sizeof(pref_ip), &pref_port, &pref_rtt)) {
            prioritize_server(&nconfig, pref_ip, pref_port);
        }
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

    /* If config nodes failed, retry with hardcoded fallback */
    if (rc != 0) {
        QGP_LOG_WARN(LOG_TAG, "Connect failed, retrying with hardcoded fallback nodes");
        nodus_singleton_close();

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
        /* Start background RTT probe to find fastest node for next startup */
        start_rtt_probe();
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

    /* bootstrap_cache disabled — no cleanup needed */

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

int nodus_messenger_poll(int timeout_ms) {
    if (!g_initialized) return -1;
    return nodus_singleton_poll(timeout_ms);
}

void nodus_messenger_force_disconnect(void) {
    if (!g_initialized) return;
    nodus_singleton_force_disconnect();
}

bool nodus_messenger_wait_for_ready(int timeout_ms) {
    int elapsed = 0;
    while (!nodus_messenger_is_ready() && elapsed < timeout_ms) {
        nodus_singleton_poll(100);
        elapsed += 100;
    }
    return nodus_messenger_is_ready();
}
