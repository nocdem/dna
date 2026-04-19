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
 * - Non-blocking init: connect happens in background thread
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
#include "crypto/hash/qgp_sha3.h"
#include "transport/nodus_tcp.h"
#include "dna_config.h"
/* #include "bootstrap_cache.h" — disabled, stale port data caused startup delay */

#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdatomic.h>
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

/* THR-02 / CONCURRENCY.md L3: g_nodus_init_mutex protects the non-atomic
 * static globals in this file (g_stored_identity, g_connect_thread,
 * g_config_loaded, g_config, g_status_cb, g_status_cb_data, g_known_nodes[],
 * g_known_node_count). The existing _Atomic bool g_initialized and
 * _Atomic bool g_connect_thread_running are fast-path fences and stay atomic.
 * First-time bootstrap (ensure_config + load_known_nodes) runs exactly once
 * via pthread_once(&g_nodus_once, nodus_once_init). Rules:
 *  - Lock order: L3. A thread holding this lock may acquire L4 (g_queue_mutex)
 *    and below, but MUST NOT re-enter nodus_singleton_* or nodus_client_*
 *    while holding it — that would deadlock the nodus-internal lock.
 *  - Callback pattern: on_state_change copies g_status_cb + g_status_cb_data
 *    to locals under lock, releases, then invokes the callback. User code
 *    never runs under g_nodus_init_mutex. */
static pthread_mutex_t g_nodus_init_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_once_t g_nodus_once = PTHREAD_ONCE_INIT;

static nodus_identity_t g_stored_identity;      /* Value type — no heap alloc */
static _Atomic bool g_initialized = false;
static pthread_t g_connect_thread;
static _Atomic bool g_connect_thread_running = false;
static bool g_config_loaded = false;
static dna_config_t g_config = {0};

/* Status callback */
static nodus_messenger_status_cb_t g_status_cb = NULL;
static void *g_status_cb_data = NULL;

/* ── Known Nodes Cache ─────────────────────────────────────────── */

#define KNOWN_NODES_FILE     "known_nodes"
#define KNOWN_NODES_MAX      16
#define KNOWN_NODES_FP_HEX   32   /* first 16 bytes of fingerprint = 32 hex chars */

typedef struct {
    char        ip[64];
    uint16_t    port;
    char        dil_fp[KNOWN_NODES_FP_HEX + 1];     /* first 16 bytes of Dilithium fingerprint hex */
    char        kyber_hash[KNOWN_NODES_FP_HEX + 1];  /* first 16 bytes of SHA3-512(kyber_pk) hex */
    uint64_t    last_seen;                             /* unix timestamp */
    int         rtt_ms;
} known_node_t;

static known_node_t g_known_nodes[KNOWN_NODES_MAX];
static int g_known_node_count = 0;

static int get_known_nodes_path(char *path, size_t path_size) {
    const char *data_dir = qgp_platform_app_data_dir();
    if (!data_dir) return -1;
    snprintf(path, path_size, "%s/%s", data_dir, KNOWN_NODES_FILE);
    return 0;
}

/**
 * Load known nodes from file. Format per line:
 *   ip:port|dil_fp_hex|kyber_hash_hex|last_seen|rtt_ms
 *
 * THR-02: CALLER MUST HOLD g_nodus_init_mutex, OR be called from
 * nodus_once_init (which is serialized by pthread_once).
 */
static int load_known_nodes(void) {
    char path[512];
    if (get_known_nodes_path(path, sizeof(path)) != 0) return -1;

    FILE *f = fopen(path, "r");
    if (!f) return -1;

    g_known_node_count = 0;
    char line[256];
    while (fgets(line, sizeof(line), f) && g_known_node_count < KNOWN_NODES_MAX) {
        /* Strip newline */
        size_t len = strlen(line);
        if (len > 0 && line[len - 1] == '\n') line[--len] = '\0';
        if (len == 0) continue;

        /* Parse: ip:port|dil_fp|kyber_hash|last_seen|rtt */
        char *p1 = strchr(line, '|');
        if (!p1) continue;
        *p1++ = '\0';

        char *p2 = strchr(p1, '|');
        if (!p2) continue;
        *p2++ = '\0';

        char *p3 = strchr(p2, '|');
        if (!p3) continue;
        *p3++ = '\0';

        char *p4 = strchr(p3, '|');
        if (!p4) continue;
        *p4++ = '\0';

        /* line = "ip:port", p1 = dil_fp, p2 = kyber_hash, p3 = last_seen, p4 = rtt */
        char *colon = strrchr(line, ':');
        if (!colon) continue;
        *colon = '\0';
        uint16_t port = (uint16_t)atoi(colon + 1);
        if (port == 0) continue;

        known_node_t *n = &g_known_nodes[g_known_node_count];
        memset(n, 0, sizeof(*n));
        strncpy(n->ip, line, sizeof(n->ip) - 1);
        n->port = port;
        strncpy(n->dil_fp, p1, KNOWN_NODES_FP_HEX);
        n->dil_fp[KNOWN_NODES_FP_HEX] = '\0';
        strncpy(n->kyber_hash, p2, KNOWN_NODES_FP_HEX);
        n->kyber_hash[KNOWN_NODES_FP_HEX] = '\0';
        n->last_seen = (uint64_t)strtoull(p3, NULL, 10);
        n->rtt_ms = atoi(p4);

        QGP_LOG_INFO(LOG_TAG, "[TOFU_DEBUG] loaded node[%d]: %s:%d dil=%s kyber=%s",
                     g_known_node_count, n->ip, n->port,
                     n->dil_fp[0] ? n->dil_fp : "(empty)",
                     n->kyber_hash[0] ? n->kyber_hash : "(empty)");
        g_known_node_count++;
    }

    fclose(f);
    QGP_LOG_INFO(LOG_TAG, "Loaded %d known nodes from %s", g_known_node_count, path);
    return 0;
}

/**
 * Save all known nodes to file.
 *
 * THR-02: CALLER MUST HOLD g_nodus_init_mutex.
 */
static int save_known_nodes(void) {
    char path[512];
    if (get_known_nodes_path(path, sizeof(path)) != 0) return -1;

    FILE *f = fopen(path, "w");
    if (!f) {
        QGP_LOG_WARN(LOG_TAG, "Cannot write known_nodes: %s", strerror(errno));
        return -1;
    }

    for (int i = 0; i < g_known_node_count; i++) {
        known_node_t *n = &g_known_nodes[i];
        fprintf(f, "%s:%d|%s|%s|%llu|%d\n",
                n->ip, n->port, n->dil_fp, n->kyber_hash,
                (unsigned long long)n->last_seen, n->rtt_ms);
    }

    fclose(f);
    QGP_LOG_INFO(LOG_TAG, "Saved %d known nodes", g_known_node_count);
    return 0;
}

/**
 * Update or add a node to the known nodes list.
 * If ip:port already exists, update keys + last_seen.
 * Otherwise add new entry (evict oldest if full).
 * Returns: 0 = updated/added, 1 = key changed (TOFU warning), -1 = error
 *
 * THR-02: CALLER MUST HOLD g_nodus_init_mutex.
 */
static int known_nodes_upsert(const char *ip, uint16_t port,
                               const char *dil_fp, const char *kyber_hash,
                               int rtt_ms) {
    /* Find existing entry by ip:port */
    for (int i = 0; i < g_known_node_count; i++) {
        known_node_t *n = &g_known_nodes[i];
        if (strcmp(n->ip, ip) == 0 && n->port == port) {
            int key_changed = 0;

            /* TOFU check: keys must not change */
            if (n->dil_fp[0] && dil_fp[0] && strcmp(n->dil_fp, dil_fp) != 0) {
                QGP_LOG_WARN(LOG_TAG, "⚠ TOFU: Dilithium key CHANGED for %s:%d "
                             "stored=%s new=%s", ip, port, n->dil_fp, dil_fp);
                key_changed = 1;
            }
            if (n->kyber_hash[0] && kyber_hash[0] && strcmp(n->kyber_hash, kyber_hash) != 0) {
                QGP_LOG_WARN(LOG_TAG, "⚠ TOFU: Kyber key CHANGED for %s:%d "
                             "stored=%s new=%s", ip, port, n->kyber_hash, kyber_hash);
                key_changed = 1;
            }

            /* Update */
            if (dil_fp[0]) {
                strncpy(n->dil_fp, dil_fp, KNOWN_NODES_FP_HEX);
                n->dil_fp[KNOWN_NODES_FP_HEX] = '\0';
            }
            if (kyber_hash[0]) {
                strncpy(n->kyber_hash, kyber_hash, KNOWN_NODES_FP_HEX);
                n->kyber_hash[KNOWN_NODES_FP_HEX] = '\0';
            }
            n->last_seen = (uint64_t)time(NULL);
            if (rtt_ms >= 0) n->rtt_ms = rtt_ms;

            save_known_nodes();
            return key_changed;
        }
    }

    /* New entry */
    known_node_t *n;
    if (g_known_node_count < KNOWN_NODES_MAX) {
        n = &g_known_nodes[g_known_node_count++];
    } else {
        /* Evict oldest (lowest last_seen) */
        int oldest = 0;
        for (int i = 1; i < KNOWN_NODES_MAX; i++) {
            if (g_known_nodes[i].last_seen < g_known_nodes[oldest].last_seen)
                oldest = i;
        }
        n = &g_known_nodes[oldest];
    }

    memset(n, 0, sizeof(*n));
    strncpy(n->ip, ip, sizeof(n->ip) - 1);
    n->port = port;
    if (dil_fp[0]) {
        strncpy(n->dil_fp, dil_fp, KNOWN_NODES_FP_HEX);
        n->dil_fp[KNOWN_NODES_FP_HEX] = '\0';
    }
    if (kyber_hash[0]) {
        strncpy(n->kyber_hash, kyber_hash, KNOWN_NODES_FP_HEX);
        n->kyber_hash[KNOWN_NODES_FP_HEX] = '\0';
    }
    n->last_seen = (uint64_t)time(NULL);
    n->rtt_ms = rtt_ms;

    save_known_nodes();
    QGP_LOG_INFO(LOG_TAG, "New known node: %s:%d", ip, port);
    return 0;
}

/**
 * Find a known node by ip:port. Returns pointer or NULL.
 *
 * THR-02: CALLER MUST HOLD g_nodus_init_mutex. The returned pointer is only
 * valid while the caller continues to hold the mutex — it points directly
 * into g_known_nodes[].
 */
static known_node_t *known_nodes_find(const char *ip, uint16_t port) {
    for (int i = 0; i < g_known_node_count; i++) {
        if (strcmp(g_known_nodes[i].ip, ip) == 0 && g_known_nodes[i].port == port)
            return &g_known_nodes[i];
    }
    return NULL;
}

/**
 * Compute hex hash prefix from raw key bytes (first 16 bytes of SHA3-512).
 */
static void compute_key_hash_hex(const uint8_t *key, size_t key_len,
                                  char *hex_out, size_t hex_size) {
    uint8_t hash[64]; /* SHA3-512 */
    qgp_sha3_512(key, key_len, hash);
    size_t hex_bytes = (hex_size - 1) / 2;
    if (hex_bytes > 16) hex_bytes = 16;
    for (size_t i = 0; i < hex_bytes; i++)
        snprintf(hex_out + i * 2, 3, "%02x", hash[i]);
    hex_out[hex_bytes * 2] = '\0';
}

/* ── Helpers ────────────────────────────────────────────────────── */

static void ensure_config(void) {
    if (!g_config_loaded) {
        dna_config_load(&g_config);
        g_config_loaded = true;

        /* bootstrap_cache disabled — stale port 4000 entries caused startup delay */
    }
}

/**
 * THR-02: First-time bootstrap helper. Runs exactly once across all threads
 * via pthread_once(&g_nodus_once, nodus_once_init). POSIX guarantees exactly-
 * once semantics, so this does NOT take g_nodus_init_mutex — pthread_once
 * already serializes. Subsequent mutations of the statics that this function
 * populates go through g_nodus_init_mutex in the regular entry points.
 */
static void nodus_once_init(void) {
    ensure_config();
    load_known_nodes();
}

/* Hardcoded fallback bootstrap nodes (compiled into binary) */
static const char *g_fallback_nodes[] = {
    "154.38.182.161:4001",
    "164.68.105.227:4001",
    "164.68.116.180:4001",
    "161.97.85.25:4001",
    "156.67.24.125:4001",
    "156.67.25.251:4001",
    "75.119.141.51:4001",
};
static const int g_fallback_count = 7;

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
static const char *state_name(nodus_client_state_t s) {
    switch (s) {
        case NODUS_CLIENT_DISCONNECTED: return "DISCONNECTED";
        case NODUS_CLIENT_CONNECTING:   return "CONNECTING";
        case NODUS_CLIENT_AUTHENTICATING: return "AUTHENTICATING";
        case NODUS_CLIENT_READY:        return "READY";
        case NODUS_CLIENT_RECONNECTING: return "RECONNECTING";
        default: return "UNKNOWN";
    }
}

static void on_state_change(nodus_client_state_t old_state,
                            nodus_client_state_t new_state,
                            void *user_data) {
    (void)user_data;

    QGP_LOG_INFO(LOG_TAG, "[STATE] %s → %s", state_name(old_state), state_name(new_state));

    /* THR-02: on_state_change fires on the nodus poll thread. The anti-pattern
     * rule is: NEVER call nodus_singleton_* / nodus_client_* while holding
     * g_nodus_init_mutex — that would deadlock the nodus-internal lock.
     * Strategy: (1) snapshot all server data from the nodus client into
     * locals with the singleton held (nodus-internal lock only, NOT our
     * mutex). (2) Release the nodus singleton. (3) Take g_nodus_init_mutex
     * to mutate g_known_nodes via known_nodes_upsert + copy out g_status_cb.
     * (4) Release our mutex. (5) Invoke the user callback OUTSIDE the lock. */

    bool is_connect_event = false;
    bool is_disconnect_event = false;
    bool have_server_info = false;
    char srv_ip[64] = {0};
    uint16_t srv_port = 0;
    char kyber_hash[KNOWN_NODES_FP_HEX + 1] = {0};
    char dil_fp_hex[KNOWN_NODES_FP_HEX + 1] = {0};

    if (new_state == NODUS_CLIENT_READY) {
        is_connect_event = true;

        /* Step 1: Snapshot connected server info under nodus singleton lock. */
        nodus_client_t *client = nodus_singleton_get();
        if (client) {
            /* Get connected server IP:port directly from the TCP connection,
             * NOT from config.servers[server_idx] — the index can be stale
             * after reconnect/failover, causing hash to be stored against
             * the wrong IP (the bug that caused duplicate TOFU hashes). */
            nodus_tcp_conn_t *conn = (nodus_tcp_conn_t *)client->conn;
            if (conn && conn->ip[0] && conn->port > 0) {
                strncpy(srv_ip, conn->ip, sizeof(srv_ip) - 1);
                srv_ip[sizeof(srv_ip) - 1] = '\0';
                srv_port = conn->port;

                /* Compute Kyber PK hash if we have it */
                if (client->has_cached_server_kyber) {
                    compute_key_hash_hex(client->cached_server_kyber_pk,
                                         NODUS_KYBER_PK_BYTES,
                                         kyber_hash, sizeof(kyber_hash));
                }

                /* Dilithium fingerprint from server's signed AUTH_OK */
                if (client->has_server_dil_pk) {
                    compute_key_hash_hex(client->server_dil_pk.bytes,
                                         NODUS_PK_BYTES,
                                         dil_fp_hex, sizeof(dil_fp_hex));
                    QGP_LOG_INFO(LOG_TAG, "[TOFU_DEBUG] server dil_pk available, fp_hash=%s", dil_fp_hex);
                } else {
                    QGP_LOG_INFO(LOG_TAG, "[TOFU_DEBUG] server dil_pk NOT available (legacy server)");
                }

                QGP_LOG_INFO(LOG_TAG, "[TOFU_DEBUG] server=%s:%d has_cached_kyber=%d kyber_hash=%s",
                             srv_ip, srv_port, client->has_cached_server_kyber,
                             kyber_hash[0] ? kyber_hash : "(empty)");

                have_server_info = true;
            }
            nodus_singleton_release();
        }
    } else if (old_state == NODUS_CLIENT_READY) {
        is_disconnect_event = true;
        QGP_LOG_WARN(LOG_TAG, "[DISCONNECT] Connection lost (was READY → %s)", state_name(new_state));
    }
    /* Ignore non-READY → non-READY transitions (DISCONNECTED→CONNECTING,
     * CONNECTING→AUTHENTICATING, etc.) to avoid false "DHT disconnected"
     * warnings during initial connection sequence. */

    if (!is_connect_event && !is_disconnect_event) {
        return;
    }

    /* Step 2: Under g_nodus_init_mutex, do TOFU upsert and snapshot status_cb.
     * NO nodus_singleton_* / nodus_client_* calls inside this critical section. */
    nodus_messenger_status_cb_t cb_local = NULL;
    void *cb_data_local = NULL;
    int tofu_rc = 0;
    bool did_upsert = false;
    bool existing_present = false;
    char existing_dil[KNOWN_NODES_FP_HEX + 1] = {0};
    char existing_kyber[KNOWN_NODES_FP_HEX + 1] = {0};
    uint64_t existing_last_seen = 0;

    /* CONCURRENCY.md L3: g_nodus_init_mutex */
    pthread_mutex_lock(&g_nodus_init_mutex);

    if (is_connect_event && have_server_info) {
        /* Check what's stored in known_nodes for this server */
        known_node_t *existing = known_nodes_find(srv_ip, srv_port);
        if (existing) {
            existing_present = true;
            strncpy(existing_dil, existing->dil_fp, sizeof(existing_dil) - 1);
            strncpy(existing_kyber, existing->kyber_hash, sizeof(existing_kyber) - 1);
            existing_last_seen = existing->last_seen;
        }

        tofu_rc = known_nodes_upsert(srv_ip, srv_port,
                                      dil_fp_hex, kyber_hash, -1);
        did_upsert = true;
    }

    cb_local = g_status_cb;
    cb_data_local = g_status_cb_data;

    pthread_mutex_unlock(&g_nodus_init_mutex);

    /* Step 3: Diagnostic logging and callback invocation OUTSIDE the lock. */
    if (is_connect_event && have_server_info) {
        if (existing_present) {
            QGP_LOG_INFO(LOG_TAG, "[TOFU_DEBUG] existing entry: dil_fp=%s kyber_hash=%s last_seen=%llu",
                         existing_dil[0] ? existing_dil : "(empty)",
                         existing_kyber[0] ? existing_kyber : "(empty)",
                         (unsigned long long)existing_last_seen);
        } else {
            QGP_LOG_INFO(LOG_TAG, "[TOFU_DEBUG] no existing entry for %s:%d (new node)",
                         srv_ip, srv_port);
        }

        if (did_upsert) {
            if (tofu_rc == 1) {
                QGP_LOG_ERROR(LOG_TAG, "⚠ TOFU VIOLATION: Server %s:%d key changed! "
                              "Possible MITM attack.", srv_ip, srv_port);
            } else if (tofu_rc == 0) {
                QGP_LOG_INFO(LOG_TAG, "[TOFU_DEBUG] upsert OK (no key change) for %s:%d",
                             srv_ip, srv_port);
            }
        }
    }

    if (cb_local) {
        cb_local(is_connect_event, cb_data_local);
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
    /* Skip entirely under DNA_NO_FALLBACK=1 — rtt_probe_thread
     * connects to every hardcoded fallback IP unconditionally, which
     * TOFU-upserts them into known_nodes. For isolated test clusters
     * (Stage F harness) this would leak production IPs into a
     * supposedly-clean HOME. */
    if (getenv("DNA_NO_FALLBACK") != NULL) {
        QGP_LOG_INFO(LOG_TAG, "DNA_NO_FALLBACK set — skipping RTT probe");
        return;
    }

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

/* ── Background Connect Thread ──────────────────────────────────── */

static void* nodus_connect_thread_fn(void *arg) {
    (void)arg;
    QGP_LOG_INFO(LOG_TAG, "Connect thread started");

    int rc = nodus_singleton_connect();
    fprintf(stderr, "[NODUS_INIT] Singleton connect rc=%d\n", rc);

    if (rc != 0 && getenv("DNA_NO_FALLBACK") == NULL) {
        QGP_LOG_WARN(LOG_TAG, "Connect failed, retrying with hardcoded fallback nodes");
        nodus_singleton_close();

        nodus_client_config_t nconfig;
        memset(&nconfig, 0, sizeof(nconfig));
        nconfig.auto_reconnect = true;
        nconfig.on_value_changed = nodus_ops_dispatch;
        nconfig.on_state_change = on_state_change;
        load_fallback_nodes(&nconfig);

        for (int i = 0; i < nconfig.server_count; i++) {
            fprintf(stderr, "[NODUS_INIT] Fallback server %d: %s:%d\n",
                    i, nconfig.servers[i].ip, nconfig.servers[i].port);
        }

        if (nconfig.server_count > 0) {
            rc = nodus_singleton_init(&nconfig, &g_stored_identity);
            if (rc == 0) {
                rc = nodus_singleton_connect();
                fprintf(stderr, "[NODUS_INIT] Fallback connect rc=%d\n", rc);
            }
        }
    }

    if (rc == 0) {
        start_rtt_probe();
    } else {
        QGP_LOG_ERROR(LOG_TAG, "All bootstrap sources failed (connect thread)");
    }

    /* NOTE: Do NOT clear g_connect_thread_running here.
     * The flag means "thread was spawned and needs join", not "thread is active".
     * close()/reinit() will join and clear the flag. */
    QGP_LOG_INFO(LOG_TAG, "Connect thread exiting (rc=%d)", rc);
    return NULL;
}

/* ── Public API ─────────────────────────────────────────────────── */

int nodus_messenger_init(const nodus_identity_t *identity) {
    if (!identity) {
        QGP_LOG_ERROR(LOG_TAG, "NULL identity");
        return -1;
    }

    /* Fast path: already initialized (atomic fence, no lock). */
    if (atomic_load(&g_initialized)) {
        QGP_LOG_WARN(LOG_TAG, "Already initialized");
        return 0;
    }

    /* First-time bootstrap — exactly once, across all callers.
     * Populates g_config_loaded / g_config and g_known_nodes[] / g_known_node_count. */
    pthread_once(&g_nodus_once, nodus_once_init);

    /* CONCURRENCY.md L3: g_nodus_init_mutex
     * Serialize concurrent nodus_messenger_init calls and protect the
     * non-atomic statics (g_stored_identity, g_connect_thread, g_known_nodes,
     * g_config, g_status_cb) through the whole init sequence. The winning
     * thread sets g_initialized=true at the end; all losing threads see it
     * via the double-check under lock.
     *
     * Anti-pattern carve-out: this critical section calls nodus_singleton_init
     * (and optionally nodus_singleton_connect on the pthread_create failure
     * fallback). That is SAFE here because:
     *   (a) nodus_singleton_init is the FIRST-EVER init of the singleton in
     *       this process — no other thread can hold the nodus-internal lock
     *       yet, so there is no reverse ordering to deadlock against.
     *   (b) on_state_change — the only reverse-ordering hazard — can only
     *       fire from the nodus poll thread, which is not started until the
     *       connect thread runs, which is spawned AFTER we finish this
     *       critical section (pthread_create below). At the moment of
     *       nodus_singleton_init, no poll thread exists.
     *   (c) nodus_singleton_connect under lock only happens on the rare
     *       pthread_create failure fallback, and even then the connect
     *       thread can't already be running (that's the failure we are
     *       recovering from).
     * Outside of init(), the strict rule applies: no nodus_singleton_* /
     * nodus_client_* calls under g_nodus_init_mutex (see close, reinit,
     * set_status_callback, on_state_change). */
    pthread_mutex_lock(&g_nodus_init_mutex);

    /* Double-check under lock */
    if (atomic_load(&g_initialized)) {
        pthread_mutex_unlock(&g_nodus_init_mutex);
        QGP_LOG_WARN(LOG_TAG, "Already initialized (race resolved)");
        return 0;
    }

    /* Store identity (value copy — no heap, no leak) */
    g_stored_identity = *identity;

    /* Build Nodus client config from bootstrap nodes */
    nodus_client_config_t nconfig;
    memset(&nconfig, 0, sizeof(nconfig));
    nconfig.auto_reconnect = true;
    nconfig.on_value_changed = nodus_ops_dispatch;
    nconfig.on_state_change = on_state_change;

    /* ── Try sources in order: known_nodes → config → hardcoded fallback ── */

    /* Source 1: Known nodes cache (populated by nodus_once_init on first init; TOFU upserts since). */
    if (g_known_node_count > 0) {
        QGP_LOG_INFO(LOG_TAG, "Using %d known nodes from cache", g_known_node_count);
        for (int i = 0; i < g_known_node_count && nconfig.server_count < NODUS_CLIENT_MAX_SERVERS; i++) {
            if (is_invalid_server_ip(g_known_nodes[i].ip)) continue;
            strncpy(nconfig.servers[nconfig.server_count].ip,
                    g_known_nodes[i].ip, sizeof(nconfig.servers[0].ip) - 1);
            nconfig.servers[nconfig.server_count].port = g_known_nodes[i].port;
            nconfig.server_count++;
        }
    }

    /* Source 2: Config file nodes (merge, dedup) */
    if (g_config.bootstrap_count > 0) {
        QGP_LOG_INFO(LOG_TAG, "Merging %d config bootstrap nodes", g_config.bootstrap_count);
        /* Only add config nodes not already in the list */
        nodus_client_config_t tmp;
        memset(&tmp, 0, sizeof(tmp));
        load_config_nodes(&tmp);
        for (int i = 0; i < tmp.server_count && nconfig.server_count < NODUS_CLIENT_MAX_SERVERS; i++) {
            bool dup = false;
            for (int j = 0; j < nconfig.server_count; j++) {
                if (strcmp(nconfig.servers[j].ip, tmp.servers[i].ip) == 0 &&
                    nconfig.servers[j].port == tmp.servers[i].port) {
                    dup = true;
                    break;
                }
            }
            if (!dup) {
                nconfig.servers[nconfig.server_count] = tmp.servers[i];
                nconfig.server_count++;
            }
        }
    }

    /* Source 3: Hardcoded fallback (merge remaining).
     * Skipped when DNA_NO_FALLBACK=1 — used by the Stage F integration
     * harness to keep localhost-only test clusters isolated from
     * production bootstrap IPs. (Without this, TOFU upserts against
     * the fallback pollute known_nodes + preferred_node with
     * production endpoints, and even HOME-isolated tests can leak
     * state into the real network.) */
    if (getenv("DNA_NO_FALLBACK") == NULL) {
        nodus_client_config_t tmp;
        memset(&tmp, 0, sizeof(tmp));
        load_fallback_nodes(&tmp);
        for (int i = 0; i < tmp.server_count && nconfig.server_count < NODUS_CLIENT_MAX_SERVERS; i++) {
            bool dup = false;
            for (int j = 0; j < nconfig.server_count; j++) {
                if (strcmp(nconfig.servers[j].ip, tmp.servers[i].ip) == 0 &&
                    nconfig.servers[j].port == tmp.servers[i].port) {
                    dup = true;
                    break;
                }
            }
            if (!dup) {
                nconfig.servers[nconfig.server_count] = tmp.servers[i];
                nconfig.server_count++;
            }
        }
    } else {
        QGP_LOG_INFO(LOG_TAG, "DNA_NO_FALLBACK set — skipping hardcoded bootstrap fallback");
    }

    if (nconfig.server_count == 0) {
        QGP_LOG_ERROR(LOG_TAG, "No bootstrap nodes available");
        pthread_mutex_unlock(&g_nodus_init_mutex);
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

    int rc = nodus_singleton_init(&nconfig, &g_stored_identity);
    if (rc != 0) {
        fprintf(stderr, "[NODUS_INIT] Singleton init failed (rc=%d)\n", rc);
        QGP_LOG_ERROR(LOG_TAG, "Singleton init failed");
        pthread_mutex_unlock(&g_nodus_init_mutex);
        return -1;
    }

    /* Initialize channel connection pool (TCP 4003) */
    nodus_ops_ch_init(NULL, NULL);

    /* Mark initialized before spawning connect thread */
    atomic_store(&g_initialized, true);

    /* Spawn background connect thread (non-blocking init).
     * pthread_create writes g_connect_thread — protected by g_nodus_init_mutex. */
    atomic_store(&g_connect_thread_running, true);
    if (pthread_create(&g_connect_thread, NULL, nodus_connect_thread_fn, NULL) != 0) {
        QGP_LOG_WARN(LOG_TAG, "Failed to create connect thread, falling back to blocking connect");
        atomic_store(&g_connect_thread_running, false);
        /* Blocking fallback — release our mutex first so nodus_singleton_connect
         * does not run under g_nodus_init_mutex (callback path may try to take
         * our lock from the poll thread). */
        pthread_mutex_unlock(&g_nodus_init_mutex);
        nodus_singleton_connect();
        return 0;
    }

    pthread_mutex_unlock(&g_nodus_init_mutex);
    return 0;
}

void nodus_messenger_close(void) {
    if (!atomic_load(&g_initialized)) return;

    QGP_LOG_INFO(LOG_TAG, "Closing");

    /* Snapshot the connect-thread handle under the lock, then release
     * before calling any nodus_singleton_* / pthread_join (which block and
     * could interact with on_state_change taking g_nodus_init_mutex on the
     * poll thread — that would deadlock if we held it here). */
    pthread_t thread_to_join = 0;
    bool need_join = false;

    /* CONCURRENCY.md L3: g_nodus_init_mutex */
    pthread_mutex_lock(&g_nodus_init_mutex);
    if (atomic_load(&g_connect_thread_running)) {
        thread_to_join = g_connect_thread;
        need_join = true;
    }
    pthread_mutex_unlock(&g_nodus_init_mutex);

    /* Join connect thread BEFORE closing singleton — outside our mutex. */
    if (need_join) {
        QGP_LOG_INFO(LOG_TAG, "Waiting for connect thread to finish...");
        nodus_singleton_force_disconnect();
        pthread_join(thread_to_join, NULL);
        atomic_store(&g_connect_thread_running, false);
    }

    /* Shut down channel connection pool (TCP 4003) before closing singleton */
    nodus_ops_ch_shutdown();

    /* Cancel all nodus_ops listeners first */
    nodus_ops_cancel_all();

    /* Close the singleton (disconnects TCP, frees client) */
    nodus_singleton_close();

    /* Clear stored identity — protected by the mutex. */
    pthread_mutex_lock(&g_nodus_init_mutex);
    nodus_identity_clear(&g_stored_identity);
    pthread_mutex_unlock(&g_nodus_init_mutex);

    /* bootstrap_cache disabled — no cleanup needed */

    atomic_store(&g_initialized, false);
}

int nodus_messenger_reinit(void) {
    QGP_LOG_INFO(LOG_TAG, "Network change, reinitializing...");

    if (!atomic_load(&g_initialized)) {
        QGP_LOG_ERROR(LOG_TAG, "Not initialized, cannot reinit");
        return -1;
    }

    /* Snapshot identity + connect-thread handle under lock, then release
     * before calling nodus_singleton_* / pthread_join. Same rationale as
     * nodus_messenger_close. */
    nodus_identity_t saved;
    pthread_t thread_to_join = 0;
    bool need_join = false;

    /* CONCURRENCY.md L3: g_nodus_init_mutex */
    pthread_mutex_lock(&g_nodus_init_mutex);
    saved = g_stored_identity;
    if (atomic_load(&g_connect_thread_running)) {
        thread_to_join = g_connect_thread;
        need_join = true;
    }
    pthread_mutex_unlock(&g_nodus_init_mutex);

    /* Join connect thread BEFORE closing singleton — outside our mutex. */
    if (need_join) {
        QGP_LOG_INFO(LOG_TAG, "Waiting for connect thread to finish...");
        nodus_singleton_force_disconnect();
        pthread_join(thread_to_join, NULL);
        atomic_store(&g_connect_thread_running, false);
    }

    /* Close current connection */
    nodus_ops_ch_shutdown();
    nodus_ops_cancel_all();
    nodus_singleton_close();
    atomic_store(&g_initialized, false);

    /* Re-init with saved identity */
    return nodus_messenger_init(&saved);
}

bool nodus_messenger_is_ready(void) {
    return atomic_load(&g_initialized) && nodus_singleton_is_ready();
}

bool nodus_messenger_is_initialized(void) {
    return atomic_load(&g_initialized);
}

void nodus_messenger_set_status_callback(nodus_messenger_status_cb_t cb, void *user_data) {
    /* CONCURRENCY.md L3: g_nodus_init_mutex
     * Store cb + user_data under the mutex to avoid a torn fn-ptr/user-data
     * pair being read by on_state_change on the nodus poll thread. */
    pthread_mutex_lock(&g_nodus_init_mutex);
    g_status_cb = cb;
    g_status_cb_data = user_data;
    pthread_mutex_unlock(&g_nodus_init_mutex);

    /* Fire immediately if already connected — OUTSIDE the mutex so user
     * callback code never runs under our lock (and cannot re-enter our
     * entry points or nodus_singleton_*). */
    if (atomic_load(&g_initialized) && nodus_singleton_is_ready() && cb) {
        cb(true, user_data);
    }
}

int nodus_messenger_poll(int timeout_ms) {
    if (!atomic_load(&g_initialized)) return -1;
    return nodus_singleton_poll(timeout_ms);
}

void nodus_messenger_force_disconnect(void) {
    if (!atomic_load(&g_initialized)) return;
    nodus_singleton_force_disconnect();
}

void nodus_messenger_suspend(void) {
    if (!atomic_load(&g_initialized)) return;
    nodus_singleton_suspend();
}

void nodus_messenger_resume(void) {
    if (!atomic_load(&g_initialized)) return;
    nodus_singleton_resume();
}

bool nodus_messenger_wait_for_ready(int timeout_ms) {
    int elapsed = 0;
    while (!nodus_messenger_is_ready() && elapsed < timeout_ms) {
        nodus_singleton_poll(100);
        elapsed += 100;
    }
    return nodus_messenger_is_ready();
}
